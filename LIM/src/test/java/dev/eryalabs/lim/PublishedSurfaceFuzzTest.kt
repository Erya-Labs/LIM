package dev.eryalabs.lim

import android.content.Context
import android.content.Intent
import android.os.BadParcelableException
import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Method
import java.lang.reflect.Modifier
import java.lang.reflect.ParameterizedType
import java.lang.reflect.Type
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.util.Random

/**
 * **Does every published entry point degrade safely on a value another app chose?** — asked of the
 * whole surface at once, mechanically, instead of in prose.
 *
 * `PublicApiAuditTest` answers two neighbouring questions and not this one. Its manifest answers
 * "is every public member *tested*", and its signature snapshot answers "has its shape moved".
 * Neither looks at behaviour. The hostile-input question was answered once, by hand, in a Progress
 * log entry dated 2026-08-13 (T9) that listed the functions reachable with attacker-chosen data and
 * reasoned about each — and prose cannot be re-run. A public function added tomorrow can carry no
 * hostile-input test at all and nothing in this repository goes red. This file is that list turned
 * into a verifier, and its third assertion is the point: **the set of methods actually invoked must
 * equal the published set**, minus a [NOT_FUZZABLE] map whose every entry names a reason and the
 * test that covers the member instead.
 *
 * **Which file owns what.** The hostile surface splits in two and the halves must not duplicate
 * each other:
 *
 * - `NullArgumentTest` (T25) owns the **`null`** half — every reference parameter position called
 *   with a `null` argument, and whether the position's Kotlin declaration tolerates one. Nothing
 *   here passes a `null` *argument*.
 * - This file owns the hostile-**value** half — non-null references carrying contents nobody
 *   designed: empty, blank, oversized, control-charactered, type-confused, structurally broken,
 *   and `null` *inside* a collection the signature says holds non-null elements.
 * - `DecoderFuzzTest` (T8 and after) owns **depth** over the three decoders, the six parsers and
 *   the verifiers: thousands of mutated payloads per function, with the security properties stated
 *   per flow. This file owns **breadth** instead — a handful of vectors per method, but *every*
 *   method — so the two are not alternatives and neither subsumes the other.
 *
 * That separation is why the corpus below is this file's own and is deliberately not shared with
 * `DecoderFuzzTest`: its generator is private, extracting it would move its pinned `CORPUS_DIGEST`,
 * and a corpus two files draw from is a corpus neither can change. Each has its own digest.
 *
 * **What a hostile vector is.** Values are drawn by parameter *type* from [corpusText] and
 * [corpusLongs] — see [valueFor] for the table. Two types are filled with real, benign values on
 * purpose, and the reason is the trust boundary this library sits on: a `Context` is the client
 * app's own handle on the framework and a `SecureRandom` is its own entropy source. Neither can
 * arrive from another app across IPC, so fuzzing them would be fuzzing the caller rather than the
 * attacker. [BENIGN_POSITIONS] states every such position by name, so a *new* parameter of either
 * type cannot slip in unexamined and a position that quietly stopped being fuzzed fails here.
 *
 * **Runtime is the design constraint.** This is breadth, so the draw count per method is small and
 * the corpus is short; the measured wall-clock is printed on every run.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class PublishedSurfaceFuzzTest {

    // ── The corpus ───────────────────────────────────────────────────────

    // Code points spelled out numerically rather than typed literally, `DecoderFuzzTest`'s
    // reasoning: two of them cannot survive a round trip through a UTF-8 source file, and a corpus
    // whose contents depend on how this file was saved is not a reproducible corpus.
    private val nul = 0x0000.toChar()
    private val eAcute = 0x00E9.toChar()
    private val bidiOverride = 0x202E.toChar()

    /** No `String` can encode this to UTF-8, so it also exercises the lossy path to bytes. */
    private val loneSurrogate = 0xD83D.toChar()

    /**
     * Hostile text, and the source of every hostile `ByteArray` too.
     *
     * Short on purpose — this file is breadth, and depth over mutated payloads is
     * `DecoderFuzzTest`'s job. Each entry is here for a reason rather than for volume: the
     * boundaries a length check gets wrong (`""`, one character, blank), the shapes a decoder
     * mistakes for structure, the characters that break a renderer or a log line, text that is
     * nearly a key or nearly an envelope, something far longer than any buffer anybody sized, and
     * nesting deep enough to matter but well inside the depth `DecoderFuzzTest` already proves the
     * JSON parser survives.
     *
     * The first two entries are load-bearing beyond their content: `the fuzz reaches every hostile
     * position` asserts that *both* were handed to every invoked `String` position, which is what
     * makes a one-character-off bug in a published function reachable from here at all.
     */
    private val corpusText: List<String> = listOf(
        "",
        "x",
        "   ",
        "{}",
        "[]",
        "null",
        "\"unterminated",
        """{"id":"x","publicKey":"k","fields":{"a":null}}""",
        """{"value":"v","type":"String"}""",
        "lim.statement.v1",
        "lim.env.v1:lim.rotate.v1::",
        // Base64-shaped but far too short to be a key, so it decodes to bytes and still fails.
        "MIIBIjANBgkq",
        "====",
        "a" + nul + "b",
        "caf$eAcute",
        "$bidiOverride}{",
        "$loneSurrogate",
        "x".repeat(16_384),
        "[".repeat(300) + "1" + "]".repeat(300),
    )

    /**
     * Hostile `long`s. Primitives cannot be `null`, so the whole of what another app can choose
     * about one is its value, and these are the values that break arithmetic rather than parsing:
     * the saturating bounds (an authorization at [Long.MAX_VALUE] is permanently unrevocable, which
     * [Utils.isRevoked] documents), zero, negative, and a plausible clock either side of itself.
     */
    private val corpusLongs: List<Long> = listOf(
        0L,
        -1L,
        1L,
        Long.MIN_VALUE,
        Long.MAX_VALUE,
        FUZZ_CLOCK,
        -FUZZ_CLOCK,
    )

    // ── Fixtures that are deliberately not hostile ───────────────────────

    /**
     * The client app's own handle on the framework. Not a trust boundary: nothing another app sends
     * across IPC arrives as a `Context`, so a fuzzed one would be fuzzing the caller. Robolectric's
     * is used so that `shareEntry` and the three intent builders run their real bodies.
     */
    private val context: Context = ApplicationProvider.getApplicationContext()

    /**
     * A real entropy source, for the same reason: a `SecureRandom` is the caller's own, and
     * [Utils.generateNonce] takes it by injection so that `NonceTest` can pin it — not because it
     * crosses a boundary. Seeding it here would make this file a weaker copy of that one.
     */
    private val entropy = SecureRandom()

    /**
     * An intent whose extras cannot be read at all.
     *
     * Unparcelling a bundle that references a class this process does not have throws in exactly
     * this way, and the *sender* chooses what goes in the bundle — so every function that reads an
     * extra must survive it. The fixture is the one `ResultParsingTest:77` introduced, restated
     * here rather than shared: it is private to that class, and this file's whole premise is that
     * its inputs are its own.
     */
    private class UnreadableIntent : Intent() {
        override fun getStringExtra(name: String?): String? =
            throw BadParcelableException("extras reference an unknown class")
    }

    // ── The value provider ───────────────────────────────────────────────

    /**
     * The intent shapes a hostile payload can arrive in: under each LIM extra in turn, under all of
     * them at once, and an intent that throws on every read.
     *
     * The extra keys are read off `Utils` by reflection rather than listed, for the reason
     * `PublicApiAuditTest` discovers its classes rather than listing them: an extra added later
     * must be fuzzed without anybody remembering to come back here. `every intent shape was used`
     * is what stops that enumeration from quietly going empty.
     */
    private val limExtraKeys: List<String> = Utils::class.java.declaredFields
        .filter { Modifier.isPublic(it.modifiers) && !it.isSynthetic && it.name.startsWith("EXTRA_") }
        .sortedBy { it.name }
        .map { it.get(null) as String }

    private val intentShapes: List<String> =
        limExtraKeys.map { "one:$it" } + "all" + "unreadable"

    private fun intentFor(shape: String, text: String): Intent = when {
        shape == "unreadable" -> UnreadableIntent()
        shape == "all" -> Intent().apply {
            limExtraKeys.forEach { putExtra(it, text) }
        }

        else -> Intent().apply { putExtra(shape.removePrefix("one:"), text) }
    }

    /**
     * A field map carrying a genuine `null` where the declared type says there cannot be one.
     *
     * Reachable in production two ways — Java handing this library a map it built, and the `Unsafe`
     * hazard [Utils.decodeEntry] exists for — and unreachable from Kotlin source without the cast,
     * which is the [Utils.validateEntry] precedent for writing it this way.
     *
     * **A null *key* is deliberately not drawn, and the asymmetry is about which contract exists.**
     * [Utils.validateEntry]'s KDoc promises it defends against a field map whose declared-non-null
     * contents are genuinely null, so the null *value* is a documented case this file is entitled
     * to hold it to. No such promise is offered about a key, and none is reachable without one: a
     * null key cannot arrive from a decoded payload — JSON has no null object key, and
     * [Utils.decodeFields] builds its map from parsed names — so the only producer is a caller
     * corrupting its own map, which is not the trust boundary this file is about. Drawing one
     * anyway would assert a contract nobody offered, which is the opposite of what a fuzz run is
     * for.
     *
     * Both entries are always present, keyed on two *different* corpus indices. Keying both on the
     * same draw would collide once in nineteen and silently leave a map carrying only the null —
     * still hostile, but no longer the mixed shape `validateEntry` is about.
     */
    @Suppress("UNCHECKED_CAST")
    private fun hostileFields(rnd: Random): Map<String, TypedField> {
        val valued = rnd.nextInt(corpusText.size)
        val nulled = (valued + 1 + rnd.nextInt(corpusText.size - 1)) % corpusText.size
        val raw = LinkedHashMap<String, TypedField?>()
        raw[corpusText[valued]] = TypedField(text(rnd), text(rnd))
        raw[corpusText[nulled]] = null
        return raw as Map<String, TypedField>
    }

    private fun text(rnd: Random): String = corpusText[rnd.nextInt(corpusText.size)]

    private fun long(rnd: Random): Long = corpusLongs[rnd.nextInt(corpusLongs.size)]

    private fun hostileEntry(rnd: Random) = Entry(text(rnd), hostileFields(rnd), text(rnd))

    private fun hostileRotation(rnd: Random) =
        RotationStatement(text(rnd), text(rnd), text(rnd), long(rnd), long(rnd))

    private fun hostileAuthorization(rnd: Random) =
        RecoveryAuthorization(text(rnd), text(rnd), text(rnd), long(rnd), long(rnd))

    private fun hostileRevocation(rnd: Random) =
        Revocation(text(rnd), text(rnd), long(rnd), long(rnd))

    /**
     * The three parsed-request types, hostile — T29's request overloads take one each, and a
     * vault reaches them with whatever [Utils.parseShareRequest] and its siblings handed back.
     *
     * Built from this file's **own** corpus draws, [text] and [long], and no new corpus entry:
     * the digest below is computed over the static `corpusText` and `corpusLongs` lists rather
     * than over the draw sequence, so these vectors move it by nothing — and adding entries would
     * put the every-entry-is-drawn floors at risk for no gain.
     *
     * **Wider than the parser in one direction and narrower in another, both stated.** A real
     * parser returns a `requestCode` that is `null` or non-blank and never blank, and a `nonce`
     * that is never empty — this provider produces both of those, because a vault can construct
     * one of these itself and `ShareRequest` is a published constructor with no validation in
     * it. What it does *not* produce is the `null` `requestCode`, since [text] is non-null by
     * construction and adding a conditional draw would shift the draw sequence and so the corpus
     * reach floors below. `ResultBuilderTest`'s codeless controls own that shape, over all three
     * flows, through the parsers rather than around them.
     *
     * `protocolVersion` is a corpus `long` truncated to `Int`, so the saturating bounds reach it
     * as `0` and `-1` rather than not at all. It is a declaration the client made and nothing
     * here honours it, which is exactly why it must not crash a builder that ignores it.
     */
    private fun hostileShareRequest(rnd: Random) =
        ShareRequest(hostileEntry(rnd), text(rnd), long(rnd).toInt())

    private fun hostileQueryRequest(rnd: Random) =
        QueryRequest(text(rnd), text(rnd), long(rnd).toInt())

    private fun hostileSignChallengeRequest(rnd: Random) =
        SignChallengeRequest(text(rnd), text(rnd).toByteArray(), text(rnd), text(rnd), long(rnd).toInt())

    /**
     * A set of field names, drawn from the corpus — and every third one carrying a `null`, which
     * the signature forbids and Java can pass. Required fields' `optionalFields` is one; a client
     * chooses it, but it names fields of an entry another app may have sent.
     */
    @Suppress("UNCHECKED_CAST")
    private fun hostileNames(rnd: Random): Set<String> {
        val names = linkedSetOf<String?>(text(rnd), text(rnd))
        if (rnd.nextInt(3) == 0) names += null
        return names as Set<String>
    }

    /**
     * Requirements as a vault might hold them: corpus names, some declared optional, and the same
     * Java `null` the constructor documents skipping. Built through the published constructor,
     * which is the only way one exists.
     */
    @Suppress("UNCHECKED_CAST")
    private fun hostileRequirements(rnd: Random): FieldRequirements {
        val names = arrayListOf<String?>(text(rnd), text(rnd), text(rnd))
        if (rnd.nextInt(3) == 0) names += null
        return FieldRequirements(names as List<String>, hostileNames(rnd))
    }

    private fun rawOf(type: Type): Class<*>? = when (type) {
        is ParameterizedType -> type.rawType as? Class<*>
        is Class<*> -> type
        else -> null
    }

    private fun elementOf(type: Type): Type? =
        (type as? ParameterizedType)?.actualTypeArguments?.singleOrNull()

    /**
     * Whether the provider has a vector for this parameter type **at all**.
     *
     * This is the hinge of the whole file. A type that is not covered means the method carrying it
     * is not invoked, which means it is missing from the invoked set, which means
     * `every published method is fuzzed or excused by name` fails and names it. A published
     * function taking a `java.io.File` is exactly that case.
     */
    private fun covered(type: Type): Boolean {
        val raw = rawOf(type) ?: return false
        // Containers are checked by type *argument*, not by raw type. A `List<String>` or a
        // `Map<String, String>` added later is a parameter this provider has no vector for, and
        // matching on `List`/`Map` alone would hand it a list of revocations or a map of typed
        // fields, count it as fuzzed, and pass — which is the same mistake as not covering it,
        // only silent.
        if (raw == List::class.java) {
            val element = elementOf(type)
            return element == Revocation::class.java ||
                element == RecoveryAuthorization::class.java
        }
        if (raw == Map::class.java) {
            return (type as? ParameterizedType)?.actualTypeArguments?.toList() ==
                listOf<Type>(String::class.java, TypedField::class.java)
        }
        // Required fields' `Set<String>` of optional names; a set of anything else is uncovered.
        if (raw == Set::class.java) return elementOf(type) == String::class.java
        return raw in COVERED_TYPES
    }

    /** One hostile (or, for the two stated types, deliberately benign) value of [type]. */
    private fun valueFor(type: Type, rnd: Random): Any {
        val raw = rawOf(type)
            ?: throw AssertionError("unhandled parameter type shape: ${render(type)}")
        return when (raw) {
            Context::class.java -> context
            SecureRandom::class.java -> entropy
            String::class.java -> text(rnd)
            ByteArray::class.java -> text(rnd).toByteArray()
            java.lang.Long.TYPE -> long(rnd)
            Entry::class.java -> hostileEntry(rnd)
            RotationStatement::class.java -> hostileRotation(rnd)
            RecoveryAuthorization::class.java -> hostileAuthorization(rnd)
            Revocation::class.java -> hostileRevocation(rnd)
            ShareRequest::class.java -> hostileShareRequest(rnd)
            QueryRequest::class.java -> hostileQueryRequest(rnd)
            SignChallengeRequest::class.java -> hostileSignChallengeRequest(rnd)
            FieldRequirements::class.java -> hostileRequirements(rnd)
            Set::class.java -> hostileNames(rnd)
            Map::class.java -> hostileFields(rnd)
            Intent::class.java -> intentFor(intentShapes[rnd.nextInt(intentShapes.size)], text(rnd))
            List::class.java -> hostileList(type, rnd)
            else -> throw AssertionError(
                "no hostile value for parameter type ${render(type)} — add one deliberately, or " +
                    "excuse the member in NOT_FUZZABLE with a reason and a covering test",
            )
        }
    }

    /**
     * A one- or two-element list of whatever the declared element type is — and sometimes one
     * carrying a `null`, which the signature says is impossible and an unchecked cast from Java
     * makes real. [Utils.isRevoked] and [Utils.liveAuthorizations] both document that case.
     */
    @Suppress("UNCHECKED_CAST")
    private fun hostileList(type: Type, rnd: Random): List<Any> {
        val element = elementOf(type)
        val one: Any = when (element) {
            Revocation::class.java -> hostileRevocation(rnd)
            RecoveryAuthorization::class.java -> hostileAuthorization(rnd)
            else -> throw AssertionError("no hostile element for list parameter ${render(type)}")
        }
        // Every third draw carries the null, so both shapes occur and `a null-bearing list was
        // drawn` can assert the harder one did.
        return if (rnd.nextInt(3) == 0) listOf(one, null) as List<Any> else listOf(one)
    }

    // ── The mutation detector ────────────────────────────────────────────

    /**
     * One argument a function wrote to, and what it looked like either side of the call.
     *
     * Recorded rather than asserted inline. [fuzz] is reached through the instance `by lazy`
     * [measured], shared across the tests that touch it, so an assertion inside the loop would
     * redden whichever test initialises the lazy first rather than the one that owns the claim —
     * and it would make [writesToItsArguments], the control that proves the detector inspects
     * anything at all, unrunnable through the same code.
     */
    private class Mutation(val methodKey: String, val position: Int, val before: String, val after: String) {
        override fun toString(): String = "$methodKey#$position: $before -> $after"
    }

    /** What the detector saw over one call: what moved, and how each position was compared. */
    private class Detected(
        val mutations: List<Mutation>,
        /** `methodKey#index` to the [snapshot] strategy that position was compared under. */
        val strategies: Map<String, String>,
        /**
         * The classes actually reported under [IMMUTABLE], read off the arguments.
         *
         * [snapshot]'s immutable branch, [strategyFor]'s and [IMMUTABLE_PROTOCOL_TYPES] are three
         * hand-kept lists, and the reflection walk that makes "immutable" a checked claim reads
         * only the third. Dropping a type from it would silently remove the only thing behind
         * seven of the seventeen promises while the strategy was still reported. This is what ties
         * them together.
         */
        val immutableTypes: Set<Class<*>>,
    )

    /**
     * A copy of [value] deep enough to notice a write, **one level into the container and no
     * further** — the whole trick of this detector, and the thing a naive version gets wrong.
     *
     * [Entry], `Map`, `Set`, `List` and `ByteArray` already have structural (or content) equality,
     * so what defeats a naive check is snapshotting a *reference* rather than a copy:
     * `LinkedHashMap(map) == map` after the call is sufficient, and a plain `map` is not. A data
     * class's generated `copy()` is not a snapshot either — `Entry.copy()` shares the same `fields`
     * object (`Entry.kt:62`), so an [Entry] whose field map was written to would stay `==` to its
     * own snapshot, and five of the published promises this file censuses are [Entry]-typed.
     *
     * **One level, and never into the [TypedField], which is what keeps this null-safe.** The field
     * maps and entries this run draws carry genuine `null`s on purpose — [hostileFields] always
     * inserts a null [TypedField] and [hostileNames] and [hostileRequirements] can hold null
     * elements — so a per-element deep copy would die *inside* [fuzz] and take every other test
     * that reads [measured] with it, before any assertion ran. A shallow copy
     * never dereferences a value. The [Entry] branch dereferences only `id`, `fields` and
     * `publicKey`, which [hostileEntry] always supplies non-null; the nulls are inside the map.
     *
     * Three strategies, named by [strategyFor] and reported per promise by the census:
     *
     * - **copy** — a real one-level copy, so a write is visible.
     * - **immutable** — the type has no mutable state at all, so the promise cannot be broken.
     *   Seven of the seventeen promises the census finds rest on this, so
     *   [IMMUTABLE_PROTOCOL_TYPES] is walked by reflection rather than taken on trust.
     * - **identity** — no meaningful snapshot exists. Only [Context] and [SecureRandom], neither of
     *   which is a trust boundary; the census refuses any promise that rests on this alone.
     *
     * Unknown types throw rather than falling through to identity: a parameter type with mutable
     * state snapshotted by reference would make the detector silently blind to it. Because this
     * runs *before* each call and [strategyFor] runs after, a new type is stopped here first, so
     * the two tables cannot drift.
     */
    private fun snapshot(value: Any?): Any? = when (value) {
        null -> null
        is Context, is SecureRandom -> value
        is String, is Long, is Int, is Boolean, is TypedField, is RotationStatement,
        is RecoveryAuthorization, is Revocation, is QueryRequest,
        -> value

        is ByteArray -> value.copyOf()
        is Entry -> entryView(value)
        is ShareRequest -> listOf(entryView(value.entry), value.requestCode, value.protocolVersion)
        is SignChallengeRequest -> value.copy(nonce = value.nonce.copyOf())
        is FieldRequirements -> FieldRequirements(value.fieldNames, value.optionalFields)
        is Intent -> extrasOf(value)
        is Map<*, *> -> ordered(value)
        is Set<*> -> value.toList()
        is List<*> -> ArrayList(value)
        else -> throw AssertionError(
            "no snapshot strategy for parameter type ${value.javaClass.name} — add one " +
                "deliberately. A type with mutable state snapshotted by reference stays equal to " +
                "itself after a write, which makes this detector blind to exactly the promise it " +
                "exists to check",
        )
    }

    /** See [snapshot]. Mirrors its table; a type it has no branch for never reaches here. */
    private fun strategyFor(value: Any?): String = when (value) {
        // Its own name, not `immutable`: a position only ever handed `null` is a comparison that
        // cannot fail, and the census must be able to tell that apart from a type whose
        // immutability [IMMUTABLE_PROTOCOL_TYPES] actually checked. Unreachable from `valueFor`,
        // which owns the non-null half of the surface — `NullArgumentTest` owns the other.
        null -> ABSENT
        is Context, is SecureRandom -> IDENTITY
        is ByteArray, is Entry, is ShareRequest, is SignChallengeRequest, is FieldRequirements,
        is Intent, is Map<*, *>, is Set<*>, is List<*>,
        -> COPY

        else -> IMMUTABLE
    }

    /**
     * An intent's extras, value-level — the only route a snapshot can take.
     *
     * [UnreadableIntent] throws `BadParcelableException` out of `getStringExtra`, so reading an
     * extra the way `describeIntent` does would die here. `Intent.getExtras()` is not overridden
     * and neither is `Bundle.getString`, so this route survives it — and unlike a key-set
     * comparison it can see a changed extra *value*, which is what the aliasing half below is
     * about.
     *
     * **Two things it cannot see, both stated.** `Bundle.getString` answers `null` for a non-String
     * extra, so one non-String extra replaced by another reads as `null` either side; nothing in
     * this protocol writes one, every drawn extra is a String, and the aliasing half proves the key
     * it compares carries a value before comparing it. And an [UnreadableIntent] built with no
     * extras — which is the shape [intentFor] draws — has a null `extras` and so snapshots as the
     * empty map either side; the census test feeds one *with* an extra, which is where the claim
     * about this route rather than `getStringExtra` is actually pinned.
     *
     * `getExtras()` returns a fresh `Bundle` copy per call on Android, so reading it before and
     * after is a genuine value comparison and not two views of one object.
     */
    private fun extrasOf(intent: Intent): Map<String, String?> {
        val extras = intent.extras ?: return emptyMap()
        return extras.keySet().associateWith { extras.getString(it) }
    }

    private fun snapshotsOf(args: List<Any?>, skip: Set<Int>): List<Any?> =
        args.mapIndexed { index, value -> if (index in skip) null else snapshot(value) }

    /**
     * The other half of the detector: what [snapshotsOf] recorded, against what is there now.
     *
     * Called from three places — [fuzz], the [FieldRequirements] arm of the census, and the
     * [writesToItsArguments] control — so all three see the same comparison and the control really
     * does exercise the code the pass rests on.
     */
    private fun compare(
        methodKey: String,
        args: List<Any?>,
        snapshots: List<Any?>,
        skip: Set<Int>,
    ): Detected {
        val mutations = mutableListOf<Mutation>()
        val strategies = linkedMapOf<String, String>()
        val immutableTypes = linkedSetOf<Class<*>>()
        args.forEachIndexed { index, value ->
            if (index in skip) return@forEachIndexed
            val strategy = strategyFor(value)
            strategies["$methodKey#$index"] = strategy
            if (strategy == IMMUTABLE && value != null) immutableTypes += value.javaClass
            if (!unchanged(snapshots[index], value)) {
                mutations += Mutation(
                    methodKey,
                    index,
                    renderChange(snapshots[index]),
                    renderChange(nowView(value)),
                )
            }
        }
        return Detected(mutations, strategies, immutableTypes)
    }

    /** Snapshot against live value, by content where the type has no structural equality. */
    private fun unchanged(snapshot: Any?, now: Any?): Boolean =
        if (now is ByteArray) {
            // Arrays compare by identity under `==`, so a copy would never equal its original and
            // the detector would report a false mutation at every byte-array position — 222 of
            // them, over 23 distinct positions, when that was measured. Control (b). (Counted off
            // the HTML report: the JUnit XML carries a failure message twice, once as an
            // attribute and once as element text, so grepping it doubles the figure. This task is
            // about a count nobody checked; the first draft of this comment said 444.)
            snapshot is ByteArray && snapshot.contentEquals(now)
        } else {
            snapshot == nowView(now)
        }

    /**
     * The post-call reading [unchanged] compares against, in the shape [snapshot] produced.
     *
     * Written once and shared with [renderChange], so what a mutation report prints either side of
     * its arrow is the very thing that was compared rather than a second opinion of it.
     */
    private fun nowView(value: Any?): Any? = when (value) {
        is Intent -> extrasOf(value)
        is Entry -> entryView(value)
        is ShareRequest -> listOf(entryView(value.entry), value.requestCode, value.protocolVersion)
        is Map<*, *> -> ordered(value)
        is Set<*> -> value.toList()
        else -> value
    }

    /**
     * Enough of a changed argument to find the call again, escaped and capped by [printable]: a
     * corpus vector can hold a 16 KB string, and a failure message is for locating the call rather
     * than for reading the payload back out.
     *
     * One thinness worth naming: [TypedField.toString] redacts its value, so a mutation that
     * changed only a field's *value* renders identically either side of the arrow. Detection is
     * unaffected — the comparison is over the values, not over this rendering — and the method key
     * and position are what a reader needs. Printing the value instead would make a redaction this
     * library exists for into a test-log leak.
     */
    private fun renderChange(value: Any?): String = printable(
        when (value) {
            // `describe` prints an array as its length alone, which would render a mutated byte
            // array identically either side of the arrow.
            is ByteArray -> value.toList().toString()
            else -> describe(value)
        },
    )

    /**
     * A map or set read **in order**, which is what the comparison needs and `==` does not give.
     *
     * `==` on two maps or two sets is order-insensitive, and insertion order is part of what this
     * library promises: `encodeFields`/`decodeFields` pin it on the JSON side and `Entry`'s own
     * `Parceler` pins it on the other. A callee that reordered a caller's `LinkedHashMap` in place
     * has modified it in the way that matters, and under plain `==` the detector would not notice.
     * An untouched map iterates identically whatever its implementation, so this adds no false
     * positive. For maps and sets, which have no duplicate keys or elements, the ordered reading
     * is strictly stronger than equality and replaces it rather than joining it.
     */
    private fun ordered(map: Map<*, *>): List<Pair<Any?, Any?>> = map.map { it.key to it.value }

    /**
     * An [Entry] as the detector reads it: its three slots, with the field map's order kept.
     *
     * A projection rather than a copy of the class, and that is deliberate. All three of an
     * [Entry]'s properties are declared non-null and are **genuinely nullable at runtime** — the
     * Gson/`Unsafe` hazard `Utils.decodeEntry` documents, which `Utils.kt:2866` reads through a
     * nullable local for exactly this reason. Rebuilding an `Entry` would put those values back
     * through a constructor that null-checks them, so a vector planting a null-slotted entry
     * would die inside the shared `by lazy` with an NPE and take every test reading [measured]
     * with it. A list cannot.
     */
    private fun entryView(entry: Entry): List<Any?> {
        val fields: Map<String, TypedField>? = entry.fields
        return listOf(entry.id, entry.publicKey, fields?.let(::ordered))
    }

    /**
     * A function that **does** write to its arguments — the negative control, kept as a fixture
     * rather than probed and reverted.
     *
     * Without it the detector could be reporting nothing because it inspects nothing, which is the
     * failure mode a census-shaped test has. It is also why [fuzz] *records* rather than asserts:
     * a fixture that deliberately mutates has to be runnable through the same code.
     *
     * The casts are what a Java caller gets for free, and every position is written so that the
     * control covers each strategy that can detect anything: a copied container, an array compared
     * by content, a set, and — because five of the seventeen promises are [Entry]-typed, and
     * [entryView] is the one projection that reaches a container *inside* another object — an
     * [Entry] whose field map is written through.
     */
    @Suppress("UNCHECKED_CAST")
    private fun writesToItsArguments(
        fields: Map<String, TypedField>,
        bytes: ByteArray,
        names: Set<String>,
        entry: Entry,
    ) {
        (fields as MutableMap<String, TypedField>)["written-by-the-control"] =
            TypedField(value = "x", type = FieldType.STRING)
        bytes[0] = (bytes[0] + 1).toByte()
        (names as MutableSet<String>) += "written-by-the-control"
        (entry.fields as MutableMap<String, TypedField>)["written-by-the-control"] =
            TypedField(value = "x", type = FieldType.STRING)
    }

    /**
     * A function that writes **nothing but the order** of its argument — content identical,
     * iteration order changed.
     *
     * The other half of [ordered]'s reason for existing. Under plain `==` a reordered map is equal
     * to its own snapshot, so without this the order-sensitive comparison could be removed and
     * every assertion in this file would stay green: [writesToItsArguments] changes content as
     * well as order and so cannot tell the two designs apart.
     */
    private fun reordersItsArgument(fields: MutableMap<String, TypedField>) {
        val first = fields.keys.first()
        fields.remove(first)?.let { fields[first] = it }
    }

    // ── Enumeration ──────────────────────────────────────────────────────

    /**
     * The audit's own filter, `PublicApiAuditTest:456`, which explains why the `$default` bridges
     * carrying default-argument values must go — nobody writes against them and they move with the
     * compiler — and why the `@JvmOverloads` arities must stay, since each is separately callable
     * from Java and each is therefore separately reachable with hostile data.
     *
     * Spelled out rather than shared, `NullArgumentTest`'s reasoning: it is private to that class,
     * and widening a test's visibility to borrow a one-line predicate buys less than the citation
     * does. A divergence cannot hide for long — it surfaces as a method this file has no vector for
     * or as the audit's own signature snapshot moving.
     */
    private fun Method.isPublishedApi(): Boolean =
        Modifier.isPublic(modifiers) && !isSynthetic && !isBridge

    /** `isNonceFresh(byte[], long)`, as the audit's snapshot spells it — arity included. */
    private fun methodKey(method: Method): String =
        "${method.name}(${method.genericParameterTypes.joinToString(", ", transform = ::render)})"

    /** `PublicApiAuditTest:1172`'s renderer, so a key here reads like a line of that snapshot. */
    private fun render(type: Type): String = PACKAGE_QUALIFIER.replace(type.typeName, "")

    private val publishedMethods: List<Method> = Utils::class.java.declaredMethods
        .filter { it.isPublishedApi() }
        .sortedBy(::methodKey)

    // ── The run ──────────────────────────────────────────────────────────

    /** One call, and everything that came back out of it. */
    private class Call(
        val methodKey: String,
        val args: List<Any?>,
        val returned: Any?,
        val thrown: Throwable?,
    )

    private class Run(
        val published: List<String>,
        val invoked: List<String>,
        /** Method key to the parameter type the provider has no vector for. */
        val uncovered: Map<String, String>,
        val calls: List<Call>,
        /** Reference positions, and the subset that was ever handed a trust-boundary value. */
        val referencePositions: Set<String>,
        val hostilePositions: Set<String>,
        /** `String` positions handed exactly `""` and exactly a one-character string. */
        val emptyStringPositions: Set<String>,
        val oneCharStringPositions: Set<String>,
        val intentShapesUsed: Set<String>,
        /**
         * What actually arrived at a position, by type: the three reach controls. Read off the
         * arguments rather than off the provider, so a draw that silently stopped varying is
         * caught by the corpus it stopped covering.
         */
        val textsDrawn: Set<String>,
        val byteVectorsDrawn: Set<List<Byte>>,
        val longsDrawn: Set<Long>,
        val nullBearingLists: Int,
        val mixedFieldMaps: Int,
        /** Every argument this run found changed across its own call. See [snapshot]. */
        val mutations: List<Mutation>,
        /** `methodKey#index` to the snapshot strategy it was compared under. */
        val strategies: Map<String, String>,
        /** Snapshot-against-live comparisons made, which [strategies] collapses by position. */
        val comparisons: Int,
        /** See [Detected.immutableTypes]. */
        val immutableTypes: Set<Class<*>>,
        val elapsedMillis: Long,
    )

    /**
     * One loop, every answer: each property below is a *reading* of this run rather than a run of
     * its own. Written as separate loops they would be separate enumerations agreeing by
     * construction, and a method dropped by one filter would simply vanish from that property's
     * report instead of failing it.
     *
     * **What actually happens, stated rather than implied:** this is an instance `by lazy` and
     * JUnit 4 constructs a fresh test-class instance per `@Test`, so [fuzz] runs once for each of
     * the tests that touch it — five of the nine, ~15ms apiece. (It said "four of the seven" until
     * T61, which is the hazard of counting siblings in prose: the four was still right and the
     * seven had been wrong for two tasks.) They are the same enumeration
     * because
     * the run is deterministic and for no other reason: one fixed seed, [publishedMethods] sorted
     * by key, [limExtraKeys] sorted by field name.
     *
     * **What is deterministic is every argument, which is narrower than the whole loop and is the
     * part that matters.** The loop does reach a clock and an entropy source — `generateNonce` is
     * handed the real [entropy], and the published two-arity `isNonceFresh` defaults its `now` to
     * `System.currentTimeMillis()` — so the *return values* of those two calls differ between
     * runs. Nothing reads them: neither is in [AUTHENTICATION_ANSWERS], and a `ByteArray` or a
     * freshness `Boolean` is neither `true` from `verifySignature` nor `VALID`. The claim is
     * therefore that no drawn argument and no assertion depends on either, and that is what is
     * load-bearing rather than incidental: feed a `SecureRandom` draw into a *vector*, or leave an
     * enumeration unsorted, and the properties below become readings of four different runs,
     * which is the thing this comment says they are not.
     */
    private val measured: Run by lazy { fuzz() }

    private fun fuzz(): Run {
        val startedAt = System.nanoTime()
        val rnd = Random(MASTER_SEED)
        val invoked = mutableListOf<String>()
        val uncovered = linkedMapOf<String, String>()
        val calls = mutableListOf<Call>()
        val referencePositions = linkedSetOf<String>()
        val hostilePositions = linkedSetOf<String>()
        val emptyStringPositions = linkedSetOf<String>()
        val oneCharStringPositions = linkedSetOf<String>()
        val intentShapesUsed = linkedSetOf<String>()
        val textsDrawn = linkedSetOf<String>()
        val byteVectorsDrawn = linkedSetOf<List<Byte>>()
        val longsDrawn = linkedSetOf<Long>()
        var nullBearingLists = 0
        var mixedFieldMaps = 0
        val mutations = mutableListOf<Mutation>()
        val strategies = linkedMapOf<String, String>()
        val immutableTypes = linkedSetOf<Class<*>>()
        var comparisons = 0

        for (method in publishedMethods) {
            val key = methodKey(method)
            val types = method.genericParameterTypes
            if (key in NOT_FUZZABLE) continue

            val uncoverable = types.firstOrNull { !covered(it) }
            if (uncoverable != null) {
                uncovered[key] = render(uncoverable)
                continue
            }

            fun draw(): Array<Any?> = Array(types.size) { valueFor(types[it], rnd) }

            val vectors = mutableListOf<Array<Any?>>()
            repeat(DRAWS) { vectors += draw() }
            // The floor that makes the second plant in this task's text lethal. A one-character-off
            // bug — `text.substring(3)` — is only reachable if a string shorter than three
            // characters actually *reaches* a `String` position, and with a handful of draws per
            // method a corpus that merely contains such strings does not guarantee it. So each
            // `String` position is handed them outright, and `the fuzz reaches every hostile
            // position` asserts afterwards that it was.
            types.forEachIndexed { index, type ->
                if (type != String::class.java) return@forEachIndexed
                STRING_FLOOR.forEach { floored ->
                    vectors += draw().also { it[index] = floored }
                }
            }

            // Primitive positions are excluded from the detector for the reason they are excluded
            // from the position sets: a `long` cannot be written to through a parameter.
            val primitives = types.indices
                .filter { (types[it] as? Class<*>)?.isPrimitive == true }
                .toSet()

            vectors.forEach { args ->
                args.forEachIndexed { index, value ->
                    val position = "$key#$index"
                    // Recorded before the primitive guard, because a `long` position is exactly
                    // the one no position set can see: primitives are excluded from the sets
                    // below, so without this the whole of `corpusLongs` could stop varying with
                    // every assertion in this file still green.
                    if (value is Long) longsDrawn += value
                    if (value is ByteArray) byteVectorsDrawn += value.toList()
                    if ((types[index] as? Class<*>)?.isPrimitive == true) return@forEachIndexed
                    referencePositions += position
                    // Read off the value that was actually passed rather than off the type table,
                    // so a provider that silently started handing a benign value to a hostile
                    // position fails here instead of agreeing with itself.
                    if (value !is Context && value !is SecureRandom) hostilePositions += position
                    if (value == "") emptyStringPositions += position
                    if (value is String && value.length == 1) oneCharStringPositions += position
                    if (value is String) textsDrawn += value
                    if (value is Intent) {
                        intentShapesUsed += if (value is UnreadableIntent) {
                            "unreadable"
                        } else {
                            limExtraKeys.filter { value.hasExtra(it) }.let { present ->
                                when {
                                    present.size == limExtraKeys.size -> "all"
                                    present.size == 1 -> "one:${present.single()}"
                                    else -> "unexpected:${present.size}"
                                }
                            }
                        }
                    }
                    if (value is List<*> && value.any { it == null }) nullBearingLists++
                    // The mixed shape specifically — a genuine value beside a genuine null — and
                    // not merely "a map arrived". That is the shape `validateEntry` documents,
                    // and a `hostileFields` whose two keys collided would quietly stop producing
                    // it while every other assertion here stayed green.
                    if (value is Map<*, *> && value.any { it.value == null } &&
                        value.any { it.value != null }
                    ) {
                        mixedFieldMaps++
                    }
                }
                // The detector. Taken off the vectors already drawn and containing no `Random`
                // call, so the draw sequence above cannot move — see the new census test, which
                // prints `textsDrawn`, `byteVectorsDrawn` and `longsDrawn` as the proof of that.
                val snapshots = snapshotsOf(args.toList(), primitives)
                calls += call(method, key, args)
                val detected = compare(key, args.toList(), snapshots, primitives)
                mutations += detected.mutations
                strategies += detected.strategies
                immutableTypes += detected.immutableTypes
                comparisons += detected.strategies.size
            }
            invoked += key
        }

        return Run(
            published = publishedMethods.map(::methodKey).sorted(),
            invoked = invoked.sorted(),
            uncovered = uncovered,
            calls = calls,
            referencePositions = referencePositions,
            hostilePositions = hostilePositions,
            emptyStringPositions = emptyStringPositions,
            oneCharStringPositions = oneCharStringPositions,
            intentShapesUsed = intentShapesUsed,
            textsDrawn = textsDrawn,
            byteVectorsDrawn = byteVectorsDrawn,
            longsDrawn = longsDrawn,
            nullBearingLists = nullBearingLists,
            mixedFieldMaps = mixedFieldMaps,
            mutations = mutations,
            strategies = strategies,
            comparisons = comparisons,
            immutableTypes = immutableTypes,
            elapsedMillis = (System.nanoTime() - startedAt) / 1_000_000,
        )
    }

    /**
     * Invoke and report, unwrapping before classifying.
     *
     * `InvocationTargetException` is reflection's wrapper, not the finding: `targetException` is
     * what a direct Java call at this site would catch. An `IllegalArgumentException` from `invoke`
     * itself is deliberately *not* caught — that means the vector is ill-typed, which is a bug in
     * this file and must be loud rather than reported as a library failure.
     */
    private fun call(method: Method, key: String, args: Array<Any?>): Call = try {
        Call(key, args.toList(), method.invoke(Utils, *args), null)
    } catch (e: InvocationTargetException) {
        Call(key, args.toList(), null, e.targetException)
    }

    /** Enough of an argument to find the failure again, with everything unprintable escaped. */
    private fun describe(value: Any?): String = when (value) {
        is String -> "\"${printable(value)}\""
        is ByteArray -> "bytes[${value.size}]"
        is Intent ->
            if (value is UnreadableIntent) {
                "UnreadableIntent"
            } else {
                "Intent extras=${value.extras?.keySet()}"
            }

        is List<*> -> "[${value.joinToString { if (it == null) "null" else it.toString() }}]"
        else -> value.toString()
    }

    private fun printable(text: String): String {
        val capped = text.take(PAYLOAD_PREVIEW)
        val escaped = buildString(capped.length) {
            capped.forEach { c ->
                if (c in ' '..'~') {
                    append(c)
                } else {
                    append("\\u")
                    append(HEX[(c.code shr 12) and 0xF])
                    append(HEX[(c.code shr 8) and 0xF])
                    append(HEX[(c.code shr 4) and 0xF])
                    append(HEX[c.code and 0xF])
                }
            }
        }
        return if (text.length > PAYLOAD_PREVIEW) {
            "$escaped... (+${text.length - PAYLOAD_PREVIEW} more chars)"
        } else {
            escaped
        }
    }

    private fun report(call: Call, what: String): String = buildString {
        append(what).append('\n')
        append("  masterSeed = ").append(MASTER_SEED).append("L\n")
        append("  method     = ").append(call.methodKey).append('\n')
        call.args.forEachIndexed { index, value ->
            append("  arg#").append(index).append("     = ").append(describe(value)).append('\n')
        }
        append("  returned   = ").append(call.returned)
    }

    // ── Property one: nothing throws ─────────────────────────────────────

    /** `shareEntry/java.lang.SecurityException`, the key [TOLERATED] is written in. */
    private fun toleratedKey(call: Call): String =
        "${call.methodKey.substringBefore('(')}/${call.thrown!!.javaClass.name}"

    @Test
    fun `no published entry point throws on a hostile argument`() {
        val escaped = measured.calls
            .filter { it.thrown != null }
            .filterNot { toleratedKey(it) in TOLERATED }
            .map {
                val thrown = it.thrown!!
                report(it, "${it.methodKey} threw ${thrown.javaClass.name}: ${thrown.message}")
            }

        assertEquals(
            "a published function threw on a value another app can choose. Everything this " +
                "library decodes arrived across IPC from an app it does not control, so \"I " +
                "could not read this\" has to be an answer rather than a crash — fix the " +
                "function, or document the throw and add it to TOLERATED with its reason",
            emptyList<String>(),
            escaped,
        )

        // What the allow-list actually excused — asserted, not printed. The assertion above says
        // "no *undocumented* throw", and on its own that is satisfied by a function throwing a
        // documented exception the KDoc claims is unreachable here. This pins the second half:
        // today nothing in TOLERATED fires at all. If a tolerated exception ever does become
        // reachable from a hostile vector, this is the line to record it on, deliberately, with
        // the measurement in hand.
        val fired = measured.calls.filter { it.thrown != null }.map(::toleratedKey).toSet()
        assertEquals(
            "a tolerated exception fired. TOLERATED's one entry is documented as unreachable " +
                "under Robolectric — which installs no vault, so shareEntry answers false before " +
                "it starts anything — and a throw getting this far means either that stopped " +
                "being true or the allow-list is excusing something new",
            emptySet<String>(),
            fired,
        )

        // Non-vacuity: `filter { thrown != null }` over an empty run is also empty.
        assertTrue(
            "no call was made at all, so this property passed over nothing; got " +
                "${measured.calls.size}",
            measured.calls.size > 200,
        )
    }

    // ── Property two: no positive authentication answer ──────────────────

    @Test
    fun `no hostile argument earns a positive authentication answer`() {
        val accepted = measured.calls.filter { it.thrown == null }.mapNotNull { call ->
            when {
                call.methodKey.startsWith("verifySignature(") && call.returned == true ->
                    report(call, "verifySignature ACCEPTED a hostile argument vector")

                call.returned == StatementVerdict.VALID ->
                    report(call, "${call.methodKey} returned VALID on a hostile argument vector")

                else -> null
            }
        }

        assertEquals(
            "a hostile vector authenticated. None of these inputs was signed by anybody: a " +
                "`true` here is a service logging in an attacker, and a VALID is one moving a " +
                "user's account onto a key of the attacker's choosing or cancelling the recovery " +
                "device the user is relying on",
            emptyList<String>(),
            accepted,
        )

        // Non-vacuity, and it has to be per-function: a single count would be satisfied by one
        // verifier running and the other three being skipped.
        val answered = measured.calls
            .filter { it.returned is Boolean || it.returned is StatementVerdict }
            .groupingBy { it.methodKey.substringBefore('(') }
            .eachCount()
        AUTHENTICATION_ANSWERS.forEach { name ->
            assertTrue(
                "$name produced no answer at all, so \"never positive\" is a claim about " +
                    "nothing; got $answered",
                (answered[name] ?: 0) > 0,
            )
        }
    }

    // ── Property three: the one prose could never enforce ────────────────

    /**
     * **The set of methods actually invoked must equal the published set**, minus the members
     * [NOT_FUZZABLE] excuses by name.
     *
     * A public function added later is then fuzzed, or excluded on purpose by somebody who wrote
     * down why. Both failure directions matter: a member on the left of this comparison and not
     * the right is a published entry point no hostile value has ever reached, and one on the right
     * and not the left is a stale excuse — a member removed or renamed, which is stop rule 10.
     */
    @Test
    fun `every published method is fuzzed or excused by name`() {
        assertEquals(
            "the fuzzed set is not the published set. A member missing from the right was " +
                "published without a hostile-value vector: either add one to `valueFor` for the " +
                "parameter type it introduced, or excuse it in NOT_FUZZABLE with a reason and " +
                "the test that covers it instead. Parameter types the provider has no vector " +
                "for: ${measured.uncovered}",
            (measured.published - NOT_FUZZABLE.keys).sorted(),
            measured.invoked,
        )

        // The other direction, which the comparison above cannot make: an excuse naming a member
        // that no longer exists reads as coverage and is not.
        assertEquals(
            "NOT_FUZZABLE names members reflection cannot find. A renamed or removed public " +
                "member breaks apps compiled against 1.0.0 — see stop rule 10 — and either way " +
                "the excuse must move with it",
            emptyList<String>(),
            (NOT_FUZZABLE.keys - measured.published.toSet()).sorted(),
        )
    }

    /**
     * The excuses' *values*, machine-checked — `PublicApiAuditTest:513`'s question asked of this
     * file's own waivers.
     *
     * "The test that covers this member instead" is the whole of what an excuse rests on, and the
     * failure mode is an excuse naming a test that does not exist, was renamed, or lives in
     * another class than the citation claims. Keyed by class *and* method for the reason the audit
     * gives: matching the method name alone would let a citation resolve to a real test in the
     * wrong file, which is precisely the mis-attribution a waiver must not make.
     *
     * The classes are named rather than enumerated off the classpath, which is what lets this be
     * nine lines instead of the audit's forty: a citation that names a class reflection cannot
     * load fails here as surely as one naming a method that is not there.
     */
    @Test
    fun `every NOT_FUZZABLE entry names a test that exists`() {
        val dangling = NOT_FUZZABLE.entries.mapNotNull { (member, excuse) ->
            val className = excuse.coveredBy.substringBefore(": ")
            val testName = excuse.coveredBy.substringAfter(": ")
            val resolved = runCatching {
                Class.forName("dev.eryalabs.lim.$className").declaredMethods.any {
                    it.name == testName && it.isAnnotationPresent(Test::class.java)
                }
            }.getOrDefault(false)
            if (resolved) null else "$member -> ${excuse.coveredBy}"
        }.sorted()

        assertEquals(
            "a NOT_FUZZABLE entry cites a @Test that does not exist under the class it names. A " +
                "renamed or moved test must be updated here too, or the member it excused is " +
                "silently neither fuzzed nor covered",
            emptyList<String>(),
            dangling,
        )

        // Non-vacuity: `mapNotNull` over an empty map is also empty, and a `runCatching` that
        // swallowed everything would report every citation as resolved.
        assertTrue("no excuse was stated, so this proves nothing", NOT_FUZZABLE.isNotEmpty())
        assertTrue(
            "the resolver must be able to fail, or it is reporting success unconditionally",
            runCatching {
                Class.forName("dev.eryalabs.lim.NonceTest").declaredMethods.any {
                    it.name == "a test nobody wrote" && it.isAnnotationPresent(Test::class.java)
                }
            }.getOrDefault(false).not(),
        )
        assertTrue(
            "…and it must be able to succeed on a citation of the shape used above",
            Class.forName("dev.eryalabs.lim.NonceTest").declaredMethods.any {
                it.name == "the default random and clock produce a fresh nonce" &&
                    it.isAnnotationPresent(Test::class.java)
            },
        )
        assertEquals(
            "every excuse must carry a reason as well as a citation",
            emptyList<String>(),
            NOT_FUZZABLE.filterValues { it.reason.isBlank() }.keys.sorted(),
        )
    }

    // ── Floors ───────────────────────────────────────────────────────────

    @Test
    fun `the fuzz reaches every hostile position, and the string floors specifically`() {
        println(
            "PublishedSurfaceFuzzTest: published=${measured.published.size} " +
                "fuzzed=${measured.invoked.size} notFuzzable=${NOT_FUZZABLE.size} " +
                "calls=${measured.calls.size} positions=${measured.referencePositions.size} " +
                "elapsed=${measured.elapsedMillis}ms",
        )

        // Every reference position was handed a trust-boundary value at least once — except the
        // ones stated as benign, which must be exactly the stated set. Both directions are real:
        // a new `Context` parameter appears here until somebody looks at it, and a position that
        // stopped being fuzzed appears here too.
        assertEquals(
            "the positions never handed a hostile value are not the stated benign ones. A " +
                "position on the left was fuzzed after all, so the entry is stale; one on the " +
                "right is a published parameter that no hostile value has ever reached",
            BENIGN_POSITIONS,
            (measured.referencePositions - measured.hostilePositions).sorted().toSet(),
        )

        // The two floors, asserted rather than offered. What they pin is that the floor *loop*
        // still exists and still lands on the position it names: the values are injected rather
        // than drawn, so these cannot catch a provider that stopped fuzzing `String` — `every
        // corpus string must reach some position`, below, is what catches that. What they do catch
        // is the floor being removed, mis-indexed, or quietly outgrown by a method added later,
        // and without them a one-character-off bug in a published function is reachable only by
        // luck: with a handful of draws per method, a corpus that merely *contains* short strings
        // does not guarantee one arrives anywhere in particular.
        val stringPositions = measured.referencePositions.filter { position ->
            val method = publishedMethods.single { methodKey(it) == position.substringBefore('#') }
            method.genericParameterTypes[position.substringAfter('#').toInt()] == String::class.java
        }.toSet()
        assertTrue(
            "no String position was enumerated, so the two floors below assert nothing",
            stringPositions.size > 15,
        )
        assertEquals(
            "every String position must be handed the empty string at least once; a length or " +
                "index bug is reachable from nowhere else",
            emptySet<String>(),
            stringPositions - measured.emptyStringPositions,
        )
        assertEquals(
            "…and a one-character string, which is what makes an off-by-two index bug reachable",
            emptySet<String>(),
            stringPositions - measured.oneCharStringPositions,
        )

        // The breadth floor. Stated as a minimum rather than as the exact count so that adding a
        // published member does not fail here — `every published method is fuzzed or excused by
        // name` is what notices that — while a filter drifting towards the empty set does.
        assertTrue(
            "only ${measured.published.size} published methods found, floor " +
                "$MINIMUM_PUBLISHED — the filter has drifted and every assertion in this file " +
                "is passing over nothing",
            measured.published.size >= MINIMUM_PUBLISHED,
        )

        // A cap, not a floor, and the only one in this file: excusing the surface wholesale is the
        // lazy path out of this task, so the excuses may never outnumber a third of the surface.
        assertTrue(
            "NOT_FUZZABLE excuses ${NOT_FUZZABLE.size} of ${measured.published.size} published " +
                "methods, which is more than a third. Each entry may be individually reasonable " +
                "and the set still be a way of not doing this",
            NOT_FUZZABLE.size * 3 <= measured.published.size,
        )

        // Every vector shape the provider can build must actually have been built, or the table
        // in `valueFor` describes a corpus this run did not use.
        assertEquals(
            "every intent shape must be fuzzed: each LIM extra in turn, all of them at once, " +
                "and the unreadable intent",
            intentShapes.toSet(),
            measured.intentShapesUsed,
        )
        assertTrue(
            "the extra keys must be read off Utils, not an empty reflection result; got " +
                "$limExtraKeys",
            limExtraKeys.size >= 10,
        )
        // The three reach controls, one per corpus-fed type, and they are the only thing that
        // stops a draw from quietly collapsing to a constant. Every other assertion in this file
        // survives `String::class.java -> "a fixed string"` or `long(rnd) -> 0L`: the position
        // sets record that *a* value arrived, the throw and authentication properties are
        // satisfied by a benign one, and the digest pins the corpus's contents rather than its
        // use. These compare what the corpus holds against what actually reached an argument.
        assertEquals(
            "every corpus string must reach some String position, else it is decoration",
            emptySet<String>(),
            corpusText.toSet() - measured.textsDrawn,
        )
        assertEquals(
            "…every corpus entry must reach a ByteArray position too, since that is where " +
                "isStatementPreImage and nonceTimestamp get the whole of their input",
            emptySet<List<Byte>>(),
            corpusText.map { it.toByteArray().toList() }.toSet() - measured.byteVectorsDrawn,
        )
        assertEquals(
            "…and every corpus long must reach a long position: the saturating bounds are the " +
                "whole point of that list — an authorization at Long.MAX_VALUE is permanently " +
                "unrevocable — and a primitive position is in no position set, so nothing else " +
                "here would notice",
            emptySet<Long>(),
            corpusLongs.toSet() - measured.longsDrawn,
        )
        assertTrue(
            "no list carrying a null element was drawn, so the case `isRevoked` and " +
                "`liveAuthorizations` both document is never exercised",
            measured.nullBearingLists > 0,
        )
        assertTrue(
            "no field map carrying a genuine null *beside* a genuine value reached a position, " +
                "so the shape `validateEntry` documents is never exercised at a Map parameter",
            measured.mixedFieldMaps > 0,
        )
    }

    // ── FieldRequirements, member by member ──────────────────────────────

    /**
     * The one published type outside [Utils] whose methods take hostile input: a vault builds a
     * [FieldRequirements] out of names another app sent and then hands it the user's draft, and a
     * client hands it the fields a vault answered with. The enumeration above is of [Utils]'s
     * methods, so this arm calls every member of this one directly, over the same corpus, with its
     * own seed so that the draw sequence above is not moved by it.
     *
     * Nothing may throw, and four invariants must hold of whatever comes back: the optional set is
     * a subset of the declared names and the required set is the rest; `committed` is `null`
     * exactly when `missingRequired` is non-empty, and keeps only declared names when it is not;
     * and `toString` is counts and nothing else.
     */
    @Test
    fun `every FieldRequirements member survives hostile names and hostile drafts`() {
        val rnd = Random(MASTER_SEED xor 0x4652L)
        var committedSome = 0
        var refusedSome = 0
        val shape = Regex("""FieldRequirements\(fields=\d+, optional=\d+\)""")

        repeat(FIELD_REQUIREMENTS_DRAWS) { draw ->
            val requirements = hostileRequirements(rnd)
            val other = hostileRequirements(rnd)
            // Half the drafts are the corpus's own mixed field map; the other half answer the
            // declared names with corpus values, blanks included, which is what a vault's form
            // produces — without them a draft would almost never satisfy anything.
            val draft = if (draw % 2 == 0) {
                hostileFields(rnd)
            } else {
                requirements.fieldNames.associateWith { TypedField(text(rnd), text(rnd)) }
            }
            fun where() = "draw #$draw: $requirements over draft keys ${draft.keys.map(::printable)}"

            val outcome = runCatching {
                val names = requirements.fieldNames
                assertTrue(where(), names.toSet().containsAll(requirements.optionalFields))
                assertEquals(where(), names.toSet() - requirements.optionalFields, requirements.requiredFields)
                assertEquals(where(), names.distinct(), names)

                val missing = requirements.missingRequired(draft)
                val committed = requirements.committed(draft)
                assertEquals(where(), missing.isNotEmpty(), committed == null)
                if (committed == null) refusedSome++ else committedSome++
                committed?.keys?.forEach { assertTrue(where(), it in names) }
                requirements.isSatisfiedBy(draft)
                requirements.equals(other)
                requirements.hashCode()
                assertTrue(where(), shape.matches(requirements.toString()))
            }
            assertTrue("${where()} threw ${outcome.exceptionOrNull()}", outcome.isSuccess)
        }

        assertTrue("no draw committed, so the non-null half went unchecked", committedSome > 0)
        assertTrue("no draw was refused, so the null half went unchecked", refusedSome > 0)
    }

    // ── The census: who promised "Not modified", and who checked ─────────

    /** One rendered `@param` that promises [NOT_MODIFIED], and the member it is published on. */
    private class Promise(
        val owner: String,
        val line: Int,
        val member: String,
        val parameter: String,
        /** The parameter's index in its own declaration, which is the argument position. */
        val parameterIndex: Int,
        /**
         * How many parameters that declaration has — which is the arity of the JVM method it
         * compiles to, and the only way to tell two overloads apart by name.
         *
         * Without it the census would resolve a promise by name and position alone, and position 3
         * of `createShareIntent` is a `Set<String>` in one overload and a `String` in another. The
         * `@JvmOverloads` arities below the full one take no caller argument at that position at
         * all — they supply the default — so the declaration's own arity is the one to check.
         */
        val declarationArity: Int,
        /** True when no single source line carries the phrase — the naive grep misses these. */
        val wrapped: Boolean,
    ) {
        override fun toString(): String =
            "$owner.$member/$declarationArity(@param $parameter) at $owner.kt:$line"
    }

    /** A declaration as the census reads it: enough to say what it is called and who may call it. */
    private class Declaration(val name: String, val parameters: List<String>, val published: Boolean)

    /**
     * Every [NOT_MODIFIED] promise in one source, **built over the rendered `@param` text** rather
     * than line by line.
     *
     * That is the whole difficulty. The phrase wraps in two places today — `FieldRequirements`'
     * `committed` ends a line on "Not" and begins the next with "modified.", and so does
     * `Utils.encodeRevocation` — so a line-based count misses two of them, and a census that
     * missed them would wave through exactly the promises nobody had noticed. Continuation lines
     * are joined before matching, and both numbers are printed by the test below: what the naive
     * grep sees, and what the census finds.
     *
     * A `@param` ends at a blank doc line, at the next `@` tag, or at the end of the block, so the
     * prose some of these blocks carry *after* their parameter list is not attributed to the last
     * parameter.
     */
    private fun promisesIn(file: String, source: String): List<Promise> {
        val owner = file.removeSuffix(".kt")
        val lines = source.split("\n")
        val found = mutableListOf<Promise>()
        var index = 0
        while (index < lines.size) {
            if (!lines[index].trimStart().startsWith("/**")) {
                index++
                continue
            }
            var end = index
            while (end < lines.size && !lines[end].contains("*/")) end++
            val last = minOf(end, lines.size - 1)
            val declaration = declarationAfter(lines, last + 1)
            var cursor = index
            while (cursor <= last) {
                val tag = PARAM_TAG.find(lines[cursor])
                if (tag == null) {
                    cursor++
                    continue
                }
                val rendered = StringBuilder(tag.groupValues[2].trim())
                var tail = cursor + 1
                while (tail <= last) {
                    val body = DOC_BODY.find(lines[tail])?.groupValues?.get(1) ?: break
                    if (body.isBlank() || body.trimStart().startsWith("@")) break
                    rendered.append(' ').append(body.trim())
                    tail++
                }
                if (NOT_MODIFIED in rendered && declaration?.published != false) {
                    // A block this parser could not attribute is recorded as UNATTRIBUTABLE
                    // rather than dropped, so it lands in the census's `unreached` list and
                    // reddens. Dropping it would be the one failure a census must not have: the
                    // count would fall silently and the floor is well below it on purpose.
                    found += Promise(
                        owner = owner,
                        line = cursor + 1,
                        member = declaration?.name ?: UNATTRIBUTABLE,
                        parameter = tag.groupValues[1],
                        parameterIndex = declaration?.parameters?.indexOf(tag.groupValues[1]) ?: -1,
                        declarationArity = declaration?.parameters?.size ?: -1,
                        wrapped = (cursor until tail).none { NOT_MODIFIED in lines[it] },
                    )
                }
                cursor = tail
            }
            index = end + 1
        }
        return found
    }

    /**
     * The declaration a KDoc block documents: the first thing after it that is not blank, an
     * annotation or a comment.
     *
     * [Declaration.published] is read off the modifiers before the keyword, which is what makes
     * control (c) — a `Not modified` `@param` added to a *private* function — stay out of the
     * census. A block documenting nothing, or one whose declaration this parser cannot read,
     * returns `null`, and its promises are recorded under [UNATTRIBUTABLE] so they redden rather
     * than vanish — see [promisesIn].
     */
    private fun declarationAfter(lines: List<String>, from: Int): Declaration? {
        var index = from
        while (index < lines.size) {
            val trimmed = lines[index].trim()
            if (trimmed.isEmpty() || trimmed.startsWith("@") || trimmed.startsWith("//")) {
                index++
                continue
            }
            break
        }
        if (index >= lines.size) return null
        val head = DECLARATION.find(lines[index]) ?: return null
        val keyword = head.groupValues[1]
        return Declaration(
            name = head.groupValues[2],
            // Only a `fun` or a constructor has an argument list a `@param` can index into. A
            // `val`'s initialiser has parentheses too, and reading those as parameters would hand
            // the census nonsense.
            parameters = if (keyword == "fun" || keyword == "class") {
                parameterNamesFrom(lines, index, head.range.last + 1)
            } else {
                emptyList()
            },
            published = !NOT_PUBLISHED.containsMatchIn(lines[index].substring(0, head.range.first)),
        )
    }

    /** The parameter names of the declaration starting at [line], in order, across line breaks. */
    private fun parameterNamesFrom(lines: List<String>, line: Int, column: Int): List<String> {
        val list = StringBuilder()
        var depth = 0
        var started = false
        var index = line
        var from = column
        while (index < lines.size) {
            for (position in from until lines[index].length) {
                val c = lines[index][position]
                if (c == '(') {
                    depth++
                    if (!started) {
                        started = true
                        continue
                    }
                }
                if (c == ')') {
                    depth--
                    if (depth == 0) return splitParameters(list.toString())
                }
                if (started) list.append(c)
            }
            if (started) list.append(' ')
            index++
            from = 0
        }
        return emptyList()
    }

    /** `a: Int, b: Map<String, TypedField>` to `[a, b]` — split at depth zero, so generics hold. */
    private fun splitParameters(list: String): List<String> {
        val parts = mutableListOf<String>()
        val current = StringBuilder()
        var depth = 0
        for (c in list) {
            when {
                c == '<' || c == '(' || c == '[' -> { depth++; current.append(c) }
                c == '>' || c == ')' || c == ']' -> { depth--; current.append(c) }
                c == ',' && depth == 0 -> { parts += current.toString(); current.clear() }
                else -> current.append(c)
            }
        }
        parts += current.toString()
        return parts
            .map { it.substringBefore(':').trim().substringAfterLast(' ') }
            .filter { it.isNotEmpty() }
    }

    /**
     * Every Kotlin source of the published package, keyed by file name.
     *
     * `KDocCoverageTest:2179`'s walk-up locator, for its reason: the working directory of a Gradle
     * unit test is the module directory, but that is a Gradle default rather than a promise, so
     * every ancestor is tried both as the module root and as the repository root. If none of them
     * holds the directory this *fails naming every path it tried* — a census that silently found
     * nothing would pass for ever.
     */
    private fun publishedSources(): Map<String, String> {
        val workingDirectory = File(".").absoluteFile.normalize()
        val tried = mutableListOf<File>()
        var directory: File? = workingDirectory
        while (directory != null) {
            for (candidate in listOf(File(directory, SOURCE_ROOT), File(directory, "LIM/$SOURCE_ROOT"))) {
                tried += candidate
                if (candidate.isDirectory) {
                    val sources = candidate.walkTopDown().filter { it.isFile && it.name.endsWith(".kt") }
                    return sources.associate { it.name to it.readText() }
                        .also { check(it.isNotEmpty()) { "no Kotlin sources under $candidate" } }
                }
            }
            directory = directory.parentFile
        }
        throw AssertionError(
            "cannot find `$SOURCE_ROOT`, and this census must not be silently skipped. Working " +
                "directory: $workingDirectory. Tried:\n" +
                tried.map { it.absolutePath }.distinct().joinToString("\n"),
        )
    }

    /**
     * **Seventeen published `@param`s promise "Not modified", and until this test nothing in this
     * repository had ever checked one** — asked as a detector and a census, because either alone
     * passes for the wrong reason.
     *
     * The naive grep sees **fifteen**; the phrase wraps across two lines in two places
     * (`FieldRequirements.committed`, `Utils.encodeRevocation`), so the rendered census is
     * **seventeen** and both numbers are printed. A line-based count of this phrase was never safe,
     * which is the finding as much as the gap is.
     *
     * Three questions, and they are different claims:
     *
     * 1. **The detector** — nothing a published function was handed is different after the call.
     *    Every reference argument of every invoked method is snapshotted one level into its
     *    container before the call and compared after it; see [snapshot] for the per-type table
     *    and for why one level is exactly right. [writesToItsArguments] is the control that proves
     *    the detector inspects anything at all.
     * 2. **The census** — every rendered `@param` that makes the promise names a member the
     *    detector actually invoked, at the argument position the promise is about. A member no
     *    hostile value ever reached cannot be said to keep the promise, so this is what stops (1)
     *    being vacuous, and a promise added later cannot arrive uncovered.
     * 3. **Aliasing**, which "Not modified" does *not* say. It says the callee does not write to
     *    your object; it says nothing about whether the callee kept a *reference*, and a vault
     *    that builds an answer and then adds a field to the same draft map is relying on the
     *    second. These builders encode eagerly, so (3) passes today — the point is that nothing
     *    said so.
     *
     * **Two limits, written down rather than left to be found.** The detector sees only arguments
     * the fuzz run actually draws, so a parameter type the provider has no vector for would be
     * covered by the census as "not reached" and by nothing else — today none of the seventeen is
     * in that position, and the census prints which members carry them. And "Not modified" is a
     * claim about the *argument*: a function returning a live view of its argument is a different
     * question, already pinned for this type at `FieldRequirementsTest:418`, and not restated here.
     */
    @Test
    fun `nothing writes to an argument it promised not to modify, and every promise is reached`() {
        // ── (1) The detector, over the run that already exists ───────────

        assertEquals(
            "a published function wrote to an argument whose `@param` promises \"Not modified\". " +
                "A vault reusing one draft map across two answers depends on every one of those " +
                "promises, and this is the first thing in this repository to check one",
            emptyList<String>(),
            measured.mutations.map { it.toString() },
        )

        // Non-vacuity: `mutations` over a run that compared nothing is also empty.
        assertTrue(
            "the detector compared nothing, so \"nothing was modified\" is a claim about " +
                "nothing; got ${measured.comparisons} comparisons over " +
                "${measured.strategies.size} distinct positions",
            measured.comparisons > 500 && measured.strategies.size > 100,
        )

        // The snapshot is taken off the vectors already drawn and contains no `Random` call, so
        // `fuzz()`'s draw sequence cannot have moved. These three are the proof of that — `the
        // corpus is byte-identical on every run` is **not**, since it digests the static corpus
        // lists and would pass even if the snapshot consumed `rnd`.
        println(
            "T61 detector: comparisons=${measured.comparisons} positions=" +
                "${measured.strategies.size} mutations=${measured.mutations.size} " +
                "calls=${measured.calls.size} textsDrawn=${measured.textsDrawn.size} " +
                "byteVectorsDrawn=${measured.byteVectorsDrawn.size} " +
                "longsDrawn=${measured.longsDrawn.size} " +
                "strategies=${measured.strategies.values.groupingBy { it }.eachCount()} " +
                "immutableTypes=${measured.immutableTypes.map { it.simpleName }.sorted()}",
        )

        // The control. A function that *does* write to its arguments, run through the same
        // `snapshotsOf`/`compare` pair, must be reported — naming the method and every position.
        val controlRandom = Random(MASTER_SEED xor 0x4D55544CL)
        val controlArgs = listOf<Any?>(
            hostileFields(controlRandom),
            "x".toByteArray(),
            linkedSetOf("a"),
            hostileEntry(controlRandom),
        )
        val controlKey = "writesToItsArguments(Map<String, TypedField>, byte[], Set<String>, Entry)"
        val controlSnapshots = snapshotsOf(controlArgs, emptySet())
        @Suppress("UNCHECKED_CAST")
        writesToItsArguments(
            controlArgs[0] as Map<String, TypedField>,
            controlArgs[1] as ByteArray,
            controlArgs[2] as Set<String>,
            controlArgs[3] as Entry,
        )
        assertEquals(
            "the detector must report a function that does write to its arguments, naming the " +
                "method and each argument position. Without this the empty list above could be a " +
                "detector that inspects nothing, which is the failure mode a census-shaped test has",
            listOf("$controlKey#0", "$controlKey#1", "$controlKey#2", "$controlKey#3"),
            compare(controlKey, controlArgs, controlSnapshots, emptySet())
                .mutations.map { "${it.methodKey}#${it.position}" },
        )

        // …and a function that changes nothing but the *order*, which `==` cannot see and which
        // this library's own wire promises make a real modification. Without it the order-sensitive
        // half of `ordered` could be deleted with every assertion here still green.
        val reorderKey = "reordersItsArgument(Map<String, TypedField>)"
        val reorderArg = linkedMapOf(
            "a" to TypedField(value = "1", type = FieldType.STRING),
            "b" to TypedField(value = "2", type = FieldType.STRING),
        )
        val reorderArgs = listOf<Any?>(reorderArg)
        val reorderSnapshots = snapshotsOf(reorderArgs, emptySet())
        reordersItsArgument(reorderArg)
        assertEquals(
            "the detector must report a map whose iteration order was changed in place. Its " +
                "content is identical, so `==` sees nothing — and insertion order is what " +
                "`encodeFields`, `decodeFields` and `Entry`'s own Parceler all promise to keep",
            listOf("$reorderKey#0"),
            compare(reorderKey, reorderArgs, reorderSnapshots, emptySet())
                .mutations.map { "${it.methodKey}#${it.position}" },
        )
        assertEquals(
            "…and the reorder must be content-preserving, or the control proves only that the " +
                "detector notices a changed value",
            mapOf(
                "a" to TypedField(value = "1", type = FieldType.STRING),
                "b" to TypedField(value = "2", type = FieldType.STRING),
            ),
            reorderArg,
        )

        // `extrasOf` is the detector's only route into an `Intent`, and an `extrasOf` that
        // answered `emptyMap()` would make every Intent position — and every comparison in the
        // aliasing half — two empty maps that cannot differ, with nothing else in this file
        // noticing. That is the no-op arm a census-shaped test has to rule out by hand.
        assertEquals(
            "extrasOf must read every extra an intent carries, by value",
            limExtraKeys.associateWith { "probe" },
            extrasOf(intentFor("all", "probe")),
        )
        // The unreadable intent, carrying an extra — not the empty one the run draws. An empty
        // `UnreadableIntent` has a null `extras`, so the loop never runs and a `getStringExtra`
        // route would pass this too: the claim needs a key to read before it means anything.
        val unreadable = UnreadableIntent().apply { putExtra(Utils.EXTRA_PUBLIC_KEY, "k") }
        assertEquals(
            "extrasOf must read an intent whose `getStringExtra` throws. That is why the route " +
                "is `extras` plus `Bundle.getString`, which UnreadableIntent does not override",
            mapOf(Utils.EXTRA_PUBLIC_KEY to "k"),
            extrasOf(unreadable),
        )
        assertTrue(
            "…and the fixture must really throw through the route a snapshot cannot take, or " +
                "the sentence above is about nothing",
            runCatching { unreadable.getStringExtra(Utils.EXTRA_PUBLIC_KEY) }
                .exceptionOrNull() is BadParcelableException,
        )

        // The three hand-kept immutability tables, tied together. Both directions, because the
        // subset relation alone is satisfied by an empty measurement — delete the line in
        // `compare` that feeds `immutableTypes` and a subset-only assertion goes green while
        // seven of the seventeen promises stop resting on anything.
        assertEquals(
            "the classes reported under the `immutable` strategy are not the ones this file " +
                "checks the immutability of. A type on the right and not the left is one the " +
                "run stopped reaching, which makes the reflection walk below a check of nothing; " +
                "one on the left and not the right is a type snapshotted by reference that " +
                "nobody has looked at. Either way, seven of the seventeen promises rest on this",
            listOf("QueryRequest", "RecoveryAuthorization", "Revocation", "RotationStatement", "String"),
            measured.immutableTypes.map { it.simpleName }.sorted(),
        )
        assertEquals(
            "…and every one of them must be a type the walk below covers or a JDK leaf, which " +
                "is what catches `IMMUTABLE_PROTOCOL_TYPES` drifting from `snapshot`'s own " +
                "branch list rather than from the run",
            emptyList<String>(),
            (measured.immutableTypes - IMMUTABLE_PROTOCOL_TYPES.toSet() - IMMUTABLE_LEAVES)
                .map { it.name }.sorted(),
        )

        // The `immutable` strategy, checked rather than claimed: seven of the seventeen promises
        // rest on it — the three statement encoders, the three `encode*` carriers and `isRevoked`
        // — so "this type has no mutable state" must be a fact about the type.
        assertEquals(
            "a type the detector snapshots by reference under the `immutable` strategy has a " +
                "field that is either not final or not of an immutable type, so a callee could " +
                "write through it and the detector would never see it",
            emptyList<String>(),
            IMMUTABLE_PROTOCOL_TYPES.flatMap { type ->
                type.declaredFields
                    .filterNot { Modifier.isStatic(it.modifiers) }
                    .filterNot { Modifier.isFinal(it.modifiers) && it.type in IMMUTABLE_LEAVES }
                    .map { "${type.simpleName}.${it.name}: ${it.type.simpleName}" }
            }.sorted(),
        )

        // Three of the seventeen are outside `fuzz()`, which enumerates `Utils`'s declared methods
        // only: `FieldRequirements.missingRequired`, `isSatisfiedBy` and `committed` — three, not
        // two, because `committed` is one of the wrapped promises the grep misses and is outside
        // for the identical reason. The detector is extended to them here rather than excusing
        // them by name. Its own seed, so the run above is not moved by it.
        val armRandom = Random(MASTER_SEED xor 0x4E4F544DL)
        val armMutations = mutableListOf<Mutation>()
        val armStrategies = linkedMapOf<String, String>()
        val requirementMethods = FieldRequirements::class.java.declaredMethods.filter { it.isPublishedApi() }
        repeat(NOT_MODIFIED_DRAWS) { draw ->
            val requirements = hostileRequirements(armRandom)
            // The split `every FieldRequirements member survives hostile names and hostile drafts`
            // uses, so `committed` is exercised either side of its null/non-null branch.
            val draft: Map<String, TypedField> = if (draw % 2 == 0) {
                hostileFields(armRandom)
            } else {
                requirements.fieldNames.associateWith { TypedField(text(armRandom), text(armRandom)) }
            }
            listOf<Pair<String, () -> Any?>>(
                "missingRequired" to { requirements.missingRequired(draft) },
                "isSatisfiedBy" to { requirements.isSatisfiedBy(draft) },
                "committed" to { requirements.committed(draft) },
            ).forEach { (name, invoke) ->
                val key = methodKey(requirementMethods.single { it.name == name })
                val args = listOf<Any?>(draft)
                val snapshots = snapshotsOf(args, emptySet())
                invoke()
                val detected = compare(key, args, snapshots, emptySet())
                armMutations += detected.mutations
                armStrategies += detected.strategies
            }
        }
        assertEquals(
            "a FieldRequirements member wrote to the draft it was handed. A vault gates Save on " +
                "these three and then persists `committed` of the very same map",
            emptyList<String>(),
            armMutations.map { it.toString() },
        )
        assertEquals(
            "all three FieldRequirements members must have been reached, or the census below is " +
                "excusing them rather than checking them",
            listOf("committed", "isSatisfiedBy", "missingRequired"),
            armStrategies.keys.map { it.substringBefore('(') }.distinct().sorted(),
        )

        // ── (2) The census ──────────────────────────────────────────────

        // The parser first, against a source whose answer is known. Without this the seventeen
        // below is self-reported: every assertion in this half is a reading of `promisesIn`, and
        // `promisesIn` is regex over Kotlin source. See [CENSUS_FIXTURE] for what each case is.
        assertEquals(
            "the census parser does not read the fixture the way it must: continuation lines " +
                "joined before matching, a `@param` ended at a blank doc line, a generic " +
                "parameter list split at depth zero, a private member excluded, and a block it " +
                "cannot attribute reported rather than dropped",
            listOf(
                "visible/4#0 kept wrapped=false",
                "visible/4#1 joined wrapped=true",
                "visible/4#3 typed wrapped=false",
                "terse/1#0 inline wrapped=false",
                "$UNATTRIBUTABLE/-1#-1 orphan wrapped=false",
            ),
            promisesIn("Fixture.kt", CENSUS_FIXTURE).map {
                "${it.member}/${it.declarationArity}#${it.parameterIndex} ${it.parameter} " +
                    "wrapped=${it.wrapped}"
            },
        )

        val sources = publishedSources()
        val naive = sources.values.sumOf { source -> source.split("\n").count { NOT_MODIFIED in it } }
        val promises = sources.entries.sortedBy { it.key }.flatMap { promisesIn(it.key, it.value) }
        val wrapped = promises.filter { it.wrapped }
        println(
            "T61 census: naive grep lines=$naive rendered promises=${promises.size} " +
                "wrapped=${wrapped.size} $wrapped members=" +
                "${promises.map { "${it.owner}.${it.member}" }.distinct().sorted()}",
        )
        assertTrue(
            "the census found ${promises.size} promises, floor $MINIMUM_PROMISES. A parser that " +
                "stopped matching would report an empty census and satisfy every check below. " +
                "The floor is well under the measured count on purpose: this is a census of " +
                "promises *made*, not a floor on how many there must be, so deleting one must " +
                "not redden",
            promises.size >= MINIMUM_PROMISES,
        )
        // The gap between $naive and ${promises.size} is the finding, and it is *reported* rather
        // than asserted: the phrase wraps in two places today, and reflowing either paragraph so
        // it fits on one line would close the gap without changing a single promise. A test that
        // reddened on that would be a test of a line break. What pins the renderer instead is the
        // `joined` case of [CENSUS_FIXTURE], which no prose edit can reach.

        val published = mapOf(
            "Utils" to publishedMethods.associate { methodKey(it) to it.parameterCount },
            "FieldRequirements" to requirementMethods.associate { methodKey(it) to it.parameterCount },
        )
        val invoked = mapOf(
            "Utils" to measured.invoked.toSet(),
            "FieldRequirements" to armStrategies.keys.map { it.substringBefore('#') }.toSet(),
        )
        val strategies = measured.strategies.mapKeys { "Utils.${it.key}" } +
            armStrategies.mapKeys { "FieldRequirements.${it.key}" }

        val coveredBy = linkedMapOf<String, Set<String>>()
        val unreached = promises.mapNotNull { promise ->
            val siblings = published[promise.owner].orEmpty()
                .filterKeys { it.substringBefore('(') == promise.member }
            // The declaration's own arity, not every overload of the name: see
            // [Promise.declarationArity].
            val carrying = siblings.filterValues { it == promise.declarationArity }.keys
            coveredBy["$promise"] =
                carrying.mapNotNull { strategies["${promise.owner}.$it#${promise.parameterIndex}"] }.toSet()
            val reasons = mutableListOf<String>()
            if (siblings.isEmpty()) reasons += "no published member of that name"
            if (promise.parameterIndex < 0) {
                reasons += "`@param ${promise.parameter}` names no parameter of the declaration"
            } else if (carrying.isEmpty()) {
                reasons += "no published overload of that name takes ${promise.declarationArity} " +
                    "arguments, so the declaration this `@param` is on was not found"
            }
            (siblings.keys - invoked[promise.owner].orEmpty()).let {
                if (it.isNotEmpty()) reasons += "never invoked: ${it.sorted()}"
            }
            carrying.filterNot { "${promise.owner}.$it#${promise.parameterIndex}" in strategies }.let {
                if (it.isNotEmpty()) reasons += "never compared at #${promise.parameterIndex}: ${it.sorted()}"
            }
            if (reasons.isEmpty()) null else "$promise -> ${reasons.joinToString("; ")}"
        }.sorted()

        // The first limit, reported rather than left to be found: the detector sees only arguments
        // the fuzz run actually draws, so a promise on a member carrying a parameter type the
        // provider has no vector for would be covered by the census as "not reached" and by
        // nothing else. None of the seventeen is in that position today. Printed before the
        // assertions so the numbers are in hand when one of them fails.
        println(
            "T61 census coverage: " +
                "${coveredBy.values.groupingBy { it.sorted().joinToString("+") }.eachCount()} " +
                "notReached=${unreached.size}",
        )

        assertEquals(
            "a published `@param` promises \"Not modified\" and the detector never reached it, " +
                "so nothing here checks that promise. Either give the fuzz run a vector for the " +
                "parameter type the member introduced, or excuse the member by name with a " +
                "reason and the test that covers it instead — a member no call ever reached " +
                "cannot be said to keep a promise, and this is what stops (1) being vacuous",
            emptyList<String>(),
            unreached,
        )
        assertEquals(
            "a promise is covered only by strategies the detector is blind under — `identity`, " +
                "where no meaningful snapshot exists (a Context, a SecureRandom), or `absent`, " +
                "where the position was only ever handed `null`. Neither carries this promise " +
                "today, and one that did would need a real copy or an honest excuse rather than " +
                "a comparison that cannot fail",
            emptyList<String>(),
            coveredBy.filterValues { it.isNotEmpty() && it.all { s -> s in BLIND_STRATEGIES } }
                .keys.sorted(),
        )

        // ── (3) Aliasing: a different claim, said to be different ───────

        // **Three different counts of the same thing, and all three belong here.** There are
        // **seven** Kotlin declarations in `Utils.kt` taking a field map, and only **three** of
        // them call `encodeFields` directly — the other four delegate — which is why the property
        // is asserted at all seven: a caller cannot know which delegates, and the promise has to
        // hold at the surface they call. And reflection sees a third number again: `@JvmOverloads`
        // expands those seven declarations plus `encodeFields` into **13** published JVM methods,
        // which is what this assertion is over. The arities below the full one take
        // no caller map at all — they supply `emptyMap()` — and every arity of a declaration runs
        // the same body, so the nine cases below call each declaration at its full arity.
        val mapTakers = publishedMethods.filter { method ->
            method.genericParameterTypes.any { rawOf(it) == Map::class.java && covered(it) }
        }
        assertEquals(
            "the published JVM methods taking a field map are not the ones this half covers. A " +
                "new result builder, or a new `@JvmOverloads` arity of an existing one, must " +
                "either appear in the nine cases below or be accounted for here",
            listOf(
                "createQueryResultIntent", "createQueryResultIntent", "createQueryResultIntent",
                "createShareResultIntent", "createShareResultIntent", "createShareResultIntent",
                "createShareResultIntent",
                "createSignChallengeResultIntent", "createSignChallengeResultIntent",
                "createSignChallengeResultIntent", "createSignChallengeResultIntent",
                "createSignChallengeResultIntent",
                "encodeFields",
            ),
            mapTakers.map { it.name }.sorted(),
        )
        assertEquals(
            "…and the seven Kotlin declarations behind them — each named by the JVM method its " +
                "full arity compiles to — must all still be published map-takers. A renamed or " +
                "removed one breaks apps compiled against 1.0.0 (stop rule 10) and must move here",
            emptyList<String>(),
            (FULL_ARITY_MAP_BUILDERS - mapTakers.map(::methodKey).toSet()).sorted(),
        )

        val draft = LinkedHashMap<String, TypedField>()
        draft["name"] = TypedField(value = "Ada", type = FieldType.STRING)
        val optional = linkedSetOf("name")
        val declared = FieldRequirements(listOf("name"), setOf("name"))
        val entry = Entry(id = "alias-probe", fields = draft, publicKey = "alias-key")
        val signature = byteArrayOf(1, 2, 3)

        // The injected field must change what the map encodes to, or every comparison below is a
        // property of a mutation that did nothing — and a lazy builder would then pass too.
        //
        // That is the whole of the non-vacuity argument available here, and it is deliberate. The
        // matching mutation probe — "make a builder retain its map and write the payload in a lazy
        // block" — cannot be written against these functions at all: `Intent.putExtra` takes a
        // value, not a provider, so a lazy result builder would mean a published function
        // returning an `Intent` subclass of this library's own. That is reshaping source this task
        // has no business changing, so the probe was skipped and said to be skipped. What *was*
        // measured is a simulated late read — re-writing the payload extra after the call, with
        // the draft mutated — and the comparison below does redden on it.
        val encodedBefore = Utils.encodeFields(draft)
        draft["injected"] = TypedField(value = "late", type = FieldType.STRING)
        val encodedAfter = Utils.encodeFields(draft)
        draft.remove("injected")
        assertTrue(
            "injecting a field must change the map's encoding, or the aliasing half passes for " +
                "the wrong reason: got <$encodedBefore> then <$encodedAfter>",
            encodedBefore != encodedAfter && "injected" in encodedAfter,
        )

        class Alias(val method: String, val keys: List<String>, val build: () -> Intent)
        val aliasing = listOf(
            Alias(
                "createShareResultIntent(String, Map<String, TypedField>, String)",
                listOf(Utils.EXTRA_FIELDS_JSON),
            ) { Utils.createShareResultIntent("alias-key", draft, "req-1") },
            Alias(
                "createShareResultIntent(String, Map<String, TypedField>, String, FieldRequirements)",
                listOf(Utils.EXTRA_FIELDS_JSON, Utils.EXTRA_APPLIED_OPTIONAL_FIELDS),
            ) { Utils.createShareResultIntent("alias-key", draft, "req-1", declared) },
            Alias(
                "createQueryResultIntent(String, Map<String, TypedField>, String)",
                listOf(Utils.EXTRA_QUERY_RESULT_FIELDS),
            ) { Utils.createQueryResultIntent("alias-key", draft, "req-1") },
            Alias(
                "createSignChallengeResultIntent(byte[], Map<String, TypedField>, String, String)",
                listOf(Utils.EXTRA_FIELDS_JSON),
            ) { Utils.createSignChallengeResultIntent(signature, draft, "req-1", "SHA256withRSA") },
            Alias(
                "createShareResultIntent(ShareRequest, String, Map<String, TypedField>)",
                listOf(Utils.EXTRA_FIELDS_JSON),
            ) { Utils.createShareResultIntent(ShareRequest(entry, "req-1"), "alias-key", draft) },
            Alias(
                "createQueryResultIntent(QueryRequest, String, Map<String, TypedField>)",
                listOf(Utils.EXTRA_QUERY_RESULT_FIELDS),
            ) { Utils.createQueryResultIntent(QueryRequest("alias-key", "req-1"), "alias-key", draft) },
            Alias(
                "createSignChallengeResultIntent(SignChallengeRequest, byte[], " +
                    "Map<String, TypedField>, String)",
                listOf(Utils.EXTRA_FIELDS_JSON),
            ) {
                Utils.createSignChallengeResultIntent(
                    SignChallengeRequest("alias-key", byteArrayOf(9), "req-1"),
                    signature,
                    draft,
                    "SHA256withRSA",
                )
            },
            // The eighth and ninth cases are the same shape from the other side: an `Entry`
            // carrying the field map, and — in the five-argument overload — the optional-name set
            // beside it, which is the other published collection a caller keeps a reference to and
            // the other `Not modified` promise of a container type.
            Alias("createShareIntent(Context, Entry)", listOf(Utils.EXTRA_ENTRY_JSON)) {
                Utils.createShareIntent(context, entry)
            },
            Alias(
                "createShareIntent(Context, Entry, String, Set<String>, String)",
                listOf(Utils.EXTRA_ENTRY_JSON, Utils.EXTRA_OPTIONAL_FIELDS),
            ) {
                Utils.createShareIntent(context, entry, "req-1", optional, Utils.DEFAULT_ENDEAVOR_PACKAGE)
            },
        )

        assertEquals(
            "every aliasing case must name a published method that really exists, and the nine " +
                "must be the seven full-arity map-taking declarations plus the two " +
                "createShareIntent overloads whose Entry carries a field map",
            (FULL_ARITY_MAP_BUILDERS + ALIASED_ENTRY_BUILDERS).sorted(),
            aliasing.map { it.method }.sorted(),
        )
        assertEquals(
            "…and each must resolve against the published surface by reflection, so a renamed " +
                "parameter type cannot leave a case pointing at nothing",
            emptyList<String>(),
            (aliasing.map { it.method } - measured.published.toSet()).sorted(),
        )

        aliasing.forEach { case ->
            val intent = case.build()
            case.keys.forEach { key ->
                val payload = intent.getStringExtra(key)
                assertTrue(
                    "${case.method} wrote nothing naming \"name\" under $key, so the comparison " +
                        "below is over an envelope that never carried the map; got <$payload>",
                    payload != null && "name" in payload,
                )
            }
            val before = extrasOf(intent)
            draft["injected"] = TypedField(value = "late", type = FieldType.STRING)
            optional += "injected"
            val after = extrasOf(intent)
            draft.remove("injected")
            optional -= "injected"
            assertEquals(
                "${case.method} is still reading the collection it was handed: adding to it after " +
                    "the call changed an intent that had already been returned. These encode " +
                    "eagerly, and a vault that builds one answer and then edits the same draft " +
                    "for the next one depends on that",
                before,
                after,
            )
        }
        assertEquals(
            "every aliasing case must run: the seven map-taking builders plus the two " +
                "createShareIntent overloads whose Entry carries a field map",
            9,
            aliasing.size,
        )
    }

    // ── Negative controls ────────────────────────────────────────────────

    /**
     * Accept-one-genuine, for every positive answer the properties above forbid.
     *
     * Without this, "no hostile argument authenticates" is satisfied by a verifier that refuses
     * everything — which is not a verifier. One genuine signature and one genuine statement of
     * each of the three kinds, each of which must come back positive.
     */
    @Test
    fun `the genuine answers still come back positive`() {
        val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val replacement =
            KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val publicKeyBase64 = Base64.encodeToString(keyPair.public.encoded, Base64.DEFAULT)
        val replacementBase64 = Base64.encodeToString(replacement.public.encoded, Base64.DEFAULT)

        fun sign(bytes: ByteArray): ByteArray = Signature.getInstance("SHA256withRSA").run {
            initSign(keyPair.private)
            update(bytes)
            sign()
        }

        val nonce = Utils.generateNonce(entropy, FUZZ_CLOCK)
        assertTrue(
            "verifySignature must accept a genuine signature, else \"never true\" is a property " +
                "of a function that refuses everything",
            Utils.verifySignature(publicKeyBase64, nonce, sign(nonce)),
        )

        val rotation = RotationStatement(
            oldPublicKey = publicKeyBase64,
            newPublicKey = replacementBase64,
            statementId = "rot-surface-0001",
            issuedAtMillis = FUZZ_CLOCK - 1_000L,
            expiresAtMillis = FUZZ_CLOCK + 1_000L,
        )
        assertEquals(
            "a genuine rotation must verify VALID, else \"never VALID\" proves nothing",
            StatementVerdict.VALID,
            Utils.verifyRotationStatement(
                rotation,
                sign(Utils.rotationStatementBytes(rotation)),
                publicKeyBase64,
                FUZZ_CLOCK,
            ),
        )

        val authorization = RecoveryAuthorization(
            subjectPublicKey = publicKeyBase64,
            recoveryPublicKey = replacementBase64,
            authorizationId = "rec-surface-0001",
            sequence = 7L,
            issuedAtMillis = FUZZ_CLOCK,
        )
        assertEquals(
            "…and a genuine authorization, the kind that never expires",
            StatementVerdict.VALID,
            Utils.verifyRecoveryAuthorization(
                authorization,
                sign(Utils.recoveryAuthorizationBytes(authorization)),
                publicKeyBase64,
            ),
        )

        val revocation = Revocation(
            subjectPublicKey = publicKeyBase64,
            revokedAuthorizationId = "rec-surface-0001",
            sequence = 8L,
            issuedAtMillis = FUZZ_CLOCK,
        )
        assertEquals(
            "…and a genuine revocation, which is the one a user discovers has failed only once " +
                "the primary phone is already gone",
            StatementVerdict.VALID,
            Utils.verifyRevocation(
                revocation,
                sign(Utils.revocationBytes(revocation)),
                publicKeyBase64,
            ),
        )
    }

    /**
     * The reproducibility claim, pinned rather than described — this file's own digest, over this
     * file's own corpus.
     *
     * Hashed as UTF-16 code units rather than through `toByteArray()`, `DecoderFuzzTest`'s
     * reasoning: no `String` can encode a lone surrogate, so UTF-8 would replace [loneSurrogate]
     * with `'?'` and the digest would be blind to an edit swapping that character for a literal
     * `'?'` — which is one of the two characters this corpus deliberately carries and cannot
     * round-trip.
     *
     * A change-detector, not a safety assertion: recomputing it is correct when the corpus was
     * edited on purpose, and wrong every other time.
     */
    @Test
    fun `the corpus is byte-identical on every run`() {
        val digest = MessageDigest.getInstance("SHA-256")
        corpusText.forEach { entry ->
            entry.forEach { c ->
                digest.update((c.code shr 8).toByte())
                digest.update((c.code and 0xFF).toByte())
            }
            // A separator no corpus entry contains, so concatenation cannot forge the same digest
            // for two different splits of the same characters.
            digest.update(0x1E.toByte())
        }
        corpusLongs.forEach { value ->
            for (shift in 56 downTo 0 step 8) digest.update(((value ushr shift) and 0xFF).toByte())
        }
        assertEquals(
            "this file's corpus changed; update CORPUS_DIGEST only if it was edited deliberately",
            CORPUS_DIGEST,
            buildString(32) {
                digest.digest().forEach { b ->
                    val v = b.toInt() and 0xFF
                    append(HEX[v shr 4])
                    append(HEX[v and 0xF])
                }
            },
        )
    }

    private companion object {
        /**
         * Why a published member is not fuzzed, and what covers it instead — as two fields rather
         * than one sentence, so that [coveredBy] can be resolved against a real `@Test` by
         * `every NOT_FUZZABLE entry names a test that exists`. Spelled `ClassName: test method
         * name`, the shape the audit's own manifest uses.
         */
        private class Excuse(val reason: String, val coveredBy: String)

        /** Arbitrary; what matters is only that it never changes. */
        private const val MASTER_SEED = 0x4C494D20543B01L

        /**
         * Vectors per method, before the `String` floors are added on top. Small on purpose: this
         * file is breadth over 40-odd methods, and depth over a corpus is `DecoderFuzzTest`'s.
         */
        private const val DRAWS = 8

        /** Draws for the [FieldRequirements] arm, which is one type rather than a whole surface. */
        private const val FIELD_REQUIREMENTS_DRAWS = 400

        /**
         * Draws for the three [FieldRequirements] promises the `Utils` enumeration cannot reach.
         * Smaller than [FIELD_REQUIREMENTS_DRAWS]: this arm asks one question of each member
         * rather than four invariants, and the draws it needs are the ones that reach both sides
         * of `committed`'s branch.
         */
        private const val NOT_MODIFIED_DRAWS = 40

        /** The published phrase this census is of, spelled once. */
        private const val NOT_MODIFIED = "Not modified"

        /**
         * A non-vacuity floor on the census, deliberately well under the measured 17.
         *
         * This is a census of promises *made*, not a floor on how many there must be: deleting a
         * `Not modified` line is a documentation decision and must not redden a test. What the
         * floor catches is a parser that stopped matching — which would report an empty census and
         * satisfy every assertion built on it.
         */
        private const val MINIMUM_PROMISES = 12

        /** The snapshot strategies; see [snapshot]. */
        private const val COPY = "copy"
        private const val IMMUTABLE = "immutable"
        private const val IDENTITY = "identity"
        private const val ABSENT = "absent"

        /** The strategies under which a promise is *not* checked by anything. */
        private val BLIND_STRATEGIES = setOf(IDENTITY, ABSENT)

        /** What the census records a promise under when it cannot read its declaration. */
        private const val UNATTRIBUTABLE = "<unattributable>"

        /**
         * A source the census parser is held to, so that the seventeen it reports off the real
         * tree is not self-reported.
         *
         * `promisesIn` is a hundred-odd lines of regex over Kotlin source, and its only other
         * verifier is the tree it reads — which means every assertion in the census half is a
         * reading of an unverified parser. `KDocCoverageTest`'s `FIXTURE_SOURCE` is the precedent.
         * Every line here is one case:
         *
         * - `kept` — the ordinary shape, on one line.
         * - `joined` — the phrase split across two source lines, which is the whole reason the
         *   census is built over rendered text. Pinned here rather than on the real sources, so
         *   reflowing a published KDoc paragraph is a prose edit and not a build failure.
         * - `inline` — a one-line block, with the tag on the comment's own opening delimiter and
         *   so with no leading asterisk of its own.
         * - `ended` — a `@param` whose text ends at a blank doc line, with the phrase in the prose
         *   *after* it. Not a promise about `ended`, and attributing it to one is how a parser
         *   that joined the whole block would read these blocks: four of the real ones carry
         *   trailing prose.
         * - `typed` — a generic parameter, so the comma inside `Map<String, TypedField>` must not
         *   split the parameter list.
         * - `hidden` — on a `private` member, which the census is not of. Control (c), as a
         *   fixture rather than a probe against the real source.
         * - `orphan` — a block documenting nothing, recorded as [UNATTRIBUTABLE] so it reddens.
         *   This is the case that matters most, because it is where the shapes this parser cannot
         *   read go: a generic `fun <T>`, a modifier on a line of its own. Both fail loudly
         *   instead of quietly shrinking the census.
         *
         * **Two shapes it would still read wrongly, and neither exists in `LIM/src/main` today.**
         * A declaration written on the same line as its annotation is skipped by
         * `declarationAfter`'s annotation guard, and the promise is then attributed to whatever
         * declaration comes next — misattributed rather than reported. And a comment-closing
         * delimiter inside a KDoc code fence would end the block early, which [MINIMUM_PROMISES]
         * at 12 against a measured 17 would absorb. Both are stated rather than guarded: Kotlin
         * KDoc cannot carry the second at all, and the first is a style this codebase does not
         * use. If either becomes possible, the fixture is where the case belongs.
         */
        private val CENSUS_FIXTURE = """
            object Fixture {
                /**
                 * Doc.
                 *
                 * @param kept  One line. Not modified.
                 * @param joined A promise that wraps, because the phrase does not fit on the
                 *               line the sentence ends on. Not
                 *               modified.
                 * @param ended A parameter whose text ends here.
                 *
                 *               Not modified — prose after a blank doc line, belonging to the
                 *               block rather than to any parameter.
                 * @param typed A generic parameter, so the split must hold. Not modified.
                 * @return nothing
                 */
                @JvmOverloads
                fun visible(
                    kept: String,
                    joined: ByteArray,
                    ended: Int,
                    typed: Map<String, TypedField>,
                ) = 0

                /** @param inline All on the opening line. Not modified. */
                fun terse(inline: String) = 0

                /**
                 * @param hidden Not modified.
                 */
                private fun invisible(hidden: String) = 0

                /**
                 * @param orphan Not modified.
                 */
            }
        """.trimIndent()

        /** Where the census reads the published `@param`s from. `KDocCoverageTest:2234` verbatim. */
        private const val SOURCE_ROOT = "src/main/java/dev/eryalabs/lim"

        /**
         * `@param name rest-of-line`, inside a KDoc block.
         *
         * The optional slash-star is for a tag written on the comment's own opening delimiter,
         * which therefore has no leading asterisk — a shape the first draft of this parser missed
         * silently. (Spelled in words because Kotlin block comments *nest*: a literal opening
         * delimiter inside this KDoc would open a second comment and swallow the companion. That
         * cost one compile.)
         */
        private val PARAM_TAG = Regex("""^[ \t]*(?:/\*)?\*[ \t]*@param[ \t]+(\S+)[ \t]*(.*)$""")

        /** A KDoc body line, and what it says once the leading `*` is off. */
        private val DOC_BODY = Regex("""^[ \t]*\*(.*)$""")

        /** The declaration a KDoc block documents, with an optional extension receiver. */
        private val DECLARATION =
            Regex("""\b(fun|val|var|class|object)\s+(?:[A-Za-z_][A-Za-z0-9_]*\.)?([A-Za-z_][A-Za-z0-9_]*)""")

        /** What keeps a declaration out of the census — control (c)'s whole subject. */
        private val NOT_PUBLISHED = Regex("""\b(private|internal|protected)\b""")

        /**
         * The library types the detector snapshots **by reference**, because they hold no mutable
         * state at all — so "Not modified" is true of them by construction rather than by check.
         *
         * Seven of the seventeen promises rest on this, so the claim is machine-checked by the
         * census test rather than taken on trust: every non-static field of each must be `final`
         * and of a type in [IMMUTABLE_LEAVES]. `String` and the boxed primitives are the leaves
         * themselves and are not walked — `String`'s own `hash` field is not final, which says
         * only that the JDK caches a hash code.
         */
        private val IMMUTABLE_PROTOCOL_TYPES = listOf<Class<*>>(
            TypedField::class.java,
            RotationStatement::class.java,
            RecoveryAuthorization::class.java,
            Revocation::class.java,
            QueryRequest::class.java,
        )

        /**
         * The seven Kotlin declarations in `Utils.kt` taking a field map, each named by the JVM
         * method its **full** arity compiles to — which is the arity the aliasing half calls.
         *
         * Only three of the seven call `encodeFields` directly; the other four delegate. The
         * property is asserted at all seven anyway, because a caller cannot know which delegates
         * and the promise has to hold at the surface they call.
         */
        private val FULL_ARITY_MAP_BUILDERS = setOf(
            "createQueryResultIntent(QueryRequest, String, Map<String, TypedField>)",
            "createQueryResultIntent(String, Map<String, TypedField>, String)",
            "createShareResultIntent(ShareRequest, String, Map<String, TypedField>)",
            "createShareResultIntent(String, Map<String, TypedField>, String)",
            "createShareResultIntent(String, Map<String, TypedField>, String, FieldRequirements)",
            "createSignChallengeResultIntent(SignChallengeRequest, byte[], Map<String, TypedField>, String)",
            "createSignChallengeResultIntent(byte[], Map<String, TypedField>, String, String)",
        )

        /** The same shape from the other side: an [Entry] carrying the map, and a `Set` beside it. */
        private val ALIASED_ENTRY_BUILDERS = setOf(
            "createShareIntent(Context, Entry)",
            "createShareIntent(Context, Entry, String, Set<String>, String)",
        )

        private val IMMUTABLE_LEAVES = setOf<Class<*>>(
            String::class.java,
            java.lang.Long.TYPE,
            java.lang.Integer.TYPE,
            java.lang.Boolean.TYPE,
            java.lang.Long::class.java,
            Integer::class.java,
            java.lang.Boolean::class.java,
        )

        private const val PAYLOAD_PREVIEW = 120
        private const val HEX = "0123456789abcdef"

        /** A fixed clock, so nothing here means something different tomorrow. */
        private const val FUZZ_CLOCK = 1_770_000_000_000L

        /**
         * Below the measured 64 — 47 when this file was written, plus T28's ten result-builder
         * arities and T29's seven request overloads — so that *adding* a published member does
         * not fail this — the
         * invoked-set equality is what notices that — while a filter drifting towards the empty
         * set does. The actual is printed on every run.
         */
        private const val MINIMUM_PUBLISHED = 45

        /** `PublicApiAuditTest:1172` verbatim: strips `java.util.` and leaves `Map` alone. */
        private val PACKAGE_QUALIFIER = Regex("""\b(?:[a-z][A-Za-z0-9_]*\.)+(?=[A-Z])""")

        /**
         * Handed to every invoked `String` position outright, not merely offered by the corpus.
         * See the comment at the call site.
         */
        private val STRING_FLOOR = listOf("", "x")

        /** See [covered]. A type absent from here makes its method unfuzzable, loudly. */
        private val COVERED_TYPES = setOf<Class<*>>(
            Context::class.java,
            SecureRandom::class.java,
            String::class.java,
            ByteArray::class.java,
            java.lang.Long.TYPE,
            Entry::class.java,
            RotationStatement::class.java,
            RecoveryAuthorization::class.java,
            Revocation::class.java,
            // T29's request overloads. Until these were added, the three parsed-request types
            // were parameter types this provider had no vector for, so all seven of those methods
            // landed in `uncovered` and the invoked-set equality failed naming each method and
            // each rendered type — the `java.io.File` plant T27 wrote that assertion for, met for
            // the first time by a real change.
            ShareRequest::class.java,
            QueryRequest::class.java,
            SignChallengeRequest::class.java,
            // Required fields: the requirements a vault read and a client declared. `Set` is
            // checked by element type in [covered], like `List` and `Map`.
            FieldRequirements::class.java,
            Map::class.java,
            Intent::class.java,
            List::class.java,
        )

        /**
         * The published methods this file deliberately does not call, each with the reason and the
         * test that covers the member instead.
         *
         * Every entry is here for one reason: the method takes nothing another app can choose.
         * Three take no argument at all, and the fourth takes only the caller's own entropy
         * source. There is no hostile vector to build, so invoking them would add a call and no
         * property — and an excuse that says so is more honest than a call that proves nothing.
         *
         * Note what is *not* here: `generateNonce(SecureRandom, long)`, whose `long` is a clock
         * value a caller can get wrong, and `shareDataAction(String)` and
         * `signChallengeAction(String)`, whose target package is a string. Those are fuzzed.
         *
         * **Every citation is a `JavaInteropTest` one, and that is not an accident.** All four of
         * these are the *shorter* arity `@JvmOverloads` generated, and a Kotlin `generateNonce()`
         * does not call it — a defaulted Kotlin call compiles to the `$default` bridge, so
         * `NonceTest` and `IntentBuilderTest` exercise the behaviour through a different JVM
         * method entirely. Java is the only caller of the published zero-arity form, which is the
         * audience `@JvmOverloads` added it for. Citing the Kotlin suite here would be the
         * "member waved through by a line naming a test that does not do what it says" that
         * `PublicApiAuditTest:513` exists to catch, so `every NOT_FUZZABLE entry names a test
         * that exists` resolves each citation by reflection rather than taking the prose on trust.
         *
         * Capped at a third of the surface by `the fuzz reaches every hostile position` — each
         * entry can be individually reasonable and the set still be a way of not doing this.
         */
        private val NOT_FUZZABLE: Map<String, Excuse> = mapOf(
            "generateNonce()" to Excuse(
                reason = "takes no argument, so there is nothing another app can choose about " +
                    "the call",
                coveredBy = "JavaInteropTest: nonceHelpersAreCallableWithoutAClockOrARandom",
            ),
            "generateNonce(SecureRandom)" to Excuse(
                reason = "its only parameter is the caller's own entropy source, injected so a " +
                    "test can pin it rather than because it crosses a boundary",
                coveredBy = "JavaInteropTest: nonceHelpersAreCallableWithoutAClockOrARandom",
            ),
            "shareDataAction()" to Excuse(
                reason = "takes no argument",
                coveredBy = "JavaInteropTest: actionHelpersAreCallableWithNoArguments",
            ),
            "signChallengeAction()" to Excuse(
                reason = "takes no argument",
                coveredBy = "JavaInteropTest: actionHelpersAreCallableWithNoArguments",
            ),
        )

        /**
         * The reference positions deliberately filled with a real value, by name.
         *
         * A `Context` is the client app's own handle on the framework and a `SecureRandom` is its
         * own entropy source. Neither can arrive from another app across IPC — nothing in this
         * protocol transports one — so neither is a trust boundary, and fuzzing them would be
         * fuzzing the caller rather than the attacker.
         *
         * Stated as a literal set rather than derived from the types, because derived it would be
         * a tautology: the provider decides benignness by type, so asking it the same question
         * back could not fail. Spelled out, a new parameter of either type has to be looked at by
         * somebody, and a position that quietly stopped being fuzzed shows up as a missing line.
         */
        private val BENIGN_POSITIONS = setOf(
            "createQueryIntent(Context, String, String)#0",
            "createQueryIntent(Context, String, String, String)#0",
            "createShareIntent(Context, Entry)#0",
            "createShareIntent(Context, Entry, String)#0",
            "createShareIntent(Context, Entry, String, Set<String>, String)#0",
            "createShareIntent(Context, Entry, String, String)#0",
            "createSignChallengeIntent(Context, String, byte[], String)#0",
            "createSignChallengeIntent(Context, String, byte[], String, String)#0",
            "createSignChallengeIntent(Context, String, byte[], String, String, String)#0",
            "generateNonce(SecureRandom, long)#0",
            "shareEntry(Context, Entry)#0",
            "shareEntry(Context, Entry, String)#0",
        )

        /**
         * The only exception a published function is allowed to raise on a hostile argument, keyed
         * by `method/exception` and carrying its reason and the KDoc that documents it.
         *
         * One entry, and it is not reachable from here. `shareEntry` documents a `SecurityException`
         * (`Utils.kt:219`): a vault that matches the intent but refuses the launch — an activity
         * that is not exported, or one behind a permission the caller does not hold — is a
         * misconfiguration on one side or the other, not a device without a vault, and reporting it
         * as `false` would send the client to tell the user to install an app they already have. It
         * is deliberately not caught. Robolectric installs no vault, so `resolveActivity` returns
         * null and `shareEntry` answers `false` before it starts anything; the entry is stated
         * because the contract exists, and `no published entry point throws on a hostile argument`
         * prints which entries actually fired so one that has stopped being reachable is visible.
         */
        private val TOLERATED: Map<String, String> = mapOf(
            "shareEntry/java.lang.SecurityException" to
                "documented at Utils.kt:219 and deliberately not caught; unreachable under " +
                    "Robolectric, which installs no vault",
        )

        /**
         * The four functions that answer an authentication question, named so that "never
         * positive" can be asserted to be a property of each rather than of the one that happened
         * to run.
         */
        private val AUTHENTICATION_ANSWERS = listOf(
            "verifySignature",
            "verifyRotationStatement",
            "verifyRecoveryAuthorization",
            "verifyRevocation",
        )

        /** See `the corpus is byte-identical on every run`. */
        private const val CORPUS_DIGEST =
            "8ba54e961af92014f2f37babff76c318f8d06ca2d5cf673cb7f341986ccb229b"
    }
}
