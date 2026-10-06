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
     * the tests that touch it — four of the seven, ~15ms apiece. They are the same enumeration
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
                calls += call(method, key, args)
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

        private const val PAYLOAD_PREVIEW = 120
        private const val HEX = "0123456789abcdef"

        /** A fixed clock, so nothing here means something different tomorrow. */
        private const val FUZZ_CLOCK = 1_770_000_000_000L

        /**
         * Below the measured 47, so that *adding* a published member does not fail this — the
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
