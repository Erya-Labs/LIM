package dev.eryalabs.lim

import android.content.Context
import android.content.Intent
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.lang.reflect.Method
import java.lang.reflect.Modifier

/**
 * **Is every key this protocol defines both written and read by published API?** — asked
 * mechanically, of the whole extras surface at once.
 *
 * Nothing in this repository asked it before, and the honest measure of how badly it was needed is
 * the answer: for `extra_query_result_fields`, `extra_fields_json`, `extra_signature` and
 * `extra_algorithm` it was **no** — `Utils` wrote six of the ten extras and merely *read* the other
 * four, so the result half of the wire format existed here as four parsers' expectations and
 * nothing else. Every vault hand-assembled its result intents, the reference vault grew its own
 * builder to do it, and nothing went red for twenty-seven tasks. T28 wrote the four builders; this
 * file is the verifier that stops the next one-sided extra sitting unnoticed for as long.
 *
 * **Which file owns what.** Three verifiers now sweep the published surface and they ask three
 * different questions:
 *
 * - `PublicApiAuditTest` asks "is every public member *tested*" (its manifest) and "has its shape
 *   moved" (its signature snapshot). Neither looks at the wire.
 * - `PublishedSurfaceFuzzTest` (T27) asks "does every published entry point survive hostile
 *   values". It enumerates *methods*.
 * - This file enumerates *keys*, and asks whether each is reachable from both directions.
 *
 * **Both properties are measured by calling, never by grep.** A `grep` for `putExtra` over the
 * source would pass on a line in dead code, would credit a key written only by a `private` helper
 * nobody calls, and would not survive a rename. So:
 *
 * - **Written** — call every published builder at its full arity, union the `extras` key sets of
 *   what comes back, and require every enumerated extra to be in that union. "Full arity" is itself
 *   asserted ([the builder table calls every builder at its full published arity]) by comparing the
 *   arity each call supplies against the maximum reflection reports for that method name: otherwise
 *   "written" quietly means "written in the call I happened to write", and an unsupplied
 *   `algorithm` would make `EXTRA_ALGORITHM` look unwritten when the builder writes it perfectly.
 * - **Read** — a differential. Build a complete well-formed intent for the flow that carries the
 *   extra, parse it with all eight published parsers for a baseline, build the same intent
 *   **without that one extra**, and parse again. The extra is read if any of the eight answers
 *   changed. That is a measurement of the parsers' actual behaviour, and it needs no privileged
 *   access to them.
 *
 * The carrier intent for each extra is not a hand-written table — it is the first builder in
 * [builders] whose output actually carries the key. A hand table would go stale; derived, a new
 * extra that no builder writes is reported on *both* axes at once — a key reachable from neither
 * direction is exactly the failure this file is for, so it is named twice rather than once.
 *
 * **A verifier whose own round created the facts it checks is worth exactly as much as its negative
 * controls**, so both halves are proved able to answer "no" as well as "yes", and both answers come
 * out of the same [classify] call rather than from a second mechanism that could agree with the
 * first by construction. [the read differential reports a key no parser reads as unread] feeds
 * [classify] a fixture key — `extra_symmetry_probe`, a literal here and never in `Utils` — written
 * onto a complete intent by a fixture builder; it comes back in `notRead`.
 * [the written union reports the extras of a builder that writes none as unwritten] feeds the same
 * function a fixture builder returning a bare `Intent()`; every enumerated extra comes back in
 * `notWritten`. A `keySet()` read that silently returned everything, or nothing, fails one of them.
 *
 * **The property this file deliberately does not assert, stated here so nobody adds it later as an
 * obvious improvement:** there is no "each extra belongs to exactly one flow" claim, and there must
 * not be. [Utils.EXTRA_PUBLIC_KEY] and [Utils.EXTRA_SHARE_REQUEST_CODE] are shared across flows by
 * design — the correlation token is the one extra that must survive every answer — and
 * [Utils.EXTRA_FIELDS_JSON] is written by two of the three result builders, the share result and
 * the sign-challenge result, because they carry the same payload under the same key on purpose.
 * A one-flow-per-key assertion would be red on the day it was written and would have to be
 * weakened into meaninglessness to pass.
 *
 * **No keypair is generated and nothing here verifies a signature.** [SIGNATURE_BYTES] is Base64
 * round-trippable and non-empty, which is all `parseSignChallengeResult` asks of it; proof of
 * possession is `ResultBuilderTest`'s and `SignatureVerificationTest`'s. That is deliberate and it
 * is what keeps this file — breadth over twelve keys and eight parsers — well under a second. The
 * measured wall-clock is printed on every run.
 *
 * Robolectric is required: [Intent] extras and `android.util.Base64` are unimplemented stubs in a
 * plain JVM unit test.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ProtocolSymmetryTest {

    // ── The enumeration ──────────────────────────────────────────────────

    /**
     * Every extra the protocol defines, by constant name and wire value, read off [Utils] rather
     * than listed here.
     *
     * A list would be the thing this file exists to replace: it would have been written with the
     * same six names the builders already wrote, and the four one-sided keys would have been as
     * invisible to it as they were to everything else. `public static final String` whose name
     * starts with `EXTRA_` is what a Kotlin `const val` in an `object` compiles to, so the filter
     * is the published shape and not an approximation of it.
     */
    private val extras: Map<String, String> = Utils::class.java.declaredFields
        .filter { field ->
            field.name.startsWith("EXTRA_") &&
                field.type == String::class.java &&
                Modifier.isPublic(field.modifiers) &&
                Modifier.isStatic(field.modifiers) &&
                Modifier.isFinal(field.modifiers) &&
                !field.isSynthetic
        }
        .sortedBy { it.name }
        .associate { field -> field.name to field.get(null) as String }

    // ── The fixtures ─────────────────────────────────────────────────────

    private val context: Context = ApplicationProvider.getApplicationContext()

    private val entry = Entry(
        id = "ada",
        fields = linkedMapOf("email" to TypedField("ada@example.com", FieldType.EMAIL)),
        publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A-client-key",
    )

    /**
     * Non-empty on purpose, and the one fixture choice that is load-bearing rather than decorative.
     * An empty map encodes to `{}`, which [Utils.decodeFields] and an *absent* extra both read as
     * an empty map — so the read differential over the two field keys would see no change and
     * report them unread, with nothing wrong in `Utils` at all.
     */
    private val fields = linkedMapOf(
        "email" to TypedField("ada@example.com", FieldType.EMAIL),
        "age" to TypedField("36", FieldType.INTEGER),
    )

    private val nonce = Utils.generateNonce(now = FIXED_CLOCK)

    // ── The builder table ────────────────────────────────────────────────

    /**
     * One published builder, one valid call, and the arity that call supplies.
     *
     * [arity] is stated rather than counted from the lambda because a lambda has no arity to count:
     * it is the number this file claims to be passing, checked against reflection by
     * [the builder table calls every builder at its full published arity]. A call that quietly
     * dropped an optional argument would otherwise make its key look unwritten.
     *
     * **Two limits of that check, stated rather than left for a reader to discover.** It compares
     * the claim against reflection, not the claim against the call, so a lambda edited to pass
     * fewer arguments while [arity] stays put is invisible *to it*. Most such edits are caught by
     * the properties instead — dropping `nonceFormat`, `algorithm` or `fields` makes a key
     * unwritten or unread — and the one that is not is a bare third positional argument to
     * `createShareIntent`, which binds the `targetPackage` overload and drops
     * [Utils.EXTRA_SHARE_REQUEST_CODE]: that key has five other writers, so the union stays
     * complete. Second, the table calls the `String`-first family of each result builder and never
     * the `request`-first family, and keying on the method name cannot tell them apart since both
     * top out at the same arity. Safe direction: those overloads delegate, so a future divergence
     * would show up as a key reported unwritten — a false red that forces a row to be added here,
     * not a false green.
     */
    private class Builder(val name: String, val arity: Int, val build: () -> Intent)

    private val builders: List<Builder> = listOf(
        // `requestCode` by name, not positionally: a bare third string binds to the
        // `targetPackage` overload and addresses the intent to a package named `req-1`, which is
        // the hazard `createShareIntent`'s own KDoc spends a paragraph on.
        //
        // The fullest `createShareIntent` is the required-fields overload, at 5, so that is the
        // one called: it delegates through the 1.0.0 request-code overload and then adds the
        // declaration, so every key that overload wrote is still written here. `email` is named
        // optional because it is a field of [entry]; a name the entry lacked would be dropped and
        // the declaration would read the same with or without the extra.
        Builder("createShareIntent", 5) {
            Utils.createShareIntent(
                context,
                entry,
                requestCode = CODE,
                optionalFields = setOf("email"),
                targetPackage = VAULT_PACKAGE,
            )
        },
        Builder("createQueryIntent", 4) {
            Utils.createQueryIntent(context, VAULT_KEY, CODE, VAULT_PACKAGE)
        },
        Builder("createSignChallengeIntent", 6) {
            Utils.createSignChallengeIntent(
                context,
                VAULT_KEY,
                nonce,
                CODE,
                VAULT_PACKAGE,
                Utils.NONCE_FORMAT_TIMESTAMPED,
            )
        },
        // The fullest share-result builder is the requirements-aware one, at 4. The fixture
        // requirements name `age` optional and the payload fills both fields, so they are
        // satisfied and the acknowledgement is written — over an unsatisfied payload it would be
        // omitted, and the key would look unwritten with nothing wrong in `Utils`.
        Builder("createShareResultIntent", 4) {
            Utils.createShareResultIntent(
                VAULT_KEY,
                fields,
                CODE,
                FieldRequirements(fields.keys, setOf("age")),
            )
        },
        Builder("createQueryResultIntent", 3) {
            Utils.createQueryResultIntent(VAULT_KEY, fields, CODE)
        },
        Builder("createSignChallengeResultIntent", 4) {
            Utils.createSignChallengeResultIntent(SIGNATURE_BYTES, fields, CODE, ALGORITHM)
        },
    )

    // ── The mechanism ────────────────────────────────────────────────────

    /**
     * The eight published parsers, in a fixed order, applied to the same intent.
     *
     * Order matters only for reproducibility; what matters for the property is that all eight are
     * here, which [the enumeration and the table meet their floors] pins by count. Every one of the
     * eight parsed types compares by content — `SignChallengeRequest` and `SignChallengeResult`
     * override `equals` precisely because a data class would compare their arrays by identity,
     * `FieldRequirements` declares its own equality, and the acknowledgement is a plain read-only
     * set — so list equality below is a comparison of answers and not of references.
     */
    private fun parseAll(intent: Intent): List<Any?> = listOf(
        Utils.parseShareRequest(intent),
        Utils.parseQueryRequest(intent),
        Utils.parseSignChallengeRequest(intent),
        Utils.parseShareResult(intent),
        Utils.parseQueryResult(intent),
        Utils.parseSignChallengeResult(intent),
        // Required fields' two readers.
        Utils.parseFieldRequirements(intent),
        Utils.parseAppliedOptionalFields(intent),
    )

    /**
     * The read differential: does removing [wireKey] from an otherwise complete intent change what
     * any published parser says?
     *
     * [build] is invoked twice rather than the intent being copied, so the stripped envelope is the
     * builder's own output minus one key and not a clone whose extras bundle might be shared.
     */
    private fun isRead(build: () -> Intent, wireKey: String): Boolean {
        val complete = build()
        check(complete.hasExtra(wireKey)) { "the carrier for $wireKey does not carry it" }
        val baseline = parseAll(complete)
        val stripped = build().apply { removeExtra(wireKey) }
        check(!stripped.hasExtra(wireKey)) { "removeExtra($wireKey) did not remove it" }
        return parseAll(stripped) != baseline
    }

    /** What one run of [classify] measured. Names, not wire values; messages render both. */
    private class Symmetry(
        val written: Set<String>,
        val notWritten: List<String>,
        val notRead: List<String>,
        val unclassifiable: List<String>,
        val classified: Set<String>,
        val elapsedMillis: Long,
    )

    /**
     * Classify every entry of [enumerated] on both axes, using [table] as the whole of the
     * published builder surface.
     *
     * Both negative controls call this with a different [table] or a different [enumerated] and
     * read the answers out of the same fields the real properties read, which is the point: two
     * mechanisms, one for the yes answers and one for the no answers, would agree by construction
     * and prove nothing.
     *
     * An extra no builder in [table] writes lands in [Symmetry.unclassifiable] as well as
     * [Symmetry.notWritten] — there is no complete intent to run the read differential against, so
     * reporting it unread would be a guess. That is not a gap: a key reachable from neither
     * direction is exactly the failure this file is for, and it is reported twice rather than
     * silently once.
     */
    private fun classify(table: List<Builder>, enumerated: Map<String, String>): Symmetry {
        val startedAt = System.nanoTime()
        val written = table.flatMap { it.build().extras?.keySet() ?: emptySet() }.toSet()
        val notWritten = mutableListOf<String>()
        val notRead = mutableListOf<String>()
        val unclassifiable = mutableListOf<String>()
        val classified = linkedSetOf<String>()

        enumerated.forEach { (name, wireKey) ->
            if (wireKey !in written) notWritten += name
            val carrier = table.firstOrNull { it.build().hasExtra(wireKey) }
            if (carrier == null) {
                unclassifiable += name
            } else {
                if (!isRead(carrier.build, wireKey)) notRead += name
                classified += name
            }
        }

        return Symmetry(
            written = written,
            notWritten = notWritten.sorted(),
            notRead = notRead.sorted(),
            unclassifiable = unclassifiable.sorted(),
            classified = classified,
            elapsedMillis = (System.nanoTime() - startedAt) / 1_000_000,
        )
    }

    /** One run for the whole class; every property below reads this one measurement. */
    private val measured: Symmetry by lazy { classify(builders, extras) }

    private fun render(names: List<String>): List<String> =
        names.map { "$it (${extras[it] ?: "not enumerated"})" }

    // ── The two properties ───────────────────────────────────────────────

    @Test
    fun `every extra this protocol defines is written by a published builder`() {
        assertEquals(
            "these extras are defined by the protocol and written by nothing this library " +
                "publishes, so every peer that sends one spells it by hand — which is how four " +
                "of them sat unwritten for twenty-seven tasks. Add a builder that writes it, or " +
                "excuse it in NOT_WRITTEN with a reason and a covering test and say in the " +
                "commit message why a one-sided key is right this time",
            emptyList<String>(),
            render(measured.notWritten.filterNot { it in NOT_WRITTEN }),
        )
    }

    /**
     * [Symmetry.unclassifiable] counts against this property as well as against the written one,
     * and that is deliberate rather than double-counting. The claim here is that every extra is
     * *demonstrably* read, and a key no builder writes has no complete intent to strip — so there
     * is no demonstration, only an absence of one. The message keeps the two causes apart because
     * the fixes differ: one needs a parser, the other needs a builder first.
     */
    @Test
    fun `every extra this protocol defines is read by a published parser`() {
        assertEquals(
            "these extras are not demonstrably read by published API. For one in the first " +
                "group, removing it from a complete intent changed no published parser's " +
                "answer, so the protocol defines a key nothing here reads: a peer that sends " +
                "one is talking to itself. For one in the second, no published builder writes " +
                "it either, so there was no complete intent to strip and the read side cannot " +
                "be measured at all — fix the written property first. Add a parser that reads " +
                "it, or excuse it in NOT_READ with a reason and a covering test",
            emptyList<String>(),
            render(measured.notRead.filterNot { it in NOT_READ }) +
                render(measured.unclassifiable.filterNot { it in NOT_READ }),
        )
    }

    // ── Negative controls ────────────────────────────────────────────────

    /**
     * Control (a): the read differential must be able to answer "no".
     *
     * `extra_symmetry_probe` is a literal in this file and appears nowhere in `Utils`, so no parser
     * can read it — and it is carried by a *complete* query-result intent, not a bare one, so the
     * differential has real answers on both sides and the only difference is the probe. One
     * mechanism, two answers, and no mutation of main source required to get the second.
     */
    @Test
    fun `the read differential reports a key no parser reads as unread`() {
        val carrier = builders.single { it.name == "createQueryResultIntent" }
        val probing = Builder("a fixture builder, not published API", 0) {
            carrier.build().apply { putExtra(PROBE_KEY, "present") }
        }

        val control = classify(
            builders + probing,
            extras + (PROBE_NAME to PROBE_KEY),
        )

        // Scoped to the probe deliberately: the whole-table claim belongs to the real property
        // above, and a control that restated it would redden for somebody else's reason.
        assertFalse(
            "the probe key is written by the fixture builder, so it must not be reported " +
                "unwritten — if it is, the written union is not seeing the fixture's output",
            PROBE_NAME in control.notWritten,
        )
        assertTrue(
            "the read differential reported a key no parser reads as read. It is therefore " +
                "answering yes unconditionally, and the real property above means nothing",
            PROBE_NAME in control.notRead,
        )
        // …and the same differential, in the same run, still answers yes for a real key on the
        // same intent. Without this the control would pass against a mechanism that answered no
        // to everything, which is the other way round to be useless.
        //
        // The name is resolved against the enumeration first, because a name the enumeration does
        // not produce can never appear in `notRead` — so a renamed constant would turn the probe
        // below into a tautology and quietly cost this control its yes half.
        assertTrue(
            "$CARRIED_KEY_NAME is not an enumerated extra, so the probe below asserts nothing",
            CARRIED_KEY_NAME in extras.keys,
        )
        assertFalse(
            "the read differential reported every key unread, so its no answers mean nothing",
            CARRIED_KEY_NAME in control.notRead,
        )
        assertTrue(
            "the probe must be classified like any other key, out of the same loop",
            PROBE_NAME in control.classified,
        )
    }

    /**
     * Control (b): the written union must be able to answer "no".
     *
     * A `keySet()` read that silently returned everything — the shape a `Bundle` mistake takes —
     * passes the real property and fails here.
     */
    @Test
    fun `the written union reports the extras of a builder that writes none as unwritten`() {
        val bare = Builder("a fixture builder, not published API", 0) { Intent() }

        val control = classify(listOf(bare), extras)

        assertTrue(
            "a bare Intent contributed extras to the union, so the collection is not reading " +
                "what the builder actually wrote",
            control.written.isEmpty(),
        )
        assertEquals(
            "every enumerated extra must be reported unwritten against a builder that writes " +
                "none. A shortfall here means the union is answering yes unconditionally",
            extras.keys.sorted(),
            control.notWritten,
        )
        assertEquals(
            "…and with nothing written there is no complete intent to strip, so every extra is " +
                "unclassifiable on the read axis rather than guessed at",
            extras.keys.sorted(),
            control.unclassifiable,
        )
        assertTrue(
            "no extra may be classified when nothing was written",
            control.classified.isEmpty(),
        )

        // The other direction, from the same function: the real table writes every enumerated key.
        // Without this, a `classify` that returned empty sets for everything would pass above.
        assertEquals(
            "the real builder table must write every enumerated extra, measured by the same " +
                "collection the control just used",
            extras.values.toSet(),
            measured.written.intersect(extras.values.toSet()),
        )
    }

    // ── Floors and completeness ──────────────────────────────────────────

    /**
     * Shortfalls against the fullest arity reflection reports for each name — computed by
     * [shortfalls] so the control below can run the identical comparison over a table that is
     * wrong on purpose. `publishedArities(name).max()` is the measurement; [Builder.arity] is the
     * claim; this is where the two meet.
     */
    private fun shortfalls(table: List<Builder>): List<String> = table.mapNotNull { builder ->
        val arities = publishedArities(builder.name)
        check(arities.isNotEmpty()) { "${builder.name} is not a published method of Utils" }
        val fullest = arities.max()
        if (builder.arity == fullest) {
            null
        } else {
            "${builder.name}: the table calls ${builder.arity} of $fullest"
        }
    }.sorted()

    @Test
    fun `the builder table calls every builder at its full published arity`() {
        assertEquals(
            "a builder is called with fewer arguments than it publishes, so an extra written " +
                "only by the omitted argument would be reported unwritten when the builder is " +
                "correct. Supply every optional argument",
            emptyList<String>(),
            shortfalls(builders),
        )

        // Non-vacuity, out of the same function: with all six arities correct the list above is
        // empty, so `arity == fullest` could be `true` unconditionally and nothing here would
        // notice. A fixture table that understates one arity on purpose is what makes the
        // comparison a measurement — `createSignChallengeResultIntent` publishes 1 through 4, so
        // claiming 1 is a genuine three-argument shortfall and must be reported as one.
        assertEquals(
            "the arity comparison cannot report a shortfall, so the assertion above is green " +
                "whatever the table claims",
            listOf("createSignChallengeResultIntent: the table calls 1 of 4"),
            shortfalls(listOf(Builder("createSignChallengeResultIntent", 1) { Intent() })),
        )
    }

    @Test
    fun `the enumeration and the table meet their floors, and every extra is classified twice`() {
        println(
            "ProtocolSymmetryTest: extras=${extras.size} builders=${builders.size} " +
                "parsers=${parseAll(Intent()).size} written=${measured.written.size} " +
                "elapsed=${measured.elapsedMillis}ms",
        )

        assertTrue(
            "only ${extras.size} extras enumerated, below the floor of $MINIMUM_EXTRAS — the " +
                "reflection filter has drifted towards the empty set and both properties above " +
                "are passing over almost nothing",
            extras.size >= MINIMUM_EXTRAS,
        )
        assertTrue(
            "only ${builders.size} builders in the table, below the floor of $MINIMUM_BUILDERS",
            builders.size >= MINIMUM_BUILDERS,
        )
        // Both directions, and the second is the one that matters: comparing `parseAll`'s length
        // against a constant in the same file only catches a line *deleted* from it. A parser
        // *added* to `Utils` and never wired in here is caught by counting them off the published
        // surface instead — eight today, and a ninth makes this red until parseAll names it.
        assertEquals(
            "a line has been removed from parseAll, so the differential no longer runs every " +
                "parser and an extra only that parser reads would be reported unread",
            PARSER_COUNT,
            parseAll(Intent()).size,
        )
        assertEquals(
            "Utils publishes ${publishedParserNames.size} intent parsers and parseAll runs " +
                "$PARSER_COUNT. A parser added without a line in parseAll is a reader this file " +
                "is blind to: ${publishedParserNames.sorted()}",
            PARSER_COUNT,
            publishedParserNames.size,
        )

        // Completeness, stated positively — the read property states the same fact as an absence,
        // and both are worth having: this one fails if `classify` silently stopped looping, which
        // an empty `notRead` list cannot distinguish from a clean run.
        assertEquals(
            "every enumerated extra must be classified on both axes: a measured write answer " +
                "and a measured read answer. A name missing here was never measured at all",
            extras.keys,
            measured.classified,
        )
    }

    /**
     * Both excuse maps are empty, which is this round's achievement stated as an assertion rather
     * than as a sentence: after T28 there is no key in this protocol that published API writes but
     * never reads, or reads but never writes.
     *
     * The maps are not decoration — the two properties above subtract them, so they are the
     * documented way to land a deliberately one-sided key. Adding an entry means editing this
     * assertion too, which is the point: a one-sided extra should cost a human a decision and a
     * written reason, not a quiet line in a map.
     */
    @Test
    fun `no extra is excused today, and no excuse names a key the enumeration did not produce`() {
        assertEquals(
            "an extra is excused from the written property. That may be right, but it is a " +
                "protocol key no published builder writes — say in the commit message why, and " +
                "keep the citation current",
            emptyMap<String, Excuse>(),
            NOT_WRITTEN,
        )
        assertEquals(
            "an extra is excused from the read property — a key this library sends and nothing " +
                "here can interpret",
            emptyMap<String, Excuse>(),
            NOT_READ,
        )

        // A renamed constant must not be able to leave a dead excuse behind, waving through a key
        // the enumeration now reports under a different name.
        assertEquals(
            "an excuse names a constant reflection cannot find on Utils. A renamed or removed " +
                "EXTRA_ must be updated here, or the key it excused is silently unchecked",
            emptyList<String>(),
            (NOT_WRITTEN.keys + NOT_READ.keys).filterNot { it in extras.keys }.sorted(),
        )

        // The other kind of stale excuse, and the one the emptiness assertions above will stop
        // catching the moment somebody deletes them to add the first entry: an excuse for a key
        // that has since become two-sided excuses nothing, and leaving it there means the next
        // regression on that key is waved through by a line nobody re-read.
        // `PublishedSurfaceFuzzTest:815`'s rule, applied to keys rather than methods. Vacuous
        // today by construction; written now, while it costs nothing, rather than later when it
        // would have to be noticed first.
        assertEquals(
            "these keys are excused from the written property but a published builder does " +
                "write them. The excuse is stale — delete it",
            emptyList<String>(),
            NOT_WRITTEN.keys.filterNot { it in measured.notWritten }.sorted(),
        )
        assertEquals(
            "these keys are excused from the read property but a published parser does read " +
                "them. The excuse is stale — delete it",
            emptyList<String>(),
            NOT_READ.keys
                .filterNot { it in measured.notRead || it in measured.unclassifiable }
                .sorted(),
        )
    }

    /**
     * The excuse maps' *values*, machine-checked — `PublishedSurfaceFuzzTest`'s rule and
     * `PublicApiAuditTest`'s before it: a citation that resolves to no real `@Test` waves a member
     * through on prose alone.
     *
     * The loop over the maps is **vacuous today**, deliberately, because both maps are empty. So
     * the resolver itself is what is asserted here instead: that it can fail on a citation nobody
     * wrote and succeed on one of the shape an excuse would use. Without those two probes this
     * test would pass unchanged if the resolver were replaced with `true`, and the first excuse
     * anybody ever adds would be checked by nothing.
     */
    @Test
    fun `every excuse names a test that exists, and the resolver can tell`() {
        val dangling = (NOT_WRITTEN + NOT_READ).entries.mapNotNull { (name, excuse) ->
            if (resolves(excuse.coveredBy)) null else "$name -> ${excuse.coveredBy}"
        }.sorted()
        assertEquals(
            "an excuse cites a @Test that does not exist under the class it names",
            emptyList<String>(),
            dangling,
        )

        assertEquals(
            "every excuse must carry a reason as well as a citation",
            emptyList<String>(),
            (NOT_WRITTEN + NOT_READ).filterValues { it.reason.isBlank() }.keys.sorted(),
        )

        assertFalse(
            "the resolver must be able to fail, or it is reporting success unconditionally",
            resolves("ResultBuilderTest: a test nobody wrote"),
        )
        assertFalse(
            "…and it must be able to fail on a class that does not exist either",
            resolves("NoSuchTest: a test nobody wrote"),
        )
        assertTrue(
            "…and it must be able to succeed on a citation of the shape an excuse would use",
            resolves("ResultParsingTest: $REFERENCE_TEST"),
        )
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    /**
     * The published parsers, by name, read off [Utils] rather than counted from [parseAll]'s
     * length — a single-`Intent`-parameter `parse*` function is what one is.
     *
     * Deliberately *not* used to invoke them: reflection would make the eight calls in [parseAll]
     * uniform and unreadable, and the list there is the thing a reader should be able to check by
     * eye. This is only the census that notices a ninth.
     */
    private val publishedParserNames: Set<String> = Utils::class.java.declaredMethods
        .filter { method ->
            method.name.startsWith("parse") &&
                method.isPublishedApi() &&
                method.parameterTypes.singleOrNull() == Intent::class.java
        }
        .map(Method::getName)
        .toSet()

    /**
     * Every arity reflection reports for a published method of [Utils] named [name].
     *
     * `PublicApiAuditTest:462`'s filter verbatim: public, not synthetic, not a bridge. The
     * `$default` bridges `@JvmOverloads` and Kotlin's own defaults generate are dropped a step
     * earlier, by the name comparison — they are named `createShareIntent$default` and friends —
     * so no fullest arity can be overstated by their extra mask parameter.
     */
    private fun publishedArities(name: String): List<Int> = Utils::class.java.declaredMethods
        .filter { it.name == name && it.isPublishedApi() }
        .map(Method::getParameterCount)

    private fun Method.isPublishedApi(): Boolean =
        Modifier.isPublic(modifiers) && !isSynthetic && !isBridge

    /** `ClassName: test method name`, the shape the audit's own manifest uses. */
    private fun resolves(citation: String): Boolean = runCatching {
        Class.forName("dev.eryalabs.lim.${citation.substringBefore(": ")}")
            .declaredMethods
            .any {
                it.name == citation.substringAfter(": ") && it.isAnnotationPresent(Test::class.java)
            }
    }.getOrDefault(false)

    private companion object {
        /**
         * Why an extra is one-sided on purpose, and what covers it instead — two fields rather than
         * one sentence, so [coveredBy] can be resolved against a real `@Test`.
         * `PublishedSurfaceFuzzTest:1049`'s class, deliberately duplicated rather than shared: a
         * type two files declare is a type neither can change, and this one is four lines.
         */
        private data class Excuse(val reason: String, val coveredBy: String)

        /**
         * Empty, and asserted so — see
         * [no extra is excused today, and no excuse names a key the enumeration did not produce].
         */
        private val NOT_WRITTEN: Map<String, Excuse> = emptyMap()

        /** Ditto. */
        private val NOT_READ: Map<String, Excuse> = emptyMap()

        /**
         * Twelve today, and the floor is the same twelve rather than something lower: unlike
         * `PublishedSurfaceFuzzTest`'s method count, this number cannot grow by accident — adding
         * an extra is a wire change, and the two properties are what notice it. What the floor
         * catches is the reflection filter drifting towards the empty set. The actual is printed on
         * every run. It was ten until required fields added `EXTRA_OPTIONAL_FIELDS` and
         * `EXTRA_APPLIED_OPTIONAL_FIELDS`, and moved with them so that it stays the measured value.
         */
        private const val MINIMUM_EXTRAS = 12

        /** Three request builders and three result builders, as of T28. */
        private const val MINIMUM_BUILDERS = 6

        /**
         * Three request parsers and three result parsers, plus required fields' two readers —
         * `parseFieldRequirements` and `parseAppliedOptionalFields`, each a published single-`Intent`
         * `parse*` function, which is what the census below counts.
         */
        private const val PARSER_COUNT = 8

        private const val CODE = "req-1"
        private const val VAULT_PACKAGE = "com.example.vault"
        private const val VAULT_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A-vault-key"
        private const val ALGORITHM = "SHA256withRSA"

        /** A fixed clock, so the nonce fixture means the same thing tomorrow. */
        private const val FIXED_CLOCK = 1_770_000_000_000L

        /**
         * Not a signature and not pretending to be one — see the class KDoc. Non-empty and Base64
         * round-trippable is the whole requirement `parseSignChallengeResult` places on it.
         */
        private val SIGNATURE_BYTES = ByteArray(64) { (it * 7 + 1).toByte() }

        /** A key `Utils` does not define and no parser reads. Control (a) depends on both. */
        private const val PROBE_NAME = "EXTRA_SYMMETRY_PROBE"
        private const val PROBE_KEY = "extra_symmetry_probe"

        /**
         * The real key control (a) rides alongside the probe, so that one run of the differential
         * answers both yes and no. The query-result flow's own field payload, and
         * [the read differential reports a key no parser reads as unread] checks it is still
         * enumerated before relying on it.
         */
        private const val CARRIED_KEY_NAME = "EXTRA_QUERY_RESULT_FIELDS"

        /** A real `@Test` in `ResultParsingTest`, for the resolver's can-succeed probe. */
        private const val REFERENCE_TEST = "each parser reads only its own fields key"
    }
}
