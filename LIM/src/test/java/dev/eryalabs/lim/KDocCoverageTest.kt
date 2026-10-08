package dev.eryalabs.lim

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * **No test in this repository had ever read a doc comment.** `PublicApiAuditTest` answers "is
 * every published member tested" and "has its shape moved", `ProtocolSymmetryTest` answers "is
 * every extra key two-sided", `PublishedSurfaceFuzzTest` answers "does every entry point survive
 * hostile values". None of them can tell an integrator what a parameter *means*, and the KDoc that
 * can was backed by nothing — which is how `Entry`, the first type an integrator constructs, went
 * this long with no class comment at all, and how `shareEntry` ended up with a `@return`, a
 * `@throws` and not one `@param`.
 *
 * Two rules, scoped narrowly on purpose so that neither widens into style policing:
 *
 *  1. **every parameter of every published function has a `@param`**, and every `@param` names a
 *     parameter the function actually has — the second half is what catches a rename;
 *  2. **every public property or constant of every published type is documented**, either by an
 *     `@property` on the type (the house style for a constructor property) or by its own doc
 *     comment (the house style for a `const val` or an enum constant) — and every `@property`
 *     names a property the type actually declares.
 *
 * **There is deliberately no `@return` rule.** The nine `@return` tags in `Utils.kt` sit on the
 * functions whose return value is a *verdict* rather than the thing the summary already names, and
 * a blanket rule would mint "Returns the intent." lines — filler that makes a surface look
 * documented while telling a reader nothing. Which functions earn one stays a judgement.
 *
 * **What is out of scope, stated so nobody widens it later.** Private and `internal` members: a
 * `@param` added to or removed from one changes nothing here, because the subject is the surface a
 * third party reads. `override` declarations: `equals(other)`, `hashCode()`, `toString()` and the
 * `Parceler` pair are Kotlin's and Android's signatures rather than this library's API decisions,
 * and an override's contract is its supertype's — which is also where its doc belongs. And the
 * *wording*: this file pins coverage, not prose. Reflowing a doc comment without touching a tag
 * reddens nothing, and whether the prose reads well is a human judgement (VISION).
 *
 * **The hard part is the parameter list, because multi-line is the house style here.** A line-wise
 * reader would see `fun createShareIntent(` and no parameters at all. So each file is masked
 * (comments and string literals blanked, newlines kept), declarations are found over the masked
 * text, and every parameter list is read from `(` to the matching `)` by counting parentheses over
 * the joined text. Overloads are keyed by name *and* rendered parameter list, because
 * `createShareIntent` is two functions and only one of them carried the `@param targetPackage`.
 *
 * **Three limits, recorded rather than left to be discovered**, since none is reachable from
 * anything this library publishes today and all three would be a silent hole if it grew one:
 *
 *  - [DECLARATION] recognises `class`, `object`, `interface`, `fun`, `val` and `var`, so a
 *    published `typealias` or a published **secondary** `constructor` is invisible to both rules.
 *  - A member key renders the parameter *types* but not an extension receiver, so
 *    `fun String.foo(x: Int)` and `fun Int.foo(x: Int)` would collide at `foo(Int)` and one
 *    [Excuse] would cover both. Nothing in `LIM/src/main/` is an extension on a published surface.
 *  - Kotlin block comments nest and the masker does not; see [mask].
 *
 * Regex and a character walk over 16 files, so it runs in milliseconds: no Robolectric, and no
 * reflection beyond resolving an excuse's citation.
 */
class KDocCoverageTest {

    // ── What a source file declares ───────────────────────────────────────

    /** Which rule a declaration falls under. */
    private enum class Kind { TYPE, FUNCTION, PROPERTY }

    /** One parameter, as written: `fields: Map<String, TypedField> = emptyMap()`. */
    private class Parameter(val name: String, val type: String, modifiers: String) {
        private val words: List<String> = MODIFIER_WORD.findAll(modifiers).map { it.value }.toList()

        /** A constructor parameter declared `val`/`var` is a property; a bare one is not. */
        val isProperty: Boolean = words.any { it in PROPERTY_WORDS }

        val isOverride: Boolean = "override" in words

        val isHidden: Boolean = words.any { it in HIDDEN_WORDS }
    }

    /**
     * A published member the rules have something to say about.
     *
     * [key] is what an excuse is spelled with and what a failure names: `Utils.shareEntry(Context,
     * Entry, String)` for a function, `Utils.EXTRA_NONCE` for a constant. The rendered parameter
     * list is part of it because two overloads are two members with two doc comments, and keying
     * by name alone would let the documented one vouch for the undocumented one.
     */
    private class Member(
        val kind: Kind,
        val file: String,
        val line: Int,
        val name: String,
        val key: String,
        val owner: String,
        val parameters: List<Parameter>,
        val doc: String?,
        val ownerDoc: String?,
        /** For a function: whether the scanner located a parameter list at all. See [headOf]. */
        val parameterListFound: Boolean = true,
        /** Whether the head walk ended somewhere a head legitimately ends. See [headOf]. */
        val headUnderstood: Boolean = true,
    ) {
        val where: String = "$key ($file:$line)"
    }

    /**
     * Why a published member's gap is left open, and what covers it instead — two fields rather
     * than one sentence, so [coveredBy] can be resolved against a real `@Test` instead of taken on
     * trust. `PublishedSurfaceFuzzTest`'s form, spelled `ClassName: test method name`.
     *
     * An excuse suppresses a *coverage* gap only. A stale `@param` or `@property` is a doc comment
     * that is wrong rather than one that is absent, and there is nothing to excuse about it.
     */
    private class Excuse(val reason: String, val coveredBy: String)

    /** Every complaint the sources produce, so the real tests and the controls share one loop. */
    private class Report(
        val members: List<Member>,
        val undocumentedParameters: List<String>,
        val staleParameterTags: List<String>,
        val undocumentedProperties: List<String>,
        val stalePropertyTags: List<String>,
        val danglingExcuses: List<String>,
        val inertExcuses: List<String>,
    ) {
        val types: List<Member> = members.filter { it.kind == Kind.TYPE }
        val functions: List<Member> = members.filter { it.kind == Kind.FUNCTION }
        val properties: List<Member> = members.filter { it.kind == Kind.PROPERTY }
        val parameterCount: Int = functions.sumOf { it.parameters.size }
    }

    // ── The one measurement every assertion below reads ───────────────────

    /**
     * Every published declaration in [sources], against [excuses].
     *
     * The published surface is computed from the source rather than by reflection on purpose:
     * reflection cannot see a doc comment at all, and it cannot see the difference between the two
     * `createShareIntent` overloads' *documentation* — only their signatures, which
     * `PublicApiAuditTest` already pins.
     */
    private fun audit(sources: Map<String, String>, excuses: Map<String, Excuse>): Report {
        val members = sources.entries.sortedBy { it.key }.flatMap { membersIn(it.key, it.value) }

        val declared = mutableMapOf<String, MutableSet<String>>()
        sources.entries.sortedBy { it.key }.forEach { (_, text) ->
            declaredPropertyNamesIn(text).forEach { (path, names) ->
                declared.getOrPut(path) { mutableSetOf() } += names
            }
        }

        val undocumentedParameters = mutableListOf<String>()
        val staleParameterTags = mutableListOf<String>()
        val undocumentedProperties = mutableListOf<String>()
        val stalePropertyTags = mutableListOf<String>()
        val excusedKeys = mutableSetOf<String>()

        for (member in members) {
            when (member.kind) {
                Kind.FUNCTION -> {
                    val tagged = tagsIn(member.doc, "param")
                    val names = member.parameters.map { it.name }
                    val missing = names.filterNot { it in tagged }
                    if (missing.isNotEmpty() && member.key in excuses) {
                        excusedKeys += member.key
                    } else {
                        missing.forEach {
                            undocumentedParameters +=
                                "${member.where} — parameter `$it` has no @param"
                        }
                    }
                    tagged.filterNot { it in names }.forEach {
                        staleParameterTags += "${member.where} — @param `$it` names no parameter " +
                            "of it; its parameters are " +
                            (if (names.isEmpty()) "none" else names.joinToString(", "))
                    }
                }

                Kind.PROPERTY -> {
                    val documented =
                        member.doc != null || member.name in tagsIn(member.ownerDoc, "property")
                    if (!documented) {
                        if (member.key in excuses) {
                            excusedKeys += member.key
                        } else {
                            undocumentedProperties += "${member.where} — no doc comment of its " +
                                "own and no `@property ${member.name}` on " +
                                member.owner.ifEmpty { member.file }
                        }
                    }
                }

                Kind.TYPE -> {
                    val names = declared[member.key].orEmpty()
                    tagsIn(member.doc, "property").filterNot { it in names }.forEach {
                        stalePropertyTags += "${member.where} — @property `$it` names no property " +
                            "it declares; it declares " +
                            (if (names.isEmpty()) "none" else names.sorted().joinToString(", "))
                    }
                }
            }
        }

        val keys = members.map { it.key }.toSet()
        return Report(
            members = members,
            undocumentedParameters = undocumentedParameters.sorted(),
            staleParameterTags = staleParameterTags.sorted(),
            undocumentedProperties = undocumentedProperties.sorted(),
            stalePropertyTags = stalePropertyTags.sorted(),
            danglingExcuses = excuses.keys.filterNot { it in keys }.sorted(),
            inertExcuses = excuses.keys.filter { it in keys && it !in excusedKeys }.sorted(),
        )
    }

    /**
     * The published sources, measured once for the whole class.
     *
     * `GuideSnippetTest`'s lesson, learned there the expensive way: JUnit constructs a fresh
     * instance per test method, so a per-instance `by lazy` would re-read and re-scan every source
     * once per assertion. The files cannot change within a run, and editing one re-runs the class
     * from scratch.
     */
    private fun onDisk(): Report = cachedOnDisk
        ?: audit(publishedSources(), EXCUSES).also { cachedOnDisk = it }

    // ── The two rules ─────────────────────────────────────────────────────

    @Test
    fun `every parameter of every published function has a param tag`() {
        assertEquals(
            "a published function takes a parameter its KDoc does not mention. An integrator " +
                "reading this surface in an IDE sees a name and a type and nothing about what to " +
                "pass — which is how `shareEntry` ended up with a @return, a @throws and no " +
                "@param at all",
            emptyList<String>(),
            onDisk().undocumentedParameters,
        )
        // Floor: a scanner that found no parameters would report no offenders for ever.
        assertTrue(
            "the scan must find parameters for this to mean anything; found " +
                "${onDisk().parameterCount} across ${onDisk().functions.size} published functions",
            onDisk().parameterCount >= MINIMUM_PARAMETERS,
        )
    }

    @Test
    fun `every param tag names a parameter the function has`() {
        assertEquals(
            "a KDoc documents a parameter its function does not have. This is the half that " +
                "catches a rename: renaming a parameter without renaming its @param leaves the " +
                "surface describing an argument nobody can pass, and the real one undocumented",
            emptyList<String>(),
            onDisk().staleParameterTags,
        )
    }

    @Test
    fun `every published property and constant is documented`() {
        assertEquals(
            "a published property or constant carries no documentation — neither an `@property` " +
                "on its type nor a doc comment of its own. Eleven of this library's types already " +
                "document every property; the rule exists so the next one cannot be the exception",
            emptyList<String>(),
            onDisk().undocumentedProperties,
        )
        assertTrue(
            "the scan must find properties for this to mean anything; found " +
                "${onDisk().properties.size}",
            onDisk().properties.size >= MINIMUM_PROPERTIES,
        )
    }

    @Test
    fun `every property tag names a property the type declares`() {
        assertEquals(
            "a type's KDoc documents an `@property` it does not declare — the rename failure " +
                "again, one declaration out",
            emptyList<String>(),
            onDisk().stalePropertyTags,
        )
    }

    // ── The excuse map, and that it is empty ──────────────────────────────

    @Test
    fun `nothing is excused, and no excuse is stale in either direction`() {
        assertEquals(
            "EXCUSES must be empty: every gap the rules above describe was closed when this test " +
                "was written, so an entry here means somebody chose not to document something and " +
                "owes the next reader a reason",
            emptyMap<String, Excuse>(),
            EXCUSES,
        )
        assertEquals(
            "an excuse names a member no published source declares. A renamed or removed member " +
                "leaves a dead excuse behind, and a dead excuse would wave through whatever lands " +
                "under that key next",
            emptyList<String>(),
            onDisk().danglingExcuses,
        )
        assertEquals(
            "an excuse names a member that has no gap, so it is excusing nothing — the gap was " +
                "closed and the excuse was not removed with it",
            emptyList<String>(),
            onDisk().inertExcuses,
        )
        assertEquals(
            "every excuse must carry a reason as well as a citation",
            emptyList<String>(),
            EXCUSES.filterValues { it.reason.isBlank() }.keys.sorted(),
        )
        assertEquals(
            "an excuse cites a @Test that does not exist under the class it names",
            emptyList<String>(),
            EXCUSES.entries
                .filterNot { resolvesToATest(it.value.coveredBy) }
                .map { "${it.key} -> ${it.value.coveredBy}" }
                .sorted(),
        )
        // The resolver must be able to answer both ways, or it reports success unconditionally —
        // which, over an empty map, is the only thing standing between it and vacuity.
        assertFalse(resolvesToATest("KDocCoverageTest: a test nobody wrote"))
        assertFalse(
            resolvesToATest("NoSuchTestClass: every param tag names a parameter the function has"),
        )
        assertTrue(
            resolvesToATest("KDocCoverageTest: every param tag names a parameter the function has"),
        )
    }

    // ── That the scanner sees the whole surface ───────────────────────────

    @Test
    fun `the scanner sees every published source and every published member`() {
        val sources = publishedSources()
        assertTrue(
            "the published package must hold at least the $MINIMUM_SOURCES sources this test was " +
                "written against; found ${sources.size}: ${sources.keys.sorted()}",
            sources.size >= MINIMUM_SOURCES,
        )
        assertTrue(
            "expected at least $MINIMUM_FUNCTIONS published functions; found " +
                "${onDisk().functions.size}",
            onDisk().functions.size >= MINIMUM_FUNCTIONS,
        )
        assertTrue(
            "expected at least $MINIMUM_TYPES published types; found ${onDisk().types.size}",
            onDisk().types.size >= MINIMUM_TYPES,
        )

        // The three guards against the one failure mode of this file that matters: a parameter
        // list the scanner never found, which satisfies the parameter rule by asking nothing and
        // makes every real `@property` on a type look stale. Four shapes produced one before
        // review probes found them — a generic function, a generic type, an extension on a
        // parameterized receiver, an explicit `@JvmOverloads constructor` — so the guards sit on
        // the *symptom*, not on that list, because the next shape is the one nobody thought of.
        assertEquals(
            "every published declaration's head must have been understood: the walk ended " +
                "somewhere that is neither a parameter list nor anything that legitimately " +
                "follows a name, so whatever it stopped on was not read. On a type this is the " +
                "only guard there is — an absent parameter list is an ordinary fact for an " +
                "`object` or an `enum class`, so it cannot be failed on directly",
            emptyList<String>(),
            onDisk().members.filterNot { it.headUnderstood }.map { it.where },
        )
        assertEquals(
            "…and every published function must have had its parameter list located. Every " +
                "Kotlin function has one, so a `fun` whose head this scanner could not walk to " +
                "its `(` is a scanner failure and never a fact about the source",
            emptyList<String>(),
            onDisk().functions.filterNot { it.parameterListFound }.map { it.where },
        )
        assertEquals(
            "…and every published declaration must have a name this scanner could read; " +
                "`$ANONYMOUS` means the name matcher failed outright",
            emptyList<String>(),
            onDisk().members.filter { it.name == ANONYMOUS }.map { it.where },
        )

        // The overload pair is the reason a key carries a rendered parameter list at all, so it is
        // asserted rather than assumed: both must be seen, and seen separately.
        val shareIntents = onDisk().functions
            .filter { it.name == "createShareIntent" }
            .map { it.key }
            .sorted()
        assertEquals(
            "both `createShareIntent` overloads must be seen as separate members, or the " +
                "documented one vouches for the other; found $shareIntents",
            listOf(
                "Utils.createShareIntent(Context, Entry, String)",
                "Utils.createShareIntent(Context, Entry, String, String)",
            ),
            shareIntents,
        )

        println(
            "KDocCoverageTest: ${sources.size} sources, ${onDisk().types.size} published types, " +
                "${onDisk().functions.size} published functions with " +
                "${onDisk().parameterCount} parameters, ${onDisk().properties.size} published " +
                "properties and constants",
        )
    }

    /**
     * `Entry`'s class comment, named rather than left to the general rule.
     *
     * It is the one gap that was *total* — the file went from `@Parcelize` straight to the
     * declaration and the only doc comment in it sat on `toString()` — and it is the first type an
     * integrator constructs. The general rules above would not notice its absence: `@property`
     * coverage is satisfied by three tags with no surrounding prose, and nothing else asks whether
     * a type says what it is for.
     */
    @Test
    fun `the first type an integrator constructs has a class comment`() {
        val entry = onDisk().types.single { it.key == "Entry" }
        assertTrue(
            "`Entry` must carry a class-level doc comment: it is what `createShareIntent(context, " +
                "Entry(...))` sends, and an IDE shows this text when an integrator types it",
            entry.doc != null,
        )
        val doc = entry.doc!!
        val prose = doc.lines()
            .takeWhile { !PROPERTY_TAG_LINE.containsMatchIn(it) }
            .filter { PROSE_LINE.containsMatchIn(it) }
        assertTrue(
            "…and it must say something before its @property tags, which is the prose the " +
                "general rule cannot ask for. Found ${prose.size} line(s) of it",
            prose.size >= 10,
        )
        assertTrue(
            "…and it must name `validateEntry`, which exists to say in advance why an entry will " +
                "be refused — the thing an integrator most needs pointing at from here",
            "validateEntry" in doc,
        )
    }

    // ── Negative controls ─────────────────────────────────────────────────
    //
    // Every one of these runs the *same* `audit` the assertions above run, over a fixture source
    // instead of the real ones, and asserts the same list is non-empty and names the right thing.
    // One mechanism, two answers — no second implementation to agree with the first.

    /**
     * (a) The scanner reports absence **and** presence from the same loop.
     *
     * [FIXTURE_SOURCE]'s `halfDocumented` takes one documented parameter and one undocumented one,
     * so neither a scanner that reports everything nor one that reports nothing can pass this.
     */
    @Test
    fun `control - one documented and one undocumented parameter yields exactly one report`() {
        val reports = fixtureReport().undocumentedParameters.filter { "halfDocumented" in it }
        assertEquals("found $reports", 1, reports.size)
        assertTrue(
            "the complaint must name the undocumented parameter: $reports",
            "`forgotten`" in reports.single(),
        )
        assertTrue(
            "…and the member, with its rendered parameter list: $reports",
            "Fixture.halfDocumented(String, Int)" in reports.single(),
        )
        assertEquals(
            "nothing may be reported about the documented parameter, or the rule reports every " +
                "parameter and means nothing",
            emptyList<String>(),
            fixtureReport().undocumentedParameters.filter { "`kept`" in it },
        )
    }

    /**
     * (b) The stale direction, which is the half that catches a rename.
     *
     * There is no real instance of this today — every `@param` in the library names a parameter
     * that exists — so the fixture carries one on purpose. Without it, "every @param names a
     * parameter the function has" would be an assertion that has never been shown to fail.
     */
    @Test
    fun `control - a param tag naming no parameter is reported`() {
        val stale = fixtureReport().staleParameterTags
        assertEquals("found $stale", 1, stale.size)
        assertTrue(
            "the complaint must name the tag and the member: $stale",
            "`renamed`" in stale.single() && "Fixture.stale(String)" in stale.single(),
        )
        assertTrue(
            "…and list the parameters it does have, or a failure is unactionable: $stale",
            "current" in stale.single(),
        )
    }

    /**
     * (c) The multi-line extractor is load-bearing: it is what the house style requires and what a
     * line-wise reader would get wrong.
     *
     * `spread` is declared over five lines with a defaulted middle parameter whose default
     * contains a comma inside a string literal — the shape that breaks a naive comma split, and
     * one of the reasons the scan runs over masked text.
     */
    @Test
    fun `control - a declaration spread over five lines yields all of its parameters`() {
        val spread = fixtureReport().functions.single { it.name == "spread" }
        assertEquals(
            "every parameter of a multi-line declaration must be found, in order",
            listOf("first", "middle", "last"),
            spread.parameters.map { it.name },
        )
        assertEquals(
            "…with its type rendered for the key, so a comma inside a generic argument or a " +
                "string default cannot split one parameter into two",
            listOf("Map<String, List<Int>>", "String", "ByteArray"),
            spread.parameters.map { it.type },
        )
        assertEquals(
            "…and all three are documented, so nothing is reported about it",
            emptyList<String>(),
            fixtureReport().undocumentedParameters.filter { "spread" in it },
        )
    }

    /** (d) Excuse hygiene, in both directions and in the direction that actually suppresses. */
    @Test
    fun `control - excuse hygiene holds in both directions`() {
        val reason = "a fixture gap, left open on purpose"
        val citation = "KDocCoverageTest: control - excuse hygiene holds in both directions"

        val suppressed = fixtureReport(mapOf("Fixture.bare" to Excuse(reason, citation)))
        assertEquals(
            "an excused member's gap must disappear from the coverage answer, or the map does " +
                "nothing",
            emptyList<String>(),
            suppressed.undocumentedProperties.filter { "Fixture.bare" in it },
        )
        assertEquals(
            "…and nothing else may be suppressed with it: ${suppressed.undocumentedProperties}",
            fixtureReport().undocumentedProperties.size - 1,
            suppressed.undocumentedProperties.size,
        )
        assertEquals(
            "…and it is not reported as dangling",
            emptyList<String>(),
            suppressed.danglingExcuses,
        )
        assertEquals("…nor as inert", emptyList<String>(), suppressed.inertExcuses)

        val dangling = fixtureReport(mapOf("Fixture.renamedAway" to Excuse(reason, citation)))
        assertEquals(
            "an excuse naming no declared member must be reported: a renamed member leaves a " +
                "dead excuse behind",
            listOf("Fixture.renamedAway"),
            dangling.danglingExcuses,
        )

        val inert = fixtureReport(mapOf("Fixture.own" to Excuse(reason, citation)))
        assertEquals(
            "an excuse for a member that has no gap must be reported too, or closing a gap " +
                "leaves an excuse that will silently cover the next one",
            listOf("Fixture.own"),
            inert.inertExcuses,
        )
        assertEquals(
            "…and it is not dangling, which is a different complaint",
            emptyList<String>(),
            inert.danglingExcuses,
        )
    }

    /**
     * (e) The whole property rule over the fixture: exactly the three undocumented ones, and
     * neither of the two that are documented — one by an `@property` on its type, one by its own
     * comment.
     */
    @Test
    fun `control - an undocumented property, constant and enum entry are each reported`() {
        assertEquals(
            "the property rule must report exactly the fixture's six gaps, by key",
            listOf(
                "Box.unheld",
                "Explicit.undeclared",
                "Fixture.bare",
                "Fixture.undocumented",
                "FixtureVerdict.BARE",
                "FixtureVerdict.Mixed",
            ),
            fixtureReport().undocumentedProperties.map { it.substringBefore(" (") }.sorted(),
        )
        // Keys compared exactly, not by substring: `undocumented` contains `documented`, which is
        // how the first draft of this control passed itself while asking nothing.
        assertEquals(
            "a type's `@property` must count as documentation for a constructor property, and a " +
                "doc comment of its own for a body-level one or an enum constant",
            emptyList<String>(),
            fixtureReport().undocumentedProperties
                .map { it.substringBefore(" (") }
                .filter { it in DOCUMENTED_FIXTURE_PROPERTIES },
        )
    }

    /**
     * (f) The one that must **not** redden, stated so nobody widens the rule later.
     *
     * The fixture's `hidden` is private and takes an undocumented parameter; `toString` and
     * `equals` are overrides, and `Subtype.inherited` is an `override val`. None is reported,
     * because the subject of this file is the surface a third party reads — and an override's
     * parameter list and contract are the supertype's rather than this library's.
     */
    @Test
    fun `control - a private function and an override are outside the rule`() {
        assertEquals(
            "a private function's parameters are nobody's published surface; reporting them " +
                "would turn this file into style policing",
            emptyList<String>(),
            fixtureReport().undocumentedParameters.filter { "hidden" in it },
        )
        assertEquals(
            "an override is skipped whole: its contract — and its doc — belong to the supertype",
            emptyList<String>(),
            fixtureReport().undocumentedParameters
                .filter { "toString" in it || "equals" in it },
        )
        assertEquals(
            "…including an `override val`, which the base type documents",
            emptyList<String>(),
            fixtureReport().undocumentedProperties.filter { "inherited" in it },
        )
        assertTrue(
            "the fixture must actually declare the private function, or this control is about " +
                "nothing",
            fixtureReport().members.none { it.name == "hidden" } &&
                "private fun hidden" in FIXTURE_SOURCE,
        )
    }

    /**
     * (g) A declaration head never costs the parameter list — every shape a review probe caught it
     * losing, each of which was a *silent* drop: zero parameters satisfies the parameter rule by
     * asking nothing, and on a type it also makes a real `@property` look stale.
     *
     * A type parameter before the name (`fun <T> generic(…)`); one after it (`class Box<T>(…)`);
     * an extension receiver, parameterized (`fun Map<String, Int>.onReceiver(…)`), nullable and
     * generic (`fun <T> List<T>?.receiverGap(…)`) or plain (`fun String.plainReceiver(…)`, where a
     * greedy path match absorbed the receiver into the *name*); and an explicitly declared primary
     * constructor (`class Explicit @JvmOverloads constructor(…)`), which is the one that produced
     * a false accusation rather than a silent gap.
     */
    @Test
    fun `control - a declaration head never costs the parameter list`() {
        val found = { name: String -> fixtureReport().functions.single { it.name == name } }

        // First, because it is the assertion that *explains* a regression: the ones below use
        // `single { … }`, which dies with a bare NoSuchElementException when a head goes unread.
        assertEquals(
            "every fixture declaration's head must have been understood",
            emptyList<String>(),
            fixtureReport().members.filterNot { it.headUnderstood }.map { it.where },
        )
        assertEquals(
            "…and no fixture function may be missing its parameter list",
            emptyList<String>(),
            fixtureReport().functions.filterNot { it.parameterListFound }.map { it.where },
        )

        assertEquals(
            "a type parameter before the name must not cost the parameter list",
            listOf("only"),
            found("generic").parameters.map { it.name },
        )
        assertEquals("…nor the member key", "Fixture.generic(T)", found("generic").key)
        assertEquals(
            "a parameterized extension receiver must not cost it either, and the *name* must be " +
                "the function's rather than the receiver's",
            listOf("only"),
            found("onReceiver").parameters.map { it.name },
        )
        assertEquals("onReceiver(String)", found("onReceiver").key)
        assertEquals(
            "a *plain* extension receiver must answer alike: a greedy path match named this one " +
                "`String.plainReceiver`, so the two receiver shapes disagreed about the name",
            "plainReceiver(String)",
            found("plainReceiver").key,
        )

        val box = fixtureReport().types.single { it.name == "Box" }
        assertEquals(
            "a type parameter after the name must not cost the constructor's properties",
            listOf("held", "unheld"),
            box.parameters.map { it.name },
        )
        val explicit = fixtureReport().types.single { it.name == "Explicit" }
        assertEquals(
            "an explicitly declared primary constructor must not cost them either",
            listOf("declared", "undeclared"),
            explicit.parameters.map { it.name },
        )
        // Scoped to this type on purpose: the fixture carries a genuinely stale tag elsewhere, for
        // control (i), and an unscoped `isEmpty` here would cancel that one out.
        assertEquals(
            "…and its documented property must not be reported as a stale `@property`, which is " +
                "what a lost list turns every real tag into: ${fixtureReport().stalePropertyTags}",
            emptyList<String>(),
            fixtureReport().stalePropertyTags.filter { "Explicit" in it },
        )

        // And the gaps are *reported*, which is what a dropped parameter list would hide.
        assertEquals(
            "a generic function's undocumented parameter must be reported like any other: " +
                "${fixtureReport().undocumentedParameters}",
            1,
            fixtureReport().undocumentedParameters.count { "genericGap" in it },
        )
        assertEquals(
            "…and so must one behind a nullable generic receiver",
            1,
            fixtureReport().undocumentedParameters.count { "receiverGap" in it },
        )
        assertEquals(
            "…and so must one behind a plain receiver",
            1,
            fixtureReport().undocumentedParameters.count { "plainReceiver" in it },
        )
        assertEquals(
            "…and a generic type's undocumented constructor property too",
            1,
            fixtureReport().undocumentedProperties.count { "Box.unheld" in it },
        )
        assertEquals(
            "…and an explicit constructor's",
            1,
            fixtureReport().undocumentedProperties.count { "Explicit.undeclared" in it },
        )
    }

    /**
     * (h) A bracket-ish character in a type or a default is not always a bracket. Three shapes,
     * each of which loses every parameter after it.
     *
     * `flag: Boolean = 1 > 0, tail: String` drove a single depth counter negative, after which no
     * comma was top-level again and `tail` vanished without a word. `Map<(String) -> Int, String>`
     * is the arrow half: the `>` of the arrow cancels the `<` of `Map`, so the comma *inside* the
     * type reads as the end of the parameter — which is why the arrow is consumed as one token and
     * why this fixture puts it inside the brackets rather than at the end of the list, where the
     * final flush would absorb the damage and the assertion would pin nothing. A lambda default
     * (`= { a, b -> … }`) is the third: its comma belongs to its braces, which is why braces count
     * in the default part and nowhere else.
     */
    @Test
    fun `control - a comparison, an arrow or a lambda default does not swallow what follows`() {
        val comparisons = fixtureReport().functions.single { it.name == "comparisons" }
        assertEquals(
            "every parameter after a defaulted one holding `>`, after a type holding `->`, and " +
                "after a lambda default holding a comma, must still be found",
            listOf("flag", "handler", "lambda", "tail"),
            comparisons.parameters.map { it.name },
        )
        assertEquals(
            "…with the arrow inside the generic arguments read as one token, so the comma beside " +
                "it stays inside the type, and the lambda default kept out of the rendered type",
            listOf("Boolean", "Map<(String) -> Int, String>", "(String, String) -> Int", "String"),
            comparisons.parameters.map { it.type },
        )
        assertEquals(
            "…and nothing reported, since all four are documented",
            emptyList<String>(),
            fixtureReport().undocumentedParameters.filter { "comparisons" in it },
        )
    }

    /**
     * (i) The stale direction of the *property* rule, which is control (b)'s argument applied to
     * the other half.
     *
     * All four real `@property` tags in the library — and all four in this fixture before this one
     * was added — name a property that exists, so `every property tag names a property the type
     * declares` had never been shown to fail: deleting the rule's implementation left all sixteen
     * tests green. Control (g) exercises only the *false-accusation* half, which is the half that
     * survives the rule being deleted. So the fixture carries a genuinely stale tag.
     */
    @Test
    fun `control - a property tag naming no property is reported`() {
        val stale = fixtureReport().stalePropertyTags
        assertEquals("found $stale", 1, stale.size)
        assertTrue(
            "the complaint must name the tag and the type it is on: $stale",
            "`renamed`" in stale.single() && "Stale" in stale.single(),
        )
        assertTrue(
            "…and list the properties the type does declare, or a failure is unactionable: $stale",
            "it declares real" in stale.single(),
        )
        assertEquals(
            "the real tag beside it must not be reported, or the rule reports every tag and " +
                "means nothing",
            emptyList<String>(),
            stale.filter { "`real`" in it },
        )
    }

    /**
     * The scan is only as trustworthy as its brace bookkeeping: a file whose braces it mis-counted
     * would put members in the wrong scope, and the scope is what decides whether a member is
     * published at all.
     *
     * So every source must balance to exactly zero open scopes at its end. This is what would
     * catch the masker losing a string literal — a `{` inside an interpolated string, or inside
     * `Regex("[A-Za-z0-9+/]*={0,2}")`, would otherwise open a scope that never closes and hide
     * every member after it.
     */
    @Test
    fun `every published source balances its braces under the masker`() {
        val unbalanced = publishedSources().entries.sortedBy { it.key }.mapNotNull { (name, text) ->
            val depth = scopeDepthAtEndOf(mask(text).text)
            if (depth == 0) null else "$name ends with $depth unclosed scope(s)"
        }
        assertEquals(
            "the brace scan must balance, or every scope decision after the error is wrong",
            emptyList<String>(),
            unbalanced,
        )
        assertEquals("the fixture must balance too", 0, scopeDepthAtEndOf(mask(FIXTURE_SOURCE).text))
    }

    // ── Masking ───────────────────────────────────────────────────────────

    /** The masked text of one file, and its doc comments keyed by the line their `*&#47;` sits on. */
    private class Masked(val text: String, val docs: Map<Int, String>)

    /**
     * Comments and string literals blanked to spaces, newlines kept, plus every doc comment keyed
     * by the line it ends on.
     *
     * Masking first is what makes everything below safe to do with a regex: `Regex("…={0,2}")`
     * holds a brace, an interpolated `toString()` holds two, and a doc comment holds the word `fun`
     * in prose more than once. Line numbers survive because only non-newline characters are
     * replaced.
     *
     * The one limit, recorded rather than left to be discovered: a *nested* block comment, which
     * Kotlin allows, would be closed at the first inner terminator. No source here contains one,
     * and `every published source balances its braces under the masker` is what would notice.
     */
    private fun mask(source: String): Masked {
        val out = StringBuilder(source.length)
        val docs = mutableMapOf<Int, String>()
        var line = 1
        var i = 0

        fun blankTo(end: Int) {
            while (i < end) {
                if (source[i] == '\n') {
                    out.append('\n')
                    line++
                } else {
                    out.append(' ')
                }
                i++
            }
        }

        /** The index just past the closing quote of a literal whose opener is at `from - 1`. */
        fun endOfQuoted(from: Int): Int {
            val quote = source[from - 1]
            var j = from
            while (j < source.length) {
                when (source[j]) {
                    '\\' -> j++
                    quote -> return j + 1
                    '\n' -> return j
                }
                j++
            }
            return source.length
        }

        while (i < source.length) {
            when {
                source.startsWith("/**", i) -> {
                    val end = source.indexOf("*/", i + 2).let { if (it < 0) source.length else it + 2 }
                    val text = source.substring(i, end)
                    val startLine = line
                    blankTo(end)
                    docs[startLine + text.count { it == '\n' }] = text
                }
                source.startsWith("/*", i) -> {
                    blankTo(source.indexOf("*/", i + 2).let { if (it < 0) source.length else it + 2 })
                }
                source.startsWith("//", i) -> {
                    blankTo(source.indexOf('\n', i).let { if (it < 0) source.length else it })
                }
                source.startsWith("\"\"\"", i) -> {
                    blankTo(source.indexOf("\"\"\"", i + 3).let { if (it < 0) source.length else it + 3 })
                }
                source[i] == '"' || source[i] == '\'' -> {
                    out.append(' ')
                    i++
                    blankTo(endOfQuoted(i))
                }
                else -> {
                    if (source[i] == '\n') line++
                    out.append(source[i])
                    i++
                }
            }
        }
        return Masked(out.toString(), docs)
    }

    /**
     * How many scopes are still open at the end of [masked] — zero for a well-formed file, and the
     * same bookkeeping [membersIn] makes every scope decision with.
     */
    private fun scopeDepthAtEndOf(masked: String): Int {
        var depth = 0
        var parens = 0
        for (c in masked) {
            when (c) {
                '(' -> parens++
                ')' -> parens--
                '{' -> if (parens == 0) depth++
                '}' -> if (parens == 0) depth--
            }
        }
        return depth
    }

    // ── Scanning ──────────────────────────────────────────────────────────

    /** A brace-delimited body, as the scan descends into one. */
    private class Scope(
        val name: String,
        val isPublishedType: Boolean,
        val isEnum: Boolean,
        val owner: String,
        val doc: String?,
        val bodyStart: Int,
    ) {
        val path: String = listOf(owner, name).filter { it.isNotEmpty() }.joinToString(".")
    }

    /** One `class`/`object`/`fun`/`val` declaration, read off the masked text. */
    private class Declaration(
        val keyword: String,
        modifiers: String,
        val name: String,
        val line: Int,
        val owner: String,
        val parameters: List<Parameter>,
        /** Whether the head walk reached a `(` at all. See [headOf]. */
        val parameterListFound: Boolean,
        /** Whether the head walk ended somewhere a head legitimately ends. See [headOf]. */
        val headUnderstood: Boolean,
    ) {
        private val words: List<String> = MODIFIER_WORD.findAll(modifiers).map { it.value }.toList()

        val isType: Boolean = keyword in TYPE_WORDS
        val isEnum: Boolean = isType && "enum" in words
        val published: Boolean = words.none { it in HIDDEN_WORDS }
        val isOverride: Boolean = "override" in words

        val path: String = listOf(owner, name).filter { it.isNotEmpty() }.joinToString(".")

        val key: String =
            if (keyword == "fun") "$path(${parameters.joinToString(", ") { it.type }})" else path

        val kind: Kind = when {
            isType -> Kind.TYPE
            keyword == "fun" -> Kind.FUNCTION
            else -> Kind.PROPERTY
        }
    }

    /**
     * Every published member of one source.
     *
     * One character walk, which is what makes the scope question answerable at all: a declaration
     * is a *member* only when every brace it sits inside belongs to a published type. That keeps a
     * local `val` out of the property rule, a lambda's parameters out of the parameter rule, and
     * anything inside a private function out of both.
     */
    private fun membersIn(file: String, source: String): List<Member> {
        val masked = mask(source)
        val text = masked.text
        val lines = source.lines()
        val lineOf = lineIndex(text)
        val starts = DECLARATION.findAll(text).associateBy { it.range.first }

        val members = mutableListOf<Member>()
        val scopes = mutableListOf<Scope>()
        var pending: Declaration? = null
        var parens = 0
        var i = 0

        fun docFor(line: Int): String? {
            var probe = line - 1
            while (probe >= 1 && lines[probe - 1].trim().startsWith("@")) probe--
            return masked.docs[probe]
        }

        while (i < text.length) {
            val match = starts[i]
            if (match != null && parens == 0) {
                val declaration = declarationAt(
                    match,
                    text,
                    lineOf[i],
                    scopes.lastOrNull()?.path.orEmpty(),
                )
                pending = declaration
                val inPublishedType = scopes.all { it.isPublishedType }
                if (inPublishedType && declaration.published && !declaration.isOverride) {
                    val ownDoc = docFor(declaration.line)
                    members += Member(
                        kind = declaration.kind,
                        file = file,
                        line = declaration.line,
                        name = declaration.name,
                        key = declaration.key,
                        owner = declaration.owner,
                        parameters = declaration.parameters,
                        doc = ownDoc,
                        ownerDoc = scopes.lastOrNull()?.doc,
                        parameterListFound = declaration.parameterListFound,
                        headUnderstood = declaration.headUnderstood,
                    )
                    if (declaration.isType) {
                        members += declaration.parameters
                            .filter { it.isProperty && !it.isOverride && !it.isHidden }
                            .map { parameter ->
                                Member(
                                    kind = Kind.PROPERTY,
                                    file = file,
                                    line = declaration.line,
                                    name = parameter.name,
                                    key = "${declaration.path}.${parameter.name}",
                                    owner = declaration.path,
                                    parameters = emptyList(),
                                    doc = null,
                                    ownerDoc = ownDoc,
                                )
                            }
                    }
                }
            }
            when (text[i]) {
                '(' -> parens++
                ')' -> parens--
                ';' -> if (parens == 0) pending = null
                '{' -> if (parens == 0) {
                    val declaration = pending?.takeIf { it.isType }
                    scopes += Scope(
                        name = declaration?.name ?: ANONYMOUS,
                        isPublishedType = declaration != null &&
                            declaration.published &&
                            scopes.all { it.isPublishedType },
                        isEnum = declaration?.isEnum == true,
                        owner = declaration?.owner ?: scopes.lastOrNull()?.path.orEmpty(),
                        doc = declaration?.let { docFor(it.line) },
                        bodyStart = i + 1,
                    )
                    pending = null
                }
                '}' -> if (parens == 0 && scopes.isNotEmpty()) {
                    val scope = scopes.removeAt(scopes.size - 1)
                    if (scope.isEnum && scope.isPublishedType) {
                        members += enumEntriesIn(
                            file = file,
                            body = text.substring(scope.bodyStart, i),
                            bodyStart = scope.bodyStart,
                            lineOf = lineOf,
                            owner = scope.path,
                            ownerDoc = scope.doc,
                            docFor = ::docFor,
                        )
                    }
                    pending = null
                }
            }
            i++
        }
        return members
    }

    private fun declarationAt(
        match: MatchResult,
        text: String,
        line: Int,
        owner: String,
    ): Declaration {
        val keyword = match.groupValues[2]
        val from = match.range.last + 1
        val head = headOf(text.substring(from, minOf(text.length, from + DECLARATION_WINDOW)))
        val name = head.name ?: if (keyword == "object") COMPANION else ANONYMOUS
        val remainder = head.rest.trimStart()
        val found = remainder.startsWith("(")
        val parameters = if (found) {
            parametersIn(balancedParentheses(head.rest.substring(head.rest.indexOf('('))))
        } else {
            emptyList()
        }
        return Declaration(
            keyword = keyword,
            modifiers = match.groupValues[1],
            name = name,
            line = line,
            owner = owner,
            parameters = parameters,
            parameterListFound = found,
            headUnderstood = found ||
                remainder.isEmpty() ||
                HEAD_CONTINUATION.containsMatchIn(remainder),
        )
    }

    /** A declaration's name, and the text that follows it. */
    private class Head(val name: String?, val rest: String)

    /**
     * The name out of a declaration head, and where the head ends.
     *
     * **A declaration head has more in it than a name**, and every shape below was a silent
     * parameter-list drop until a review probe found it. A dropped list is not a mis-read list: it
     * is an *empty* one, which satisfies the parameter rule by asking nothing, and on a type it
     * also makes every real `@property` tag look stale. So the head is walked rather than
     * pattern-matched:
     *
     *  1. a leading type-parameter list — `fun <T> name(…)`;
     *  2. then a dotted chain of segments, each of which may carry its own type arguments and a
     *     `?`, with the **last** segment the name. That is what an extension receiver is:
     *     `fun Map<String, Int>.name(…)`, `fun <T> List<T>?.name(…)`, `fun String.name(…)`. Taking
     *     segments one at a time rather than matching the whole dotted path keeps those three
     *     spellings answering alike — a greedy path match named the last one `String.name`;
     *  3. then, on a type, an explicitly declared primary constructor with its own annotations and
     *     visibility: `class Foo @JvmOverloads constructor(…)`. The list is still the primary
     *     constructor's.
     *
     * Whatever is left is [rest]. **The guards are on the symptom rather than on this list**,
     * because the list is three review rounds long and the next shape is the one nobody thought
     * of: `every published function must have had its parameter list located` fails for a `fun`
     * whose head does not end at a `(` — every Kotlin function has a parameter list — and
     * `every published declaration's head was understood` fails for *any* declaration whose head
     * ends somewhere that is neither a `(` nor one of the handful of things that legitimately
     * follow a name ([HEAD_CONTINUATION]). The second is what catches a type, where an absent
     * parameter list is an ordinary fact.
     */
    private fun headOf(from: String): Head {
        var rest = skipTypeParameters(from)
        var name: String? = null
        while (true) {
            val segment = NAME_SEGMENT.find(rest) ?: break
            name = segment.groupValues[1]
            rest = skipTypeParameters(rest.substring(segment.range.last + 1))
            var next = rest.trimStart()
            if (next.startsWith("?")) next = next.substring(1).trimStart()
            if (!next.startsWith(".")) break
            // That segment was a receiver, not the name; keep walking.
            rest = next.substring(1)
        }
        // An explicit primary constructor, with whatever annotations and visibility it carries.
        PRIMARY_CONSTRUCTOR.find(rest)?.let { rest = rest.substring(it.range.last + 1) }
        return Head(name, rest)
    }

    /** Past a leading `<` … matching `>`, if there is one. */
    private fun skipTypeParameters(from: String): String {
        val trimmed = from.trimStart()
        if (!trimmed.startsWith("<")) return from
        var depth = 0
        for ((offset, c) in trimmed.withIndex()) {
            when (c) {
                '<' -> depth++
                '>' -> {
                    depth--
                    if (depth == 0) return trimmed.substring(offset + 1)
                }
            }
        }
        return from
    }

    /**
     * The text inside `(` … matching `)`, found by **counting parentheses over the joined text**.
     *
     * This is the load-bearing line of the whole file. Multi-line parameter lists are the house
     * style here, so a line-wise reader sees `fun createShareIntent(` and no parameters at all —
     * and `shareEntry`, whose three undocumented parameters were this task's premise, is declared
     * across four lines like most of its neighbours.
     */
    private fun balancedParentheses(from: String): String {
        var depth = 0
        for ((offset, c) in from.withIndex()) {
            when (c) {
                '(' -> depth++
                ')' -> {
                    depth--
                    if (depth == 0) return from.substring(1, offset)
                }
            }
        }
        return from.removePrefix("(")
    }

    /** Where in one parameter the walk below has got to. */
    private enum class Part { HEAD, TYPE, DEFAULT }

    /**
     * The parameters of a (masked) parameter list, walked rather than split.
     *
     * **An angle bracket is a bracket in a type and an operator in an expression**, and treating
     * it as a bracket everywhere is how the first draft of this went wrong: `flag: Boolean = 1 > 0,
     * tail: String` drove a single depth counter to −1, after which no comma was ever "top level"
     * again and every parameter after the comparison vanished — silently, which for this file is
     * the worst outcome available. So the walk tracks which *part* of a parameter it is in:
     *
     *  - **HEAD** — modifiers and the name, up to the `:`;
     *  - **TYPE** — where `<`/`>` genuinely delimit (`Map<String, List<Int>>` must not split) and
     *    `->` is consumed as one token so a lambda type's arrow is not read as a close;
     *  - **DEFAULT** — after the `=`, where angle brackets are ignored outright because a default
     *    is an expression and may compare.
     *
     * Round and square brackets are tracked throughout: they are strictly balanced in Kotlin
     * wherever they appear, so they need no such care.
     */
    private fun parametersIn(list: String): List<Parameter> {
        val parameters = mutableListOf<Parameter>()
        val head = StringBuilder()
        val type = StringBuilder()
        var part = Part.HEAD
        var round = 0
        var angle = 0

        fun flush() {
            val before = head.toString().trim()
            val name = before.substringAfterLast(' ').trim()
            if (part != Part.HEAD && name.isNotEmpty()) {
                parameters += Parameter(
                    name = name,
                    type = type.toString().trim().replace(PACKAGE_QUALIFIER, ""),
                    modifiers = before.removeSuffix(name).trim(),
                )
            }
            head.clear()
            type.clear()
            part = Part.HEAD
            round = 0
            angle = 0
        }

        var i = 0
        while (i < list.length) {
            val c = list[i]
            when (part) {
                Part.HEAD -> when {
                    c == '(' || c == '[' -> { round++; head.append(c) }
                    c == ')' || c == ']' -> { round--; head.append(c) }
                    c == ':' && round == 0 -> part = Part.TYPE
                    c == ',' && round == 0 -> flush()
                    else -> head.append(c)
                }

                Part.TYPE -> when {
                    c == '-' && i + 1 < list.length && list[i + 1] == '>' -> {
                        type.append("->")
                        i++
                    }
                    c == '(' || c == '[' -> { round++; type.append(c) }
                    c == ')' || c == ']' -> { round--; type.append(c) }
                    c == '<' -> { angle++; type.append(c) }
                    c == '>' -> { if (angle > 0) angle-- ; type.append(c) }
                    c == '=' && round == 0 && angle == 0 -> part = Part.DEFAULT
                    c == ',' && round == 0 && angle == 0 -> flush()
                    else -> type.append(c)
                }

                // The default value's text is not kept: nothing in either rule is about it, and
                // reading it is only a way to find where this parameter ends. Braces count here
                // and nowhere else, because a default can be a lambda — `= { a, b -> 0 }` — whose
                // commas belong to it; a *type* can hold no brace at all.
                Part.DEFAULT -> when {
                    c == '(' || c == '[' || c == '{' -> round++
                    c == ')' || c == ']' || c == '}' -> round--
                    c == ',' && round == 0 -> flush()
                    else -> Unit
                }
            }
            i++
        }
        flush()
        return parameters
    }

    /**
     * An enum's constants, which are constants of a published type by any reading and the one
     * shape the `val`/`const val` scan cannot see.
     *
     * Only the region before the first top-level `;` is read — Kotlin's own boundary between an
     * enum's entries and its members — so a `fun` or a `val` after one is left to the general scan.
     */
    private fun enumEntriesIn(
        file: String,
        body: String,
        bodyStart: Int,
        lineOf: IntArray,
        owner: String,
        ownerDoc: String?,
        docFor: (Int) -> String?,
    ): List<Member> = ENUM_ENTRY.findAll(body.substringBefore(';')).map { match ->
        val line = lineOf[bodyStart + match.groups[1]!!.range.first]
        val name = match.groupValues[1]
        Member(
            kind = Kind.PROPERTY,
            file = file,
            line = line,
            name = name,
            key = "$owner.$name",
            owner = owner,
            parameters = emptyList(),
            doc = docFor(line),
            ownerDoc = ownerDoc,
        )
    }.toList()

    /**
     * Every property name each type declares, whatever its visibility and whether or not it is an
     * `override`.
     *
     * The coverage rule asks only about published non-override properties; the *stale* `@property`
     * rule has to accept a tag naming any declared one, or documenting an inherited property —
     * which `SignedStatement` does, from the base class, for the `signature` its three cases
     * override — would read as a dead tag.
     */
    private fun declaredPropertyNamesIn(source: String): Map<String, Set<String>> {
        val text = mask(source).text
        val starts = DECLARATION.findAll(text).associateBy { it.range.first }
        val names = mutableMapOf<String, MutableSet<String>>()
        val scopes = mutableListOf<String>()
        var pending: Declaration? = null
        var parens = 0
        var i = 0
        while (i < text.length) {
            val match = starts[i]
            if (match != null && parens == 0) {
                val path = scopes.joinToString(".")
                val declaration = declarationAt(match, text, 1, path)
                pending = declaration
                if (declaration.keyword in PROPERTY_WORDS) {
                    names.getOrPut(path) { mutableSetOf() } += declaration.name
                }
                if (declaration.isType) {
                    names.getOrPut(declaration.path) { mutableSetOf() } +=
                        declaration.parameters.filter { it.isProperty }.map { it.name }
                }
            }
            when (text[i]) {
                '(' -> parens++
                ')' -> parens--
                ';' -> if (parens == 0) pending = null
                '{' -> if (parens == 0) {
                    scopes += pending?.takeIf { it.isType }?.name ?: ANONYMOUS
                    pending = null
                }
                '}' -> if (parens == 0 && scopes.isNotEmpty()) {
                    scopes.removeAt(scopes.size - 1)
                    pending = null
                }
            }
            i++
        }
        return names.filterKeys { ANONYMOUS !in it }
    }

    /** Which line every index of [text] sits on, so a match can be reported where it is. */
    private fun lineIndex(text: String): IntArray {
        val index = IntArray(text.length + 1)
        var line = 1
        for (i in text.indices) {
            index[i] = line
            if (text[i] == '\n') line++
        }
        index[text.length] = line
        return index
    }

    /** The values of a KDoc block tag, one per `@tag name` line. */
    private fun tagsIn(doc: String?, tag: String): List<String> =
        if (doc == null) {
            emptyList()
        } else {
            Regex("""(?m)^[ \t]*\*?[ \t]*@$tag[ \t]+(\S+)""").findAll(doc)
                .map { it.groupValues[1] }
                .toList()
        }

    private fun resolvesToATest(citation: String): Boolean {
        val className = citation.substringBefore(": ")
        val testName = citation.substringAfter(": ")
        return runCatching {
            Class.forName("dev.eryalabs.lim.$className").declaredMethods.any {
                it.name == testName && it.isAnnotationPresent(Test::class.java)
            }
        }.getOrDefault(false)
    }

    // ── Finding the files ─────────────────────────────────────────────────

    /**
     * Every Kotlin source of the published package, keyed by file name.
     *
     * `RedactionVisibilityTest:96`'s walk-up locator, for its reason: the working directory of a
     * Gradle unit test is the module directory, but that is a Gradle default rather than a promise,
     * so every ancestor is tried both as the module root and as the repository root. If none of
     * them holds the directory the test *fails naming every absolute path it tried* — a scanner
     * that silently finds nothing would pass for ever, which is the vacuity trap every floor in
     * this file also guards.
     */
    private fun publishedSources(): Map<String, String> {
        val workingDirectory = File(".").absoluteFile.normalize()
        val tried = mutableListOf<File>()
        var directory: File? = workingDirectory
        while (directory != null) {
            for (candidate in listOf(
                File(directory, SOURCE_ROOT),
                File(directory, "LIM/$SOURCE_ROOT"),
            )) {
                tried += candidate
                if (candidate.isDirectory) {
                    val sources = candidate.walkTopDown()
                        .filter { it.isFile && it.name.endsWith(".kt") }
                        .toList()
                    check(sources.isNotEmpty()) {
                        "no Kotlin sources under ${candidate.absolutePath}"
                    }
                    // Keyed by file name because that is what a failure message is readable with,
                    // so two same-named files under different subpackages would silently collide
                    // and one would never be scanned at all. `GuideSnippetTest`'s guard, for the
                    // same reason: a source this file cannot see is a surface nothing checks.
                    val shared = sources.groupBy { it.name }.filterValues { it.size > 1 }.keys
                    check(shared.isEmpty()) {
                        "two published sources share a file name ($shared), so one of them would " +
                            "be dropped from this scan silently"
                    }
                    return sources.associate { it.name to it.readText() }
                }
            }
            directory = directory.parentFile
        }
        throw AssertionError(
            "cannot find `$SOURCE_ROOT` — this test pins a source-level fact and must not be " +
                "silently skipped. Working directory: $workingDirectory. Tried:\n" +
                tried.map { it.absolutePath }.distinct().joinToString("\n"),
        )
    }

    // ── Fixtures ──────────────────────────────────────────────────────────

    private fun fixtureReport(excuses: Map<String, Excuse> = emptyMap()): Report =
        audit(mapOf("Fixture.kt" to FIXTURE_SOURCE), excuses)

    private companion object {
        private const val SOURCE_ROOT = "src/main/java/dev/eryalabs/lim"

        /** The on-disk measurement, shared across this class's test instances. See [onDisk]. */
        private var cachedOnDisk: Report? = null

        private const val ANONYMOUS = "<anonymous>"
        private const val COMPANION = "Companion"

        /** How far past a keyword a declaration's name and parameter list can possibly reach. */
        private const val DECLARATION_WINDOW = 4096

        private val TYPE_WORDS = setOf("class", "object", "interface")
        private val PROPERTY_WORDS = setOf("val", "var")
        private val HIDDEN_WORDS = setOf("private", "internal", "protected")

        /**
         * **Nothing is excused today, and the assertion that says so is the point.** Every gap the
         * rules above found was closed rather than written down here. An entry is
         * `Excuse(reason, coveredBy)` — `PublishedSurfaceFuzzTest:1049`'s form — keyed by the
         * member key a failure prints: `Utils.shareEntry(Context, Entry, String)` for a function,
         * `Utils.EXTRA_NONCE` for a constant.
         */
        private val EXCUSES = emptyMap<String, Excuse>()

        /**
         * Floors, each at or below a count this file *measured* and prints on every run — 16
         * sources, 19 published types, 45 published functions with 93 parameters, and 82 published
         * properties and constants when it was written. Set below the actuals so that *adding* a
         * published member does not fail this file, while a scanner drifting towards the empty set
         * does.
         *
         * [MINIMUM_SOURCES] is the one set *at* the measured value rather than below it, on
         * purpose: a source file disappearing from the published package is worth a failure, while
         * adding one is not.
         */
        private const val MINIMUM_SOURCES = 16
        private const val MINIMUM_TYPES = 15
        private const val MINIMUM_FUNCTIONS = 38
        private const val MINIMUM_PARAMETERS = 85
        private const val MINIMUM_PROPERTIES = 70

        /**
         * A declaration at the start of a line, with its modifier run.
         *
         * Anchored at a line start and applied to *masked* text, which together are what keep it
         * from matching the word `fun` in a doc comment, a `val` inside a parameter list (those
         * are read off their type's own declaration instead) or `object :` in the middle of an
         * expression.
         */
        private val DECLARATION = Regex(
            "(?m)^[ \\t]*((?:(?:public|private|internal|protected|open|abstract|final|sealed|" +
                "data|enum|annotation|value|inner|companion|override|lateinit|const|suspend|" +
                "inline|noinline|crossinline|operator|infix|external|expect|actual|tailrec|" +
                "@[A-Za-z_][A-Za-z0-9_.]*(?:\\([^)\\n]*\\))?)[ \\t]+)*)" +
                "(class|object|interface|fun|val|var)[ \\t\\n]",
        )

        /**
         * **One** segment of a declaration head — never the whole dotted path.
         *
         * [headOf] walks the path a segment at a time so that `fun String.name(…)` and
         * `fun Map<String, Int>.name(…)` answer alike. A greedy path match handled the second
         * correctly, by accident of the `<` stopping it, and named the first `String.name`.
         */
        private val NAME_SEGMENT = Regex("""^[ \t]*([A-Za-z_][A-Za-z0-9_]*)""")

        /** An explicitly declared primary constructor: `class Foo @JvmOverloads constructor(…)`. */
        private val PRIMARY_CONSTRUCTOR = Regex(
            "^[ \\t\\n]*(?:(?:@[A-Za-z_][A-Za-z0-9_.]*(?:\\([^)\\n]*\\))?|public|private|" +
                "internal|protected)[ \\t\\n]+)*constructor[ \\t\\n]*",
        )

        /**
         * What may legitimately follow a declaration's name when there is no parameter list: a
         * supertype or return-type `:`, an initialiser or expression body `=`, a body `{`, a
         * generic constraint `where`, a delegate `by`, or a custom accessor `get`/`set`. Anything
         * else means the head walk stopped on something it did not read — see [headOf].
         *
         * Deliberately a short allow-list rather than a deny-list: a shape nobody anticipated
         * reddens with its file and line, which is the conservative direction. The cost is that a
         * published shape this list has not met yet fails here before it fails anywhere real, and
         * extending the list is the fix — `get` and `set` were added for exactly that reason,
         * after a probe wrote `val x get() = 3`.
         */
        private val HEAD_CONTINUATION = Regex("""^(?:[:={]|where\b|by\b|get\b|set\b)""")

        /**
         * An enum constant at the start of a line, with or without a constructor call or a body.
         *
         * `[A-Za-z0-9_]` rather than `[A-Z0-9_]`: SCREAMING_CASE is this library's convention and
         * `StatementVerdict`'s seven constants all follow it, but Kotlin does not require it, and
         * an `enum class Flow { Share, Query }` was invisible to the property rule until a review
         * probe named it.
         *
         * **The cost of that breadth, recorded rather than left to be discovered**, like the
         * masker's nested-comment limit: an entry with a *body* — allowed by the `{` alternative —
         * has its body scanned too, so a continuation line beginning with an upper-case call
         * (`StringBuilder(…)`) is reported as an undocumented constant. No enum here has an entry
         * body; the failure is loud and names the line, so it costs a reader a minute rather than
         * a surface going unchecked, and narrowing the terminator again would cost the mixed-case
         * entry this regex exists for.
         */
        private val ENUM_ENTRY = Regex("""(?m)^[ \t]*([A-Z][A-Za-z0-9_]*)[ \t]*(?:\(|\{|,|;|$)""")

        private val MODIFIER_WORD = Regex("""[A-Za-z_][A-Za-z0-9_]*""")

        /** `PublicApiAuditTest:1172` verbatim: strips `java.util.` and leaves `Map` alone. */
        private val PACKAGE_QUALIFIER = Regex("""\b(?:[a-z][A-Za-z0-9_]*\.)+(?=[A-Z])""")

        /** A line that opens an `@property` tag, for the one prose assertion in this file. */
        private val PROPERTY_TAG_LINE = Regex("""^[ \t]*\*?[ \t]*@property\b""")

        /** The fixture properties that *are* documented, between them by both of the two ways. */
        private val DOCUMENTED_FIXTURE_PROPERTIES = setOf(
            "Fixture.documented",
            "Subtype.documented",
            "Box.held",
            "Fixture.own",
            "FixtureVerdict.GOOD",
        )

        /** A doc-comment line with words on it, rather than one holding only comment framing. */
        private val PROSE_LINE = Regex("""[A-Za-z]{3}""")

        /**
         * One fixture source carrying every shape the controls ask about, so each control runs the
         * same [audit] the real assertions run rather than a second implementation of it.
         *
         * `halfDocumented` is control (a); `stale` is (b) — the rename failure, which has no real
         * instance in the library; `spread` is (c), five lines with a defaulted middle parameter
         * whose default holds a comma inside a string; `bare`, `undocumented`, `Box.unheld` and
         * `FixtureVerdict.BARE`, `FixtureVerdict.Mixed` and `Explicit.undeclared` are (e);
         * `hidden`, the overrides and `Subtype.inherited` are (f); `generic`, `genericGap`, `Box`,
         * `Explicit`, `onReceiver`, `receiverGap` and `plainReceiver` are (g); `comparisons` is
         * (h); `Stale` is (i). Those last shapes are here because adversarial review probes found the scanner
         * blind to every one of them — nothing in the library is generic, extends a receiver,
         * declares its constructor explicitly, defaults to a comparison or names an enum constant
         * in mixed case today, so without a fixture neither rule would ever have been asked about
         * any of them.
         */
        private val FIXTURE_SOURCE = """
            package dev.eryalabs.fixture

            /**
             * A fixture type.
             *
             * @property documented Covered by an `@property` on the type, which is the house style
             *                      for a constructor property.
             */
            open class Fixture(
                val documented: String,
                val bare: String,
            ) {

                /**
                 * One documented parameter and one not.
                 *
                 * @param kept The documented one.
                 */
                fun halfDocumented(kept: String, forgotten: Int): String = kept

                /**
                 * A tag naming a parameter this function does not have.
                 *
                 * @param renamed Was called this before somebody changed the signature.
                 */
                fun stale(current: String): String = current

                /**
                 * Every parameter documented, across five lines.
                 *
                 * @param first  The one whose type carries a comma.
                 * @param middle The one whose default carries a comma.
                 * @param last   The one after it.
                 */
                fun spread(
                    first: Map<String, List<Int>>,
                    middle: String = "a, b",
                    last: ByteArray,
                ): Int = first.size + middle.length + last.size

                /**
                 * A generic function, whose type parameter sits between `fun` and the name.
                 *
                 * @param only The one parameter.
                 */
                fun <T> generic(only: T): T = only

                /** A generic function whose one parameter is undocumented. */
                fun <T> genericGap(slipped: T): T = slipped

                /**
                 * A default holding a comparison, and an arrow inside generic arguments.
                 *
                 * @param flag    Defaulted, with a `>` that is an operator and not a bracket.
                 * @param handler A type whose arrow sits *inside* the generic brackets, so the
                 *                comma beside it must stay inside the type.
                 * @param lambda  A lambda default, whose own comma belongs to its braces.
                 * @param tail    The parameter a single depth counter swallowed.
                 */
                fun comparisons(
                    flag: Boolean = 1 > 0,
                    handler: Map<(String) -> Int, String>,
                    lambda: (String, String) -> Int = { a, b -> a.length - b.length },
                    tail: String,
                ): Int = handler.size + tail.length + if (flag) 1 else 0

                /** No param tag at all, and it must not be reported: this is private. */
                private fun hidden(ignored: String): String = ignored

                /** Documented by its own comment. */
                val own: String = ""

                val undocumented: Int = 0

                override fun toString(): String = "Fixture"

                override fun equals(other: Any?): Boolean = other === this

                override fun hashCode(): Int = 0
            }

            /**
             * A fixture subtype whose second property is an override.
             *
             * @property documented Still documented here.
             */
            open class Subtype(
                val documented: String,
                override val inherited: String,
            ) : Fixture(documented, documented)

            /**
             * A generic type, whose type parameter sits after the name.
             *
             * @property held Documented here.
             */
            class Box<T>(val held: T, val unheld: T)

            /**
             * A type whose second property tag names nothing it declares.
             *
             * @property real    Documented and declared.
             * @property renamed Was called this before somebody changed the declaration.
             */
            class Stale(val real: String)

            /**
             * A fixture type declaring its primary constructor explicitly.
             *
             * @property declared Documented here, and must not be reported as a stale tag.
             */
            class Explicit @JvmOverloads constructor(
                val declared: String = "",
                val undeclared: Int = 0,
            )

            /**
             * An extension on a parameterized receiver — the third place a `<` hides in a head.
             *
             * @param only The one parameter.
             */
            fun Map<String, Int>.onReceiver(only: String): Int = size + only.length

            /** An extension on a nullable generic receiver, whose parameter is undocumented. */
            fun <T> List<T>?.receiverGap(slipped: String): Int = slipped.length

            /** An extension on a plain receiver, whose name must not absorb it. */
            fun String.plainReceiver(documentedOnly: String): Int = length + documentedOnly.length

            /** A fixture enum, whose constants are not all SCREAMING_CASE. */
            enum class FixtureVerdict {

                /** Documented by its own comment, the house style for a constant. */
                GOOD,

                BARE,

                Mixed,
            }
        """.trimIndent()
    }
}
