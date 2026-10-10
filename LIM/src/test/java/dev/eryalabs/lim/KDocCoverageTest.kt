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
 * Rules, scoped narrowly on purpose so that none widens into style policing:
 *
 *  1. **every parameter of every published function has a `@param`**, and every `@param` names a
 *     parameter the function actually has — the second half is what catches a rename;
 *  2. **every public property or constant of every published type is documented**, either by an
 *     `@property` on the type (the house style for a constructor property) or by its own doc
 *     comment (the house style for a `const val` or an enum constant) — and every `@property`
 *     names a property the type actually declares;
 *  3. **every published type, and every published zero-parameter function, has a doc comment.**
 *     Rules 1 and 2 require neither: `@property` coverage is satisfied by tags with no prose
 *     around them, and a function with nothing to pass satisfies rule 1 by asking nothing. The
 *     type half had a real gap — `Entry`'s `companion object : Parceler<Entry>`, seven published
 *     member lines in `LIM/api/lim.api`, carried no comment at all. The zero-parameter half has
 *     no subject in the library, because all fourteen zero-argument functions it publishes are
 *     `override`s and those are skipped; it is prophylactic, and control (n) is all of its
 *     evidence;
 *  4. **every `[link]` in every doc comment names something that still exists.** This is the one
 *     kind of rot none of the others can see: renaming a function leaves every `[oldName]` in
 *     every *other* comment untouched while every tag in its own comment stays correct, and the
 *     link then renders as literal brackets in the IDE and in the javadoc jar. There are 674 of
 *     them. **The resolver's vocabulary is deliberately wider than the published surface this
 *     file otherwise audits** — see [Vocabulary], where the reason is that real KDoc here links
 *     private things, internal things, overrides and a private function's parameter, and Dokka
 *     resolves every one. What rule 4 does *not* claim is that Dokka resolves a link in its own
 *     lexical scope; see the test.
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
 * **Limits, recorded rather than left to be discovered.** All but the last are unreachable from
 * anything this library publishes today and every one of those would be a silent hole if it grew
 * one; the last is reached by a real doc comment and is noted as such:
 *
 *  - [DECLARATION] recognises `class`, `object`, `interface`, `fun`, `val` and `var`, so a
 *    published `typealias` or a published **secondary** `constructor` is invisible to every rule.
 *  - A member key renders the parameter *types* but not an extension receiver, so
 *    `fun String.foo(x: Int)` and `fun Int.foo(x: Int)` would collide at `foo(Int)` and one
 *    [Excuse] would cover both. Nothing in `LIM/src/main/` is an extension on a published surface.
 *  - Kotlin block comments nest and the masker does not; see [mask].
 *  - Rule 4 reads `[name]` and `[label][target]` and nothing else: a link carrying a parameter
 *    list, which KDoc also accepts, is outside [DOC_LINK]. [MINIMUM_LINKS] is what would notice
 *    the spelling drifting that way wholesale.
 *  - [Vocabulary.membersOf] is keyed by a type's *simple* name, so two nested types sharing one
 *    would merge. The only such name here is `Companion`.
 *  - A backtick code span that opens on one doc line and closes on the next leaks its contents to
 *    the link extractor; see [linksIn]. **This one is reached**: `Utils.kt:357-358` holds such a
 *    span. It carries no bracket, so nothing is miscounted today, and the consequence if one
 *    appeared is a false report with a file and a line on it — the loud direction.
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

    /**
     * One `[name]` written in a doc comment, with where it was written.
     *
     * [name] is the half a resolver must answer about, which for KDoc's link-with-label form
     * `[label][target]` is the **target**: a resolver that took the label would report
     * `[Activity][android.app.Activity]`'s `Activity` as dangling and would never look at the
     * target, where a genuine break would be.
     */
    private class Link(val name: String, val file: String, val line: Int) {
        val where: String = "[$name] ($file:$line)"
    }

    /**
     * The names a `[link]` may resolve to — deliberately a **wider** set than [Report.members].
     *
     * That report is the *published* surface by construction: it drops `private` and `internal`
     * declarations and skips `override`s, which is right for "is this documented" and wrong for
     * "does this name still exist". Real KDoc in this library links private and internal things
     * and Dokka resolves every one of them — `[presentStringExtra]` is a private function,
     * `[redactedValue]` is `internal`, `[width]` is *a private function's parameter* and
     * `[TypedField.toString]` is an override. A resolver over the published report alone would
     * call all of those dangling, and the fix an implementer would then reach for is deleting a
     * correct cross-reference.
     *
     * So this set is every declaration in every published source whatever its visibility,
     * `override`s included, plus the parameters of all of them, plus every enum entry.
     *
     * @property types Simple names of every declared `class`/`object`/`interface`, for rule (i)
     *                 and for the owner half of a qualified link.
     * @property names Every declaration name and every parameter name, for rules (ii) and (iii).
     * @property membersOf What each type declares, keyed by the type's **simple** name, for rule
     *                     (iv). Two nested types sharing a simple name would merge here; the only
     *                     such name in this library is `Companion`, and the alternative — keying
     *                     by path — would refuse `[Entry.fields]` for being written unqualified.
     */
    private class Vocabulary(
        val types: Set<String>,
        val names: Set<String>,
        val membersOf: Map<String, Set<String>>,
    )

    /** Every complaint the sources produce, so the real tests and the controls share one loop. */
    private class Report(
        val members: List<Member>,
        val undocumentedParameters: List<String>,
        val staleParameterTags: List<String>,
        val undocumentedProperties: List<String>,
        val stalePropertyTags: List<String>,
        val undocumentedTypes: List<String>,
        val undocumentedNullaryFunctions: List<String>,
        val links: List<Link>,
        val danglingLinks: List<String>,
        val externalLinks: List<Link>,
        val unusedExternals: List<String>,
        val danglingExcuses: List<String>,
        val inertExcuses: List<String>,
    ) {
        val types: List<Member> = members.filter { it.kind == Kind.TYPE }
        val functions: List<Member> = members.filter { it.kind == Kind.FUNCTION }
        val properties: List<Member> = members.filter { it.kind == Kind.PROPERTY }
        val parameterCount: Int = functions.sumOf { it.parameters.size }
        val resolvedLinkCount: Int = links.size - danglingLinks.size
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
    private fun audit(
        sources: Map<String, String>,
        excuses: Map<String, Excuse>,
        externals: Map<String, String> = EXTERNAL,
    ): Report {
        // Masked once per source, because three readers want it: the member scan, the
        // declared-property scan the stale `@property` rule needs, and the link extractor.
        val ordered = sources.entries.sortedBy { it.key }
            .map { Triple(it.key, it.value, mask(it.value)) }
        val scans = ordered.map { (file, text, masked) -> scanIn(file, text, masked) }
        val members = scans.flatMap { it.members }
        val vocabulary = vocabularyOf(scans)

        val declared = mutableMapOf<String, MutableSet<String>>()
        ordered.forEach { (_, _, masked) ->
            declaredPropertyNamesIn(masked).forEach { (path, names) ->
                declared.getOrPut(path) { mutableSetOf() } += names
            }
        }

        val undocumentedParameters = mutableListOf<String>()
        val staleParameterTags = mutableListOf<String>()
        val undocumentedProperties = mutableListOf<String>()
        val stalePropertyTags = mutableListOf<String>()
        val undocumentedTypes = mutableListOf<String>()
        val undocumentedNullaryFunctions = mutableListOf<String>()
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
                    // The `@param` rule above asks nothing of a function that takes nothing, so
                    // this is the half that keeps a zero-parameter member from being undocumented
                    // and compliant at once.
                    if (member.parameters.isEmpty() && member.doc == null) {
                        if (member.key in excuses) {
                            excusedKeys += member.key
                        } else {
                            undocumentedNullaryFunctions += "${member.where} — a published " +
                                "function taking no parameters and carrying no doc comment, so " +
                                "the @param rule has nothing to ask of it"
                        }
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
                    // `@property` coverage is satisfied by tags with no surrounding prose, and
                    // nothing else asked whether a published type says what it is for.
                    if (member.doc == null) {
                        if (member.key in excuses) {
                            excusedKeys += member.key
                        } else {
                            undocumentedTypes += "${member.where} — a published type with no doc " +
                                "comment of any kind, so an IDE shows an integrator its name and " +
                                "nothing else"
                        }
                    }
                }
            }
        }

        val links = scans.flatMap { it.links }
        val danglingLinks = mutableListOf<String>()
        val externalLinks = mutableListOf<Link>()
        val usedExternals = mutableSetOf<String>()
        for (link in links) {
            if (resolvesInternally(link.name, vocabulary)) continue
            val external = externalKeyFor(link.name, externals)
            if (external != null) {
                usedExternals += external
                externalLinks += link
            } else {
                danglingLinks += "${link.where} — names nothing this library declares, at any " +
                    "visibility, and sits on no EXTERNAL allow-list. An IDE and the javadoc jar " +
                    "both render it as literal brackets"
            }
        }

        val keys = members.map { it.key }.toSet()
        return Report(
            members = members,
            undocumentedParameters = undocumentedParameters.sorted(),
            staleParameterTags = staleParameterTags.sorted(),
            undocumentedProperties = undocumentedProperties.sorted(),
            stalePropertyTags = stalePropertyTags.sorted(),
            undocumentedTypes = undocumentedTypes.sorted(),
            undocumentedNullaryFunctions = undocumentedNullaryFunctions.sorted(),
            links = links,
            danglingLinks = danglingLinks.sorted(),
            externalLinks = externalLinks,
            unusedExternals = externals.keys.filterNot { it in usedExternals }.sorted(),
            danglingExcuses = excuses.keys.filterNot { it in keys }.sorted(),
            inertExcuses = excuses.keys.filter { it in keys && it !in excusedKeys }.sorted(),
        )
    }

    /**
     * The wider name set, merged across every source. See [Vocabulary] for why it is wider.
     *
     * `<anonymous>` scopes are skipped, which is what keeps a function's local `val` out of the
     * vocabulary: Dokka cannot resolve a link to a local declaration either, so accepting one
     * would be the loose direction — a `[verifiedKey]` written in prose would resolve against a
     * local in some unrelated function body and the rename rot would go unreported.
     */
    private fun vocabularyOf(scans: List<SourceScan>): Vocabulary {
        val types = mutableSetOf<String>()
        val names = mutableSetOf<String>()
        val membersOf = mutableMapOf<String, MutableSet<String>>()

        fun own(owner: String, name: String) {
            if (owner.isEmpty()) return
            membersOf.getOrPut(owner.substringAfterLast('.')) { mutableSetOf() } += name
        }

        for (scan in scans) {
            for (declaration in scan.declarations) {
                if (declaration.name == ANONYMOUS) continue
                names += declaration.name
                own(declaration.owner, declaration.name)
                declaration.parameters.forEach { parameter ->
                    names += parameter.name
                    // A type's parameter list is its primary constructor's, so those names are
                    // members of it: `[Entry.fields]` is written that way.
                    if (declaration.isType) own(declaration.path, parameter.name)
                }
                if (declaration.isType) types += declaration.name
            }
            for ((owner, name) in scan.enumEntries) {
                names += name
                own(owner, name)
            }
        }
        return Vocabulary(types, names, membersOf)
    }

    /**
     * Whether `[name]` names something this library still declares — rules (i) to (iv).
     *
     * A qualified `A.b` is split at the **last** dot and `A`'s own last segment is what must be a
     * type, so `[SignedStatement.Rotate.signature]` asks the same question of `Rotate` that
     * `[Entry.fields]` asks of `Entry`.
     */
    private fun resolvesInternally(name: String, vocabulary: Vocabulary): Boolean {
        if ('.' !in name) return name in vocabulary.names
        val owner = name.substringBeforeLast('.').substringAfterLast('.')
        return owner in vocabulary.types &&
            name.substringAfterLast('.') in vocabulary.membersOf[owner].orEmpty()
    }

    /**
     * Which [EXTERNAL] entry accepts `[name]`, or `null` — rule (v), and the only rule that can
     * say yes about a name this repository does not contain.
     *
     * An exact entry accepts the name itself **or any dotted owner of it**, because a member of an
     * external type is external too: `Base64` is Android's and so `[Base64.DEFAULT]` is Android's
     * constant, without `EXTERNAL` having to enumerate the platform's members. A prefix entry —
     * one ending in `.` — accepts anything beneath it, which is what `[android.app.Activity]` and
     * `[java.security.Signature]` are written as. The longest prefix wins so that a later, more
     * specific entry can be the one a usage is attributed to.
     */
    private fun externalKeyFor(name: String, externals: Map<String, String>): String? {
        var probe = name
        while (true) {
            if (probe in externals) return probe
            if ('.' !in probe) break
            probe = probe.substringBeforeLast('.')
        }
        return externals.keys
            .filter { it.endsWith(".") && name.startsWith(it) }
            .maxByOrNull { it.length }
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

    // ── The two rules T33's log named as where this surface can regrow ────

    /**
     * Every published **type** carries a doc comment.
     *
     * The rules above require none: `@property` coverage is satisfied by tags with no prose
     * around them, and a type with no properties at all is asked nothing by anything. Only
     * `Entry`'s class comment was pinned, and that by name. This is the half with a *measured*
     * gap rather than a prophylactic rule — `Entry`'s `companion object : Parceler<Entry>` is
     * real published surface, seven member lines of it in `LIM/api/lim.api`, and it carried no
     * comment at all.
     */
    @Test
    fun `every published type has a doc comment`() {
        assertEquals(
            "a published type carries no documentation of any kind. `@property` tags satisfy the " +
                "property rule without a word of prose around them, and a type with no " +
                "properties is asked nothing by anything else — so this is the rule that keeps " +
                "the next type from being published anonymous",
            emptyList<String>(),
            onDisk().undocumentedTypes,
        )
    }

    /**
     * Every published **zero-parameter** function carries a doc comment.
     *
     * **Prophylactic, and the task that added it says so rather than implying it closed a gap:**
     * every zero-argument function in the published sources today is an `override` — fourteen
     * `toString` and `hashCode` implementations across ten published types — and the scanner
     * skips overrides, so this rule has no subject at all. (The one zero-argument function that
     * is *not* an override, `readText` at `Utils.kt:1632`, is local to a function body, so it is
     * not published either and the scan correctly never sees it.) What keeps the rule honest is
     * its fixture in control (n): without one it would be an assertion that has never been shown
     * to fail, which is control (b)'s and control (i)'s argument applied a third time.
     *
     * It exists because the `@param` rule is the only thing asking a function for documentation,
     * and a function with nothing to pass satisfies it by asking nothing.
     */
    @Test
    fun `every published zero-parameter function has a doc comment`() {
        assertEquals(
            "a published function takes no parameters and carries no doc comment, which the " +
                "@param rule cannot notice: it asks a function about its parameters and this one " +
                "has none",
            emptyList<String>(),
            onDisk().undocumentedNullaryFunctions,
        )
    }

    // ── Cross-references ──────────────────────────────────────────────────

    /**
     * Every `[link]` in every published doc comment names something that still exists.
     *
     * **This is the one kind of doc rot nothing here could see.** `KDocCoverageTest`'s other rules
     * answer "is every member documented"; `ChangelogTest` resolves every code span in one
     * markdown file; a KDoc cross-reference was checked by nothing, and there are hundreds of
     * them. A link naming something this library no longer has renders as literal brackets in the
     * IDE and in the javadoc jar — and `@param`/`@property` coverage cannot catch it, because
     * renaming a function leaves every `[oldName]` in every *other* comment untouched and every
     * tag in its own comment still correct.
     *
     * **What this deliberately does not claim**, so it cannot be widened into a reimplementation
     * of Dokka: that Dokka resolves the link *in that lexical scope*. A `[publicKey]` written in a
     * function that has no such parameter resolves here, because some other declaration in the
     * library has that name. The question answered is the rename rot, and this is the version of
     * the rule whose first run does not demand an unbounded comment rewrite.
     */
    @Test
    fun `every KDoc link resolves to a name this library still has`() {
        assertEquals(
            "a doc comment cross-references a name nothing in this library declares. Fix the " +
                "link: a link naming something that left the library is the link's fault, not " +
                "the code's",
            emptyList<String>(),
            onDisk().danglingLinks,
        )
        // Floor, measured over the surface actually scanned and set below it: an extractor that
        // found nothing would report nothing dangling for ever, which is this file's standing
        // vacuity trap.
        assertTrue(
            "the scan must find links for this to mean anything; found ${onDisk().links.size}",
            onDisk().links.size >= MINIMUM_LINKS,
        )
        // And the published surface must be reached by the *internal* half of the resolver, or an
        // over-broad EXTERNAL entry could carry the whole measurement.
        assertTrue(
            "most links must resolve internally; ${onDisk().externalLinks.size} of " +
                "${onDisk().links.size} went to EXTERNAL",
            onDisk().externalLinks.size * 4 < onDisk().links.size,
        )
        println(
            "KDocCoverageTest: ${onDisk().links.size} KDoc links checked, " +
                "${onDisk().resolvedLinkCount} resolved " +
                "(${onDisk().externalLinks.size} of them external), " +
                "${onDisk().danglingLinks.size} dangling",
        )
    }

    /**
     * [EXTERNAL] hygiene, in both directions, which is what keeps rule (v) from becoming the
     * drawer a dangling link is filed in.
     *
     * The unused direction is the one that needs saying: an entry whose last usage went away is
     * an allow-list line that will wave through whatever lands under that name next.
     */
    @Test
    fun `every EXTERNAL entry is used, and carries a reason`() {
        assertEquals(
            "an EXTERNAL entry nothing links to. It was either never needed or the link that " +
                "needed it has gone; either way it now stands ready to vouch for a name nobody " +
                "has written yet",
            emptyList<String>(),
            onDisk().unusedExternals,
        )
        assertEquals(
            "every EXTERNAL entry must say what it is and why this library may point at it",
            emptyList<String>(),
            EXTERNAL.filterValues { it.isBlank() }.keys.sorted(),
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
     * (j) The link resolver reports absence **and** presence from one loop, which is control (a)'s
     * argument applied to the new rule.
     *
     * `[kept]` names the fixture's one property and `[renamedAway]` names nothing, so neither a
     * resolver that accepts everything nor one that accepts nothing can pass this.
     */
    @Test
    fun `control - one resolving and one dangling link yields exactly one report`() {
        val report = linkReport(LINK_FIXTURE_PAIR)
        assertEquals("found ${report.danglingLinks}", 1, report.danglingLinks.size)
        assertTrue(
            "the complaint must name the link and where it is written: ${report.danglingLinks}",
            "[renamedAway]" in report.danglingLinks.single() &&
                "Fixture.kt:3" in report.danglingLinks.single(),
        )
        assertEquals(
            "…and both links must have been extracted, or the one report is an accident",
            listOf("kept", "renamedAway"),
            report.links.map { it.name },
        )
    }

    /**
     * (k) A qualified link is two questions, and both halves must be asked.
     *
     * `[Fixture.kept]` has an owner this fixture declares and a member it declares; the shape
     * beside it has the owner and not the member. The real instance is asserted too: the
     * library's nine `[Utils.decodeEntry]` links resolve, which a resolver that gave up on the
     * first dot would also manage — by reporting them, which is why the fixture carries the
     * negative half. (The assertion is `>= 1` rather than that count, so adding or removing one
     * of those links is not a reason for this control to fail.)
     */
    @Test
    fun `control - a qualified link whose member is gone is reported`() {
        val report = linkReport(LINK_FIXTURE_QUALIFIED)
        assertEquals("found ${report.danglingLinks}", 1, report.danglingLinks.size)
        assertTrue(
            "the complaint must name the whole qualified link: ${report.danglingLinks}",
            "[Fixture.goneAway]" in report.danglingLinks.single(),
        )
        assertEquals(
            "the resolving one beside it must not be reported, or the rule means nothing",
            emptyList<String>(),
            report.danglingLinks.filter { "Fixture.kept" in it },
        )
        assertEquals(
            "…and the real shape must resolve over the real sources",
            emptyList<String>(),
            onDisk().danglingLinks.filter { "Utils.decodeEntry" in it },
        )
        assertTrue(
            "…having actually been found there, or that assertion is about nothing",
            onDisk().links.count { it.name == "Utils.decodeEntry" } >= 1,
        )
    }

    /**
     * (l) KDoc's link-with-label form, in both directions — the pair is what pins the trap.
     *
     * `[label][target]` puts the name to resolve in the **second** bracket. A resolver that took
     * the label would report `[Activity][android.app.Activity]`'s label as dangling and would
     * never look at the target, where a genuine break would be. There are four real instances and
     * all four are a label a resolver should ignore.
     */
    @Test
    fun `control - the target of a labelled link is the half resolved`() {
        val report = linkReport(LINK_FIXTURE_LABELLED)
        assertEquals("found ${report.danglingLinks}", 1, report.danglingLinks.size)
        assertTrue(
            "the complaint must name the target, not the label: ${report.danglingLinks}",
            "[noSuchTarget]" in report.danglingLinks.single(),
        )
        assertEquals(
            "a nonsense *label* in front of a real target must not be reported — that is the " +
                "half a label-reading resolver gets wrong",
            emptyList<String>(),
            report.danglingLinks.filter { "nonsenseLabel" in it },
        )
        assertEquals(
            "…and only the two targets may be extracted at all",
            listOf("kept", "noSuchTarget"),
            report.links.map { it.name },
        )
    }

    /** (m) [EXTERNAL] hygiene, both ways, over a fixture that needs exactly one entry. */
    @Test
    fun `control - external hygiene holds in both directions`() {
        val reason = "a fixture external, named on purpose"

        val unknown = linkReport(LINK_FIXTURE_EXTERNAL, emptyMap())
        assertEquals(
            "an external name on no allow-list must be reported: that is the direction which " +
                "keeps rule (v) from being a hole",
            2,
            unknown.danglingLinks.size,
        )

        val allowed = linkReport(LINK_FIXTURE_EXTERNAL, mapOf("Alien" to reason))
        assertEquals(
            "…and an exact entry must accept the name and its members, or every platform " +
                "constant would need enumerating: ${allowed.danglingLinks}",
            emptyList<String>(),
            allowed.danglingLinks,
        )
        assertEquals(
            "…counted as external rather than quietly as internal",
            2,
            allowed.externalLinks.size,
        )
        assertEquals("…and the entry is used, so it is not reported", emptyList<String>(), allowed.unusedExternals)

        val prefixed = linkReport(LINK_FIXTURE_EXTERNAL, mapOf("Alien." to reason))
        assertEquals(
            "a prefix entry accepts what is beneath it and not the bare name, so `[Alien]` is " +
                "still reported: the two entry shapes are different claims",
            1,
            prefixed.danglingLinks.size,
        )

        val unused = linkReport(
            LINK_FIXTURE_EXTERNAL,
            mapOf("Alien" to reason, "NobodyLinksThis" to reason),
        )
        assertEquals(
            "an entry nothing links to must be reported, or an allow-list line outlives its " +
                "last usage and vouches for whatever lands under that name next",
            listOf("NobodyLinksThis"),
            unused.unusedExternals,
        )
    }

    /**
     * (n) The two rules T33's log named, each over a fixture, because one of them has no real
     * subject at all.
     *
     * The zero-parameter rule is prophylactic — every zero-argument function the library publishes
     * is an `override` and the scanner skips those — so this fixture is the only thing standing
     * between it and an assertion that has never been shown to fail.
     */
    @Test
    fun `control - an undocumented type and an undocumented nullary function are reported`() {
        assertEquals(
            "a published type with no doc comment must be reported, by key",
            listOf("Undocumented"),
            fixtureReport().undocumentedTypes.map { it.substringBefore(" (") },
        )
        assertEquals(
            "…and a published zero-parameter function with none, likewise",
            listOf("undocumentedNullary()"),
            fixtureReport().undocumentedNullaryFunctions.map { it.substringBefore(" (") },
        )
        // A floor, not the non-reporting claim — that is the `assertEquals` above, which names
        // the one offender exactly and so already refuses a rule that reports every type.
        assertTrue(
            "the scan must have found the fixture's types for this to mean anything: six " +
                "documented and the one undocumented; found ${fixtureReport().types.size}",
            fixtureReport().types.size >= 7,
        )
    }

    /**
     * (o) **The vocabulary split**, which is the control the whole resolver turns on.
     *
     * One fixture, one loop, both answers: a link naming a `private` function, that function's
     * parameter, an `internal` type, an internal type's property, an `override` and a private
     * enum's constant all resolve, while a link naming nothing at all is reported. A resolver
     * scoped to [Report.members] — the *published* report, which drops private and internal
     * declarations and skips overrides — fails this control and passes every other one in the
     * file, and would have had an implementer deleting six correct cross-references.
     */
    @Test
    fun `control - a link to a private or internal name resolves and a link to nothing does not`() {
        val report = linkReport(LINK_FIXTURE_VISIBILITY)
        assertEquals("found ${report.danglingLinks}", 1, report.danglingLinks.size)
        assertTrue(
            "the one complaint must be the name nothing declares: ${report.danglingLinks}",
            "[nobodysName]" in report.danglingLinks.single(),
        )
        assertEquals(
            "a private declaration, its parameter, an internal type, an internal type's " +
                "property, an override and a private enum's constant must each resolve",
            emptyList<String>(),
            report.danglingLinks.filter { complaint ->
                HIDDEN_FIXTURE_LINKS.any { "[$it]" in complaint }
            },
        )
        assertEquals(
            "…and every one of them must have been extracted, or this control is about nothing",
            HIDDEN_FIXTURE_LINKS,
            report.links.map { it.name }.filter { it in HIDDEN_FIXTURE_LINKS },
        )
        // And the premise: the published report genuinely cannot see any of them. Compared on the
        // *last segment*, because a `Member` name is never qualified while `[HiddenFlow.OFF]` is —
        // so matching the list verbatim would have let a leaked enum constant through as `OFF`.
        val hiddenSimpleNames = HIDDEN_FIXTURE_LINKS.map { it.substringAfterLast('.') }
        assertEquals(
            "none of those six may appear in the published member set, or the two sets are not " +
                "different and this control proves nothing",
            emptyList<String>(),
            report.members.map { it.name }.filter { it in hiddenSimpleNames },
        )
    }

    /**
     * (p) A bracketed subscript is not a link — in a fence, in a backtick span, and bare.
     *
     * **Prophylactic in both of the first two directions**, and the prose says so rather than
     * implying a fix: there is no bracket occurrence inside any fence or code span in the
     * published sources today. The hazard is concrete all the same. `KDocExampleTest` copies
     * guide blocks verbatim into doc comments, and `docs/INTEGRATION.md:255` is
     * `val account = accounts[verifiedKey]` — a subscript on a local `val`. The day that block is
     * pulled into a doc comment, reporting it would offer two fixes and no good one: edit the
     * example, which breaks the verbatim rule and `GuideSnippetTest`'s region equality, or excuse
     * it, which is coverage theatre.
     *
     * The third and fourth fixtures are the *other* direction, because a skip that skipped
     * everything would pass the first two for the wrong reason — and the fourth is the one a
     * review probe earned. Pairing backticks left to right on a line with an odd count makes a
     * stray backtick pair with the next span's opener and blanks the prose between them, so a
     * genuinely dangling link went unreported and the whole suite stayed green. See
     * [withoutCodeSpans].
     */
    @Test
    fun `control - a bracketed subscript inside a fence or a code span is not a link`() {
        assertEquals(
            "a fenced example's subscript must be invisible to the extractor, not merely " +
                "unreported: ${linkReport(LINK_FIXTURE_FENCED).links.map { it.name }}",
            emptyList<String>(),
            linkReport(LINK_FIXTURE_FENCED).links.map { it.name },
        )
        assertEquals(
            "…and so must one inside a backtick span",
            emptyList<String>(),
            linkReport(LINK_FIXTURE_SPANNED).links.map { it.name },
        )
        val bare = linkReport(LINK_FIXTURE_UNFENCED)
        assertEquals(
            "…while the same text with no fence and no backticks around it is a link like any " +
                "other, and is reported",
            listOf("verifiedKey"),
            bare.links.map { it.name },
        )
        assertEquals("found ${bare.danglingLinks}", 1, bare.danglingLinks.size)
        assertTrue(
            "…naming it: ${bare.danglingLinks}",
            "[verifiedKey]" in bare.danglingLinks.single(),
        )
        // And the one that was a silent hole until a probe wrote it: a stray backtick before a
        // real span must not swallow the link between them.
        val stray = linkReport(LINK_FIXTURE_STRAY_BACKTICK)
        assertEquals(
            "a line whose backtick count is odd must be read whole, or an unpaired backtick " +
                "blanks the prose up to the next span and takes a dangling link with it — " +
                "silently, which for this file is the worst outcome available",
            listOf("swallowed"),
            stray.links.map { it.name },
        )
        assertEquals("found ${stray.danglingLinks}", 1, stray.danglingLinks.size)
    }

    /**
     * (q) Markdown's own `[text](url)` form is not a KDoc link — trap (ii), and the one that was
     * claimed as "pinned by a fixture" before it was.
     *
     * There are no `](` occurrences in the published sources, so this is prevention like the
     * fence rule. A review round proved the skip was dead to the suite — removing the `(` half of
     * the test in [linksIn] left all 28 tests green — which is the same vacuity this file refuses
     * everywhere else, so the fixture carries both directions: a markdown link whose text would
     * resolve to nothing is skipped, and the same bracket without a `(` after it is reported.
     */
    @Test
    fun `control - a markdown text and url link is not a KDoc link`() {
        assertEquals(
            "a `[text](url)` form must be invisible to the extractor: it is markdown's link " +
                "syntax, and its text is prose rather than a name to resolve",
            emptyList<String>(),
            linkReport(LINK_FIXTURE_MARKDOWN).links.map { it.name },
        )
        val bare = linkReport(LINK_FIXTURE_MARKDOWN_WITHOUT_URL)
        assertEquals(
            "…while the same bracket with no `(` after it is a KDoc link like any other",
            listOf("guide"),
            bare.links.map { it.name },
        )
        assertEquals("found ${bare.danglingLinks}", 1, bare.danglingLinks.size)
        assertTrue(
            "…naming it: ${bare.danglingLinks}",
            "[guide]" in bare.danglingLinks.single(),
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
     * same bookkeeping [scanIn] makes every scope decision with.
     *
     * (This link said `membersIn` until the scan was renamed under it — rule 4's own rot, in rule
     * 4's author's comment, found by a review round rather than by the rule. The resolver reads
     * `LIM/src/main/` only, so nothing in this file's links is checked by anything; that is a
     * deliberate scope and the reason it is written down here.)
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
     * What one source yields, on one walk: its published members, the wider vocabulary a `[link]`
     * resolves against, and the links themselves.
     *
     * @property members The published surface, which is what the coverage rules ask about.
     * @property declarations Every declaration in a *named* scope, whatever its visibility, with
     *                       `override`s kept. See [Vocabulary] for why this is a different set.
     * @property enumEntries Owner path to entry name — the one shape no [DECLARATION] match
     *                       covers, and the one `[StatementVerdict.VALID]` needs.
     * @property links Every `[name]` written in a doc comment of this source.
     */
    private class SourceScan(
        val members: List<Member>,
        val declarations: List<Declaration>,
        val enumEntries: List<Pair<String, String>>,
        val links: List<Link>,
    )

    /**
     * Every published member of one source, plus the wider sets above.
     *
     * One character walk, which is what makes the scope question answerable at all: a declaration
     * is a *member* only when every brace it sits inside belongs to a published type. That keeps a
     * local `val` out of the property rule, a lambda's parameters out of the parameter rule, and
     * anything inside a private function out of both.
     */
    private fun scanIn(file: String, source: String, masked: Masked): SourceScan {
        val text = masked.text
        val lines = source.lines()
        val lineOf = lineIndex(text)
        val starts = DECLARATION.findAll(text).associateBy { it.range.first }

        val members = mutableListOf<Member>()
        val declarations = mutableListOf<Declaration>()
        val enumEntries = mutableListOf<Pair<String, String>>()
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
                // The wider set, collected before the published filter below and deliberately
                // without it: a link may name a private thing and Dokka will resolve it.
                if (scopes.none { it.name == ANONYMOUS }) declarations += declaration
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
                    if (scope.isEnum) {
                        val entries = enumEntriesIn(
                            file = file,
                            body = text.substring(scope.bodyStart, i),
                            bodyStart = scope.bodyStart,
                            lineOf = lineOf,
                            owner = scope.path,
                            ownerDoc = scope.doc,
                            docFor = ::docFor,
                        )
                        enumEntries += entries.map { scope.path to it.name }
                        if (scope.isPublishedType) members += entries
                    }
                    pending = null
                }
            }
            i++
        }
        return SourceScan(
            members = members,
            declarations = declarations,
            enumEntries = enumEntries,
            links = linksIn(file, masked),
        )
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
     * Every `[name]` in one source's doc comments, read off [Masked.docs] rather than by line
     * prefix.
     *
     * **The scoping is the first parser rule and it is not cosmetic.** The arithmetic behind the
     * total is derived in exactly one place, [MINIMUM_LINKS]'s KDoc, because this file's whole
     * thesis is that a number transcribed twice is a number that will disagree with itself. The
     * part that matters here is the split: of the bracket shapes on disk, most sit on `*`-prefixed lines, 7 are real code
     * (`fields[key]`, `nonce[i]`), 7 are `//` comments Dokka never renders — and **7 are links on
     * single-line `/** … */` comments, which Dokka renders like any other**. An extractor scoped
     * to `*`-prefixed lines would silently skip that last bucket, two of whose targets are among
     * the private-and-internal names this resolver exists for. Going through the masker's own doc
     * spans picks them up and drops, correctly, the four links in `Redaction.kt`'s plain `/* */`
     * file header, which is not KDoc and which Dokka does not render at all.
     *
     * **Three things in brackets that are not links**, each skipped here rather than excused
     * later. **The first two are prevention rather than repair — neither has an instance in the
     * published sources today**, which is why the extracted total equals the arithmetic with no
     * deduction for either, and why each is pinned by a fixture in both directions rather than by
     * a real occurrence: controls (p) and (q). The third has four real instances and is the only
     * one of the three that changes the total:
     *
     *  - a **fenced code block**, and an **inline backtick span**. `KDocExampleTest` copies guide
     *    blocks verbatim into doc comments, and `docs/INTEGRATION.md:255` is
     *    `val account = accounts[verifiedKey]` — a subscript on a local `val`. That block has not
     *    been pulled into a doc comment yet; when it is, reporting it would offer only two fixes:
     *    edit the example, which breaks `GuideSnippetTest`'s region equality, or excuse it, which
     *    is coverage theatre. The 7 real-code occurrences above are the same rule seen from the
     *    other side, and they are what makes the hazard concrete rather than imagined.
     *  - markdown's own **`[text](url)`** form; there are no `](` occurrences in the published
     *    sources.
     *  - the **label** half of KDoc's `[label][target]`; see [Link]. Four instances, all of them
     *    a label a resolver should ignore.
     *
     * Backtick spans are paired within a line, and only when the line's count is even; see
     * [withoutCodeSpans], which is where a review probe found the one silent hole this extractor
     * had. A span that opens on one line and closes on the next leaks its contents here —
     * Markdown mostly allows that, this does not read it, and the consequence is a false report
     * carrying a file and a line rather than a silent miss.
     */
    private fun linksIn(file: String, masked: Masked): List<Link> {
        val links = mutableListOf<Link>()
        for ((endLine, doc) in masked.docs.entries.sortedBy { it.key }) {
            val docLines = doc.lines()
            val startLine = endLine - (docLines.size - 1)
            var inFence = false
            for ((offset, raw) in docLines.withIndex()) {
                if (DOC_FENCE_LINE.containsMatchIn(raw)) {
                    inFence = !inFence
                    continue
                }
                if (inFence) continue
                val prose = withoutCodeSpans(raw)
                for (match in DOC_LINK.findAll(prose)) {
                    val after = prose.getOrNull(match.range.last + 1)
                    // `(` makes it markdown's link form; `[` makes it a label, whose target this
                    // same loop reaches on its next iteration.
                    if (after == '(' || after == '[') continue
                    links += Link(match.groupValues[1], file, startLine + offset)
                }
            }
        }
        return links
    }

    /**
     * One doc-comment line with its backtick spans blanked, pairs left to right.
     *
     * **A line whose backtick count is odd is left entirely alone**, and that is the only choice
     * here that is not obvious. Pairing left to right on such a line is *wrong in the silent
     * direction*: a stray backtick pairs with the next real span's opener, so the prose between
     * them — including any `[link]` in it — is blanked and never checked. A review probe proved
     * it with a real doc comment, where a genuinely dangling link went unreported and the whole
     * suite stayed green. Blanking nothing instead can only produce a *false* report, with a file
     * and a line on it, which is the direction a reader can act on.
     *
     * Which backtick is the unmatched one is not decidable from the line alone, so this does not
     * try. **The odd-count branch is taken by the real sources on every run**, rather than being
     * prophylactic: `Utils.kt:357-358` is a code span spread across two lines, so the first line
     * carries one backtick and the second carries three, and those two are the whole of it. (A
     * *fence* line never reaches here — [linksIn] toggles on it and skips the block's interior
     * before calling this — so the 22 fence lines are not instances, which a review round
     * established by instrumenting the branch and printing every line that took it.) Neither of
     * the two holds a bracket today, so the extracted total is the same either way; the branch is
     * live all the same, and that span is a standing instance of the cross-line limit the class
     * KDoc records.
     */
    private fun withoutCodeSpans(line: String): String {
        if (line.count { it == '`' } % 2 != 0) return line
        val out = StringBuilder(line.length)
        var i = 0
        while (i < line.length) {
            val close = if (line[i] == '`') line.indexOf('`', i + 1) else -1
            if (close < 0) {
                out.append(line[i])
                i++
            } else {
                while (i <= close) {
                    out.append(' ')
                    i++
                }
            }
        }
        return out.toString()
    }

    /**
     * Every property name each type declares, whatever its visibility and whether or not it is an
     * `override`.
     *
     * The coverage rule asks only about published non-override properties; the *stale* `@property`
     * rule has to accept a tag naming any declared one, or documenting an inherited property —
     * which `SignedStatement` does, from the base class, for the `signature` its three cases
     * override — would read as a dead tag.
     */
    private fun declaredPropertyNamesIn(masked: Masked): Map<String, Set<String>> {
        val text = masked.text
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
        audit(mapOf("Fixture.kt" to FIXTURE_SOURCE), excuses, externals = emptyMap())

    /**
     * One link fixture, audited with no excuses and only the externals a control states.
     *
     * The link controls take a source each rather than sharing [FIXTURE_SOURCE]: every one of
     * them claims an *exact* count, and a shared fixture carrying seven deliberate danglers would
     * turn each of those claims into a substring filter — which is how the first draft of control
     * (e) passed itself while asking nothing.
     */
    private fun linkReport(source: String, externals: Map<String, String> = emptyMap()): Report =
        audit(mapOf("Fixture.kt" to source), emptyMap(), externals)

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
         * The names a `[link]` may resolve to that this repository does not contain — rule (v),
         * and the only place where "resolves" is a claim about somebody else's code.
         *
         * Each entry carries its reason, and `EXTERNAL hygiene holds in both directions` fails on
         * an entry nothing uses as well as on a name no entry covers. That is what keeps this map
         * from becoming the place a dangling link goes to be forgotten: adding a line here is as
         * visible as adding one to [EXCUSES], and removing a usage reddens the file.
         *
         * A key ending in `.` is a **package prefix** and accepts everything beneath it; any
         * other key is an **exact name** and accepts that name and its members. See
         * [externalKeyFor].
         *
         * The hygiene direction has already earned its keep: a first draft of this map carried
         * `kotlin.`, `Activity`, `Gson`, `ByteArray` and `Map`, every one of them plausible and
         * none of them linked by anything. The test below named all five.
         */
        private val EXTERNAL = mapOf(
            "android." to "fully-qualified Android platform links: `android.app.Activity`, " +
                "written out in five `@param` tags because `Utils` does not import the type, and " +
                "`android.content.Intent` where the prose needs the whole name",
            "java." to "fully-qualified JDK links, all of them in the signing and key-decoding " +
                "KDoc — `java.security.Signature`, `java.security.KeyFactory`, `java.util.Locale`",
            "Context" to "Android's, imported by `Utils` and the first parameter of every " +
                "intent-building entry point",
            "Intent" to "Android's, imported by `Utils`; the type every entry point returns",
            "Parcelable" to "Android's, the supertype `Entry` and `TypedField` implement",
            "Parcel" to "Android's, what `Entry`'s hand-written `Parceler` writes to and reads " +
                "from; the argument whose untrusted contents its `create` defaults rather than " +
                "throws on",
            "Parceler" to "`kotlinx.parcelize.Parceler`, which `Entry.Companion` implements — the " +
                "published surface whose doc comment this rule's sibling asked for",
            "Base64" to "Android's `android.util.Base64`, which encodes every key and signature " +
                "this library moves; `Base64.DEFAULT` is reached as a member of it",
            "SecureRandom" to "`java.security.SecureRandom`, the injected randomness " +
                "`generateNonce` and `createSignChallengeIntent` take",
            "String" to "Kotlin's, named where a doc comment is about the type itself rather than " +
                "a parameter that happens to be one",
            "Int" to "Kotlin's, named where the protocol-version parser explains what does not " +
                "fit in one",
            "Long" to "Kotlin's; `Long.MAX_VALUE` is cited where a freshness window saturates",
            "Char" to "Kotlin's; `Char.isISOControl` is cited by the describe-text sanitiser",
            "NullPointerException" to "`java.lang`'s, named five times by the Java-interop " +
                "warnings: a Kotlin non-null parameter compiles to a `checkNotNullParameter` " +
                "intrinsic that Java callers can and do trip",
        )


        /**
         * Floors, each at or below a count this file *measured* and prints on every run — 16
         * sources, 19 published types, 45 published functions with 93 parameters, 82 published
         * properties and constants, and **674 KDoc links** when it was written. Set below the
         * actuals so that *adding* a published member does not fail this file, while a scanner
         * drifting towards the empty set does.
         *
         * [MINIMUM_SOURCES] is the one set *at* the measured value rather than below it, on
         * purpose: a source file disappearing from the published package is worth a failure, while
         * adding one is not.
         *
         * [MINIMUM_LINKS] was measured the same way and is worth showing the arithmetic for,
         * because a floor transcribed from a planning document is a floor nobody measured. `grep`
         * for the bracket shape over the published sources returns 696 occurrences: 675 on
         * `*`-prefixed lines, 7 on `//` lines Dokka never renders, 7 on single-line `/** … */`
         * comments it renders like any other, and 7 that are real code (`fields[key]`,
         * `nonce[i]`). Doc-span extraction takes the first and third buckets, drops the four
         * links in `Redaction.kt`'s plain `/* */` file header, and resolves the *target* half of
         * the four `[label][target]` pairs rather than both halves: 675 − 4 + 7 − 4 = **674**,
         * which is what the run prints. 33 of them go to [EXTERNAL].
         */
        private const val MINIMUM_SOURCES = 16
        private const val MINIMUM_TYPES = 15
        private const val MINIMUM_FUNCTIONS = 38
        private const val MINIMUM_PARAMETERS = 85
        private const val MINIMUM_PROPERTIES = 70
        private const val MINIMUM_LINKS = 620

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
         * A KDoc cross-reference, in the one spelling this library uses: `[name]`, where the name
         * may be dotted.
         *
         * Identical to the shape the measurement in [linksIn] counts, so the extracted total and
         * the `grep` total are answers to the same question. A link carrying a parameter list —
         * `[createShareIntent(Context, Entry)]`, which KDoc also accepts — is outside it, and
         * there are none; the floor is what would notice a drift towards the empty set.
         */
        private val DOC_LINK = Regex("""\[([A-Za-z][A-Za-z0-9_.]*)]""")

        /**
         * A fenced-code line inside a doc comment — `KDocExampleTest:1747` verbatim, on purpose.
         *
         * That file *refuses* a fence line in a doc comment that carries no `*` prefix, as well
         * as `~~~`, HTML `<pre>` and markdown's indented form. So this one pattern is enough to
         * find every fence in this library's KDoc, and the two files agree about what a fence is
         * by construction rather than by coincidence.
         */
        private val DOC_FENCE_LINE = Regex("""^\s*\*\s*```""")

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
         * (h); `Stale` is (i); `Undocumented` and `undocumentedNullary` are (n), and the nullary
         * one has no real subject in the library at all — every zero-argument function it
         * publishes is an `override`, so this fixture is the whole of that rule's evidence.
         * Those last shapes are here because adversarial review probes found the scanner
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

            class Undocumented {

                /** Documented, so the only gap is the type's own. */
                val held: String = ""
            }

            fun undocumentedNullary(): Int = 0
        """.trimIndent()

        /**
         * The six fixture names control (o) requires to resolve — a private function, its
         * parameter, an `internal` type, an internal type's property, an `override` and a
         * **private enum's constant**, which is the one shape no [DECLARATION] match covers and
         * which no other fixture here exercises.
         *
         * Every one of them is a shape [Report.members] drops. **Three of the six have a real
         * instance in the library and three do not**, which is worth stating exactly because the
         * fixture is the only evidence for the other three: `[presentStringExtra]` is a private
         * function, `[width]` is a private function's parameter and `[TypedField.toString]` is an
         * override. An `internal` *type* and an internal type's property have no instance —
         * `redactedValue` (`Redaction.kt:28`) is the library's only `internal` declaration and it
         * is a function — and neither has a private enum's constant, `StatementVerdict` being the
         * only enum here and published.
         */
        private val HIDDEN_FIXTURE_LINKS = listOf(
            "hiddenHelper",
            "hiddenOnly",
            "Invisible",
            "unpublished",
            "toString",
            "HiddenFlow.OFF",
        )

        /** (j) One resolving link and one dangling one, and nothing else. */
        private val LINK_FIXTURE_PAIR = """
            package dev.eryalabs.fixture

            /** A fixture type linking [kept] and [renamedAway]. */
            class Fixture(val kept: String)
        """.trimIndent()

        /** (k) A qualified link whose member exists, beside one whose member does not. */
        private val LINK_FIXTURE_QUALIFIED = """
            package dev.eryalabs.fixture

            /** A fixture type linking [Fixture.kept] and [Fixture.goneAway]. */
            class Fixture(val kept: String)
        """.trimIndent()

        /**
         * (l) KDoc's `[label][target]` in both directions: a nonsense label in front of a real
         * target, and a real label in front of a target that is gone.
         */
        private val LINK_FIXTURE_LABELLED = """
            package dev.eryalabs.fixture

            /** A fixture type linking [nonsenseLabel][kept] and [kept][noSuchTarget]. */
            class Fixture(val kept: String)
        """.trimIndent()

        /** (m) An external name and a member of one, neither of which this fixture declares. */
        private val LINK_FIXTURE_EXTERNAL = """
            package dev.eryalabs.fixture

            /** A fixture type linking [Alien] and [Alien.member]. */
            class Fixture(val kept: String)
        """.trimIndent()

        /**
         * (o) The vocabulary split: six links the *published* report cannot see, and one that
         * names nothing at all.
         */
        private val LINK_FIXTURE_VISIBILITY = """
            package dev.eryalabs.fixture

            /**
             * A fixture type linking [hiddenHelper], [hiddenOnly], [Invisible], [unpublished],
             * [toString], [HiddenFlow.OFF] and [nobodysName].
             *
             * The first six are private, internal or an override, and Dokka resolves every one
             * of them. The last names nothing.
             */
            class Fixture(val kept: String) {

                /** A private function, whose own name and whose parameter a link may name. */
                private fun hiddenHelper(hiddenOnly: String): Int = hiddenOnly.length

                override fun toString(): String = "Fixture"
            }

            /**
             * An internal type, which the published report also drops.
             *
             * @property unpublished Its one property.
             */
            internal class Invisible(val unpublished: String)

            /**
             * A private enum, whose constants no published report contains.
             *
             * Spelled one entry per line because that is what `ENUM_ENTRY` reads — it is anchored
             * at a line start, so `{ ON, OFF }` on one line yields no entries at all. Every enum
             * in the library is written this way; a review probe discovered the constraint by
             * writing this fixture the short way first.
             */
            private enum class HiddenFlow {

                ON,

                OFF,
            }
        """.trimIndent()

        /** (p) A guide example copied verbatim into a doc comment, fence and all. */
        private val LINK_FIXTURE_FENCED = """
            package dev.eryalabs.fixture

            /**
             * A fixture type whose example came out of the guide unaltered.
             *
             * ```kotlin
             * val account = accounts[verifiedKey]
             * ```
             */
            class Fenced(val kept: String)
        """.trimIndent()

        /** (p) The same subscript inside an inline backtick span. */
        private val LINK_FIXTURE_SPANNED = """
            package dev.eryalabs.fixture

            /** A fixture type whose prose mentions `accounts[verifiedKey]` in passing. */
            class Spanned(val kept: String)
        """.trimIndent()

        /** (p) The other direction: the same text as prose, where it *is* a link. */
        private val LINK_FIXTURE_UNFENCED = """
            package dev.eryalabs.fixture

            /**
             * A fixture type whose example lost its fence.
             *
             * val account = accounts[verifiedKey]
             */
            class Unfenced(val kept: String)
        """.trimIndent()

        /**
         * (p) A stray backtick in front of a real code span, with a dangling link between them.
         *
         * Pairing left to right blanks from the stray to the span's opening backtick, which is
         * exactly the text holding the link. Three backticks on the line, so the count is odd.
         */
        private val LINK_FIXTURE_STRAY_BACKTICK = """
            package dev.eryalabs.fixture

            /** A quote ` and [swallowed] before a `span` that closes. */
            class Stray(val kept: String)
        """.trimIndent()

        /** (q) Markdown's `[text](url)` form, whose text is prose and not a name. */
        private val LINK_FIXTURE_MARKDOWN = """
            package dev.eryalabs.fixture

            /** A fixture type pointing at [guide](../docs/INTEGRATION.md) for the whole flow. */
            class Linked(val kept: String)
        """.trimIndent()

        /** (q) The other direction: the same bracket with no URL after it, where it is a link. */
        private val LINK_FIXTURE_MARKDOWN_WITHOUT_URL = """
            package dev.eryalabs.fixture

            /** A fixture type pointing at [guide] for the whole flow. */
            class Linked(val kept: String)
        """.trimIndent()
    }
}
