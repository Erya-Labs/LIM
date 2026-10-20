package dev.eryalabs.lim

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.lang.reflect.Modifier

/**
 * **`CHANGELOG.md`, complete by construction.**
 *
 * A changelog is the one document whose failure mode is silence: it is right on the day it is
 * written and wrong from the first commit afterwards, and nothing about reading it says which. So
 * the file is checked in both directions against what the compiler actually produced.
 *
 *  - **Complete.** Every published function and constant on [Utils], every published type in
 *    `dev.eryalabs.lim`, and both published top-level members of `Redaction.kt` must be named in
 *    some `## ` section — the union of them all, `## Unreleased` included. A new public member
 *    reddens this file until somebody writes the line.
 *  - **Not stale.** Every `Utils.<member>` the file names must still be a member of [Utils], and
 *    every published name it cites in a code span must still exist. A changelog naming a member
 *    that was renamed is worse than one that is short: the short one is merely incomplete, the
 *    stale one sends an integrator looking for something that is not there.
 *
 * **What the census reaches, and what it does not.** It is the *published surface's* names:
 * `Utils`'s functions and constants, the top-level types, and `Redaction.kt`'s two. It is
 * deliberately not every member of every type — `Entry`'s properties, `FieldType`'s eight
 * constants, `StatementVerdict`'s seven verdicts and the `componentN`/`copy`/`CREATOR` members a
 * data class generates are described in the file as prose and pinned member-by-member by
 * `PublicApiAuditTest` and `LIM/api/lim.api`. Requiring a changelog line per generated accessor
 * would be noise, not coverage. What the stale direction *does* police is any such member the file
 * chooses to name: cite `Entry.publicKey` and it must exist.
 *
 * **The trap this file is written around is substring matching**, and it has a concrete instance
 * here rather than a hypothetical one: `PROTOCOL_VERSION` is a substring of
 * `EXTRA_PROTOCOL_VERSION`, so a naive `contains` would certify the constant as covered by a file
 * that only ever names the extra. Every name is matched on **word boundaries** by [mentions], and
 * `the matcher is not satisfied by a longer name that contains a shorter one` pins it with the
 * four near-misses this library actually has.
 *
 * **Where the census comes from.** [Utils]'s half is plain reflection, so a planted constant
 * reddens on the same run that compiles it. The type list and the cross-check come out of
 * `LIM/api/lim.api`, the checked-in baseline `ApiBaselineTest` already holds equal to reflection
 * member-for-member — which is why there is no third copy of that file's class enumerator here.
 * A new published type therefore reddens *something* either way: the baseline if it has not been
 * regenerated, this file once it has.
 *
 * No Robolectric: nothing here constructs an Android object, so the whole file is reflection over
 * names plus four text files.
 *
 * **A green run after editing only the changelog can now be trusted, and that is a change.**
 * `CHANGELOG.md` *is* a declared input of `:LIM:testDebugUnitTest` — `LIM/build.gradle.kts`
 * declares it, along with `LIM/api/lim.api` for `ApiBaselineTest` and `docs/INTEGRATION.md` for
 * `GuideSnippetTest`, and `BuildInputsTest` holds that declaration honest in both directions. So a
 * commit whose only change is to this document re-runs the suite, and the `--rerun` ritual this
 * paragraph used to demand is no longer needed.
 *
 * It *was* needed, and the paragraph that said so was right when it was written: before the
 * declaration existed, a run whose only change was to this document came back `UP-TO-DATE` without
 * executing anything — this test, a changelog edited to say something false, and a successful build
 * all at once. The residue of that hole is narrower and is still open: the suite also reads the
 * *main sources* as text, and the test task fingerprints those as compiled output, so a comment-only
 * edit to a main source can still leave the gate `UP-TO-DATE` with the rules that read it
 * unexecuted. That one is a decision about the Gradle cache, logged for a human rather than closed
 * here.
 */
class ChangelogTest {

    // ── Locating the files ────────────────────────────────────────────────

    /**
     * A repository file, by walking up from the working directory.
     *
     * The working directory of a Gradle unit test is the module directory, but that is a Gradle
     * default rather than a promise, so every ancestor is tried both as the module root and as the
     * repository root. A failure names every absolute path it tried: a changelog test that
     * silently found no changelog would pass for ever.
     */
    private fun locate(relative: String, complaint: () -> String): File {
        val workingDirectory = File(".").absoluteFile.normalize()
        val tried = mutableListOf<File>()
        var directory: File? = workingDirectory
        while (directory != null) {
            for (candidate in listOf(File(directory, relative), File(directory, "LIM/$relative"))) {
                tried += candidate
                if (candidate.isFile) return candidate
            }
            directory = directory.parentFile
        }
        throw AssertionError(
            complaint() + " Working directory: $workingDirectory. Tried:\n" +
                tried.map { it.absolutePath }.distinct().joinToString("\n"),
        )
    }

    private fun changelogFile(): File = locate(CHANGELOG_PATH) {
        "cannot find $CHANGELOG_PATH, so there is no changelog and nothing here means anything."
    }

    private fun baselineFile(): File = locate(BASELINE_RELATIVE) {
        "cannot find $BASELINE_PATH, which is where the published type list is read from."
    }

    private fun moduleBuildFile(): File = locate(MODULE_BUILD_FILE) {
        "cannot find the module's build.gradle.kts, so the version the changelog must head its " +
            "section with cannot be read from anywhere."
    }

    private fun redactionSource(): File = locate(REDACTION_SOURCE) {
        "cannot find Redaction.kt, whose two published top-level members are part of the census " +
            "and whose Kotlin visibility is not readable from the JVM surface."
    }

    // ── The published surface, measured ───────────────────────────────────

    /** Public, not synthetic, not a bridge — the same filter the audit uses, for the same reason. */
    private fun methodNames(type: Class<*>): Set<String> = type.declaredMethods
        .filter { Modifier.isPublic(it.modifiers) && !it.isSynthetic && !it.isBridge }
        .map { it.name }
        .toSet()

    private fun fieldNames(type: Class<*>): Set<String> = type.declaredFields
        .filter { Modifier.isPublic(it.modifiers) && !it.isSynthetic }
        .map { it.name }
        .toSet()

    /** The 38-odd distinct published function names on [Utils]. Overloads collapse to one name. */
    private fun utilsFunctions(): List<String> = methodNames(Utils::class.java).sorted()

    /**
     * [Utils]'s public `const val`s.
     *
     * `INSTANCE` is dropped: it is the handle the Kotlin compiler emits for an `object`, not a
     * constant anybody declared, and requiring a changelog bullet for it would be requiring a line
     * about the language rather than about this library. It stays in [utilsMembers], so the file
     * may still name `Utils.INSTANCE` where Java interop is the subject — which it does.
     */
    private fun utilsConstants(): List<String> =
        (fieldNames(Utils::class.java) - OBJECT_INSTANCE).sorted()

    /** Everything a `Utils.<name>` citation is allowed to resolve to, `INSTANCE` included. */
    private fun utilsMembers(): Set<String> =
        methodNames(Utils::class.java) + fieldNames(Utils::class.java)

    /**
     * One rendered `lim.api` line's owner: `dev.eryalabs.lim.Utils.shareEntry(…): boolean` →
     * `Utils`, and `public final class dev.eryalabs.lim.Entry: android.os.Parcelable` → `Entry`.
     *
     * A **member** line is matched on `<owner>.<member>` followed by `(` or `:` — the two
     * characters that can begin a parameter list or a type — rather than by stripping modifier
     * words, so that a *parameter* of type `dev.eryalabs.lim.Entry` cannot be mistaken for a
     * declaration: it is followed by `,` or `)`, and a return type by end of line.
     *
     * A **class-header** line is matched by its `class` keyword, and the care in [CLASS_OWNER] is
     * worth stating precisely rather than dramatically. A header names its supertypes, and a
     * sealed subclass's supertype is a type in this very package:
     * `public static final class dev.eryalabs.lim.SignedStatement$Rotate:
     * dev.eryalabs.lim.SignedStatement` mentions two of them. The obvious parser — scan the line
     * for the package prefix — gets the *right* answer on that line anyway, because `find` takes
     * the first match and the rendering always puts the declaration first. That is a property of
     * how `ApiBaselineTest` renders, not of the parser, and it is not what a census should rest
     * on: the keyword is the only token on the line that says which name is being declared.
     *
     * What the anchor is actually load-bearing for is that [CLASS_OWNER] **declines a member
     * line**, since [owner] consults it first. The naive prefix regex claims every line in the
     * file, which would quietly retire [OWNER] and with it the `<owner>.<member>` boundary that
     * keeps a *parameter* of type `dev.eryalabs.lim.Entry` from reading as a declaration.
     * `a class line's owner is its declared type and never one of its supertypes` asserts the
     * decline directly, which is the assertion that separates the two regexes.
     */
    private fun owner(line: String): String? =
        CLASS_OWNER.find(line)?.groupValues?.get(1) ?: OWNER.find(line)?.groupValues?.get(1)

    private fun baselineLines(): List<String> = baselineFile()
        .readLines()
        .map { it.trim() }
        .filter { it.isNotEmpty() && !it.startsWith("#") }

    /**
     * Every published top-level type in the package, read off the checked-in baseline.
     *
     * Nested owners (`Entry$Companion`, `SignedStatement$Rotate`) are not census entries of their
     * own: a changelog bullet per `Parcelable` creator would be noise. They remain reachable by
     * the stale direction, which resolves `SignedStatement.Rotate` as a class. The file facade
     * `RedactionKt` is dropped because it is not a type anybody can name — its two members are
     * census entries in their own right, via [redactionMembers].
     *
     * Both line shapes in the baseline name an owner and both are read, because the alternative
     * is not "ignore the class lines": the assertion below is that **every** non-comment line
     * names one, which is what stops a shape this parser has never seen from being skipped
     * silently while the census quietly shrinks. The two shapes agree on the type list — a class
     * with no visible member still has a header, and a member's owner still has one — so reading
     * both changes no census name, and that is checked by the whole file staying green rather
     * than asserted here.
     */
    private fun publishedTypes(): List<String> {
        val unreadable = baselineLines().filter { owner(it) == null }
        assertEquals(
            "these $BASELINE_PATH lines name no owner, so the published type list cannot be read " +
                "out of them",
            emptyList<String>(),
            unreadable,
        )
        return baselineLines()
            .mapNotNull { owner(it) }
            .filterNot { '$' in it }
            .filterNot { it == FILE_FACADE }
            .distinct()
            .sorted()
    }

    /**
     * `Redaction.kt`'s published top-level members, read from the **source**.
     *
     * The JVM cannot answer this one. A Kotlin `internal` top-level declaration compiles to a
     * `public static` member with no mangling, so `redactedValue` is indistinguishable from real
     * API by reflection — `PublicApiAuditTest` records exactly that, and calls it "JVM surface by
     * accident rather than API anybody was offered". Reading the modifier off the declaration is
     * the only way to tell, so that is what this does, with
     * `the Redaction.kt source and its compiled surface describe the same three declarations`
     * standing guard over the parse.
     */
    private fun redactionDeclarations(): List<Pair<String, String>> =
        TOP_LEVEL_DECLARATION.findAll(redactionSource().readText())
            .map { it.groupValues[1].ifEmpty { "public" } to it.groupValues[2] }
            .toList()

    private fun redactionMembers(): List<String> = redactionDeclarations()
        .filterNot { (visibility, _) -> visibility in NOT_PUBLISHED }
        .map { (_, name) -> name }
        .sorted()

    /** The whole census: the names the changelog's version sections have to contain. */
    private fun census(): List<String> =
        (utilsFunctions() + utilsConstants() + publishedTypes() + redactionMembers())
            .distinct()
            .sorted()

    // ── The changelog as text ─────────────────────────────────────────────

    /**
     * The release section's body: from the `##` heading that names the declared version to the
     * next `##` heading, or the end of the file.
     *
     * What still reads only this: the date-and-tag rule and `the release section is grouped by
     * flow`, which are claims about the version the build declares. The census and the lead check
     * read [everySection] instead — see there for why that was widened, and what it costs.
     */
    private fun releaseSection(): String = releaseSectionIn(changelogFile().readLines(), declaredVersion())

    /** [releaseSection] over any text, so the widening's control can run it over a fixture. */
    private fun releaseSectionIn(lines: List<String>, version: String): String {
        val start = lines.indexOfFirst { it.startsWith("## ") && mentions(it, version) }
        assertTrue(
            "no `## ` heading in $CHANGELOG_PATH names version $version, which is " +
                "what ${moduleBuildFile().absolutePath} declares in its coordinates(...) call",
            start >= 0,
        )
        val rest = lines.drop(start + 1)
        val end = rest.indexOfFirst { it.startsWith("## ") }
        return (if (end < 0) rest else rest.take(end)).joinToString("\n")
    }

    /**
     * The body of **every** `## ` section, joined — what the census and the lead check read.
     *
     * **A declared widening, and the reason is mechanical rather than a preference.** Until the
     * required-fields work, both read [releaseSection] alone, which is the section named by the
     * build's `coordinates(...)` version. A member added after a release has nowhere to be
     * described there: the declared version's section is the *released* one, a dated record of
     * what shipped, and it must not grow a bullet for something that did not ship in it. Bumping
     * the coordinates instead would not help either, because the new version's section would
     * then have to repeat every name the old one already describes. So new members go under a
     * `## Unreleased` heading, and the two checks read the union.
     *
     * **What that costs, recorded rather than implied.** A name can now satisfy the census or
     * lead a bullet in *any* version's section, so "the current section describes it" has become
     * "some section describes it". The preamble is still excluded — a name mentioned only there
     * is mentioned without being described — and the per-version claims, the date-and-tag rule
     * and the grouping check, still read the declared version's section alone.
     * `a name present only in an Unreleased section is found by the census` is the control.
     *
     * Joined with a blank line between sections, so the last bullet of one cannot swallow the
     * first line of the next as a continuation.
     */
    private fun everySection(): String = sectionsIn(changelogFile().readLines())

    /** [everySection] over any text. */
    private fun sectionsIn(lines: List<String>): String {
        val bodies = mutableListOf<String>()
        var current: MutableList<String>? = null
        for (line in lines) {
            if (line.startsWith("## ")) {
                current?.let { bodies += it.joinToString("\n") }
                current = mutableListOf()
            } else {
                current?.add(line)
            }
        }
        current?.let { bodies += it.joinToString("\n") }
        return bodies.joinToString("\n\n")
    }

    /** The `##` headings, which is where a version lives; `###` group headings are not these. */
    private fun versionHeadings(): List<String> = changelogFile()
        .readLines()
        .filter { it.startsWith("## ") }

    /** The version out of the module's own `coordinates(group, artifact, version)` call. */
    private fun declaredVersion(): String {
        val declared = COORDINATES.findAll(moduleBuildFile().readText()).toList()
        assertEquals(
            "expected exactly one `coordinates(group, artifact, version)` call in " +
                "${moduleBuildFile().absolutePath}; the version the changelog heads its section " +
                "with is read out of it",
            1,
            declared.size,
        )
        return declared.single().groupValues[3]
    }

    /**
     * Whether [text] names [name] — on **word boundaries**, never as a substring.
     *
     * This is the whole mechanism of the completeness check, and getting it wrong would make every
     * assertion above weaker than it reads. `PROTOCOL_VERSION` sits inside
     * `EXTRA_PROTOCOL_VERSION`, `Entry` inside `decodeEntry`, `Revocation` inside
     * `encodeRevocation`, `EXTRA_NONCE` inside `EXTRA_NONCE_FORMAT`: a `contains` would report all
     * four as covered by a file that names only the longer one. `\b` sees `_` as a word character,
     * which is exactly what makes the first and fourth pairs distinguishable, and it sees `.` and
     * `` ` `` as boundaries, so `Utils.PROTOCOL_VERSION` in a code span still counts.
     */
    private fun mentions(text: String, name: String): Boolean =
        Regex("""\b""" + Regex.escape(name) + """\b""").containsMatchIn(text)

    // ── Completeness ──────────────────────────────────────────────────────

    @Test
    fun `every published name is described in the changelog`() {
        val section = everySection()
        val census = census()
        val missing = census.filterNot { mentions(section, it) }

        assertEquals(
            "these published names appear in no `## ` section of $CHANGELOG_PATH — not the " +
                "${declaredVersion()} one and not `## Unreleased`, which is where a member added " +
                "since that release belongs. A changelog that omits a member is a changelog an integrator cannot " +
                "use to find it — write the line; do not shorten this census. Names are matched " +
                "on word boundaries, so mentioning EXTRA_PROTOCOL_VERSION does not cover " +
                "PROTOCOL_VERSION. The file to edit is ${changelogFile().absolutePath}",
            emptyList<String>(),
            missing,
        )
    }

    @Test
    fun `the census covers a whole surface rather than a corner of one`() {
        val functions = utilsFunctions()
        val constants = utilsConstants()
        val types = publishedTypes()
        val redaction = redactionMembers()
        val census = census()
        val matched = census.count { mentions(everySection(), it) }

        println(
            "CHANGELOG.md: ${census.size} census names matched $matched times over " +
                "${functions.size} Utils functions, ${constants.size} Utils constants, " +
                "${types.size} published types and ${redaction.size} Redaction.kt members",
        )

        assertTrue(
            "expected at least $MINIMUM_CENSUS published names in the census; found " +
                "${census.size}. A census that found nothing would make every assertion in this " +
                "file pass over an empty list",
            census.size >= MINIMUM_CENSUS,
        )
        assertTrue(
            "expected at least $MINIMUM_CENSUS of them matched in the changelog; found $matched",
            matched >= MINIMUM_CENSUS,
        )
        assertEquals(
            "every census name must be matched, or the completeness test above is reporting " +
                "something this count disagrees with",
            census.size,
            matched,
        )
        // Each measured half non-empty in its own right: one reflection filter or one text parse
        // returning nothing would otherwise hide inside a total that is still over the floor.
        assertTrue("no published functions found on Utils", functions.size >= 30)
        assertTrue("no published constants found on Utils", constants.size >= 15)
        assertTrue("no published types found in $BASELINE_PATH", types.size >= 12)
        assertEquals(
            "Redaction.kt publishes previewedPublicKey and PUBLIC_KEY_PREVIEW_CHARS and nothing " +
                "else; redactedValue is `internal` and is JVM surface by accident",
            listOf("PUBLIC_KEY_PREVIEW_CHARS", "previewedPublicKey"),
            redaction,
        )
    }

    /**
     * The two sources the census is assembled from must agree about [Utils].
     *
     * The type list is read out of `LIM/api/lim.api` rather than by keeping a third copy of that
     * file's class enumerator, which is only sound while the baseline is in step with the
     * compiler. `ApiBaselineTest` is what holds it so; this is the cheap independent confirmation,
     * on the one class whose members this file measures both ways, so that a stale baseline cannot
     * quietly shrink the census here.
     */
    @Test
    fun `the baseline and reflection agree about Utils`() {
        val fromBaseline = baselineLines()
            .filter { owner(it) == "Utils" }
            .mapNotNull { OWNER.find(it)?.groupValues?.get(2) }
            // `$default` and any `access$` member is a compiler artifact: public and static, but
            // also synthetic, so reflection's filter above drops every one of them.
            .filterNot { '$' in it }
            .toSet()

        assertEquals(
            "$BASELINE_PATH and reflection disagree about Utils's members, so the published type " +
                "list this file reads out of that baseline cannot be trusted either. Regenerate " +
                "it — ./gradlew :LIM:testDebugUnitTest --tests '*ApiBaselineTest'",
            utilsMembers().toSortedSet().toSet(),
            fromBaseline.toSortedSet().toSet(),
        )
    }

    @Test
    fun `the Redaction_kt source and its compiled surface describe the same three declarations`() {
        val facade = Class.forName("$PACKAGE.$FILE_FACADE", false, javaClass.classLoader)
        val compiled = methodNames(facade) + fieldNames(facade)
        val declared = redactionDeclarations().map { (_, name) -> name }

        assertEquals(
            "the top-level declarations parsed out of ${redactionSource().absolutePath} are not " +
                "the members the compiler emitted for $FILE_FACADE. A declaration the parser " +
                "missed would be silently absent from the census — and if it is `internal`, " +
                "nothing else in this file could tell",
            compiled.toSortedSet().toList(),
            declared.toSortedSet().toList(),
        )
    }

    // ── The stale direction ───────────────────────────────────────────────

    /**
     * The qualified spelling, wherever the document uses it.
     *
     * **Its reach is small, and saying so is the point.** This changelog cites members bare — one
     * code span per name — and writes `Utils.` in front of one of them, so this test covers that
     * one reference and nothing else. It is here because a qualified citation is the shape a
     * *future* edit is most likely to arrive in, and because `Utils.nope` must be reported rather
     * than read as prose. The check with teeth over this document as written is
     * `every name the changelog leads a bullet with is a published name`, which reads the bare
     * citations; this one is not a substitute for it.
     */
    @Test
    fun `every Utils member the changelog names still exists`() {
        val members = utilsMembers()
        val cited = UTILS_CITATION.findAll(changelogFile().readText())
            .map { it.groupValues[1] }
            .toSortedSet()
        val unknown = cited.filterNot { it in members }

        assertTrue(
            "the changelog uses no `Utils.<name>` spelling at all, so this check is reading an " +
                "empty list. That is not necessarily wrong — the bare citations are covered " +
                "elsewhere — but it means this test is asserting nothing, so it should be " +
                "deleted rather than left looking like coverage",
            cited.isNotEmpty(),
        )
        assertEquals(
            "$CHANGELOG_PATH names these as members of Utils and reflection cannot find them. A " +
                "changelog naming a renamed or deleted member is worse than one that is short: " +
                "fix the file, and if the member really was removed, that is stop rule 10 and " +
                "the code is what to look at. Members found: ${members.toSortedSet()}",
            emptyList<String>(),
            unknown,
        )
    }

    /**
     * **Every name the changelog cites in a code span must resolve — prose included.**
     *
     * Every span, not only the upper-case ones. An earlier round of this file checked only spans
     * beginning with a capital, on the grounds that a lowercase span is usually a parameter or
     * somebody else's method and that policing them would need an allow-list of the whole Android
     * and Kotlin vocabulary. That turned out to be the wrong trade: **every one of the 38
     * function names this changelog exists to document is lowercase**, so the bound excluded
     * exactly the names most likely to be renamed. The allow-list it was meant to avoid,
     * [NOT_A_PUBLISHED_NAME], stayed short — it holds the foreign names this document actually
     * cites and nothing else — because [resolves]'s bare-name rung accepts a Kotlin property
     * through its generated accessor, and most parameter names are property names.
     *
     * Spans that are not a single dotted identifier are prose, not citations, and are not checked:
     * `Map<String, TypedField>`, `putExtra(key, null as String?)`, `"a quoted literal"`,
     * `docs/INTEGRATION.md`. Nor is a source file name — `Redaction.kt` is where two members live,
     * not a member.
     */
    @Test
    fun `every published name the changelog cites in a code span resolves`() {
        val spans = citations(changelogFile().readText())

        val unresolved = spans
            .filterNot { it in NOT_A_PUBLISHED_NAME }
            .filterNot { resolves(it) }

        println("CHANGELOG.md: ${spans.size} code-span citations checked: $spans")
        assertTrue(
            "the changelog cites no published name in a code span, so this check is passing over " +
                "an empty list; ${spans.size} found, $MINIMUM_SPANS expected",
            spans.size >= MINIMUM_SPANS,
        )
        assertEquals(
            "$CHANGELOG_PATH cites these and nothing in dev.eryalabs.lim answers to them. Either " +
                "the name is stale — fix the changelog — or it belongs to Android, the JDK, " +
                "Gson or Gradle, in which case record it in NOT_A_PUBLISHED_NAME with the " +
                "reason. ${spans.size} citations checked",
            emptyList<String>(),
            unresolved,
        )
    }

    /** The single-dotted-identifier code spans of [text] — its citations, as against its prose. */
    private fun citations(text: String): Set<String> = CODE_SPAN.findAll(text)
        .map { it.groupValues[1] }
        .filter { DOTTED_NAME.matches(it) }
        .filterNot { FILE_NAME.matches(it) }
        .toSortedSet()

    /**
     * **Every published function leads a bullet, and every bullet lead resolves.**
     *
     * *Leads a bullet*, not *leads a bullet of its own*: the document's convention is one bullet
     * per member **or group of members** — ``- `a`, `b` and `c` — what they do`` — and a good
     * many of its bullets rely on that, the widest being the four-name
     * `encodeRotationStatement`…`parseSignedStatement` one. What matters is that the name sits in
     * a lead rather than in prose. (No count here on purpose: a hand-maintained tally of how many
     * bullets share a lead is a number that is wrong the next time somebody groups two.)
     *
     * The check above answers "is anything the document says stale". This one answers the question
     * underneath it — *is the document still a list of the members it claims to describe* — and it
     * is the structural guarantee that makes the stale direction worth anything.
     *
     * Two assertions, and the first is the load-bearing one:
     *
     *  - **Every one of [utilsFunctions] appears in some bullet's lead.** Without it the
     *    completeness check could be satisfied by a name buried in a paragraph, and this test's own
     *    assertion could be satisfied by a document that led no bullets with anything.
     *  - **Every bullet lead resolves.** That is the shape a rename leaves behind: completeness
     *    reddens naming the *new* name, the cheapest fix is to add a bullet, and the old bullet
     *    stays. Completeness cannot see it — it only asks what is missing — and the task that
     *    commissioned this file says a changelog naming a renamed member is worse than a short one.
     *
     * **A lead is what precedes a bullet's em dash, so a bullet without one has no lead at all**
     * and is skipped. That is not pedantry about punctuation: `substringBefore` returns the whole
     * string when its delimiter is absent, so counting those bullets would donate their entire
     * prose body to the lead set — and a function named only in such a bullet's prose would
     * satisfy the first assertion above, which is precisely the hole it exists to close. The
     * document has one em-dash-less citation bullet, under "Not in this release".
     *
     * Bullets are **joined from their continuation lines** before the em dash is looked for. A
     * line-oriented version of this read only a bullet's first physical line, which silently
     * excluded `parseSignedStatement` — the one citation in this document that wraps — and that is
     * precisely the kind of name this test is for. They are read out of [everySection] rather than
     * the whole file, so the preamble can lead nothing — and out of every section rather than
     * [releaseSection] alone since the required-fields work, a declared widening whose reason and
     * cost [everySection] records: a function added after a release leads a bullet under
     * `## Unreleased`, and a function may now satisfy this from a historical entry while the
     * current one only mentions it in passing.
     */
    @Test
    fun `every published function leads a bullet that still resolves`() {
        val leads = leads(everySection())
        val cited = citations(leads.joinToString("\n"))

        println("CHANGELOG.md: ${leads.size} bullet leads citing ${cited.size} names: $cited")
        assertEquals(
            "these published functions lead no bullet in any `## ` section of $CHANGELOG_PATH. Being " +
                "mentioned somewhere in it is not enough: a name in a paragraph cannot be told " +
                "from prose, so it is the one shape the stale direction below cannot police. " +
                "Give each a lead — ``- `name` — what it does`` — alone or beside its siblings",
            emptyList<String>(),
            utilsFunctions().filterNot { it in cited },
        )
        assertEquals(
            "$CHANGELOG_PATH leads a bullet with each of these and nothing in dev.eryalabs.lim " +
                "answers to it. This is the shape a renamed member leaves behind: the new name " +
                "satisfies the completeness check while the bullet for the old one stays. Fix " +
                "the changelog — and if the member really was removed, that is stop rule 10 and " +
                "the code is what to look at. A foreign name leading a bullet belongs in " +
                "NOT_A_PUBLISHED_NAME, same as in the check above",
            emptyList<String>(),
            cited.filterNot { it in NOT_A_PUBLISHED_NAME }.filterNot { resolves(it) },
        )
    }

    /**
     * The lead of every citation bullet in [text]: what precedes the em dash of a list item that
     * opens with a code span.
     *
     * A bullet with no em dash has no lead and is dropped whole, rather than contributing
     * `substringBefore`'s fallback — which is the entire string. `a name in a bullet's prose is
     * not a lead` is the fixture for all three of those rules.
     */
    private fun leads(text: String): List<String> = bullets(text)
        .filter { BULLET_CITATION.containsMatchIn(it) && EM_DASH in it }
        .map { it.substringBefore(EM_DASH) }

    /**
     * [text]'s list items, each joined from the continuation lines that belong to it.
     *
     * A continuation is an indented non-blank line that does not itself open a list item; a blank
     * line, a heading or an unindented paragraph ends the run. It is the difference between
     * reading a bullet and reading a bullet's first line — see
     * `every published function leads a bullet that still resolves`. An *unindented* wrap, which
     * markdown would also fold into the item, is not joined — and that fails safe: the wrapped
     * name drops out of the lead set and reddens rather than slipping through.
     */
    private fun bullets(text: String): List<String> {
        val bullets = mutableListOf<String>()
        var current: StringBuilder? = null
        for (line in text.lines()) {
            when {
                BULLET_START.containsMatchIn(line) -> {
                    current?.let { bullets += it.toString() }
                    current = StringBuilder(line.trim())
                }

                current != null && line.isNotBlank() && line.first().isWhitespace() ->
                    current.append(' ').append(line.trim())

                else -> {
                    current?.let { bullets += it.toString() }
                    current = null
                }
            }
        }
        current?.let { bullets += it.toString() }
        return bullets
    }

    /**
     * The resolution ladder, in the order a citation is most cheaply recognised: a published
     * constant, a published class, a bare member name, then `Type.member`.
     *
     * **Classes are resolved against the baseline's owners, not against the classloader**, and
     * that is load-bearing rather than fussy. `Class.forName` at test time sees this package's 41
     * *test* classes too, so a ladder built on it certified `ChangelogTest` and
     * `PublicApiAuditTest` as "published names that still exist" — and would have certified a
     * bullet led by `ThreadSafetyTest`. The baseline records only what ships.
     *
     * The bare-member rung is what makes a lowercase citation checkable at all — `shareEntry`
     * names no class and is not a constant — and it accepts a Kotlin **property** name through the
     * accessor the compiler generated for it, so `publicKey` resolves via `getPublicKey` and
     * `isVerified` via itself. It is a union across the published types rather than a per-owner
     * lookup: a changelog bullet does not say which class it is about, and `getFields` being
     * published on four of them is not a distinction a reader needs made here.
     */
    private fun resolves(name: String): Boolean {
        if (name in constantNames()) return true
        if (publishedClass(name) != null) return true
        if (isMemberName(name)) return true
        val type = publishedClass(name.substringBeforeLast('.', "")) ?: return false
        return declaresMember(type, name.substringAfterLast('.'))
    }

    /** [name] as a class, only if the baseline records it as an owner of a published member. */
    private fun publishedClass(name: String): Class<*>? {
        if (name.replace('.', '$') !in baselineOwners()) return null
        return loadClass(name)
    }

    /** Every owner the baseline records, in the JVM's `Outer$Nested` spelling. */
    private fun baselineOwners(): Set<String> = baselineLines().mapNotNull { owner(it) }.toSet()

    private fun isMemberName(name: String): Boolean {
        val members = memberNames()
        if (name in members) return true
        val capitalized = name.replaceFirstChar { it.uppercaseChar() }
        return "get$capitalized" in members || "is$capitalized" in members
    }

    /**
     * Every published member name of every class the baseline records an owner for — **minus the
     * file facade's members that Kotlin does not publish.**
     *
     * That subtraction is not tidying. `RedactionKt.redactedValue` is `internal` in Kotlin and
     * `public static` on the JVM, so the baseline records it and reflection finds it; this same
     * file asserts a few tests up that it is "JVM surface by accident rather than API anybody was
     * offered". Leaving it in here would let a bullet led by `redactedValue` pass as a published
     * citation while the census refused to count it — one file disagreeing with itself about the
     * one name whose two answers differ.
     */
    private fun memberNames(): Set<String> = baselineLines()
        .mapNotNull { owner(it) }
        .distinct()
        .mapNotNull { simple -> loadClass(simple.replace('$', '.'))?.let { simple to it } }
        .flatMap { (simple, type) ->
            val names = methodNames(type) + fieldNames(type)
            if (simple == FILE_FACADE) names.filter { it in redactionMembers() } else names
        }
        .toSet()

    /** `Entry`, or `SignedStatement.Rotate`, as the JVM spells it. Never initialised. */
    private fun loadClass(name: String): Class<*>? {
        if (name.isEmpty()) return null
        return runCatching {
            Class.forName("$PACKAGE.${name.replace('.', '$')}", false, javaClass.classLoader)
        }.getOrNull()
    }

    /**
     * Published constants anywhere a changelog would cite one bare: [Utils]'s extras and protocol
     * version, [FieldType]'s datatype names, [StatementVerdict]'s verdicts, and
     * `PUBLIC_KEY_PREVIEW_CHARS`.
     */
    private fun constantNames(): Set<String> = CONSTANT_HOLDERS
        .mapNotNull { loadClass(it) }
        .flatMap { fieldNames(it) }
        .toSet()

    /** A member of [type], accepting the JVM accessor name a Kotlin property compiles to. */
    private fun declaresMember(type: Class<*>, name: String): Boolean {
        val members = methodNames(type) + fieldNames(type)
        if (name in members) return true
        val capitalized = name.replaceFirstChar { it.uppercaseChar() }
        return "get$capitalized" in members || "is$capitalized" in members
    }

    // ── The version heading, and what it may claim ──────────────────────────────

    /**
     * The heading carries the version the build declares, and its date says whether that version
     * was actually released - decided by the one record of a release this repository keeps: a git
     * tag of that version.
     *
     * **What this replaced, and why it is not the old assertion flipped.** Until 1.0.0 shipped, this
     * asserted `unreleased` as literal text and forbade a date, because nothing here could publish
     * and a dated heading would be a release nobody cut. Its KDoc said that when a human cut the
     * release, *this assertion was the thing to change*. 1.0.0 was published to Maven Central on
     * 2026-10-10. Flipping it to "must carry a date" would have been true for exactly one version:
     * as soon as the build declared 1.0.1, its new heading would have been required to carry a date
     * for a release nobody had cut - the very hazard the original assertion existed to prevent.
     *
     * So the rule is stated against the repository instead: a heading is dated **exactly when** a
     * tag of its version exists, and says `unreleased` exactly when one does not. Never both, never
     * neither.
     *
     * **One exception: the tagged commit itself.** A release is tagged at the commit that declares
     * it, and the release date is only known once Maven Central records it, so that commit's
     * heading still says `unreleased`, as 1.0.0's did. Its tests then run a second time, at publish,
     * from a checkout of the tag, where the tag already exists. Without the exception the rule
     * fails the very commit being released, and the release script refuses to stage it. So
     * `unreleased` is still allowed while HEAD *is* the tagged commit; every commit after it must
     * carry the date. Where git cannot say what the tag points at, the date is required.
     *
     * **Asked of git, not read out of `.git/`.** Tags may be loose files or packed into one file,
     * and in a worktree `.git` is itself a file pointing elsewhere; git resolves all of that. It is
     * not declared as a Gradle input for the same reason - no `.git` path is stable across clones and
     * worktrees. The cost is bounded: adding a tag alone does not invalidate this test's cached
     * result, but a release also edits this file, which does. Where git cannot be asked at all - no
     * binary, or a source tarball - only the never-both / never-neither half is checked, and the
     * control below reports itself skipped rather than passing silently.
     */
    @Test
    fun `the release section is dated exactly when its version has been tagged`() {
        val version = declaredVersion()
        val naming = versionHeadings().filter { mentions(it, version) }

        assertEquals(
            "expected exactly one `## ` heading in $CHANGELOG_PATH naming version $version, the " +
                "one ${moduleBuildFile().absolutePath} declares. Found: ${versionHeadings()}",
            1,
            naming.size,
        )
        val heading = naming.single()
        val dated = ISO_DATE.containsMatchIn(heading)
        val unreleased = UNRELEASED in heading
        assertTrue(
            "the heading must not be both dated and `$UNRELEASED`. Found: \"$heading\"",
            !(dated && unreleased),
        )
        assertTrue(
            "the heading must be either dated or `$UNRELEASED`. Found: \"$heading\"",
            dated || unreleased,
        )
        when (tagExists(version)) {
            true -> if (tagIsHead(version) != true) assertTrue(
                "git tag $version exists, so $version was released: its heading must carry the " +
                    "release date, not `$UNRELEASED`. Found: \"$heading\"",
                dated,
            )
            false -> assertTrue(
                "there is no git tag $version, so $version has not been released: its heading " +
                    "must say `$UNRELEASED` and carry no date. Found: \"$heading\"",
                unreleased,
            )
            null -> Unit // git could not be asked; the control below reports that.
        }
    }

    /**
     * The control for the arm above: the tag query answers, both ways, against tags this repository
     * is known to hold. Without it, a query that silently answered "no tag" for everything would turn
     * a released heading into a demand for `unreleased` - and pass every unreleased one for free.
     *
     * Skipped rather than failed where git cannot be asked.
     */
    @Test
    fun `the tag query finds known tags and not an invented one`() {
        val first = tagExists("0.1.0")
        org.junit.Assume.assumeTrue("git cannot be asked here, so the tag rule is unchecked", first != null)
        assertEquals("tag 0.1.0 must be found", true, first)
        assertEquals("tag 1.0.0 must be found", true, tagExists("1.0.0"))
        assertEquals("an invented tag must not be found", false, tagExists("0.0.0-never-tagged"))
        // The exception's query must not answer "this is the tagged commit" for a tag far behind
        // HEAD, or for no tag at all: either would excuse every undated heading.
        assertEquals("tag 0.1.0 is not HEAD", false, tagIsHead("0.1.0"))
        assertEquals("an invented tag is not HEAD", null, tagIsHead("0.0.0-never-tagged"))
    }

    /**
     * Whether the tag named exactly [name] points at the commit checked out (HEAD), or null when git
     * cannot say: no such tag, or no git at all.
     */
    private fun tagIsHead(name: String): Boolean? {
        val tagged = gitCommit("refs/tags/$name^{commit}") ?: return null
        val head = gitCommit("HEAD") ?: return null
        return tagged == head
    }

    /** The full commit id git resolves [rev] to, or null when it cannot. */
    private fun gitCommit(rev: String): String? = try {
        val process = ProcessBuilder("git", "rev-parse", "--verify", "--quiet", rev)
            .directory(changelogFile().absoluteFile.parentFile)
            .start()
        val output = process.inputStream.bufferedReader().readText().trim()
        if (process.waitFor() != 0 || output.isEmpty()) null else output
    } catch (e: java.io.IOException) {
        null
    }

    /**
     * Whether a git tag named exactly [name] exists in this repository, or null when git cannot be
     * asked. `git tag --list` takes a pattern, so its output is compared line by line rather than
     * trusted as a yes or no.
     */
    private fun tagExists(name: String): Boolean? = try {
        val process = ProcessBuilder("git", "tag", "--list", name)
            .directory(changelogFile().absoluteFile.parentFile)
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().readText()
        if (process.waitFor() != 0) null else output.lineSequence().any { it.trim() == name }
    } catch (e: java.io.IOException) {
        null
    }

    /**
     * The entry that describes the whole surface is grouped by flow, and each group is present.
     *
     * That entry is [FULL_SURFACE_VERSION]'s. It had no earlier release to diff against, so it
     * describes everything, and a flow missing from it is a part of the library nobody wrote down.
     * Every later entry is an ordinary list of what changed, as the preamble says: 1.1.1 touches
     * sign-up alone, and demanding a Query or Diagnostics heading of it would only breed empty ones.
     * Until the release after 1.0.0, this check read the declared version's section, which was
     * the same entry.
     *
     * Presence only, in no particular order: this file pins *coverage*, not arrangement. Reordering
     * the sections reddens nothing, and an assertion that fought every future edit to the document
     * would be worse than none.
     */
    @Test
    fun `the release section is grouped by flow`() {
        // Read out of that entry's section rather than out of the whole file: headings belonging
        // to any other version must not satisfy this one's claim.
        val groups = releaseSectionIn(changelogFile().readLines(), FULL_SURFACE_VERSION)
            .lines().filter { it.startsWith("### ") }
        val absent = REQUIRED_GROUPS.filterNot { required ->
            groups.any { required in it }
        }

        assertEquals(
            "the $FULL_SURFACE_VERSION section must group the surface by flow; these groups have " +
                "no `### ` heading. Found: $groups",
            emptyList<String>(),
            absent,
        )
    }

    // ── Controls on the matcher ───────────────────────────────────────────

    /**
     * [leads] and [bullets], on markdown written to exercise them rather than on the document.
     *
     * The real document cannot test these: it has one em-dash-less citation bullet and that bullet
     * cites only `EXTRA_ALGORITHM`, which resolves — so deleting the `EM_DASH in it` guard today
     * would leave every assertion in this file green while the rule it enforces was gone. A
     * fixture closes that. Four rules, one text:
     *
     *  - a name after the em dash is prose, not a lead;
     *  - a bullet with **no** em dash has no lead and contributes nothing — not its whole body,
     *    which is what `substringBefore` would otherwise hand over;
     *  - a lead that wraps onto an indented line is read whole;
     *  - a bullet that does not open with a code span is a prose bullet and is skipped.
     */
    @Test
    fun `a name in a bullet's prose is not a lead`() {
        val fixture = listOf(
            "- `leadName` — prose that also names `prosePeer` after the dash.",
            "- `noDashLead` is a bullet with no em dash, naming `hiddenInBody` in its body.",
            "- `wrappedOne`, `wrappedTwo` and",
            "  `wrappedThree` — a lead continued onto a second line.",
            // An em dash *and* a code span before it, both deliberate: with no em dash the guard
            // above would drop this bullet and the opens-with-a-code-span rule would never be the
            // thing deciding, which is a fixture that reads as coverage without being any.
            "- a prose bullet naming `neverALead` — and nothing else.",
            "",
            "Closing paragraph, naming `notInAnyBullet`.",
        ).joinToString("\n")

        assertEquals(
            "a lead is what precedes the em dash of a bullet that opens with a code span: a prose " +
                "name, an em-dash-less bullet's whole body, a prose bullet's own span and a " +
                "paragraph must all stay out of it",
            setOf("leadName", "wrappedOne", "wrappedTwo", "wrappedThree"),
            citations(leads(fixture).joinToString("\n")).toSet(),
        )
        // The joining itself, asserted as the exact list rather than as a count: four items is
        // also what a `bullets` that dropped continuation lines entirely would report, so the
        // count alone would not notice losing the third item's second line.
        assertEquals(
            "a bullet is its first line plus the indented lines that continue it, and a " +
                "paragraph after a blank line is not one",
            listOf(
                "- `leadName` — prose that also names `prosePeer` after the dash.",
                "- `noDashLead` is a bullet with no em dash, naming `hiddenInBody` in its body.",
                "- `wrappedOne`, `wrappedTwo` and `wrappedThree` — a lead continued onto a " +
                    "second line.",
                "- a prose bullet naming `neverALead` — and nothing else.",
            ),
            bullets(fixture),
        )
    }

    /**
     * The control for [everySection]'s widening: a name described only under `## Unreleased` is
     * found by the census and leads a bullet, a name only in the preamble is found by neither, and
     * the declared version's own section — what the date-and-tag rule and the grouping check still
     * read — does not see the Unreleased name at all.
     *
     * The last half is what keeps the widening from being a quiet replacement of [releaseSection]:
     * if [everySection] had simply become the whole file, or [releaseSectionIn] had started
     * reading past the next heading, one of the three would fail.
     */
    @Test
    fun `a name present only in an Unreleased section is found by the census`() {
        val fixture = listOf(
            "# Changelog",
            "",
            "A preamble naming `preambleOnly`, which no section describes.",
            "",
            "## Unreleased",
            "",
            "### Share",
            "",
            "- `unreleasedOnly` — added after the last release.",
            "## 1.0.0 — 2026-10-10",
            "",
            "- `releasedName` — what shipped.",
        )

        val every = sectionsIn(fixture)
        assertTrue("an Unreleased-only name must be found", mentions(every, "unreleasedOnly"))
        assertTrue("…and so must a released one", mentions(every, "releasedName"))
        assertFalse("a preamble-only name must not be", mentions(every, "preambleOnly"))
        assertEquals(
            "the lead check reads the same union, and only bullet leads count",
            setOf("unreleasedOnly", "releasedName"),
            citations(leads(every).joinToString("\n")).toSet(),
        )

        val released = releaseSectionIn(fixture, "1.0.0")
        assertTrue("the declared version's section still holds its own", mentions(released, "releasedName"))
        assertFalse(
            "…and nothing from Unreleased: the per-version checks are not widened",
            mentions(released, "unreleasedOnly"),
        )
        // The other order: an Unreleased section *after* the released one must stop it, too.
        val releasedFirst = listOf(
            "## 1.0.0 — 2026-10-10",
            "- `releasedName` — what shipped.",
            "## Unreleased",
            "- `unreleasedOnly` — added after the last release.",
        )
        assertFalse(
            "a section ends at the next `## ` heading, whichever order the two come in",
            mentions(releaseSectionIn(releasedFirst, "1.0.0"), "unreleasedOnly"),
        )
        assertTrue(mentions(sectionsIn(releasedFirst), "unreleasedOnly"))
    }

    /**
     * The substring trap, as a fixture, because it needs no plant to demonstrate and because it is
     * the mechanism every other assertion here rests on.
     *
     * All four pairs are real names in this library, not invented ones: three of them are the
     * near-misses named in the task that asked for this file, and the fourth —
     * `EXTRA_NONCE`/`EXTRA_NONCE_FORMAT` — is the one a `contains` would get wrong *in the same
     * direction* for a reason an author would not notice, since the shorter name is a genuine
     * prefix of the longer.
     */
    @Test
    fun `the matcher is not satisfied by a longer name that contains a shorter one`() {
        val pairs = listOf(
            "PROTOCOL_VERSION" to "EXTRA_PROTOCOL_VERSION",
            "EXTRA_NONCE" to "EXTRA_NONCE_FORMAT",
            "Entry" to "decodeEntry",
            "Revocation" to "encodeRevocation",
        )

        for ((shorter, longer) in pairs) {
            val onlyTheLonger = "A changelog that names `$longer` and nothing else."
            assertTrue(
                "the fixture is pointless unless `$shorter` really is a substring of `$longer`",
                shorter in longer,
            )
            assertTrue(
                "`$longer` must be reported as mentioned in its own text",
                mentions(onlyTheLonger, longer),
            )
            assertTrue(
                "`$longer` must NOT cover `$shorter` — that is the substring match this file " +
                    "exists to avoid, and a changelog naming only the longer name would " +
                    "otherwise certify coverage it does not have",
                !mentions(onlyTheLonger, shorter),
            )
        }

        // And the boundary is not so strict that a real citation stops counting: a code span, a
        // dotted reference and a sentence-final name all have to match.
        for (text in listOf("`PROTOCOL_VERSION`", "`Utils.PROTOCOL_VERSION` = 2", "named PROTOCOL_VERSION.")) {
            assertTrue(
                "PROTOCOL_VERSION must be found in \"$text\", or the completeness check is " +
                    "stricter than the document it reads",
                mentions(text, "PROTOCOL_VERSION"),
            )
        }
    }

    /**
     * [owner] reads a declaration out of both `lim.api` shapes, and [CLASS_OWNER] reads one out
     * of the class shape only.
     *
     * The last assertion is the one that discriminates, and it is worth being plain about why the
     * others do not. Every fixture here is a verbatim `lim.api` line; the second mentions
     * `dev.eryalabs.lim.SignedStatement` as a supertype and the third names `Parceler` from
     * outside the package — and a naive `Regex("""\bdev\.eryalabs\.lim\.([A-Za-z0-9_$]+)""")`
     * substituted for [CLASS_OWNER] would still answer all three correctly, because `find`
     * returns the first match and the declaration is always rendered first. So those three pin
     * the *answers* and would survive the wrong parser.
     *
     * `assertNull` on the member line is what does not. The naive regex matches a member line too
     * — `owner` consults [CLASS_OWNER] first, so it would return from there and [OWNER], the
     * regex carrying the `<owner>.<member>` boundary, would never run again for any line in the
     * file. That is the mistake the keyword anchor exists to prevent, so that is the assertion
     * that has to be able to fail.
     */
    @Test
    fun `a class line's owner is its declared type and never one of its supertypes`() {
        val member = "public final dev.eryalabs.lim.Utils.shareEntry(android.content.Context, " +
            "dev.eryalabs.lim.Entry, java.lang.String): boolean"
        val sealedSubclass = "public static final class dev.eryalabs.lim.SignedStatement\$Rotate: " +
            "dev.eryalabs.lim.SignedStatement"
        val foreignSupertype = "public static final class dev.eryalabs.lim.Entry\$Companion: " +
            "java.lang.Object, kotlinx.parcelize.Parceler"

        assertEquals("a member line still reads as its owner", "Utils", owner(member))
        assertEquals("SignedStatement\$Rotate", owner(sealedSubclass))
        assertEquals("Entry\$Companion", owner(foreignSupertype))

        // The discriminating one: the class parser must decline a member line outright, leaving
        // it to `OWNER`. A prefix scan would claim it and return the same string by luck.
        assertNull(
            "the class-header parser must not claim a member line, or the member parser and its " +
                "`<owner>.<member>` boundary stop being consulted at all",
            CLASS_OWNER.find(member),
        )
        assertTrue(
            "…while still claiming a class line, or it is declining everything",
            CLASS_OWNER.find(sealedSubclass) != null,
        )

        // And through the census filter, named specifically rather than as a `'$' in it` sweep
        // that only restates `publishedTypes`'s own filter: the two types these headers declare
        // must be absent while the top-level types they belong to are present, which is the
        // property a changelog bullet per Parcelable creator would violate.
        val types = publishedTypes()
        assertTrue("SignedStatement is published in its own right", "SignedStatement" in types)
        assertTrue("so is Entry", "Entry" in types)
        assertTrue(
            "but a nested owner is not a census entry of its own: $types",
            "SignedStatement\$Rotate" !in types && "Entry\$Companion" !in types,
        )
    }

    /** A citation the surface does not answer to is reported, whichever shape it arrives in. */
    @Test
    fun `an unknown citation is reported rather than waved through`() {
        assertTrue("Utils.shareEntry is a real member", "shareEntry" in utilsMembers())
        assertTrue("Utils.nope is not", "nope" !in utilsMembers())

        assertTrue("`Entry` must resolve", resolves("Entry"))
        assertTrue("a nested type must resolve", resolves("SignedStatement.Rotate"))
        assertTrue("a property must resolve through its getter", resolves("Entry.publicKey"))
        assertTrue("a constant must resolve", resolves("PUBLIC_KEY_PREVIEW_CHARS"))
        assertTrue("an enum verdict must resolve", resolves("StatementVerdict.VALID"))
        assertTrue("a bare function name must resolve", resolves("shareEntry"))
        assertTrue("a bare property name must resolve through its getter", resolves("publicKey"))
        // The one name whose two answers differ, and the reason `memberNames` subtracts the file
        // facade's unpublished members: reflection finds `RedactionKt.redactedValue` and the
        // baseline records it, but Kotlin declares it `internal`, so it is not a name this
        // changelog may cite as published. If this line ever goes green, the two halves of this
        // file have stopped agreeing about what is published.
        assertTrue("an internal member must not resolve", !resolves("redactedValue"))

        assertTrue("a renamed type must not", !resolves("RotationStatment"))
        assertTrue("a renamed member must not", !resolves("Entry.pubKey"))
        // `EXTRA_PROBE` is the name every plant in this repository's queue uses, which is why it
        // is the one asserted absent: the day somebody publishes it for real, this line reddening
        // is the correct signal that a fixture has stopped being invented.
        assertTrue("an invented constant must not", !resolves("EXTRA_PROBE"))
        assertTrue("a foreign name must not resolve by itself", !resolves("Parcelable"))
        // A class the classloader *can* find and the shipped artifact does not contain. Every test
        // in this package is one, which is why the ladder resolves a class against the baseline's
        // owners rather than against `Class.forName` alone.
        assertTrue("a test class must not resolve as published", !resolves("ThreadSafetyTest"))
    }

    private companion object {
        private const val PACKAGE = "dev.eryalabs.lim"
        private const val CHANGELOG_PATH = "CHANGELOG.md"
        private const val BASELINE_PATH = "LIM/api/lim.api"
        private const val BASELINE_RELATIVE = "api/lim.api"
        private const val MODULE_BUILD_FILE = "build.gradle.kts"
        private const val REDACTION_SOURCE = "src/main/java/dev/eryalabs/lim/Redaction.kt"

        /** The facade class a file's top-level declarations compile into. Not a nameable type. */
        private const val FILE_FACADE = "RedactionKt"

        /** The handle the compiler emits for a Kotlin `object`; see [utilsConstants]. */
        private const val OBJECT_INSTANCE = "INSTANCE"

        private const val UNRELEASED = "unreleased"

        /**
         * Floors, set below the values measured when this file was written (73 census names, 113
         * checked code-span citations) so that ordinary additions do not have to move them. They
         * exist against a different failure: a parse or a reflection filter that found nothing
         * would make the assertions they guard pass over an empty list. The bullet-lead test needs
         * no floor of its own — it asserts all 38 published function names are present, which no
         * empty parse can satisfy.
         */
        private const val MINIMUM_CENSUS = 65
        private const val MINIMUM_SPANS = 90

        /** `<owner>.<member>` at the head of a `lim.api` member line; see [owner]. */
        private val OWNER =
            Regex("""\bdev\.eryalabs\.lim\.([A-Za-z0-9_$]+)\.(<init>|[A-Za-z0-9_$]+)\s*[(:]""")

        /**
         * The declared type of a `lim.api` class-header line, by its `class` keyword; see [owner].
         *
         * Anchored on the keyword rather than on the package prefix, because a header's supertype
         * list can name types in this package too and only the declaration follows `class`.
         */
        private val CLASS_OWNER = Regex("""\bclass\s+dev\.eryalabs\.lim\.([A-Za-z0-9_$]+)""")

        private val COORDINATES =
            Regex("""coordinates\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)""")

        /** A top-level `val`/`var`/`fun` in a Kotlin source, with its visibility if it has one. */
        private val TOP_LEVEL_DECLARATION = Regex(
            """(?m)^(public|internal|private)?\s*(?:const\s+)?(?:val|var|fun)\s+""" +
                """([A-Za-z_][A-Za-z0-9_]*)""",
        )

        /** Kotlin visibilities that are not published API, whatever the JVM surface says. */
        private val NOT_PUBLISHED = setOf("internal", "private")

        /** A markdown inline code span. */
        private val CODE_SPAN = Regex("""`([^`\n]+)`""")

        /** A list item. */
        private val BULLET_START = Regex("""^\s*-\s+\S""")

        /** A list item that opens with a code span — a citation rather than a prose bullet. */
        private val BULLET_CITATION = Regex("""^\s*-\s+`""")

        /** What separates a bullet's citations from its prose throughout this document. */
        private const val EM_DASH = "—"

        /**
         * `Entry`, `EXTRA_NONCE`, `SignedStatement.Rotate`, `Entry.publicKey` — one dotted
         * identifier and nothing else, so a span containing a quote, a type argument, a space or
         * a path separator is prose rather than a citation and is left alone.
         *
         * `_` is in the first segment deliberately: without it every `SCREAMING_SNAKE` constant
         * in the document would fall out of this check unexamined, which is most of the names the
         * protocol's vocabulary is made of.
         */
        private val DOTTED_NAME = Regex("""[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*""")

        /** `Redaction.kt` is a file, not a type; a path with a `/` never matched [DOTTED_NAME]. */
        private val FILE_NAME = Regex("""[A-Za-z0-9_]+\.(?:kt|kts|md|api|json|pro|xml)""")

        /** A `Utils.<name>` reference anywhere in the document, code span or prose. */
        private val UTILS_CITATION = Regex("""\bUtils\.([A-Za-z_][A-Za-z0-9_]*)""")

        private val ISO_DATE = Regex("""\d{4}-\d{2}-\d{2}""")

        /** Where a bare `SCREAMING_SNAKE` citation can legitimately come from. */
        private val CONSTANT_HOLDERS =
            listOf("Utils", "FieldType", "StatementVerdict", FILE_FACADE)

        /**
         * Code spans that look like a published name and are not one — mostly because they belong
         * to somebody else, and in three cases because they belong to this repository without
         * being published (two test classes and this document's own heading word).
         *
         * Kept short on purpose: it is the escape hatch, so every entry carries the reason it is
         * here, and an entry that stops being cited should be deleted rather than left to look
         * like coverage of something.
         */
        private val NOT_A_PUBLISHED_NAME = setOf(
            // Android.
            "Parcelable",
            "putExtra",
            "setResult",
            // JDK.
            "SecureRandom",
            "NullPointerException",
            // JCA algorithm names, which are strings rather than anything declared here — and
            // `MD5withRSA` appears precisely because nothing honours a declared algorithm.
            "SHA256withRSA",
            "MD5withRSA",
            // Gson: `sun.misc.Unsafe`, which is how it builds an object without running the
            // constructor — the reason the decoders exist at all — and its own parse entry point,
            // named so the changelog can say what not to call.
            "Unsafe",
            "fromJson",
            // Kotlin's own vocabulary, quoted as code because that is what it is.
            "false",
            "null",
            "object",
            // Gradle: a repository name, and this library's package and group, which is a
            // coordinate rather than a member.
            "mavenLocal",
            "dev.eryalabs.lim",
            // The one parameter name in the document with no property of the same name behind it:
            // `targetPackage` is a parameter of both action helpers and of every request builder,
            // and nothing publishes it as a property. The rest — `publicKey`, `fields`,
            // `requestCode` — resolve through the accessors their types generate.
            "targetPackage",
            // This document's own heading word, which is prose about a release rather than a name.
            "unreleased",
            // This repository's own tests, cited so a reader can find the check being described.
            // They are not published API and [resolves] deliberately will not have them: it
            // resolves a class against the baseline's owners rather than against the classloader,
            // which at test time can see every test class in this package.
            "ChangelogTest",
            "PublicApiAuditTest",
        )

        /**
         * The release whose entry describes the whole surface rather than a change to it: the
         * first one. See `the release section is grouped by flow`.
         */
        private const val FULL_SURFACE_VERSION = "1.0.0"

        /**
         * The flows the [FULL_SURFACE_VERSION] entry groups the surface by. Matched as substrings
         * of a `### ` heading, in no order; see `the release section is grouped by flow`.
         */
        private val REQUIRED_GROUPS = listOf(
            "Share",
            "Query",
            "Sign-challenge",
            "Result building",
            "Statements and migration",
            "Diagnostics",
        )
    }
}
