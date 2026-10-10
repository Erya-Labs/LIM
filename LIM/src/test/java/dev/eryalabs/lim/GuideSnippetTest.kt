package dev.eryalabs.lim

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * `docs/INTEGRATION.md` is the library's whole adoption surface, and prose rots. This test is what
 * stops it: **every fenced Kotlin block in the guide is a region of a test source, quoted
 * verbatim.**
 *
 * The guide marks each block with an HTML comment naming its source —
 * `<!-- snippet: GuideExamplesTest.kt#login-result -->` — and the test source wraps the quoted
 * lines in `// region snippet:login-result` … `// endregion snippet:login-result`. Seven properties
 * hold the pair together:
 *
 *  1. every ` ```kotlin ` block carries a marker;
 *  2. every marker resolves to a region that exists;
 *  3. every block equals its region verbatim, after stripping the region's common leading
 *     indentation and nothing else;
 *  4. every region in every test source is quoted by **exactly one** block — so a marker left
 *     behind after an edit fails as surely as a missing one — and no two regions share a name,
 *     because an ambiguous name is not compared against anything;
 *  5. every region sits **directly in the body of an un-`@Ignore`d `@Test` method of the
 *     top-level test class**, which is what makes a printed snippet *evidence*: each line in the
 *     guide is a line JUnit executed to get this suite green. Anything looser admits code that
 *     compiles and never runs — a helper, a nested class, a `@Test` method *of* a nested class
 *     (which the JUnit4 runner does not collect), an uninvoked lambda, an `@Ignore`d test;
 *  6. every fenced block in any other language is excused by name in [NOT_A_SNIPPET], with a
 *     reason and a test that covers it instead;
 *  7. every fence in the guide is one this test can see — an indented or `~~~` fence is refused
 *     rather than silently skipped.
 *
 * **The marker rule binds ` ```kotlin ` and nothing else**, which is why the Setup section's
 * dependency declaration is fenced ` ```gradle `, the vault-visibility section's manifest element is
 * fenced ` ```xml ` and the minification section's keep rules are fenced ` ```proguard `. Fencing
 * Gradle Kotlin DSL as Kotlin would put it under rule 1, which has no region to offer it, and rules
 * 1 and 6 would deadlock on the one block the guide cannot do without; the same is true of an XML
 * element and of a ProGuard rule set, neither of which any test here can execute. [NOT_A_SNIPPET] is
 * the exhaustive list, and the one to read rather than this sentence.
 *
 * **What this test deliberately does not pin: the prose.** Rewriting any sentence outside a fenced
 * block changes nothing here, and that is the honest statement of its scope — it pins code, not
 * writing. Whether the guide reads well is a human judgement (VISION), and an assertion pretending
 * otherwise would be worse than none.
 *
 * Regex over two files, so it runs in milliseconds: no Robolectric, no reflection beyond resolving
 * the excuses' citations.
 */
class GuideSnippetTest {

    // ── What the two files contain ────────────────────────────────────────

    /** A fenced block in the guide, with the marker above it if it has one. */
    private class Block(
        val heading: String,
        val language: String,
        val markerFile: String?,
        val markerRegion: String?,
        val lines: List<String>,
        val lineNumber: Int,
    ) {
        /** `GuideExamplesTest.kt#login-result`, or null for a block with no marker. */
        val marker: String? = markerFile?.let { "$it#$markerRegion" }

        val where: String = "the `$language` block at line $lineNumber under \"$heading\""

        /** The key [NOT_A_SNIPPET] is spelled with: fence language and heading, nothing else. */
        val excuseKey: String = "$language under $heading"
    }

    /** A `// region snippet:name` span of a test source. */
    private class Region(
        val file: String,
        val name: String,
        val lines: List<String>,
        val lineNumber: Int,
        /** The brace scopes containing it, outermost first — `FixtureTest > fun a fixture test`. */
        val placement: String,
        /** Whether JUnit4 runs the body this region sits in. Rule 5's whole question. */
        val isRunnable: Boolean,
    ) {
        val id: String = "$file#$name"

        val where: String = "$id ($file:$lineNumber)"
    }

    /**
     * A brace-delimited block, as the scope scan descends into one.
     *
     * Three facts rather than a name, because rule 5 is a question about the whole chain and each
     * link can fail differently: [isFunction] and [isTest] say whether JUnit *collects* this
     * method, [isTestHost] whether JUnit *instantiates* this type. A `@Test` method of an
     * `@Ignore`d, `abstract` or `object` declaration is collected by nothing, and asking only
     * about the method would miss it — which is how a whole suite can be parked with one
     * annotation while every snippet claims to have run.
     *
     * [description] is rendered here so a failure says what is wrong with the scope rather than
     * just naming it.
     */
    private class Scope(
        val description: String,
        val isFunction: Boolean,
        val isTest: Boolean,
        val isTestHost: Boolean,
    )

    /**
     * Why a fenced block carries no snippet, and what covers it instead — two fields rather than
     * one sentence, so [coveredBy] can be resolved against a real `@Test` instead of taken on
     * trust. `PublishedSurfaceFuzzTest`'s form, spelled `ClassName: test method name`.
     */
    private class Excuse(val reason: String, val coveredBy: String)

    /** Every complaint the two files produce, so the real tests and the controls share one loop. */
    private class Audit(
        val blocks: List<Block>,
        val regions: List<Region>,
        val unmarkedKotlinBlocks: List<String>,
        val danglingMarkers: List<String>,
        val mismatched: List<String>,
        val orphanRegions: List<String>,
        val doublyQuotedRegions: List<String>,
        val duplicateRegionNames: List<String>,
        val regionsOutsideATest: List<String>,
        val unexcusedBlocks: List<String>,
        val danglingExcuses: List<String>,
        val collidingExcuseKeys: List<String>,
    ) {
        val kotlinBlocks: List<Block> = blocks.filter { it.language == SNIPPET_LANGUAGE }
    }

    // ── The one measurement every assertion below reads ───────────────────

    /**
     * The guide against every Kotlin test source.
     *
     * The *sources* are every `.kt` file rather than `GuideExamplesTest.kt` alone, because rule 4
     * is a claim about all of them: a region marked anywhere in the suite and quoted nowhere is
     * exactly the stale marker this test exists to find.
     *
     * A region whose name is duplicated is held out of the verbatim, orphan and dangling-marker
     * answers entirely rather than being resolved arbitrarily. Resolving it would report a block
     * that *is* verbatim one of its regions as drifted from the other, naming neither — a wrong
     * answer dressed as a precise one. Rule 4 reports the duplication instead and nothing else
     * speaks about those names until it is fixed.
     */
    private fun audit(
        guide: String,
        sources: Map<String, String>,
        excuses: Map<String, Excuse>,
    ): Audit {
        val blocks = blocksIn(guide)
        val regions = sources.entries.sortedBy { it.key }.flatMap { regionsIn(it.key, it.value) }
        val grouped = regions.groupBy { it.id }
        val duplicated = grouped.filterValues { it.size > 1 }
        val byId = grouped.filterValues { it.size == 1 }.mapValues { it.value.single() }
        val unambiguous = regions.filterNot { it.id in duplicated }

        val kotlinBlocks = blocks.filter { it.language == SNIPPET_LANGUAGE }
        val otherBlocks = blocks.filterNot { it.language == SNIPPET_LANGUAGE }

        val quoted = kotlinBlocks.mapNotNull { it.marker }
        val quotedCount = quoted.groupingBy { it }.eachCount()
        val presentKeys = otherBlocks.map { it.excuseKey }

        return Audit(
            blocks = blocks,
            regions = regions,
            unmarkedKotlinBlocks = kotlinBlocks.filter { it.marker == null }.map { it.where },
            danglingMarkers = quoted.filterNot { it in byId || it in duplicated }
                .distinct()
                .sorted(),
            mismatched = kotlinBlocks.mapNotNull { block ->
                val region = byId[block.marker] ?: return@mapNotNull null
                val expected = dedented(region.lines)
                if (expected == block.lines) null else describeMismatch(block, region, expected)
            }.sorted(),
            orphanRegions = unambiguous.filter { it.id !in quotedCount }.map { it.where }.sorted(),
            doublyQuotedRegions = unambiguous.filter { (quotedCount[it.id] ?: 0) > 1 }
                .map { "${it.id} is quoted by ${quotedCount[it.id]} blocks" }
                .sorted(),
            duplicateRegionNames = duplicated.values
                .map { same -> same.joinToString(", ") { it.where } }
                .sorted(),
            regionsOutsideATest = regions.filterNot { it.isRunnable }
                .map { "${it.where} sits at `${it.placement}`, which JUnit does not run" }
                .sorted(),
            unexcusedBlocks = otherBlocks.filterNot { it.excuseKey in excuses }
                .map { "${it.where} — excuse key `${it.excuseKey}`" }
                .sorted(),
            danglingExcuses = excuses.keys.filterNot { it in presentKeys }.sorted(),
            collidingExcuseKeys = presentKeys.groupingBy { it }.eachCount()
                .filterValues { it > 1 }.keys.sorted(),
        )
    }

    /**
     * The guide against every test source, measured once for the whole class.
     *
     * JUnit constructs a fresh instance per test method, so a per-instance `by lazy` re-read and
     * re-parsed all 38 sources 22 times over and took this file from 0.3s to 1.1s — for a file
     * whose whole claim on the suite is that it is regex over text and costs nothing. The files
     * cannot change within a run, and a mutation to either one re-runs the class from scratch.
     */
    private fun onDisk(): Audit = cachedOnDisk
        ?: audit(guideFile().readText(), testSources(), NOT_A_SNIPPET).also { cachedOnDisk = it }

    // ── The seven properties ──────────────────────────────────────────────

    @Test
    fun `every Kotlin block in the guide names a region`() {
        assertEquals(
            "a fenced `$SNIPPET_LANGUAGE` block in the guide must be preceded by " +
                "`<!-- snippet: File.kt#region -->`. An unmarked block is prose that compiled " +
                "once and is pinned by nothing, which is the whole failure this test exists to " +
                "prevent",
            emptyList<String>(),
            onDisk().unmarkedKotlinBlocks,
        )
        // Floor: a scanner that found no blocks at all would report no offenders for ever.
        assertTrue(
            "the guide must contain Kotlin blocks for this to mean anything; found " +
                "${onDisk().kotlinBlocks.size} of ${onDisk().blocks.size} fenced blocks",
            onDisk().kotlinBlocks.size >= REQUIRED_SECTIONS.size,
        )
    }

    @Test
    fun `every marker resolves to a region that exists`() {
        assertEquals(
            "a marker in the guide names a region no test source contains — a renamed or " +
                "deleted region leaves the guide quoting nothing while still looking quoted",
            emptyList<String>(),
            onDisk().danglingMarkers,
        )
    }

    @Test
    fun `every block in the guide is its region verbatim`() {
        assertEquals(
            "a block in the guide has drifted from the region it quotes. The guide is not " +
                "edited to match: the region is the source of truth, so change the test and " +
                "copy it across",
            emptyList<String>(),
            onDisk().mismatched,
        )
        // Floor: a comparison over zero pairs is also equal.
        assertTrue(
            "no block resolved to a region, so nothing was compared",
            onDisk().kotlinBlocks.count { it.marker != null } > 0,
        )
    }

    @Test
    fun `every region is quoted by exactly one block`() {
        assertEquals(
            "two regions share a name. Nothing resolves an ambiguous marker, so neither of " +
                "them is compared against the guide at all until one is renamed — which is a " +
                "quieter failure than a mismatch and the reason this is its own assertion",
            emptyList<String>(),
            onDisk().duplicateRegionNames,
        )
        assertEquals(
            "a region is marked in a test source and quoted by no block in the guide. Either " +
                "the guide lost the block, or the markers were left behind by an edit — a stale " +
                "marker is a claim that something is published when it is not",
            emptyList<String>(),
            onDisk().orphanRegions,
        )
        assertEquals(
            "a region is quoted by two blocks, so one of them can drift out of the guide's " +
                "narrative while every verbatim check stays green",
            emptyList<String>(),
            onDisk().doublyQuotedRegions,
        )
        assertTrue("no regions were found at all, so this proves nothing", onDisk().regions.isNotEmpty())
        println(
            "GuideSnippetTest: ${onDisk().regions.size} regions in " +
                "${onDisk().regions.map { it.file }.distinct().size} source(s), " +
                "${onDisk().kotlinBlocks.size} Kotlin blocks, " +
                "${onDisk().blocks.size - onDisk().kotlinBlocks.size} excused block(s)",
        )
    }

    /**
     * The strongest claim here, and the reason a snippet is evidence rather than paste: the lines
     * the guide prints are lines JUnit ran.
     *
     * A region in a helper, in an `@Ignore`d test, in an uninvoked lambda, in a nested class body,
     * or in a `@Test` method of a nested class is all still real compiling code — and still never
     * executes, so it could be wrong in any way that compiles. Control (d) below drives all five
     * shapes through this same answer and asserts each is reported.
     */
    @Test
    fun `every quoted region sits inside a function JUnit runs`() {
        assertEquals(
            "a region's enclosing function is not annotated `@Test`, so the guide is printing " +
                "code that compiles but never runs",
            emptyList<String>(),
            onDisk().regionsOutsideATest,
        )
    }

    @Test
    fun `every fenced block that is not a snippet is excused by name`() {
        assertEquals(
            "a fenced block in a language other than `$SNIPPET_LANGUAGE` is outside the marker " +
                "rule and therefore backed by no test. Each one must be excused in " +
                "NOT_A_SNIPPET, keyed by fence language and heading, by somebody who wrote down " +
                "why",
            emptyList<String>(),
            onDisk().unexcusedBlocks,
        )
        assertEquals(
            "NOT_A_SNIPPET names a block the guide does not contain. A rewritten heading or a " +
                "deleted block leaves a dead excuse behind, and a dead excuse would wave " +
                "through the next block that happens to land under that key",
            emptyList<String>(),
            onDisk().danglingExcuses,
        )
        assertEquals(
            "two fenced blocks share one excuse key, so one of them is being excused by the " +
                "other's reason; give the second block a heading of its own",
            emptyList<String>(),
            onDisk().collidingExcuseKeys,
        )
        assertTrue("no excuse was stated, so this proves nothing", NOT_A_SNIPPET.isNotEmpty())
        assertEquals(
            "every excuse must carry a reason as well as a citation",
            emptyList<String>(),
            NOT_A_SNIPPET.filterValues { it.reason.isBlank() }.keys.sorted(),
        )
        assertEquals(
            "a NOT_A_SNIPPET entry cites a @Test that does not exist under the class it names. " +
                "A renamed or moved test must be updated here too, or the block it excused is " +
                "neither pinned nor covered",
            emptyList<String>(),
            NOT_A_SNIPPET.entries
                .filterNot { resolvesToATest(it.value.coveredBy) }
                .map { "${it.key} -> ${it.value.coveredBy}" }
                .sorted(),
        )
        // The resolver must be able to answer both ways, or it reports success unconditionally.
        assertFalse(resolvesToATest("GuideSnippetTest: a test nobody wrote"))
        assertFalse(resolvesToATest("NoSuchTestClass: every region is quoted by exactly one block"))
        assertTrue(resolvesToATest("GuideSnippetTest: every region is quoted by exactly one block"))
    }

    /**
     * Rule 7, and it exists because of what the parser *cannot* see rather than what it can.
     *
     * [FENCE_OPEN] anchors at column 0 and accepts a bare language word, so three shapes are
     * invisible to it: a fence indented under a list item — the shape this guide's "Where to look
     * next" section is one edit away from — a `~~~` fence, and an info string like
     * ` ```kotlin title=x `. A Kotlin block hidden in any of them would be published with nothing
     * pinning it. Rather than widen the parser and inherit Markdown's indentation rules, the guide
     * refuses all three and says so here, so the test's name is true of the whole file rather than
     * of the subset it happens to parse.
     */
    @Test
    fun `the guide uses no fence this test cannot see`() {
        val unreadable = unreadableFences(guideFile().readLines())
        assertEquals(
            "an indented fence, a `~~~` fence or a fence with an info string beyond the language " +
                "word is invisible to this test, so a Kotlin block inside one would be published " +
                "with nothing pinning it. Fence at column 0 with backticks and a bare language " +
                "word, or widen the parser deliberately",
            emptyList<String>(),
            unreadable,
        )
    }

    // ── What the guide must say ───────────────────────────────────────────

    @Test
    fun `the guide carries every section an integration needs`() {
        val sections = SECTION.findAll(guideFile().readText()).map { it.groupValues[1] }.toList()
        assertEquals(
            "the guide must not ship half-written; these sections are missing: " +
                "${REQUIRED_SECTIONS.filterNot { it in sections }}. Found: $sections",
            emptyList<String>(),
            REQUIRED_SECTIONS.filterNot { it in sections },
        )
    }

    /**
     * The coverage floor, measured over the regions' **code** lines rather than over the guide's
     * prose: a guide that documented only sign-up would pass every property above, and one that
     * merely *mentioned* the rest of the loop in a comment would pass a floor measured over
     * region text as a whole.
     *
     * These eleven are the core loop VISION's yardstick names — ask whether there is a vault to
     * ask, send, parse, correlate, challenge, verify, expire — on both of the two flows that have a
     * result worth checking, plus the one call that answers "is a vault installed at all".
     */
    @Test
    fun `every function in the core loop is called in a snippet`() {
        // Trailing comments go too, not only comment-only lines: `val x = 1 // then call
        // parseQueryResult` would otherwise satisfy the floor with a mention rather than a call.
        val code = onDisk().regions
            .flatMap { it.lines }
            .map { it.substringBefore("//") }
            .joinToString("\n")
        assertEquals(
            "the guide must show the whole core loop in code a test ran, not describe it in a " +
                "comment. These appear in no executed region line",
            emptyList<String>(),
            CORE_LOOP.filterNot { it in code },
        )
        println(
            "GuideSnippetTest: ${CORE_LOOP.size} core-loop functions, all called across " +
                "${onDisk().regions.size} regions (${code.lines().size} code lines of " +
                "${onDisk().regions.sumOf { it.lines.size }} snippet lines)",
        )
    }

    /**
     * The Setup section prints a coordinate, and a coordinate that falls out of step with the
     * build file is worse than none: it sends an integrator to resolve something that was never
     * published under that version.
     *
     * So the version is read out of `LIM/build.gradle.kts`'s own `coordinates(...)` call. A human
     * bumping it reddens the guide — which is the point. The build file is never edited from here.
     */
    @Test
    fun `the guide prints the coordinate the build file declares`() {
        val buildFile = locate(MODULE_BUILD_FILE)
        val declared = COORDINATES.findAll(buildFile.readText()).toList()
        assertEquals(
            "expected exactly one `coordinates(group, artifact, version)` call in " +
                "${buildFile.absolutePath}; the version the guide must print is read out of it",
            1,
            declared.size,
        )
        val (group, artifact, version) = declared.single().destructured
        val prefix = "$group:$artifact:"
        val printed = Regex(Regex.escape(prefix) + """([0-9A-Za-z.\-+]+)""")
            .findAll(guideFile().readText())
            .map { it.groupValues[1] }
            .toSet()
        assertEquals(
            "the guide must print `$prefix$version`, and no other version of it. If the build " +
                "file's version moved, the guide is now advertising a coordinate the build does " +
                "not declare — update the guide, not this test",
            setOf(version),
            printed,
        )
    }

    /**
     * The build-from-source block's citation, and it is worth being exact about what it does and
     * does not claim.
     *
     * Nothing in this repository can execute a consumer project's build, so whether that block's
     * *mechanics* work is not pinned by anything — the guide says so in as many words, in the one
     * place it says it. What is pinned is every **name** in it, which is what actually rots: the
     * Gradle project path comes out of `settings.gradle.kts`, the artifact file name out of the
     * module name, and the Gson coordinate out of the module's own `implementation` line, since
     * an AAR carries no dependency metadata and a bumped Gson would otherwise leave the guide
     * telling integrators to add a version this library no longer builds against.
     */
    @Test
    fun `the build-from-source path names what the build declares`() {
        val module = INCLUDE.find(locate(SETTINGS_FILE).readText())?.groupValues?.get(1)
        assertEquals(
            "the Gradle project path in the guide is derived from `include(...)` in " +
                "${locate(SETTINGS_FILE).absolutePath}",
            "LIM",
            module,
        )
        val guide = guideFile().readText()
        assertTrue(
            "the guide must name the assemble task for project `:$module`",
            ":$module:assembleRelease" in guide,
        )
        assertTrue(
            "…and the artifact that task writes, which AGP names after the module",
            "$module-release.aar" in guide,
        )

        // Every configuration that puts something on a *consumer's* runtime classpath, not just
        // `implementation("g:a:v")`: an `api(...)` or a version-catalog alias is just as much a
        // dependency a bare-AAR consumer has to add, and matching only the literal shape would
        // let one appear without the guide noticing.
        val buildFile = locate(MODULE_BUILD_FILE).readText()
        val runtime = Regex("""(?m)^\s*(?:implementation|api|runtimeOnly)\((.+)\)\s*$""")
            .findAll(buildFile)
            .map { it.groupValues[1].trim() }
            .toList()
        assertEquals(
            "this module declares exactly one dependency a consumer inherits, and a bare AAR " +
                "carries no metadata for it, so the guide has to name it. If a second one " +
                "appears, the guide must name that too. Found: $runtime",
            1,
            runtime.size,
        )
        val coordinate = Regex("""^"([^"]+:[^"]+:[^"]+)"$""").find(runtime.single())?.groupValues?.get(1)
        assertEquals(
            "the one inherited dependency must be a literal coordinate for the guide to be able " +
                "to print it; a version-catalog alias (`libs.gson`) would leave the guide naming " +
                "a version read from somewhere this test does not look. Found: ${runtime.single()}",
            runtime.single().trim('"'),
            coordinate,
        )
        assertTrue(
            "the guide must print `$coordinate` — the dependency a consumer of the AAR has to " +
                "add by hand, at the version this library builds against",
            coordinate != null && coordinate in guide,
        )
    }

    /**
     * The vault-visibility section prints a package name, and that is the one name in its ` ```xml `
     * block — the block [NOT_A_SNIPPET] excuses, citing a *behaviour* test rather than anything that
     * reads the block's text. So the name is pinned here instead.
     *
     * A `<queries>` element naming a package this library never addresses leaves an installed vault
     * invisible on Android 11+, so [Utils.shareEntry] reports `false` on a device that has one —
     * exactly the failure that section exists to prevent, and silent in both directions. The
     * Setup section's coordinate is pinned the same way and for the same reason.
     *
     * The constant is `const val`, so the compiler inlines it here; what keeps that honest is that
     * editing `Utils.kt` recompiles this source, so the literal compared against the guide is
     * always the one the library ships.
     */
    @Test
    fun `the guide prints the vault package this library addresses by default`() {
        assertTrue(
            "the guide must print `${Utils.DEFAULT_ENDEAVOR_PACKAGE}` — the package a consumer " +
                "declares in their own `<queries>` element so that the vault is visible to them. " +
                "If the default moved, the guide is now telling integrators to declare a package " +
                "nothing here addresses: update the guide, not this test",
            Utils.DEFAULT_ENDEAVOR_PACKAGE in guideFile().readText(),
        )
    }

    @Test
    fun `the README links a guide that exists`() {
        val readme = locate("README.md")
        val links = Regex("""]\((docs/[^)]+)\)""").findAll(readme.readText())
            .map { it.groupValues[1] }
            .toList()
        assertTrue(
            "the README is the only document a third party finds on their own, so it must link " +
                "the guide; found links into docs/: $links",
            GUIDE_PATH in links,
        )
        assertEquals(
            "a README link into docs/ must resolve to a file that exists",
            emptyList<String>(),
            links.filterNot { File(readme.parentFile, it).isFile }.sorted(),
        )
    }

    // ── Negative controls ─────────────────────────────────────────────────
    //
    // Every one of these runs the *same* `audit` the assertions above run, over a fixture pair
    // instead of the two real files, and asserts the same list is non-empty and names the right
    // thing. One mechanism, two answers — no second implementation to agree with the first by
    // construction.

    /**
     * (a) The verbatim comparison can report a mismatch.
     *
     * `#quoted` differs from its region by one character — `42` against `43` — which is the
     * smallest drift the guide could suffer and the one a reader would never catch.
     */
    @Test
    fun `control - a block that differs from its region by one character is reported`() {
        val mismatched = fixtureAudit().mismatched
        assertEquals("exactly one fixture block is mis-quoted; found $mismatched", 1, mismatched.size)
        assertTrue(
            "the complaint must name the region it is about: $mismatched",
            mismatched.single().contains("FixtureTest.kt#quoted"),
        )
        assertTrue(
            "…and show both sides, or a failure is unactionable: $mismatched",
            mismatched.single().contains("val answer = 42") && mismatched.single().contains("val answer = 43"),
        )
    }

    /** (b) A region quoted by no block is reported. */
    @Test
    fun `control - a region nothing quotes is reported`() {
        val orphans = fixtureAudit().orphanRegions
        assertEquals("found $orphans", 1, orphans.size)
        assertTrue("the orphan must be named: $orphans", orphans.single().startsWith("FixtureTest.kt#orphan"))
    }

    /** (c) A marker naming a region that does not exist is reported, with file and region. */
    @Test
    fun `control - a marker naming a region that does not exist is reported`() {
        val dangling = fixtureAudit().danglingMarkers
        assertEquals(
            "a dangling marker must be reported naming the file and the region it asked for",
            listOf("FixtureTest.kt#never-written"),
            dangling,
        )
    }

    /**
     * (d) Rule 5 can fail, in every shape that compiles — without which the strongest claim in
     * this file would be unfalsifiable.
     *
     * Each of the seven is a way for a published line to never execute, and all but the first were
     * live defects in some earlier version of this rule. They are one fixture because they are one
     * property: `#untested`, a plain helper; `#ignored`, a `@Test` taken back out of the run by
     * `@Ignore` in the fully-qualified spelling that needs no import; `#lambda`, an uninvoked
     * lambda that inherited the scope of the expression-bodied test above it; `#nested`, a nested
     * class body; `#nested-test`, a `@Test` method *of* a nested class, which the JUnit4 runner
     * never collects and which is the shape that looks most convincingly fine; `#toplevel`, a
     * region outside every declaration; `#nested-block`, a region inside an `if` within a real
     * test, which is the documented cost of the narrow rule and is asserted so the cost is a
     * stated one rather than a surprise.
     */
    @Test
    fun `control - a region outside a test JUnit runs is reported, in every shape`() {
        val offenders = fixtureAudit().regionsOutsideATest
        assertEquals("found $offenders", 9, offenders.size)
        listOf(
            "#untested" to "a plain helper",
            "#ignored" to "an @Ignore'd test",
            "#lambda" to "an uninvoked lambda after an expression-bodied test",
            "#nested" to "a nested class body",
            "#nested-test" to "a @Test method of a nested class",
            "#toplevel" to "a region outside every declaration",
            "#nested-block" to "a region inside an `if` within a real test",
            "#commented-out" to "a whole test commented out with /* */",
            "#commented-annotation" to "a helper whose @Test is inside a /* */ comment",
        ).forEach { (region, shape) ->
            assertTrue(
                "$shape must be reported, and the complaint must name the region: $offenders",
                offenders.any { it.contains("FixtureTest.kt$region") },
            )
        }
        assertTrue(
            "every complaint must say where the region actually sits, or a failure is " +
                "unactionable: $offenders",
            offenders.all { it.contains("sits at `") },
        )
        // And the same loop must accept the fixture's genuinely runnable regions, or the rule is
        // reporting every region as unrun. `#one-line` is the single-line `@Test fun` spelling,
        // which an earlier version of the parser *rejected* — the mirror failure, and the one that
        // would have sent the next person to add a snippet looking in the wrong place.
        listOf("#quoted", "#orphan", "#one-line").forEach { region ->
            assertFalse(
                "the rule must not condemn `$region`, which is in a real @Test method of a real " +
                    "test class: $offenders",
                offenders.any { it.contains(region) },
            )
        }
    }

    /**
     * (i) The enclosing *type* is asked about too, which is a different question from the method.
     *
     * `@Ignore` on the class and `abstract class` both leave every method-level signal intact —
     * the annotation, the name, the body — and collect nothing. The first is the natural way to
     * park a suite and needs no import; it left this rule green over ten published blocks while
     * JUnit ran none of them, three times over: once when the rule asked nothing about the
     * enclosing type at all; once when it asked but read the annotations off the wrong half of the
     * line, because `@RunWith(X::class)` hides the keyword inside its own argument; and once when a
     * formatter wrapped the reason onto a second line and the continuation cleared the annotation
     * it was part of. Every one of those spellings is a fixture here, because each time the fix
     * addressed a spelling rather than the reason spellings slip.
     */
    @Test
    fun `control - a test class JUnit never instantiates is reported`() {
        val offenders = audit(
            FIXTURE_UNCOLLECTED_GUIDE,
            mapOf("Uncollected.kt" to FIXTURE_UNCOLLECTED_SOURCE),
            emptyMap(),
        ).regionsOutsideATest
        assertEquals("found $offenders", 4, offenders.size)
        listOf(
            "#ignored-class" to "an @Ignore'd class",
            "#abstract-class" to "an abstract class",
            "#ignored-one-line" to "a class parked on its own declaration line, after a " +
                "`::class` annotation argument",
            "#ignored-wrapped" to "a class parked by an annotation a formatter wrapped",
        ).forEach { (region, shape) ->
            assertTrue(
                "$shape must be reported, and the complaint must blame the class rather than " +
                    "the method: $offenders",
                offenders.any {
                    it.contains(region) && it.contains("not a class JUnit instantiates")
                },
            )
        }
    }

    /**
     * (k) A region quoted twice is reported — the other half of "a marker left behind after an
     * edit is a failure too", and the only audit answer that had no control of its own.
     */
    @Test
    fun `control - a region quoted by two blocks is reported`() {
        val doubled = audit(
            FIXTURE_DOUBLE_GUIDE,
            mapOf("FixtureTest.kt" to FIXTURE_SOURCE),
            emptyMap(),
        )
        assertEquals(
            listOf("FixtureTest.kt#quoted is quoted by 2 blocks"),
            doubled.doublyQuotedRegions,
        )
        assertEquals(
            "both blocks are verbatim the region, so the double-quoting is the only thing wrong " +
                "with them — a control that also reddened the verbatim check would not isolate it",
            emptyList<String>(),
            doubled.mismatched,
        )
    }

    /**
     * (j) Rule 7's detector can report an unreadable fence — otherwise it would pass unchanged
     * over a guide with no fences at all.
     */
    @Test
    fun `control - fences this test cannot see are reported`() {
        val reported = unreadableFences(
            listOf(
                "```kotlin",
                "val fine = 1",
                "```",
                "  ```kotlin",
                "val indented = 2",
                "  ```",
                "~~~kotlin",
                "val tildes = 3",
                "~~~",
                "```kotlin title=x",
                "val infoString = 4",
                "```",
            ),
        )
        assertEquals(
            "the indented fence (both halves), both tilde fences and the info-string fence must " +
                "be reported, and the plain one must not: $reported",
            listOf(4, 6, 7, 9, 10),
            reported.map { it.substringAfter("line ").substringBefore(":").toInt() },
        )
    }

    /** (e) Excuse hygiene, both directions, over the same fixture. */
    @Test
    fun `control - an unexcused block and a dead excuse are both reported`() {
        val withNoExcuses = fixtureAudit(excuses = emptyMap())
        assertEquals("found ${withNoExcuses.unexcusedBlocks}", 1, withNoExcuses.unexcusedBlocks.size)
        assertTrue(
            "the unexcused block must be named by language and heading: " +
                "${withNoExcuses.unexcusedBlocks}",
            withNoExcuses.unexcusedBlocks.single().contains("json under Fixture appendix"),
        )

        val withADeadExcuse = fixtureAudit(
            excuses = FIXTURE_EXCUSES +
                ("yaml under A heading the fixture guide does not have" to Excuse("dead", CONTROL_CITATION)),
        )
        assertEquals(
            "excusing the json block must silence the complaint, or the two halves of this " +
                "control are not reading the same map",
            emptyList<String>(),
            withADeadExcuse.unexcusedBlocks,
        )
        assertEquals(
            listOf("yaml under A heading the fixture guide does not have"),
            withADeadExcuse.danglingExcuses,
        )
    }

    /** (f) The unmarked-block rule, shown able to fire on the same fixture pair. */
    @Test
    fun `control - a Kotlin block with no marker above it is reported`() {
        val unmarked = fixtureAudit().unmarkedKotlinBlocks
        assertEquals("found $unmarked", 1, unmarked.size)
        assertTrue("the block must be located: $unmarked", unmarked.single().contains("under \"Fixtures\""))
    }

    /**
     * (g) Two regions with one name are reported, and nothing else speaks about them.
     *
     * The guide's block is verbatim the *first* of the two, so a resolver that picked the last
     * would report a correct block as drifted and name neither region as the cause. Both halves
     * are asserted: the duplication is reported, and the three answers that would otherwise lie
     * about it stay silent.
     */
    @Test
    fun `control - two regions sharing a name are reported and compared against nothing`() {
        val duplicate = audit(
            FIXTURE_DUPLICATE_GUIDE,
            mapOf("DupTest.kt" to FIXTURE_DUPLICATE_SOURCE),
            emptyMap(),
        )
        assertEquals("found ${duplicate.duplicateRegionNames}", 1, duplicate.duplicateRegionNames.size)
        assertTrue(
            "the complaint must name both offending regions and where they are: " +
                "${duplicate.duplicateRegionNames}",
            duplicate.duplicateRegionNames.single().let {
                it.contains("DupTest.kt:5") && it.contains("DupTest.kt:12")
            },
        )
        assertEquals(emptyList<String>(), duplicate.mismatched)
        assertEquals(emptyList<String>(), duplicate.orphanRegions)
        assertEquals(emptyList<String>(), duplicate.danglingMarkers)
    }

    /** (h) Two blocks sharing one excuse key are reported, so neither borrows the other's reason. */
    @Test
    fun `control - two blocks under one heading cannot share an excuse`() {
        val colliding = audit(
            FIXTURE_COLLIDING_GUIDE,
            emptyMap(),
            mapOf("json under Appendix" to Excuse("a fixture", CONTROL_CITATION)),
        )
        assertEquals(listOf("json under Appendix"), colliding.collidingExcuseKeys)
        // The excuse does silence the unexcused complaint, so the collision is the only finding.
        assertEquals(emptyList<String>(), colliding.unexcusedBlocks)
    }

    // ── Parsing ───────────────────────────────────────────────────────────

    /** Fence lines [blocksIn] would not parse, each located. Rule 7's whole content. */
    private fun unreadableFences(lines: List<String>): List<String> =
        lines.withIndex().filter { (_, line) ->
            val trimmed = line.trimStart()
            when {
                trimmed.startsWith("~~~") -> true
                !trimmed.startsWith("```") -> false
                trimmed != line -> true
                else -> !FENCE_OPEN.matches(line) && !FENCE_CLOSE.matches(line)
            }
        }.map { (index, line) -> "line ${index + 1}: $line" }

    private fun blocksIn(markdown: String): List<Block> {
        val lines = markdown.lines()
        val blocks = mutableListOf<Block>()
        var heading = "(no heading)"
        var index = 0
        while (index < lines.size) {
            HEADING.find(lines[index])?.let { heading = it.groupValues[1] }
            val open = FENCE_OPEN.find(lines[index])
            if (open == null) {
                index++
                continue
            }
            var cursor = index + 1
            val body = mutableListOf<String>()
            while (cursor < lines.size && !FENCE_CLOSE.matches(lines[cursor])) {
                body += lines[cursor]
                cursor++
            }
            check(cursor < lines.size) { "a fenced block opened at line ${index + 1} is never closed" }
            val marker = if (index > 0) MARKER.find(lines[index - 1]) else null
            blocks += Block(
                heading = heading,
                language = open.groupValues[1],
                markerFile = marker?.groupValues?.get(1),
                markerRegion = marker?.groupValues?.get(2),
                lines = body,
                lineNumber = index + 1,
            )
            index = cursor + 1
        }
        return blocks
    }

    /**
     * Every region in [source], each tagged with the scope chain it actually sits in.
     *
     * The scope is tracked by descending brace depth from the top of the file, not by walking up
     * to the nearest `fun` above the marker. The walk-up is the obvious implementation and it is
     * wrong in the direction that matters: a region inside a nested class, or inside any block
     * that merely *follows* a test function, would be attributed to that test and rule 5 would
     * wave it through. Rule 5 is the one claim here that has to be sound, because it is the whole
     * difference between a published snippet and a published paste.
     *
     * **[Region.isRunnable] asks the narrow question on purpose**: the chain must be exactly
     * `<a concrete, un-@Ignore'd top-level class> > <an un-@Ignore'd @Test function>`, and nothing
     * else. Every looser formulation tried here admitted code that compiles and never executes —
     * "the nearest `fun` above the marker is a `@Test`" admits a region in a nested class;
     * "the innermost enclosing function is a `@Test`" admits a `@Test` method *of* a nested class,
     * which the JUnit4 runner never collects, and an uninvoked lambda; asking nothing about the
     * enclosing type admits `@Ignore` on the class, which parks an entire suite with one line that
     * needs no import. Each of those was a live defect at some point in this file's history and
     * each is now a fixture in control (d).
     *
     * The cost of the narrow question is that a region may not sit inside an `if` or a lambda
     * within its test. That is a restriction on where a snippet may be marked, which is cheap,
     * rather than a claim that is false, which is not.
     *
     * A declaration is noticed before the braces on its own line are counted, so the `{` that
     * follows a signature — on the same line or three lines down — pushes the declaration rather
     * than an anonymous block. [CONTINUATION] is what decides when a signature has ended: a
     * declaration with no block body (`private class VaultAnswer(...)`, `fun probe() = Unit`) is
     * dropped at the end of its own line, so a later unrelated `{` cannot inherit it.
     */
    private fun regionsIn(fileName: String, source: String): List<Region> {
        val lines = source.lines()
        val regions = mutableListOf<Region>()
        val scopes = mutableListOf<Scope>()
        var pending: Scope? = null
        var pendingParens = 0
        var annotationParens = 0
        var inBlockComment = false
        var overPops = 0
        var sawTest = false
        var sawIgnore = false

        var openAt = -1
        var openName = ""
        var body = mutableListOf<String>()
        var placement = ""
        var runnable = false

        for ((index, line) in lines.withIndex()) {
            val start = REGION_START.find(line)
            if (start != null) {
                check(openAt < 0) {
                    "$fileName:${index + 1} opens region `${start.groupValues[1]}` before " +
                        "`$openName` was closed; regions do not nest"
                }
                openAt = index
                openName = start.groupValues[1]
                body = mutableListOf()
                placement = if (scopes.isEmpty()) {
                    "the top level of the file"
                } else {
                    scopes.joinToString(" > ") { it.description }
                }
                // Exactly `<collectable class> > <collectable @Test>`, per the KDoc above.
                runnable = scopes.size == 2 &&
                    scopes[0].isTestHost &&
                    scopes[1].isFunction &&
                    scopes[1].isTest
                continue
            }

            val end = REGION_END.find(line)
            if (end != null) {
                check(openAt >= 0 && end.groupValues[1] == openName) {
                    "$fileName:${index + 1} closes region `${end.groupValues[1]}`, which is not " +
                        "the open one (`${openName.ifEmpty { "none" }}`)"
                }
                regions += Region(
                    file = fileName,
                    name = openName,
                    lines = body,
                    lineNumber = openAt + 1,
                    placement = placement,
                    isRunnable = runnable,
                )
                openAt = -1
                continue
            }

            if (openAt >= 0) body += line

            val trimmed = line.trim()
            val parens = line.count { it == '(' } - line.count { it == ')' }

            // `/* … */` is the other way to take a test out of a run, and a `@Test` inside one is
            // not an annotation — nor is a commented-out `fun` a function, nor its braces braces.
            // Detected on a line *starting* with `/*` rather than containing it, so that a `"/*"`
            // string literal (this file has two) does not swallow the rest of the source.
            val insideBlockComment = inBlockComment || trimmed.startsWith("/*")
            if (!inBlockComment && trimmed.startsWith("/*") && !trimmed.endsWith("*/")) {
                inBlockComment = true
            } else if (inBlockComment && trimmed.endsWith("*/")) {
                inBlockComment = false
            }

            // A wrapped annotation — `@Ignore(\n    "reason",\n)` — is what a formatter produces
            // for a long one, and its continuation lines are not code. Letting them fall through
            // to `else` would clear the very annotation being written, which is how an `@Ignore`d
            // class reached rule 5 twice. Tracked by its own paren depth, like a signature.
            val insideAnnotation = annotationParens > 0
            annotationParens = when {
                insideBlockComment -> annotationParens
                insideAnnotation -> (annotationParens + parens).coerceAtLeast(0)
                trimmed.startsWith("@") -> parens.coerceAtLeast(0)
                else -> 0
            }

            val function = if (insideBlockComment) null else FUNCTION.find(line)
            val type = if (insideBlockComment || function != null) {
                null
            } else {
                TYPE_DECLARATION.find(line)
            }
            // Annotations on the declaration's own line count as much as ones above it:
            // `@Test fun x() {` is the idiomatic spelling and `@Ignore class Foo {` is the quiet
            // one. Taken from the regex's own first group rather than resplit off the line, for
            // the reason [ANNOTATIONS] gives.
            val head = (function ?: type)?.groupValues?.get(1).orEmpty()
            val testHere = sawTest || TEST_ANNOTATION.containsMatchIn(head)
            val ignoreHere = sawIgnore || IGNORE_ANNOTATION.containsMatchIn(head)
            when {
                function != null -> {
                    val name = function.groupValues[2].trim('`')
                    val collected = testHere && !ignoreHere
                    pending = Scope(
                        description = "fun $name" +
                            if (collected) "" else " [not a @Test JUnit collects]",
                        isFunction = true,
                        isTest = collected,
                        isTestHost = false,
                    )
                    sawTest = false
                    sawIgnore = false
                    pendingParens = parens
                }

                type != null -> {
                    val modifiers = type.groupValues[2]
                    val keyword = type.groupValues[3]
                    val name = type.groupValues[4]
                    // What JUnit4 can instantiate and run: a public, concrete `class` with a
                    // zero-argument constructor. Everything in NOT_A_TEST_HOST fails that — some
                    // of it loudly, with an `initializationError`, but a rule that waved those
                    // through would be relying on the runner to say what this test claims to.
                    val host = keyword == "class" &&
                        NOT_A_TEST_HOST.none { it in modifiers } &&
                        !ignoreHere
                    pending = Scope(
                        description = "$keyword ${name.trim('`').ifEmpty { "(anonymous)" }}" +
                            if (host) "" else " [not a class JUnit instantiates]",
                        isFunction = false,
                        isTest = false,
                        isTestHost = host,
                    )
                    sawTest = false
                    sawIgnore = false
                    pendingParens = parens
                }

                insideBlockComment -> Unit

                trimmed.startsWith("@") -> {
                    if (TEST_ANNOTATION.containsMatchIn(trimmed)) sawTest = true
                    if (IGNORE_ANNOTATION.containsMatchIn(trimmed)) sawIgnore = true
                }

                // A wrapped annotation's continuation lines, a comment or a blank line between an
                // annotation and its declaration are all legal Kotlin and change nothing about
                // what JUnit collects, so none of them may drop the annotation. Only real code in
                // between does — and that means the annotation belonged to something else.
                insideAnnotation -> Unit

                trimmed.isEmpty() || trimmed.startsWith("//") || trimmed.startsWith("*") -> Unit

                else -> {
                    sawTest = false
                    sawIgnore = false
                    if (pending != null) pendingParens += parens
                }
            }

            for (character in if (insideBlockComment) "" else line) {
                when (character) {
                    '{' -> {
                        scopes += pending ?: ANONYMOUS
                        pending = null
                        pendingParens = 0
                    }

                    // Counted rather than ignored: a `}` with nothing to pop means the brace
                    // tally is wrong — a stray one inside a string literal, say — and every
                    // region after it was attributed to a scope one level too shallow. Silently
                    // absorbing it is what let the end-of-file guard below see a balanced stack.
                    '}' -> if (scopes.isEmpty()) overPops++ else scopes.removeAt(scopes.lastIndex)
                }
            }

            // A declaration whose signature ended on this line without a `{` has no block body,
            // so it must not be left waiting to be claimed by the next brace in the file. An
            // unclosed parameter list, a trailing `,` `(` `:` `=` `->`, or a comment line inside a
            // multi-line signature all mean the declaration is still being written.
            val isComment = insideBlockComment || trimmed.startsWith("//") ||
                trimmed.startsWith("*")
            if (pending != null && pendingParens <= 0 && !isComment &&
                CONTINUATION.find(trimmed) == null
            ) {
                pending = null
            }
        }

        check(openAt < 0) { "$fileName:${openAt + 1} opens region `$openName` and never closes it" }
        // The scope scan counts every brace in the file, string literals and comments included, so
        // a file whose braces do not balance would have reported regions against the wrong scope.
        // Only files that actually carry regions can be harmed by it, and for those it is loud.
        check(regions.isEmpty() || (scopes.isEmpty() && overPops == 0)) {
            "braces do not balance in $fileName (${scopes.size} left open, $overPops closed with " +
                "nothing open), so the scope every region was attributed to is unreliable. A " +
                "brace inside a string literal or a comment is the usual cause, and it can cancel " +
                "out in the net count — which is why both halves are checked"
        }
        return regions
    }

    /**
     * The region's lines with its common leading indentation removed, and nothing else removed.
     *
     * A blank line inside a region is shorter than the indentation, so it maps to the empty
     * string rather than being sliced.
     */
    private fun dedented(lines: List<String>): List<String> {
        val indent = lines.filter { it.isNotBlank() }
            .minOfOrNull { line -> line.takeWhile { it == ' ' || it == '\t' }.length }
            ?: 0
        return lines.map { if (it.isBlank()) "" else it.substring(indent) }
    }

    private fun describeMismatch(block: Block, region: Region, expected: List<String>): String {
        val firstDifference = expected.zip(block.lines).indexOfFirst { (a, b) -> a != b }
        val detail = if (firstDifference >= 0) {
            "first difference at block line ${firstDifference + 1}:\n" +
                "    region: ${expected[firstDifference]}\n" +
                "    guide : ${block.lines[firstDifference]}"
        } else {
            "the region has ${expected.size} lines and the block has ${block.lines.size}"
        }
        return "${block.marker} (${region.file}:${region.lineNumber}) — ${block.where} is not " +
            "its region verbatim; $detail"
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

    private fun guideFile(): File = locate(GUIDE_PATH)

    /**
     * Every Kotlin test source, keyed by file name — what a marker names.
     *
     * Walked recursively rather than listed one directory deep: rule 4's claim is about *every*
     * test source, and a test added under a subpackage would otherwise be able to carry an orphan
     * region no assertion here could see. Two files sharing a name would make a marker ambiguous,
     * so that fails loudly rather than resolving to whichever the walk reached last.
     */
    private fun testSources(): Map<String, String> {
        val root = locate(TEST_SOURCE_ROOT)
        val sources = root.walkTopDown().filter { it.isFile && it.name.endsWith(".kt") }.toList()
        check(sources.isNotEmpty()) { "no Kotlin test sources under ${root.absolutePath}" }
        val shared = sources.groupBy { it.name }.filterValues { it.size > 1 }.keys.sorted()
        check(shared.isEmpty()) {
            "two test sources share a file name ($shared), so a `<!-- snippet: File.kt#r -->` " +
                "marker could not name one of them unambiguously"
        }
        return sources.associate { it.name to it.readText() }
    }

    /**
     * [relative], located by walking up from the working directory.
     *
     * `RedactionVisibilityTest`'s walk-up, for its reason: the working directory of a Gradle unit
     * test is the module directory, but that is a default rather than a promise, so every ancestor
     * is tried both as the module root and as the repository root. If none of them holds it, the
     * test *fails naming every absolute path it tried* — a scanner that silently finds nothing
     * passes for ever, and this one's whole subject is files on disk.
     */
    private fun locate(relative: String): File {
        val workingDirectory = File(".").absoluteFile.normalize()
        val tried = mutableListOf<File>()
        var directory: File? = workingDirectory
        while (directory != null) {
            for (candidate in listOf(File(directory, relative), File(directory, "LIM/$relative"))) {
                tried += candidate
                if (candidate.exists()) return candidate
            }
            directory = directory.parentFile
        }
        throw AssertionError(
            "cannot find `$relative` — this test pins the guide against its sources and must " +
                "not be silently skipped. Working directory: $workingDirectory. Tried:\n" +
                tried.map { it.absolutePath }.distinct().joinToString("\n"),
        )
    }

    // ── Fixtures ──────────────────────────────────────────────────────────

    private fun fixtureAudit(excuses: Map<String, Excuse> = FIXTURE_EXCUSES): Audit =
        audit(FIXTURE_GUIDE, mapOf("FixtureTest.kt" to FIXTURE_SOURCE), excuses)

    private companion object {
        private const val GUIDE_PATH = "docs/INTEGRATION.md"
        private const val TEST_SOURCE_ROOT = "src/test/java"
        private const val MODULE_BUILD_FILE = "LIM/build.gradle.kts"
        private const val SETTINGS_FILE = "settings.gradle.kts"

        /** The one fence language the marker rule binds. Everything else needs an excuse. */
        private const val SNIPPET_LANGUAGE = "kotlin"

        /** The on-disk measurement, shared across this class's test instances. See [onDisk]. */
        private var cachedOnDisk: Audit? = null

        /** A brace that opens no declaration: a lambda, an `if`, an `apply`. */
        private val ANONYMOUS = Scope(
            description = "an anonymous block",
            isFunction = false,
            isTest = false,
            isTestHost = false,
        )

        private val HEADING = Regex("""^#{1,6}\s+(.+?)\s*$""")
        private val SECTION = Regex("""(?m)^##\s+(.+?)\s*$""")
        private val FENCE_OPEN = Regex("""^```(\w*)\s*$""")
        private val FENCE_CLOSE = Regex("""^```\s*$""")
        private val MARKER = Regex("""^<!--\s*snippet:\s*(\S+)#(\S+)\s*-->\s*$""")
        private val REGION_START = Regex("""^\s*// region snippet:(\S+)\s*$""")
        private val REGION_END = Regex("""^\s*// endregion snippet:(\S+)\s*$""")
        /**
         * A leading run of annotations, allowed on a declaration's own line.
         *
         * Without this, `@Test fun x() {` — the idiomatic single-line spelling — matches neither
         * [FUNCTION] nor an annotation branch, so the `{` opens an anonymous scope and rule 5
         * *rejects* a region JUnit genuinely runs, with a message blaming the scope instead of the
         * formatting.
         *
         * **Captured, so the annotations are read out of the match rather than resplit off the
         * raw line.** Splitting on the first literal `class` is the obvious shortcut and it is
         * wrong on the single commonest line in this suite: `@RunWith(SomeRunner::class)` contains
         * the keyword inside its own argument, so everything to its right — including an `@Ignore`
         * that parks the entire class — fell outside the split and was never seen.
         */
        private const val ANNOTATIONS = """((?:@[\w.]+(?:\([^)]*\))?\s+)*)"""

        /** Groups: 1 the annotations, 2 the name. */
        private val FUNCTION = Regex(
            """^\s*$ANNOTATIONS""" +
                """(?:(?:private|internal|public|protected|override|open|suspend|inline|""" +
                """operator|infix|tailrec|external)\s+)*""" +
                """fun\s+(?:<[^>]+>\s*)?(`[^`]+`|[A-Za-z_]\w*)""",
        )

        /**
         * Groups: 1 the annotations, 2 the modifiers, 3 the keyword, 4 the name. The first three
         * all decide [Scope.isTestHost].
         */
        private val TYPE_DECLARATION = Regex(
            """^\s*$ANNOTATIONS((?:(?:private|internal|public|protected|abstract|open|sealed|""" +
                """data|enum|annotation|value|inner|companion)\s+)*)(class|object|interface)\b\s*""" +
                """(`[^`]+`|[A-Za-z_]\w*)?""",
        )

        /**
         * Modifiers that stop JUnit4 from instantiating a class, so a `@Test` inside it is never
         * called. `private` and `protected` leave it inaccessible to the runner; the rest cannot
         * offer a zero-argument constructor. `internal` is absent on purpose — it compiles to
         * public, so the runner reaches it.
         */
        private val NOT_A_TEST_HOST = listOf(
            "abstract", "sealed", "enum", "annotation", "data", "value", "inner",
            "private", "protected",
        )
        /**
         * `@Test` and `@Ignore`, either spelling.
         *
         * The optional package prefix is not pedantry: `@org.junit.Ignore("why")` needs no import
         * and is therefore the *easier* way to park a test, so a prefix-blind check would let the
         * one annotation that silently removes a region from the run do exactly that. Matched with
         * `containsMatchIn`, against a line already known to start with `@` or against the text
         * before a declaration's keyword — never against arbitrary prose, so the missing `^` costs
         * nothing.
         */
        private val TEST_ANNOTATION = Regex("""@(?:[\w.]+\.)?Test\b""")
        private val IGNORE_ANNOTATION = Regex("""@(?:[\w.]+\.)?Ignore\b""")

        /** A line whose declaration is unfinished: a parameter list or an assignment continues. */
        private val CONTINUATION = Regex("""(?:[,(:=]|->)$""")
        private val COORDINATES =
            Regex("""coordinates\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)""")
        private val INCLUDE = Regex("""include\("\s*:([A-Za-z_][\w\-]*)"\)""")

        /** Pinned by name so the guide cannot ship half-written. */
        private val REQUIRED_SECTIONS = listOf(
            "Setup",
            "If you minify your app",
            "Before you start: is there a vault?",
            "Sign-up (share)",
            "Query",
            "Login (sign-challenge)",
            "When the user says no",
            "Rules you must not break",
        )

        /**
         * The published surface an afternoon integration actually touches: ask whether there is a
         * vault, send, parse, correlate, challenge, verify, expire. Every one must be *called* in
         * at least one region, and the names are grouped in the order the guide's sections come in
         * — a reading aid, not a claim: nothing asserts order against the guide, and within a
         * section the guide shows `matchesRequestCode` and `isNonceFresh` before the parse and the
         * verify they guard.
         */
        private val CORE_LOOP = listOf(
            "shareEntry",
            "createShareIntent",
            "parseShareResult",
            "createQueryIntent",
            "parseQueryResult",
            "matchesRequestCode",
            "generateNonce",
            "createSignChallengeIntent",
            "parseSignChallengeResult",
            "isVerified",
            "isNonceFresh",
        )

        /**
         * The fenced blocks the marker rule does not bind, each with a reason and the test that
         * covers it instead. Keyed by fence language and heading — which is why no two of them
         * may sit under the same heading, and why a block that moves sections has to be looked at
         * by somebody.
         */
        private val NOT_A_SNIPPET: Map<String, Excuse> = mapOf(
            "gradle under Setup" to Excuse(
                reason = "the dependency declaration a consumer writes in their own build file. " +
                    "No test here can run it — the artifact is not published anywhere " +
                    "resolvable as of this commit — so what is pinned instead is the one part " +
                    "that can go stale silently: the version it prints",
                coveredBy = "GuideSnippetTest: the guide prints the coordinate the build file declares",
            ),
            "gradle under Until then: build from source" to Excuse(
                reason = "a consumer project's own build file, which this repository cannot " +
                    "execute — the guide says as much in that section rather than implying " +
                    "otherwise. What is pinned is every name in it: the Gradle project path, " +
                    "the artifact the assemble task writes, and the Gson coordinate a bare AAR " +
                    "does not carry",
                coveredBy = "GuideSnippetTest: the build-from-source path names what the build declares",
            ),
            "proguard under If you minify your app" to Excuse(
                reason = "the keep rules a consumer copies into their own ProGuard file when they " +
                    "vendor the AAR. Nothing in this repository runs R8 over this library — the " +
                    "module builds with `isMinifyEnabled = false`, which is correct for a library " +
                    "because R8 runs in the consumer's build — so whether these rules do their job " +
                    "is not measurable from here, and that section is one of the places this " +
                    "project says so in as many words. What is pinned is the block's own content: " +
                    "the cited test holds its directive lines set-equal to " +
                    "`LIM/consumer-rules.pro`, the file this library actually ships, in both " +
                    "directions and in the same order, so the guide cannot print a rule set the " +
                    "AAR does not carry",
                coveredBy = "ConsumerRulesTest: the integration guide prints the rules this file ships",
            ),
            "xml under Before you start: is there a vault?" to Excuse(
                reason = "the `<queries>` element a consumer adds to their *own* manifest, so that " +
                    "an installed vault is visible to them on Android 11+. Nothing in this " +
                    "repository can execute a consumer's manifest, and this library ships no such " +
                    "element of its own — that is a manifest change and a human decision — so the " +
                    "XML itself is unverifiable from here and is not pretended otherwise. What is " +
                    "pinned is the behaviour the element buys: the cited test is the branch a " +
                    "caller reaches when no vault answers, which is what the element's absence " +
                    "makes indistinguishable from a device with no vault at all",
                coveredBy = "ShareEntryTest: shareEntry returns false and starts nothing when no " +
                    "vault handles it",
            ),
        )

        /** What the fixture excuses cite: this file's own control, which is a real `@Test`. */
        private const val CONTROL_CITATION =
            "GuideSnippetTest: control - an unexcused block and a dead excuse are both reported"

        /**
         * The controls' fixture test source, and the reason it is assembled from one-line literals
         * rather than written as a raw string is load-bearing rather than fussy.
         *
         * The real scanner reads **every** Kotlin test source, this file among them. In a raw
         * string the markers below would begin their lines, so this file's own fixtures would be
         * collected as real regions, quoted by no block, and `every region is quoted by exactly
         * one block` would fail on its own controls. Written this way each marker sits behind an
         * opening `"`, and [REGION_START] anchors at the start of the line. If somebody converts
         * them anyway, the failure is loud rather than silent: three orphans and a rule-5
         * violation.
         */
        private val FIXTURE_SOURCE = listOf(
            "// region snippet:toplevel",
            "val atTheTopOfTheFile = 0",
            "// endregion snippet:toplevel",
            "",
            "class FixtureTest {",
            "",
            "    @Test fun `a fixture test on one line`() {",
            "        // region snippet:one-line",
            "        val answer = 33",
            "        // endregion snippet:one-line",
            "    }",
            "",
            "    @Test",
            "    fun `a fixture test whose region hides in a block`() {",
            "        if (true) {",
            "            // region snippet:nested-block",
            "            val answer = 55",
            "            // endregion snippet:nested-block",
            "        }",
            "    }",
            "",
            "    @Test",
            "    fun `a fixture test`() {",
            "        // region snippet:quoted",
            "        val answer = 42",
            "        // endregion snippet:quoted",
            "    }",
            "",
            "    /** Annotated, and quoted by nothing. */",
            "    @Test",
            "    fun `a fixture test whose region the guide forgot`() {",
            "        // region snippet:orphan",
            "        val answer = 99",
            "        // endregion snippet:orphan",
            "    }",
            "",
            "    fun `a fixture helper JUnit never runs`() {",
            "        // region snippet:untested",
            "        val answer = 44",
            "        // endregion snippet:untested",
            "    }",
            "",
            "    @Test",
            "    @org.junit.Ignore(\"a fixture, in the spelling that needs no import\")",
            "    fun `a fixture test taken back out of the run`() {",
            "        // region snippet:ignored",
            "        val answer = 77",
            "        // endregion snippet:ignored",
            "    }",
            "",
            "    @Test",
            "    fun `a fixture expression-bodied test`() = Unit",
            "    private val neverInvoked: () -> Unit = {",
            "        // region snippet:lambda",
            "        val answer = 88",
            "        // endregion snippet:lambda",
            "    }",
            "",
            // A test commented out wholesale. Every signal survives — the annotation, the name,
            // the body — and JUnit runs none of it.
            "    /*",
            "    @Test",
            "    fun `a fixture test commented out wholesale`() {",
            "        // region snippet:commented-out",
            "        val answer = 66",
            "        // endregion snippet:commented-out",
            "    }",
            "    */",
            "",
            "    /* @Test */",
            "    fun `a fixture helper whose annotation is commented out`() {",
            "        // region snippet:commented-annotation",
            "        val answer = 67",
            "        // endregion snippet:commented-annotation",
            "    }",
            "",
            "    private class NeverInstantiated {",
            "        // region snippet:nested",
            "        val neverExecuted = 1",
            "        // endregion snippet:nested",
            "",
            "        @Test",
            "        fun `annotated, and still never collected by the runner`() {",
            "            // region snippet:nested-test",
            "            val neverExecuted = 2",
            "            // endregion snippet:nested-test",
            "        }",
            "    }",
            "}",
        ).joinToString("\n")

        /** The controls' fixture guide: one of each defect, and one block that is correct. */
        private val FIXTURE_GUIDE = listOf(
            "## Fixtures",
            "",
            "<!-- snippet: FixtureTest.kt#toplevel -->",
            "```kotlin",
            "val atTheTopOfTheFile = 0",
            "```",
            "",
            "<!-- snippet: FixtureTest.kt#one-line -->",
            "```kotlin",
            "val answer = 33",
            "```",
            "",
            "<!-- snippet: FixtureTest.kt#nested-block -->",
            "```kotlin",
            "val answer = 55",
            "```",
            "",
            "<!-- snippet: FixtureTest.kt#quoted -->",
            "```kotlin",
            "val answer = 43",
            "```",
            "",
            "<!-- snippet: FixtureTest.kt#untested -->",
            "```kotlin",
            "val answer = 44",
            "```",
            "",
            "<!-- snippet: FixtureTest.kt#ignored -->",
            "```kotlin",
            "val answer = 77",
            "```",
            "",
            "<!-- snippet: FixtureTest.kt#lambda -->",
            "```kotlin",
            "val answer = 88",
            "```",
            "",
            "<!-- snippet: FixtureTest.kt#commented-out -->",
            "```kotlin",
            "val answer = 66",
            "```",
            "",
            "<!-- snippet: FixtureTest.kt#commented-annotation -->",
            "```kotlin",
            "val answer = 67",
            "```",
            "",
            "<!-- snippet: FixtureTest.kt#nested -->",
            "```kotlin",
            "val neverExecuted = 1",
            "```",
            "",
            "<!-- snippet: FixtureTest.kt#nested-test -->",
            "```kotlin",
            "val neverExecuted = 2",
            "```",
            "",
            "<!-- snippet: FixtureTest.kt#never-written -->",
            "```kotlin",
            "val answer = 45",
            "```",
            "",
            "```kotlin",
            "val answer = 46",
            "```",
            "",
            "## Fixture appendix",
            "",
            "```json",
            "{}",
            "```",
        ).joinToString("\n")

        /** Excuses for the fixture guide, so only the defect under test is reported. */
        private val FIXTURE_EXCUSES: Map<String, Excuse> = mapOf(
            "json under Fixture appendix" to Excuse(
                reason = "a fixture block, excused so the controls above report one defect each",
                coveredBy = CONTROL_CITATION,
            ),
        )

        /**
         * Control (i): the two top-level declarations JUnit never instantiates, each with a
         * genuine `@Test` method holding a region. Separate from [FIXTURE_SOURCE] because that
         * fixture's own class has to stay collectable for `#quoted` and `#one-line` to be accepted.
         */
        private val FIXTURE_UNCOLLECTED_SOURCE = listOf(
            "@org.junit.Ignore(\"the whole suite is parked, with one line and no import\")",
            "class IgnoredClassTest {",
            "    @Test",
            "    fun `a real test in a parked class`() {",
            "        // region snippet:ignored-class",
            "        val answer = 11",
            "        // endregion snippet:ignored-class",
            "    }",
            "}",
            "",
            "abstract class AbstractBaseTest {",
            "    @Test",
            "    fun `a real test in a class nothing instantiates`() {",
            "        // region snippet:abstract-class",
            "        val answer = 12",
            "        // endregion snippet:abstract-class",
            "    }",
            "}",
            "",
            // The shape that reopened this hole once: the keyword `class` appears inside the
            // runner annotation's own argument, so anything to its right — the `@Ignore` that
            // parks the suite — is missed by a parser that splits the line on `class`.
            "@RunWith(SomeRunner::class) @org.junit.Ignore(\"parked on its own line\") " +
                "class OneLineIgnoredTest {",
            "    @Test",
            "    fun `a real test in a class parked on the declaration line`() {",
            "        // region snippet:ignored-one-line",
            "        val answer = 13",
            "        // endregion snippet:ignored-one-line",
            "    }",
            "}",
            "",
            // And the spelling a formatter produces for a long reason: the annotation's argument
            // list spans lines, so its continuation is neither code nor an annotation line.
            "@org.junit.Ignore(",
            "    \"a reason long enough that the formatter wrapped it onto its own line\",",
            ")",
            "class WrappedIgnoreTest {",
            "    @Test",
            "    fun `a real test in a class parked by a wrapped annotation`() {",
            "        // region snippet:ignored-wrapped",
            "        val answer = 14",
            "        // endregion snippet:ignored-wrapped",
            "    }",
            "}",
        ).joinToString("\n")

        private val FIXTURE_UNCOLLECTED_GUIDE = listOf(
            "## Uncollected",
            "",
            "<!-- snippet: Uncollected.kt#ignored-class -->",
            "```kotlin",
            "val answer = 11",
            "```",
            "",
            "<!-- snippet: Uncollected.kt#abstract-class -->",
            "```kotlin",
            "val answer = 12",
            "```",
            "",
            "<!-- snippet: Uncollected.kt#ignored-one-line -->",
            "```kotlin",
            "val answer = 13",
            "```",
            "",
            "<!-- snippet: Uncollected.kt#ignored-wrapped -->",
            "```kotlin",
            "val answer = 14",
            "```",
        ).joinToString("\n")

        /**
         * Control (k): one region, two blocks. Both are verbatim the region, so the only honest
         * complaint is the double-quoting itself.
         */
        private val FIXTURE_DOUBLE_GUIDE = listOf(
            "## Doubled",
            "",
            "<!-- snippet: FixtureTest.kt#quoted -->",
            "```kotlin",
            "val answer = 42",
            "```",
            "",
            "<!-- snippet: FixtureTest.kt#quoted -->",
            "```kotlin",
            "val answer = 42",
            "```",
        ).joinToString("\n")

        /** Control (g): one name, two regions, and a guide block that is verbatim the first. */
        private val FIXTURE_DUPLICATE_SOURCE = listOf(
            "class DupTest {",
            "",
            "    @Test",
            "    fun `the first`() {",
            "        // region snippet:twice",
            "        val answer = 1",
            "        // endregion snippet:twice",
            "    }",
            "",
            "    @Test",
            "    fun `the second`() {",
            "        // region snippet:twice",
            "        val answer = 2",
            "        // endregion snippet:twice",
            "    }",
            "}",
        ).joinToString("\n")

        private val FIXTURE_DUPLICATE_GUIDE = listOf(
            "## Duplicates",
            "",
            "<!-- snippet: DupTest.kt#twice -->",
            "```kotlin",
            "val answer = 1",
            "```",
        ).joinToString("\n")

        /** Control (h): two blocks of one language under one heading, hence one excuse key. */
        private val FIXTURE_COLLIDING_GUIDE = listOf(
            "## Appendix",
            "",
            "```json",
            "{}",
            "```",
            "",
            "```json",
            "[]",
            "```",
        ).joinToString("\n")
    }
}
