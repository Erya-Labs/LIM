package dev.eryalabs.lim

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * `docs/INTEGRATION.md` and `docs/VAULT.md` are the library's whole adoption surface — one page for
 * each half of the wire — and prose rots. This test is what stops it: **every fenced Kotlin block
 * in either document is a region of a test source, quoted verbatim.**
 *
 * A document marks each block with an HTML comment naming its source —
 * `<!-- snippet: GuideExamplesTest.kt#login-result -->` — and the test source wraps the quoted
 * lines in `// region snippet:login-result` … `// endregion snippet:login-result`. Seven properties
 * hold the pair together:
 *
 *  1. every ` ```kotlin ` block carries a marker;
 *  2. every marker resolves to a region that exists;
 *  3. every block equals its region verbatim, after stripping the region's common leading
 *     indentation and nothing else;
 *  4. every region in every test source is quoted by **exactly one** block **in the whole document
 *     set** — so a marker left behind after an edit fails as surely as a missing one — and no two
 *     regions share a name, because an ambiguous name is not compared against anything;
 *  5. every region sits **directly in the body of an un-`@Ignore`d `@Test` method of the
 *     top-level test class**, which is what makes a printed snippet *evidence*: each line in a
 *     document is a line JUnit executed to get this suite green. Anything looser admits code that
 *     compiles and never runs — a helper, a nested class, a `@Test` method *of* a nested class
 *     (which the JUnit4 runner does not collect), an uninvoked lambda, an `@Ignore`d test;
 *  6. every fenced block in any other language is excused by name in [NOT_A_SNIPPET], with a
 *     reason and a test that covers it instead;
 *  7. every fence in either document is one this test can see — an indented or `~~~` fence is
 *     refused rather than silently skipped.
 *
 * **Which of the seven are per-document and which are tree-wide is the one thing to get right
 * here.** Rules 1, 2, 3, 6 and 7 are properties of a document and are asked of each on its own —
 * including rule 1's non-vacuity floor, which compares a document's Kotlin blocks against **its
 * own** [SNIPPET_DOCUMENTS] section list, because a floor computed over the union would be
 * satisfied by the guide's nineteen blocks while a second document published none. Rule 4 is the
 * opposite: "every region is quoted by exactly one block" is a claim about the *tree*, so it is
 * computed across the union of every document. Spelled per-document it would report every region
 * the other page quotes as an orphan, which is what reddened the day `docs/VAULT.md` arrived.
 * [Block.excuseKey] carries the document for the same reason: two pages may legitimately use the
 * same heading, and one page's excuse may not cover the other's block.
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
 * writing. Whether either page reads well is a human judgement (VISION), and an assertion
 * pretending otherwise would be worse than none.
 *
 * Regex over text, so it runs in milliseconds: no Robolectric, no reflection beyond resolving the
 * excuses' citations. The text is six things, not two — the two documents, every Kotlin test
 * source, `README.md`, `LIM/build.gradle.kts` and `settings.gradle.kts`, every one of them reached
 * through [locate]. "Two files" here was false from this class's first commit, which landed the
 * coordinate pin, the build-from-source pin and the README link test beside the snippet rules and
 * beside that sentence — not falsified later by something added since. The *pairwise* sense of
 * "two files" — one block against one region — is the one that was always true, so the two places
 * that use it, the next section's heading and [Audit]'s own KDoc, are left exactly as they were.
 */
class GuideSnippetTest {

    // ── What the two files contain ────────────────────────────────────────

    /** A fenced block in one of the documents, with the marker above it if it has one. */
    private class Block(
        /** Which document it came from — rules 1, 6 and 7 are asked of each one on its own. */
        val document: String,
        val heading: String,
        val language: String,
        val markerFile: String?,
        val markerRegion: String?,
        val lines: List<String>,
        val lineNumber: Int,
    ) {
        /** `GuideExamplesTest.kt#login-result`, or null for a block with no marker. */
        val marker: String? = markerFile?.let { "$it#$markerRegion" }

        val where: String =
            "the `$language` block at $document:$lineNumber under \"$heading\""

        /**
         * The key [NOT_A_SNIPPET] is spelled with: fence language, heading and document.
         *
         * **The document is part of the key, and leaving it out was the bug waiting to happen.**
         * Two pages may legitimately carry the same heading — and if one of them excuses a
         * ` ```json ` block under *Appendix*, that excuse would silently cover a completely
         * different block under the other page's *Appendix*, which is the one thing an excuse map
         * exists to prevent. Qualifying it also keeps the dangling-excuse rule sharp: an excuse
         * naming a heading only the *other* document has is now reported rather than resolved.
         */
        val excuseKey: String = "$language under $heading in $document"
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
        /** The regions a marker can resolve to: every region whose name is unique. See [audit]. */
        private val byId: Map<String, Region>,
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

        /** [document]'s own Kotlin blocks. Rule 1's floor is asked of each document. */
        fun kotlinBlocksIn(document: String): List<Block> =
            kotlinBlocks.filter { it.document == document }

        /**
         * The regions [document]'s own blocks quote.
         *
         * The counterpart of [regions], which is every region in the tree and is what rule 4 has
         * to be measured over. A **coverage** floor is the opposite kind of claim — it is about
         * one document's content — so measuring one over [regions] would let a region quoted only
         * by the vault page satisfy the guide's floor with nobody able to see it. See
         * `every function in the core loop is called in a snippet`.
         */
        fun regionsQuotedBy(document: String): List<Region> =
            kotlinBlocksIn(document).mapNotNull { block -> block.marker?.let(byId::get) }
    }

    // ── The one measurement every assertion below reads ───────────────────

    /**
     * The documents against every Kotlin test source.
     *
     * The *sources* are every `.kt` file rather than `GuideExamplesTest.kt` alone, because rule 4
     * is a claim about all of them: a region marked anywhere in the suite and quoted nowhere is
     * exactly the stale marker this test exists to find.
     *
     * **The documents are taken together, and rule 4 is the reason.** A per-document audit would
     * report every region the *other* page quotes as an orphan, which is precisely what happened
     * the day a second document arrived carrying regions of its own: the only spelling under which
     * "every region is quoted by exactly one block" stays true of the tree is the union. Each
     * [Block] carries the document it came from, so the complaints that *are* per-document — rules
     * 1, 6 and 7 — still name it.
     *
     * A region whose name is duplicated is held out of the verbatim, orphan and dangling-marker
     * answers entirely rather than being resolved arbitrarily. Resolving it would report a block
     * that *is* verbatim one of its regions as drifted from the other, naming neither — a wrong
     * answer dressed as a precise one. Rule 4 reports the duplication instead and nothing else
     * speaks about those names until it is fixed.
     */
    private fun audit(
        documents: Map<String, String>,
        sources: Map<String, String>,
        excuses: Map<String, Excuse>,
    ): Audit {
        val blocks = documents.entries.sortedBy { it.key }.flatMap { blocksIn(it.key, it.value) }
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
            byId = byId,
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
     * Both documents against every test source, measured once for the whole class.
     *
     * JUnit constructs a fresh instance per test method, so a per-instance `by lazy` re-read and
     * re-parsed all 38 sources 22 times over and took this file from 0.3s to 1.1s — for a file
     * whose whole claim on the suite is that it is regex over text and costs nothing. The files
     * cannot change within a run, and a mutation to any one of them re-runs the class from
     * scratch.
     */
    private fun onDisk(): Audit = cachedOnDisk
        ?: audit(documentsOnDisk(), testSources(), NOT_A_SNIPPET).also { cachedOnDisk = it }

    /**
     * Rule 1's non-vacuity floor, per document — a document must carry at least as many Kotlin
     * blocks as it names required sections.
     *
     * Extracted so that the one way this can be got wrong is falsifiable. Spelled over the union
     * (`audit.kotlinBlocks.size >= oneList.size`, which is what it was while there was only one
     * document) it passes with an entirely codeless second page, because the guide's nineteen
     * blocks already clear any one list — see
     * `control - the Kotlin-block floor is asked of each document on its own`.
     *
     * The floor is *not* a claim that the blocks are distributed across the sections: a document
     * with every block under one heading satisfies it. What it closes is a scanner that found no
     * blocks at all, which would make the rule above report no offenders for ever.
     */
    private fun blockFloorShortfalls(
        audit: Audit,
        required: Map<String, List<String>>,
    ): List<String> = required.entries.sortedBy { it.key }.mapNotNull { (document, sections) ->
        val found = audit.kotlinBlocksIn(document).size
        "$document carries $found Kotlin block(s) for ${sections.size} required section(s)"
            .takeIf { found < sections.size }
    }

    /**
     * A coverage floor's measurement, shared by both pages: the names in [required] that appear
     * in no **executed line** of [regions].
     *
     * Two decisions live here rather than in either caller, so that neither page can be measured
     * more leniently than the other. **Trailing comments are stripped, not only comment-only
     * lines** — `val x = 1 // then call parseQueryResult` would otherwise satisfy a floor with a
     * mention rather than a call, which is exactly how a page could document a function it never
     * demonstrates. And the needle is a plain substring of the remaining code, so
     * `Utils.parseQueryResult(intent)` counts and so does a qualified or chained spelling; the
     * cost is that a *different* function whose name contains one of these would count too, which
     * is why the lists are published names rather than fragments.
     *
     * The regions passed in are always one document's own — see [Audit.regionsQuotedBy] — because
     * a coverage claim is about one page's content and a floor over the union would let one page
     * satisfy another's.
     *
     * `control - a coverage floor measures code and not a trailing comment` is the control for
     * the stripping, both ways round over one fixture region.
     */
    private fun coverageShortfalls(regions: List<Region>, required: List<String>): List<String> =
        executedCode(regions).let { code -> required.filterNot { it in code } }

    /** [regions]' lines with trailing comments stripped — what [coverageShortfalls] searches. */
    private fun executedCode(regions: List<Region>): String =
        regions.flatMap { it.lines }.map { it.substringBefore("//") }.joinToString("\n")

    // ── The seven properties ──────────────────────────────────────────────

    @Test
    fun `every Kotlin block in a document names a region`() {
        assertEquals(
            "a fenced `$SNIPPET_LANGUAGE` block in either document must be preceded by " +
                "`<!-- snippet: File.kt#region -->`. An unmarked block is prose that compiled " +
                "once and is pinned by nothing, which is the whole failure this test exists to " +
                "prevent",
            emptyList<String>(),
            onDisk().unmarkedKotlinBlocks,
        )
        assertEquals(
            "each document must carry Kotlin blocks of its own for the rule above to mean " +
                "anything, and the floor is its own section list rather than the set's. A floor " +
                "computed over every document together is cleared by the guide alone — " +
                "${onDisk().kotlinBlocksIn(GUIDE_PATH).size} blocks against the longest list " +
                "here — so a second document could publish no code at all and stay green. " +
                "Shortfalls",
            emptyList<String>(),
            blockFloorShortfalls(onDisk(), SNIPPET_DOCUMENTS),
        )
    }

    @Test
    fun `every marker resolves to a region that exists`() {
        assertEquals(
            "a marker in a document names a region no test source contains — a renamed or " +
                "deleted region leaves the document quoting nothing while still looking quoted",
            emptyList<String>(),
            onDisk().danglingMarkers,
        )
    }

    @Test
    fun `every block in a document is its region verbatim`() {
        assertEquals(
            "a block in one of the documents has drifted from the region it quotes. The document " +
                "is not edited to match: the region is the source of truth, so change the test " +
                "and copy it across",
            emptyList<String>(),
            onDisk().mismatched,
        )
        // Floor: a comparison over zero pairs is also equal.
        assertTrue(
            "no block resolved to a region, so nothing was compared",
            onDisk().kotlinBlocks.count { it.marker != null } > 0,
        )
    }

    /**
     * Rule 4, and the one rule here that is **tree-wide rather than per-document**.
     *
     * "Quoted by exactly one block" is a claim about the whole document set: a region the vault
     * page quotes is not an orphan merely because the guide does not quote it, and a region each
     * page quotes once is doubly quoted even though neither page quotes it twice. Asked of one
     * document at a time it would report the other page's every region, which is exactly the red
     * the day `docs/VAULT.md` arrived.
     */
    @Test
    fun `every region is quoted by exactly one block`() {
        assertEquals(
            "two regions share a name. Nothing resolves an ambiguous marker, so neither of " +
                "them is compared against either document at all until one is renamed — which " +
                "is a quieter failure than a mismatch and the reason this is its own assertion",
            emptyList<String>(),
            onDisk().duplicateRegionNames,
        )
        assertEquals(
            "a region is marked in a test source and quoted by no block in any document. " +
                "Either a document lost the block, or the markers were left behind by an edit — " +
                "a stale marker is a claim that something is published when it is not",
            emptyList<String>(),
            onDisk().orphanRegions,
        )
        assertEquals(
            "a region is quoted by two blocks — in one document or across both — so one of " +
                "them can drift out of its page's narrative while every verbatim check stays " +
                "green",
            emptyList<String>(),
            onDisk().doublyQuotedRegions,
        )
        assertTrue("no regions were found at all, so this proves nothing", onDisk().regions.isNotEmpty())
        println(
            "GuideSnippetTest: ${onDisk().regions.size} regions in " +
                "${onDisk().regions.map { it.file }.distinct().size} source(s), " +
                "${onDisk().kotlinBlocks.size} Kotlin blocks, " +
                "${onDisk().blocks.size - onDisk().kotlinBlocks.size} excused block(s) — " +
                SNIPPET_DOCUMENTS.keys.sorted().joinToString(", ") {
                    "$it: ${onDisk().kotlinBlocksIn(it).size} Kotlin of " +
                        "${onDisk().blocks.count { block -> block.document == it }}"
                },
        )
    }

    /**
     * The strongest claim here, and the reason a snippet is evidence rather than paste: the lines
     * either document prints are lines JUnit ran.
     *
     * A region in a helper, in an `@Ignore`d test, in an uninvoked lambda, in a nested class body,
     * or in a `@Test` method of a nested class is all still real compiling code — and still never
     * executes, so it could be wrong in any way that compiles. Control (d) below drives all five
     * shapes through this same answer and asserts each is reported.
     *
     * **This is also the rule that forbids lifting a snippet off one of this repository's fixture
     * vaults**, however close one of them already is to what a page needs to show. Every one of
     * them — `ClientIntegrationExampleTest`'s `Vault` and `SignUpVault`, `GuideExamplesTest`'s
     * `FixtureVault` and `RequiredFieldsVault`, `RequirementsCompatibilityMatrixTest`'s `V0`, `V1`
     * and `V2` — is a **nested** class, so the runner collects none of their methods and this rule
     * reports a region in any of them. A vault page's blocks are written as straight-line code in
     * `@Test` bodies of a top-level class for that reason and no other.
     */
    @Test
    fun `every quoted region sits inside a function JUnit runs`() {
        assertEquals(
            "a region's enclosing function is not annotated `@Test`, so a document is printing " +
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
                "NOT_A_SNIPPET, keyed by fence language, heading and document, by somebody who " +
                "wrote down why",
            emptyList<String>(),
            onDisk().unexcusedBlocks,
        )
        assertEquals(
            "NOT_A_SNIPPET names a block no document contains. A rewritten heading, a deleted " +
                "block or a heading that exists only on the *other* page leaves a dead excuse " +
                "behind, and a dead excuse would wave through the next block that happens to " +
                "land under that key",
            emptyList<String>(),
            onDisk().danglingExcuses,
        )
        assertEquals(
            "two fenced blocks in the same document share one excuse key, so one of them is " +
                "being excused by the other's reason; give the second block a heading of its " +
                "own. Two blocks under the same heading in *different* documents do not collide " +
                "— the key carries the document, so each needs its own excuse",
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
     * pinning it. Rather than widen the parser and inherit Markdown's indentation rules, both
     * documents refuse all three and say so here, so the test's name is true of every line of
     * both files rather than of the subset it happens to parse.
     */
    @Test
    fun `no document uses a fence this test cannot see`() {
        for (document in SNIPPET_DOCUMENTS.keys.sorted()) {
            assertEquals(
                "an indented fence, a `~~~` fence or a fence with an info string beyond the " +
                    "language word is invisible to this test, so a Kotlin block inside one " +
                    "would be published with nothing pinning it. Fence at column 0 with " +
                    "backticks and a bare language word, or widen the parser deliberately. In " +
                    "`$document`",
                emptyList<String>(),
                unreadableFences(locate(document).readLines()),
            )
        }
    }

    // ── What the documents must say ───────────────────────────────────────

    /**
     * Each document's own sections, so neither can ship half-written.
     *
     * The two lists are separate because the two pages answer to different readers: the guide's
     * is what an *integration* needs, and the vault page's is what a *vault author* needs. A
     * single shared list would make every section a requirement on both pages, which is false of
     * each of them.
     */
    @Test
    fun `every document carries the sections it must not ship without`() {
        for ((document, required) in SNIPPET_DOCUMENTS.entries.sortedBy { it.key }) {
            val sections = SECTION.findAll(locate(document).readText())
                .map { it.groupValues[1] }
                .toList()
            assertEquals(
                "`$document` must not ship half-written; these sections are missing: " +
                    "${required.filterNot { it in sections }}. Found: $sections",
                emptyList<String>(),
                required.filterNot { it in sections },
            )
        }
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
     *
     * **Narrowed, deliberately, to the regions `docs/INTEGRATION.md`'s own blocks quote**, where
     * it used to be measured over every region in every test source. That was the same set while
     * the guide was the only document with regions, so the assertion read as a claim about the
     * guide — and it stopped being one the moment a second document brought regions of its own: a
     * core-loop call that appeared **only** in a vault-page region would have satisfied this floor,
     * leaving the guide free to drop `parseQueryResult` with nothing red. The narrowing is a
     * strengthening, not a scope reduction: nothing it used to catch is now missed, and a shape it
     * could not catch before now reddens. The vault page's own coverage floor is a separate claim
     * about a different audience, and is not this assertion's business.
     */
    @Test
    fun `every function in the core loop is called in a snippet`() {
        val guideRegions = onDisk().regionsQuotedBy(GUIDE_PATH)
        assertEquals(
            "`$GUIDE_PATH` must show the whole core loop in code a test ran, not describe it in " +
                "a comment — and in a region *that page* quotes, not one another document does. " +
                "These appear in no executed line of a region the guide quotes",
            emptyList<String>(),
            coverageShortfalls(guideRegions, CORE_LOOP),
        )
        // Floor: measured over a per-document subset, so an empty subset would pass for ever —
        // and the subset is empty exactly when every marker in the guide has gone stale.
        assertTrue(
            "no region resolved from a `$GUIDE_PATH` block, so the core loop was measured over " +
                "nothing at all",
            guideRegions.isNotEmpty(),
        )
        println(
            "GuideSnippetTest: ${CORE_LOOP.size} core-loop functions, all called across " +
                "${guideRegions.size} regions $GUIDE_PATH quotes " +
                "(${executedCode(guideRegions).lines().size} code " +
                "lines of ${guideRegions.sumOf { it.lines.size }} snippet lines), of " +
                "${onDisk().regions.size} regions in the tree",
        )
    }

    /**
     * The vault page's own coverage floor, [CORE_LOOP]'s sibling and measured exactly the same
     * way: over the **code** lines of the regions **that page** quotes, so a function named only
     * in a snippet's trailing comment does not satisfy it and a function called only in a
     * client-page region does not either.
     *
     * The two floors are separate assertions because they are claims about two audiences. A vault
     * never calls `shareEntry`; a client never calls `parseShareRequest`. Merging the lists would
     * oblige each page to demonstrate the other half of the wire, and merging the *regions* would
     * let either page satisfy the other's floor — which is the failure the narrowing above
     * closes, one page along.
     *
     * **This list is hand-written, and that is the honest limit of what it buys.** It is the
     * vault-half surface as somebody read it on the day the page was written: nothing here
     * notices a published vault-side function that nobody added to the list, so an eighth one
     * would be demonstrated by no block, reported by no floor, and documented nowhere while every
     * test stayed green. What it does catch is the regression — a page that *stops* showing one
     * of these, or shows it in a comment.
     */
    @Test
    fun `every function a vault calls is called in a vault-page snippet`() {
        val vaultRegions = onDisk().regionsQuotedBy(VAULT_PATH)
        assertEquals(
            "`$VAULT_PATH` must show the whole vault half of the wire in code a test ran, not " +
                "describe it in a comment — and in a region *that page* quotes. These appear in " +
                "no executed line of a region the vault page quotes",
            emptyList<String>(),
            coverageShortfalls(vaultRegions, VAULT_LOOP),
        )
        // The same floor the core loop carries, for the same reason: a per-document subset is
        // empty exactly when every marker on that page has gone stale, and an empty subset would
        // satisfy a coverage claim for ever.
        assertTrue(
            "no region resolved from a `$VAULT_PATH` block, so the vault half was measured " +
                "over nothing at all",
            vaultRegions.isNotEmpty(),
        )
        println(
            "GuideSnippetTest: ${VAULT_LOOP.size} vault-half functions, all called across " +
                "${vaultRegions.size} regions $VAULT_PATH quotes " +
                "(${executedCode(vaultRegions).lines().size} code " +
                "lines of ${vaultRegions.sumOf { it.lines.size }} snippet lines)",
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

    /**
     * The README links **both** pages, each required by name.
     *
     * The front page is the only document a third party finds on their own, so a page it does not
     * link is a page nobody reaches — and the two readers arrive here equally blind: an integrator
     * looking for the client guide and a vault author looking for the other half of the wire.
     * Requiring each path by name rather than counting links is what stops one of them being
     * quietly dropped while the other keeps this green.
     *
     * The existence half was already asserted for *any* `docs/` link, which is why a path that is
     * linked but missing fails here rather than only on a reader's click.
     */
    @Test
    fun `the README links both documents, and they exist`() {
        val readme = locate(README_PATH)
        val links = Regex("""]\((docs/[^)]+)\)""").findAll(readme.readText())
            .map { it.groupValues[1] }
            .toList()
        assertEquals(
            "the README is the only document a third party finds on their own, so it must link " +
                "every page this repository publishes — the integration guide for a client " +
                "author and the vault page for the other half of the wire. Found links into " +
                "docs/: $links. Missing",
            emptyList<String>(),
            SNIPPET_DOCUMENTS.keys.sorted().filterNot { it in links },
        )
        assertEquals(
            "a README link into docs/ must resolve to a file that exists",
            emptyList<String>(),
            links.filterNot { File(readme.parentFile, it).isFile }.sorted(),
        )
    }

    /**
     * The README names the artifact and **not** its version, and both halves are asserted.
     *
     * A third party finds this file on its own and nothing else, so it has to answer "can I use
     * this from my project" before they click anything. The name is read out of the build file's
     * own `coordinates(...)` call through the same [COORDINATES] regex that
     * `the guide prints the coordinate the build file declares` uses — one definition of what the
     * library is called, not two that have to agree.
     *
     * **The one place that tells an integrator which version to depend on is the guide's Setup
     * section.** It is pinned there against the build file, so a human bumping it reddens that
     * document by design. `CHANGELOG.md` names versions too, but as the record of what each one
     * changed, and its heading is itself held to `coordinates(...)` by `ChangelogTest`. A copy on
     * the front page would be neither of those: one more line every release has to move by hand,
     * on the page nobody re-reads. So the README's *absence* of a version is asserted rather than
     * hoped for.
     *
     * **"One place" is scoped to that instruction, not to the character sequence.** The guide
     * states a feature's minimum version in prose as well — `docs/INTEGRATION.md`'s optional-fields
     * section says which release first honoured them, and its closing section glosses a test name
     * the same way. Both subordinate themselves to Setup rather than competing with it, and
     * neither is pinned here; a count of version literals in the repository is not what this
     * asserts and would be wrong the next time somebody wrote one.
     *
     * The absence is asserted twice over, because the two ways it can be false are different. The
     * *shape* `group:artifact:version` is what an integrator would copy, and the bare declared
     * *value* is what a sentence like "current version: x" would leak without ever forming a
     * triple; neither alone covers the other.
     *
     * An absence is also the shape of assertion that passes for ever once its matcher stops
     * matching anything, so each matcher must report somewhere: the triple in the guide, which
     * genuinely prints one, and the bare version in the build file it was read out of. One
     * matcher, two answers — the negative controls' rule applied to a rule stated negatively.
     *
     * **Neither half pins which version it found, and the choice of file is what makes that
     * true.** The *value* is `the guide prints the coordinate the build file declares`'s business.
     * Asking the guide for the declared version — rather than for any triple — was measured to
     * couple this test to the release: bumping `coordinates(...)` alone turned it red, which
     * would tell a human editing the README that the front page needs touching on release. That
     * is the one thing this whole arrangement exists to stop, so a release reddens the guide's
     * coordinate test and this test stays green.
     *
     * Two limits of that arrangement, stated rather than implied away. **The bare matcher knows
     * only today's declared version**, so a README line naming a version that was *already* stale
     * when it was written — "requires LIM 1.0.0 or later", or a truncated "LIM 1.1" — is invisible
     * to both halves. Matching any `x.y.z` instead would fire on the Gson coordinate the guide
     * legitimately prints, so this is the trade rather than an oversight; what is closed is the
     * literal a release moves. And **the bare half's non-vacuity probe cannot fail as the matcher
     * is built today** — `version` is read out of the build file and `Regex.escape` makes a
     * literal of it — so it is a guard against a future bound or transformation that matches
     * nothing, not a measurement of the current code. The triple half, pointed at a different
     * file, is the one that is genuinely falsifiable: deleting the guide's coordinate reddens it.
     */
    @Test
    fun `the README names the artifact and leaves its version to the guide`() {
        val buildFile = locate(MODULE_BUILD_FILE)
        val declared = COORDINATES.findAll(buildFile.readText()).toList()
        assertEquals(
            "expected exactly one `coordinates(group, artifact, version)` call in " +
                "${buildFile.absolutePath}; the artifact the README must name is read out of it",
            1,
            declared.size,
        )
        val (group, artifact, version) = declared.single().destructured
        val readme = locate(README_PATH).readText()
        assertTrue(
            "`$README_PATH` must name `$group:$artifact` — the coordinate " +
                "`$MODULE_BUILD_FILE` declares. A visitor who finds this repository on their own " +
                "reads that file and nothing else, and it cannot tell them whether this library " +
                "is usable from their project without saying what to depend on",
            "$group:$artifact" in readme,
        )

        val triple = Regex(Regex.escape("$group:$artifact:") + """([0-9A-Za-z.\-+]+)""")
        assertEquals(
            "the one place that tells an integrator which version to depend on is the Setup " +
                "section of `$GUIDE_PATH`, where it is held to `coordinates(...)`. A copy in " +
                "`$README_PATH` is one more line every release has to move by hand, on the page " +
                "nobody re-reads, so this file names `$group:$artifact` without a version and " +
                "sends the reader to the guide for it. Drop the version here, not this assertion",
            emptySet<String>(),
            triple.findAll(readme).map { it.value }.toSet(),
        )

        // The triple is the shape an integrator would copy; the bare value is the same leak
        // without one — "Latest release v1.1.0", "the current release is 1.1.0." or a badge
        // rendering `version-1.1.0-blue` all pass the assertion above and still make the README a
        // file every release has to touch.
        //
        // **Deliberately unbounded.** Every word-boundary this was tried with let one of those
        // three through: excluding a letter on the left loses `v1.1.0`, excluding a separator on
        // the right loses the badge, and allowing one loses the sentence-final period — and the
        // bound that would tell `1.1.0` inside `1.1.0-rc1` from `1.1.0` inside `version-1.1.0-blue`
        // does not exist, because locally the two are the same text. A substring search needs no
        // such judgement: this page is meant to carry no version at all, so a longer version
        // literal that contains the declared one is a leak worth reporting rather than a false
        // positive, and the remedy is always the same — take the version off the front page.
        val bare = Regex(Regex.escape(version))
        assertEquals(
            "…and `$README_PATH` must not print the declared version `$version` anywhere at all, " +
                "in any shape, for the same reason and with the same remedy: the guide's Setup " +
                "section is where it is held to `coordinates(...)`, and nothing holds a loose " +
                "mention here. If this version's digits genuinely belong on the front page for " +
                "some unrelated reason, reword the sentence — this page has no version in it by " +
                "design. Found at",
            emptyList<String>(),
            bare.findAll(readme).map { "offset ${it.range.first}: ${it.value}" }.toList(),
        )

        // Neither absence means anything unless its matcher can find something: a regex that
        // matches nothing passes an emptiness assertion for ever.
        //
        // They are proven against different files, and the difference is the whole point. The
        // triple matcher goes to the guide, which genuinely prints one — and is asked only
        // *whether*, never which, so a version bump reddens the guide's own coordinate test and
        // not this one. The bare matcher goes to `LIM/build.gradle.kts`, the file its literal was
        // read out of: what can go wrong with it is construction — a bad escape, a lookaround
        // that matches nothing — and the string it was built from is the one place guaranteed to
        // contain it. Pointing it at the guide instead was measured to couple this test to the
        // release: bumping `coordinates(...)` alone turned it red, which is exactly the signal
        // the arrangement above exists not to send.
        val inTheGuide = triple.findAll(guideFile().readText()).map { it.value }.toSet()
        assertEquals(
            "…and both absences above are vacuous unless their matchers find something. The " +
                "triple must be found in `$GUIDE_PATH`, which genuinely prints one; the bare " +
                "version must be found in `$MODULE_BUILD_FILE`, the file it was read out of. If " +
                "this is the half that failed, the assertions above were passing for the wrong " +
                "reason until it did. Matchers that found nothing",
            emptyList<String>(),
            listOfNotNull(
                "the `$group:$artifact:<version>` triple, in `$GUIDE_PATH`"
                    .takeIf { inTheGuide.isEmpty() },
                "the bare version `$version`, in `$MODULE_BUILD_FILE`"
                    .takeIf { !bare.containsMatchIn(buildFile.readText()) },
            ),
        )
        println(
            "GuideSnippetTest: $README_PATH names $group:$artifact, with neither the triple nor " +
                "the bare version; $GUIDE_PATH prints $inTheGuide against a declared $version",
        )
    }

    /**
     * The SDK floor, which both documents print and until now neither was held to.
     *
     * It is the first question an integrator asks and the cheapest claim to leave stale: a document
     * promising `minSdk 24` after the floor rose sends somebody to a library that will not merge
     * into their manifest, and one promising a floor *lower* than the build declares is worse,
     * because the failure arrives at their users rather than at their build. So the number is read
     * out of the module's own `defaultConfig` and both documents must print that and nothing else.
     *
     * **[MIN_SDK] reads every spelling this repository can plausibly carry, with one pattern.** A
     * pattern that matched only `minSdk 24` was blind to `minSdk = 23` — and the guide already
     * carries ` ```gradle ` blocks headed with a consumer's own build file, where the assignment
     * is the natural thing to write, so the *lower-floor* case above could have landed in one and
     * stayed green. The quoted-attribute form is in for the same measured reason: the guide
     * publishes a ` ```xml ` manifest element, which is where `android:minSdkVersion="23"` would
     * go. One pattern over both documents and the build file means the set compared is the set
     * found, whichever way somebody wrote it.
     *
     * **The limit, stated rather than implied away:** it matches on the identifier, so a floor
     * written without it — "API level 24", "Android 7.0" — is invisible, as is one separated from
     * its number by anything other than whitespace, `=`, `:` or a quote — a bolded or
     * code-spanned name with the number left outside it is the easy one to write by accident.
     * What is closed is the four spellings [MIN_SDK] names.
     *
     * That hole is narrower than it looks, and in the safe direction: the comparison is set
     * equality, so a document whose *only* mention is in an unreadable spelling reports an empty
     * set and reddens. A stale floor can hide here only by sitting beside a correct, readable
     * one — which is the shape to look for if this test is ever green on a document that reads
     * wrong.
     *
     * **"Both documents" is `README.md` and `docs/INTEGRATION.md`, and `docs/VAULT.md` is
     * deliberately outside it.** The floor is a *consumer's* question — what an app's own build
     * file has to declare to resolve this library — and the vault page addresses somebody building
     * the other end of the wire, who does not depend on this artifact at all. Because the
     * comparison is set equality, adding that page here would oblige it to print a floor it has no
     * reason to state. The cost of leaving it out is stated rather than implied: a floor written
     * on the vault page would be pinned by nothing, so that page carries none.
     */
    @Test
    fun `both documents print the minimum SDK the build file declares`() {
        val buildFile = locate(MODULE_BUILD_FILE)
        val declared = MIN_SDK.findAll(buildFile.readText()).map { it.groupValues[1] }.toList()
        assertEquals(
            "expected exactly one `minSdk` declaration in ${buildFile.absolutePath}; the number " +
                "both documents must print is read out of it. Found: $declared",
            1,
            declared.size,
        )
        val floor = declared.single()
        for (document in listOf(README_PATH, GUIDE_PATH)) {
            assertEquals(
                "`$document` must print `minSdk $floor`, and no other value of it — in prose, in " +
                    "a Kotlin DSL assignment, after a colon, or as a quoted manifest attribute: " +
                    "`$MODULE_BUILD_FILE` declares `minSdk = $floor`. If the floor moved, that " +
                    "document is now advertising a minimum this library is not built for — " +
                    "update the document, not this assertion",
                setOf(floor),
                MIN_SDK.findAll(locate(document).readText()).map { it.groupValues[1] }.toSet(),
            )
        }
        println("GuideSnippetTest: minSdk $floor printed by $README_PATH and $GUIDE_PATH")
    }

    /**
     * The README carries no fenced code at all, because nothing here could execute any of it.
     *
     * Every ` ```kotlin ` block in the guide is a region of a `@Test` method, quoted verbatim —
     * that is this whole class. The marker rule binds the guide alone, so a sample on the front
     * page would be the first Kotlin this project publishes that no test ran, and the first free
     * to rot. Prose naming the coordinate is enough for a front page; code belongs in the guide,
     * behind a region.
     *
     * **The rule is "no fence", not "no `kotlin` fence", and the width is the point.** Pinning the
     * one language word leaves a page that publishes Kotlin in three green ways: a ` ```kt ` fence
     * (GitHub highlights it as Kotlin; the language word is not `kotlin`), an unlabelled ` ``` `
     * fence, and — measured, not inferred — a fence [FENCE_OPEN] cannot see at all, since it
     * anchors at column 0 and takes a bare word. A README with a Kotlin block indented under a
     * list item and a second fenced `~~~` was green against a `kotlin`-only scan. The guide
     * survives a narrow rule because rules 6 and 7 cover the rest of its fences; the README is
     * under neither, so the honest front-page rule is the simple one. Whether this page should
     * ever carry a fence — a ` ```gradle ` dependency line, say — is a presentation judgement and
     * therefore human: this assertion is where a human records that decision.
     *
     * [unreadableFences] is reused rather than restated so the shapes [FENCE_OPEN] is blind to are
     * refused here by the same scan `no document uses a fence this test cannot see` runs.
     *
     * **The limit, stated rather than implied away:** both scans look at fences, so two shapes
     * are outside them — a four-space-indented block with no fence at all, and an HTML
     * `<pre><code>` element, which GitHub also renders as code. The first hole is inherited from
     * rule 7, and closing it means taking on Markdown's indentation rules, which is the trade
     * rule 7 already declined; the second is not a fence in any sense and is named here only so
     * that "no fenced code" is read as what it says.
     */
    @Test
    fun `the README carries no fenced code, which nothing here executes`() {
        val lines = locate(README_PATH).readLines()
        assertEquals(
            "an indented fence, a `~~~` fence or a fence with an info string beyond the language " +
                "word is invisible to the fence scan below, so code inside one would be published " +
                "on the front page with nothing pinning it and nothing complaining. Fence at " +
                "column 0 with backticks and a bare language word, in `$README_PATH` as in " +
                "`$GUIDE_PATH`",
            emptyList<String>(),
            unreadableFences(lines),
        )
        assertEquals(
            "every ` ```$SNIPPET_LANGUAGE ` block in `$GUIDE_PATH` is lifted out of a test that " +
                "runs, and `$README_PATH` is under no such rule — code here would be the only " +
                "code this project publishes with no test behind it, in any language and under " +
                "any label. Move it into the guide and give it a region, or decide by hand that " +
                "this page may carry a fence and say so here. Fences found at",
            emptyList<String>(),
            lines.withIndex()
                .filter { (_, line) -> FENCE_OPEN.matches(line) }
                .map { (index, line) -> "$README_PATH:${index + 1}: $line" },
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
            mapOf(FIXTURE_GUIDE_NAME to FIXTURE_UNCOLLECTED_GUIDE),
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
            mapOf(FIXTURE_GUIDE_NAME to FIXTURE_DOUBLE_GUIDE),
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
            "the unexcused block must be named by language, heading and document: " +
                "${withNoExcuses.unexcusedBlocks}",
            withNoExcuses.unexcusedBlocks.single()
                .contains("json under Fixture appendix in $FIXTURE_GUIDE_NAME"),
        )

        val dead = "yaml under A heading the fixture guide does not have in $FIXTURE_GUIDE_NAME"
        val withADeadExcuse = fixtureAudit(
            excuses = FIXTURE_EXCUSES + (dead to Excuse("dead", CONTROL_CITATION)),
        )
        assertEquals(
            "excusing the json block must silence the complaint, or the two halves of this " +
                "control are not reading the same map",
            emptyList<String>(),
            withADeadExcuse.unexcusedBlocks,
        )
        assertEquals(listOf(dead), withADeadExcuse.danglingExcuses)
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
            mapOf(FIXTURE_GUIDE_NAME to FIXTURE_DUPLICATE_GUIDE),
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

    /**
     * (h) Two blocks sharing one excuse key are reported, so neither borrows the other's reason.
     *
     * Both blocks are in the **same** fixture document, which is now the only way two blocks can
     * collide: the key carries the document, so the same heading on two different pages yields two
     * keys. Control (o) is the other half of that — it asserts the two pages do *not* collide and
     * that each needs its own excuse.
     */
    @Test
    fun `control - two blocks under one heading cannot share an excuse`() {
        val key = "json under Appendix in $FIXTURE_GUIDE_NAME"
        val colliding = audit(
            mapOf(FIXTURE_GUIDE_NAME to FIXTURE_COLLIDING_GUIDE),
            emptyMap(),
            mapOf(key to Excuse("a fixture", CONTROL_CITATION)),
        )
        assertEquals(listOf(key), colliding.collidingExcuseKeys)
        // The excuse does silence the unexcused complaint, so the collision is the only finding.
        assertEquals(emptyList<String>(), colliding.unexcusedBlocks)
    }

    // ── Negative controls: the document set ───────────────────────────────
    //
    // The six below are the controls for the widening itself, and they share one fixture pair:
    // [FIXTURE_PAIR_SOURCE]'s five regions, split across [FIXTURE_PAIR_FIRST] (which plays
    // `docs/INTEGRATION.md`) and [FIXTURE_PAIR_SECOND] (which plays `docs/VAULT.md`). Each runs
    // the same `audit` the assertions above run.
    //
    // What makes them worth their lines: before the widening, rule 4 was computed against one
    // document, so every region the second page quotes was an orphan — not a hazard to guard
    // against but the certain outcome of adding a second page. Control (l) measures *both*
    // answers over the same fixture rather than asserting only the new one.

    /**
     * (l) The widening took effect, proved from the side that was broken before it.
     *
     * `#in-second` is quoted by a block in the second document and by nothing in the first. A
     * single-document audit calls it an orphan — correctly, on its own terms, and uselessly — and
     * the union audit says nothing about it. Both answers are measured here and printed, because
     * asserting only the new one would not show that the old one differs.
     */
    @Test
    fun `control - a region only the second document quotes is an orphan to a one-document audit`() {
        val firstAlone = audit(
            mapOf(FIXTURE_PAIR_FIRST_NAME to FIXTURE_PAIR_FIRST),
            mapOf("PairTest.kt" to FIXTURE_PAIR_SOURCE),
            emptyMap(),
        )
        val pair = fixturePairAudit()

        assertTrue(
            "auditing the first document alone must report `#in-second` as an orphan — that is " +
                "the answer the widening replaces, and if it does not hold, this control is " +
                "measuring nothing. Found ${firstAlone.orphanRegions}",
            firstAlone.orphanRegions.any { it.startsWith("PairTest.kt#in-second") },
        )
        assertEquals(
            "…and auditing the documents together must say nothing about it: a region quoted by " +
                "a block in the *other* page is quoted, which is the whole claim rule 4 makes " +
                "and the one the per-document spelling gets wrong. Orphans over the pair",
            emptyList<String>(),
            pair.orphanRegions.filter { it.startsWith("PairTest.kt#in-second") },
        )
        println(
            "GuideSnippetTest: control (l) — one document: ${firstAlone.orphanRegions.size} " +
                "orphan(s) ${firstAlone.orphanRegions.map { it.substringBefore(" ") }}; " +
                "the pair: ${pair.orphanRegions.size} " +
                "${pair.orphanRegions.map { it.substringBefore(" ") }}",
        )
    }

    /**
     * (m) …and the union answer is not vacuous: a region quoted by **neither** document is still
     * reported.
     *
     * Without this, (l) would be satisfied by an orphan rule that had stopped reporting anything
     * at all — which is exactly how a widening goes wrong.
     */
    @Test
    fun `control - a region neither document quotes is reported`() {
        val orphans = fixturePairAudit().orphanRegions
        assertEquals("found $orphans", 1, orphans.size)
        assertTrue(
            "the one region no block in either document quotes must be named: $orphans",
            orphans.single().startsWith("PairTest.kt#in-neither"),
        )
    }

    /**
     * (n) A region quoted once by each document is doubly quoted.
     *
     * Neither page quotes it twice, so this is the failure only the union can see — and the one a
     * reader is most likely to create by moving a snippet from one page to the other and leaving
     * the first marker behind.
     */
    @Test
    fun `control - a region quoted once in each document is reported as doubly quoted`() {
        assertEquals(
            listOf("PairTest.kt#in-both is quoted by 2 blocks"),
            fixturePairAudit().doublyQuotedRegions,
        )
    }

    /**
     * (o) Two documents may carry the same heading, and one page's excuse covers one page's block.
     *
     * Both fixture documents have a ` ```json ` block under *Appendix*. Under the old key —
     * language and heading — those were one key, so excusing either excused both and the
     * collision rule reported a collision that is not one. Qualified by document they are two
     * keys: excusing the first leaves the second reported, and an excuse naming a heading only
     * the *second* page has is dangling when the second page is not in the set.
     */
    @Test
    fun `control - two documents may share a heading, and one excuse does not cover both`() {
        val firstsExcuse = "json under Appendix in $FIXTURE_PAIR_FIRST_NAME"
        val secondsExcuse = "json under Appendix in $FIXTURE_PAIR_SECOND_NAME"

        assertEquals(
            "the same heading on two pages must not collide: the key carries the document, so " +
                "these are two blocks with two keys and two reasons to write down",
            emptyList<String>(),
            fixturePairAudit().collidingExcuseKeys,
        )
        val halfExcused = fixturePairAudit(
            excuses = mapOf(firstsExcuse to Excuse("a fixture", CONTROL_CITATION)),
        ).unexcusedBlocks
        assertEquals(
            "excusing the first page's block may not excuse the second page's — that is the " +
                "borrowed reason the document qualifier exists to stop. Found $halfExcused",
            1,
            halfExcused.size,
        )
        assertTrue(
            "…and the one still reported must be the second page's, named by its own key: " +
                halfExcused,
            halfExcused.single().contains(FIXTURE_PAIR_SECOND_NAME) &&
                halfExcused.single().contains(secondsExcuse),
        )
        assertEquals(
            "…and both excuses together must silence it, or the assertion above is reporting " +
                "something other than the missing excuse",
            emptyList<String>(),
            fixturePairAudit(
                excuses = mapOf(
                    firstsExcuse to Excuse("a fixture", CONTROL_CITATION),
                    secondsExcuse to Excuse("a fixture", CONTROL_CITATION),
                ),
            ).unexcusedBlocks,
        )
        // The dead-excuse half: the heading exists, on the other page, and that is not enough.
        assertEquals(
            "an excuse naming a heading only the *other* document carries must be reported as " +
                "dangling. Resolved on heading alone it would look live and would wave through " +
                "whatever lands under that heading next",
            listOf(secondsExcuse),
            audit(
                mapOf(FIXTURE_PAIR_FIRST_NAME to FIXTURE_PAIR_FIRST),
                mapOf("PairTest.kt" to FIXTURE_PAIR_SOURCE),
                mapOf(
                    firstsExcuse to Excuse("a fixture", CONTROL_CITATION),
                    secondsExcuse to Excuse("a fixture", CONTROL_CITATION),
                ),
            ).danglingExcuses,
        )
    }

    /**
     * (p) The verbatim check reports a drifted block in the second document **naming that
     * document**.
     *
     * `#drifted` differs from its region by one character. A complaint that named the guide — or
     * named no document at all, which is what [Block.where] said before the widening — would send
     * the next reader to the wrong file with a correct failure.
     */
    @Test
    fun `control - a drifted block in the second document is reported naming that document`() {
        val mismatched = fixturePairAudit().mismatched
        assertEquals("exactly one fixture block drifts; found $mismatched", 1, mismatched.size)
        assertTrue(
            "the complaint must name the document the drifted block is in, not the other one: " +
                "$mismatched",
            mismatched.single().contains(FIXTURE_PAIR_SECOND_NAME) &&
                !mismatched.single().contains(FIXTURE_PAIR_FIRST_NAME),
        )
        assertTrue(
            "…and the region, and both sides of the difference: $mismatched",
            mismatched.single().contains("PairTest.kt#drifted") &&
                mismatched.single().contains("val answer = 5") &&
                mismatched.single().contains("val answer = 6"),
        )
    }

    /**
     * (q) Rule 1's floor is asked of each document on its own, and the union spelling would pass
     * this fixture green.
     *
     * This is the same failure (l) closes for rule 4, one rule along, and it is the one a reader
     * implementing this widening is most likely to produce by accident: keep the floor as
     * `kotlinBlocks.size >= oneList.size` and a document with no code at all ships green behind
     * the other page's blocks. Both answers are measured over the same pair.
     */
    @Test
    fun `control - the Kotlin-block floor is asked of each document on its own`() {
        val pair = audit(
            mapOf(
                FIXTURE_PAIR_FIRST_NAME to FIXTURE_PAIR_FIRST,
                FIXTURE_PAIR_SECOND_NAME to FIXTURE_PAIR_PROSE_ONLY,
            ),
            mapOf("PairTest.kt" to FIXTURE_PAIR_SOURCE),
            emptyMap(),
        )
        val required = mapOf(
            FIXTURE_PAIR_FIRST_NAME to listOf("Fixture one"),
            FIXTURE_PAIR_SECOND_NAME to listOf("One", "Two", "Three"),
        )
        assertEquals(
            "a document carrying fewer Kotlin blocks than its own section list must be reported, " +
                "naming it and both counts",
            listOf("$FIXTURE_PAIR_SECOND_NAME carries 0 Kotlin block(s) for 3 required section(s)"),
            blockFloorShortfalls(pair, required),
        )
        assertEquals(
            "…and the first document, which has blocks of its own, must not be reported — a " +
                "floor that condemned everything would satisfy the assertion above for the " +
                "wrong reason",
            emptyList<String>(),
            blockFloorShortfalls(pair, required.filterKeys { it == FIXTURE_PAIR_FIRST_NAME }),
        )
        // The spelling this control exists to refuse, measured rather than described: every block
        // in the set against one document's list passes over a pair whose second page is prose.
        assertTrue(
            "the union floor must pass over this fixture, or the two spellings do not differ " +
                "here and this control proves nothing: ${pair.kotlinBlocks.size} block(s) in " +
                "the set against ${required.getValue(FIXTURE_PAIR_FIRST_NAME).size} section(s)",
            pair.kotlinBlocks.size >= required.getValue(FIXTURE_PAIR_FIRST_NAME).size,
        )
        println(
            "GuideSnippetTest: control (q) — per document " +
                "${blockFloorShortfalls(pair, required)}; over the union " +
                "${pair.kotlinBlocks.size} block(s), which clears a floor of " +
                "${required.getValue(FIXTURE_PAIR_FIRST_NAME).size}",
        )
    }

    /**
     * (r) A coverage floor measures **code**, and the stripping is proved both ways round over one
     * region rather than argued in the helper's KDoc.
     *
     * The shape it refuses is the cheapest way to make a coverage claim true without
     * demonstrating anything: name the function in a trailing comment. Both floors above —
     * [CORE_LOOP] and [VAULT_LOOP] — rest on this, and a floor measured over the region's text as
     * a whole would pass this fixture, which is the half asserted last.
     */
    @Test
    fun `control - a coverage floor measures code and not a trailing comment`() {
        val regions = regionsIn("CoverageTest.kt", FIXTURE_COVERAGE_SOURCE)
        assertEquals("precondition: one region to measure", 1, regions.size)
        assertEquals(
            "a function called in an executed line satisfies the floor",
            emptyList<String>(),
            coverageShortfalls(regions, listOf("calledForReal")),
        )
        assertEquals(
            "…and one named only in the trailing comment of that same line does not. A mention " +
                "is not a call, so stripping whole comment lines is not enough — it is the tail " +
                "of a code line that would otherwise satisfy a floor with the sentence saying a " +
                "page ought to show something",
            listOf("mentionedOnly"),
            coverageShortfalls(regions, listOf("mentionedOnly")),
        )
        assertTrue(
            "the spelling this control refuses must pass over the same fixture, or the two do " +
                "not differ here and this control proves nothing",
            regions.flatMap { it.lines }.joinToString("\n").contains("mentionedOnly"),
        )
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

    private fun blocksIn(document: String, markdown: String): List<Block> {
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
            check(cursor < lines.size) {
                "a fenced block opened at $document:${index + 1} is never closed"
            }
            val marker = if (index > 0) MARKER.find(lines[index - 1]) else null
            blocks += Block(
                document = document,
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

    /** Every document under the snippet rules, keyed by the path a failure should name. */
    private fun documentsOnDisk(): Map<String, String> =
        SNIPPET_DOCUMENTS.keys.sorted().associateWith { locate(it).readText() }

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
        audit(
            mapOf(FIXTURE_GUIDE_NAME to FIXTURE_GUIDE),
            mapOf("FixtureTest.kt" to FIXTURE_SOURCE),
            excuses,
        )

    /** Control (l)–(q)'s pair: two fixture documents quoting one fixture source between them. */
    private fun fixturePairAudit(excuses: Map<String, Excuse> = emptyMap()): Audit =
        audit(
            mapOf(
                FIXTURE_PAIR_FIRST_NAME to FIXTURE_PAIR_FIRST,
                FIXTURE_PAIR_SECOND_NAME to FIXTURE_PAIR_SECOND,
            ),
            mapOf("PairTest.kt" to FIXTURE_PAIR_SOURCE),
            excuses,
        )

    private companion object {
        private const val GUIDE_PATH = "docs/INTEGRATION.md"
        private const val VAULT_PATH = "docs/VAULT.md"
        private const val README_PATH = "README.md"
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

        /**
         * The SDK floor as the repository's documents and build file spell it: `minSdk = 24` in
         * Kotlin DSL, `minSdk 24` in prose, `minSdk: 24`, and `android:minSdkVersion="24"` in a
         * manifest — the guide publishes a manifest element, so the quoted-attribute form is one
         * a stale floor could really hide in. One pattern for the declaration and the mentions,
         * so the comparison cannot be blind to a form on one side that it reads on the other.
         * See `both documents print the minimum SDK the build file declares` for what it does not
         * reach.
         */
        private val MIN_SDK = Regex("""minSdk(?:Version)?\s*[=:]?\s*"?(\d+)""")

        /** Pinned by name so the guide cannot ship half-written. */
        private val REQUIRED_SECTIONS = listOf(
            "Setup",
            "If you minify your app",
            "Before you start: is there a vault?",
            "Sign-up (share)",
            "Query",
            "Login (sign-challenge)",
            "Surviving process death",
            "When the user says no",
            "Rules you must not break",
            "Testing your integration without a vault",
        )

        /**
         * `docs/VAULT.md`'s sections, pinned the same way and for the same reason.
         *
         * **Five, which is a vault's whole turn: read a request, answer it, or refuse.** That
         * page answers a vault author rather than an integrator, and it is being built in
         * instalments — the obligations a vault owes the protocol are the one still to come, and
         * this list is where it will be admitted. A section promised in prose before it is on
         * this list is a promise nothing holds.
         */
        private val REQUIRED_VAULT_SECTIONS = listOf(
            "What a vault answers for",
            "Routing an incoming request",
            "Reading a share request",
            "Answering a request",
            "Refusing",
        )

        /**
         * Every document under the seven properties, each against its own required sections.
         *
         * The keys are the document set [audit] reads, so adding a page here is what puts it
         * under the snippet rules — and under `BuildInputsTest`'s, which requires the same path
         * in its `VERIFIED_DOCUMENTS` and declared as an input of the test task in
         * `LIM/build.gradle.kts`. Without that declaration Gradle cannot see that this suite
         * opens the file, so a commit changing only the page comes back UP-TO-DATE and this
         * verifier does not run at all.
         *
         * The values are what keeps the per-document rules honest: rule 1's floor and the section
         * check are both asked of a document against **its own** list, never against the set's.
         */
        private val SNIPPET_DOCUMENTS: Map<String, List<String>> = mapOf(
            GUIDE_PATH to REQUIRED_SECTIONS,
            VAULT_PATH to REQUIRED_VAULT_SECTIONS,
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
         * The vault half of the same idea: the published surface a vault author actually calls —
         * read the request, read what the client declared about it, answer it.
         *
         * Seven names, in the order a vault meets them, and the list is **hand-written**: it is
         * this file's reading of the vault-side surface rather than anything derived from the
         * published API, so it cannot notice a vault-half function nobody added to it. See
         * `every function a vault calls is called in a vault-page snippet` for what that costs
         * and what the floor still buys.
         *
         * Three exclusions, each a choice rather than an oversight. `parseFieldRequirements` is
         * here and `checkFieldRequirements` is not: the first reads a client's declaration off a
         * request, which is a vault's job, while the second reads a vault's acknowledgement off an
         * answer, which is the client's. The refusal has no entry because there is no builder to
         * call — a refusal is a result code and a hand-written echo, which is a standing protocol
         * question rather than a gap in this list. And `isStatementPreImage` is deliberately
         * **not** here although a vault-page region calls it and this library calls refusing an
         * obligation: this list is the *wire* a request travels, and that call is a vault's duty
         * rather than a step in moving one. The region's own `assertNull` catches the regression
         * of lifting the guard out, so nothing is unpinned by the choice — but it is a choice, and
         * whether this list should be derived from the published surface instead of hand-written
         * is the question its hand-written-ness leaves open.
         */
        private val VAULT_LOOP = listOf(
            "parseShareRequest",
            "parseQueryRequest",
            "parseSignChallengeRequest",
            "parseFieldRequirements",
            "createShareResultIntent",
            "createQueryResultIntent",
            "createSignChallengeResultIntent",
        )

        /**
         * The fenced blocks the marker rule does not bind, each with a reason and the test that
         * covers it instead. Keyed by fence language, heading **and document** — which is why no
         * two of them may sit under the same heading *of the same page*, and why a block that
         * moves sections, or moves pages, has to be looked at by somebody.
         *
         * Every entry here is `docs/INTEGRATION.md`'s: `docs/VAULT.md` publishes Kotlin and
         * nothing else, so it needs no excuse. A fence in any other language appearing there is
         * reported by rule 6 until somebody writes down what covers it.
         */
        private val NOT_A_SNIPPET: Map<String, Excuse> = mapOf(
            "gradle under Setup in $GUIDE_PATH" to Excuse(
                reason = "the dependency declaration a consumer writes in their own build file. " +
                    "No test here can run a consumer's build, and nothing in this repository " +
                    "reaches the network to resolve it — so what is pinned instead is the one part " +
                    "that can go stale silently: the version it prints",
                coveredBy = "GuideSnippetTest: the guide prints the coordinate the build file declares",
            ),
            "gradle under Building from source in $GUIDE_PATH" to Excuse(
                reason = "a consumer project's own build file, which this repository cannot " +
                    "execute — the guide says as much in that section rather than implying " +
                    "otherwise. What is pinned is every name in it: the Gradle project path, " +
                    "the artifact the assemble task writes, and the Gson coordinate a bare AAR " +
                    "does not carry",
                coveredBy = "GuideSnippetTest: the build-from-source path names what the build declares",
            ),
            "proguard under If you minify your app in $GUIDE_PATH" to Excuse(
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
            "xml under Before you start: is there a vault? in $GUIDE_PATH" to Excuse(
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
         * What the fixture documents are called, and **why none of them ends in `.md`**.
         *
         * `BuildInputsTest`'s rule 3 reads every whole double-quoted string in every test source
         * that ends in a document extension and requires it to be a declared input of the test
         * task. A fixture label spelled `docs/fixture-guide.md` would be read as a repository
         * document this suite opens — which it is not; it never touches the disk — and that rule
         * would redden with no honest way to satisfy it, since its excuse map must stay empty.
         * Extensionless labels are outside its regex and read the same in a failure message.
         *
         * `FIXTURE_PAIR_SECOND_NAME` stands in for `docs/VAULT.md` throughout controls (l)–(q):
         * the second document of a set, quoting regions of its own.
         */
        private const val FIXTURE_GUIDE_NAME = "docs/fixture-guide"
        private const val FIXTURE_PAIR_FIRST_NAME = "docs/fixture-first"
        private const val FIXTURE_PAIR_SECOND_NAME = "docs/fixture-second"

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
            "json under Fixture appendix in $FIXTURE_GUIDE_NAME" to Excuse(
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

        /**
         * Controls (l)–(q): five regions, to be split across two fixture documents.
         *
         * Each one is a shape rule 4 has to answer differently now that there is a document set:
         * `#in-first` quoted by the first page, `#in-second` by the second **only** — the orphan
         * that was the certain consequence of adding a second page — `#in-both` once by each,
         * which is the double-quoting only the union can see, `#in-neither` by nobody, and
         * `#drifted` by the second page with one character changed.
         *
         * Assembled from one-line literals for [FIXTURE_SOURCE]'s reason: written as a raw string
         * the markers would begin their lines and this file's own fixtures would be collected as
         * real regions, quoted by no block, reddening rule 4 on its own controls.
         */
        private val FIXTURE_PAIR_SOURCE = listOf(
            "class PairTest {",
            "",
            "    @Test",
            "    fun `the first document quotes this`() {",
            "        // region snippet:in-first",
            "        val answer = 1",
            "        // endregion snippet:in-first",
            "    }",
            "",
            "    @Test",
            "    fun `only the second document quotes this`() {",
            "        // region snippet:in-second",
            "        val answer = 2",
            "        // endregion snippet:in-second",
            "    }",
            "",
            "    @Test",
            "    fun `both documents quote this`() {",
            "        // region snippet:in-both",
            "        val answer = 3",
            "        // endregion snippet:in-both",
            "    }",
            "",
            "    @Test",
            "    fun `neither document quotes this`() {",
            "        // region snippet:in-neither",
            "        val answer = 4",
            "        // endregion snippet:in-neither",
            "    }",
            "",
            "    @Test",
            "    fun `the second document quotes this one character off`() {",
            "        // region snippet:drifted",
            "        val answer = 5",
            "        // endregion snippet:drifted",
            "    }",
            "}",
        ).joinToString("\n")

        /** The pair's first document — the one that plays `docs/INTEGRATION.md`. */
        private val FIXTURE_PAIR_FIRST = listOf(
            "## Fixture one",
            "",
            "<!-- snippet: PairTest.kt#in-first -->",
            "```kotlin",
            "val answer = 1",
            "```",
            "",
            "<!-- snippet: PairTest.kt#in-both -->",
            "```kotlin",
            "val answer = 3",
            "```",
            "",
            "## Appendix",
            "",
            "```json",
            "{}",
            "```",
        ).joinToString("\n")

        /**
         * The pair's second document — the one that plays `docs/VAULT.md`.
         *
         * Its *Appendix* heading is the first document's, word for word, which is control (o)'s
         * whole subject: two pages may legitimately use the same heading, and the excuse key has
         * to tell the two blocks apart.
         */
        private val FIXTURE_PAIR_SECOND = listOf(
            "## Fixture two",
            "",
            "<!-- snippet: PairTest.kt#in-second -->",
            "```kotlin",
            "val answer = 2",
            "```",
            "",
            "<!-- snippet: PairTest.kt#in-both -->",
            "```kotlin",
            "val answer = 3",
            "```",
            "",
            "<!-- snippet: PairTest.kt#drifted -->",
            "```kotlin",
            "val answer = 6",
            "```",
            "",
            "## Appendix",
            "",
            "```json",
            "[]",
            "```",
        ).joinToString("\n")

        /**
         * Control (r)'s source: one region naming two functions, one called and one mentioned in
         * the trailing comment of that same line — the exact pair a coverage floor has to tell
         * apart, on one line so that dropping comment-only lines is not enough to tell them.
         */
        private val FIXTURE_COVERAGE_SOURCE = listOf(
            "class CoverageTest {",
            "",
            "    @Test",
            "    fun `a fixture test holding one region`() {",
            "        // region snippet:coverage",
            "        val answer = Utils.calledForReal(1) // then call Utils.mentionedOnly(answer)",
            "        // endregion snippet:coverage",
            "    }",
            "}",
        ).joinToString("\n")

        /** Control (q): a second document with prose and no fence at all. */
        private val FIXTURE_PAIR_PROSE_ONLY = listOf(
            "## Fixture two",
            "",
            "A page that publishes no code, which is what the per-document floor has to catch.",
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
