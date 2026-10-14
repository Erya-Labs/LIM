package dev.eryalabs.lim

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The guide has sixteen runnable Kotlin blocks and the IDE popup had none. **Measured before this file
 * existed: `grep -c '^\s*\* *```'` over every one of the sixteen published sources returned 0 for
 * each of them.** An integrator spends the afternoon in an IDE, not in
 * `docs/INTEGRATION.md`, so every executable example this repository owns was unreachable from the
 * one place it would be read.
 *
 * **This test pins a chain rather than a pair, and the design is "quote the guide, not the test".**
 * A doc comment carries a marker immediately above its fence —
 * `<!-- example: INTEGRATION.md#login-request -->` — and this test asserts the doc comment's block
 * equals **the guide's block of that name**, verbatim. The guide's block is already equal to a
 * `// region snippet:` span of a test source, held there by `GuideSnippetTest`, which also asserts
 * that span sits inside an un-`@Ignore`d `@Test` of a class JUnit instantiates. So:
 *
 *     KDoc example  ==  guide block  ==  region of an executed @Test
 *
 * is complete with **one** new comparison and no second region parser. There is deliberately no
 * scanner here that knows what a `// region snippet:` is.
 *
 * Seven rules:
 *
 *  1. every fenced block in every published source's doc comments carries an `example:` marker;
 *  2. every marker names a `<!-- snippet: … -->`-marked guide block that exists — a dangling one is
 *     reported by file *and* name, and a name carried by two guide blocks resolves to nothing
 *     rather than to whichever came last;
 *  3. every block equals that guide block verbatim, after the comment prefix and the block's common
 *     indentation are stripped and nothing else is;
 *  4. the block a marker resolves to is fenced ` ```kotlin `, **and so is the doc comment's own
 *     fence** — two halves, because they fail differently;
 *  5. every name in [CORE_LOOP] carries an example on at least one of its published declarations;
 *  6. a fenced block with no marker is excused by name in [NOT_AN_EXAMPLE], which must be empty
 *     today, with hygiene in both directions and no two blocks sharing one excuse key;
 *  7. **no doc comment holds one of the five code shapes this scan cannot read.** Rules 1–6 all
 *     speak about blocks found by a ` ``` ` fence at the start of a (prefix-stripped) line; a
 *     `~~~` fence, a fence with an info string beyond the language word, a markdown indented code
 *     block, an HTML `<pre>` or `<code>` block and an unclosed fence are all code in the popup and
 *     invisible to that. Each of the five is refused by name, which is what stops rule 1 from
 *     being satisfied by code it simply did not look at — `GuideSnippetTest`'s rule 7, applied to
 *     the other side of the same chain, and here because three rounds of review built exactly that
 *     evasion, three times.
 *
 *     **The rule is enumerated, not universal, and the wording above is chosen to say so.** Four
 *     review probes got past earlier drafts of it: a `~~~` fence (closed), one tab instead of four
 *     spaces (closed — see [indentColumnsOf], since markdown expands a tab to a four-column stop
 *     while a character count sees one), an indented block directly under an `<!-- … -->`
 *     marker rather than under a blank line (closed — see [continuesAParagraph], since
 *     CommonMark's rule is that indented code cannot interrupt a *paragraph*, which a leaf block
 *     is not), and an HTML `<pre>` block — the habit a Java-trained contributor reaches for first,
 *     which opens no fence, indents nothing and so was silent to every branch above (closed — see
 *     [HTML_CODE_LINE]). What remains open is a leaf block [LEAF_BLOCK_LINE] does not list, with
 *     indented code directly beneath it, and any *other* markup a renderer treats as code. That is
 *     the honest residue, and it is recorded here rather than claimed away.
 *
 * **A guide block may be quoted by several KDocs**, and that is the one place this scheme differs
 * from the guide's own. `GuideSnippetTest`'s rule 4 insists a region is quoted by *exactly* one
 * block, because the guide is a narrative and a block appearing twice in it is an editing mistake.
 * A published surface is not a narrative: both `createShareIntent` overloads want the same sign-up
 * example, and `isNonceFresh` and `SignChallengeResult.isVerified` are two of the four clauses of
 * one login check. Somebody extending this file will reach for the exactly-once rule first; it is
 * not here on purpose.
 *
 * **Why rule 4 is phrased about the *resolved* block's language.** The obvious rule — "the guide
 * block a marker quotes must itself carry a snippet marker" — is true by construction, because a
 * marker is the only way to address a block at all, so its control could never fire. For the same
 * reason the hazard "an example quotes a block no test executes" is **closed by construction**:
 * addressing is by region name and `GuideSnippetTest` pins every marked block to a region of a
 * running `@Test`. What is still reachable is a marked block in another *language* — the guide's
 * Setup section fences its dependency declaration ` ```gradle `, and nothing stops a future edit
 * from putting a `snippet:` marker above a non-Kotlin block, which has no region behind it and so
 * is pinned by nothing. That is what rule 4's first half catches, and why control (d) is a fixture:
 * no real instance exists today.
 *
 * **Rule 4's second half is about the doc comment's own fence**, and it is a separate answer
 * because it fails in the opposite direction: a KDoc block fenced ` ```gradle ` while quoting a
 * Kotlin guide block is verbatim correct, resolves correctly, and is *rendered* to the integrator
 * with the wrong syntax highlighting — nothing above would say a word about it. Two lists rather
 * than one, so each control isolates its own defect.
 *
 * **The one weak link, stated rather than discovered.** The far end of the chain is another test
 * file. If `GuideSnippetTest` were weakened or deleted, every assertion here would stay green while
 * the guide blocks stopped being pinned to anything. Nothing in a unit test can prevent that; what
 * this file does instead is name it, and the task's control (f) runs those sibling suites
 * unmodified. The one half that *is* mechanical is [CORE_LOOP]: it is a `private val` of a
 * `private companion object` over there, so this file states its own copy and then asserts the two
 * are equal **by reading the literal out of `GuideSnippetTest.kt`'s source off disk**, the way
 * every scanner in this suite reads sources. Without that, the two lists drift in silence.
 *
 * **Three traps, named rather than left to be met.**
 *
 *  - A doc-comment line is prefixed `* `, a blank one is usually exactly `*` with no trailing
 *    space, and the compiler also accepts a continuation line with no asterisk at all. All three
 *    are handled by [stripComment], pinned by a fixture, and the resulting block is then dedented
 *    — so a fence indented inside the comment is read rather than silently skipped. The stated
 *    limit is that an asterisk-less continuation line cannot carry indentation of its own, which is
 *    true of KDoc itself.
 *  - **A guide block containing `*&#47;` cannot be embedded in a doc comment at all**: it would
 *    terminate the comment. Such a block is reported as unquotable rather than left to truncate
 *    something — control (h).
 *  - This file asserts what the markdown *says*, never how an IDE renders it. Whether the popup
 *    reads well is a human judgement (VISION), and an assertion pretending otherwise would be
 *    worse than none. Rule 4's second half is the edge of that line: it pins the *declared*
 *    language of a fence, which is a fact about the text, not a claim about the rendering.
 *
 * **Three limits, recorded rather than left to be discovered.**
 *
 *  - [docCommentsIn] delimits comments by walking string literals, char literals and comments, and
 *    it does not nest block comments — the limit `KDocCoverageTest`'s masker records, for the same
 *    reason. A `/` `*` in a doc comment's *prose* therefore ends the span early and every fence
 *    below it is published, unmarked and outside all seven rules. **The limit is open and the
 *    backstop is a parity check, not a parser**: `the comment walk sees every fence a line-wise
 *    count finds` counts the blocks a second time with a regex that shares no code with the walk
 *    ([DOC_FENCE_LINE]) and requires exactly two fence lines per block **in each source
 *    separately**. Read as parity rather than as proof: what it guarantees is that the walk and the
 *    text agree about *how many* blocks a file publishes, which a lost block cannot do alone. Two
 *    review passes are written into that sentence — one asserted nothing here at all and merely
 *    *stated* the arithmetic in prose, and the next cancelled a global sum by mis-spelling a fence
 *    in a second file, which is why the comparison is per source and why [scanIn] refuses an
 *    asterisk-less fence line outright.
 *
 *    **"Cannot do alone" is exact, and a later review pass measured the accomplices, so they are
 *    named here rather than left for the next pass to find.** Two parts are not enough: a lost
 *    block re-balanced by an asterisk-less fence pair is refused by rule 7 and opens nothing, and a
 *    block smuggled below a truncated span is caught by [memberAfter], which stops at the first
 *    non-asterisk line and attributes the comment to [UNRESOLVED] — that is the half rule 5's test
 *    refuses, and **it, not this parity check, is what closes the two-part construction.** What
 *    does get through is three parts together: a nested comment in the prose, a declaration-shaped
 *    asterisk-less line to satisfy [memberAfter], then asterisk-less fences around the smuggled
 *    block. Blocks and counted fence lines both move by zero, so parity holds and every rule is
 *    silent. Closing it means closing the nesting limit itself; nothing short of a real parser
 *    does, which is why the limit is stated rather than claimed shut.
 *  - [SOURCE_ROOT] is one directory, walked recursively. Everything this library publishes is in
 *    that package, but a published source in a *sibling* package would be outside the walk and
 *    invisible to all seven rules — silently, which is the wrong direction. Every scanner in this
 *    suite shares the limit; none of them has closed it.
 *  - Rule 7's enumeration, above. A leaf block [LEAF_BLOCK_LINE] does not list, with indented code
 *    directly beneath it, is still unread, as is any markup beyond [HTML_CODE_LINE]'s two tags that
 *    a renderer shows as code. That regex is case-insensitive, so the residue is other *tags* —
 *    not other spellings of these two, which a review pass closed after finding `<PRE>` open.
 *
 * Regex over nineteen files, so it runs in milliseconds: no Robolectric, and the one piece of
 * reflection is [resolvesToATest], which resolves an excuse's cited `@Test` and is not on the
 * scanning path at all.
 */
class KDocExampleTest {

    // ── What the files contain ────────────────────────────────────────────

    /**
     * A `&#47;**` … `*&#47;` span of a source file, and the lines it occupies.
     *
     * Both delimiters are written as entities here for a reason worth one line: **Kotlin block
     * comments nest**, so a literal opener inside this comment would open a second one and the
     * first terminator would close only that — which is how this file first failed to compile,
     * exactly as `BuildInputsTest`'s own KDoc records happening to it.
     */
    private class DocComment(val startLine: Int, val endLine: Int, val text: String)

    /** A fenced block inside a doc comment, with the marker above it if it has one. */
    private class Example(
        val file: String,
        /** The declaration the comment documents, bare: `createShareIntent`, `isVerified`. */
        val member: String,
        val lineNumber: Int,
        val language: String,
        val markerFile: String?,
        val markerName: String?,
        val lines: List<String>,
    ) {
        /** `INTEGRATION.md#login-request`, or null for a block with no marker. */
        val marker: String? = markerFile?.let { "$it#$markerName" }

        val where: String = "the `$language` example at $file:$lineNumber on `$member`"

        /** The key [NOT_AN_EXAMPLE] is spelled with: fence language and member, nothing else. */
        val excuseKey: String = "$language on $member"
    }

    /** A `<!-- snippet: … -->`-marked fenced block of the guide — the only addressable kind. */
    private class GuideBlock(
        val name: String,
        val language: String,
        val lines: List<String>,
        val lineNumber: Int,
    ) {
        val id: String = "$GUIDE_NAME#$name"

        val where: String = "$id ($GUIDE_PATH:$lineNumber)"
    }

    /**
     * Why a fenced block in a doc comment carries no marker, and what covers it instead — two
     * fields rather than one sentence, so [coveredBy] can be resolved against a real `@Test`
     * instead of taken on trust. `KDocCoverageTest`'s form, spelled `ClassName: test method name`.
     */
    private class Excuse(val reason: String, val coveredBy: String)

    /** Every complaint the files produce, so the real tests and the controls share one loop. */
    private class Audit(
        val examples: List<Example>,
        val guideBlocks: List<GuideBlock>,
        val unmarkedExamples: List<String>,
        val danglingMarkers: List<String>,
        val ambiguousGuideNames: List<String>,
        val mismatched: List<String>,
        val wrongLanguage: List<String>,
        val mislabelledExamples: List<String>,
        val missingExamples: List<String>,
        val unrelatedExamples: List<String>,
        val danglingExcuses: List<String>,
        val collidingExcuseKeys: List<String>,
        val unquotableGuideBlocks: List<String>,
        val unresolvedMembers: List<String>,
        val unreadableShapes: List<String>,
        /**
         * Fence lines counted **line-wise**, without the comment walk — the independent half of
         * the two-way count. See `the comment walk sees every fence a line-wise count finds`.
         */
        val fenceLines: Int,
        /**
         * Sources where the two counts disagree. **Per source, not summed**: a sum lets one file's
         * surplus cancel another's deficit, which is how a third review pass got a smuggled block
         * past the parity check by also mis-spelling a fence in a different file.
         */
        val fenceCountMismatches: List<String>,
    )

    // ── The one measurement every assertion below reads ───────────────────

    /**
     * Every published source's doc comments against the guide.
     *
     * A guide block whose name is carried by two blocks is held out of the resolution map entirely
     * rather than resolved arbitrarily: resolving it would report an example that *is* verbatim one
     * of them as drifted from the other, naming neither — a wrong answer dressed as a precise one.
     * `GuideSnippetTest`'s rule 4 forbids the duplication from the guide's own side; it is refused
     * here too so that nothing speaks about those names until it is fixed.
     */
    private fun audit(
        sources: Map<String, String>,
        guide: String,
        coreLoop: List<String>,
        excuses: Map<String, Excuse>,
    ): Audit {
        val scans = sources.entries.sortedBy { it.key }.map { scanIn(it.key, it.value) }
        val examples = scans.flatMap { it.examples }
        val guideBlocks = snippetBlocksIn(guide)

        val grouped = guideBlocks.groupBy { it.id }
        val duplicated = grouped.filterValues { it.size > 1 }
        val byId = grouped.filterValues { it.size == 1 }.mapValues { it.value.single() }

        val marked = examples.filter { it.marker != null }
        val unmarked = examples.filter { it.marker == null }
        val unmarkedKeys = unmarked.map { it.excuseKey }
        val documented = marked.map { it.member }.toSet()

        return Audit(
            examples = examples,
            guideBlocks = guideBlocks,
            unmarkedExamples = unmarked.filterNot { it.excuseKey in excuses }
                .map { "${it.where} — excuse key `${it.excuseKey}`" }
                .sorted(),
            danglingMarkers = marked.map { it.marker!! }
                .filterNot { it in byId || it in duplicated }
                .distinct()
                .sorted(),
            ambiguousGuideNames = duplicated.values
                .map { same -> same.joinToString(", ") { it.where } }
                .sorted(),
            mismatched = marked.mapNotNull { example ->
                val block = byId[example.marker] ?: return@mapNotNull null
                if (block.lines == example.lines) null else describeMismatch(example, block)
            }.sorted(),
            wrongLanguage = marked.mapNotNull { example ->
                val block = byId[example.marker] ?: return@mapNotNull null
                if (block.language == SNIPPET_LANGUAGE) {
                    null
                } else {
                    "${example.where} resolves to ${block.where}, which is fenced " +
                        "`${block.language}` rather than `$SNIPPET_LANGUAGE` — a block in another " +
                        "language has no region behind it, so nothing executes what this example " +
                        "prints"
                }
            }.sorted(),
            mislabelledExamples = marked.filterNot { it.language == SNIPPET_LANGUAGE }
                .map {
                    "${it.where} quotes a `$SNIPPET_LANGUAGE` guide block behind a " +
                        "`${it.language}` fence, so the popup an integrator reads highlights it as " +
                        "the wrong language. Verbatim and resolvable, and still wrong where it is " +
                        "read"
                }
                .sorted(),
            missingExamples = coreLoop.filterNot { it in documented },
            unrelatedExamples = marked.filter { it.member in coreLoop }.mapNotNull { example ->
                val block = byId[example.marker] ?: return@mapNotNull null
                if (block.lines.any { example.member in it }) {
                    null
                } else {
                    "${example.where} resolves to ${block.where}, which never names " +
                        "`${example.member}` — so rule 5 counts the name as exemplified while the " +
                        "popup shows an example of something else"
                }
            }.sorted(),
            danglingExcuses = excuses.keys.filterNot { it in unmarkedKeys }.sorted(),
            collidingExcuseKeys = unmarkedKeys.groupingBy { it }.eachCount()
                .filterValues { it > 1 }.keys.sorted(),
            unquotableGuideBlocks = guideBlocks
                .filter { block -> block.lines.any { COMMENT_END in it } }
                .map {
                    "${it.where} contains `$COMMENT_END`, which terminates a doc comment, so it " +
                        "cannot be quoted as a KDoc example at all"
                }
                .sorted(),
            unresolvedMembers = examples.filter { it.member == UNRESOLVED }
                .map { it.where }
                .sorted(),
            unreadableShapes = scans.flatMap { it.unreadable }.sorted(),
            fenceLines = scans.sumOf { it.fenceLines },
            fenceCountMismatches = scans.mapNotNull { scan ->
                val expected = FENCE_LINES_PER_BLOCK * scan.examples.size
                if (scan.fenceLines == expected) {
                    null
                } else {
                    "${scan.file}: ${scan.fenceLines} doc-comment fence line(s) counted line-wise " +
                        "but ${scan.examples.size} block(s) from the comment walk, which wants " +
                        "$expected"
                }
            }.sorted(),
        )
    }

    /**
     * The published sources against the guide, measured once for the whole class.
     *
     * `GuideSnippetTest`'s cache, for its reason: JUnit constructs a fresh instance per test
     * method, so a per-instance `by lazy` would re-read and re-scan nineteen files once per
     * assertion. The files cannot change within a run, and editing one re-runs the class.
     */
    private fun onDisk(): Audit = cachedOnDisk ?: audit(
        sources = publishedSources(),
        guide = locate(GUIDE_PATH).readText(),
        coreLoop = CORE_LOOP,
        excuses = NOT_AN_EXAMPLE,
    ).also { cachedOnDisk = it }

    // ── The six rules ─────────────────────────────────────────────────────

    @Test
    fun `every fenced block in a published doc comment names a guide block`() {
        assertEquals(
            "a fenced block in a published doc comment must be preceded by " +
                "`<!-- example: $GUIDE_NAME#block -->`. An unmarked block is code that an IDE " +
                "shows to an integrator and that nothing executes — which is exactly the state " +
                "every example in this library was in before this file existed",
            emptyList<String>(),
            onDisk().unmarkedExamples,
        )
        // Floor: a scanner that found no blocks at all would report no offenders for ever.
        assertTrue(
            "the published sources must carry example blocks for this to mean anything; found " +
                "${onDisk().examples.size}",
            onDisk().examples.size >= MINIMUM_EXAMPLES,
        )
    }

    /**
     * The two-way count, and it is the backstop for the one limit this file cannot close.
     *
     * [docCommentsIn] does not nest block comments, which Kotlin does. A `/` `*` in the *prose* of
     * a doc comment therefore ends the span at the first inner terminator, and every fence below
     * it is published, unmarked, rendered as code and **invisible to rules 1–7** — a review pass
     * demonstrated exactly that with every other assertion in this file green, because a scan that
     * never sees a block reports no offender for it.
     *
     * So the blocks are counted a second time, by a regex that knows nothing about where a comment
     * starts or stops ([DOC_FENCE_LINE]), and the two counts must agree: [FENCE_LINES_PER_BLOCK]
     * per block, no more and no fewer. It shares no code with the walk, which is the only reason it
     * can contradict it.
     *
     * **Two things make it load-bearing rather than belt-and-braces, and a fourth review pass
     * broke an earlier version that had neither.** The comparison is **per source**, because a
     * global sum lets one file's surplus cancel another's deficit. And the two counters agree on
     * what a fence line *is* by construction: the walk refuses an asterisk-less fence line as a
     * rule-7 shape, so it cannot open a block the counter will not count — see [scanIn], where the
     * probe that found this is written down.
     *
     * **It is not the same guard as [MINIMUM_EXAMPLES] and neither replaces the other.** Deleting
     * a whole block removes two fence lines and one block, so this stays balanced and the floor is
     * what reddens; a block the walk cannot see leaves the floor satisfied and unbalances this. One
     * notices the losing direction, one the gaining.
     *
     * Both of this test's own assertions are therefore *also* split that way: the per-source
     * comparison is an equality, because that is the parity claim, and the global count is only a
     * floor. It was an equality in the draft a review pass read, which made adding a legitimate
     * twelfth example a failing test — see the comment on the assertion itself.
     */
    @Test
    fun `the comment walk sees every fence a line-wise count finds`() {
        assertEquals(
            "in some published source, a line-wise count of doc-comment fence lines is not " +
                "exactly $FENCE_LINES_PER_BLOCK times the number of blocks the comment walk " +
                "found there — so the walk and the text disagree about how many fenced blocks " +
                "that file publishes. Usually the walk is the half that is wrong: a `/` `*` " +
                "inside a doc comment's prose truncates its span, and every rule here is then " +
                "silent about the fences below it, which is the whole reason this assertion " +
                "exists. It can also fire the other way, for a fence-shaped line in an ordinary " +
                "block comment or a raw string, which the line-wise count has no context to " +
                "exclude — read the numbers before deciding which. Fix the comment, or close the " +
                "nesting limit in `docCommentsIn`; do not relax this",
            emptyList<String>(),
            onDisk().fenceCountMismatches,
        )
        // Floor: a counter that found nothing agrees with a walk that found nothing.
        //
        // A floor rather than an equality, and the distinction is not cosmetic: the parity *claim*
        // is the per-source assertion above, which is exact. This half only has to rule out a
        // counter that counts nothing, so pinning it to the measured number would redden on the
        // next correctly-marked example somebody adds — a false red, and one contradicting
        // MINIMUM_EXAMPLES' own rationale that losing a block is worth a failure and gaining one
        // is not. A review pass found it pointed at exactly that, and T40 then added the twelfth
        // block: the floor moved with it and this assertion did not have to.
        assertTrue(
            "…and the two counts must be about something: $MINIMUM_EXAMPLES blocks are published " +
                "today, so the line-wise count must find at least twice " +
                "that; found ${onDisk().fenceLines}",
            onDisk().fenceLines >= FENCE_LINES_PER_BLOCK * MINIMUM_EXAMPLES,
        )
    }

    @Test
    fun `every example marker resolves to a guide block that exists`() {
        assertEquals(
            "an example marker names a guide block the guide does not contain. A renamed or " +
                "deleted block leaves the surface quoting nothing while still looking quoted",
            emptyList<String>(),
            onDisk().danglingMarkers,
        )
        assertEquals(
            "two guide blocks carry one snippet name, so nothing resolves a marker naming it and " +
                "no example quoting it is compared against anything. `GuideSnippetTest`'s rule 4 " +
                "refuses this from the guide's side; it is refused here so that an ambiguous name " +
                "is a failure rather than a coin toss",
            emptyList<String>(),
            onDisk().ambiguousGuideNames,
        )
        assertTrue(
            "the guide must carry snippet-marked blocks for any of this to resolve; found " +
                "${onDisk().guideBlocks.size}",
            onDisk().guideBlocks.size >= MINIMUM_GUIDE_BLOCKS,
        )
    }

    @Test
    fun `every example is its guide block verbatim`() {
        assertEquals(
            "a KDoc example has drifted from the guide block it quotes. The doc comment is not " +
                "the source of truth and neither is the guide: the guide block is a region of a " +
                "test that runs, so change the test, copy it into the guide, and copy the guide " +
                "across to here",
            emptyList<String>(),
            onDisk().mismatched,
        )
        // Floor: a comparison over zero pairs is also equal.
        assertTrue(
            "no example resolved to a guide block, so nothing was compared",
            onDisk().examples.count { it.marker != null } > 0,
        )
    }

    @Test
    fun `every example quotes a Kotlin block of the guide`() {
        assertEquals(
            "an example resolves to a guide block fenced in another language. Only a " +
                "` ```$SNIPPET_LANGUAGE ` block is quoted out of a test region — the guide's " +
                "`gradle` blocks are a consumer's own build file, which nothing here executes — " +
                "so an example naming one of those is published code with nothing behind it",
            emptyList<String>(),
            onDisk().wrongLanguage,
        )
        assertEquals(
            "…and the doc comment's own fence must say `$SNIPPET_LANGUAGE` too. This is the half " +
                "that fails in the other direction: the block is verbatim, the marker resolves, " +
                "and the one thing the integrator actually sees — the highlighting in the popup — " +
                "is wrong, with every other rule here green",
            emptyList<String>(),
            onDisk().mislabelledExamples,
        )
    }

    /**
     * Rule 7, and it exists because of what the scan *cannot* see rather than what it can.
     *
     * Every rule above speaks about a block found by a backtick fence at the start of a
     * prefix-stripped line. Five shapes are code in the IDE popup and invisible to that: a `~~~`
     * fence, a fence with an info string, a markdown indented code block, an HTML `<pre>`/`<code>`
     * block, and a fence the comment never closes. A Kotlin example in any of them is published
     * with nothing pinning it, and rule 1 would report no offender — three rounds of review
     * constructed exactly that evasion, which is why the rule is here and why its control drives
     * all five shapes, in nine spellings, through the same answer. The test is named after the
     * five rather than after every shape a renderer has, for the reason rule 7's entry in this
     * class's KDoc gives.
     *
     * The HTML pair is the one that earns its place twice over: every other refused shape opens a
     * fence line the parity count can see, so a block lost to it leaves a trace. `<pre>` leaves
     * none, and until a review pass went looking it was the only way to publish an unpinned Kotlin
     * example with every assertion in this file green.
     */
    @Test
    fun `no published doc comment holds one of the five code shapes this test cannot read`() {
        assertEquals(
            "a published doc comment holds something a renderer shows as code and this scan does " +
                "not read, so rules 1 to 6 are silent about it. Fence it with backticks and a " +
                "bare language word, or widen this parser deliberately",
            emptyList<String>(),
            onDisk().unreadableShapes,
        )
    }

    /**
     * Rule 5, and the floor it prints is the whole reason the file is worth its runtime: the eleven
     * names an afternoon integration touches must each be *shown*, not merely described.
     *
     * The member name a block is attributed to is read off the declaration the comment precedes, so
     * a comment this scanner could not attribute to anything would satisfy this rule by being
     * invisible to it. That is asserted first.
     */
    @Test
    fun `every function in the core loop carries an example`() {
        assertEquals(
            "every example block must be attributable to the declaration its comment documents, " +
                "or rule 5 is answered by a scan that found nothing. `$UNRESOLVED` means the " +
                "declaration matcher failed outright on the lines after a doc comment",
            emptyList<String>(),
            onDisk().unresolvedMembers,
        )
        assertEquals(
            "a function in the core loop carries no example on any of its published " +
                "declarations, so an integrator reading it in an IDE gets a signature and prose " +
                "and no line of code. These are the names VISION's direction 3 is about",
            emptyList<String>(),
            onDisk().missingExamples,
        )
        // And rule 5's one real loophole, which a review probe walked straight through: the rule
        // above counts a *marked block*, not a relevant one. Re-point one marker at another
        // section's block and the name stays "exemplified" while the popup shows something else.
        // Every one of the nineteen blocks already names the member it sits on, so this costs
        // nothing today and refuses the swap.
        assertEquals(
            "a core-loop name's example never mentions it, so rule 5 is satisfied by an example " +
                "of a different call. Quote the guide block that shows the member, or the two " +
                "assertions above are counting markers rather than examples",
            emptyList<String>(),
            onDisk().unrelatedExamples,
        )
        println(
            "KDocExampleTest: ${CORE_LOOP.size} core-loop names, " +
                "${onDisk().guideBlocks.size} snippet-marked guide blocks, " +
                "${onDisk().examples.size} example block(s) over " +
                "${onDisk().examples.map { it.file }.distinct().size} of " +
                "${publishedSources().size} published source(s)",
        )
    }

    @Test
    fun `nothing is excused, and no excuse is stale`() {
        assertEquals(
            "NOT_AN_EXAMPLE must be empty: every fenced block in a published doc comment was " +
                "marked when this test was written, so an entry here means somebody published a " +
                "code block backed by nothing and owes the next reader a reason",
            emptyMap<String, Excuse>(),
            NOT_AN_EXAMPLE,
        )
        assertEquals(
            "an excuse names a block that is either absent or marked after all, so it excuses " +
                "nothing — and a dead excuse would wave through whatever lands under that key next",
            emptyList<String>(),
            onDisk().danglingExcuses,
        )
        assertEquals(
            "two unmarked blocks share one excuse key, so one of them would be excused by the " +
                "other's reason. `GuideSnippetTest`'s rule, for its reason: give the second block " +
                "a member of its own, or there is no key that can name just one of them",
            emptyList<String>(),
            onDisk().collidingExcuseKeys,
        )
        assertEquals(
            "every excuse must carry a reason as well as a citation",
            emptyList<String>(),
            NOT_AN_EXAMPLE.filterValues { it.reason.isBlank() }.keys.sorted(),
        )
        assertEquals(
            "an excuse cites a @Test that does not exist under the class it names",
            emptyList<String>(),
            NOT_AN_EXAMPLE.entries
                .filterNot { resolvesToATest(it.value.coveredBy) }
                .map { "${it.key} -> ${it.value.coveredBy}" }
                .sorted(),
        )
        // The resolver must answer both ways, or over an empty map it reports success for nothing.
        assertTrue(resolvesToATest("KDocExampleTest: nothing is excused, and no excuse is stale"))
        assertFalse(resolvesToATest("KDocExampleTest: a test nobody wrote"))
        assertFalse(resolvesToATest("NoSuchTestClass: nothing is excused, and no excuse is stale"))
    }

    // ── The mirrored list, and the chain's far end ────────────────────────

    /**
     * [CORE_LOOP] against the literal `GuideSnippetTest` holds, read off disk.
     *
     * That list is a `private val` in a `private companion object` over there, so it cannot be
     * imported and this file states its own copy. An unchecked copy is a copy that drifts: the
     * next task to append a name to the guide's floor would append it to one list and not the
     * other, and whichever test was not edited would go on claiming a coverage it no longer
     * measures. Widening the sibling's visibility to avoid this would edit a verifier; a source
     * read costs nothing and edits nothing.
     *
     * The comparison is ordered, because list equality is — which is also the reason the names
     * below are in the sibling's disk order rather than in the order the task text happens to
     * enumerate them.
     */
    @Test
    fun `the core loop this test mirrors is GuideSnippetTest's own list`() {
        val sibling = testSource(SIBLING_TEST)
        val theirs = coreLoopIn(sibling.readText(), sibling.name)
        assertTrue(
            "the literal read out of ${sibling.absolutePath} must be non-empty, or this " +
                "assertion compares two lists neither of which was measured; found $theirs",
            theirs.isNotEmpty(),
        )
        assertEquals(
            "this file's CORE_LOOP must be `GuideSnippetTest`'s, name for name and in the same " +
                "order. One of the two lists was edited and the other was not, so one of the two " +
                "coverage floors is now measuring a surface that has moved. Read the literal in " +
                "${sibling.absolutePath}; do not retype it",
            theirs,
            CORE_LOOP,
        )
    }

    @Test
    fun `no guide block is unquotable in a doc comment`() {
        assertEquals(
            "a snippet-marked guide block contains `$COMMENT_END`, so quoting it as a KDoc " +
                "example would terminate the comment and publish the rest of the doc as code. " +
                "The block has to be rewritten; there is no escaping that helps here",
            emptyList<String>(),
            onDisk().unquotableGuideBlocks,
        )
    }

    // ── Negative controls ─────────────────────────────────────────────────
    //
    // Every one of these runs the *same* `audit` the assertions above run, over a fixture pair
    // instead of the real files, and asserts the same list is non-empty and names the right thing.
    // One mechanism, two answers — no second implementation to agree with the first.

    /**
     * (a) The verbatim comparison can report a mismatch.
     *
     * `#fixture-drift` differs from its guide block by one character — `42` against `43` — which is
     * the smallest drift a doc comment could suffer and the one a reader would never catch.
     */
    @Test
    fun `control - an example that differs from its guide block by one character is reported`() {
        val mismatched = fixtureAudit().mismatched
        assertEquals("exactly one fixture example is mis-quoted; found $mismatched", 1, mismatched.size)
        assertTrue(
            "the complaint must name the block it is about: $mismatched",
            mismatched.single().contains("#fixture-drift"),
        )
        assertTrue(
            "…and the member whose doc comment carries it: $mismatched",
            mismatched.single().contains("`drifted`"),
        )
        assertTrue(
            "…and show both sides, or a failure is unactionable: $mismatched",
            mismatched.single().contains("val answer = 42") &&
                mismatched.single().contains("val answer = 43"),
        )
    }

    /** (b) A marker naming a guide block that does not exist is reported, with file and name. */
    @Test
    fun `control - a marker naming a guide block that does not exist is reported`() {
        assertEquals(
            "a dangling marker must be reported naming the document and the block it asked for",
            listOf("$GUIDE_NAME#never-written"),
            fixtureAudit().danglingMarkers,
        )
    }

    /** (c) A fenced block in a doc comment with no marker above it is reported. */
    @Test
    fun `control - a KDoc fence with no marker is reported`() {
        val unmarked = fixtureAudit().unmarkedExamples
        assertEquals("found $unmarked", 1, unmarked.size)
        assertTrue(
            "the block must be located by member and by line: $unmarked",
            unmarked.single().contains("`unmarked`") && unmarked.single().contains("Fixture.kt:"),
        )
        assertTrue(
            "…and the excuse key it would be excused under must be printed, or nobody can write " +
                "the entry the failure asks for: $unmarked",
            unmarked.single().contains("`$SNIPPET_LANGUAGE on unmarked`"),
        )
    }

    /**
     * (d) Rule 4, and it is a fixture because no real instance exists.
     *
     * The fixture's `wrongLanguage` quotes a guide block that carries a snippet marker above a
     * ` ```gradle ` fence — the shape one edit to the guide's Setup section would produce. Its KDoc
     * copy is **verbatim equal** to that block on purpose: were it not, rule 3 would report it
     * first and this control would pass with rule 4 unimplemented.
     */
    @Test
    fun `control - an example quoting a marked non-Kotlin block is reported by rule 4`() {
        val wrong = fixtureAudit().wrongLanguage
        assertEquals("found $wrong", 1, wrong.size)
        assertTrue(
            "the complaint must name the member, the block and the language it found: $wrong",
            wrong.single().contains("`wrongLanguage`") &&
                wrong.single().contains("#fixture-gradle") &&
                wrong.single().contains("`gradle`"),
        )
        assertEquals(
            "the fixture's copy is verbatim its block, so rule 4 is the only thing wrong with " +
                "it — a control that also reddened rule 3 would pass with rule 4 deleted",
            emptyList<String>(),
            fixtureAudit().mismatched.filter { "fixture-gradle" in it },
        )
    }

    /**
     * (e) Rule 5 both ways, and the mirrored list's own check.
     *
     * The fixture declares one core-loop name with an example (`createShareIntent`) and one with a
     * doc comment but no fence (`isVerified`), so neither a rule that reports every name nor one
     * that reports none can pass this.
     */
    @Test
    fun `control - a surface missing an example for a core-loop name is reported`() {
        assertEquals(
            "exactly the core-loop names the fixture does not exemplify must be reported, in " +
                "order, and the two it does must not be — `parseShareResult` among them, because " +
                "rule 5 counts a marked block whether or not it is *about* the member, which is " +
                "the relevance rule's business and not this one's",
            CORE_LOOP.filterNot { it == "createShareIntent" || it == "parseShareResult" },
            fixtureAudit().missingExamples,
        )
        assertTrue(
            "the fixture must actually declare and document `isVerified` without a fence, or " +
                "this control is about a name nobody wrote",
            "fun isVerified" in FIXTURE_SOURCE,
        )

        val tampered = coreLoopIn(FIXTURE_SIBLING_SOURCE, "Fixture$SIBLING_TEST")
        assertEquals(
            "the reader must see the fixture literal's extra name, in place",
            CORE_LOOP + EXTRA_CORE_LOOP_NAME,
            tampered,
        )
        assertNotEquals(
            "a sibling whose CORE_LOOP literal gained a name must compare unequal to this " +
                "file's copy — the drift the mirrored assertion exists to catch",
            CORE_LOOP,
            tampered,
        )
    }

    /**
     * (g) Excuse hygiene, both directions, over a **fixture** map.
     *
     * [NOT_AN_EXAMPLE] is empty, and hygiene over an empty map proves nothing — which is why
     * `GuideSnippetTest:328` asserts its own map is non-empty before checking it. So the fixture
     * supplies the map as well as the source.
     */
    @Test
    fun `control - an unexcused block and a dead excuse are both reported`() {
        val excused = fixtureAudit(
            excuses = mapOf(
                "$SNIPPET_LANGUAGE on unmarked" to Excuse(FIXTURE_REASON, CONTROL_CITATION),
            ),
        )
        assertEquals(
            "excusing the unmarked block must silence the complaint, or the two halves of this " +
                "control are not reading the same map",
            emptyList<String>(),
            excused.unmarkedExamples,
        )
        assertEquals("…and it is not reported as dangling", emptyList<String>(), excused.danglingExcuses)

        val dead = fixtureAudit(
            excuses = mapOf("json on aMemberTheFixtureDoesNotHave" to Excuse(FIXTURE_REASON, CONTROL_CITATION)),
        )
        assertEquals(
            "an excuse naming no unmarked block must be reported: a block that was marked after " +
                "all leaves a dead excuse behind",
            listOf("json on aMemberTheFixtureDoesNotHave"),
            dead.danglingExcuses,
        )
        assertEquals(
            "…and the real unmarked block is reported again, since that excuse does not cover it",
            1,
            dead.unmarkedExamples.size,
        )
    }

    /**
     * (d2) Rule 4's second half: a KDoc fence that declares the wrong language.
     *
     * The fixture's `mislabelled` quotes `#fixture-ok` **verbatim** behind a ` ```gradle ` fence,
     * so rule 3 is silent, rule 2 resolves, rule 4's first half is silent — the guide block is
     * Kotlin — and this is the only answer with anything to say. Without it the mislabelling is
     * invisible to the whole file.
     */
    @Test
    fun `control - an example behind a fence of the wrong language is reported`() {
        val mislabelled = fixtureAudit().mislabelledExamples
        assertEquals("found $mislabelled", 1, mislabelled.size)
        assertTrue(
            "the complaint must name the member and the language the fence claims: $mislabelled",
            mislabelled.single().contains("`mislabelled`") &&
                mislabelled.single().contains("`gradle` fence"),
        )
        assertEquals(
            "nothing else may speak about it, or this control does not isolate the defect",
            emptyList<String>(),
            fixtureAudit().mismatched.filter { "mislabelled" in it } +
                fixtureAudit().wrongLanguage.filter { "mislabelled" in it } +
                fixtureAudit().danglingMarkers.filter { "fixture-ok" in it },
        )
    }

    /**
     * (k) Rule 7, in all five shapes and in the four *spellings* review probes got past earlier
     * drafts — without which rule 1 means only "no block the scan happened to find is unmarked".
     *
     * Each is a Kotlin example an IDE renders as code. A `~~~` fence and an info-string fence are
     * both markdown this file refuses rather than parses; an unclosed fence is the shape that used
     * to throw out of the scan instead of being reported, which killed unrelated assertions with
     * it; the indented block comes in three spellings, two of which were live evasions —
     * four spaces after a blank line, **one tab** after a blank line, and four spaces directly
     * under an `<!-- … -->` marker, which is a leaf block rather than a paragraph; and the HTML
     * family is the fourth and fifth live evasions, in the block spelling, the one-line spelling,
     * and the capitalised one with its `>` on the following line.
     */
    @Test
    fun `control - every code shape this test cannot read is reported, in all five`() {
        val shapes = audit(
            sources = mapOf("Shapes.kt" to FIXTURE_SHAPES_SOURCE),
            guide = FIXTURE_GUIDE,
            coreLoop = emptyList(),
            excuses = emptyMap(),
        )
        listOf(
            "a `~~~` fence" to "`$TILDE_FENCE` fence",
            "a fence with an info string" to "other than a bare language word",
            "an indented markdown code block" to "indented code block",
            "an HTML code block" to "`<pre>` or `<code>` block",
            "a fence the comment never closes" to "never closes",
            "a fence line carrying no `*` prefix" to "carrying no `*` prefix",
        ).forEach { (shape, phrase) ->
            assertTrue(
                "$shape must be reported: ${shapes.unreadableShapes}",
                shapes.unreadableShapes.any { phrase in it },
            )
        }
        // The asterisk-less pair must open nothing, or the parity check is cancellable again.
        assertEquals(
            "both halves of the asterisk-less fence must be refused, and neither may open a " +
                "block: ${shapes.unreadableShapes}",
            2,
            shapes.unreadableShapes.count { "carrying no `*` prefix" in it },
        )
        // …and the arithmetic of the parity count over this fixture, stated exactly, in control
        // (o)'s style. The previous spelling of this filtered `fenceCountMismatches` for
        // "asteriskLess" and asserted the result empty — **vacuous**, because those messages are
        // built from a file name and two integers and never carry a member name, so it was the
        // empty list for every possible input including a scanner that had stopped working. A
        // review pass caught it; the comment it carried was false of this fixture as well, since
        // `Shapes.kt` is deliberately *out* of parity. The honest claim is the number: 5 counted
        // fence lines (readable's 2, infoString's 2, unclosed's 1) against 1 walked block. The
        // asterisk-less pair and the three HTML members contribute 0 to both halves, which is what
        // the old assertion was reaching for and this one actually pins.
        assertEquals(
            "the parity count over this fixture must be exactly this, which is what says a " +
                "refused fence opens nothing *and* is counted nowhere: the asterisk-less pair and " +
                "the HTML members move neither half",
            listOf(
                "Shapes.kt: 5 doc-comment fence line(s) counted line-wise but 1 block(s) from " +
                    "the comment walk, which wants 2",
            ),
            shapes.fenceCountMismatches,
        )
        // The three indented spellings, each located, because two of them passed a draft of this
        // rule: a space-indented block after a blank line, a *tab*-indented one, and one under a
        // marker. Reported by line so that closing two of three cannot pass for closing all three.
        assertEquals(
            "all three indented spellings must be reported, at the lines the fixture puts them " +
                "on: ${shapes.unreadableShapes}",
            3,
            shapes.unreadableShapes.count { "indented code block" in it },
        )
        assertTrue(
            "every complaint must locate itself by file and line, or a failure is unactionable: " +
                "${shapes.unreadableShapes}",
            shapes.unreadableShapes.all { Regex("""^Shapes\.kt:\d+: """).containsMatchIn(it) },
        )
        // And the shape that *is* readable must not be reported, or the rule condemns every fence.
        assertEquals(
            "the fixture's one well-formed fence must be read as a block rather than refused, " +
                "and none of the other four may yield one",
            listOf("readable"),
            shapes.examples.map { it.member },
        )
        // Both HTML spellings, and the `<pre>` block's *closing* tag must not be a second
        // complaint: one defect, one answer. Its body line is unindented, so the indented-code
        // branch must stay off it too — which the arithmetic below is what actually pins.
        assertEquals(
            "all three HTML spellings must be reported, once each — the block, the one-line form " +
                "and the capitalised one whose `>` is on the next line. Closing one spelling must " +
                "not pass for closing three: ${shapes.unreadableShapes}",
            3,
            shapes.unreadableShapes.count { "`<pre>` or `<code>` block" in it },
        )
        assertEquals(
            "exactly thirteen complaints, and the arithmetic is the point: both lines of the " +
                "tilde fence, the info-string fence *and* the unclosed block its own closing line " +
                "opens, both lines of the asterisk-less fence, the three indented spellings, the " +
                "three HTML blocks, and the unclosed fence. None from the readable comment, which " +
                "is the half that would fail if the rule condemned every fence, and none from a " +
                "closing `</pre>` or an unindented body line, which is what would inflate the " +
                "HTML count: ${shapes.unreadableShapes}",
            13,
            shapes.unreadableShapes.size,
        )
    }

    /**
     * (l) The member a block is attributed to, both ways.
     *
     * `unresolvedMembers` is what stops rule 5 being answered by a scan that attributed nothing,
     * and over the real sources it is empty — so it needed a fixture or deleting its computation
     * would have left every assertion green. The same fixture pins the annotation case the house
     * style only happens to avoid: `@JvmOverloads fun f(` is one line, and skipping annotation
     * lines without trying the declaration matcher on them first would attribute the comment to
     * whatever came next.
     */
    @Test
    fun `control - a comment attributable to no declaration is reported, and an annotated one is not`() {
        val attribution = audit(
            sources = mapOf("Attribution.kt" to FIXTURE_ATTRIBUTION_SOURCE),
            guide = FIXTURE_GUIDE,
            coreLoop = emptyList(),
            excuses = emptyMap(),
        )
        assertEquals(
            "a doc comment this scan cannot attribute to a declaration must be reported, not " +
                "counted: found ${attribution.unresolvedMembers}",
            1,
            attribution.unresolvedMembers.size,
        )
        assertTrue(
            "…naming the placeholder, so the failure says what went wrong: " +
                "${attribution.unresolvedMembers}",
            attribution.unresolvedMembers.single().contains(UNRESOLVED),
        )
        assertEquals(
            "…and a declaration carrying its annotation on its own line must still be attributed " +
                "to the function rather than skipped past",
            listOf("annotatedOnOneLine", UNRESOLVED),
            attribution.examples.map { it.member },
        )
    }

    /**
     * (n) Rule 5's loophole, both ways.
     *
     * The fixture's `parseShareResult` quotes a block that is verbatim, resolvable and correctly
     * fenced and never names it; its `createShareIntent` quotes one that does. A review probe
     * re-pointed one real marker at another section's block and every assertion in this file
     * stayed green, so this is the answer that refuses the swap — and the control asserts both
     * directions, because a rule that reported every example would pass the first half alone.
     */
    @Test
    fun `control - an example that never names the member it documents is reported`() {
        val unrelated = fixtureAudit().unrelatedExamples
        assertEquals("found $unrelated", 1, unrelated.size)
        assertTrue(
            "the complaint must name the member and the block it quotes instead: $unrelated",
            unrelated.single().contains("`parseShareResult`") &&
                unrelated.single().contains("#fixture-ok"),
        )
        assertEquals(
            "…and nothing else may speak about it, or the control does not isolate the defect",
            emptyList<String>(),
            fixtureAudit().mismatched.filter { "parseShareResult" in it } +
                fixtureAudit().mislabelledExamples.filter { "parseShareResult" in it } +
                fixtureAudit().wrongLanguage.filter { "parseShareResult" in it },
        )
        assertTrue(
            "…and `createShareIntent`, whose block does name it, must not be reported: a rule " +
                "that reported every core-loop example would pass the half above on its own",
            unrelated.none { "createShareIntent" in it },
        )
    }

    /**
     * (o) A block the comment walk never sees, and the two-way count as the **only** thing that
     * notices it.
     *
     * The fixture's prose holds a `/` `*` … `*` `/` comment. Kotlin nests those and
     * [docCommentsIn] does not, so the span ends inside it and the second fenced block — unmarked,
     * published, rendered as code — is outside everything rules 1 to 7 look at. Every one of them
     * is asserted silent here, which is what makes the two-way count load-bearing rather than
     * belt-and-braces.
     */
    @Test
    fun `control - a block the comment walk never sees is caught only by the two-way count`() {
        val nested = audit(
            sources = mapOf("Nested.kt" to FIXTURE_NESTED_SOURCE),
            guide = FIXTURE_GUIDE,
            coreLoop = emptyList(),
            excuses = emptyMap(),
        )
        assertEquals(
            "the walk must find only the block above the nested comment, or this fixture is not " +
                "reproducing the limit",
            1,
            nested.examples.size,
        )
        assertEquals(
            "…while the line-wise count finds both blocks' fences",
            4,
            nested.fenceLines,
        )
        assertEquals(
            "so the parity check must report that source, naming both counts",
            listOf(
                "Nested.kt: 4 doc-comment fence line(s) counted line-wise but 1 block(s) from " +
                    "the comment walk, which wants 2",
            ),
            nested.fenceCountMismatches,
        )
        // And every other answer is silent, which is the half that earns the test.
        assertEquals(
            "rule 1 cannot see the unmarked block, because the walk never produced it",
            emptyList<String>(),
            nested.unmarkedExamples,
        )
        assertEquals(
            "…and nor can rule 7: the truncated span holds no shape it refuses",
            emptyList<String>(),
            nested.unreadableShapes,
        )
        assertEquals(
            "…and nothing is mis-quoted, dangling or mislabelled either",
            emptyList<String>(),
            nested.mismatched + nested.danglingMarkers + nested.mislabelledExamples,
        )
    }

    /** (m) Two unmarked blocks on one member cannot share one excuse. */
    @Test
    fun `control - two unmarked blocks on one member cannot share an excuse`() {
        val key = "$SNIPPET_LANGUAGE on twoBlocks"
        val colliding = audit(
            sources = mapOf("Colliding.kt" to FIXTURE_COLLIDING_SOURCE),
            guide = FIXTURE_GUIDE,
            coreLoop = emptyList(),
            excuses = mapOf(key to Excuse(FIXTURE_REASON, CONTROL_CITATION)),
        )
        assertEquals(listOf(key), colliding.collidingExcuseKeys)
        // The excuse does silence the unexcused complaint, so the collision is the only finding —
        // which is exactly why it has to be reported separately.
        assertEquals(emptyList<String>(), colliding.unmarkedExamples)
        assertEquals(emptyList<String>(), colliding.danglingExcuses)
    }

    /** (h) A guide block that cannot be embedded in a doc comment at all is reported. */
    @Test
    fun `control - a guide block containing a comment terminator is reported unquotable`() {
        val unquotable = fixtureAudit().unquotableGuideBlocks
        assertEquals("found $unquotable", 1, unquotable.size)
        assertTrue(
            "the complaint must name the block and say why it cannot be quoted: $unquotable",
            unquotable.single().contains("#fixture-unquotable") &&
                unquotable.single().contains("terminates a doc comment"),
        )
    }

    /** (i) An ambiguous guide name is reported, and nothing else speaks about it. */
    @Test
    fun `control - two guide blocks sharing a name are reported and resolve to nothing`() {
        val ambiguous = audit(
            sources = mapOf("Fixture.kt" to FIXTURE_AMBIGUOUS_SOURCE),
            guide = FIXTURE_AMBIGUOUS_GUIDE,
            coreLoop = emptyList(),
            excuses = emptyMap(),
        )
        assertEquals("found ${ambiguous.ambiguousGuideNames}", 1, ambiguous.ambiguousGuideNames.size)
        assertTrue(
            "the complaint must name both blocks and where they are: " +
                "${ambiguous.ambiguousGuideNames}",
            ambiguous.ambiguousGuideNames.single().let {
                it.contains("$GUIDE_PATH:4") && it.contains("$GUIDE_PATH:9")
            },
        )
        assertEquals(
            "…and the example quoting it must not be reported as drifted, nor as dangling: " +
                "either would blame the wrong file",
            emptyList<String>(),
            ambiguous.mismatched + ambiguous.danglingMarkers,
        )
    }

    /**
     * (j) The three prefix spellings a doc-comment line can take, and the indentation rule.
     *
     * `* `, a bare `*` for a blank line, and a continuation line with no asterisk at all are all
     * legal Kotlin, and a comparison that mishandled any of them would fail on whitespace nobody
     * can see. The fixture's `spellings` member uses all three in one block; `indentedExample`
     * indents its whole block inside the comment, which is what the dedent is for.
     */
    @Test
    fun `control - every doc comment prefix spelling strips to the same text`() {
        assertEquals(
            "a `* ` line loses the asterisk and one space; a bare `*` becomes empty; a line with " +
                "no asterisk is left-trimmed, which is the one case that cannot carry indentation",
            listOf("val x = 1", "", "    nested = 2", "val y = 3", "", "x"),
            listOf("     * val x = 1", "     *", "     *     nested = 2", "   val y = 3", "", "*x")
                .map { stripComment(it) },
        )
        assertEquals(
            "the three spellings in one real block must compare equal through the same audit the " +
                "assertions above use, and the indented block must dedent to its guide block",
            emptyList<String>(),
            fixtureAudit().mismatched.filter {
                "fixture-spellings" in it || "indentedExample" in it
            },
        )
        assertTrue(
            "…and the fixture must genuinely contain an asterisk-less continuation line and an " +
                "indented fence, or neither half of this control is about anything",
            "\n       val second = 2\n" in FIXTURE_SOURCE &&
                "\n     *   ```$SNIPPET_LANGUAGE" in FIXTURE_SOURCE,
        )
        // The half above is "nothing is reported", which a comparison over *nothing* satisfies
        // just as well — and a review pass proved it: narrowing FENCE_OPEN so an indented fence
        // opens no block left all of this green, with `dedented`'s only non-trivial exercise in
        // the suite gone unobserved. So the witness is positive: the indented block must have
        // become an example, not merely have failed to complain.
        assertTrue(
            "the indented fence must be *read* as a block, or this control passes by comparing " +
                "nothing and the dedent is untested: ${fixtureAudit().examples.map { it.member }}",
            "indentedExample" in fixtureAudit().examples.map { it.member },
        )
        assertEquals(
            "…and the fixture must stay in parity, which is what says the indented fence was " +
                "counted line-wise as well as walked",
            emptyList<String>(),
            fixtureAudit().fenceCountMismatches,
        )
    }

    // ── Parsing ───────────────────────────────────────────────────────────

    /**
     * Every doc comment of one source, with the lines it spans.
     *
     * `KDocCoverageTest:838`'s walk, narrowed: string literals, char literals, line comments and
     * ordinary block comments are skipped so that a `/` `*` `*` sequence inside one of them is not
     * read as a doc comment. The same limit that file records applies — Kotlin nests block
     * comments and this does not, so a nested one is closed at the first inner terminator. No
     * published source contains one, and a comment this walk mis-delimited would show up as an
     * unclosed fence or an unresolved member rather than as silence.
     */
    private fun docCommentsIn(source: String): List<DocComment> {
        val comments = mutableListOf<DocComment>()
        var line = 1
        var index = 0
        while (index < source.length) {
            val isDoc = source.startsWith("/**", index)
            val end = when {
                isDoc -> endOfBlockComment(source, index + 3)
                source.startsWith("/*", index) -> endOfBlockComment(source, index + 2)
                source.startsWith("//", index) ->
                    source.indexOf('\n', index).let { if (it < 0) source.length else it }
                source.startsWith("\"\"\"", index) ->
                    source.indexOf("\"\"\"", index + 3).let { if (it < 0) source.length else it + 3 }
                source[index] == '"' || source[index] == '\'' ->
                    endOfQuoted(source, index + 1, source[index])
                else -> index + 1
            }
            val startLine = line
            for (cursor in index until end) if (source[cursor] == '\n') line++
            if (isDoc) {
                comments += DocComment(startLine, line, source.substring(index, end))
            }
            index = end
        }
        return comments
    }

    /** The index just past the `*&#47;` closing a block comment whose body starts at [from]. */
    private fun endOfBlockComment(source: String, from: Int): Int =
        source.indexOf(COMMENT_END, from).let {
            if (it < 0) source.length else it + COMMENT_END.length
        }

    /** The index just past the [quote] closing a literal whose body starts at [from]. */
    private fun endOfQuoted(source: String, from: Int, quote: Char): Int {
        var index = from
        while (index < source.length) {
            when (source[index]) {
                '\\' -> index++
                quote -> return index + 1
                '\n' -> return index
            }
            index++
        }
        return source.length
    }

    /**
     * One source's doc comments, read once: the blocks found, the shapes refused, and the
     * **line-wise** fence count of the whole file.
     *
     * [fenceLines] is counted over every line of the source rather than over the comment spans, on
     * purpose: the defect it exists to catch is a fence line that belongs to *no* span, because the
     * span ended early. See `the comment walk sees every fence a line-wise count finds`.
     */
    private class DocScan(
        val file: String,
        val examples: List<Example>,
        val unreadable: List<String>,
        val fenceLines: Int,
    )

    /**
     * Every fenced block in every doc comment of one source, attributed to the declaration the
     * comment documents — and, from the same walk, every shape rule 7 refuses.
     *
     * One walk rather than two on purpose: rule 7's whole claim is about what the *block* scan
     * cannot see, so a second scan with its own idea of where a fence begins could disagree with
     * this one and leave a gap between them. Here a line is either opening a block, inside one,
     * closing one, or a candidate for refusal, and the four cases are mutually exclusive by
     * construction.
     *
     * The comment's body is stripped line by line *before* any of that, which is what lets the
     * fence regexes be the same shape as the guide's and lets a fence indented inside the comment
     * be read rather than skipped.
     *
     * **A fence line must carry the comment's `*`**, which is the one place this walk is
     * deliberately narrower than Kotlin. [stripComment] accepts an asterisk-less continuation line
     * — that is a real KDoc spelling and control (j) pins it — but [DOC_FENCE_LINE], the
     * independent counter the parity check is built on, requires the asterisk. A third review pass
     * used exactly that disagreement: an asterisk-less fence pair adds a block and **no** counted
     * fence lines, which is precisely the offset needed to re-balance a block the walk lost to the
     * nesting limit, in any file. So the asymmetry is removed where it starts: an asterisk-less
     * fence line is refused by rule 7 and opens nothing, and the two counters then agree on what a
     * fence line is *by construction* rather than by coincidence.
     */
    private fun scanIn(fileName: String, source: String): DocScan {
        val lines = source.lines()
        val examples = mutableListOf<Example>()
        val unreadable = mutableListOf<String>()
        for (comment in docCommentsIn(source)) {
            val member = memberAfter(lines, comment.endLine)
            val raw = comment.text
                .removePrefix(COMMENT_START)
                .removeSuffix(COMMENT_END)
                .lines()
            val body = raw.map { stripComment(it) }

            /** Whether the line-wise counter can see the fence on body line [index]. */
            fun counted(index: Int): Boolean = DOC_FENCE_LINE.find(raw[index]) != null

            val refuseUncounted = { index: Int ->
                unreadable += "$fileName:${comment.startLine + index}: a fence line carrying no " +
                    "`*` prefix. It is legal KDoc, but it is invisible to the line-wise count the " +
                    "parity check uses, so a block opened by one would cancel a block lost " +
                    "elsewhere. Prefix it, like every other line of the comment"
            }

            var openedAt = -1
            var language = ""
            var block = mutableListOf<String>()
            for ((index, line) in body.withIndex()) {
                val where = "$fileName:${comment.startLine + index}"
                if (openedAt >= 0) {
                    if (FENCE_CLOSE.matches(line) && !counted(index)) {
                        // Looks like the close and cannot be counted, so it closes nothing: the
                        // block runs on and is reported unclosed below, which is two complaints
                        // for one defect and the loud direction.
                        refuseUncounted(index)
                        block += line
                    } else if (FENCE_CLOSE.matches(line)) {
                        val marker = if (openedAt > 0) MARKER.find(body[openedAt - 1]) else null
                        examples += Example(
                            file = fileName,
                            member = member,
                            lineNumber = comment.startLine + openedAt,
                            language = language,
                            markerFile = marker?.groupValues?.get(1),
                            markerName = marker?.groupValues?.get(2),
                            lines = dedented(block),
                        )
                        openedAt = -1
                    } else {
                        block += line
                    }
                    continue
                }
                val open = FENCE_OPEN.find(line)
                val trimmed = line.trimStart()
                when {
                    open != null && !counted(index) -> refuseUncounted(index)

                    open != null -> {
                        openedAt = index
                        language = open.groupValues[1]
                        block = mutableListOf()
                    }

                    trimmed.startsWith(TILDE_FENCE) -> unreadable += "$where: a `$TILDE_FENCE` " +
                        "fence. Markdown accepts it, this scan does not read it, and so nothing " +
                        "pins the code inside it — fence with backticks instead"

                    trimmed.startsWith(BACKTICK_FENCE) -> unreadable += "$where: a fence this " +
                        "scan cannot read — `$BACKTICK_FENCE` followed by something other than a " +
                        "bare language word. Widening the parser is a decision; spelling the " +
                        "fence plainly is not"

                    // Javadoc's code syntax rather than markdown's, and the one shape that is
                    // silent to every branch here *and* to the parity check: it opens no fence, so
                    // it is counted nowhere, and it indents nothing, so the rule below never looks.
                    HTML_CODE_LINE.containsMatchIn(line) -> unreadable += "$where: an HTML " +
                        "`<pre>` or `<code>` block. A renderer shows it as code, this scan reads " +
                        "no HTML, and — unlike every other refused shape — it opens no fence, so " +
                        "the line-wise parity count is silent about it too. It is the habit a " +
                        "Java-trained contributor reaches for first. Fence it with backticks and " +
                        "a bare language word"

                    // Markdown's *other* code syntax, and the one a review probe twice got past
                    // this rule. See [continuesAParagraph] and [indentColumnsOf] for the two
                    // conditions and for why each is the shape it is.
                    line.isNotBlank() &&
                        indentColumnsOf(line) >= INDENTED_CODE_COLUMNS &&
                        !continuesAParagraph(body, index) ->
                        unreadable += "$where: a markdown indented code block " +
                            "($INDENTED_CODE_COLUMNS columns, not continuing a paragraph), which " +
                            "renders as code and is invisible to every other rule in this file. " +
                            "Fence it, or reflow it so it is not read as code"
                }
            }
            if (openedAt >= 0) {
                unreadable += "$fileName:${comment.startLine + openedAt}: a fenced block its own " +
                    "doc comment never closes, so the block is pinned by nothing and the comment " +
                    "and the code below it cannot be told apart"
            }
        }
        return DocScan(
            file = fileName,
            examples = examples,
            unreadable = unreadable,
            fenceLines = lines.count { DOC_FENCE_LINE.find(it) != null },
        )
    }

    /**
     * The name of the declaration beginning at or after source line [endLine] + 1, bare.
     *
     * Annotations, blank lines and further comments between a doc comment and its declaration are
     * all legal and none of them is the declaration, so they are skipped. A comment this cannot
     * attribute yields [UNRESOLVED], which rule 5's test refuses rather than tolerates: a block
     * attributed to nothing would satisfy the core-loop floor by being invisible to it.
     */
    private fun memberAfter(lines: List<String>, endLine: Int): String {
        var probe = endLine
        while (probe < lines.size) {
            val trimmed = lines[probe].trim()
            val isComment = trimmed.isEmpty() || trimmed.startsWith("//") ||
                trimmed.startsWith("/*") || trimmed.startsWith("*")
            if (!isComment) {
                // The regex is tried *before* an annotation line is skipped, because
                // `@JvmOverloads fun generateNonce(` is one line and skipping it would attribute
                // the comment to whatever came next instead.
                DECLARED_NAME.find(lines[probe])?.let { return it.groupValues[1] }
                if (!trimmed.startsWith("@")) return UNRESOLVED
            }
            probe++
        }
        return UNRESOLVED
    }

    /**
     * How many columns of indentation [line] opens with, **with a tab expanded to the next stop**.
     *
     * Counting characters is the obvious implementation and it is wrong in the direction that
     * matters: markdown expands a tab to the next multiple of four, so a single tab opens an
     * indented code block while measuring one column. A review probe inserted exactly that — one
     * tab instead of four spaces — and the whole suite stayed green over an unpinned published
     * example.
     */
    private fun indentColumnsOf(line: String): Int {
        var columns = 0
        for (character in line) {
            when (character) {
                ' ' -> columns++
                '\t' -> columns += INDENTED_CODE_COLUMNS - (columns % INDENTED_CODE_COLUMNS)
                else -> return columns
            }
        }
        return columns
    }

    /**
     * Whether the indented line at [index] is continuing a paragraph rather than opening a code
     * block.
     *
     * **CommonMark's actual rule is that an indented code block cannot interrupt a paragraph** —
     * not that it must follow a blank line, which is what the first version of this asked and what
     * a review probe then walked through: an indented line directly under an `<!-- … -->` comment
     * follows a *leaf block*, so markdown reads it as code, and the surrounding example looked
     * marked and pinned while quoting nothing.
     *
     * So the question is asked the other way round. A line counts as a paragraph continuation only
     * when the line above it is ordinary prose; a blank line, a heading, a fence or an HTML comment
     * all end whatever came before them, and anything indented after one of those is code. That
     * direction is the conservative one: a shape nobody anticipated is *refused* with its file and
     * line rather than waved through, and the cost is that a deliberately indented non-code line in
     * one of those positions has to be reflowed.
     *
     * It is what keeps this rule off the 184 deeply indented `@param` and `@return` continuation
     * lines in `Utils.kt` alone, every one of which continues a paragraph.
     */
    private fun continuesAParagraph(body: List<String>, index: Int): Boolean {
        if (index == 0) return false
        val previous = body[index - 1]
        return previous.isNotBlank() && LEAF_BLOCK_LINE.find(previous) == null
    }

    /**
     * One doc-comment line with its prefix removed: leading whitespace, then one `*` if there is
     * one, then one space if there is one.
     *
     * That is KDoc's own rule, and it is why an asterisk-less continuation line is left-trimmed
     * rather than kept: it has no way to express indentation that a renderer would honour. Block
     * indentation inside the comment survives this and is removed by [dedented] instead.
     */
    private fun stripComment(line: String): String {
        val trimmed = line.trimStart()
        return if (trimmed.startsWith("*")) trimmed.substring(1).removePrefix(" ") else trimmed
    }

    /**
     * [lines] with their common leading indentation removed, and nothing else removed.
     *
     * `GuideSnippetTest:1108`'s dedent, applied to the other side of the same comparison: a blank
     * line is shorter than the indentation, so it maps to the empty string rather than being
     * sliced.
     */
    private fun dedented(lines: List<String>): List<String> {
        val indent = lines.filter { it.isNotBlank() }
            .minOfOrNull { line -> line.takeWhile { it == ' ' || it == '\t' }.length }
            ?: 0
        return lines.map { if (it.isBlank()) "" else it.substring(indent) }
    }

    /** Every `<!-- snippet: … -->`-marked fenced block of [markdown]. */
    private fun snippetBlocksIn(markdown: String): List<GuideBlock> {
        val lines = markdown.lines()
        val blocks = mutableListOf<GuideBlock>()
        var index = 0
        while (index < lines.size) {
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
                "a fenced block opened at line ${index + 1} of the guide is never closed"
            }
            SNIPPET_MARKER.find(if (index > 0) lines[index - 1] else "")?.let { marker ->
                blocks += GuideBlock(
                    name = marker.groupValues[2],
                    language = open.groupValues[1],
                    // Dedented like the KDoc side, and for symmetry rather than for any block
                    // that needs it: every guide fence sits at column 0 today, so this is a no-op
                    // on the real document. A review pass pointed out the asymmetry — the KDoc
                    // side is dedented and this side was not — which means a guide block indented
                    // inside a list would become impossible to quote, with rule 3 red and no
                    // spelling of the KDoc able to satisfy it. Applying the same transform to both
                    // sides is what makes "verbatim" a claim about the code rather than about the
                    // markdown's left margin.
                    lines = dedented(body),
                    lineNumber = index + 1,
                )
            }
            index = cursor + 1
        }
        return blocks
    }

    /**
     * The `CORE_LOOP` literal of a `GuideSnippetTest`-shaped source, in order.
     *
     * Exactly one declaration is required: two would make this read whichever came first and call
     * it the sibling's list. The one limit, recorded rather than left to be found — the literal is
     * read to its first `)`, so an entry containing one would truncate the list, and the mirrored
     * assertion would redden naming the names it lost rather than the reason.
     */
    private fun coreLoopIn(source: String, where: String): List<String> {
        val found = CORE_LOOP_LITERAL.findAll(source).toList()
        if (found.size != 1) {
            throw AssertionError(
                "expected exactly one `private val CORE_LOOP = listOf(...)` declaration in " +
                    "$where, which is where this file's mirrored copy is checked against; found " +
                    "${found.size}. If that list was renamed or moved, this test has to be " +
                    "pointed at its new spelling — it must not fall back to trusting the copy " +
                    "below",
            )
        }
        return QUOTED.findAll(found.single().groupValues[1]).map { it.groupValues[1] }.toList()
    }

    private fun describeMismatch(example: Example, block: GuideBlock): String {
        val firstDifference = block.lines.zip(example.lines).indexOfFirst { (a, b) -> a != b }
        val detail = if (firstDifference >= 0) {
            "first difference at block line ${firstDifference + 1}:\n" +
                "    guide: ${block.lines[firstDifference]}\n" +
                "    KDoc : ${example.lines[firstDifference]}"
        } else {
            "the guide block has ${block.lines.size} lines and the example has " +
                "${example.lines.size}"
        }
        return "${block.where} — ${example.where} is not its guide block verbatim; $detail"
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

    /** Every Kotlin source of the published package, keyed by file name. */
    private fun publishedSources(): Map<String, String> {
        val root = locate(SOURCE_ROOT)
        val sources = root.walkTopDown().filter { it.isFile && it.name.endsWith(KOTLIN) }.toList()
        check(sources.isNotEmpty()) { "no Kotlin sources under ${root.absolutePath}" }
        val shared = sources.groupBy { it.name }.filterValues { it.size > 1 }.keys.sorted()
        check(shared.isEmpty()) {
            "two published sources share a file name ($shared), so one of them would be dropped " +
                "from this scan silently"
        }
        return sources.associate { it.name to it.readText() }
    }

    /** One test source by file name, found by walking the test source root. */
    private fun testSource(fileName: String): File {
        val root = locate(TEST_SOURCE_ROOT)
        val found = root.walkTopDown().filter { it.isFile && it.name == fileName }.toList()
        check(found.size == 1) {
            "expected exactly one `$fileName` under ${root.absolutePath}; found ${found.size}. " +
                "This file reads that source off disk to check its own mirrored copy of " +
                "CORE_LOOP, so an ambiguous or absent one must fail rather than be skipped"
        }
        return found.single()
    }

    /**
     * [relative], located by walking up from the working directory.
     *
     * `GuideSnippetTest:1171`'s walk-up, for its reason: the working directory of a Gradle unit
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
            "cannot find `$relative` — this test pins the published surface against the guide and " +
                "must not be silently skipped. Working directory: $workingDirectory. Tried:\n" +
                tried.map { it.absolutePath }.distinct().joinToString("\n"),
        )
    }

    // ── Fixtures ──────────────────────────────────────────────────────────

    private fun fixtureAudit(excuses: Map<String, Excuse> = emptyMap()): Audit = audit(
        sources = mapOf("Fixture.kt" to FIXTURE_SOURCE),
        guide = FIXTURE_GUIDE,
        coreLoop = CORE_LOOP,
        excuses = excuses,
    )

    private companion object {
        private const val GUIDE_PATH = "docs/INTEGRATION.md"
        private const val SOURCE_ROOT = "src/main/java/dev/eryalabs/lim"
        private const val TEST_SOURCE_ROOT = "src/test/java"
        private const val KOTLIN = ".kt"

        /**
         * The sibling whose `CORE_LOOP` literal this file mirrors. Spelled without a directory so
         * it is not a path literal `BuildInputsTest`'s rule 3 has to have declared as an input: a
         * Kotlin source is compiled, and editing one already invalidates the test task.
         */
        private const val SIBLING_TEST = "GuideSnippetTest$KOTLIN"

        /**
         * The file name a marker spells, derived rather than written.
         *
         * Written out as a quoted literal, the bare file name would be a path literal of this
         * source, and `BuildInputsTest`'s rule 3 would report it as a document the suite reads and
         * the build file does not declare — which it is not: the declared spelling is the
         * directory-qualified [GUIDE_PATH], and that is the one this file opens. Rule 3 reads
         * comments as well as code, which is why the sentence above does not spell it either; its
         * own KDoc names rewording as the remedy and excusing as the thing never to reach for.
         */
        private val GUIDE_NAME = GUIDE_PATH.substringAfterLast('/')

        /** The one fence language a guide block is quoted out of a test region in. */
        private const val SNIPPET_LANGUAGE = "kotlin"

        private const val COMMENT_START = "/**"
        private const val COMMENT_END = "*/"

        /** What [memberAfter] returns when it cannot attribute a comment to a declaration. */
        private const val UNRESOLVED = "<unattributed>"

        /** The on-disk measurement, shared across this class's test instances. See [onDisk]. */
        private var cachedOnDisk: Audit? = null

        /**
         * The two floors, each set **at** the measured count rather than below it: 19 example
         * blocks over 4 published sources, and 16 snippet-marked guide blocks.
         *
         * At rather than below, because both counts are the subject here, and losing either is
         * worth a failure while adding to it is not. These are the *losing*-direction guards and
         * the two-way fence count is the gaining-direction one; neither replaces the other —
         * deleting a whole block removes one block and two fence lines, which leaves the two-way
         * count balanced and reddens only the floor below.
         */
        private const val MINIMUM_EXAMPLES = 19
        private const val MINIMUM_GUIDE_BLOCKS = 16

        /**
         * A fence, with leading whitespace tolerated because the comment prefix has already been
         * stripped and a block may still be indented inside the comment it sits in. Refusing an
         * indented fence here would make rule 1 blind to exactly the block somebody formatted
         * carefully — the opposite of the conservative direction.
         */
        private val FENCE_OPEN = Regex("""^\s*```(\w*)\s*$""")
        private val FENCE_CLOSE = Regex("""^\s*```\s*$""")

        /** The two fence spellings rule 7 speaks about, and markdown's indented-code width. */
        private const val BACKTICK_FENCE = "```"
        private const val TILDE_FENCE = "~~~"
        private const val INDENTED_CODE_COLUMNS = 4

        /**
         * An HTML code block's opening tag, which KDoc renders as code and this scan does not read.
         *
         * Rule 7's fifth shape, and a review pass found it open: `<pre>` opens no fence and indents
         * nothing, so it was silent to the tilde branch, the info-string branch, the indented-code
         * branch **and** the line-wise parity count at once — the only shape so far with no
         * backstop behind it at all. It is also the first thing a contributor used to Javadoc
         * writes.
         *
         * Matched anywhere on the line rather than only at its start, because `<pre>` and the code
         * it opens are routinely written on one line, and the closing tag needs no branch of its
         * own: the opener is enough to refuse the comment, and reporting both would be two
         * complaints for one defect. Measured when this was added: **no published source contains
         * either tag**, so the rule costs nothing today and refuses the shape before it arrives.
         *
         * **Case-insensitive, and a review pass is the reason.** The first spelling of this was
         * `[\s>/]`-terminated and case-*sensitive*, which left `<PRE>` walking through rule 7
         * exactly as `<pre>` had: HTML tag names are case-insensitive, both renderers show it as
         * code, and nothing else here would have said a word. The terminator is now `\b` rather
         * than a character class for the cousin found in the same pass — `<pre` with its `>` on the
         * following line is legal HTML and the class required a character that was not there. `\b`
         * still refuses `<precondition>`, since a word boundary needs a non-word character after
         * `pre`, and control (k) drives all three spellings.
         */
        private val HTML_CODE_LINE = Regex("""<(?:pre|code)\b""", RegexOption.IGNORE_CASE)

        /**
         * A line that ends whatever block came before it, so an indented line *after* it is code
         * rather than a paragraph continuation. See [continuesAParagraph].
         *
         * Deliberately a short list of the shapes reachable in a doc comment — a heading, either
         * fence, and either delimiter of an HTML comment, which is what every `example:` marker
         * is — rather than an attempt at CommonMark's block grammar. Anything this list does not
         * recognise is treated as prose, which is the *permissive* direction for exactly one
         * thing: a leaf block nobody thought of, with indented code directly under it. That is the
         * residual limit, and it is why rule 7's test is named after the shapes it enumerates.
         */
        private val LEAF_BLOCK_LINE = Regex("""^\s*(?:<!--|-->|#{1,6}\s|```|~~~)""")

        /**
         * A fence line of a doc comment, found **line-wise** — the second of the two ways the
         * blocks are counted, and the whole point is that it shares no code with the first.
         *
         * This is the `grep` the task's premise was measured with (`^\s*\* *` then the fence),
         * written as a regex so the suite can run it. It knows nothing about where a comment
         * begins or ends, which is exactly why it can disagree with [docCommentsIn] — and a
         * disagreement is the one signal that the comment walk lost a comment.
         *
         * Being context-free cuts both ways, and the parity check's failure message says so: a
         * fence-shaped `*`-prefixed line inside an ordinary block comment or a raw string would be
         * counted here and would correctly belong to no block, so the check would fire with the
         * walk behaving perfectly. No published source has one; if one arrives, the remedy is in
         * the source, and never a looser regex.
         */
        private val DOC_FENCE_LINE = Regex("""^\s*\*\s*```""")

        /** An open and a close. The parity check's constant, named so the arithmetic is readable. */
        private const val FENCE_LINES_PER_BLOCK = 2

        /** The KDoc marker this task introduces, and the guide marker `GuideSnippetTest` reads. */
        private val MARKER = Regex("""^\s*<!--\s*example:\s*(\S+)#(\S+)\s*-->\s*$""")
        private val SNIPPET_MARKER = Regex("""^<!--\s*snippet:\s*(\S+)#(\S+)\s*-->\s*$""")

        /**
         * A declaration's bare name, read off the first real line after a doc comment.
         *
         * An annotation is one of the leading alternatives, not only a line to skip, because
         * `@JvmOverloads fun x(` is a single line in Kotlin and this library's house style puts
         * the annotation on its own line only by convention. A type-parameter list before the
         * name is skipped for the same reason `KDocCoverageTest`'s head walk does it: without it,
         * `fun <T> x(` names `T`.
         */
        private val DECLARED_NAME = Regex(
            """^\s*(?:(?:@[\w.]+(?:\([^)]*\))?|public|private|internal|protected|open|abstract|""" +
                """final|sealed|data|enum|annotation|value|inner|companion|override|lateinit|""" +
                """const|suspend|inline|operator|infix|external|expect|actual|tailrec)\s+)*""" +
                """(?:class|object|interface|fun|val|var)\s+(?:<[^>]+>\s*)?([A-Za-z_]\w*)""",
        )

        private val CORE_LOOP_LITERAL = Regex("""private val CORE_LOOP = listOf\(([^)]*)\)""")
        private val QUOTED = Regex("\"([^\"]+)\"")

        /**
         * `GuideSnippetTest`'s core loop, mirrored — in **its** order, because list equality is
         * ordered and the assertion above compares against the literal read off disk. Read it
         * there; do not retype it.
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
         * **Nothing is excused today, and the assertion that says so is the point.** Every fenced
         * block in a published doc comment is marked. An entry is `Excuse(reason, coveredBy)`,
         * keyed the way a failure prints it: fence language, then the member the block sits on.
         */
        private val NOT_AN_EXAMPLE = emptyMap<String, Excuse>()

        /** What a fixture excuse cites: a real `@Test` of this class. */
        private const val CONTROL_CITATION =
            "KDocExampleTest: control - an unexcused block and a dead excuse are both reported"

        private const val FIXTURE_REASON = "a fixture gap, left open on purpose"

        /**
         * The name control (e)'s tampered sibling literal gains.
         *
         * It must be a name [CORE_LOOP] does not already carry, or the "tampered" literal gains a
         * *duplicate* rather than a name and the control stops being about drift. It was
         * `shareEntry` until T40 put that into the real list, which is the drift this constant
         * exists to detect happening to the constant itself.
         */
        private const val EXTRA_CORE_LOOP_NAME = "validateEntry"

        /**
         * The controls' fixture source, assembled from one-line literals rather than written as a
         * raw string, and the reason is load-bearing rather than fussy.
         *
         * A raw string would put ` ``` ` fences and `<!-- example: … -->` markers at the start of
         * their lines in **this** file. Nothing scans a test source for either today — this file
         * reads the *published* sources — but the next scanner to arrive would collect them, and
         * the failure would be in a file whose fixtures look like real examples. Written this way
         * each line sits behind an opening `"`. `GuideSnippetTest:1369`'s argument, where the same
         * shape is load-bearing rather than defensive.
         */
        private val FIXTURE_SOURCE = listOf(
            "object Fixture {",
            "",
            "    /**",
            "     * An example that is verbatim its guide block.",
            "     *",
            "     * <!-- example: INTEGRATION.md#fixture-ok -->",
            "     * ```kotlin",
            "     * val answer = 42",
            "     * ```",
            "     */",
            "    fun verbatim() = Unit",
            "",
            "    /**",
            "     * The same block, indented inside the comment — which the dedent has to undo.",
            "     *",
            "     *   <!-- example: INTEGRATION.md#fixture-ok -->",
            "     *   ```kotlin",
            "     *   val answer = 42",
            "     *   ```",
            "     */",
            "    fun indentedExample() = Unit",
            "",
            "    /**",
            "     * One character out, which is the drift a reader would never catch.",
            "     *",
            "     * <!-- example: INTEGRATION.md#fixture-drift -->",
            "     * ```kotlin",
            "     * val answer = 43",
            "     * ```",
            "     */",
            "    fun drifted() = Unit",
            "",
            "    /**",
            "     * A marker naming a block the guide never had.",
            "     *",
            "     * <!-- example: INTEGRATION.md#never-written -->",
            "     * ```kotlin",
            "     * val answer = 44",
            "     * ```",
            "     */",
            "    fun dangling() = Unit",
            "",
            "    /**",
            "     * A fence with no marker above it: published code pinned by nothing.",
            "     *",
            "     * ```kotlin",
            "     * val answer = 45",
            "     * ```",
            "     */",
            "    fun unmarked() = Unit",
            "",
            "    /**",
            "     * A marked guide block in another language, quoted verbatim so that rule 4 is",
            "     * the only thing wrong with it.",
            "     *",
            "     * <!-- example: INTEGRATION.md#fixture-gradle -->",
            "     * ```kotlin",
            "     * implementation(\"com.example:thing:1.0\")",
            "     * ```",
            "     */",
            "    fun wrongLanguage() = Unit",
            "",
            "    /**",
            "     * All three prefix spellings in one block: `* `, a bare `*`, and a continuation",
            "     * line with no asterisk at all.",
            "     *",
            "     * <!-- example: INTEGRATION.md#fixture-spellings -->",
            "     * ```kotlin",
            "     * val first = 1",
            "     *",
            "       val second = 2",
            "     * ```",
            "     */",
            "    fun spellings() = Unit",
            "",
            "    /**",
            "     * A core-loop name that *does* carry an example, and one that names it — so",
            "     * rule 5 cannot pass by reporting every name and the relevance rule stays quiet.",
            "     *",
            "     * <!-- example: INTEGRATION.md#fixture-core -->",
            "     * ```kotlin",
            "     * val request = Utils.createShareIntent(context, entry)",
            "     * ```",
            "     */",
            "    fun createShareIntent() = Unit",
            "",
            "    /**",
            "     * A core-loop name whose example is verbatim, resolvable, correctly fenced — and",
            "     * about something else entirely. Rule 5 counts it; the relevance rule does not.",
            "     *",
            "     * <!-- example: INTEGRATION.md#fixture-ok -->",
            "     * ```kotlin",
            "     * val answer = 42",
            "     * ```",
            "     */",
            "    fun parseShareResult() = Unit",
            "",
            "    /**",
            "     * Verbatim its guide block, behind a fence that claims the wrong language — the",
            "     * one defect every other rule here is silent about.",
            "     *",
            "     * <!-- example: INTEGRATION.md#fixture-ok -->",
            "     * ```gradle",
            "     * val answer = 42",
            "     * ```",
            "     */",
            "    fun mislabelled() = Unit",
            "",
            "    /**",
            "     * A core-loop name documented in prose and exemplified nowhere — the gap rule 5",
            "     * exists to find, and the state every one of these names was in.",
            "     */",
            "    fun isVerified() = Unit",
            "}",
        ).joinToString("\n")

        /**
         * Control (k): one readable fence and each of the four shapes rule 7 refuses.
         *
         * Its own source is assembled line by line for [FIXTURE_SOURCE]'s reason, and here that
         * matters more: a raw string would put a `~~~` fence and an unclosed ` ``` ` at the start
         * of their lines in this file, and an unclosed one is the kind of thing a future scanner
         * reads to the end of the file.
         */
        private val FIXTURE_SHAPES_SOURCE = listOf(
            "object Shapes {",
            "",
            "    /**",
            "     * The one shape this scan does read, so the rule cannot be condemning every fence.",
            "     *",
            "     * <!-- example: INTEGRATION.md#fixture-ok -->",
            "     * ```kotlin",
            "     * val answer = 42",
            "     * ```",
            "     */",
            "    fun readable() = Unit",
            "",
            "    /**",
            "     * Markdown accepts a tilde fence; nothing here reads one.",
            "     *",
            "     * ~~~kotlin",
            "     * val tildes = 1",
            "     * ~~~",
            "     */",
            "    fun tildes() = Unit",
            "",
            "    /**",
            "     * An info string beyond the language word, which the fence regex refuses.",
            "     *",
            "     * ```kotlin title=example",
            "     * val infoString = 2",
            "     * ```",
            "     */",
            "    fun infoString() = Unit",
            "",
            "    /**",
            "     * A fence line with no `*` prefix. Legal KDoc, and the asymmetry a fourth review",
            "     * pass used to cancel the parity check: the walk would once have opened a block",
            "     * here that the line-wise counter does not count.",
            "     *",
            "     * <!-- example: INTEGRATION.md#fixture-ok -->",
            "       ```kotlin",
            "     * val answer = 42",
            "       ```",
            "     */",
            "    fun asteriskLessFence() = Unit",
            "",
            "    /**",
            "     * Markdown's other code syntax: four spaces after a blank line.",
            "     *",
            "     *     val indented = 3",
            "     */",
            "    fun indented() = Unit",
            "",
            "    /**",
            "     * The same thing spelled with one tab, which markdown expands to a four-column",
            "     * stop while a character count sees one. A review probe's evasion, verbatim.",
            "     *",
            "     *\tval tabbed = 5",
            "     */",
            "    fun tabbed() = Unit",
            "",
            "    /**",
            "     * And indented directly under a marker, which ends a leaf block rather than a",
            "     * paragraph — so markdown reads what follows as code, and the member looks",
            "     * marked and pinned while quoting nothing. The other probe's evasion.",
            "     *",
            "     * <!-- example: INTEGRATION.md#fixture-ok -->",
            "     *     val afterAMarker = 6",
            "     */",
            "    fun afterAMarker() = Unit",
            "",
            "    /**",
            "     * Javadoc's code syntax, not markdown's. A fifth review pass found this one open:",
            "     * it opens no fence and indents nothing, so every branch above it was silent and",
            "     * so was the parity count, which is the only shape that has been true of.",
            "     *",
            "     * <pre>",
            "     * val html = 7",
            "     * </pre>",
            "     */",
            "    fun htmlPre() = Unit",
            "",
            "    /**",
            "     * The same tag family on one line, which is how it is usually written.",
            "     *",
            "     * <code>val inlineCode = 8</code>",
            "     */",
            "    fun htmlCode() = Unit",
            "",
            "    /**",
            "     * And in capitals, with the `>` on the next line — both legal HTML, both rendered",
            "     * as code, and both walking through the first spelling of this rule. A review",
            "     * pass's evasion, verbatim.",
            "     *",
            "     * <PRE",
            "     * >val shouting = 9</PRE>",
            "     */",
            "    fun htmlUpperCase() = Unit",
            "",
            "    /**",
            "     * A fence the comment never closes.",
            "     *",
            "     * ```kotlin",
            "     * val unclosed = 4",
            "     */",
            "    fun unclosed() = Unit",
            "}",
        ).joinToString("\n")

        /**
         * Control (l): one comment this scan cannot attribute to a declaration, and one whose
         * declaration carries its annotation on the same line.
         *
         * `typealias` is the unattributable half because [DECLARED_NAME] recognises `class`,
         * `object`, `interface`, `fun`, `val` and `var` and nothing else — the same limit
         * `KDocCoverageTest` records of its own declaration matcher. Nothing this library
         * publishes is one; if that changes, this control is where the reason is written down.
         */
        private val FIXTURE_ATTRIBUTION_SOURCE = listOf(
            "object Attribution {",
            "",
            "    /**",
            "     * Its annotation and its `fun` share a line, which is legal Kotlin.",
            "     *",
            "     * <!-- example: INTEGRATION.md#fixture-ok -->",
            "     * ```kotlin",
            "     * val answer = 42",
            "     * ```",
            "     */",
            "    @JvmOverloads fun annotatedOnOneLine(only: Int = 0) = only",
            "}",
            "",
            "/**",
            " * A doc comment on a declaration shape this scan does not recognise.",
            " *",
            " * <!-- example: INTEGRATION.md#fixture-ok -->",
            " * ```kotlin",
            " * val answer = 42",
            " * ```",
            " */",
            "typealias Unattributable = Int",
        ).joinToString("\n")

        /**
         * Control (o): a doc comment whose prose holds a block comment, which Kotlin nests and
         * [docCommentsIn] does not — so the second fenced block below it is outside every rule in
         * this file and only the two-way count contradicts it.
         *
         * Assembled line by line like its neighbours, and here the reason is sharper than
         * convention: written as a raw string, the terminator in the middle of it would close
         * *this file's* own fixture declaration.
         */
        private val FIXTURE_NESTED_SOURCE = listOf(
            "object Nested {",
            "",
            "    /**",
            "     * A real example, above the comment that truncates the span.",
            "     *",
            "     * <!-- example: INTEGRATION.md#fixture-ok -->",
            "     * ```kotlin",
            "     * val answer = 42",
            "     * ```",
            "     *",
            "     * A note on comment syntax: /* like this */ in prose. Kotlin nests a block",
            "     * comment; this walk does not, so the span ends inside it.",
            "     *",
            "     * ```kotlin",
            "     * val smuggled = 1",
            "     * ```",
            "     */",
            "    fun nested() = Unit",
            "}",
        ).joinToString("\n")

        /** Control (m): two unmarked blocks on one member, hence one excuse key for both. */
        private val FIXTURE_COLLIDING_SOURCE = listOf(
            "object Colliding {",
            "",
            "    /**",
            "     * Two unmarked blocks, one member, one key.",
            "     *",
            "     * ```kotlin",
            "     * val first = 1",
            "     * ```",
            "     *",
            "     * ```kotlin",
            "     * val second = 2",
            "     * ```",
            "     */",
            "    fun twoBlocks() = Unit",
            "}",
        ).joinToString("\n")

        /**
         * The controls' fixture guide: one block of each kind the rules can speak about, plus the
         * one no doc comment can hold.
         *
         * The snippet markers name `GuideExamplesTest.kt` because that is what a real one names —
         * the *test source* a block was quoted out of. This file never reads that half: a block is
         * addressed by `<document>#<name>`, which is why [GuideBlock.id] is built from
         * [GUIDE_NAME] rather than from the marker's file.
         */
        private val FIXTURE_GUIDE = listOf(
            "## Fixtures",
            "",
            "<!-- snippet: GuideExamplesTest.kt#fixture-ok -->",
            "```kotlin",
            "val answer = 42",
            "```",
            "",
            "<!-- snippet: GuideExamplesTest.kt#fixture-drift -->",
            "```kotlin",
            "val answer = 42",
            "```",
            "",
            "<!-- snippet: GuideExamplesTest.kt#fixture-core -->",
            "```kotlin",
            "val request = Utils.createShareIntent(context, entry)",
            "```",
            "",
            "<!-- snippet: GuideExamplesTest.kt#fixture-spellings -->",
            "```kotlin",
            "val first = 1",
            "",
            "val second = 2",
            "```",
            "",
            "### Setup",
            "",
            "<!-- snippet: GuideExamplesTest.kt#fixture-gradle -->",
            "```gradle",
            "implementation(\"com.example:thing:1.0\")",
            "```",
            "",
            "### A block no doc comment can hold",
            "",
            "<!-- snippet: GuideExamplesTest.kt#fixture-unquotable -->",
            "```kotlin",
            "val comment = 0 /* and the end of it */",
            "```",
        ).joinToString("\n")

        /** Control (i): one name, two blocks, and an example quoting it. */
        private val FIXTURE_AMBIGUOUS_GUIDE = listOf(
            "## Duplicates",
            "",
            "<!-- snippet: GuideExamplesTest.kt#twice -->",
            "```kotlin",
            "val answer = 1",
            "```",
            "",
            "<!-- snippet: GuideExamplesTest.kt#twice -->",
            "```kotlin",
            "val answer = 2",
            "```",
        ).joinToString("\n")

        private val FIXTURE_AMBIGUOUS_SOURCE = listOf(
            "object Fixture {",
            "",
            "    /**",
            "     * Verbatim the first of the two, so a resolver that picked the last would report",
            "     * a correct example as drifted and name neither block as the cause.",
            "     *",
            "     * <!-- example: INTEGRATION.md#twice -->",
            "     * ```kotlin",
            "     * val answer = 1",
            "     * ```",
            "     */",
            "    fun ambiguous() = Unit",
            "}",
        ).joinToString("\n")

        /**
         * Control (e): a `GuideSnippetTest`-shaped source whose `CORE_LOOP` literal carries one
         * extra name.
         *
         * Built from [CORE_LOOP] rather than retyped, so that the control proves the *reader*
         * works on a list it did not write while staying in step with whatever the real list says.
         */
        private val FIXTURE_SIBLING_SOURCE: String = (
            listOf("        private val CORE_LOOP = listOf(") +
                (CORE_LOOP + EXTRA_CORE_LOOP_NAME).map { "            \"$it\"," } +
                listOf("        )")
            ).joinToString("\n")
    }
}
