package dev.eryalabs.lim

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The suite's first gate is `./gradlew :LIM:testDebugUnitTest`, and for three commits out of four
 * in this repository's recent history it proved nothing. This test is what stops that coming back.
 *
 * **The failure, measured rather than reasoned about.** Gradle decides whether a task is
 * UP-TO-DATE from its *declared* inputs. Main and test sources are declared, because they are
 * compiled — which is exactly why nobody noticed. A *document* is opened at test time with
 * `File.readText`, and Gradle cannot see that. So with `CHANGELOG.md` moved out of the tree
 * entirely, `:LIM:testDebugUnitTest` reported `UP-TO-DATE` and BUILD SUCCESSFUL, while
 * `--rerun-tasks` on the same tree failed 7 `ChangelogTest` tests; and breaking one member name in
 * a `CHANGELOG.md` bullet was green with no `--rerun` while reddening 4 of them with one. Three of
 * the four release-readiness artifacts this project owes a reader are documents.
 *
 * `LIM/build.gradle.kts` now declares them. This test holds that declaration honest, in three
 * rules:
 *
 *  1. every path in [VERIFIED_DOCUMENTS] exists on disk, located with the walk-up that fails
 *     *naming every absolute path it tried* — a locator that silently found nothing would make
 *     every rule below pass over an empty list;
 *  2. every one of them is declared in the build file under its own `withPropertyName`, and
 *     nothing else is — found by that property name rather than by line number, so moving the
 *     block does not break this and deleting a stanza does;
 *  3. every string literal in any Kotlin test source that names a repository file outside a source
 *     set — a path literal ending `.md`, `.api`, `.toml`, `.kts` or `.pro` — is in
 *     [VERIFIED_DOCUMENTS], or excused by name in [EXCUSES] with a reason and the test that
 *     covers it instead.
 *
 * **Rule 3 is the one that earns the file.** Rules 1 and 2 pin the documents
 * [VERIFIED_DOCUMENTS] already lists; rule 3 is what makes the *next* test that reads a new
 * document fail loudly instead of quietly never running. Which is also why [EXCUSES] is asserted
 * empty: excusing a document is precisely the way to pass this test while leaving its premise
 * intact.
 *
 * **The trap inside rule 3, and why the comparison resolves instead of matching strings.** Of the
 * path literals on disk, two are spelled *module*-relative while the declaration is
 * *root*-relative: `"build.gradle.kts"` (`ApiBaselineTest`, `ChangelogTest`) and `"api/lim.api"`
 * (the same two). A rule 3 that compared literals for equality would report both as undeclared
 * when they are declared, with no excuse available and nothing wrong. So each literal is resolved
 * through the same walk-up the tests themselves use and the resolved *file* is compared, not the
 * string.
 *
 * **What this test does not do, and the one thing a reader should not conclude from it.** It says
 * nothing about anything under `src/`: a `src/`-relative path literal is out of rule 3's scope, and
 * nobody should add a source directory to [VERIFIED_DOCUMENTS], because the three rules above are
 * about *documents*.
 *
 * But the usual reason given for that — "sources are compiled, so editing one already invalidates
 * the task" — is **not true of a comment**, and this was measured rather than assumed. The test
 * task's fingerprint of the main source set is the compiled output, so a comment edit invalidates
 * it only when the class files actually change. Deleting a KDoc block does (the line-number table
 * moves) and the suite re-ran; changing one character *in place* does not. `@param raw` →
 * `@param rww` in `FieldType.normalize`'s KDoc — which reddens two `KDocCoverageTest` rules under
 * `--rerun` — left `:LIM:testDebugUnitTest` UP-TO-DATE and BUILD SUCCESSFUL.
 *
 * So the hole this file closes for documents is still open for the main sources that
 * `KDocCoverageTest` and `ChangelogTest` read *as text*. Closing it means declaring a source
 * directory as a text input, which would re-run the whole suite on every comment edit — a cache
 * trade-off that is a decision, not a cleanup, and is deliberately left to one.
 *
 * **Two more edges of rule 3, stated so a green run is not read as more than it says.** It matches
 * a bare quoted path with one of five extensions, so a test that opened `LICENSE`, `jitpack.yml`
 * or `gradle.properties`, or that built its path by concatenation, would be invisible to it and
 * would re-create exactly the failure this file exists to stop. (`LIM/proguard-rules.pro` was in
 * that list until `ConsumerRulesTest` arrived and `pro` joined [PATH_LITERAL]; a `.pro` file a test
 * opens is now in scope like any other document, which is what rule 3 is for.) No test reads an
 * out-of-scope path today — that was checked, not assumed — but the next one to do it gets no
 * warning from here. And the scan reads comments as well as code, so a path named in prose *with
 * real quotes around it* is reported like any other; the remedy is to reword the comment, never to
 * excuse it. That happened on the very commit that added `pro`: `ConsumerRulesTest`'s header
 * quoted its own rules file in a sentence, rule 3 reported it, and the sentence was reworded.
 *
 * (A Kotlin KDoc nests its block comments, so writing a source directory as a `/`-`*` glob here
 * would open one. That is how this file first failed to compile.)
 *
 * Regex over the build file and a few dozen test sources, so it runs in milliseconds: no
 * Robolectric, no Gradle, no reflection beyond resolving an excuse's citation.
 */
class BuildInputsTest {

    // ── What the sources contain ──────────────────────────────────────────

    /**
     * One `inputs.files(...)` … `withPropertyName(...)` stanza of the build file, as two paths.
     *
     * [file] is what Gradle fingerprints; [label] is what the stanza calls it. They are read
     * separately because a stanza where they disagree is the one failure mode rule 2 could not
     * see before: correct label, correct task, wrong file. See [declarationsIn].
     */
    private class Declaration(val file: String, val label: String)

    /** A path literal found in a test source, with where it was found. */
    private class Literal(val path: String, val where: String) {
        /** How a failure should name it: the spelling used, and the line that used it. */
        val described: String = "$path ($where)"
    }

    /**
     * Why a path literal is left undeclared, and what covers it instead — two fields rather than
     * one sentence, so [Excuse.coveredBy] can be resolved against a real `@Test` instead of taken
     * on trust. `KDocCoverageTest`'s form, spelled `ClassName: test method name`.
     */
    private class Excuse(val reason: String, val coveredBy: String)

    /** Every complaint the sources produce, so the real tests and the controls share one loop. */
    private class Report(
        /** Every in-scope path literal found, for the floor that guards against an empty scan. */
        val literals: List<Literal>,
        /** In-scope literals resolving to no declared document, and not excused. */
        val undeclared: List<String>,
        /** Excuses naming a literal no test source contains. */
        val danglingExcuses: List<String>,
        /** Excuses naming a literal that is declared anyway, so they excuse nothing. */
        val inertExcuses: List<String>,
    )

    /**
     * Every path literal in [sources], judged against [VERIFIED_DOCUMENTS] and [excuses].
     *
     * Each literal is resolved through [resolve] and compared as a canonical file, which is what
     * makes a module-relative spelling and a root-relative one the same answer. A literal that
     * resolves to nothing at all cannot match a declared document and is reported by its spelling,
     * which is how a path that was renamed away — or never existed — is caught by the same rule.
     */
    private fun audit(sources: Map<String, String>, excuses: Map<String, Excuse>): Report {
        val declared = VERIFIED_DOCUMENTS.mapNotNull { resolve(it)?.canonicalFile }.toSet()

        val literals = sources.entries.sortedBy { it.key }.flatMap { (name, text) ->
            text.lines().mapIndexed { index, line ->
                PATH_LITERAL.findAll(line)
                    .map { Literal(it.groupValues[1], "$name:${index + 1}") }
                    .toList()
            }.flatten()
        }
        val inScope = literals.filterNot { it.path.startsWith(SOURCE_SET_PREFIX) }
        val spelled = inScope.map { it.path }.toSet()
        val gaps = inScope.filterNot { literal ->
            val resolved = resolve(literal.path)?.canonicalFile
            resolved != null && resolved in declared
        }

        return Report(
            literals = inScope,
            undeclared = gaps.filterNot { it.path in excuses }.map { it.described }.sorted(),
            danglingExcuses = excuses.keys.filterNot { it in spelled }.sorted(),
            inertExcuses = excuses.keys
                .filter { it in spelled && gaps.none { gap -> gap.path == it } }
                .sorted(),
        )
    }

    /**
     * Every test source against the real excuse map, measured once for the whole class.
     *
     * JUnit constructs a fresh instance per test method, so a per-instance `by lazy` would re-read
     * and re-scan every source for each of the tests below. `GuideSnippetTest`'s cache, for its
     * reason.
     */
    private fun onDisk(): Report =
        cachedOnDisk ?: audit(testSources(), EXCUSES).also { cachedOnDisk = it }

    // ── Rule 1: the listed documents exist ────────────────────────────────

    @Test
    fun `every verified document exists on disk`() {
        assertTrue(
            "VERIFIED_DOCUMENTS must list at least the ${MINIMUM_DOCUMENTS} documents the suite " +
                "is known to read; a list that shrank to nothing would make rules 2 and 3 pass " +
                "over it. The floor is kept equal to the list's size, so adding a document means " +
                "raising it by hand. Found: $VERIFIED_DOCUMENTS",
            VERIFIED_DOCUMENTS.size >= MINIMUM_DOCUMENTS,
        )
        assertEquals(
            "a path may not be listed twice: the second entry would be declared, checked and " +
                "reported by nothing of its own",
            VERIFIED_DOCUMENTS.distinct(),
            VERIFIED_DOCUMENTS,
        )
        // `locate` is the assertion: it throws naming every absolute path it tried.
        for (document in VERIFIED_DOCUMENTS) locate(document)
    }

    // ── Rule 2: the build file declares each of them ──────────────────────

    @Test
    fun `every verified document is declared as an input of the test task`() {
        val buildFile = locate(MODULE_BUILD_FILE)
        val text = buildFile.readText()
        val declared = declaredInputsIn(text)

        assertEquals(
            "${buildFile.absolutePath} must declare each verified document as an input of the " +
                "unit-test task, inside a `$TEST_TASK_SELECTOR` block and under " +
                "`withPropertyName(\"$PROPERTY_PREFIX<path>\")`. Without the declaration, " +
                "Gradle cannot see that the suite reads the document, so a commit changing only " +
                "that document comes back UP-TO-DATE and the test that checks it does not run",
            emptyList<String>(),
            VERIFIED_DOCUMENTS.filterNot { it in declared }.sorted(),
        )
        assertEquals(
            "a stanza's `inputs.files(...)` argument and its `withPropertyName` must name the " +
                "same path. The property name is only a label; the file Gradle actually " +
                "fingerprints is the argument, so a stanza whose halves disagree is a label on " +
                "the right task attached to the wrong file — every rule here would be green " +
                "while that document stopped being an input. This is the shape a document " +
                "rename takes when one of the two spellings is missed",
            emptyList<String>(),
            declarationsIn(text)
                .filterNot { it.file == it.label }
                .map { "${it.label} is declared on ${it.file}" }
                .sorted(),
        )
        assertEquals(
            "the base every declared path is resolved against must be pinned too, and exactly: " +
                "`${REPOSITORY_ROOT_LINE.trim()}`. Appending `.dir(\"docs\")` to it leaves every " +
                "stanza agreeing with itself and every rule here green while Gradle fingerprints " +
                "a whole set of files that do not exist — the one limit of this rule that would " +
                "otherwise fail *green* rather than red, which is the direction this file exists to " +
                "refuse. Matched as a whole line, so extending the expression is a mismatch",
            1,
            repositoryBaseLinesIn(text),
        )
        assertEquals(
            "the build file declares a verified-document input this test does not list, so " +
                "rules 1 and 3 say nothing about it — add it to VERIFIED_DOCUMENTS or stop " +
                "declaring it",
            emptyList<String>(),
            declared.filterNot { it in VERIFIED_DOCUMENTS }.sorted(),
        )
    }

    /**
     * The shortcut that would pass every other assertion in this file and pin nothing.
     *
     * `outputs.upToDateWhen { false }` on the test task makes the gate honest about documents by
     * making it honest about nothing: it cannot tell a changed `CHANGELOG.md` from a changed
     * `LICENSE`, so it re-runs the whole suite on every build for ever. It is refused here rather
     * than only in a comment, because a comment is not a verifier.
     */
    @Test
    fun `the declaration is an input set rather than a disabled up-to-date check`() {
        val buildFile = locate(MODULE_BUILD_FILE)
        val code = withoutComments(buildFile.readText())

        assertTrue(
            "${buildFile.absolutePath} must not disable the up-to-date check. The documents are " +
                "declared as inputs so that changing one re-runs the suite and changing " +
                "something else does not; `upToDateWhen { false }` buys the first half at the " +
                "price of the cache, for ever — it cannot tell a changed CHANGELOG.md from a " +
                "changed LICENSE",
            UP_TO_DATE_WHEN !in code,
        )
        assertTrue(
            "every declared input must be fingerprinted with RELATIVE path sensitivity, or the " +
                "absolute location of this checkout enters the cache key and the key stops " +
                "meaning the same thing on another machine. Found " +
                "${code.occurrencesOf(RELATIVE_SENSITIVITY)} for " +
                "${VERIFIED_DOCUMENTS.size} documents",
            code.occurrencesOf(RELATIVE_SENSITIVITY) >= VERIFIED_DOCUMENTS.size,
        )
        // Wrapped in a real selector block on purpose: an input with no block around it is
        // discarded before the comment stripper can matter, so the bare line would pass this
        // assertion even with `withoutComments` deleted.
        assertEquals(
            "both checks read the build file with its comments stripped, which is what lets the " +
                "block up there name the forbidden shortcut in prose so the next reader does " +
                "not reach for it. A commented-out declaration must count for nothing",
            emptyList<String>(),
            declaredInputsIn(
                "$TEST_TASK_SELECTOR.configureEach {\n" +
                    "// inputs.files(repository.file(\"ghost$DOT_MD\"))\n" +
                    "//     .withPropertyName(\"${PROPERTY_PREFIX}ghost$DOT_MD\")\n" +
                    "}",
            ),
        )
        assertEquals(
            "…and the same lines uncommented must be found, or the assertion above proves only " +
                "that the fixture was unparseable",
            listOf("ghost$DOT_MD"),
            declaredInputsIn(
                "$TEST_TASK_SELECTOR.configureEach {\n" +
                    "inputs.files(repository.file(\"ghost$DOT_MD\"))\n" +
                    "    .withPropertyName(\"${PROPERTY_PREFIX}ghost$DOT_MD\")\n" +
                    "}",
            ),
        )
    }

    // ── Rule 3: no test reads a document nobody declared ──────────────────

    @Test
    fun `every repository file a test source names is a declared input`() {
        assertTrue(
            "the scan found ${onDisk().literals.size} path literals, fewer than the " +
                "$MINIMUM_PATH_LITERALS measured when this file was written. A regex or a " +
                "locator that found nothing would make the assertion below pass over an empty " +
                "list, which is the one way this rule can rot silently",
            onDisk().literals.size >= MINIMUM_PATH_LITERALS,
        )
        assertEquals(
            "a test source names a repository file that is not a declared input of the test " +
                "task, so a commit changing only that file comes back UP-TO-DATE and the test " +
                "reading it does not run. Add it to VERIFIED_DOCUMENTS *and* to the build " +
                "file's declared-inputs block — this is the rule that exists so the next " +
                "document to arrive cannot arrive quietly",
            emptyList<String>(),
            onDisk().undeclared,
        )
    }

    // ── The excuse map, and that it is empty ──────────────────────────────

    @Test
    fun `nothing is excused, and no excuse is stale in either direction`() {
        assertEquals(
            "EXCUSES must be empty. Every document the rules above describe is declared, so an " +
                "entry here means somebody chose to excuse a file the test suite reads instead " +
                "of declaring it — which passes this test while leaving its whole premise " +
                "intact, and is the one outcome this file exists to prevent",
            emptyMap<String, Excuse>(),
            EXCUSES,
        )
        assertEquals(
            "an excuse names a path literal no test source contains. A renamed or deleted " +
                "literal leaves a dead excuse behind, and a dead excuse would wave through " +
                "whatever lands under that spelling next",
            emptyList<String>(),
            onDisk().danglingExcuses,
        )
        assertEquals(
            "an excuse names a path literal that is declared anyway, so it excuses nothing — " +
                "the document was declared and the excuse was not removed with it",
            emptyList<String>(),
            onDisk().inertExcuses,
        )
        assertEquals(
            "every excuse must carry a reason as well as a citation",
            emptyList<String>(),
            EXCUSES.filterValues { it.reason.isBlank() }.keys.sorted(),
        )
        assertEquals(
            "an excuse cites a @Test that does not exist under the class it names. A renamed or " +
                "moved test must be updated here too, or the path it excused is neither " +
                "declared nor covered",
            emptyList<String>(),
            EXCUSES.entries
                .filterNot { resolvesToATest(it.value.coveredBy) }
                .map { "${it.key} -> ${it.value.coveredBy}" }
                .sorted(),
        )
    }

    // ── Controls ──────────────────────────────────────────────────────────

    /**
     * (e) Rule 1 over a path that is not there: the locator must fail *naming every absolute path
     * it tried*, which is the difference between a test that found no document and a test that
     * found no documents to check.
     */
    @Test
    fun `control - a listed document that does not exist fails naming every path tried`() {
        val absent = "docs/NOT_A_DOCUMENT$DOT_MD"
        val failure = runCatching { locate(absent) }.exceptionOrNull()

        assertTrue("a missing document must fail, not resolve: $failure", failure is AssertionError)
        val message = failure?.message.orEmpty()
        assertTrue("the failure must name the path it wanted: $message", absent in message)
        assertTrue(
            "…and the working directory it started from: $message",
            "Working directory" in message,
        )
        assertTrue(
            "…and every absolute path it tried, so a reader can see where to put the file: " +
                message,
            File(".").absoluteFile.normalize().path in message,
        )
    }

    /**
     * (d) Rule 2 over a build file with one stanza taken out, and (the mutation) one whose
     * property name was renamed.
     *
     * All three are run against the real build file's text with one in-memory edit, so what rule 2
     * actually reads is what is being mutated. The rename is sharper than the removal: the path is
     * still in the file — on the `inputs.files(...)` line — and rule 2 must still report it,
     * because what Gradle keys the input on is the property name. The third is sharper again, and
     * is the one a reviewer asked for: every literal stays exactly where it is and only the block
     * they sit in changes type, which is what a refactor looks like and is a complete reopening of
     * the hole.
     */
    @Test
    fun `control - a removed, renamed or re-homed declaration is reported naming the path`() {
        val text = locate(MODULE_BUILD_FILE).readText()
        val victim = "README$DOT_MD"

        val removed = text.lines().filterNot { victim in it }.joinToString("\n")
        assertEquals(
            "a document whose stanza was deleted must be reported as undeclared",
            listOf(victim),
            VERIFIED_DOCUMENTS.filterNot { it in declaredInputsIn(removed) },
        )

        val renamed = text.replace("$PROPERTY_PREFIX$victim", "somethingElse:$victim")
        assertEquals(
            "a document whose `withPropertyName` was renamed must be reported too: the path " +
                "still appears in the file, but Gradle fingerprints the input under the " +
                "property name, so a renamed property is an undeclared document",
            listOf(victim),
            VERIFIED_DOCUMENTS.filterNot { it in declaredInputsIn(renamed) },
        )
        val reHomed = text.replace(TEST_TASK_SELECTOR, "tasks.withType<Copy>()")
        assertEquals(
            "a declaration attached to something other than the unit-test task must report " +
                "every document, not none. A `withPropertyName` is a label; what closes the " +
                "UP-TO-DATE hole is the label being on the task that reads the file, so rule 2 " +
                "has to be a statement about the block and not about the text",
            VERIFIED_DOCUMENTS,
            VERIFIED_DOCUMENTS.filterNot { it in declaredInputsIn(reHomed) },
        )
        assertEquals(
            "…and the same if the selector is gone altogether rather than mis-typed, which is " +
                "the branch that would otherwise return every stanza in the file",
            VERIFIED_DOCUMENTS,
            VERIFIED_DOCUMENTS.filterNot { it in declaredInputsIn(text.replace(TEST_TASK_SELECTOR, "")) },
        )

        // The two above both leave no `tasks.withType<Test>()` in the text at all, so a rule 2
        // that merely searched for the selector and then scanned the whole file would pass them.
        // This one does not: the selector survives, its block is closed empty, and every
        // stanza now sits in a block that configures something else entirely — which is what the
        // refactor this rule guards against actually looks like.
        val reHomedPastTheBlock = text.replace(
            "$TEST_TASK_SELECTOR.configureEach {",
            "$TEST_TASK_SELECTOR.configureEach { }\ntasks.register(\"documents\") {",
        )
        assertEquals(
            "a declaration outside every test-task block must be reported even though the " +
                "selector is still in the file. Rule 2 is a statement about the block; searching " +
                "the whole text would wave this through and reopen the hole completely",
            VERIFIED_DOCUMENTS,
            VERIFIED_DOCUMENTS.filterNot { it in declaredInputsIn(reHomedPastTheBlock) },
        )

        // …and the converse, which is what makes the brace *counting* load-bearing rather than a
        // scan to the first `}`: a nested brace inside the block must not end it.
        val nested = text.replace(
            REPOSITORY_ROOT_LINE,
            "    if (false) { logger.lifecycle(\"nothing\") }\n$REPOSITORY_ROOT_LINE",
        )
        assertTrue("the nesting mutation must have applied", nested != text)
        assertEquals(
            "a nested brace must not end the block. A scan to the first `}` would report every " +
                "document as undeclared on a build file that is entirely correct",
            emptyList<String>(),
            VERIFIED_DOCUMENTS.filterNot { it in declaredInputsIn(nested) },
        )

        assertEquals(
            "an unbalanced `{` inside the block must report nothing rather than run to the end " +
                "of the file: over-reporting is the direction that hides the re-homing above",
            VERIFIED_DOCUMENTS,
            VERIFIED_DOCUMENTS.filterNot {
                it in declaredInputsIn(text.replace(REPOSITORY_ROOT_LINE, "    run {"))
            },
        )
        // The sharpest of the lot, and the one a reviewer demonstrated end-to-end against the
        // real build: the label stays correct and on the correct task, and only the file it is
        // attached to changes. Measured before this assertion existed — all ten tests stayed
        // green and `README.md` went back to being UP-TO-DATE-invisible to the gate.
        val pointedElsewhere = text.replace(
            "repository.file(\"$victim\")",
            "repository.file(\"docs/NOT_A_DOCUMENT$DOT_MD\")",
        )
        assertTrue("the re-pointing mutation must have applied", pointedElsewhere != text)
        assertEquals(
            "a stanza whose `inputs.files(...)` names a different file than its " +
                "`withPropertyName` must not count as declaring either: the label is not the " +
                "input, the argument is",
            listOf(victim),
            VERIFIED_DOCUMENTS.filterNot { it in declaredInputsIn(pointedElsewhere) },
        )
        assertEquals(
            "…and the disagreement must be reported in its own words, naming both halves",
            listOf("$victim is declared on docs/NOT_A_DOCUMENT$DOT_MD"),
            declarationsIn(pointedElsewhere)
                .filterNot { it.file == it.label }
                .map { "${it.label} is declared on ${it.file}" },
        )

        assertEquals(
            "…and nothing else may be reported with it, or this control would pass for a rule " +
                "that simply fails",
            emptyList<String>(),
            VERIFIED_DOCUMENTS.filterNot { it in declaredInputsIn(text) },
        )
        assertEquals(
            "…and the real build file's stanzas must all agree with themselves",
            emptyList<String>(),
            declarationsIn(text).filterNot { it.file == it.label }.map { it.label },
        )

        // The base, which is the one mutation of this rule that would otherwise fail green:
        // every stanza still agrees with itself, and every path resolves against a directory
        // that does not exist.
        val reBased = text.replace(REPOSITORY_ROOT_LINE, "$REPOSITORY_ROOT_LINE.dir(\"docs\")")
        assertTrue("the re-basing mutation must have applied", reBased != text)
        assertEquals(
            "an extended resolution base must not be accepted: the stanzas are unchanged and " +
                "self-consistent, so nothing else here would notice",
            0,
            repositoryBaseLinesIn(reBased),
        )
        assertEquals(
            "…and the unmutated file must carry exactly one, or the assertion above would pass " +
                "for a build file that never had a base at all",
            1,
            repositoryBaseLinesIn(text),
        )
    }

    /**
     * (f) Rule 3 over a fixture source, which is where the trap is proved: the fixture names one
     * document root-relative, one module-relative, one that is in no source set and is declared by
     * nobody, and one inside a source set. Exactly the third must be reported.
     */
    @Test
    fun `control - an undeclared document is reported and a module-relative spelling is not`() {
        val report = fixtureAudit()

        assertEquals(
            "rule 3 must report exactly the fixture's one undeclared path, by spelling and line",
            listOf("$UNDECLARED_FIXTURE_PATH ($FIXTURE_NAME:4)"),
            report.undeclared,
        )
        assertEquals(
            "every path literal in the fixture outside a source set must be scanned — four of " +
                "the five, the fifth being the one under `src/`. Found: " +
                report.literals.map { it.described },
            4,
            report.literals.size,
        )
        assertTrue(
            "a path under a source set must be out of scope rather than reported: sources are " +
                "compiled, so editing one already re-runs the task. Found: " +
                report.literals.map { it.path },
            report.literals.none { it.path.startsWith(SOURCE_SET_PREFIX) },
        )
    }

    /** (f, continued) Excuse hygiene in both directions, over the same fixture. */
    @Test
    fun `control - excuse hygiene holds in both directions`() {
        val reason = "a fixture document, left undeclared on purpose"
        val citation =
            "BuildInputsTest: control - excuse hygiene holds in both directions"

        val suppressed = fixtureAudit(mapOf(UNDECLARED_FIXTURE_PATH to Excuse(reason, citation)))
        assertEquals(
            "an excused literal must disappear from the answer, or the map does nothing",
            emptyList<String>(),
            suppressed.undeclared,
        )
        assertEquals(
            "…and it is not reported as dangling",
            emptyList<String>(),
            suppressed.danglingExcuses,
        )
        assertEquals("…nor as inert", emptyList<String>(), suppressed.inertExcuses)

        val dangling = fixtureAudit(
            mapOf("docs/RENAMED_AWAY$DOT_MD" to Excuse(reason, citation)),
        )
        assertEquals(
            "an excuse naming a literal no source contains must be reported: a renamed literal " +
                "leaves a dead excuse behind",
            listOf("docs/RENAMED_AWAY$DOT_MD"),
            dangling.danglingExcuses,
        )
        assertEquals(
            "…and the real gap is still reported, since that excuse covered nothing",
            listOf("$UNDECLARED_FIXTURE_PATH ($FIXTURE_NAME:4)"),
            dangling.undeclared,
        )

        val inert = fixtureAudit(mapOf(VERIFIED_DOCUMENTS.first() to Excuse(reason, citation)))
        assertEquals(
            "an excuse for a document that is declared anyway must be reported too, or " +
                "declaring a document leaves behind an excuse that will silently cover the next " +
                "one to go undeclared",
            listOf(VERIFIED_DOCUMENTS.first()),
            inert.inertExcuses,
        )
        assertEquals(
            "…and it is not dangling, which is a different complaint",
            emptyList<String>(),
            inert.danglingExcuses,
        )

        assertTrue(
            "the citation these fixtures use must resolve to a real @Test, since that is what " +
                "the excuse-hygiene assertion above requires of a real entry",
            resolvesToATest(citation),
        )
    }

    /**
     * The regex itself, which is the one piece of rule 3 that can be wrong in a way no other
     * assertion here would notice: it has to match a bare path literal and nothing else.
     */
    @Test
    fun `control - the path literal regex matches a path and not prose about one`() {
        val matches = { text: String ->
            PATH_LITERAL.findAll(text).map { it.groupValues[1] }.toList()
        }
        val quoted = { path: String -> "val p = \"$path\"" }

        assertEquals(listOf("CHANGELOG$DOT_MD"), matches(quoted("CHANGELOG$DOT_MD")))
        assertEquals(
            listOf("gradle/libs.versions$DOT_TOML"),
            matches(quoted("gradle/libs.versions$DOT_TOML")),
        )
        assertEquals(
            "a sentence that mentions a document is prose, not a path a test opens; matching it " +
                "would make every failure message in this repository a rule 3 finding",
            emptyList<String>(),
            matches(quoted("cannot find docs/INTEGRATION$DOT_MD anywhere")),
        )
        assertEquals(
            "a bare extension is not a path",
            emptyList<String>(),
            matches(quoted(DOT_MD)),
        )
        assertEquals(
            "a Kotlin source is not one of the extensions this rule covers: it is compiled, so " +
                "it is already an input",
            emptyList<String>(),
            matches(quoted("src/main/java/dev/eryalabs/lim/Redaction.kt")),
        )
        assertEquals(
            "two literals on one line are two findings",
            listOf("CHANGELOG$DOT_MD", "api/lim$DOT_API"),
            matches("listOf(\"CHANGELOG$DOT_MD\", \"api/lim$DOT_API\")"),
        )
    }

    // ── Finding the files ─────────────────────────────────────────────────

    /**
     * [relative], located by walking up from the working directory, or a failure naming every path
     * it tried.
     *
     * `ApiBaselineTest:258`'s walk-up, for its reason: the working directory of a Gradle unit test
     * is the module directory, but that is a Gradle default rather than a promise, so every
     * ancestor is tried both as the module root and as the repository root. Each path is tried
     * module-relative as well, which is what lets `"build.gradle.kts"` and `"LIM/build.gradle.kts"`
     * name the same file — the trap rule 3 has to survive.
     */
    private fun locate(relative: String): File {
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
            "cannot find `$relative`, so nothing here can say whether the test task declares " +
                "it as an input — and a gate that cannot find the document it guards passes " +
                "for ever. Working directory: $workingDirectory. Tried:\n" +
                tried.map { it.absolutePath }.distinct().joinToString("\n"),
        )
    }

    /** [locate] without the failure: rule 3 reports an unresolvable literal rather than dying. */
    private fun resolve(relative: String): File? =
        runCatching { locate(relative) }.getOrNull()

    /**
     * Every Kotlin test source, keyed by file name.
     *
     * `GuideSnippetTest:1150`'s walk, for its reason: rule 3's claim is about *every* test source,
     * and a test added under a subpackage would otherwise be able to read an undeclared document
     * that no assertion here could see.
     */
    private fun testSources(): Map<String, String> {
        val root = locateDirectory(TEST_SOURCE_ROOT)
        val sources = root.walkTopDown().filter { it.isFile && it.name.endsWith(".kt") }.toList()
        check(sources.isNotEmpty()) { "no Kotlin test sources under ${root.absolutePath}" }
        val shared = sources.groupBy { it.name }.filterValues { it.size > 1 }.keys.sorted()
        check(shared.isEmpty()) {
            "two test sources share a file name ($shared), so a rule 3 finding could not name " +
                "one of them unambiguously"
        }
        return sources.associate { it.name to it.readText() }
    }

    /** [locate] for a directory rather than a file — the test source root. */
    private fun locateDirectory(relative: String): File {
        val workingDirectory = File(".").absoluteFile.normalize()
        val tried = mutableListOf<File>()
        var directory: File? = workingDirectory
        while (directory != null) {
            for (candidate in listOf(File(directory, relative), File(directory, "LIM/$relative"))) {
                tried += candidate
                if (candidate.isDirectory) return candidate
            }
            directory = directory.parentFile
        }
        throw AssertionError(
            "cannot find `$relative`, so rule 3 has no sources to scan and would pass over an " +
                "empty list. Working directory: $workingDirectory. Tried:\n" +
                tried.map { it.absolutePath }.distinct().joinToString("\n"),
        )
    }

    /**
     * The verified-document paths the build file declares, by their `withPropertyName`.
     *
     * Only the ones **inside a [TEST_TASK_SELECTOR] block**, which is the part that makes rule 2 a
     * statement about Gradle rather than about a string. A property name is a label; what closes
     * the UP-TO-DATE hole is the label being attached to the task that reads the document. Moving
     * these stanzas into `tasks.register("docs")`, or changing the selector's type argument,
     * is a plausible refactor that reopens the hole completely while leaving every literal in the
     * file untouched — so a search of the whole text would stay green through it.
     *
     * **Every** such block is scanned, not the first, so splitting the stanzas across two of them
     * is not a false alarm. What is still outside this function's reach is the parenthesis-free
     * `tasks.withType<Test> { … }` spelling, which would make rule 2 red on a build file that is
     * actually correct — the safe direction, and the fix is to spell it as [TEST_TASK_SELECTOR]
     * does.
     */
    private fun declaredInputsIn(buildFile: String): List<String> =
        declarationsIn(buildFile).filter { it.file == it.label }.map { it.label }

    /**
     * Every input declaration inside a [TEST_TASK_SELECTOR] block, as the pair of paths it
     * spells: the file handed to `inputs.files(...)` and the path its `withPropertyName` claims.
     *
     * Both halves are read because each stanza writes its path **twice** and only one of them is
     * the file Gradle fingerprints. Reading the label alone makes rule 2 a statement about a name:
     * point `inputs.files(...)` at a different document and leave the label, and every rule here
     * stays green while that document silently stops being an input — measured, it does, and
     * `README.md` went back to being invisible to the gate. [declaredInputsIn] therefore counts a
     * path as declared only when the two agree, and rule 2 reports a disagreement separately so
     * the failure says which half is wrong rather than just "undeclared".
     *
     * The two halves are paired by a lazy scan that refuses to cross another `inputs.files`, so a
     * stanza missing its label matches nothing instead of borrowing the next stanza's.
     */
    /**
     * How many lines inside a test-task block are exactly [REPOSITORY_ROOT_LINE].
     *
     * A whole line rather than a substring, which is the whole point: `inputs.files(...)` and
     * `withPropertyName(...)` pin the *path*, and nothing pins what the path is resolved
     * **against**. Extend the base to `…projectDirectory.dir("docs")` and every stanza still
     * agrees with itself, so every other rule here stays green while Gradle fingerprints a set of
     * files that do not exist. Substring matching would wave that through; line matching does not.
     */
    private fun repositoryBaseLinesIn(buildFile: String): Int =
        testTaskBlocksIn(withoutComments(buildFile)).sumOf { block ->
            block.lines().count { it.trimEnd() == REPOSITORY_ROOT_LINE }
        }

    private fun declarationsIn(buildFile: String): List<Declaration> =
        testTaskBlocksIn(withoutComments(buildFile)).flatMap { block ->
            DECLARED_INPUT.findAll(block)
                .map { Declaration(file = it.groupValues[1], label = it.groupValues[2]) }
                .toList()
        }

    /**
     * The body of every [TEST_TASK_SELECTOR] block in [code], delimited by counting braces from
     * the selector's own `{`.
     *
     * No string inside the real block contains a brace, which is why counting is enough. If one
     * ever does, the count is wrong in one of two ways and **both are resolved towards reporting
     * nothing**: a stray `}` ends the block early, and a stray `{` is never closed, which this
     * treats as a parse failure rather than running to the end of the file. The second case is the
     * one that matters — falling through would scan the rest of the build file and count a
     * declaration sitting *outside* any test-task block as declared, which is precisely the
     * refactor rule 2 exists to catch.
     */
    private fun testTaskBlocksIn(code: String): List<String> {
        val blocks = mutableListOf<String>()
        var from = 0
        while (true) {
            val selector = code.indexOf(TEST_TASK_SELECTOR, from)
            if (selector < 0) return blocks
            val open = code.indexOf('{', selector)
            if (open < 0) return blocks

            var depth = 0
            var end = -1
            for (index in open until code.length) {
                when (code[index]) {
                    '{' -> depth++
                    '}' -> if (--depth == 0) {
                        end = index
                        break
                    }
                }
            }
            if (end < 0) return blocks
            blocks += code.substring(open, end)
            from = end
        }
    }

    /**
     * [source] with its comments removed.
     *
     * Every rule that reads the build file reads it through this, which is what lets the block
     * above the declaration explain the shortcut it refuses by naming it. A rule that searched the
     * raw text would make the explanation its own violation, and the usual resolution of that is
     * to delete the explanation.
     *
     * Line comments are cut at the first `//`, which also cuts a `//` inside a string literal.
     * Harmless as the build file stands — the only such lines are the POM URLs in
     * `mavenPublishing {}`, which sits after the test-task block, so no brace the block matcher
     * depends on is lost. A URL inside the block would truncate its line, and the direction that
     * breaks is under-reporting, which reddens rule 2.
     */
    private fun withoutComments(source: String): String =
        source.replace(BLOCK_COMMENT, " ").lines().joinToString("\n") { it.substringBefore("//") }

    /** How many times [needle] occurs in this string. */
    private fun String.occurrencesOf(needle: String): Int = split(needle).size - 1

    private fun resolvesToATest(citation: String): Boolean {
        val className = citation.substringBefore(": ")
        val testName = citation.substringAfter(": ")
        return runCatching {
            Class.forName("dev.eryalabs.lim.$className").declaredMethods.any {
                it.name == testName && it.isAnnotationPresent(Test::class.java)
            }
        }.getOrDefault(false)
    }

    // ── Fixtures ──────────────────────────────────────────────────────────

    private fun fixtureAudit(excuses: Map<String, Excuse> = emptyMap()): Report =
        audit(mapOf(FIXTURE_NAME to FIXTURE_SOURCE.joinToString("\n")), excuses)

    private companion object {
        /**
         * Every repository file outside a source set that the unit-test suite opens at test time,
         * spelled as the build file declares it: relative to the repository root.
         *
         * This list is the subject of all three rules. It is not a convenience: rule 2 requires
         * the build file to declare each of these, and rule 3 requires every path literal in every
         * test source to be one of them, so the list is the single place where "the suite reads
         * this file" is written down once for Gradle and for the suite at the same time.
         */
        private val VERIFIED_DOCUMENTS = listOf(
            "CHANGELOG.md",
            "README.md",
            "docs/INTEGRATION.md",
            "LIM/api/lim.api",
            "gradle/libs.versions.toml",
            "settings.gradle.kts",
            "LIM/build.gradle.kts",
            "LIM/consumer-rules.pro",
        )

        /** The excuse map, and it is empty. See the test that says so. */
        private val EXCUSES = emptyMap<String, Excuse>()

        private const val MODULE_BUILD_FILE = "LIM/build.gradle.kts"
        private const val TEST_SOURCE_ROOT = "src/test/java"

        /** The prefix the build file spells every declared document's input property with. */
        private const val PROPERTY_PREFIX = "verifiedDocument:"

        /**
         * The block a declaration has to be inside to be one. See [declaredInputsIn].
         *
         * The AGP unit-test task is a plain `org.gradle.api.tasks.testing.Test`, so this selector
         * reaches it; any other selector reaches something that does not read these documents.
         */
        private const val TEST_TASK_SELECTOR = "tasks.withType<Test>()"

        /**
         * The block's first statement, used as the anchor the brace controls splice at.
         *
         * Named rather than inlined because those controls assert the splice applied: a mutation
         * whose anchor has drifted silently mutates nothing, and an assertion over an unmutated
         * build file passes for the wrong reason.
         */
        private const val REPOSITORY_ROOT_LINE =
            "    val repository = rootProject.layout.projectDirectory"

        /** The shortcut rule 2 refuses. Spelled once, as the build file would have to spell it. */
        private const val UP_TO_DATE_WHEN = "upToDateWhen"

        /** The fingerprinting every declared input must use; counted, not just looked for. */
        private const val RELATIVE_SENSITIVITY = "withPathSensitivity(PathSensitivity.RELATIVE)"

        /** Anything under here is compiled, so it is already an input. Out of rule 3's scope. */
        private const val SOURCE_SET_PREFIX = "src/"

        /**
         * A bare path literal naming a repository file: a whole double-quoted string, nothing
         * less.
         *
         * Anchored on both quotes on purpose. Half the failure messages in this suite mention a
         * document by name in prose — `"cannot find gradle/libs.versions.toml, so …"` — and an
         * unanchored match would report every one of them as a test reading an undeclared file.
         * What rule 3 is looking for is the literal a test *opens*, which is a path and only a
         * path. The first character must be a name character so that a bare extension is not a
         * path, and `.kt` is absent from the alternatives because a Kotlin source is compiled.
         *
         * `pro` is in the list because `ConsumerRulesTest` reads `LIM/consumer-rules.pro`, the rule
         * set this library ships into every consumer's R8 run. It was added with that test rather
         * than after it, and the difference was measured: with the extension absent, the whole of
         * this file was green over a new test whose document was declared nowhere at all.
         */
        private val PATH_LITERAL =
            Regex("\"([A-Za-z0-9_][A-Za-z0-9_./-]*\\.(?:md|api|toml|kts|pro))\"")

        /**
         * One input stanza: the path `inputs.files(...)` is given, then the path its
         * `withPropertyName` claims. See [declarationsIn] for why both.
         *
         * The receiver of `.file(...)` is matched loosely (any dotted identifier) so that
         * renaming the build file's local `repository` val, or inlining
         * `rootProject.layout.projectDirectory`, is not a false alarm. The middle is a lazy scan
         * **tempered against `inputs.files`**: without that, a stanza whose label was renamed
         * would silently pair with the *next* stanza's label and report two documents wrong
         * instead of one.
         */
        private val DECLARED_INPUT = Regex(
            """inputs\.files\(\s*[A-Za-z_][A-Za-z0-9_.]*\.file\("([^"]+)"\)\s*\)""" +
                """(?:(?!inputs\.files)[\s\S])*?""" +
                """\.withPropertyName\("$PROPERTY_PREFIX([^"]+)"\)""",
        )

        /** A slash-star comment, however many lines it spans. See [withoutComments]. */
        private val BLOCK_COMMENT = Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL)

        /**
         * Floors against a different failure than the rules above: a regex or a locator that found
         * nothing would make the assertions they guard pass over an empty list.
         *
         * [MINIMUM_PATH_LITERALS] sits below the value measured when this file was written (24
         * in-scope path literals over 4 test sources), so ordinary additions do not have to move it.
         *
         * [MINIMUM_DOCUMENTS] does **not**, and the difference is deliberate. It is equal to
         * [VERIFIED_DOCUMENTS]`.size`, so every document added to that list has to raise it by hand
         * — which is the point: the list is the one place where "the suite reads this file" is
         * written down, and a floor that trailed behind it would let the list shrink back to the
         * count it was last set at while rule 1 stayed green. It was 7 until
         * `LIM/consumer-rules.pro` became the eighth.
         */
        private const val MINIMUM_DOCUMENTS = 8
        private const val MINIMUM_PATH_LITERALS = 16

        /** The on-disk measurement, shared across this class's test instances. See [onDisk]. */
        private var cachedOnDisk: Report? = null

        // The extensions, held as constants so the fixtures below can name a path without this
        // file's own source containing one. See [FIXTURE_SOURCE].
        private const val DOT_MD = ".md"
        private const val DOT_API = ".api"
        private const val DOT_TOML = ".toml"

        private const val FIXTURE_NAME = "FixtureTest.kt"

        /** The one undeclared path the fixture names, built the same way the fixture is. */
        private const val UNDECLARED_FIXTURE_PATH = "docs/UNDECLARED$DOT_MD"

        /**
         * The controls' fixture source, and the reason every path in it is assembled from an
         * extension constant instead of written out is load-bearing rather than fussy.
         *
         * Rule 3 reads **every** Kotlin test source, this file among them. Written out, the
         * undeclared path below would be a path literal of this very file, and
         * `every repository file a test source names is a declared input` would fail on its own
         * control — with no excuse available, since [EXCUSES] must be empty. Assembled, this
         * file's source contains `"docs/UNDECLARED${'$'}DOT_MD"`, which [PATH_LITERAL] does not
         * match, while the string this fixture *is* at runtime contains the path in full.
         *
         * Line 4 is the one that must be reported; the controls cite that number, so nothing may
         * be inserted above it without updating them.
         */
        private val FIXTURE_SOURCE = listOf(
            """class FixtureTest {""",
            """    private val changelog = File(root, "CHANGELOG$DOT_MD")""",
            """    private val baseline = File(root, "api/lim$DOT_API")""",
            """    private val missing = File(root, "$UNDECLARED_FIXTURE_PATH")""",
            """    private val catalogue = File(root, "gradle/libs.versions$DOT_TOML")""",
            """    private val ownSource = File(root, "src/test/fixtures/Sample.kts")""",
            """}""",
        )
    }
}
