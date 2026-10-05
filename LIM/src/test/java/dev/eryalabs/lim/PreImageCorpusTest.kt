package dev.eryalabs.lim

import android.util.Base64
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.MessageDigest
import java.util.Locale
import java.util.Random

/**
 * The pre-image layout, pinned by a property over generated shapes rather than by frozen pairs.
 *
 * Injectivity is the property every signature in this library rests on: if two *different*
 * statements can produce the same bytes then a signature over one is a signature over the other.
 * `StatementPreImageTest` and `RecoveryPreImageTest` pin that with three hand-made collision
 * cases, a frozen Base64 per kind and a hand-built `ByteBuffer` oracle beside each one — all
 * necessary, none of it scaling. A frozen literal catches a change to the statement it names; it
 * says nothing about a component that is empty, multi-byte, 64 KB, or a timestamp whose big-endian
 * bytes spell a plausible length prefix. So the idea of an independent encoder is not new here;
 * what is new is running one over shapes nobody chose.
 *
 * The corpus is a few thousand component tuples from a `java.util.Random` pinned to one seed, so it
 * is the *same* corpus on every run and on every machine — a failure is reproducible from the log
 * rather than from a lucky rerun, and [PRE_IMAGE_CORPUS_DIGEST] pins the whole of it so that claim
 * cannot quietly stop being true. The pool is chosen to **collide under a naive encoder**, which is
 * what makes the four properties below mean something; the control that says so is
 * `a naive encoder collides on this corpus`.
 *
 * **One shape is deliberately kept out of the pool.** No `String` can encode an unpaired surrogate
 * to UTF-8, so a component containing one encodes to the same bytes as one containing `?` —
 * documented on `Utils.rotationStatementBytes` and pinned by `StatementPreImageTest`'s
 * `an unpaired surrogate is the one input the encoding cannot separate`. A corpus containing both
 * would make injectivity fail on *accepted* behaviour. So every prefix and truncation here is cut
 * at a code-point boundary, `no component is lost to the one equivalence the encoding has` proves
 * the corpus is clean, and the exception is turned into a control of its own rather than merely
 * avoided.
 *
 * `DecoderFuzzTest` is untouched by this file, so its own `CORPUS_DIGEST` cannot move.
 *
 * **Runtime, measured and kept.** 3.171s for the twelve tests here, against 4.062s for
 * `DecoderFuzzTest` and 14.9s for the whole module (479 tests, 0 skipped), summed from the
 * per-class `time` attributes in the JUnit XML under `LIM/build/test-results/testDebugUnitTest/`
 * on a full `--rerun-tasks` run timestamped 2026-10-05T15:25Z.
 *
 * That headline figure is the **cold** one and is worth reading carefully: in that run this class
 * happened to go first, so its first test carries 2.083s of one-time Robolectric and JIT bootstrap
 * that whichever class runs first pays. The eleven tests after it total 1.088s, and in a run where
 * another class went first this one measured 1.185s overall — so the honest statement is **~1.1s
 * of actual work, ~3.2s if it draws the short straw on ordering.** Either way it runs on every
 * tick, and a fuzz suite that doubles the module's test time is one that stops being run — which
 * is why the 64 KB draw below is weighted at four in a thousand rather than at one in a hundred,
 * why the generator floors count it rather than trusting the weight, and why every failure message
 * in this file is built inside a failure branch rather than handed to an `assertTrue` that
 * evaluates it on the passing path too.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class PreImageCorpusTest {

    /** Every assertion that touches [Locale] restores it here, whether it passed or failed. */
    private val defaultLocale: Locale = Locale.getDefault()

    @After
    fun restoreLocale() {
        Locale.setDefault(defaultLocale)
    }

    // ── The corpus ───────────────────────────────────────────────────────

    /** The three statement kinds, each with its kind tag spelled out rather than referenced. */
    private enum class Kind(val tag: String, val texts: Int) {
        ROTATE("lim.rotate.v1", 3),
        RECOVER("lim.recover.v1", 3),
        REVOKE("lim.revoke.v1", 2),
    }

    /**
     * One draw: three text components and two 64-bit components, enough to fill every kind.
     *
     * [seed] rides along so a failure names the draw that produced it, and [twinAt] records which
     * component boundary the boundary-shifted partner described on [twinOf] was built across —
     * `null` for an ordinary draw.
     */
    private data class Tuple(
        val seed: Long,
        val texts: List<String>,
        val longs: List<Long>,
        val twinAt: Int?,
    )

    /**
     * A tuple filled into one kind — the thing that actually gets encoded.
     *
     * Deliberately free of the draw it came from: equality is structural and is what the
     * injectivity property compares, so a seed or a twin marker in here would make two identical
     * statements look like two different ones.
     */
    private data class Element(val kind: Kind, val texts: List<String>, val longs: List<Long>)

    /** An element alongside the draw that produced it, so a failure can name both. */
    private data class Case(val tuple: Tuple, val element: Element)

    /**
     * Short components whose concatenations overlap heavily: prefixes of one another, and values
     * ending exactly where the next component would begin. A naive encoder merges many of these;
     * the real one must not.
     */
    private val boundaryTexts = listOf(
        "", "A", "B", "C", "AB", "BC", "ABC", "a", "ab", "bc", "abc", "K", "K2", "K2a",
    )

    /**
     * The shapes a hand-made case never reaches. `é` is two UTF-8 bytes and `𝄞` is a surrogate pair
     * encoding to four, so both separate a prefix counting *characters* from one counting bytes;
     * the two [LENGTH_SPELLING] values are text whose own UTF-8 bytes open with the big-endian
     * encoding of a plausible length, which is what a decoder resynchronising by scanning for a
     * length would trip over.
     */
    private val exoticTexts = listOf(
        "é", "éé", "rot-ééé", "éA", "𝄞", "𝄞𝄞", "A𝄞B", LENGTH_SPELLING, LENGTH_SPELLING_AB,
    )

    /**
     * The arithmetic edges, plus the near-neighbours that catch a width or sign-extension slip. A
     * timestamp and a sequence both arrive from a peer, so `Long.MIN_VALUE` and `-1` are exactly
     * what a hostile or clock-broken device puts there.
     */
    private val boundaryLongs = listOf(
        0L, 1L, -1L, 2L, -2L, 10L, 12L, 123L, -12L,
        Long.MIN_VALUE, Long.MIN_VALUE + 1, Long.MAX_VALUE, Long.MAX_VALUE - 1,
    )

    /**
     * Longs whose eight big-endian bytes are printable ASCII. Under the real encoder they are eight
     * raw bytes; under a naive one they are their decimal rendering, and the two are nothing alike.
     * They are here because a fixed-width field that *looks* like text is the shape most likely to
     * fool a reader that scans rather than counts.
     */
    private val asciiLongs = listOf(
        "00000005", "00000002", "AAAAAAAA", "lim.rot1", "    AB  ",
    ).map { asciiLong(it) }

    private fun drawText(rnd: Random): String {
        val roll = rnd.nextInt(1000)
        val base = when {
            roll < 650 -> boundaryTexts[rnd.nextInt(boundaryTexts.size)]
            roll < 996 -> exoticTexts[rnd.nextInt(exoticTexts.size)]
            // Rare on purpose, and the weight is load-bearing rather than taste: a 64 KB
            // component has to be in the corpus, but each one costs every arm below a 64 KB
            // encode, and a fuzz suite that doubles the module's test time is one that stops
            // being run. A few dozen draws is enough for the floor and cheap enough to keep.
            else -> HUGE_TEXT
        }
        // Prefixes of the drawn value, which is where much of the overlap the pool exists for
        // comes from. Cut at a code-point boundary so an astral pair is never split: a lone
        // surrogate encodes to the same byte as `?`, and a corpus containing both would make
        // injectivity fail on behaviour this library accepts and documents.
        return if (base.length <= TRUNCATION_LIMIT && rnd.nextInt(4) == 0) {
            prefixAtCodePoint(base, rnd.nextInt(base.length + 1))
        } else {
            base
        }
    }

    private fun drawLong(rnd: Random): Long = when (rnd.nextInt(10)) {
        in 0..5 -> boundaryLongs[rnd.nextInt(boundaryLongs.size)]
        6, 7 -> asciiLongs[rnd.nextInt(asciiLongs.size)]
        else -> rnd.nextLong()
    }

    /** A pure function of its seed, so a failure message naming the seed is a reproduction. */
    private fun tupleFor(seed: Long): Tuple {
        val rnd = Random(seed)
        return Tuple(
            seed = seed,
            texts = List(3) { drawText(rnd) },
            longs = List(2) { drawLong(rnd) },
            twinAt = null,
        )
    }

    /**
     * The partner that makes a naive collision structural rather than lucky: one code point moved
     * off the head of one component onto the tail of the one before it.
     *
     * The two tuples concatenate to the identical string, so an encoder joining components without
     * delimiting them hands the signer the same bytes for both — a rotation onto one key and a
     * rotation onto another. Relying on the random draw to stumble into such a pair would leave
     * `a naive encoder collides on this corpus` passing by luck, and a control that passes by luck
     * is one that will quietly stop.
     *
     * **Which boundary is chosen matters, and shifting only across the first one was the gap this
     * file was reviewed into closing.** A twin built always across `texts[0]`/`texts[1]` leaves the
     * `newPublicKey`/`statementId` boundary — the one `StatementPreImageTest`'s
     * `a statement id ending at a component boundary does not collide` pins by hand — reached by
     * nothing the generator produces, so the property would have generalised exactly one of the two
     * text boundaries the hand-made cases cover. The boundary is drawn from [Tuple.seed] rather
     * than from the master generator so a twin stays a pure function of its draw, and
     * `the generator really draws the shapes it claims` floors both boundaries separately.
     *
     * `null` when the component to the right is empty, since there is nothing to move, and when
     * either side is long, since the point is the boundary and not the copying.
     *
     * **Precondition, relied on and not checked here:** no pool entry ends in a high surrogate and
     * [prefixAtCodePoint] never produces one, so `left + right.substring(0, width)` cannot
     * manufacture a pair across the join and `right.codePointAt(0)` always sees a whole code point.
     * Adding a component with a trailing high surrogate would break that silently — which is what
     * `no component is lost to the one equivalence the encoding has` is there to catch.
     */
    private fun twinOf(tuple: Tuple): Tuple? {
        val at = Random(tuple.seed xor TWIN_SALT).nextInt(2)
        val left = tuple.texts[at]
        val right = tuple.texts[at + 1]
        if (right.isEmpty()) return null
        if (left.length > TRUNCATION_LIMIT || right.length > TRUNCATION_LIMIT) return null

        val width = Character.charCount(right.codePointAt(0))
        val shifted = tuple.texts.toMutableList()
        shifted[at] = left + right.substring(0, width)
        shifted[at + 1] = right.substring(width)
        return tuple.copy(texts = shifted, twinAt = at)
    }

    private fun tuples(): List<Tuple> {
        val master = Random(CORPUS_SEED)
        val out = ArrayList<Tuple>(TUPLES * 2)
        repeat(TUPLES) {
            val tuple = tupleFor(master.nextLong())
            out += tuple
            twinOf(tuple)?.let { out += it }
        }
        return out
    }

    /** Every kind the tuple fits. A revocation names no second key, so it takes the first two. */
    private fun elementsOf(tuple: Tuple): List<Case> = Kind.values().map { kind ->
        Case(tuple, Element(kind, tuple.texts.take(kind.texts), tuple.longs))
    }

    /**
     * The corpus, with the three floors every arm below needs stated once rather than per arm.
     *
     * Each arm used to carry its own `checked > TUPLES * 2`, and every one of those could not fail:
     * `tuples()` appends `TUPLES` elements unconditionally and each fills three kinds, so the
     * structural minimum was already 6000 against a threshold of 4000 — a corpus that lost a whole
     * kind, or a `TUPLES` cut to 300 for a quick local run, would have passed all of them. These
     * three are stated against the *draw* instead, so each of those three edits reddens every arm
     * in the file:
     *
     * - the element count is exactly one per kind per draw, so a lost kind is a failure;
     * - the draw count exceeds [TUPLES], so a [twinOf] that stopped producing twins is a failure;
     * - [TUPLES] itself is held at [MINIMUM_TUPLES], so shrinking the corpus is a failure.
     *
     * Only the middle one has teeth *today*: [elementsOf] maps over `Kind.values()`
     * unconditionally so the first holds by construction, and the third compares two constants
     * that are currently equal. They are guards against the three specific future edits named
     * above, not live checks on today's generator — which is exactly what the floors they replaced
     * failed to be, since those were stated against `TUPLES` multiples that the structural minimum
     * already exceeded and so could not have caught any of the three.
     */
    private fun corpus(): List<Case> {
        val draws = tuples()
        val cases = draws.flatMap(::elementsOf)

        if (cases.size != Kind.values().size * draws.size) {
            throw AssertionError(
                "every draw must fill every kind it fits: expected " +
                    "${Kind.values().size * draws.size} elements from ${draws.size} draws, got " +
                    "${cases.size}. A corpus that lost a kind would leave that kind's layout " +
                    "pinned by nothing in this file",
            )
        }
        if (draws.size <= TUPLES) {
            throw AssertionError(
                "twinOf must produce boundary-shifted partners, or `a naive encoder collides on " +
                    "this corpus` is left waiting on a coincidence: got ${draws.size} draws from " +
                    "TUPLES=$TUPLES",
            )
        }
        if (TUPLES < MINIMUM_TUPLES) {
            throw AssertionError(
                "the corpus must stay a few thousand tuples; TUPLES=$TUPLES is below " +
                    "MINIMUM_TUPLES=$MINIMUM_TUPLES",
            )
        }
        return cases
    }

    // ── The four properties ──────────────────────────────────────────────

    /**
     * Injectivity, over shapes nobody chose.
     *
     * Two distinct `(kind, components)` pairs must never produce the same bytes. The map is keyed
     * by a digest of the pre-image rather than by the bytes themselves — a 64 KB component makes a
     * 64 KB key — so a digest hit is re-encoded and compared **byte for byte** before anything is
     * reported, and a SHA-256 collision is named as one rather than printed as an encoder bug. The
     * earlier version of this arm claimed that guard in its KDoc while only comparing the two
     * `Element`s, which distinguishes a re-drawn identical element from a different one and says
     * nothing about the bytes.
     */
    @Test
    fun `no two distinct statements in the corpus share a pre-image`() {
        val seen = HashMap<String, Case>()
        var duplicates = 0
        var checked = 0

        corpus().forEach { case ->
            val bytes = preImage(case.element)
            val previous = seen.put(sha256Hex(bytes), case)
            checked++
            if (previous == null) return@forEach
            if (previous.element == case.element) {
                duplicates++
                return@forEach
            }
            val before = preImage(previous.element)
            if (!before.contentEquals(bytes)) {
                throw AssertionError(
                    "SHA-256 collision between two different pre-images — astronomically " +
                        "unlikely, so suspect the digest helper rather than the encoder:\n" +
                        describe(previous) + "\n" + describe(case),
                )
            }
            throw AssertionError(
                "two different statements share a pre-image, so a signature over one is a " +
                    "signature over the other:\n" + describe(previous) + "\n" + describe(case) +
                    "\n  shared pre-image = " + preview(bytes),
            )
        }

        // Non-vacuity, both ways: the corpus must have produced plenty of distinct pre-images, and
        // the duplicate branch above must have been reachable — otherwise it is dead code hiding
        // whatever it would have let through. The distinct-pre-image floor is stated as a fraction
        // of what was actually visited rather than against a constant, so it tracks the corpus.
        assertTrue(
            "the corpus must produce mostly distinct pre-images; got ${seen.size} from $checked",
            seen.size > checked / 2,
        )
        // The equal-elements branch has to be reachable too, or it is dead code hiding whatever it
        // would otherwise have let through. It is reached mostly via `Kind.REVOKE`, which projects
        // `texts[2]` away: any two draws agreeing on the first two texts and both longs collapse
        // to the same `Element`. A genuinely re-drawn tuple does it as well, but far more rarely —
        // worth naming, because "the generator re-draws sometimes" is the explanation a reader
        // reaches for and it is not the main one.
        assertTrue(
            "the equal-elements branch above is never exercised, so it is hiding whatever it " +
                "would have let through; got $duplicates",
            duplicates > 0,
        )
    }

    /**
     * Determinism: identical bytes on a repeated call, and on an independently constructed equal
     * object. String *identity* is exactly what a canonical encoding must not depend on, so the
     * second element's components are rebuilt character by character rather than copied.
     *
     * Spec-required and, honestly, by construction: all three encoders allocate a fresh
     * [ByteArrayOutputStream] per call, read no state and memoize nothing, so no production
     * mutation reddens this arm today. It is a guard against one being given a cache later, which
     * is the change that would make two equal statements sign differently.
     */
    @Test
    fun `the encoder is deterministic across calls and across equal objects`() {
        corpus().forEach { case ->
            val once = preImage(case.element)
            bytesDiffer(once, preImage(case.element))?.let {
                throw AssertionError("repeated calls differ: $it\n" + describe(case))
            }

            val rebuilt = case.element.copy(
                texts = case.element.texts.map { String(it.toCharArray()) },
                longs = case.element.longs.toList(),
            )
            if (rebuilt != case.element) {
                throw AssertionError("the rebuilt element must be equal to begin with")
            }
            bytesDiffer(once, preImage(rebuilt))?.let {
                throw AssertionError(
                    "two equal statements must sign to identical bytes: $it\n" + describe(case),
                )
            }
        }
    }

    /**
     * Layout agreement with an encoder written fresh from the documented layout.
     *
     * [referencePreImage] goes through [DataOutputStream] — whose `writeInt` and `writeLong` are
     * big-endian by contract — rather than through a shift loop, and it is deliberately *not*
     * `StatementPreImageTest`'s `handBuiltPreImage`: an oracle that pins one fixed statement stops
     * being independent the moment it is edited to take generated components. Over this corpus it
     * is what pins the four-byte prefix width, the component order and the big-endian direction
     * across every shape rather than across three.
     *
     * This is the arm the task's planted mutations have to redden, and all three do. Two of them
     * diverge on the **kind tag's own length prefix**, before any drawn component is reached: the
     * domain prefix occupies bytes 0-15, so a little-endian prefix differs at byte 16 (`0x0D`
     * against the reference's `0x00`) and `COMPONENT_LENGTH_BYTES` 4 → 2 differs at byte 17, where
     * production has already started the tag while the reference is still writing zeroes. The
     * third — the two long components swapped — can only diverge on a draw whose two longs differ,
     * which is why `the generator really draws the shapes it claims` floors that case explicitly
     * rather than leaving the mutation's detectability to the draw.
     */
    @Test
    fun `the layout agrees with an independent reference encoder on every element`() {
        val cases = corpus()
        var checked = 0
        cases.forEach { case ->
            bytesDiffer(referencePreImage(case.element), preImage(case.element))?.let {
                throw AssertionError(
                    "the encoder disagrees with the documented layout: $it\n" + describe(case),
                )
            }
            checked++
        }
        assertEquals("every element must be checked", cases.size, checked)
    }

    /**
     * Readability: every element survives the transport envelope and reads back component for
     * component. This is the half T14's length prefixes exist for and the half T18's envelope
     * depends on — a pre-image that is merely *comparable* could not cross a relay.
     */
    @Test
    fun `every element round-trips through the statement envelope`() {
        val cases = corpus()
        var checked = 0
        cases.forEach { case ->
            val parsed = Utils.parseSignedStatement(envelope(case.element, SIGNATURE))
                ?: throw AssertionError("the envelope must parse\n" + describe(case))

            val read = elementOf(parsed)
            if (read != case.element) {
                throw AssertionError(
                    "the components must survive the envelope\n" + describe(case) +
                        "\n  read back kind  = " + read.kind +
                        "\n  read back texts = " + read.texts.map(::printable) +
                        "\n  read back longs = " + read.longs,
                )
            }
            bytesDiffer(SIGNATURE, signatureOf(parsed))?.let {
                throw AssertionError("the signature must survive too: $it\n" + describe(case))
            }
            checked++
        }
        assertEquals("every element must be round-tripped", cases.size, checked)
    }

    // ── Negative controls ────────────────────────────────────────────────

    /**
     * The control that makes the whole file mean something.
     *
     * A corpus that collides nowhere under a naive encoder proves nothing about the real one, and
     * blandness is exactly what a generator drifts into. So the same corpus goes through
     * [naivePreImage] — components concatenated with no length prefixes, longs rendered through
     * `toString()` — and the collisions are counted. [twinOf] is what guarantees there are some,
     * which is why the failure message names it: a zero here is a report about the *generator*,
     * not about the encoder, and the twin count is the first thing to look at.
     */
    @Test
    fun `a naive encoder collides on this corpus`() {
        val seen = HashMap<String, Case>()
        var collisions = 0
        var twins = 0

        corpus().forEach { case ->
            if (case.tuple.twinAt != null) twins++
            val previous = seen.put(sha256Hex(naivePreImage(case.element)), case)
            if (previous != null && previous.element != case.element) collisions++
        }

        assertTrue(
            "the corpus must collide under a naive encoder, or the injectivity property above is " +
                "asserting nothing about the layout — it would hold for any encoder at all. " +
                "Collisions found: $collisions, from $twins boundary-shifted twin elements; if " +
                "the twin count is zero the fault is in twinOf, not in the encoder",
            collisions > 0,
        )
    }

    /**
     * Cross-kind: the kind tag is the only thing standing between "authorized to replace this key
     * today" and "authorized to replace it forever", so over every tuple that fits both, the
     * rotation and recovery pre-images must differ.
     */
    @Test
    fun `rotation and recovery pre-images differ for every tuple`() {
        val draws = tuples()
        var checked = 0
        draws.forEach { tuple ->
            val rotate = Element(Kind.ROTATE, tuple.texts, tuple.longs)
            val recover = Element(Kind.RECOVER, tuple.texts, tuple.longs)
            if (preImage(rotate).contentEquals(preImage(recover))) {
                throw AssertionError(
                    "a rotation and a recovery authorization with identical components share a " +
                        "pre-image, so a signature over one authorizes the other\n" +
                        describe(Case(tuple, rotate)),
                )
            }
            checked++
        }
        assertEquals("every draw must be checked", draws.size, checked)
    }

    /**
     * The reference encoder must not be a third copy of the wrong thing. If it agreed with the
     * naive one it would be asserting the *absence* of length prefixes, and the layout-agreement
     * arm would be green against an encoder that has none.
     *
     * Required by the task and, like the determinism arm, true by construction rather than by luck:
     * [referencePreImage]'s byte 16 is always `0x00`, the high byte of the kind tag's four-byte
     * length, while [naivePreImage]'s is always `'l'`, the first character of the tag itself.
     * Stated over the whole corpus anyway, because the arm's job is to keep being true if either
     * encoder is edited.
     */
    @Test
    fun `the reference encoder disagrees with the naive one on every element`() {
        val cases = corpus()
        var checked = 0
        cases.forEach { case ->
            if (referencePreImage(case.element).contentEquals(naivePreImage(case.element))) {
                throw AssertionError(
                    "the reference encoder produced the naive encoding, so it is not an " +
                        "independent reading of the layout\n" + describe(case),
                )
            }
            checked++
        }
        assertEquals("every element must be checked", cases.size, checked)
    }

    /**
     * Generator floors. A pool is a claim about what gets exercised, and a claim nothing checks is
     * one that survives the draw weights drifting until the interesting shapes stop appearing.
     * Every count is reported, not just the failing one, so a thin corpus is visible at a glance.
     *
     * Two of these floors are not pool shapes but **mutation preconditions**, and they are here
     * because the asymmetry was a real gap: swapping the two long components in
     * `rotationStatementBytes` is only detectable on a draw whose two longs differ, and the same
     * swap applied to two text slots is only detectable on a draw whose texts differ. Every other
     * mutation the task plants diverges structurally, on the kind tag, before a drawn component is
     * reached. Without `distinctLongs` a drift in `drawLong`'s weights — or a "simplification" of
     * `List(2) { drawLong(rnd) }` to two copies of one value — would let that mutation survive the
     * layout arm with all nine pool floors still green.
     */
    @Test
    fun `the generator really draws the shapes it claims`() {
        var empty = 0
        var multiByte = 0
        var astral = 0
        var lengthSpelling = 0
        var huge = 0
        var minValue = 0
        var maxValue = 0
        var negative = 0
        var asciiSpelling = 0
        var twinsAtFirst = 0
        var twinsAtSecond = 0
        var distinctLongs = 0
        var distinctTexts = 0

        val draws = tuples()
        draws.forEach { tuple ->
            when (tuple.twinAt) {
                0 -> twinsAtFirst++
                1 -> twinsAtSecond++
            }
            tuple.texts.forEach { text ->
                if (text.isEmpty()) empty++
                // The whole four-byte trap, not merely "contains a NUL": `drawText` takes a
                // code-point prefix one time in four, so LENGTH_SPELLING is routinely drawn
                // truncated to one, two or three NULs — which spell no length prefix at all and
                // would trip no decoder resynchronising on a four-byte scan. Counting those as
                // the shape would leave the floor green on exactly the drift that removed it.
                if (text == LENGTH_SPELLING || text == LENGTH_SPELLING_AB) lengthSpelling++
                // Counted first and then skipped, rather than scanned: the 64 KB draw is plain
                // ASCII `x` and prefixes of it are never taken (`drawText` leaves anything over
                // `TRUNCATION_LIMIT` whole), so it can be none of the shapes below — and the two
                // character scans below it are the bulk of this test's runtime. The two checks
                // above are both O(1) on it: `isEmpty` reads a length, and `String.equals`
                // compares lengths before contents.
                if (text.length >= HUGE_CHARS) {
                    huge++
                    return@forEach
                }
                if (text.any { it.code in 0x80..0xFFFF && !it.isSurrogate() }) multiByte++
                if (text.codePoints().anyMatch { it > 0xFFFF }) astral++
            }
            if (tuple.texts[0] != tuple.texts[1]) distinctTexts++
            tuple.longs.forEach { value ->
                if (value == Long.MIN_VALUE) minValue++
                if (value == Long.MAX_VALUE) maxValue++
                if (value < 0) negative++
                if (value in asciiLongs) asciiSpelling++
            }
            if (tuple.longs[0] != tuple.longs[1]) distinctLongs++
        }

        val tally = "draws=${draws.size} empty=$empty multiByte=$multiByte astral=$astral " +
            "lengthSpelling=$lengthSpelling huge=$huge minValue=$minValue maxValue=$maxValue " +
            "negative=$negative asciiSpelling=$asciiSpelling twinsAtFirst=$twinsAtFirst " +
            "twinsAtSecond=$twinsAtSecond distinctLongs=$distinctLongs " +
            "distinctTexts=$distinctTexts"

        listOf(
            "an empty component" to empty,
            "a multi-byte component" to multiByte,
            "an astral component" to astral,
            "a component whose bytes open with a length prefix, drawn whole" to lengthSpelling,
            "a 64 KB component" to huge,
            "Long.MIN_VALUE" to minValue,
            "Long.MAX_VALUE" to maxValue,
            "a negative long" to negative,
            "a long whose bytes are printable ASCII" to asciiSpelling,
            "a twin shifted across the first text boundary" to twinsAtFirst,
            "a twin shifted across the second text boundary" to twinsAtSecond,
            "a draw whose two long components differ" to distinctLongs,
            "a draw whose first two text components differ" to distinctTexts,
        ).forEach { (what, count) ->
            assertTrue("the corpus never drew $what — $tally", count > 0)
        }
    }

    /**
     * The precondition injectivity rests on: every component survives a UTF-8 round trip, so none
     * of them is the one input the encoding cannot separate.
     *
     * Asserted as the round trip rather than by scanning for surrogates, because the round trip is
     * the property itself — a component that comes back changed is a component two different
     * statements could share bytes through. It covers twins as well as ordinary draws, since
     * [tuples] returns both, and every component any kind encodes is a member of `tuple.texts`.
     */
    @Test
    fun `no component is lost to the one equivalence the encoding has`() {
        val draws = tuples()
        var checked = 0
        draws.forEach { tuple ->
            tuple.texts.forEach { text ->
                if (String(text.toByteArray(Charsets.UTF_8), Charsets.UTF_8) != text) {
                    throw AssertionError(
                        "a component does not survive UTF-8, so the corpus contains the " +
                            "documented lone-surrogate equivalence and injectivity would fail on " +
                            "accepted behaviour: seed=${tuple.seed}L twinAt=${tuple.twinAt} " +
                            "text=${printable(text)}",
                    )
                }
                checked++
            }
        }
        assertEquals("every component must be checked", draws.size * 3, checked)
    }

    /**
     * And the carve-out itself, pinned rather than merely avoided.
     *
     * `StatementPreImageTest`'s `an unpaired surrogate is the one input the encoding cannot
     * separate` records this on a rotation; re-asserted here because it is the reason this file's
     * pool is constrained, and a reader meeting the constraint should find the exception beside it.
     *
     * Like the determinism arm, this one compares two production calls against each other, so an
     * encoder that returned a constant would satisfy it. That is fine for what it is — a record of
     * a known equivalence rather than a check on the layout — and the layout, injectivity,
     * cross-kind and round-trip arms all fail against such an encoder. Said out loud so the next
     * reader does not count it as coverage it is not.
     */
    @Test
    fun `a lone surrogate and a question mark encode identically`() {
        assertTrue(
            "known and documented on Utils.rotationStatementBytes: UTF-8 has no encoding for a " +
                "lone surrogate, so it collides with the substitute the encoder writes instead. " +
                "This file's pool excludes unpaired surrogates for that reason",
            Utils.rotationStatementBytes(RotationStatement("K", "K2", LONE_SURROGATE, 1L, 2L))
                .contentEquals(
                    Utils.rotationStatementBytes(RotationStatement("K", "K2", "?", 1L, 2L)),
                ),
        )

        // The same equivalence through the other two kinds, since all three share the encoder.
        assertTrue(
            "the same holds for a recovery authorization",
            Utils.recoveryAuthorizationBytes(
                RecoveryAuthorization("K", "K2", LONE_SURROGATE, 1L, 2L),
            ).contentEquals(
                Utils.recoveryAuthorizationBytes(RecoveryAuthorization("K", "K2", "?", 1L, 2L)),
            ),
        )
        assertTrue(
            "and for a revocation",
            Utils.revocationBytes(Revocation("K", LONE_SURROGATE, 1L, 2L))
                .contentEquals(Utils.revocationBytes(Revocation("K", "?", 1L, 2L))),
        )

        // The control that says the fixture is genuinely the shape being described, rather than a
        // character that merely renders oddly in an editor.
        assertEquals("the fixture must be one lone high surrogate", 1, LONE_SURROGATE.length)
        assertTrue("and it must be unpaired", LONE_SURROGATE[0].isHighSurrogate())
    }

    /**
     * The change-detector for the corpus itself.
     *
     * Not one of the safety assertions: it catches an *accidental* edit to the generator, which
     * would silently swap the corpus for a different one and make every earlier failure report in
     * the log unreproducible. Recomputing it is correct when the generator was edited on purpose,
     * and wrong every other time.
     */
    @Test
    fun `the corpus is byte-identical on every run`() {
        assertEquals(
            "the pre-image corpus changed; update PRE_IMAGE_CORPUS_DIGEST only if the generator " +
                "was edited deliberately",
            PRE_IMAGE_CORPUS_DIGEST,
            corpusDigest(),
        )
    }

    /**
     * The check that catches a `String.format("%d")` hidden in the encoder.
     *
     * Under `ar-EG` the JDK's locale-sensitive number formatting emits Eastern Arabic-Indic digits,
     * so a pre-image built from formatted numbers would come out different bytes on a phone set to
     * Arabic — a signature that verifies in one language and not another. Both digests are taken:
     * the corpus, so a locale-sensitive *generator* is caught too, and the pre-images, which is
     * where a number-formatting slip would actually show up.
     */
    @Test
    fun `neither the corpus nor its pre-images change under another locale`() {
        val corpusBefore = corpusDigest()
        val preImagesBefore = preImageDigest()

        Locale.setDefault(Locale.forLanguageTag("ar-EG"))

        assertEquals("the locale must not reach the corpus generator", corpusBefore, corpusDigest())
        assertEquals(
            "the locale must not reach a single byte of a single pre-image",
            preImagesBefore,
            preImageDigest(),
        )
        assertEquals(
            "and the pinned corpus digest must hold under any locale too",
            PRE_IMAGE_CORPUS_DIGEST,
            corpusDigest(),
        )
        // Without this the test would pass on a JDK where `ar-EG` happens to format digits as
        // ASCII anyway, and would then be asserting nothing about locale sensitivity. Stated as
        // "not ASCII" rather than pinning the Arabic-Indic digits, which are the JDK's locale data
        // and not this library's to freeze.
        assertTrue(
            "control: this locale must genuinely format digits differently, or the assertions " +
                "above cannot fail",
            String.format(Locale.getDefault(), "%d", 123) != "123",
        )
    }

    // ── Encoders ─────────────────────────────────────────────────────────

    /** The production encoder for whichever kind the element is. */
    private fun preImage(element: Element): ByteArray = when (element.kind) {
        Kind.ROTATE -> Utils.rotationStatementBytes(rotation(element))
        Kind.RECOVER -> Utils.recoveryAuthorizationBytes(recovery(element))
        Kind.REVOKE -> Utils.revocationBytes(revocation(element))
    }

    /**
     * The documented layout, read fresh: the domain prefix raw, then the kind tag and every text
     * component as a four-byte big-endian *byte* length followed by its UTF-8 bytes, then every
     * 64-bit component as eight big-endian bytes.
     *
     * Through [DataOutputStream], whose `writeInt` and `writeLong` are big-endian by contract, so
     * an endianness slip in the production shift loop cannot be mirrored here by accident. Every
     * literal is spelled out rather than referenced from [Utils] — a reference encoder that reads
     * the production constants is an encoder that moves with them.
     */
    private fun referencePreImage(element: Element): ByteArray {
        val bytes = ByteArrayOutputStream()
        DataOutputStream(bytes).use { out ->
            out.write("lim.statement.v1".toByteArray(Charsets.UTF_8))
            (listOf(element.kind.tag) + element.texts).forEach { text ->
                val encoded = text.toByteArray(Charsets.UTF_8)
                out.writeInt(encoded.size)
                out.write(encoded)
            }
            element.longs.forEach { out.writeLong(it) }
        }
        return bytes.toByteArray()
    }

    /**
     * The encoder this library deliberately does not have: everything concatenated, no length
     * prefixes, numbers rendered as text. It exists to prove the corpus can tell the two apart.
     */
    private fun naivePreImage(element: Element): ByteArray = buildString {
        append("lim.statement.v1")
        append(element.kind.tag)
        element.texts.forEach { append(it) }
        element.longs.forEach { append(it.toString()) }
    }.toByteArray(Charsets.UTF_8)

    private fun envelope(element: Element, signature: ByteArray): String = when (element.kind) {
        Kind.ROTATE -> Utils.encodeRotationStatement(rotation(element), signature)
        Kind.RECOVER -> Utils.encodeRecoveryAuthorization(recovery(element), signature)
        Kind.REVOKE -> Utils.encodeRevocation(revocation(element), signature)
    }

    private fun rotation(element: Element) = RotationStatement(
        oldPublicKey = element.texts[0],
        newPublicKey = element.texts[1],
        statementId = element.texts[2],
        issuedAtMillis = element.longs[0],
        expiresAtMillis = element.longs[1],
    )

    private fun recovery(element: Element) = RecoveryAuthorization(
        subjectPublicKey = element.texts[0],
        recoveryPublicKey = element.texts[1],
        authorizationId = element.texts[2],
        sequence = element.longs[0],
        issuedAtMillis = element.longs[1],
    )

    private fun revocation(element: Element) = Revocation(
        subjectPublicKey = element.texts[0],
        revokedAuthorizationId = element.texts[1],
        sequence = element.longs[0],
        issuedAtMillis = element.longs[1],
    )

    private fun elementOf(parsed: SignedStatement): Element = when (parsed) {
        is SignedStatement.Rotate -> parsed.statement.let {
            Element(
                Kind.ROTATE,
                listOf(it.oldPublicKey, it.newPublicKey, it.statementId),
                listOf(it.issuedAtMillis, it.expiresAtMillis),
            )
        }

        is SignedStatement.Recover -> parsed.authorization.let {
            Element(
                Kind.RECOVER,
                listOf(it.subjectPublicKey, it.recoveryPublicKey, it.authorizationId),
                listOf(it.sequence, it.issuedAtMillis),
            )
        }

        is SignedStatement.Revoke -> parsed.revocation.let {
            Element(
                Kind.REVOKE,
                listOf(it.subjectPublicKey, it.revokedAuthorizationId),
                listOf(it.sequence, it.issuedAtMillis),
            )
        }
    }

    private fun signatureOf(parsed: SignedStatement): ByteArray = when (parsed) {
        is SignedStatement.Rotate -> parsed.signature
        is SignedStatement.Recover -> parsed.signature
        is SignedStatement.Revoke -> parsed.signature
    }

    // ── Digests and reporting ────────────────────────────────────────────

    /** A digest of the corpus as drawn — kinds and components, no encoder involved. */
    private fun corpusDigest(): String {
        val digest = MessageDigest.getInstance("SHA-256")
        corpus().forEach { case ->
            digest.update(case.element.kind.name.toByteArray(Charsets.UTF_8))
            case.element.texts.forEach { text ->
                // Length-prefixed, for the same reason the layout itself is: without it
                // `("A","B")` and `("AB","")` would digest alike.
                digest.update(bigEndian(text.length.toLong(), 4))
                digest.update(codeUnits(text))
            }
            case.element.longs.forEach { digest.update(bigEndian(it, 8)) }
        }
        return hex(digest.digest())
    }

    /** A digest of every pre-image the corpus produces, for the locale control. */
    private fun preImageDigest(): String {
        val digest = MessageDigest.getInstance("SHA-256")
        corpus().forEach { digest.update(preImage(it.element)) }
        return hex(digest.digest())
    }

    private fun describe(case: Case): String = buildString {
        append("  seed   = ").append(case.tuple.seed).append("L   (reproduce with tupleFor(")
            .append(case.tuple.seed).append("L)")
            .append(if (case.tuple.twinAt != null) ", then twinOf()" else "").append(")\n")
        append("  kind   = ").append(case.element.kind)
            .append(if (case.tuple.twinAt != null) "   twin shifted at boundary " else "")
            .append(case.tuple.twinAt ?: "").append('\n')
        append("  texts  = ").append(case.element.texts.map(::printable)).append('\n')
        append("  longs  = ").append(case.element.longs)
    }

    /** Escape everything unprintable so a component survives a log file, and cap the length. */
    private fun printable(text: String): String {
        val capped = text.take(COMPONENT_PREVIEW)
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
        return if (text.length > COMPONENT_PREVIEW) {
            "\"" + escaped + "\"... (+" + (text.length - COMPONENT_PREVIEW) + " more chars)"
        } else {
            "\"" + escaped + "\""
        }
    }

    /**
     * Where two byte strings first differ, as a message, or `null` when they are equal. A 64 KB
     * component makes a whole-array dump useless, and "they differ" with no offset makes a 3am
     * failure a rerun rather than a diagnosis.
     */
    private fun bytesDiffer(expected: ByteArray, actual: ByteArray): String? {
        if (expected.contentEquals(actual)) return null
        val shared = minOf(expected.size, actual.size)
        val at = (0 until shared).firstOrNull { expected[it] != actual[it] } ?: shared
        return "lengths ${expected.size} vs ${actual.size}, first difference at byte $at:\n" +
            "    expected ..." + window(expected, at) + "...\n" +
            "    actual   ..." + window(actual, at) + "..."
    }

    private fun window(bytes: ByteArray, at: Int): String =
        hex(bytes.copyOfRange(maxOf(0, at - 8), minOf(bytes.size, at + 8)))

    private fun preview(bytes: ByteArray): String =
        if (bytes.size <= PRE_IMAGE_PREVIEW) {
            Base64.encodeToString(bytes, Base64.NO_WRAP)
        } else {
            Base64.encodeToString(bytes.copyOf(PRE_IMAGE_PREVIEW), Base64.NO_WRAP) +
                "... (${bytes.size} bytes)"
        }

    private fun sha256Hex(bytes: ByteArray): String =
        hex(MessageDigest.getInstance("SHA-256").digest(bytes))

    companion object {
        /** Arbitrary; what matters is only that it never changes. */
        private const val CORPUS_SEED = 0x4C494D20543233L

        /**
         * Mixed into a draw's seed to choose its twin's boundary, so [twinOf] stays a pure function
         * of the [Tuple] it is given rather than of where the master generator happens to be.
         */
        private const val TWIN_SALT = 0x5457494E42444559L

        /**
         * Tuples drawn, before boundary-shifted twins. Each fills all three kinds and roughly
         * seven draws in eight yield a twin, so the corpus is **3,751 draws and 11,253 elements**
         * — measured, not estimated; `the generator really draws the shapes it claims` reports the
         * draw count in its tally. That is enough to reach every corner of the pool and still
         * finish in about a second, which is what keeps a fuzz suite being run.
         */
        private const val TUPLES = 2000

        /**
         * The floor [corpus] holds [TUPLES] to. T23 asks for "a few thousand component tuples", and
         * a constant nothing checks is one a quick local run shrinks to 300 and commits.
         */
        private const val MINIMUM_TUPLES = 2000

        /** Length of the 64 KB component, in characters — one byte each, so also in bytes. */
        private const val HUGE_CHARS = 64 * 1024

        /** Above this, a component is left alone: the point is the boundary, not the copying. */
        private const val TRUNCATION_LIMIT = 64

        private const val COMPONENT_PREVIEW = 200
        private const val PRE_IMAGE_PREVIEW = 64
        private const val HEX = "0123456789abcdef"

        /**
         * See `the corpus is byte-identical on every run`. Captured from the first run that also
         * passed the layout-agreement, injectivity and round-trip properties — a change-detector
         * from then on, and nothing else. It pins only this file's corpus; `DecoderFuzzTest`'s
         * `CORPUS_DIGEST` is a separate constant over a separate generator and is untouched here.
         */
        private const val PRE_IMAGE_CORPUS_DIGEST =
            "3f1675bdb61aba9407455b86a5fb3acd3404974b9144dff42c85a90c9578031b"

        /**
         * A 64 KB component. The length prefix is four bytes wide precisely so a component this
         * size still delimits.
         *
         * Not the largest the encoder has ever seen — `RotationVerificationTest`'s
         * `extreme statement components earn a verdict rather than a throw` and two cases in
         * `RecoveryVerificationTest` already push 200,000-character components straight through it.
         * What is new here is a component this size inside a *generated* corpus, and inside the
         * envelope round-trip, where a four-byte length is what has to carry it back out again.
         */
        private val HUGE_TEXT = "x".repeat(HUGE_CHARS)

        /**
         * Text whose own UTF-8 bytes are `00 00 00 05` — the big-endian encoding of the length 5,
         * sitting *inside* a component rather than in front of one. A decoder resynchronising by
         * scanning for a plausible prefix would read a different statement out of these bytes; one
         * that counts, as the documented layout does, cannot.
         *
         * Spelled numerically rather than with escapes, the way `DecoderFuzzTest` spells its NUL
         * and its lone surrogate: a raw control byte in a source file makes the file binary to
         * every tool that reads it, `grep` included.
         */
        private val LENGTH_SPELLING =
            String(charArrayOf(0.toChar(), 0.toChar(), 0.toChar(), 5.toChar()))

        /** The same trap carrying a payload after it, so the false length has something to span. */
        private val LENGTH_SPELLING_AB =
            String(charArrayOf(0.toChar(), 0.toChar(), 0.toChar(), 2.toChar())) + "AB"

        /**
         * One unpaired high surrogate — the shape the pool excludes and the carve-out control
         * asserts on. Numeric for the same reason as [LENGTH_SPELLING], and because no encoding of
         * a source file can hold it literally.
         */
        private val LONE_SURROGATE = String(charArrayOf(0xD83D.toChar()))

        /**
         * A non-empty signature for the envelope arm. Nothing here signs or verifies — the envelope
         * carries the signature section opaquely, and an empty one is refused by
         * `Utils.parseSignedStatement` by design.
         */
        private val SIGNATURE = ByteArray(32) { (it * 7 + 3).toByte() }

        /** The long whose eight big-endian bytes are [text]'s, left-padded with zeroes. */
        private fun asciiLong(text: String): Long {
            val bytes = text.toByteArray(Charsets.UTF_8)
            require(bytes.size <= 8) { "$text does not fit in eight bytes" }
            var value = 0L
            bytes.forEach { value = (value shl 8) or (it.toLong() and 0xFF) }
            return value
        }

        /**
         * A prefix of [text] no longer than [chars], cut back if that would land between a
         * surrogate pair. Splitting a pair leaves a lone high surrogate, and that is the one shape
         * this corpus must not contain.
         */
        private fun prefixAtCodePoint(text: String, chars: Int): String {
            if (chars <= 0) return ""
            if (chars >= text.length) return text
            val end = if (text[chars - 1].isHighSurrogate()) chars - 1 else chars
            return text.substring(0, end)
        }

        /**
         * [text]'s raw UTF-16 code units, two bytes each, most significant first.
         *
         * Written by hand rather than through `toByteArray(Charsets.UTF_16BE)`, and that is the
         * whole point: `String.toByteArray(Charset)` encodes with `REPLACE`, so a lone surrogate is
         * malformed input for UTF-16BE too and digests as U+FFFD — exactly the substitution UTF-8
         * makes to `?`. A corpus digest taken through a charset encoder would therefore be blind to
         * the one character class this file's pool is built to exclude, and an edit that
         * reintroduced a lone surrogate would leave [PRE_IMAGE_CORPUS_DIGEST] unmoved.
         * `DecoderFuzzTest` writes its own code units by hand for the same reason.
         */
        private fun codeUnits(text: String): ByteArray {
            val out = ByteArray(text.length * 2)
            for (i in text.indices) {
                val code = text[i].code
                out[i * 2] = (code shr 8).toByte()
                out[i * 2 + 1] = code.toByte()
            }
            return out
        }

        /** [value]'s low [width] bytes, most significant first. Only `corpusDigest` needs this. */
        private fun bigEndian(value: Long, width: Int): ByteArray =
            ByteArray(width) { ((value ushr (8 * (width - 1 - it))) and 0xFF).toByte() }

        private fun hex(bytes: ByteArray): String = buildString(bytes.size * 2) {
            bytes.forEach { b ->
                val v = b.toInt() and 0xFF
                append(HEX[v shr 4])
                append(HEX[v and 0xF])
            }
        }
    }
}
