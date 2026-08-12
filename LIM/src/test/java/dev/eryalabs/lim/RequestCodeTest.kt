package dev.eryalabs.lim

import android.content.Intent
import android.os.BadParcelableException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.RuntimeEnvironment

/**
 * [Utils.matchesRequestCode] exists so that a client with several requests in flight never acts
 * on the answer to a different one. The failure it prevents is silent — no crash, just a
 * disclosure attributed to the wrong request — so what is pinned below is mostly the *refusals*.
 *
 * The trap at the centre of this file is "nothing equals nothing": a client that forgot to tag
 * its request compares `""` against a result that carries no code, and a naive equality check
 * says yes. Every combination of blank on either side is asserted, in both directions.
 *
 * Robolectric is required: [Intent] extras are unimplemented stubs in a plain JVM unit test.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class RequestCodeTest {

    private val context get() = RuntimeEnvironment.getApplication()

    /** A result intent as the vault builds it: a bare [Intent] carrying extras. */
    private fun resultIntent(vararg extras: Pair<String, String>) = Intent().apply {
        extras.forEach { (key, value) -> putExtra(key, value) }
    }

    private fun taggedIntent(requestCode: String) =
        resultIntent(Utils.EXTRA_SHARE_REQUEST_CODE to requestCode)

    /**
     * An intent whose extras cannot be read. Unparcelling a bundle that references a class this
     * process does not have throws in exactly this way, and the sender chooses what goes in the
     * bundle — so correlating must not take the client down.
     */
    private class UnreadableIntent : Intent() {
        /** Counted so the test can prove the throw was reached, not merely that false came back. */
        var reads = 0
            private set

        override fun getStringExtra(name: String?): String? {
            reads++
            throw BadParcelableException("extras reference an unknown class")
        }
    }

    // ── The one shape that matches ───────────────────────────────────────

    @Test
    fun `an echoed request code matches the one that was sent`() {
        assertTrue(Utils.matchesRequestCode(taggedIntent("req-1"), "req-1"))
    }

    /**
     * The helper is only useful if it reads the same extra the builders write. Each of the three
     * request-bearing intents this library constructs is checked against its own code, so a
     * change to either side that silently stopped correlating shows up here rather than in a
     * client's `onActivityResult`.
     */
    @Test
    fun `intents built by this library correlate with their own request code`() {
        val entry = Entry(id = "id-1", fields = emptyMap(), publicKey = "PUBLIC-KEY")

        // Named: the three-argument overload's third parameter is `targetPackage`, not this.
        val share = Utils.createShareIntent(context, entry, requestCode = "req-share")
        assertTrue("share intent", Utils.matchesRequestCode(share, "req-share"))
        assertFalse("share intent, wrong code", Utils.matchesRequestCode(share, "req-query"))

        val query = Utils.createQueryIntent(context, "PUBLIC-KEY", "req-query")
        assertTrue("query intent", Utils.matchesRequestCode(query, "req-query"))

        val challenge = Utils.createSignChallengeIntent(
            context,
            publicKey = "PUBLIC-KEY",
            nonce = Utils.generateNonce(now = 1_770_000_000_000L),
            requestCode = "req-challenge",
        )
        assertTrue("sign-challenge intent", Utils.matchesRequestCode(challenge, "req-challenge"))
    }

    // ── Everything that must not ─────────────────────────────────────────

    @Test
    fun `a different request code does not match`() {
        assertFalse(Utils.matchesRequestCode(taggedIntent("req-1"), "req-2"))
    }

    /**
     * Substrings and prefixes are the shapes an over-clever comparison lets through. `"req-1"`
     * and `"req-10"` are two different requests, and a client that numbers its requests will
     * generate exactly this pair on its tenth one.
     */
    @Test
    fun `a prefix or extension of the code is not the code`() {
        assertFalse("expected is a prefix of the actual", Utils.matchesRequestCode(taggedIntent("req-10"), "req-1"))
        assertFalse("actual is a prefix of the expected", Utils.matchesRequestCode(taggedIntent("req-1"), "req-10"))
        assertFalse("substring", Utils.matchesRequestCode(taggedIntent("xx-req-1-xx"), "req-1"))
    }

    @Test
    fun `the comparison is case sensitive`() {
        assertFalse(Utils.matchesRequestCode(taggedIntent("req-1"), "REQ-1"))
    }

    @Test
    fun `a null intent does not match`() {
        assertFalse(Utils.matchesRequestCode(null, "req-1"))
    }

    @Test
    fun `an intent with no request-code extra does not match`() {
        assertFalse("no extras at all", Utils.matchesRequestCode(Intent(), "req-1"))
        assertFalse(
            "extras from other flows only",
            Utils.matchesRequestCode(
                resultIntent(
                    Utils.EXTRA_PUBLIC_KEY to "req-1",
                    Utils.EXTRA_SIGNATURE to "req-1",
                    Utils.EXTRA_ENTRY_JSON to "req-1",
                ),
                "req-1",
            ),
        )
    }

    @Test
    fun `a present but empty request-code extra does not match`() {
        assertFalse("empty", Utils.matchesRequestCode(taggedIntent(""), "req-1"))
        assertFalse("whitespace", Utils.matchesRequestCode(taggedIntent("   "), "req-1"))
    }

    /**
     * The sender picks the extra's type, not just its value. A non-String extra reads back as
     * null rather than throwing, so it must count as absent — never as something coerced through
     * `toString()` into a match.
     */
    @Test
    fun `a request-code extra of the wrong type does not match`() {
        val intent = Intent().apply { putExtra(Utils.EXTRA_SHARE_REQUEST_CODE, 42) }
        assertFalse(Utils.matchesRequestCode(intent, "42"))
    }

    /**
     * Self-anchoring on purpose. `false` is also what an unreached override would produce, and
     * this is the only assertion in the file that distinguishes reading the extra *safely* from
     * not reading it at all — every other case here returns false for the safe read and the
     * unsafe one alike. Without the counter, a helper that throws `BadParcelableException`
     * straight into a client's `onActivityResult` would pass this suite green.
     */
    @Test
    fun `an intent whose extras cannot be read does not match rather than throwing`() {
        val intent = UnreadableIntent()

        assertFalse(Utils.matchesRequestCode(intent, "req-1"))
        assertEquals("the throwing read must actually have been attempted", 1, intent.reads)
    }

    // ── Nothing equals nothing ───────────────────────────────────────────

    /**
     * The bug this helper exists to prevent. A client that never tagged its request holds `""`;
     * a result that was never tagged carries nothing, or carries `""` back. Equality says those
     * are the same and the client acts on someone else's answer. They are not the same, and no
     * blank ever matches anything.
     */
    @Test
    fun `a blank expected never matches`() {
        for (expected in listOf("", " ", "   ", "\t", "\n")) {
            assertFalse("blank vs no extra: [$expected]", Utils.matchesRequestCode(Intent(), expected))
            assertFalse("blank vs empty extra: [$expected]", Utils.matchesRequestCode(taggedIntent(""), expected))
            assertFalse(
                "blank vs whitespace extra: [$expected]",
                Utils.matchesRequestCode(taggedIntent("   "), expected),
            )
            assertFalse(
                "blank vs a real code: [$expected]",
                Utils.matchesRequestCode(taggedIntent("req-1"), expected),
            )
        }
    }

    /**
     * The same blank on both sides is the exact pair that must not match: byte-identical, and
     * still not a correlation. Asserted separately from the loop above because it is the one an
     * equality check gets wrong without any help from the caller.
     */
    @Test
    fun `an identical blank on both sides does not match`() {
        assertFalse("empty on both sides", Utils.matchesRequestCode(taggedIntent(""), ""))
        assertFalse("whitespace on both sides", Utils.matchesRequestCode(taggedIntent("   "), "   "))
    }

    // ── Whitespace is part of the token ──────────────────────────────────

    /**
     * A request code is an opaque handle the client minted. Trimming it would be this library
     * deciding two tokens the client deliberately kept apart are the same one, so padding is
     * significant on both sides — and, in the third case, on both sides at once.
     */
    @Test
    fun `leading or trailing whitespace makes a different code`() {
        assertFalse("leading, on the expected", Utils.matchesRequestCode(taggedIntent("req-1"), " req-1"))
        assertFalse("trailing, on the expected", Utils.matchesRequestCode(taggedIntent("req-1"), "req-1 "))
        assertFalse("newline, on the expected", Utils.matchesRequestCode(taggedIntent("req-1"), "req-1\n"))
        assertFalse("leading, on the intent", Utils.matchesRequestCode(taggedIntent(" req-1"), "req-1"))
        assertFalse("trailing, on the intent", Utils.matchesRequestCode(taggedIntent("req-1 "), "req-1"))
        assertFalse("padded differently on each side", Utils.matchesRequestCode(taggedIntent(" req-1"), "req-1 "))
    }

    /**
     * The corollary: a padded code is still a code. It matches itself exactly, which is what
     * proves the rule above is "no trimming" rather than "anything with whitespace is refused".
     */
    @Test
    fun `a code carrying whitespace still matches itself exactly`() {
        assertTrue(Utils.matchesRequestCode(taggedIntent(" req-1 "), " req-1 "))
    }

    /**
     * Where "blank" actually stops, pinned because reading the Java method gets it wrong.
     *
     * T6's progress-log note reasoned that a non-breaking-space token matches itself, on the
     * grounds that `Character.isWhitespace` excludes U+00A0. It does — but Kotlin's `isBlank`
     * does not call it alone: `Char.isWhitespace()` is
     * `Character.isWhitespace(c) || Character.isSpaceChar(c)`, and U+00A0 is `Zs`, so it passes
     * the second test. A token made only of non-breaking spaces is therefore blank on both
     * sides and matches nothing, which is the safer answer and the opposite of what was
     * written down. The same rule decides the blank-identity refusal in `Utils.decodeEntry`,
     * so it is worth one assertion rather than one comment.
     */
    @Test
    fun `a non-breaking space is blank, but only when it is the whole token`() {
        val nbsp = " "

        // The character above is invisible, so it is checked rather than trusted: an editor or
        // a re-encoding that quietly folded it to an ordinary space would leave every assertion
        // below passing while testing something else entirely.
        assertEquals(
            "this test needs a literal U+00A0 — the source file's copy has been mangled",
            0x00A0,
            nbsp.single().code,
        )

        assertFalse(
            "Kotlin's isBlank also asks isSpaceChar, so a lone U+00A0 never correlates",
            Utils.matchesRequestCode(taggedIntent(nbsp), nbsp),
        )
        assertFalse("...on the expected side alone", Utils.matchesRequestCode(taggedIntent("req-1"), nbsp))
        assertFalse("...on the intent side alone", Utils.matchesRequestCode(taggedIntent(nbsp), "req-1"))

        assertTrue(
            "a non-breaking space inside a token leaves it non-blank, so it is a real code",
            Utils.matchesRequestCode(taggedIntent("req${nbsp}1"), "req${nbsp}1"),
        )
        assertFalse(
            "...and it is not the same code as the one with an ordinary space",
            Utils.matchesRequestCode(taggedIntent("req${nbsp}1"), "req${' '}1"),
        )
    }
}
