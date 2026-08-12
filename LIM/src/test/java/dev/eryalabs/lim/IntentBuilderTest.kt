package dev.eryalabs.lim

import android.content.Intent
import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import com.google.gson.Gson
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * The intents are the protocol. Action strings and extra keys are matched literally by the
 * vault's manifest and its intent handlers, so a typo here is a silent no-op in production —
 * the intent simply resolves to nothing. Every wire constant is pinned to a literal below,
 * deliberately not to the `Utils` constant, so that renaming a constant cannot quietly
 * rename the wire format.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class IntentBuilderTest {

    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()
    private val vault = Utils.DEFAULT_ENDEAVOR_PACKAGE

    private val entry = Entry(
        id = "profile-1",
        fields = linkedMapOf(
            "name" to TypedField("Ada", FieldType.STRING),
            "age" to TypedField("36", FieldType.INTEGER),
        ),
        publicKey = "PUBLIC-KEY-BASE64",
    )

    // ── Action strings ───────────────────────────────────────────────────

    @Test
    fun `action strings are scoped to the target package`() {
        assertEquals(
            "com.github.adaydreamaway.endeavor.ACTION_SHARE_DATA",
            Utils.shareDataAction(),
        )
        assertEquals(
            "com.github.adaydreamaway.endeavor.ACTION_SIGN_CHALLENGE",
            Utils.signChallengeAction(),
        )
        assertEquals("dev.other.vault.ACTION_SHARE_DATA", Utils.shareDataAction("dev.other.vault"))
        assertEquals(
            "dev.other.vault.ACTION_SIGN_CHALLENGE",
            Utils.signChallengeAction("dev.other.vault"),
        )
    }

    @Test
    fun `the default vault package is Endeavor`() {
        assertEquals("com.github.adaydreamaway.endeavor", Utils.DEFAULT_ENDEAVOR_PACKAGE)
    }

    // ── Share ────────────────────────────────────────────────────────────

    @Test
    fun `share intent targets the vault and carries the entry as JSON`() {
        val intent = Utils.createShareIntent(context, entry)

        assertEquals("com.github.adaydreamaway.endeavor.ACTION_SHARE_DATA", intent.action)
        assertEquals(vault, intent.`package`)

        val json = intent.getStringExtra("extra_entry_json")
        val decoded = Gson().fromJson(json, Entry::class.java)
        assertEquals(entry.id, decoded.id)
        assertEquals(entry.publicKey, decoded.publicKey)
        assertEquals("Ada", decoded.fields["name"]?.value)
        assertEquals(FieldType.INTEGER, decoded.fields["age"]?.type)
    }

    /**
     * Pins the reasoning in [Utils.createShareIntent]'s comment: CLEAR_TOP delivers to an
     * existing vault instance via onNewIntent, while NEW_TASK would put the vault in a
     * separate task and silently break `startActivityForResult` delivery. Adding NEW_TASK
     * here would be an easy, plausible, and completely invisible regression.
     */
    @Test
    fun `share intent sets CLEAR_TOP but not NEW_TASK`() {
        val flags = Utils.createShareIntent(context, entry).flags
        assertTrue("CLEAR_TOP must be set", flags and Intent.FLAG_ACTIVITY_CLEAR_TOP != 0)
        assertFalse(
            "NEW_TASK must NOT be set — it breaks result delivery",
            flags and Intent.FLAG_ACTIVITY_NEW_TASK != 0,
        )
    }

    @Test
    fun `share intent omits the request code unless one is given`() {
        assertNull(Utils.createShareIntent(context, entry).getStringExtra("extra_share_request_code"))
    }

    @Test
    fun `share intent echoes the request code when given`() {
        val intent = Utils.createShareIntent(context, entry, requestCode = "req-42")
        assertEquals("req-42", intent.getStringExtra("extra_share_request_code"))
        assertEquals("com.github.adaydreamaway.endeavor.ACTION_SHARE_DATA", intent.action)
    }

    // ── Query ────────────────────────────────────────────────────────────

    @Test
    fun `query intent reuses the share action and carries the public key`() {
        val intent = Utils.createQueryIntent(context, "PUBLIC-KEY-BASE64", "req-7")

        assertEquals("com.github.adaydreamaway.endeavor.ACTION_SHARE_DATA", intent.action)
        assertEquals(vault, intent.`package`)
        assertEquals("PUBLIC-KEY-BASE64", intent.getStringExtra("extra_public_key"))
        assertEquals("req-7", intent.getStringExtra("extra_share_request_code"))
        assertNull(
            "a query carries no entry payload",
            intent.getStringExtra("extra_entry_json"),
        )
    }

    // ── Sign challenge ───────────────────────────────────────────────────

    @Test
    fun `sign challenge intent carries key, nonce and request code`() {
        val nonce = byteArrayOf(1, 2, 3, 4, 5)
        val intent = Utils.createSignChallengeIntent(context, "PUBLIC-KEY-BASE64", nonce, "req-9")

        assertEquals("com.github.adaydreamaway.endeavor.ACTION_SIGN_CHALLENGE", intent.action)
        assertEquals(vault, intent.`package`)
        assertEquals("PUBLIC-KEY-BASE64", intent.getStringExtra("extra_public_key"))
        assertEquals("req-9", intent.getStringExtra("extra_share_request_code"))

        val roundTripped = Base64.decode(intent.getStringExtra("extra_nonce"), Base64.DEFAULT)
        assertTrue("nonce must survive base64 intact", nonce.contentEquals(roundTripped))
    }

    /**
     * A long nonce is the realistic case (32 random bytes plus a timestamp). `NO_WRAP` is
     * what keeps the encoding free of newlines; DEFAULT would wrap at 76 characters and hand
     * the vault a value that naive parsers split on.
     */
    @Test
    fun `a long nonce is encoded without line breaks`() {
        val nonce = ByteArray(64) { it.toByte() }
        val intent = Utils.createSignChallengeIntent(context, "PUBLIC-KEY-BASE64", nonce, "req-10")
        val encoded = intent.getStringExtra("extra_nonce")!!

        assertFalse("nonce encoding must not wrap", encoded.contains("\n"))
        assertTrue(nonce.contentEquals(Base64.decode(encoded, Base64.DEFAULT)))
    }

    /**
     * The nonce is generated on this side, Base64'd onto the wire, and its freshness is read
     * back out of the same bytes. A wrapping or padding slip anywhere along that path would
     * corrupt the timestamp and expire every challenge instantly, so the whole path is
     * walked once here rather than trusting the two halves in isolation.
     */
    @Test
    fun `a generated nonce survives the intent and is still fresh`() {
        val clock = 1_770_000_000_000L
        val nonce = Utils.generateNonce(now = clock)
        val intent = Utils.createSignChallengeIntent(context, "PUBLIC-KEY-BASE64", nonce, "req-11")

        val roundTripped = Base64.decode(intent.getStringExtra("extra_nonce"), Base64.DEFAULT)
        assertTrue(nonce.contentEquals(roundTripped))
        assertTrue(Utils.isNonceFresh(roundTripped, 60_000, now = clock + 30_000))
        assertFalse(Utils.isNonceFresh(roundTripped, 60_000, now = clock + 60_001))
    }

    @Test
    fun `intents can be aimed at a vault other than Endeavor`() {
        val other = "dev.eryalabs.othervault"
        val share = Utils.createShareIntent(context, entry, targetPackage = other)
        val query = Utils.createQueryIntent(context, "K", "r", targetPackage = other)
        val sign = Utils.createSignChallengeIntent(context, "K", byteArrayOf(1), "r", targetPackage = other)

        listOf(share, query, sign).forEach { assertEquals(other, it.`package`) }
        assertEquals("$other.ACTION_SHARE_DATA", share.action)
        assertEquals("$other.ACTION_SHARE_DATA", query.action)
        assertEquals("$other.ACTION_SIGN_CHALLENGE", sign.action)
    }

    // ── Extra-key constants are wire format ──────────────────────────────

    @Test
    fun `extra keys match the literals the vault reads`() {
        assertEquals("extra_entry_json", Utils.EXTRA_ENTRY_JSON)
        assertEquals("extra_share_request_code", Utils.EXTRA_SHARE_REQUEST_CODE)
        assertEquals("extra_query_result_fields", Utils.EXTRA_QUERY_RESULT_FIELDS)
        assertEquals("extra_public_key", Utils.EXTRA_PUBLIC_KEY)
        assertEquals("extra_nonce", Utils.EXTRA_NONCE)
        assertEquals("extra_signature", Utils.EXTRA_SIGNATURE)
        assertEquals("extra_algorithm", Utils.EXTRA_ALGORITHM)
        assertEquals("extra_fields_json", Utils.EXTRA_FIELDS_JSON)
    }
}
