package dev.eryalabs.lim

import android.content.Intent
import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Protocol versioning: the one fact every future protocol addition depends on is that a
 * client can tell "the vault honoured this" from "the vault ignored what it did not know".
 * The version rides in both directions — attached to every outgoing request, echoed by a
 * vault that understands it — and like every wire constant, the key and the value are pinned
 * to literals here so a renamed constant cannot quietly rename the wire format.
 *
 * The echo is hostile input like every other extra: a peer app chooses what to send back, so
 * every unusable declaration must read as `null` — the legacy shape — and never as a throw,
 * and never as a *default*, because a `null` that quietly became a modern version would tell
 * a client its request was honoured by a vault that never saw it.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ProtocolVersionTest {

    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()

    private val entry = Entry(
        id = "profile-1",
        fields = mapOf("name" to TypedField("Ada", FieldType.STRING)),
        publicKey = "PUBLIC-KEY-BASE64",
    )

    /** A result intent as the vault builds it: a bare [Intent] carrying extras. */
    private fun resultIntent(vararg extras: Pair<String, String>) = Intent().apply {
        extras.forEach { (key, value) -> putExtra(key, value) }
    }

    private val signatureExtra =
        Utils.EXTRA_SIGNATURE to Base64.encodeToString(ByteArray(16) { 7 }, Base64.DEFAULT)

    // ── The constants are wire format ────────────────────────────────────

    @Test
    fun `the protocol version and its extra key match the wire literals`() {
        assertEquals(2, Utils.PROTOCOL_VERSION)
        assertEquals("extra_protocol_version", Utils.EXTRA_PROTOCOL_VERSION)
    }

    // ── Every request builder declares the version ───────────────────────

    @Test
    fun `every outgoing request carries the protocol version as a decimal string`() {
        val share = Utils.createShareIntent(context, entry)
        val taggedShare = Utils.createShareIntent(context, entry, requestCode = "req-1")
        val query = Utils.createQueryIntent(context, "PUBLIC-KEY-BASE64", "req-2")
        val sign = Utils.createSignChallengeIntent(context, "PUBLIC-KEY-BASE64", byteArrayOf(1), "req-3")

        listOf("share" to share, "tagged share" to taggedShare, "query" to query, "sign" to sign)
            .forEach { (name, intent) ->
                assertEquals(
                    "$name must declare the version under the literal key",
                    "2",
                    intent.getStringExtra("extra_protocol_version"),
                )
            }
    }

    // ── A versioned vault's echo is surfaced ─────────────────────────────

    @Test
    fun `a version-2 result reports the vault's protocol version on all three parsers`() {
        val version = Utils.EXTRA_PROTOCOL_VERSION to "2"

        val query = Utils.parseQueryResult(
            resultIntent(Utils.EXTRA_SHARE_REQUEST_CODE to "req-7", version),
        )
        assertEquals(2, query?.vaultProtocolVersion)

        val share = Utils.parseShareResult(
            resultIntent(Utils.EXTRA_PUBLIC_KEY to "PUBLIC-KEY-BASE64", version),
        )
        assertEquals(2, share?.vaultProtocolVersion)

        val sign = Utils.parseSignChallengeResult(resultIntent(signatureExtra, version))
        assertEquals(2, sign?.vaultProtocolVersion)
    }

    /** Future vaults may speak later versions; the parser reports, it does not gatekeep. */
    @Test
    fun `a later version than this library's is reported as sent`() {
        val result = Utils.parseQueryResult(
            resultIntent(
                Utils.EXTRA_SHARE_REQUEST_CODE to "req-7",
                Utils.EXTRA_PROTOCOL_VERSION to "9",
            ),
        )
        assertEquals(9, result?.vaultProtocolVersion)
    }

    // ── The legacy shape is untouched ────────────────────────────────────

    @Test
    fun `a legacy result with no version extra parses as before with a null version`() {
        val query = Utils.parseQueryResult(resultIntent(Utils.EXTRA_SHARE_REQUEST_CODE to "req-7"))
        assertNotNull(query)
        assertNull(query!!.vaultProtocolVersion)
        assertEquals("req-7", query.requestCode)

        val share = Utils.parseShareResult(resultIntent(Utils.EXTRA_PUBLIC_KEY to "PUBLIC-KEY-BASE64"))
        assertNotNull(share)
        assertNull(share!!.vaultProtocolVersion)
        assertEquals("PUBLIC-KEY-BASE64", share.publicKey)

        val sign = Utils.parseSignChallengeResult(resultIntent(signatureExtra))
        assertNotNull(sign)
        assertNull(sign!!.vaultProtocolVersion)
    }

    /**
     * The version is an annotation on an answer, not an answer: each parser's empty-envelope
     * rule is decided over its own flow's extras, so an intent carrying nothing but a version
     * is still nothing. Otherwise a hostile peer could conjure a non-null "result" out of an
     * extra no legacy vault even knows exists.
     */
    @Test
    fun `a version alone is still an empty envelope`() {
        val versionOnly = resultIntent(Utils.EXTRA_PROTOCOL_VERSION to "2")
        assertNull(Utils.parseQueryResult(versionOnly))
        assertNull(Utils.parseShareResult(versionOnly))
        assertNull(Utils.parseSignChallengeResult(versionOnly))
    }

    // ── Hostile declarations read as "did not say", never as a throw ─────

    @Test
    fun `an unusable version value reads as null on all three parsers`() {
        // One case per failure mode: blank, non-numeric, negative, zero, too large for an
        // Int, and internal whitespace. "Lenient" means unusable values degrade to null,
        // never that they are repaired into a number — though the parse is Kotlin's
        // toIntOrNull, which does accept a leading `+` and non-ASCII digits, so anything
        // it yields is still the positive integer the sender encoded.
        val hostile = listOf("", "   ", "abc", "-1", "0", "2147483648", " 2", "2.0")

        hostile.forEach { value ->
            val version = Utils.EXTRA_PROTOCOL_VERSION to value

            val query = Utils.parseQueryResult(
                resultIntent(Utils.EXTRA_SHARE_REQUEST_CODE to "req-7", version),
            )
            assertNotNull("query result must survive version '$value'", query)
            assertNull("query version for '$value'", query!!.vaultProtocolVersion)

            val share = Utils.parseShareResult(
                resultIntent(Utils.EXTRA_PUBLIC_KEY to "PUBLIC-KEY-BASE64", version),
            )
            assertNotNull("share result must survive version '$value'", share)
            assertNull("share version for '$value'", share!!.vaultProtocolVersion)

            val sign = Utils.parseSignChallengeResult(resultIntent(signatureExtra, version))
            assertNotNull("sign result must survive version '$value'", sign)
            assertNull("sign version for '$value'", sign!!.vaultProtocolVersion)
        }
    }

    /** The sender picks the extra's type, not just its value — an Int extra is not a String. */
    @Test
    fun `a version extra of the wrong type reads as null`() {
        val intent = Intent().apply {
            putExtra(Utils.EXTRA_SHARE_REQUEST_CODE, "req-7")
            putExtra(Utils.EXTRA_PROTOCOL_VERSION, 2)
        }
        val result = Utils.parseQueryResult(intent)
        assertNotNull(result)
        assertNull(result!!.vaultProtocolVersion)
    }

    // ── The new property joins the hand-written equality contract ────────

    /**
     * [SignChallengeResult] writes its own `equals`/`hashCode` for the signature bytes, so
     * the new property had to be threaded through by hand — the generated classes get this
     * for free, this one only by assertion.
     */
    @Test
    fun `sign-challenge results differing only in vault version are not equal`() {
        val a = SignChallengeResult(byteArrayOf(1, 2), null, emptyMap(), "req-1")
        val b = a.copy(vaultProtocolVersion = 2)

        assertNotEquals(a, b)
        assertEquals(a, a.copy())
        assertEquals(a.hashCode(), a.copy().hashCode())
        assertEquals(2, b.vaultProtocolVersion)
    }
}
