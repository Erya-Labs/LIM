package dev.eryalabs.lim

import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * The nonce-format declaration: a sign-challenge request may name the layout of the nonce it
 * carries, so a vault finally has grounds to check freshness for the clients that opt in —
 * today it cannot enforce anything, because a hand-rolled nonce without the timestamp header
 * is indistinguishable from a stale one. Like every wire constant, the key and the value are
 * pinned to literals here so a renamed constant cannot quietly rename the wire format.
 *
 * The negative control matters more than the positive one: the parameter defaults to `null`,
 * and `null` must attach *nothing* — an upgraded-but-unaware client rebuilding against this
 * version must produce an intent identical to today's, never a declaration its hand-rolled
 * nonce does not live up to.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class NonceFormatTest {

    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()

    @Test
    fun `the nonce-format constants match the wire literals`() {
        assertEquals("extra_nonce_format", Utils.EXTRA_NONCE_FORMAT)
        assertEquals("lim-ts1", Utils.NONCE_FORMAT_TIMESTAMPED)
    }

    @Test
    fun `by default a sign-challenge intent carries no nonce-format extra`() {
        val intent = Utils.createSignChallengeIntent(
            context, "PUBLIC-KEY-BASE64", byteArrayOf(1, 2, 3), "req-1",
        )
        assertFalse(
            "the default must declare nothing, not declare an empty something",
            intent.hasExtra("extra_nonce_format"),
        )
    }

    /**
     * "Attaches nothing" is necessary but not sufficient for "identical to today's": the
     * whole extras envelope is pinned, so the default-parameter path cannot have gained or
     * lost anything else either.
     */
    @Test
    fun `the default-parameter intent is identical to the pre-parameter one`() {
        val intent = Utils.createSignChallengeIntent(
            context, "PUBLIC-KEY-BASE64", byteArrayOf(1, 2, 3), "req-2",
        )
        assertEquals(
            "exactly the four extras every sign-challenge request has carried since T11",
            setOf(
                "extra_public_key",
                "extra_nonce",
                "extra_share_request_code",
                "extra_protocol_version",
            ),
            intent.extras?.keySet(),
        )
        assertEquals("com.github.adaydreamaway.endeavor.ACTION_SIGN_CHALLENGE", intent.action)
    }

    @Test
    fun `declaring the timestamped format attaches exactly its literal`() {
        val intent = Utils.createSignChallengeIntent(
            context,
            "PUBLIC-KEY-BASE64",
            Utils.generateNonce(now = 1_770_000_000_000L),
            "req-3",
            nonceFormat = Utils.NONCE_FORMAT_TIMESTAMPED,
        )
        assertEquals("lim-ts1", intent.getStringExtra("extra_nonce_format"))
    }

    /**
     * The parameter is a declaration, not an enum: a client speaking a future format this
     * library has never heard of passes its own token and it travels verbatim. The vault
     * decides what it understands — this side only carries the words.
     */
    @Test
    fun `a caller-chosen format string travels verbatim`() {
        val intent = Utils.createSignChallengeIntent(
            context, "PUBLIC-KEY-BASE64", byteArrayOf(9), "req-4",
            nonceFormat = "vendor-fmt2",
        )
        assertEquals("vendor-fmt2", intent.getStringExtra("extra_nonce_format"))
    }

    /**
     * The declaration must not disturb the rest of the request: same action, same package,
     * same key, nonce and correlation extras, same protocol version.
     */
    @Test
    fun `declaring a format leaves every other extra untouched`() {
        val nonce = Utils.generateNonce(now = 1_770_000_000_000L)
        val plain = Utils.createSignChallengeIntent(context, "K", nonce, "req-5")
        val declared = Utils.createSignChallengeIntent(
            context, "K", nonce, "req-5", nonceFormat = Utils.NONCE_FORMAT_TIMESTAMPED,
        )

        assertEquals(plain.action, declared.action)
        assertEquals(plain.`package`, declared.`package`)
        listOf(
            "extra_public_key", "extra_nonce", "extra_share_request_code",
            "extra_protocol_version",
        ).forEach { key ->
            assertEquals(key, plain.getStringExtra(key), declared.getStringExtra(key))
        }
        assertEquals(
            setOf(
                "extra_public_key", "extra_nonce", "extra_share_request_code",
                "extra_protocol_version", "extra_nonce_format",
            ),
            declared.extras?.keySet(),
        )
    }
}
