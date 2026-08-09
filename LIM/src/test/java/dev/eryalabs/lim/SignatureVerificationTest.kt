package dev.eryalabs.lim

import android.util.Base64
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature

/**
 * Proof-of-possession is the pillar that replaces passwords, so its verifier gets the
 * harshest treatment in this suite: one positive case and six ways it must say no.
 *
 * Robolectric is required because [Utils.verifySignature] decodes with `android.util.Base64`,
 * which is a stub that returns null under plain JVM unit tests. The crypto itself is
 * ordinary JCE and runs natively — no device, no keystore, no network.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class SignatureVerificationTest {

    companion object {
        private lateinit var keyPair: KeyPair
        private lateinit var otherKeyPair: KeyPair

        /** 2048-bit RSA generation is slow (~100ms each); do it once for the whole class. */
        @JvmStatic
        @BeforeClass
        fun generateKeys() {
            val gen = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }
            keyPair = gen.generateKeyPair()
            otherKeyPair = gen.generateKeyPair()
        }
    }

    private fun publicKeyOf(kp: KeyPair): String =
        Base64.encodeToString(kp.public.encoded, Base64.DEFAULT)

    private fun sign(kp: KeyPair, data: ByteArray): ByteArray =
        Signature.getInstance("SHA256withRSA").run {
            initSign(kp.private)
            update(data)
            sign()
        }

    private val nonce = "challenge-nonce-1770000000".toByteArray()

    // ── The one case that must succeed ───────────────────────────────────

    @Test
    fun `a genuine signature over the nonce verifies`() {
        assertTrue(
            Utils.verifySignature(publicKeyOf(keyPair), nonce, sign(keyPair, nonce)),
        )
    }

    /**
     * Endeavor encodes public keys with `Base64.DEFAULT`, which wraps at 76 chars and
     * embeds newlines. If the verifier ever switched to a strict decoder this would break
     * in production and nowhere else, so it is pinned here explicitly.
     */
    @Test
    fun `public keys carrying DEFAULT-encoding newlines still verify`() {
        val encoded = publicKeyOf(keyPair)
        assertTrue("precondition: DEFAULT encoding should wrap", encoded.contains("\n"))
        assertTrue(Utils.verifySignature(encoded, nonce, sign(keyPair, nonce)))
    }

    // ── Negative controls: every way this must refuse ────────────────────

    @Test
    fun `a signature from a different keypair is rejected`() {
        assertFalse(
            "signature made with another private key must not verify",
            Utils.verifySignature(publicKeyOf(keyPair), nonce, sign(otherKeyPair, nonce)),
        )
    }

    @Test
    fun `a signature over different data is rejected`() {
        val signatureOverSomethingElse = sign(keyPair, "a different challenge".toByteArray())
        assertFalse(
            "replaying a signature bound to another nonce must not verify",
            Utils.verifySignature(publicKeyOf(keyPair), nonce, signatureOverSomethingElse),
        )
    }

    @Test
    fun `a tampered nonce is rejected`() {
        val signature = sign(keyPair, nonce)
        val tampered = nonce.copyOf().also { it[0] = (it[0] + 1).toByte() }
        assertFalse(Utils.verifySignature(publicKeyOf(keyPair), tampered, signature))
    }

    @Test
    fun `a tampered signature is rejected`() {
        val signature = sign(keyPair, nonce)
        signature[signature.size - 1] = (signature[signature.size - 1] + 1).toByte()
        assertFalse(Utils.verifySignature(publicKeyOf(keyPair), nonce, signature))
    }

    @Test
    fun `garbage inputs are rejected rather than throwing`() {
        val good = publicKeyOf(keyPair)
        val signature = sign(keyPair, nonce)

        assertFalse("empty public key", Utils.verifySignature("", nonce, signature))
        assertFalse("non-base64 public key", Utils.verifySignature("!!!not base64!!!", nonce, signature))
        assertFalse("base64 that is not a key", Utils.verifySignature("aGVsbG8gd29ybGQ=", nonce, signature))
        assertFalse("empty signature", Utils.verifySignature(good, nonce, ByteArray(0)))
        assertFalse("random signature bytes", Utils.verifySignature(good, nonce, ByteArray(256) { 7 }))
    }

    /**
     * The empty nonce is legal input to the JCE, so this asserts consistency rather than
     * refusal: whatever the verifier does, it must not accept a signature that was made
     * over a *different* empty-ish value.
     */
    @Test
    fun `an empty nonce does not verify against a signature over real data`() {
        assertFalse(
            Utils.verifySignature(publicKeyOf(keyPair), ByteArray(0), sign(keyPair, nonce)),
        )
    }
}
