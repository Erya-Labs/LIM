package dev.eryalabs.lim

import android.content.Intent
import android.os.BadParcelableException
import android.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
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
 * The result intents are the other half of the protocol, and they arrive from the vault —
 * i.e. from another app, i.e. from something this library must not trust. Two properties are
 * pinned below: every malformed shape degrades to `null` or an empty result instead of
 * throwing in the client's `onActivityResult`, and a *parsed* sign-challenge result can never
 * pass itself off as an *authenticated* one.
 *
 * Robolectric is required: [Intent] extras and `android.util.Base64` are unimplemented stubs
 * in a plain JVM unit test. The crypto is ordinary JCE and runs on the host.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ResultParsingTest {

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

    private val nonce = Utils.generateNonce(now = 1_770_000_000_000L)

    private fun publicKeyOf(kp: KeyPair): String =
        Base64.encodeToString(kp.public.encoded, Base64.DEFAULT)

    private fun sign(kp: KeyPair, data: ByteArray): ByteArray =
        Signature.getInstance("SHA256withRSA").run {
            initSign(kp.private)
            update(data)
            sign()
        }

    private val fieldsJson = Utils.encodeFields(
        linkedMapOf(
            "email" to TypedField("ada@example.com", FieldType.EMAIL),
            "age" to TypedField("36", FieldType.INTEGER),
        ),
    )

    /** A result intent as the vault builds it: a bare [Intent] carrying extras. */
    private fun resultIntent(vararg extras: Pair<String, String>) = Intent().apply {
        extras.forEach { (key, value) -> putExtra(key, value) }
    }

    /**
     * An intent whose extras cannot be read. Unparcelling a bundle that references a class
     * this process does not have throws in exactly this way, and the sender chooses what goes
     * in the bundle — so the parsers must survive it.
     */
    private class UnreadableIntent : Intent() {
        /** Counted so the test can prove the throw was reached, not merely that null came back. */
        var reads = 0
            private set

        override fun getStringExtra(name: String?): String? {
            reads++
            throw BadParcelableException("extras reference an unknown class")
        }
    }

    // ── Sign challenge: the happy path ───────────────────────────────────

    @Test
    fun `a full sign-challenge result is decoded`() {
        val signature = sign(keyPair, nonce)
        val result = Utils.parseSignChallengeResult(
            resultIntent(
                Utils.EXTRA_SIGNATURE to Base64.encodeToString(signature, Base64.DEFAULT),
                Utils.EXTRA_ALGORITHM to "SHA256withRSA",
                Utils.EXTRA_FIELDS_JSON to fieldsJson,
                Utils.EXTRA_SHARE_REQUEST_CODE to "req-9",
            ),
        )

        assertNotNull(result)
        assertTrue("signature bytes must survive base64", signature.contentEquals(result!!.signature))
        assertEquals("SHA256withRSA", result.algorithm)
        assertEquals("req-9", result.requestCode)
        assertEquals(2, result.fields.size)
        assertEquals("ada@example.com", result.fields["email"]?.value)
        assertEquals(FieldType.EMAIL, result.fields["email"]?.type)
        assertEquals(FieldType.INTEGER, result.fields["age"]?.type)
    }

    /**
     * A real 2048-bit signature Base64s to more than 76 characters, so `Base64.DEFAULT`
     * wraps it. A strict decoder here would reject every genuine result and nothing else,
     * which is why the precondition is asserted rather than assumed.
     */
    @Test
    fun `a signature carrying DEFAULT-encoding newlines is decoded`() {
        val signature = sign(keyPair, nonce)
        val encoded = Base64.encodeToString(signature, Base64.DEFAULT)
        assertTrue("precondition: DEFAULT encoding should wrap", encoded.contains("\n"))

        val result = Utils.parseSignChallengeResult(resultIntent(Utils.EXTRA_SIGNATURE to encoded))
        assertTrue(signature.contentEquals(result!!.signature))
    }

    @Test
    fun `an absent algorithm and request code read as null`() {
        val result = Utils.parseSignChallengeResult(
            resultIntent(Utils.EXTRA_SIGNATURE to Base64.encodeToString(sign(keyPair, nonce), Base64.DEFAULT)),
        )

        assertNotNull(result)
        assertNull(result!!.algorithm)
        assertNull(result.requestCode)
        assertTrue(result.fields.isEmpty())
    }

    // ── Sign challenge: every way it must refuse ─────────────────────────

    @Test
    fun `a null intent yields null`() {
        assertNull(Utils.parseSignChallengeResult(null))
        assertNull(Utils.parseQueryResult(null))
        assertNull(Utils.parseShareResult(null))
    }

    @Test
    fun `an intent with no extras yields null`() {
        assertNull(Utils.parseSignChallengeResult(Intent()))
        assertNull(Utils.parseQueryResult(Intent()))
        assertNull(Utils.parseShareResult(Intent()))
    }

    /**
     * Two different refusals, and the second is the one that is easy to miss: Android's
     * `Base64` does not reject characters outside the alphabet, it *skips* them. `"!!! not
     * base64 !!!"` throws only because the nine surviving alphabet characters are a bad
     * length, while `"!!!!"` decodes cheerfully to zero bytes. A parser that only guarded
     * against the throw would hand the client a result carrying an empty signature — which
     * cannot verify, but which arrives looking like an answer.
     */
    @Test
    fun `a signature that is not valid base64 yields null`() {
        assertNull(
            "junk that throws",
            Utils.parseSignChallengeResult(
                resultIntent(
                    Utils.EXTRA_SIGNATURE to "!!! not base64 !!!",
                    Utils.EXTRA_FIELDS_JSON to fieldsJson,
                ),
            ),
        )
        assertNull(
            "junk that silently decodes to no bytes",
            Utils.parseSignChallengeResult(
                resultIntent(
                    Utils.EXTRA_SIGNATURE to "!!!!",
                    Utils.EXTRA_FIELDS_JSON to fieldsJson,
                ),
            ),
        )
        assertNull(
            "punctuation only",
            Utils.parseSignChallengeResult(resultIntent(Utils.EXTRA_SIGNATURE to "@@@@@@@@")),
        )
    }

    @Test
    fun `a missing or blank signature yields null`() {
        assertNull(
            "no signature extra at all",
            Utils.parseSignChallengeResult(resultIntent(Utils.EXTRA_FIELDS_JSON to fieldsJson)),
        )
        assertNull("empty", Utils.parseSignChallengeResult(resultIntent(Utils.EXTRA_SIGNATURE to "")))
        assertNull("whitespace", Utils.parseSignChallengeResult(resultIntent(Utils.EXTRA_SIGNATURE to "   ")))
        assertNull(
            "base64 of no bytes",
            Utils.parseSignChallengeResult(resultIntent(Utils.EXTRA_SIGNATURE to "====")),
        )
    }

    /**
     * The sender picks the extra's type, not just its value. `getStringExtra` returns null
     * for a non-String extra rather than throwing, so this pins that the parser treats it as
     * absent instead of, say, calling `toString()` on it.
     */
    @Test
    fun `a signature extra of the wrong type yields null`() {
        val intent = Intent().apply { putExtra(Utils.EXTRA_SIGNATURE, 42) }
        assertNull(Utils.parseSignChallengeResult(intent))
    }

    /**
     * The signature is independent of the field payload: a vault that garbles the profile
     * JSON has still proved possession, and discarding the whole result would turn a
     * disclosure failure into an authentication failure.
     */
    @Test
    fun `a malformed fields payload leaves the signature intact`() {
        val signature = sign(keyPair, nonce)
        val result = Utils.parseSignChallengeResult(
            resultIntent(
                Utils.EXTRA_SIGNATURE to Base64.encodeToString(signature, Base64.DEFAULT),
                Utils.EXTRA_FIELDS_JSON to "{not json at all",
            ),
        )

        assertNotNull(result)
        assertTrue("fields must degrade to empty", result!!.fields.isEmpty())
        assertTrue(signature.contentEquals(result.signature))
        assertTrue(result.isVerified(publicKeyOf(keyPair), nonce))
    }

    @Test
    fun `hostile field entries are repaired rather than handed on`() {
        val result = Utils.parseSignChallengeResult(
            resultIntent(
                Utils.EXTRA_SIGNATURE to Base64.encodeToString(sign(keyPair, nonce), Base64.DEFAULT),
                Utils.EXTRA_FIELDS_JSON to """{"a":{"value":"x"},"b":null,"c":{"type":"Email"}}""",
            ),
        )!!

        assertNull("a null entry is dropped", result.fields["b"])
        // Declared non-null but genuinely null out of Gson; reading them must not throw.
        result.fields.forEach { (key, field) ->
            assertNotNull("$key value", field.value)
            assertNotNull("$key type", field.type)
            assertTrue("$key type", field.type.isNotEmpty())
        }
        assertEquals(FieldType.STRING, result.fields["a"]?.type)
        assertEquals("", result.fields["c"]?.value)
    }

    /**
     * Self-anchoring, for the same reason the correlation helper's copy of this fixture is:
     * `null` is also what a parser that never touched the intent would return, so without the
     * counter this passes green against a `presentStringExtra` that throws
     * `BadParcelableException` straight into the client's `onActivityResult`. It is the only
     * assertion in the file that tells a *safe* read from *no* read.
     *
     * The query parser's count is the interesting one: it reads three extras and must survive
     * all three, so a guard that bailed after the first would still return null and would still
     * be wrong about the two it skipped.
     */
    @Test
    fun `an intent whose extras cannot be read yields null rather than throwing`() {
        val signIntent = UnreadableIntent()
        assertNull(Utils.parseSignChallengeResult(signIntent))
        assertEquals(
            "the throwing read must actually have been attempted",
            1,
            signIntent.reads,
        )

        val queryIntent = UnreadableIntent()
        assertNull(Utils.parseQueryResult(queryIntent))
        assertEquals(
            "every query extra must be attempted and survive, not just the first",
            3,
            queryIntent.reads,
        )

        val shareIntent = UnreadableIntent()
        assertNull(Utils.parseShareResult(shareIntent))
        assertEquals(
            "every share extra must be attempted and survive, not just the first",
            3,
            shareIntent.reads,
        )
    }

    /**
     * The two field payloads sit under different keys at different points in the protocol.
     * Reading either key from either flow would let a query answer be presented as a signed
     * disclosure, so the separation is pinned in both directions.
     */
    @Test
    fun `each parser reads only its own fields key`() {
        val signResult = Utils.parseSignChallengeResult(
            resultIntent(
                Utils.EXTRA_SIGNATURE to Base64.encodeToString(sign(keyPair, nonce), Base64.DEFAULT),
                Utils.EXTRA_QUERY_RESULT_FIELDS to fieldsJson,
            ),
        )!!
        assertTrue(
            "the sign-challenge parser must ignore the query-result fields key",
            signResult.fields.isEmpty(),
        )

        val queryResult = Utils.parseQueryResult(
            resultIntent(
                Utils.EXTRA_FIELDS_JSON to fieldsJson,
                Utils.EXTRA_SHARE_REQUEST_CODE to "req-7",
            ),
        )!!
        assertTrue(
            "the query parser must ignore the sign-challenge fields key",
            queryResult.fields.isEmpty(),
        )

        val shareResult = Utils.parseShareResult(
            resultIntent(
                Utils.EXTRA_QUERY_RESULT_FIELDS to fieldsJson,
                Utils.EXTRA_SHARE_REQUEST_CODE to "req-7",
            ),
        )!!
        assertTrue(
            "the share parser must ignore the query-result fields key",
            shareResult.fields.isEmpty(),
        )
    }

    // ── Parsed is not authenticated ──────────────────────────────────────

    @Test
    fun `a genuine signature verifies against the key and nonce that produced it`() {
        val result = Utils.parseSignChallengeResult(
            resultIntent(
                Utils.EXTRA_SIGNATURE to Base64.encodeToString(sign(keyPair, nonce), Base64.DEFAULT),
                Utils.EXTRA_FIELDS_JSON to fieldsJson,
            ),
        )!!

        assertTrue(result.isVerified(publicKeyOf(keyPair), nonce))
    }

    @Test
    fun `verification fails against the wrong key, the wrong nonce and a garbage key`() {
        val result = Utils.parseSignChallengeResult(
            resultIntent(
                Utils.EXTRA_SIGNATURE to Base64.encodeToString(sign(keyPair, nonce), Base64.DEFAULT),
            ),
        )!!

        assertFalse(
            "another profile's public key must not authenticate this signature",
            result.isVerified(publicKeyOf(otherKeyPair), nonce),
        )
        assertFalse(
            "a signature is bound to one challenge only",
            result.isVerified(publicKeyOf(keyPair), "some other challenge".toByteArray()),
        )
        assertFalse("empty key", result.isVerified("", nonce))
        assertFalse("non-base64 key", result.isVerified("!!!not base64!!!", nonce))
        assertFalse("base64 that is not a key", result.isVerified("aGVsbG8gd29ybGQ=", nonce))
    }

    /**
     * A forged result is the whole threat here: anything can put bytes in an intent. What it
     * cannot do is make those bytes verify against the key and nonce the *client* chose.
     */
    @Test
    fun `a forged signature parses but does not authenticate`() {
        val result = Utils.parseSignChallengeResult(
            resultIntent(
                Utils.EXTRA_SIGNATURE to Base64.encodeToString(ByteArray(256) { 7 }, Base64.DEFAULT),
                Utils.EXTRA_ALGORITHM to "SHA256withRSA",
                Utils.EXTRA_FIELDS_JSON to fieldsJson,
            ),
        )

        assertNotNull("a well-formed but forged result still parses", result)
        assertFalse(result!!.isVerified(publicKeyOf(keyPair), nonce))
    }

    /**
     * The structural guarantee behind the two tests above: there is no way to *ask* a parsed
     * result whether it is authenticated without supplying the key and the nonce. A property
     * or no-argument accessor returning `Boolean` would be exactly that — a value a caller
     * could read, and a sender could influence, without ever running the verification. It
     * would also be a natural thing for a later change to add, which is why this is asserted
     * against the class rather than left to review.
     */
    @Test
    fun `a parsed result exposes no argument-free success signal`() {
        val offenders = SignChallengeResult::class.java.declaredMethods
            .filter { !it.isSynthetic }
            .filter { it.parameterCount == 0 }
            .filter { it.returnType == java.lang.Boolean.TYPE || it.returnType == java.lang.Boolean::class.java }
            .map { it.name }

        assertEquals(
            "verification must require the caller's own public key and nonce; found $offenders",
            emptyList<String>(),
            offenders,
        )
    }

    @Test
    fun `results carrying the same bytes are equal`() {
        val encoded = Base64.encodeToString(sign(keyPair, nonce), Base64.DEFAULT)
        val a = Utils.parseSignChallengeResult(resultIntent(Utils.EXTRA_SIGNATURE to encoded))!!
        val b = Utils.parseSignChallengeResult(resultIntent(Utils.EXTRA_SIGNATURE to encoded))!!

        assertEquals("array identity must not decide equality", a, b)
        assertEquals(a.hashCode(), b.hashCode())

        val different = Utils.parseSignChallengeResult(
            resultIntent(Utils.EXTRA_SIGNATURE to Base64.encodeToString(ByteArray(64) { 3 }, Base64.DEFAULT)),
        )!!
        assertFalse(a == different)
    }

    // ── Query results ────────────────────────────────────────────────────

    @Test
    fun `a full query result is decoded`() {
        val result = Utils.parseQueryResult(
            resultIntent(
                Utils.EXTRA_QUERY_RESULT_FIELDS to fieldsJson,
                Utils.EXTRA_PUBLIC_KEY to "PUBLIC-KEY-BASE64",
                Utils.EXTRA_SHARE_REQUEST_CODE to "req-7",
            ),
        )

        assertNotNull(result)
        assertEquals("PUBLIC-KEY-BASE64", result!!.publicKey)
        assertEquals("req-7", result.requestCode)
        assertEquals(2, result.fields.size)
        assertEquals("ada@example.com", result.fields["email"]?.value)
        assertEquals(FieldType.INTEGER, result.fields["age"]?.type)
    }

    @Test
    fun `a malformed query payload yields an empty map rather than null`() {
        val result = Utils.parseQueryResult(
            resultIntent(
                Utils.EXTRA_QUERY_RESULT_FIELDS to "[1,2,3]",
                Utils.EXTRA_SHARE_REQUEST_CODE to "req-7",
            ),
        )

        assertNotNull("the correlation token is still usable", result)
        assertTrue(result!!.fields.isEmpty())
        assertEquals("req-7", result.requestCode)
        assertNull(result.publicKey)
    }

    /**
     * "The vault disclosed nothing" and "the vault did not answer" are different outcomes,
     * and a client that shows the user a consent failure has to be able to tell them apart.
     */
    @Test
    fun `a query result carrying only a correlation token still comes back`() {
        val result = Utils.parseQueryResult(resultIntent(Utils.EXTRA_SHARE_REQUEST_CODE to "req-7"))

        assertNotNull(result)
        assertTrue(result!!.fields.isEmpty())
        assertEquals("req-7", result.requestCode)
    }

    /**
     * A blank extra reads as absent, not as an empty token. Otherwise a client comparing its
     * own request code against `""` could match a result it never asked for — the same
     * "nothing equals nothing" trap the correlation helper exists to prevent.
     */
    @Test
    fun `blank extras read as absent`() {
        val result = Utils.parseQueryResult(
            resultIntent(
                Utils.EXTRA_QUERY_RESULT_FIELDS to fieldsJson,
                Utils.EXTRA_PUBLIC_KEY to "   ",
                Utils.EXTRA_SHARE_REQUEST_CODE to "",
            ),
        )

        assertNotNull(result)
        assertNull(result!!.requestCode)
        assertNull(result.publicKey)
        assertEquals(2, result.fields.size)

        assertNull(
            "an envelope of nothing but blanks is not an answer",
            Utils.parseQueryResult(
                resultIntent(
                    Utils.EXTRA_QUERY_RESULT_FIELDS to "",
                    Utils.EXTRA_PUBLIC_KEY to "",
                    Utils.EXTRA_SHARE_REQUEST_CODE to "  ",
                ),
            ),
        )
    }

    @Test
    fun `a query result ignores extras belonging to other flows`() {
        val result = Utils.parseQueryResult(
            resultIntent(
                Utils.EXTRA_ENTRY_JSON to """{"id":"x","publicKey":"k","fields":{}}""",
                Utils.EXTRA_SIGNATURE to "c2ln",
            ),
        )

        assertNull("none of the query extras are present", result)
    }

    // ── Share results ────────────────────────────────────────────────────
    //
    // The acknowledgement half of the share flow. The extras below are the ones the vault's
    // ShareResultBuilder writes — EXTRA_PUBLIC_KEY, EXTRA_FIELDS_JSON via encodeFields, and
    // a conditional EXTRA_SHARE_REQUEST_CODE — so these tests pin the client half of a wire
    // surface that previously existed only as the vault's convention.

    @Test
    fun `a full share result is decoded`() {
        val result = Utils.parseShareResult(
            resultIntent(
                Utils.EXTRA_PUBLIC_KEY to "PUBLIC-KEY-BASE64",
                Utils.EXTRA_FIELDS_JSON to fieldsJson,
                Utils.EXTRA_SHARE_REQUEST_CODE to "req-5",
            ),
        )

        assertNotNull(result)
        assertEquals("PUBLIC-KEY-BASE64", result!!.publicKey)
        assertEquals("req-5", result.requestCode)
        assertEquals(2, result.fields.size)
        assertEquals("ada@example.com", result.fields["email"]?.value)
        assertEquals(FieldType.EMAIL, result.fields["email"]?.type)
        assertEquals("36", result.fields["age"]?.value)
        assertEquals(FieldType.INTEGER, result.fields["age"]?.type)
    }

    /**
     * The request-code extra is conditional on the vault side: it is echoed only when the
     * share was created with the overload that carried one. An untagged share's result must
     * still come back whole.
     */
    @Test
    fun `a share result without a request code still comes back`() {
        val result = Utils.parseShareResult(
            resultIntent(
                Utils.EXTRA_PUBLIC_KEY to "PUBLIC-KEY-BASE64",
                Utils.EXTRA_FIELDS_JSON to fieldsJson,
            ),
        )

        assertNotNull(result)
        assertNull(result!!.requestCode)
        assertEquals("PUBLIC-KEY-BASE64", result.publicKey)
        assertEquals(2, result.fields.size)
    }

    /**
     * Mirrors the sign-challenge rule for the same reason: the public key still stands on
     * its own, and discarding the whole acknowledgement because the field echo was garbled
     * would tell the client its share failed when it succeeded.
     */
    @Test
    fun `a malformed share fields payload yields an empty map rather than null`() {
        val result = Utils.parseShareResult(
            resultIntent(
                Utils.EXTRA_PUBLIC_KEY to "PUBLIC-KEY-BASE64",
                Utils.EXTRA_FIELDS_JSON to "{not json at all",
                Utils.EXTRA_SHARE_REQUEST_CODE to "req-5",
            ),
        )

        assertNotNull("the public key and correlation token are still usable", result)
        assertTrue(result!!.fields.isEmpty())
        assertEquals("PUBLIC-KEY-BASE64", result.publicKey)
        assertEquals("req-5", result.requestCode)
    }

    @Test
    fun `blank share extras read as absent`() {
        val result = Utils.parseShareResult(
            resultIntent(
                Utils.EXTRA_PUBLIC_KEY to "   ",
                Utils.EXTRA_FIELDS_JSON to fieldsJson,
                Utils.EXTRA_SHARE_REQUEST_CODE to "",
            ),
        )

        assertNotNull(result)
        assertNull(result!!.publicKey)
        assertNull(result.requestCode)
        assertEquals(2, result.fields.size)

        assertNull(
            "an envelope of nothing but blanks is not an answer",
            Utils.parseShareResult(
                resultIntent(
                    Utils.EXTRA_PUBLIC_KEY to "",
                    Utils.EXTRA_FIELDS_JSON to "  ",
                    Utils.EXTRA_SHARE_REQUEST_CODE to "",
                ),
            ),
        )
    }

    @Test
    fun `a share result ignores extras belonging to other flows`() {
        val result = Utils.parseShareResult(
            resultIntent(
                Utils.EXTRA_ENTRY_JSON to """{"id":"x","publicKey":"k","fields":{}}""",
                Utils.EXTRA_SIGNATURE to "c2ln",
                Utils.EXTRA_QUERY_RESULT_FIELDS to fieldsJson,
            ),
        )

        assertNull("none of the share extras are present", result)
    }

    @Test
    fun `hostile share field entries are repaired rather than handed on`() {
        val result = Utils.parseShareResult(
            resultIntent(
                Utils.EXTRA_PUBLIC_KEY to "PUBLIC-KEY-BASE64",
                Utils.EXTRA_FIELDS_JSON to """{"a":{"value":"x"},"b":null,"c":{"type":"Email"}}""",
            ),
        )!!

        assertNull("a null entry is dropped", result.fields["b"])
        result.fields.forEach { (key, field) ->
            assertNotNull("$key value", field.value)
            assertNotNull("$key type", field.type)
        }
        assertEquals(FieldType.STRING, result.fields["a"]?.type)
        assertEquals("", result.fields["c"]?.value)
    }
}
