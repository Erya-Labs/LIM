package dev.eryalabs.lim

import android.content.Intent
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
 * The half of the wire format this library had never written.
 *
 * `IntentBuilderTest` pins the three *request* intents a client sends; `ResultParsingTest` pins
 * what a *result* means when it arrives. Between them sat a gap: of the ten extras this protocol
 * defines, `Utils` wrote six and merely read the other four — `extra_query_result_fields`,
 * `extra_fields_json`, `extra_signature` and `extra_algorithm` existed here as four parsers'
 * expectations and nothing else, so every vault hand-assembled its result intents and the
 * reference vault grew its own builder to do it. This file is the builders' side of that half,
 * and two of the keys below have never been written by a published function before.
 *
 * Pinned to **literals**, not to the `Utils` constants — `IntentBuilderTest`'s own rule and the
 * reason it exists: a constant renamed or re-valued must not be able to quietly rename the wire
 * format, and an assertion written against the constant would move with it.
 *
 * The central property is not "the extras are there" but **build → parse returns the result the
 * vault meant**, asserted as the whole `ShareResult` / `QueryResult` / `SignChallengeResult`
 * value — they are data classes, and `SignChallengeResult` compares its signature by content
 * (`SignChallengeResult.kt:55-63`) — including `vaultProtocolVersion == 2`, which is the echo a
 * hand-written vault forgets and a client then reads as a legacy vault.
 *
 * Robolectric is required: [Intent] extras and `android.util.Base64` are unimplemented stubs in a
 * plain JVM unit test. One 2048-bit keypair is generated for the whole class, for the one control
 * that needs a genuine signature, and it dominates this file's runtime.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ResultBuilderTest {

    companion object {
        private lateinit var keyPair: KeyPair

        /**
         * One keygen for the whole class, the `ResultParsingTest` idiom. Only
         * `a declared algorithm changes no verification outcome` needs it — but it needs a
         * *genuine* `SHA256withRSA` signature, and a control that cannot produce one proves
         * nothing about the algorithm-confusion boundary it exists to pin.
         */
        @JvmStatic
        @BeforeClass
        fun generateKey() {
            keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        }
    }

    /** Safe as an instance initializer: `@BeforeClass` runs before JUnit constructs the class. */
    private val publicKey: String = Base64.encodeToString(keyPair.public.encoded, Base64.DEFAULT)

    private val nonce = Utils.generateNonce(now = 1_770_000_000_000L)

    private fun sign(data: ByteArray): ByteArray = Signature.getInstance("SHA256withRSA").run {
        initSign(keyPair.private)
        update(data)
        sign()
    }

    private val fields = linkedMapOf(
        "email" to TypedField("ada@example.com", FieldType.EMAIL),
        "age" to TypedField("36", FieldType.INTEGER),
    )

    /**
     * The payload the builders are expected to write, by the function they are expected to write
     * it with. Deliberately not a frozen JSON literal: `FieldsCodecTest` owns the encoding's
     * shape, and a second copy of it here would be a copy that drifts. What this file pins is
     * *which key* the payload lands under and that it round-trips.
     */
    private val fieldsJson = Utils.encodeFields(fields)

    // ── The wire, as literals ────────────────────────────────────────────

    /**
     * Every extra each builder writes, under the literal key a vault's reader matches on, and —
     * the other half of the same claim — **nothing else**. The key set is asserted whole, so a
     * stray write (a public key echoed into a sign-challenge result, say) fails here rather than
     * going unnoticed because no assertion asked about it.
     */
    @Test
    fun `the share result writes its flow's literals and nothing else`() {
        val intent = Utils.createShareResultIntent(publicKey, fields, "req-5")

        assertEquals(publicKey, intent.getStringExtra("extra_public_key"))
        assertEquals(fieldsJson, intent.getStringExtra("extra_fields_json"))
        assertEquals("req-5", intent.getStringExtra("extra_share_request_code"))
        assertEquals("2", intent.getStringExtra("extra_protocol_version"))
        assertEquals(
            setOf(
                "extra_public_key",
                "extra_fields_json",
                "extra_share_request_code",
                "extra_protocol_version",
            ),
            intent.extras!!.keySet(),
        )
    }

    @Test
    fun `the query result writes its flow's literals and nothing else`() {
        val intent = Utils.createQueryResultIntent(publicKey, fields, "req-7")

        assertEquals(publicKey, intent.getStringExtra("extra_public_key"))
        assertEquals(fieldsJson, intent.getStringExtra("extra_query_result_fields"))
        assertEquals("req-7", intent.getStringExtra("extra_share_request_code"))
        assertEquals("2", intent.getStringExtra("extra_protocol_version"))
        assertEquals(
            setOf(
                "extra_public_key",
                "extra_query_result_fields",
                "extra_share_request_code",
                "extra_protocol_version",
            ),
            intent.extras!!.keySet(),
        )
    }

    /**
     * `extra_signature` and `extra_algorithm` are the two keys no published function in this
     * library has ever written, which is what this task is really about.
     */
    @Test
    fun `the sign-challenge result writes its flow's literals and nothing else`() {
        val signature = sign(nonce)
        val intent = Utils.createSignChallengeResultIntent(
            signature,
            fields,
            requestCode = "req-9",
            algorithm = "SHA256withRSA",
        )

        val encoded = intent.getStringExtra("extra_signature")!!
        assertTrue(
            "the signature must survive Base64 intact",
            signature.contentEquals(Base64.decode(encoded, Base64.DEFAULT)),
        )
        assertTrue(
            "DEFAULT, not NO_WRAP: a 2048-bit signature wraps, and that is what the parser " +
                "documents arriving",
            encoded.contains("\n"),
        )
        assertEquals("SHA256withRSA", intent.getStringExtra("extra_algorithm"))
        assertEquals(fieldsJson, intent.getStringExtra("extra_fields_json"))
        assertEquals("req-9", intent.getStringExtra("extra_share_request_code"))
        assertEquals("2", intent.getStringExtra("extra_protocol_version"))
        assertEquals(
            setOf(
                "extra_signature",
                "extra_algorithm",
                "extra_fields_json",
                "extra_share_request_code",
                "extra_protocol_version",
            ),
            intent.extras!!.keySet(),
        )
    }

    /**
     * A result is `setResult`'s payload, not something the system has to route: both parsers'
     * flows work off extras alone and **no parser here reads the action**
     * (`Utils.kt`'s `describeIntent` says so of the whole protocol). An action or a package on a
     * result would therefore be new wire surface with no reader — and a plausible thing for a
     * later change to add "for symmetry".
     */
    @Test
    fun `a result intent carries no action and no package`() {
        val results = listOf(
            Utils.createShareResultIntent(publicKey, fields, "req-5"),
            Utils.createQueryResultIntent(publicKey, fields, "req-7"),
            Utils.createSignChallengeResultIntent(sign(nonce), fields, "req-9", "SHA256withRSA"),
        )

        results.forEach { intent ->
            assertNull("a result declares no action", intent.action)
            assertNull("a result names no package", intent.`package`)
            assertEquals("a result sets no flags", 0, intent.flags)
        }
    }

    // ── The central property: build → parse is what the vault meant ──────

    @Test
    fun `a built share result parses back as the result the vault meant`() {
        val intent = Utils.createShareResultIntent(publicKey, fields, "req-5")

        assertEquals(
            ShareResult(
                publicKey = publicKey,
                fields = fields,
                requestCode = "req-5",
                vaultProtocolVersion = 2,
            ),
            Utils.parseShareResult(intent),
        )
    }

    @Test
    fun `a built query result parses back as the result the vault meant`() {
        val intent = Utils.createQueryResultIntent(publicKey, fields, "req-7")

        assertEquals(
            QueryResult(
                fields = fields,
                publicKey = publicKey,
                requestCode = "req-7",
                vaultProtocolVersion = 2,
            ),
            Utils.parseQueryResult(intent),
        )
    }

    @Test
    fun `a built sign-challenge result parses back as the result the vault meant`() {
        val signature = sign(nonce)
        val intent = Utils.createSignChallengeResultIntent(
            signature,
            fields,
            requestCode = "req-9",
            algorithm = "SHA256withRSA",
        )

        assertEquals(
            SignChallengeResult(
                signature = signature,
                algorithm = "SHA256withRSA",
                fields = fields,
                requestCode = "req-9",
                vaultProtocolVersion = 2,
            ),
            Utils.parseSignChallengeResult(intent),
        )
    }

    /**
     * "Nothing disclosed" and "the vault did not answer" are different outcomes, so the field
     * payload is written even for an empty map — `encodeFields(emptyMap())` is `"{}"`, which
     * reads back as an empty map rather than as an absent payload. This is the rule
     * `parseQueryResult`'s KDoc already states from the parser's side, reached from the builder's.
     */
    @Test
    fun `an empty fields map is still an answer`() {
        val query = Utils.createQueryResultIntent(publicKey)
        assertEquals("{}", query.getStringExtra("extra_query_result_fields"))
        assertEquals(
            QueryResult(emptyMap(), publicKey, null, 2),
            Utils.parseQueryResult(query),
        )

        val share = Utils.createShareResultIntent(publicKey)
        assertEquals("{}", share.getStringExtra("extra_fields_json"))
        assertEquals(ShareResult(publicKey, emptyMap(), null, 2), Utils.parseShareResult(share))

        val signature = sign(nonce)
        val signChallenge = Utils.createSignChallengeResultIntent(signature)
        assertEquals("{}", signChallenge.getStringExtra("extra_fields_json"))
        assertEquals(
            SignChallengeResult(signature, null, emptyMap(), null, 2),
            Utils.parseSignChallengeResult(signChallenge),
        )
    }

    // ── Negative control (a): cross-flow key separation, from this side ──

    /**
     * The control for the single most likely implementation error, and the one no round trip
     * against a builder's *own* parser can see: the two field payloads sit under different keys,
     * so a query result read by `parseShareResult` discloses **nothing**, and a share result read
     * by `parseQueryResult` likewise.
     *
     * This is the mirror of `ResultParsingTest`'s `each parser reads only its own fields key`,
     * which pins the parser side over hand-built intents and must pass unmodified. Point
     * `createQueryResultIntent` at `extra_fields_json` and this test and the query round trip both
     * redden; the parser-side test stays green, which is why both halves have to exist.
     */
    @Test
    fun `a result built for one flow discloses no fields to the other`() {
        val asShare = Utils.parseShareResult(
            Utils.createQueryResultIntent(publicKey, fields, "req-7"),
        )!!
        assertTrue(
            "the share parser must not read the query flow's fields key",
            asShare.fields.isEmpty(),
        )
        assertEquals("…though the rest of the envelope is still readable", publicKey, asShare.publicKey)

        val asQuery = Utils.parseQueryResult(
            Utils.createShareResultIntent(publicKey, fields, "req-5"),
        )!!
        assertTrue(
            "the query parser must not read the share flow's fields key",
            asQuery.fields.isEmpty(),
        )
        assertEquals(publicKey, asQuery.publicKey)
    }

    // ── Negative control (b): no envelope its own parser refuses ─────────

    /**
     * For every builder and every combination of present and absent optional arguments, the
     * matching parser returns non-null. A builder that can mint an intent its own parser throws
     * away is a worse trap than no builder at all, and the empty-map case is exactly where that
     * would bite: it is the envelope with the least in it.
     *
     * **One measured exception, asserted below rather than glossed:** an empty `signature`
     * Base64-encodes to nothing, reads back as a blank extra, and `parseSignChallengeResult`
     * refuses the whole intent — a signature over zero bytes could never authenticate anything.
     *
     * This control only means something because the parsers can still say no.
     * `ProtocolVersionTest`'s `a version alone is still an empty envelope` pins the hand-built
     * bare-plus-version intent at `null` for all three parsers and must pass unmodified; it is
     * cited here rather than re-added.
     */
    @Test
    fun `no built envelope is refused by its own parser`() {
        val signature = sign(nonce)
        val envelopes: List<Pair<String, Any?>> = listOf(
            "share(key)" to Utils.parseShareResult(Utils.createShareResultIntent(publicKey)),
            "share(key, fields)" to
                Utils.parseShareResult(Utils.createShareResultIntent(publicKey, fields)),
            "share(key, requestCode)" to Utils.parseShareResult(
                Utils.createShareResultIntent(publicKey, requestCode = "req-5"),
            ),
            "share(key, fields, requestCode)" to Utils.parseShareResult(
                Utils.createShareResultIntent(publicKey, fields, "req-5"),
            ),
            "query(key)" to Utils.parseQueryResult(Utils.createQueryResultIntent(publicKey)),
            "query(key, fields)" to
                Utils.parseQueryResult(Utils.createQueryResultIntent(publicKey, fields)),
            "query(key, requestCode)" to Utils.parseQueryResult(
                Utils.createQueryResultIntent(publicKey, requestCode = "req-7"),
            ),
            "query(key, fields, requestCode)" to Utils.parseQueryResult(
                Utils.createQueryResultIntent(publicKey, fields, "req-7"),
            ),
            "sign(sig)" to Utils.parseSignChallengeResult(
                Utils.createSignChallengeResultIntent(signature),
            ),
            "sign(sig, fields)" to Utils.parseSignChallengeResult(
                Utils.createSignChallengeResultIntent(signature, fields),
            ),
            "sign(sig, requestCode)" to Utils.parseSignChallengeResult(
                Utils.createSignChallengeResultIntent(signature, requestCode = "req-9"),
            ),
            "sign(sig, algorithm)" to Utils.parseSignChallengeResult(
                Utils.createSignChallengeResultIntent(signature, algorithm = "SHA256withRSA"),
            ),
            "sign(sig, fields, requestCode)" to Utils.parseSignChallengeResult(
                Utils.createSignChallengeResultIntent(signature, fields, "req-9"),
            ),
            "sign(sig, fields, algorithm)" to Utils.parseSignChallengeResult(
                Utils.createSignChallengeResultIntent(signature, fields, algorithm = "SHA256withRSA"),
            ),
            "sign(sig, requestCode, algorithm)" to Utils.parseSignChallengeResult(
                Utils.createSignChallengeResultIntent(
                    signature,
                    requestCode = "req-9",
                    algorithm = "SHA256withRSA",
                ),
            ),
            "sign(sig, fields, requestCode, algorithm)" to Utils.parseSignChallengeResult(
                Utils.createSignChallengeResultIntent(signature, fields, "req-9", "SHA256withRSA"),
            ),
        )

        assertEquals(
            "every combination of optional arguments must parse; a refused envelope means the " +
                "builder and its own parser disagree",
            emptyList<String>(),
            envelopes.filter { (_, parsed) -> parsed == null }.map { (name, _) -> name },
        )
        // Non-vacuity: a `filter` over an empty table is also empty.
        assertEquals("every optional-argument combination must be enumerated", 16, envelopes.size)
    }

    /** The one exception, measured: an empty byte array is not a signature. */
    @Test
    fun `an empty signature is not a signature`() {
        val intent = Utils.createSignChallengeResultIntent(ByteArray(0))

        assertTrue(
            "an empty signature encodes to nothing and reads as blank",
            intent.getStringExtra("extra_signature").isNullOrBlank(),
        )
        assertNull(
            "the parser refuses an envelope whose signature could never authenticate anything",
            Utils.parseSignChallengeResult(intent),
        )
    }

    // ── Negative control (d): the echo is the detectability signal ───────

    /**
     * One mechanism, two answers: a built result reports version 2, and the *same extras*
     * hand-written without the echo report `null` — a legacy vault, with nothing anywhere to fail.
     * That is the shape `ProtocolVersionTest`'s `a legacy result with no version extra parses as
     * before with a null version` pins from the parser side, reached here from the builder's,
     * and it is the whole reason these functions attach the version unconditionally.
     */
    @Test
    fun `a built result declares the version a hand-written one forgets`() {
        val built = Utils.parseShareResult(Utils.createShareResultIntent(publicKey, fields, "req-5"))!!
        assertEquals(2, built.vaultProtocolVersion)

        val handWritten = Utils.parseShareResult(
            Intent().apply {
                putExtra("extra_public_key", publicKey)
                putExtra("extra_fields_json", fieldsJson)
                putExtra("extra_share_request_code", "req-5")
            },
        )!!
        assertNull("the forgotten echo reads as a legacy vault", handWritten.vaultProtocolVersion)
        assertEquals(
            "…and the two are otherwise the same result, so the version is the only difference",
            built,
            handWritten.copy(vaultProtocolVersion = 2),
        )
    }

    // ── Negative control (e): blank collapses to absent ──────────────────

    /**
     * `presentStringExtra` maps blank to absent, so a builder that wrote a blank would mint an
     * intent its own parser disagrees with. **Omission means not calling `putExtra` at all:**
     * `putExtra(key, null as String?)` stores a null and leaves `hasExtra` returning `true`, so
     * these assertions are spelled `!hasExtra(…)` — `getStringExtra(…) == null` would pass
     * against the broken implementation too.
     */
    @Test
    fun `a blank request code is omitted rather than written`() {
        listOf("", "   ").forEach { blank ->
            val share = Utils.createShareResultIntent(publicKey, fields, blank)
            assertFalse(
                "a blank request code must leave no extra at all, not a null one",
                share.hasExtra("extra_share_request_code"),
            )
            assertFalse(
                "matchesRequestCode must not correlate a blank with a blank",
                Utils.matchesRequestCode(share, blank),
            )
            assertNull(Utils.parseShareResult(share)!!.requestCode)
            // Not a hollow intent: the flow's own extras are still there, so "carries no request
            // code" cannot be satisfied by a builder that wrote nothing.
            assertEquals(publicKey, Utils.parseShareResult(share)!!.publicKey)
            assertEquals(fields, Utils.parseShareResult(share)!!.fields)

            val query = Utils.createQueryResultIntent(publicKey, fields, blank)
            assertFalse(query.hasExtra("extra_share_request_code"))
            assertEquals(fields, Utils.parseQueryResult(query)!!.fields)

            val signChallenge =
                Utils.createSignChallengeResultIntent(sign(nonce), fields, blank, blank)
            assertFalse(signChallenge.hasExtra("extra_share_request_code"))
            assertFalse(
                "a blank algorithm is undeclared, not declared blank",
                signChallenge.hasExtra("extra_algorithm"),
            )
            assertEquals(fields, Utils.parseSignChallengeResult(signChallenge)!!.fields)
        }
    }

    @Test
    fun `a blank public key is omitted rather than written`() {
        val share = Utils.createShareResultIntent("   ", fields, "req-5")
        assertFalse(share.hasExtra("extra_public_key"))
        assertNotNull("the rest of the envelope still parses", Utils.parseShareResult(share))
        assertNull(Utils.parseShareResult(share)!!.publicKey)
        assertEquals(fields, Utils.parseShareResult(share)!!.fields)

        val query = Utils.createQueryResultIntent("", fields, "req-7")
        assertFalse(query.hasExtra("extra_public_key"))
        assertNull(Utils.parseQueryResult(query)!!.publicKey)
        assertEquals(fields, Utils.parseQueryResult(query)!!.fields)
    }

    /** An absent optional is absent, not a stored null — the same trap, stated as a key set. */
    @Test
    fun `an absent optional leaves no extra behind`() {
        val share = Utils.createShareResultIntent(publicKey)
        assertFalse(share.hasExtra("extra_share_request_code"))
        assertEquals(
            setOf("extra_public_key", "extra_fields_json", "extra_protocol_version"),
            share.extras!!.keySet(),
        )

        val query = Utils.createQueryResultIntent(publicKey)
        assertFalse(query.hasExtra("extra_share_request_code"))
        assertEquals(
            setOf("extra_public_key", "extra_query_result_fields", "extra_protocol_version"),
            query.extras!!.keySet(),
        )

        val signChallenge = Utils.createSignChallengeResultIntent(sign(nonce))
        assertFalse(signChallenge.hasExtra("extra_share_request_code"))
        assertFalse(signChallenge.hasExtra("extra_algorithm"))
        assertEquals(
            setOf("extra_signature", "extra_fields_json", "extra_protocol_version"),
            signChallenge.extras!!.keySet(),
        )
    }

    // ── Negative control (f): the algorithm declaration decides nothing ──

    /**
     * The algorithm-confusion boundary, pinned from the builder side — the half the standing
     * blocked item about honouring `extra_algorithm` does not cover.
     *
     * [Utils.verifySignature] hardcodes `SHA256withRSA`, so a result built declaring
     * `"MD5withRSA"` over a **genuine** signature still verifies `true`, and one declaring the
     * correct algorithm over a **tampered** signature still returns `false`. The declaration is
     * informational in both directions; a client that reads it and branches on it is the attack
     * this is here to keep visible.
     *
     * What this does *not* prove, stated plainly: that the parameter influences nothing at all.
     * Defaulting `algorithm` to `"SHA256withRSA"` would change no verification outcome anywhere
     * and would leave this control green — it is the honest limit of a test that can only observe
     * the two answers the verifier gives.
     */
    @Test
    fun `a declared algorithm changes no verification outcome`() {
        val genuine = sign(nonce)
        val misdeclared = Utils.parseSignChallengeResult(
            Utils.createSignChallengeResultIntent(genuine, fields, "req-9", "MD5withRSA"),
        )!!
        assertEquals("MD5withRSA", misdeclared.algorithm)
        assertTrue(
            "a genuine signature verifies whatever the vault declared it was made with",
            misdeclared.isVerified(publicKey, nonce),
        )

        val tampered = genuine.copyOf().also { it[0] = (it[0] + 1).toByte() }
        val welldeclared = Utils.parseSignChallengeResult(
            Utils.createSignChallengeResultIntent(tampered, fields, "req-9", "SHA256withRSA"),
        )!!
        assertEquals("SHA256withRSA", welldeclared.algorithm)
        assertFalse(
            "and a correct declaration buys a tampered signature nothing",
            welldeclared.isVerified(publicKey, nonce),
        )
    }
}
