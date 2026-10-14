package dev.eryalabs.lim

import android.content.Context
import android.content.Intent
import android.util.Base64
import androidx.test.core.app.ApplicationProvider
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
import java.util.TreeMap

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

    /**
     * Needed only by the request-overload section below, which builds its requests with the same
     * client-side builders an integrator uses rather than by hand — that is the whole point of
     * going through a round trip instead of constructing a [QueryRequest] directly.
     */
    private val context: Context = ApplicationProvider.getApplicationContext()

    /** A pushable entry for the share flow; [Utils.decodeEntry] refuses a blank identity. */
    private val entry = Entry("profile-1", fields, publicKey)

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

    // ── Answering a parsed request: the token, and nothing else ──────────
    //
    // T29's three overloads take a parsed request instead of a request-code string, so the one
    // extra that must survive both a refusal and an answer stops being a hand-written line a
    // vault can drop. The rule they publish is narrower than "answer the request": **the request
    // is read, never retained, and the only value taken off it is the correlation token.**
    //
    // Everything below is one of two claims. The central property is that a token minted by a
    // client survives LIM's own request builder, LIM's own request parser, the answer, and the
    // result parser — reached with `matchesRequestCode`, which is the function a client actually
    // uses to decide an answer is its own. The controls are the other half: that *nothing else*
    // came off the request, swept over every extra rather than only the one it would be expected
    // in, because the failure this shape prevents is a caller choosing the identifier that names
    // its own disclosure.

    /**
     * Every extra of [intent] whose value contains [needle] — the sweep, not a spot check.
     *
     * Line breaks are stripped from both sides before matching, because this protocol uses two
     * Base64 flavours: requests write `NO_WRAP` and results write `DEFAULT`, which wraps at 76
     * characters. Comparing the raw strings would make the sweep blind to a leak re-encoded on
     * the way out as soon as the payload outgrew one line — which is every signature.
     *
     * **Its remaining floor, stated rather than discovered later:** it reads values with
     * `getStringExtra`, so a leak written as a non-`String` extra would read back `null` and pass
     * this silently. Nothing in this protocol writes a non-string extra — every builder above
     * writes `String` only — and the equivalence control's exact key-set assertions are what
     * would catch one appearing. Widening this to walk the bundle by type would assert against a
     * shape the wire format does not have.
     */
    private fun extrasMentioning(intent: Intent, needle: String): List<String> {
        val flat = needle.replace("\n", "").replace("\r", "")
        return intent.extras!!.keySet().filter { key ->
            intent.getStringExtra(key)?.replace("\n", "")?.replace("\r", "")?.contains(flat) == true
        }
    }

    @Test
    fun `a parsed share request is answered with the token the client minted`() {
        val minted = "req-share-1"
        val request = Utils.parseShareRequest(
            Utils.createShareIntent(context, entry, requestCode = minted),
        )!!

        val result = Utils.createShareResultIntent(request, publicKey, fields)

        assertEquals(
            ShareResult(publicKey, fields, minted, 2),
            Utils.parseShareResult(result),
        )
        assertTrue(
            "the token the client minted must correlate the answer it gets back",
            Utils.matchesRequestCode(result, minted),
        )
    }

    @Test
    fun `a parsed query request is answered with the token the client minted`() {
        val minted = "req-query-1"
        val request = Utils.parseQueryRequest(
            Utils.createQueryIntent(context, "CALLER-CHOSEN-KEY-QUERY", minted),
        )!!

        val result = Utils.createQueryResultIntent(request, publicKey, fields)

        assertEquals(
            QueryResult(fields, publicKey, minted, 2),
            Utils.parseQueryResult(result),
        )
        assertTrue(Utils.matchesRequestCode(result, minted))
    }

    /**
     * **What the correlation half of this property cannot see, measured rather than assumed.**
     * Parse this answer back with `parseShareResult` instead and `matchesRequestCode` still says
     * `true`, because both flows carry the token under the same extra and the two results differ
     * only in which key the fields sit under. Nothing in *this* task reddens for that — the
     * cross-flow separation is T28's control (a), `a result built for one flow discloses no
     * fields to the other`, and it is the one place the two tasks' controls must not be expected
     * to overlap. The whole-value `assertEquals` and the `isVerified` check below are what make
     * this test about the sign-challenge flow rather than about any flow with a token in it.
     */
    @Test
    fun `a parsed sign-challenge request is answered with the token the client minted`() {
        val minted = "req-sign-1"
        val request = Utils.parseSignChallengeRequest(
            Utils.createSignChallengeIntent(
                context,
                publicKey,
                nonce,
                minted,
                nonceFormat = Utils.NONCE_FORMAT_TIMESTAMPED,
            ),
        )!!
        // Signed over the nonce the *parser* handed back, which is the only use a vault has for
        // it: the overload will not sign anything for you, because this library holds no key.
        val signature = sign(request.nonce)

        val result =
            Utils.createSignChallengeResultIntent(request, signature, fields, "SHA256withRSA")

        assertEquals(
            SignChallengeResult(signature, "SHA256withRSA", fields, minted, 2),
            Utils.parseSignChallengeResult(result),
        )
        assertTrue(Utils.matchesRequestCode(result, minted))
        assertTrue(
            "…and the proof is genuine, so the round trip is over a real signature rather than " +
                "an arbitrary byte array",
            Utils.parseSignChallengeResult(result)!!.isVerified(publicKey, nonce),
        )
    }

    // ── T29 control (a)+(c)+(d): the laundering control, and a codeless request ──

    /**
     * **The reason these overloads take `publicKey` explicitly.** A query request's `publicKey` is
     * the key the *caller* chose to ask about; echoing it automatically would let the caller pick
     * the identifier that appears in its own answer, and the key a result must name is the one the
     * vault holds. So a request naming `A`, answered with `B`, yields a result naming `B` — and
     * the string `A` appears under **no** extra of it, swept over every key rather than only
     * `extra_public_key`.
     *
     * The same loop carries control (c), because a codeless request is where the echo is easiest
     * to get wrong: `createQueryIntent` writes a blank request code as a present-but-blank extra,
     * `presentStringExtra` reads that as absent, so `QueryRequest.requestCode` is `null` and the
     * answer must carry **no** `extra_share_request_code` at all — `!hasExtra`, since
     * `putExtra(key, null as String?)` leaves a present extra reading null. And
     * `matchesRequestCode(result, "")` is `false`: "nothing equals nothing" is the mistake that
     * pairs an untagged request with the first result that happens to arrive.
     *
     * **That last assertion is weaker than it reads, and is recorded as such.** It holds on
     * `matchesRequestCode`'s `expected.isBlank()` short-circuit (`Utils.kt`) before the intent is
     * read at all, so it would pass against a bare `Intent()` too — it exercises the *caller's*
     * blank guard, not anything these builders do. It is here because it is the call a vault's
     * client reaches for when it has no token, and `RequestCodeTest` owns the function's actual
     * discrimination. What proves the builder's half is the `!hasExtra` line above it.
     *
     * Control (d) is the two counters: the loop must produce at least one answer that carries a
     * code and at least one that does not, or either arm alone is satisfiable by a builder that
     * echoes nothing.
     */
    @Test
    fun `an answer names the vault's key and never the one the caller asked about`() {
        val askedAbout = "CALLER-CHOSEN-KEY-LAUNDER"
        var carryingCode = 0
        var carryingNone = 0

        listOf("req-query-7", "", "   ").forEach { minted ->
            val request = Utils.parseQueryRequest(
                Utils.createQueryIntent(context, askedAbout, minted),
            )!!
            assertEquals(
                "the request really does name the caller's key, or this control sweeps for a " +
                    "string that was never in play",
                askedAbout,
                request.publicKey,
            )

            val result = Utils.createQueryResultIntent(request, publicKey, fields)
            val parsed = Utils.parseQueryResult(result)!!

            assertEquals(
                "the answer must name the key the vault holds, not the one it was asked about",
                publicKey,
                parsed.publicKey,
            )
            assertEquals(
                "the caller's chosen key must appear under no extra of the answer at all",
                emptyList<String>(),
                extrasMentioning(result, askedAbout),
            )
            assertEquals(
                "…and the disclosure itself is still there, so this is not satisfied by an " +
                    "empty answer",
                fields,
                parsed.fields,
            )

            if (minted.isBlank()) {
                assertNull(
                    "a blank request code reads as absent, so the request is codeless",
                    request.requestCode,
                )
                assertFalse(
                    "a codeless request's answer must carry no request-code extra at all, not a " +
                        "null one",
                    result.hasExtra("extra_share_request_code"),
                )
                assertNull(parsed.requestCode)
                assertFalse(
                    "nothing equals nothing: a blank never correlates, not even with a codeless " +
                        "answer",
                    Utils.matchesRequestCode(result, ""),
                )
                carryingNone++
            } else {
                assertEquals(minted, parsed.requestCode)
                assertTrue(Utils.matchesRequestCode(result, minted))
                carryingCode++
            }
        }

        // Control (d): either arm alone is satisfiable by a builder that echoes nothing.
        assertTrue("no answer carried a code, so the echo arm proves nothing", carryingCode > 0)
        assertTrue(
            "no answer was codeless, so the omission arm proves nothing",
            carryingNone > 0,
        )
    }

    /**
     * The same sweep for the other two flows, where the request carries more than a key: a share
     * request's entry has an `id`, a `publicKey` and field *names* of the caller's choosing, and a
     * sign-challenge request names a key too. None of it may reach the answer.
     *
     * Not folded into the loop above because the query flow is the one control (a) is *about* —
     * there the laundering would be invisible, since `QueryResult.publicKey` is exactly where a
     * reader expects the queried key to be.
     */
    @Test
    fun `nothing else from a request reaches the answer either`() {
        val callerEntry = Entry(
            "CALLER-ENTRY-ID",
            mapOf("caller_chosen_field" to TypedField("CALLER-VALUE", FieldType.STRING)),
            "CALLER-CHOSEN-KEY-SHARE",
        )
        val shareResult = Utils.createShareResultIntent(
            Utils.parseShareRequest(
                Utils.createShareIntent(context, callerEntry, requestCode = "req-share-2"),
            )!!,
            publicKey,
            fields,
        )
        listOf(
            "CALLER-ENTRY-ID",
            "CALLER-CHOSEN-KEY-SHARE",
            "caller_chosen_field",
            "CALLER-VALUE",
        ).forEach { needle ->
            assertEquals(
                "a share answer must carry nothing off the request but its token; found $needle",
                emptyList<String>(),
                extrasMentioning(shareResult, needle),
            )
        }
        assertTrue(Utils.matchesRequestCode(shareResult, "req-share-2"))
        assertEquals(publicKey, Utils.parseShareResult(shareResult)!!.publicKey)

        val signRequest = Utils.parseSignChallengeRequest(
            Utils.createSignChallengeIntent(
                context,
                "CALLER-CHOSEN-KEY-SIGN",
                nonce,
                "req-sign-2",
                nonceFormat = Utils.NONCE_FORMAT_TIMESTAMPED,
            ),
        )!!
        val signResult =
            Utils.createSignChallengeResultIntent(signRequest, sign(nonce), fields)
        listOf(
            "CALLER-CHOSEN-KEY-SIGN",
            // NO_WRAP, which is what `createSignChallengeIntent` writes — and the sweep strips
            // line breaks from both sides, so this needle also finds a leak re-encoded with
            // `Base64.DEFAULT`, the wrapping flavour every result extra uses. Matching on one
            // encoding only would go blind the moment a leaked payload outgrew a single line.
            Base64.encodeToString(nonce, Base64.NO_WRAP),
            Utils.NONCE_FORMAT_TIMESTAMPED,
        ).forEach { needle ->
            assertEquals(
                "a sign-challenge answer must carry nothing off the request but its token; " +
                    "found $needle",
                emptyList<String>(),
                extrasMentioning(signResult, needle),
            )
        }
        assertTrue(Utils.matchesRequestCode(signResult, "req-sign-2"))
    }

    /**
     * Control (c) for the other two flows, because the codeless path is where the overloads'
     * delegation is easiest to get wrong and the loop above only walks the query one.
     *
     * The three delegations are character-for-character identical and `putPresentExtra` collapses
     * `null` and blank alike, so this is cheap rather than deep — but "cheap" is not "covered",
     * and a vault that answers a legacy untagged share is the client population this protocol
     * cannot drop.
     */
    @Test
    fun `a codeless share or sign-challenge request is answered without an echo`() {
        val shareResult = Utils.createShareResultIntent(
            Utils.parseShareRequest(Utils.createShareIntent(context, entry, requestCode = ""))!!,
            publicKey,
            fields,
        )
        assertFalse(
            "a codeless share request's answer must carry no request-code extra at all",
            shareResult.hasExtra("extra_share_request_code"),
        )
        // Weak for the reason the laundering control above records in full: this holds on
        // `matchesRequestCode`'s own blank guard, not on anything the builder did. The `!hasExtra`
        // line above and the whole-value assertion below are the load-bearing ones.
        assertFalse(Utils.matchesRequestCode(shareResult, ""))
        assertEquals(
            "…and the acknowledgement is otherwise complete",
            ShareResult(publicKey, fields, null, 2),
            Utils.parseShareResult(shareResult),
        )

        val signature = sign(nonce)
        val signResult = Utils.createSignChallengeResultIntent(
            Utils.parseSignChallengeRequest(
                Utils.createSignChallengeIntent(context, publicKey, nonce, "   "),
            )!!,
            signature,
            fields,
        )
        assertFalse(signResult.hasExtra("extra_share_request_code"))
        // Same caller-side blank guard, same caveat.
        assertFalse(Utils.matchesRequestCode(signResult, ""))
        assertEquals(
            SignChallengeResult(signature, null, fields, null, 2),
            Utils.parseSignChallengeResult(signResult),
        )
    }

    // ── T29 control (b): equivalence, not a second wire format ───────────

    /**
     * The request overload and the string one must produce the **same** result — equal parsed
     * objects *and* an identical set of present extra keys. A convenience that quietly wrote a
     * different envelope would be a second wire format, which is the one thing a delegating
     * overload must not become.
     *
     * The key sets are spelled as literals here rather than read off `Utils`: `DESCRIBED_EXTRAS`
     * is private and `describeIntent`'s wording is explicitly not API, and an assertion written
     * against a constant would move with a rename instead of catching it — `IntentBuilderTest`'s
     * rule, applied to a key *set*.
     */
    @Test
    fun `the request overload writes the same wire as the string one`() {
        val shareRequest = Utils.parseShareRequest(
            Utils.createShareIntent(context, entry, requestCode = "req-share-3"),
        )!!
        val queryRequest = Utils.parseQueryRequest(
            Utils.createQueryIntent(context, "CALLER-CHOSEN-KEY-EQUIV", "req-query-3"),
        )!!
        val signRequest = Utils.parseSignChallengeRequest(
            Utils.createSignChallengeIntent(context, publicKey, nonce, "req-sign-3"),
        )!!
        val signature = sign(nonce)

        val share = Utils.createShareResultIntent(shareRequest, publicKey, fields) to
            Utils.createShareResultIntent(publicKey, fields, shareRequest.requestCode)
        assertEquals(
            Utils.parseShareResult(share.second),
            Utils.parseShareResult(share.first),
        )
        val shareKeys = setOf(
            "extra_public_key",
            "extra_fields_json",
            "extra_share_request_code",
            "extra_protocol_version",
        )
        assertEquals(shareKeys, share.first.extras!!.keySet())
        assertEquals(shareKeys, share.second.extras!!.keySet())

        val query = Utils.createQueryResultIntent(queryRequest, publicKey, fields) to
            Utils.createQueryResultIntent(publicKey, fields, queryRequest.requestCode)
        assertEquals(
            Utils.parseQueryResult(query.second),
            Utils.parseQueryResult(query.first),
        )
        val queryKeys = setOf(
            "extra_public_key",
            "extra_query_result_fields",
            "extra_share_request_code",
            "extra_protocol_version",
        )
        assertEquals(queryKeys, query.first.extras!!.keySet())
        assertEquals(queryKeys, query.second.extras!!.keySet())

        val sign = Utils.createSignChallengeResultIntent(
            signRequest,
            signature,
            fields,
            "SHA256withRSA",
        ) to Utils.createSignChallengeResultIntent(
            signature,
            fields,
            signRequest.requestCode,
            "SHA256withRSA",
        )
        assertEquals(
            Utils.parseSignChallengeResult(sign.second),
            Utils.parseSignChallengeResult(sign.first),
        )
        val signKeys = setOf(
            "extra_signature",
            "extra_algorithm",
            "extra_fields_json",
            "extra_share_request_code",
            "extra_protocol_version",
        )
        assertEquals(signKeys, sign.first.extras!!.keySet())
        assertEquals(signKeys, sign.second.extras!!.keySet())
    }

    // ── The requirements-aware share result ─────────────────────────────

    /** `email` required, `age` optional — the class fixture's two fields. */
    private val requirements = FieldRequirements(fields.keys, setOf("age"))

    /**
     * The four 1.0.0 extras exactly as the three-argument builder writes them, plus the
     * acknowledgement naming the applied set — and nothing else.
     */
    @Test
    fun `the requirements-aware share result writes the 1_0_0 extras plus the acknowledgement`() {
        val intent = Utils.createShareResultIntent(publicKey, fields, "req-5", requirements)
        val plain = Utils.createShareResultIntent(publicKey, fields, "req-5")

        assertEquals("""["age"]""", intent.getStringExtra("extra_applied_optional_fields"))
        assertEquals(plain.extras!!.keySet() + "extra_applied_optional_fields", intent.extras!!.keySet())
        plain.extras!!.keySet().forEach { key ->
            assertEquals("extra $key", plain.getStringExtra(key), intent.getStringExtra(key))
        }
        assertEquals("2", intent.getStringExtra("extra_protocol_version"))
        assertEquals(
            "nothing optional is acknowledged as the empty array, not omitted",
            "[]",
            Utils.createShareResultIntent(publicKey, fields, "req-5", FieldRequirements(fields.keys))
                .getStringExtra("extra_applied_optional_fields"),
        )
        assertEquals(
            "a null request code attaches nothing, as on the sibling",
            false,
            Utils.createShareResultIntent(publicKey, fields, null, requirements).hasExtra("extra_share_request_code"),
        )
    }

    /**
     * Over a payload that does not satisfy the requirements the acknowledgement is omitted, never
     * thrown and never written — so a buggy vault degrades to an older vault's answer instead of a
     * false claim.
     */
    @Test
    fun `no acknowledgement is written over a payload that does not satisfy the requirements`() {
        val missingRequired = linkedMapOf("age" to TypedField("36", FieldType.INTEGER))
        val blankRequired = linkedMapOf(
            "email" to TypedField("  ", FieldType.EMAIL),
            "age" to TypedField("36", FieldType.INTEGER),
        )
        val blankOptionalKept = fields + ("age" to TypedField("", FieldType.INTEGER))

        for ((case, payload) in listOf(
            "a required field missing" to missingRequired,
            "a required field blank" to blankRequired,
            "a blank optional field not dropped" to blankOptionalKept,
        )) {
            val intent = Utils.createShareResultIntent(publicKey, payload, "req-5", requirements)
            assertFalse("$case: no acknowledgement", intent.hasExtra("extra_applied_optional_fields"))
            assertEquals(
                "$case: the rest is the sibling's answer exactly",
                Utils.createShareResultIntent(publicKey, payload, "req-5").extras!!.keySet(),
                intent.extras!!.keySet(),
            )
        }
    }

    /**
     * The old-client differential: whatever the requirements, a 1.0.0 client's parse of the new
     * builder's answer is its parse of the three-argument builder's.
     */
    @Test
    fun `an old client parses the requirements-aware answer exactly as the 1_0_0 one`() {
        for (declared in listOf(requirements, FieldRequirements(fields.keys), FieldRequirements(listOf("missing")))) {
            assertEquals(
                Utils.parseShareResult(Utils.createShareResultIntent(publicKey, fields, "req-5")),
                Utils.parseShareResult(Utils.createShareResultIntent(publicKey, fields, "req-5", declared)),
            )
        }
    }

    /**
     * The payload is checked by the keys it will be encoded under, not by the map's own lookup. A
     * case-insensitive map holding `EMAIL` answers for `email`, but it is encoded as `"EMAIL"`, so
     * the client looking up `email` finds nothing — an acknowledgement over it would make the
     * client read the answer as `VIOLATED` and blame the vault. None is written, and the client
     * reads `INCOMPLETE`, as it would for any answer missing a required field.
     */
    @Test
    fun `a case-insensitive payload whose keys lack a required field is not acknowledged`() {
        val draft = TreeMap<String, TypedField>(String.CASE_INSENSITIVE_ORDER).apply {
            put("EMAIL", TypedField("ada@example.com", FieldType.EMAIL))
            put("age", TypedField("36", FieldType.INTEGER))
        }
        assertTrue("precondition: the map answers for email by itself", draft.containsKey("email"))

        val intent = Utils.createShareResultIntent(publicKey, draft, "req-5", requirements)

        assertFalse("no acknowledgement", intent.hasExtra("extra_applied_optional_fields"))
        assertEquals(setOf("EMAIL", "age"), Utils.parseShareResult(intent)!!.fields.keys)
        assertEquals(FieldRequirementsVerdict.INCOMPLETE, Utils.checkFieldRequirements(requirements, intent))
    }
}
