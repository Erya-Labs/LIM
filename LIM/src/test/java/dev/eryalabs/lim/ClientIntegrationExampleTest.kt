package dev.eryalabs.lim

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
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
 * The three original flows as one runnable example — sign-up, query and login, in the order an
 * integrator meets them — and the fourth thing every integration has to handle: the user saying
 * no.
 *
 * `RequestParsingTest` and `ResultParsingTest` already pin each builder and each parser
 * field-for-field, and this file deliberately does not repeat them. Its subject is the
 * **sequence**: mint a nonce, correlate a request code, verify against the key you already hold.
 * That order is what an afternoon integration gets wrong, and a paragraph describing it goes
 * stale the moment the API moves — so it is written as a test instead, the same reason
 * `MigrationEndToEndTest` exists for the migration flow.
 *
 * Referenced from the KDoc of the client-side builders — [Utils.createShareIntent] (both
 * overloads), [Utils.createQueryIntent], [Utils.createSignChallengeIntent] — and from the
 * vault-side ones its own fixture vault answers with: [Utils.createShareResultIntent],
 * [Utils.createQueryResultIntent] and [Utils.createSignChallengeResultIntent], each in the
 * request-taking overload. The reference runs both directions, which is the point: the one
 * runnable example of a vault answering a request must not teach hand-written extras.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ClientIntegrationExampleTest {

    private val context = ApplicationProvider.getApplicationContext<Context>()

    /** What the user has typed into the vault's own form. The client never supplies a value. */
    private val profile = linkedMapOf(
        "name" to TypedField(SENTINEL_NAME, FieldType.STRING),
        "email" to TypedField(SHARED_EMAIL, FieldType.EMAIL),
    )

    /** A second person who happens to use the same email address. See the test that uses it. */
    private val otherProfile = linkedMapOf(
        "name" to TypedField("Grace", FieldType.STRING),
        "email" to TypedField(SHARED_EMAIL, FieldType.EMAIL),
    )

    /** What `onActivityResult` hands a client back: a result code and, perhaps, some data. */
    private class VaultAnswer(val resultCode: Int, val data: Intent?)

    /**
     * A service as an integrator would write one: **accounts keyed by the public key**, and
     * nothing about the user held that a disclosure did not give it.
     *
     * VISION fixes the rule, and this is the file somebody copies, so it is worth stating plainly:
     * *a service must never link an account to a disclosed field such as email; the public key is
     * the account identifier.* An email address is the user's data and not the service's handle on
     * them — the user can change it, the vault may decline to disclose it next time, and two
     * different people can present the same one, which
     * `two profiles sharing an email are two accounts` plays out below.
     *
     * [disclosed] is populated only out of a result this library parsed, never out of a request
     * the service itself built, so the table holds no value the user did not consent to send.
     */
    private class Service {
        private val accounts = mutableMapOf<String, String>()
        private val disclosed = mutableMapOf<String, Map<String, TypedField>>()
        private var nextAccount = 1

        /**
         * Sign-up. The handle to keep is the key the *result* carried: the vault mints the keypair,
         * so whatever the client put in the slot on the way out is not an identifier.
         */
        fun signUp(result: ShareResult): String? {
            val key = result.publicKey ?: return null
            return accounts.getOrPut(key) { "account-${nextAccount++}" }
        }

        fun accountFor(publicKey: String): String? = accounts[publicKey]

        fun fieldsFor(publicKey: String): Map<String, TypedField> = disclosed[publicKey].orEmpty()

        /** A query answer is a disclosure, not a login: nothing in it is signed, so nothing is proved. */
        fun recordDisclosure(result: QueryResult) {
            val key = result.publicKey?.takeIf { it in accounts } ?: return
            disclosed[key] = result.fields
        }

        /**
         * Login, and the one line where "parsed is not authenticated" earns its keep: the account
         * comes back only when the signature verifies against the key **this service already
         * stores** and the nonce **the client generated**. A key or nonce read back out of the
         * result would let the sender choose both sides of the proof.
         */
        fun logIn(publicKey: String, result: SignChallengeResult?, nonce: ByteArray): String? {
            if (result == null || !result.isVerified(publicKey, nonce)) return null
            return accounts[publicKey]
        }
    }

    /**
     * A vault holding one profile, with a locally generated JCE keypair standing in for the
     * Keystore key a real vault would never let out of the device.
     *
     * LIM's request parsers on the way in and LIM's result builders on the way out, each answer
     * built from the request it answers: a vault that hand-writes an extra is a vault that drifts
     * from the client, which is the whole reason both halves of the wire format live in this
     * library. The one hand-built intent left is [decline], and it says why.
     */
    private class Vault(
        private val keyPair: KeyPair,
        private val profile: Map<String, TypedField>,
    ) {
        /** The public half, and the only thing this vault ever hands out. */
        val publicKey: String = Base64.encodeToString(keyPair.public.encoded, Base64.NO_WRAP)

        /** The user's answer at the consent dialog. `false` plays the fourth scene. */
        var consents: Boolean = true

        private var stored: Entry? = null

        /**
         * Route an incoming request the way a real vault routes one: on the **action** first,
         * because a share and a query travel under the same action and a sign-challenge does not.
         * Within that action the payload is what tells a share from a query, and LIM's two request
         * parsers are the disambiguation — never a hand-read extra.
         */
        fun handle(request: Intent): VaultAnswer = when (request.action) {
            Utils.shareDataAction() ->
                Utils.parseShareRequest(request)?.let(::store)
                    ?: Utils.parseQueryRequest(request)?.let(::disclose)
                    ?: VaultAnswer(Activity.RESULT_CANCELED, null)

            Utils.signChallengeAction() ->
                Utils.parseSignChallengeRequest(request)?.let(::signChallenge)
                    ?: VaultAnswer(Activity.RESULT_CANCELED, null)

            else -> VaultAnswer(Activity.RESULT_CANCELED, null)
        }

        private fun store(request: ShareRequest): VaultAnswer {
            // The client's entry declares which fields it wants and what type each one is; the
            // values come from the vault's own form, and the public key is the one this vault
            // minted. Nothing the client sent in either slot survives.
            val created = Entry(
                id = request.entry.id,
                fields = request.entry.fields.mapValues { (key, declared) ->
                    TypedField(value = profile[key]?.value ?: "", type = declared.type)
                },
                publicKey = publicKey,
            )
            stored = created
            // The request goes in so the correlation token comes out; the key and the fields are
            // the vault's own, passed explicitly. `createShareResultIntent` reads nothing else off
            // the request — notably not `request.entry.publicKey`, which is the client's.
            return VaultAnswer(
                Activity.RESULT_OK,
                Utils.createShareResultIntent(request, publicKey, created.fields),
            )
        }

        private fun disclose(request: QueryRequest): VaultAnswer {
            val held = stored?.fields?.takeIf { request.publicKey == publicKey }
            // An unknown key and a refused consent collapse into the same answer deliberately:
            // answering "no such profile" would tell the caller that a profile *does* exist for
            // every key it is not told that about.
            if (held == null || !consents) {
                return VaultAnswer(Activity.RESULT_CANCELED, decline(request.requestCode))
            }
            // The query builder, not the share one: a disclosure's fields travel under
            // `extra_query_result_fields` and the two keys are not interchangeable. Choosing
            // between them by hand is the mistake this pair of functions exists to remove.
            return VaultAnswer(
                Activity.RESULT_OK,
                Utils.createQueryResultIntent(request, publicKey, held),
            )
        }

        private fun signChallenge(request: SignChallengeRequest): VaultAnswer {
            // An unknown key and a refused consent collapse here too, for the reason [disclose]
            // gives: the shape of the answer must not depend on whether the profile exists.
            val held = stored
            if (held == null || request.publicKey != publicKey || !consents) {
                return VaultAnswer(Activity.RESULT_CANCELED, decline(request.requestCode))
            }
            // The check a signing device owes every signature it makes. These bytes are whatever
            // the caller chose, and they could be a signed statement's pre-image rather than a
            // challenge — signing one under a dialog that said "prove your identity" would
            // authorize a key rotation the user never agreed to. Only this side can tell the two
            // apart; afterwards no verifier can.
            if (Utils.isStatementPreImage(request.nonce)) {
                return VaultAnswer(Activity.RESULT_CANCELED, decline(request.requestCode))
            }
            val signature = Signature.getInstance(SIGN_ALGORITHM).run {
                initSign(keyPair.private)
                update(request.nonce)
                sign()
            }
            // The raw bytes go in and the builder does the Base64; `algorithm` is passed because
            // it is part of this answer's shape, not because anything honours it — `isVerified`
            // hardcodes `SHA256withRSA`. The fields are the disclosure a sign-challenge answer
            // carries alongside the proof, under this flow's own `extra_fields_json`; they are
            // unverified until the client's own `isVerified` says otherwise. The nonce is read off
            // the request here and nowhere else: the builder never signs anything.
            return VaultAnswer(
                Activity.RESULT_OK,
                Utils.createSignChallengeResultIntent(request, signature, held.fields, SIGN_ALGORITHM),
            )
        }

        /**
         * A refusal, as a vault actually sends one today: `RESULT_CANCELED` carrying the echoed
         * request code and nothing else. Not an empty intent — correlation has to survive a
         * refusal or a client cannot tell which request was refused.
         *
         * **Hand-built on purpose, and the one intent in this fixture that is.** Every result
         * builder in this library writes `extra_protocol_version` unconditionally — that echo is
         * the point of them, since it is what lets a client tell a vault that honoured a modern
         * request from one that ignored what it did not know. A refusal honoured nothing, so
         * routing one through a builder would attach a protocol version to a refusal: a change to
         * the wire, not a tidy-up. There is no refusal builder to call, and whether there should
         * be one is drafted under "Blocked on human" because it is a protocol decision. The
         * negative control in scene four pins today's shape so the question has to be answered
         * rather than assumed.
         */
        private fun decline(requestCode: String?): Intent = Intent().apply {
            requestCode?.let { putExtra(Utils.EXTRA_SHARE_REQUEST_CODE, it) }
        }
    }

    // ── The three scenes, in order, against one profile ──────────────────

    @Test
    fun `sign-up, then query, then login, against one profile`() {
        val service = Service()
        val vault = Vault(profileKeyPair, profile)

        // ── Scene 1: sign-up ─────────────────────────────────────────────
        // The client asks for the fields it needs, declaring a type for each. It has no public key
        // yet — the vault mints that — but the slot is not optional today: `createShareIntent`
        // encodes a blank `publicKey` happily while `parseShareRequest` refuses one, so a client
        // that sends blank is dropped with nothing to show for it. Hence the placeholder below, and
        // hence the rule: **the handle to keep is the key the result carries, never the one you
        // sent.** (Narrowing the encoder to refuse a blank is recorded under "Blocked on human" —
        // it narrows what the protocol accepts, so the vault has to agree.)
        //
        // `requestCode` is passed **by name**, and that is not stylistic. The positional
        // three-argument call `createShareIntent(context, entry, "signup-1")` resolves to the
        // *targetPackage* overload instead, addressing the intent to a package named "signup-1"
        // and reaching no vault at all. This example was written with the positional form first
        // and every scene failed, which is how it got the comment.
        val signUp = vault.handle(Utils.createShareIntent(context, pushedEntry(), requestCode = SIGN_UP_CODE))
        assertEquals(Activity.RESULT_OK, signUp.resultCode)

        val shareResult = Utils.parseShareResult(signUp.data)
        assertNotNull("a share answer must parse", shareResult)
        val accountKey = shareResult!!.publicKey
        assertEquals("the vault answers with the key it minted", vault.publicKey, accountKey)
        assertNotEquals("and not with the slot the client had to fill", NO_KEY_YET, accountKey)
        assertEquals("account-1", service.signUp(shareResult))
        assertEquals(
            "the type the client declared is metadata and survives the round trip",
            FieldType.EMAIL,
            shareResult.fields["email"]?.type,
        )
        assertEquals(
            "and the value is the one the user typed into the vault, not the blank the client sent",
            SHARED_EMAIL,
            shareResult.fields["email"]?.value,
        )

        // ── Scene 2: query ───────────────────────────────────────────────
        // Issued for the key scene 1 handed back, with a request code of its own: two requests can
        // be in flight at once, and `matchesRequestCode` is what tells their answers apart.
        val query = vault.handle(Utils.createQueryIntent(context, accountKey!!, QUERY_CODE))
        assertEquals(Activity.RESULT_OK, query.resultCode)
        assertTrue("this answer is the one the query was waiting for", Utils.matchesRequestCode(query.data, QUERY_CODE))

        val queryResult = Utils.parseQueryResult(query.data)
        assertNotNull(queryResult)
        assertEquals("the answer is about the key that was asked about", accountKey, queryResult!!.publicKey)
        assertEquals(SHARED_EMAIL, queryResult.fields["email"]?.value)
        service.recordDisclosure(queryResult)
        assertEquals(
            "the service now holds exactly what was disclosed to it",
            SHARED_EMAIL,
            service.fieldsFor(accountKey)["email"]?.value,
        )
        // A disclosure is not a login. Nothing in a query answer is signed, so this says "the
        // vault told us this", never "the holder of the key is present".

        // ── Scene 3: login ───────────────────────────────────────────────
        // The order is the lesson. Generate the nonce, keep it, and verify against it and against
        // the key the service already stores — neither read back out of the result.
        val nonce = Utils.generateNonce()
        val login = vault.handle(
            Utils.createSignChallengeIntent(
                context,
                accountKey,
                nonce,
                LOGIN_CODE,
                nonceFormat = Utils.NONCE_FORMAT_TIMESTAMPED,
            ),
        )
        assertEquals(Activity.RESULT_OK, login.resultCode)
        assertTrue(Utils.matchesRequestCode(login.data, LOGIN_CODE))

        val loginResult = Utils.parseSignChallengeResult(login.data)
        assertEquals(
            "the login must land on the account the sign-up created",
            "account-1",
            service.logIn(accountKey, loginResult, nonce),
        )
        // The answer carries the disclosure alongside the proof, and the order matters: these
        // fields were unverified bytes from another app until the line above returned an account.
        assertEquals(SHARED_EMAIL, loginResult?.fields?.get("email")?.value)
        // Declared, not honoured — `isVerified` hardcodes the algorithm and never reads this. It is
        // asserted anyway because it is the one extra on this flow no other test in this file
        // reads: a vault author copying the login scene and omitting it would delete
        // `extra_algorithm` from the published example with every other assertion still green.
        assertEquals("the vault declares what it signed with", SIGN_ALGORITHM, loginResult?.algorithm)
        // Freshness is a separate question from the signature, and the client owns it: the nonce
        // carries its own timestamp, so there is no server state to keep.
        assertTrue("the challenge is still inside its window", Utils.isNonceFresh(nonce, 60_000L))
        assertEquals("one profile, one account, all the way through", "account-1", service.accountFor(vault.publicKey))
    }

    // ── Scene 4: the user says no ────────────────────────────────────────

    /**
     * The scene an integration cannot skip, and the one with a trap in it.
     *
     * A consent denial today is a bare `RESULT_CANCELED` carrying the echoed request code, so the
     * assertions below are what actually holds rather than what would be tidy.
     */
    @Test
    fun `scene four, the user declines, and a refusal is not the absence of an answer`() {
        val service = Service()
        val vault = Vault(profileKeyPair, profile)
        val accountKey = signUpOn(service, vault)

        vault.consents = false
        val declined = vault.handle(Utils.createQueryIntent(context, accountKey, QUERY_CODE))

        assertEquals(Activity.RESULT_CANCELED, declined.resultCode)
        // Correlation survives a refusal: the echoed code is the one extra a declining vault sends,
        // so a client with several requests in flight still knows which one was refused.
        assertTrue(Utils.matchesRequestCode(declined.data, QUERY_CODE))
        // There is no signature to carry, so there is no sign-challenge result at all.
        assertNull(Utils.parseSignChallengeResult(declined.data))
        // The boundary the successful paths below do *not* cross, pinned as a wire literal rather
        // than described: a refusal carries the echoed code and nothing else. Every result builder
        // in this library writes `extra_protocol_version` unconditionally and on purpose, so
        // routing a refusal through one would attach a protocol version to a refusal — a wire
        // change. This is the assertion a future "use a builder everywhere" refactor goes red on.
        assertFalse(
            "a refusal declares no protocol version",
            declined.data!!.hasExtra("extra_protocol_version"),
        )

        // And the trap. A decline parses into a perfectly good `QueryResult` with no fields —
        // identical to a vault that consented and disclosed nothing. The empty-envelope guard only
        // fires when all three of the flow's extras are absent, and the echoed request code is one
        // of them. So **branch on the result code, never on the parse.** A structured decline
        // signal (`extra_result_status`, with pinned `"declined"` / `"error"` values) is drafted
        // under "Blocked on human" and waits on a privacy decision — whether telling a service
        // "declined" also tells it a profile exists. This scene pins today's shape and must not
        // invent a signal.
        val result = Utils.parseQueryResult(declined.data)
        assertNotNull("a refusal still parses", result)
        assertTrue("with nothing disclosed", result!!.fields.isEmpty())
        assertNull("and no key echoed", result.publicKey)
        assertNull(
            "a declining vault says nothing else — not even which protocol refused you",
            result.vaultProtocolVersion,
        )
        // Filed the way a client that branched on the parse rather than the result code would file
        // it — and nothing lands, because a refusal carries no key to file it under.
        service.recordDisclosure(result)
        assertEquals("nothing reaches the service from a refusal", emptyMap<String, TypedField>(), service.fieldsFor(accountKey))

        // "The vault answered a refusal" and "nothing came back at all" are different facts, and a
        // client has to be able to tell them apart: a null intent correlates with nothing.
        assertFalse(Utils.matchesRequestCode(null, QUERY_CODE))

        // A login is refused by the same dialog and answers the same way — still a refusal, still
        // correlated, still no signature.
        val refusedLogin = vault.handle(
            Utils.createSignChallengeIntent(context, accountKey, Utils.generateNonce(), LOGIN_CODE),
        )
        assertEquals(Activity.RESULT_CANCELED, refusedLogin.resultCode)
        assertTrue(Utils.matchesRequestCode(refusedLogin.data, LOGIN_CODE))
        assertNull(Utils.parseSignChallengeResult(refusedLogin.data))
        assertNull("a refused login must not log anybody in", service.logIn(accountKey, null, Utils.generateNonce()))

        // The control that the refusal is the user's doing and not the flow's: consent restored,
        // the same query answers.
        vault.consents = true
        val granted = vault.handle(Utils.createQueryIntent(context, accountKey, QUERY_CODE))
        assertEquals(Activity.RESULT_OK, granted.resultCode)
        assertEquals(SHARED_EMAIL, Utils.parseQueryResult(granted.data)?.fields?.get("email")?.value)

        // And the shape a vault must *also* give an unknown key, consent or no consent: the same
        // refusal. Answering "no such profile" here would tell the caller that a profile exists
        // for every key it is not told that about, which is existence disclosure by elimination.
        assertEquals(
            "an unknown key must be indistinguishable from a refusal",
            Activity.RESULT_CANCELED,
            vault.handle(Utils.createQueryIntent(context, otherPublicKey, QUERY_CODE)).resultCode,
        )
        assertEquals(
            Activity.RESULT_CANCELED,
            vault.handle(
                Utils.createSignChallengeIntent(context, otherPublicKey, Utils.generateNonce(), LOGIN_CODE),
            ).resultCode,
        )
    }

    // ── Negative controls ────────────────────────────────────────────────

    /**
     * A signature answers exactly one challenge from exactly one key, and the two ways an
     * integration gets that wrong are verifying against a key it was handed and re-using an answer
     * it already has.
     */
    @Test
    fun `a login answer verifies against nothing but the key and nonce the client chose`() {
        val service = Service()
        val vault = Vault(profileKeyPair, profile)
        val accountKey = signUpOn(service, vault)

        val nonce = Utils.generateNonce()
        val result = Utils.parseSignChallengeResult(
            vault.handle(Utils.createSignChallengeIntent(context, accountKey, nonce, LOGIN_CODE)).data,
        )
        assertNotNull(result)
        assertTrue("control: it does authenticate the profile it was issued for", result!!.isVerified(accountKey, nonce))

        // A different public key. The signature is genuine and still proves nothing about this key.
        assertFalse(result.isVerified(otherPublicKey, nonce))
        assertNull(service.logIn(otherPublicKey, result, nonce))

        // The replay the nonce exists to stop: yesterday's captured answer against a fresh
        // challenge. Two nonces generated in the same millisecond still differ — the random half
        // is 32 bytes — so this is the signature failing, not the clock.
        val second = Utils.generateNonce()
        assertFalse("a captured answer must not answer a new challenge", nonce.contentEquals(second))
        assertFalse(result.isVerified(accountKey, second))
        assertNull(service.logIn(accountKey, result, second))
    }

    /**
     * T3's structural property, re-asserted where an integrator meets it: a parsed result carries
     * no verdict of its own, so there is nothing to mistake for success.
     */
    @Test
    fun `a parsed login answer cannot report itself authenticated`() {
        val service = Service()
        val vault = Vault(profileKeyPair, profile)
        val accountKey = signUpOn(service, vault)
        val nonce = Utils.generateNonce()

        val booleanMethods = SignChallengeResult::class.java.declaredMethods
            .filter { !it.isSynthetic }
            .filter { it.returnType == java.lang.Boolean.TYPE || it.returnType == java.lang.Boolean::class.java }
        // The floor: a scan that stopped seeing methods at all would report no offenders for ever.
        assertTrue(
            "the scan must find isVerified, which takes the key and the nonce",
            booleanMethods.any { it.name == "isVerified" && it.parameterCount == 2 },
        )

        val offenders = booleanMethods.filter { it.parameterCount == 0 }.map { it.name }
        assertEquals(
            "verification must require the caller's own key and nonce; found $offenders",
            emptyList<String>(),
            offenders,
        )

        // Behaviourally, on the path a client actually walks: anything can put bytes in an intent,
        // and they parse just as well as a genuine answer does.
        val forged = Utils.parseSignChallengeResult(
            Intent()
                .putExtra(Utils.EXTRA_SIGNATURE, Base64.encodeToString(ByteArray(256) { 9 }, Base64.DEFAULT))
                .putExtra(Utils.EXTRA_SHARE_REQUEST_CODE, LOGIN_CODE),
        )
        assertNotNull("a forged answer still parses", forged)
        assertNull("but it never logs anybody in", service.logIn(accountKey, forged, nonce))

        // The non-vacuity floor: the genuine answer on the same path does log in.
        val genuine = Utils.parseSignChallengeResult(
            vault.handle(Utils.createSignChallengeIntent(context, accountKey, nonce, LOGIN_CODE)).data,
        )
        assertEquals("account-1", service.logIn(accountKey, genuine, nonce))
    }

    /**
     * The correlation slip this helper exists to prevent: acting on the answer to a different
     * request. Driven with the two codes the scenes above actually used.
     */
    @Test
    fun `an answer from one scene is not accepted for another scene's request`() {
        val vault = Vault(profileKeyPair, profile)
        val signUp = vault.handle(
            Utils.createShareIntent(context, pushedEntry(), requestCode = SIGN_UP_CODE),
        )

        assertTrue("the sign-up answer is the sign-up's", Utils.matchesRequestCode(signUp.data, SIGN_UP_CODE))
        assertFalse(
            "and must not be mistaken for the query's, which is still in flight",
            Utils.matchesRequestCode(signUp.data, QUERY_CODE),
        )
        assertFalse(Utils.matchesRequestCode(signUp.data, LOGIN_CODE))
    }

    /**
     * The impersonation vector VISION calls out, played in the only place it can be: a service
     * keyed on the public key.
     *
     * Had this service keyed accounts on the disclosed `email`, the second sign-up would have
     * landed on the first one's row — one account for two people, with either able to read the
     * other's disclosures, and nothing in the protocol able to object. The email is identical by
     * construction here; the keys are not, and the keys are the identifiers.
     */
    @Test
    fun `two profiles sharing an email are two accounts`() {
        val service = Service()
        val first = Vault(profileKeyPair, profile)
        val second = Vault(otherProfileKeyPair, otherProfile)

        val firstKey = signUpOn(service, first)
        val secondKey = signUpOn(service, second)

        assertNotEquals("precondition: two distinct identifiers", firstKey, secondKey)
        assertEquals("account-1", service.accountFor(firstKey))
        assertEquals("account-2", service.accountFor(secondKey))

        // Both disclose the same email, and each disclosure lands on its own account.
        service.recordDisclosure(Utils.parseQueryResult(first.handle(Utils.createQueryIntent(context, firstKey, QUERY_CODE)).data)!!)
        service.recordDisclosure(Utils.parseQueryResult(second.handle(Utils.createQueryIntent(context, secondKey, QUERY_CODE)).data)!!)

        assertEquals(SHARED_EMAIL, service.fieldsFor(firstKey)["email"]?.value)
        assertEquals(SHARED_EMAIL, service.fieldsFor(secondKey)["email"]?.value)
        assertNotEquals(
            "the one field that differs is what proves these are two profiles, not one row written twice",
            service.fieldsFor(firstKey)["name"]?.value,
            service.fieldsFor(secondKey)["name"]?.value,
        )

        // The account table is what decides, not the intent: a disclosure about a key this service
        // holds no account for is not filed at all, however well-formed it is.
        val stranger = "a-key-this-service-never-signed-up"
        service.recordDisclosure(QueryResult(fields = profile, publicKey = stranger, requestCode = QUERY_CODE))
        assertEquals(emptyMap<String, TypedField>(), service.fieldsFor(stranger))
    }

    /**
     * Redaction asserted over a whole flow rather than one class at a time: a sentinel planted in
     * the user's `name` must appear in no `toString()` of anything these scenes construct.
     *
     * The nested renderings are where a naive override leaks — an [Entry] carries the field map and
     * a [ShareRequest] carries the [Entry] — so every object on the path is checked, not just the
     * leaves, and the ones that genuinely hold the sentinel are asserted to hold it first.
     */
    @Test
    fun `no object these scenes construct prints a field value`() {
        val vault = Vault(profileKeyPair, profile)

        val shareIntent = Utils.createShareIntent(context, pushedEntry(), requestCode = SIGN_UP_CODE)
        val shareRequest = Utils.parseShareRequest(shareIntent)
        val shareResult = Utils.parseShareResult(vault.handle(shareIntent).data)
        val accountKey = shareResult!!.publicKey!!

        val queryIntent = Utils.createQueryIntent(context, accountKey, QUERY_CODE)
        val queryRequest = Utils.parseQueryRequest(queryIntent)
        val queryResult = Utils.parseQueryResult(vault.handle(queryIntent).data)

        val nonce = Utils.generateNonce()
        val loginIntent = Utils.createSignChallengeIntent(context, accountKey, nonce, LOGIN_CODE)
        val loginRequest = Utils.parseSignChallengeRequest(loginIntent)
        val loginResult = Utils.parseSignChallengeResult(vault.handle(loginIntent).data)

        // The entry a client keeps after sign-up: its own id, the key the vault minted, and the
        // values it was told. This is the [Entry] that actually holds personal data in this flow —
        // the *pushed* one never does, because a client has no values to push.
        val kept = Entry(id = "signup-form-1", fields = shareResult.fields, publicKey = accountKey)

        // Split deliberately. A redaction test whose subjects never held the secret passes for
        // ever, so the carriers are asserted to hold it one by one before anything is rendered.
        val carriers = mapOf(
            "Entry (kept by the client)" to kept,
            "TypedField" to shareResult.fields["name"],
            "ShareResult" to shareResult,
            "QueryResult" to queryResult,
            "SignChallengeResult" to loginResult,
        )
        assertEquals(SENTINEL_NAME, kept.fields["name"]?.value)
        assertEquals(SENTINEL_NAME, shareResult.fields["name"]?.value)
        assertEquals(SENTINEL_NAME, queryResult?.fields?.get("name")?.value)
        assertEquals(SENTINEL_NAME, loginResult?.fields?.get("name")?.value)

        // On the same path, and checked for the same property, but carrying no field value in this
        // flow at all — asserted rather than claimed, so the split above cannot quietly become a
        // place to hide a subject that stopped being checked.
        val valueless = mapOf(
            "Entry (as pushed)" to shareRequest?.entry,
            "ShareRequest" to shareRequest,
            "QueryRequest" to queryRequest,
            "SignChallengeRequest" to loginRequest,
        )
        assertEquals("", shareRequest?.entry?.fields?.get("name")?.value)

        (carriers + valueless).forEach { (name, subject) ->
            assertNotNull("precondition: $name must exist to be rendered", subject)
            assertFalse(
                "$name leaked a field value: ${subject.toString()}",
                subject.toString().contains(SENTINEL_NAME),
            )
        }
        // And the keys and types still print, so the redaction is not a constant.
        assertTrue(shareResult.fields.getValue("name").toString().contains(FieldType.STRING))
        assertTrue(kept.toString().contains("email"))
        assertTrue(shareRequest!!.entry.toString().contains("email"))
    }

    /**
     * The one nonce a vault must refuse, kept in this file because this is where a vault author
     * reads the login sequence.
     *
     * The flow signs arbitrary caller-supplied bytes with the profile's key, and a signed
     * statement's pre-image is exactly such bytes — get one signed under a "prove your identity"
     * dialog and the answer is a valid key rotation. The signing device is the only place the two
     * can be told apart, so [Utils.isStatementPreImage] is called before signing and a match is
     * refused.
     */
    @Test
    fun `the vault refuses to sign a statement pre-image handed to it as a challenge`() {
        val service = Service()
        val vault = Vault(profileKeyPair, profile)
        val accountKey = signUpOn(service, vault)

        val preImage = Utils.rotationStatementBytes(
            RotationStatement(
                oldPublicKey = accountKey,
                newPublicKey = otherPublicKey,
                statementId = "rot-as-a-challenge",
                issuedAtMillis = 1_770_000_000_000L,
                expiresAtMillis = 1_770_000_600_000L,
            ),
        )
        assertTrue("precondition: these bytes are a statement", Utils.isStatementPreImage(preImage))

        val answer = vault.handle(
            Utils.createSignChallengeIntent(context, accountKey, preImage, LOGIN_CODE),
        )
        assertEquals(Activity.RESULT_CANCELED, answer.resultCode)
        assertNull("nothing was signed", Utils.parseSignChallengeResult(answer.data))
        // The control that the refusal is the pre-image's doing: an ordinary nonce is signed.
        val nonce = Utils.generateNonce()
        assertFalse("a generated nonce is never a pre-image", Utils.isStatementPreImage(nonce))
        assertEquals(
            Activity.RESULT_OK,
            vault.handle(Utils.createSignChallengeIntent(context, accountKey, nonce, LOGIN_CODE)).resultCode,
        )
    }

    // ── Shared setup ─────────────────────────────────────────────────────

    /** The entry a client pushes on sign-up: field keys and types, no values, no key of its own. */
    private fun pushedEntry() = Entry(
        id = "signup-form-1",
        fields = linkedMapOf(
            "name" to TypedField(value = "", type = FieldType.STRING),
            "email" to TypedField(value = "", type = FieldType.EMAIL),
        ),
        publicKey = NO_KEY_YET,
    )

    /** Scene 1, for the tests whose subject is a later scene. Returns the key to keep. */
    private fun signUpOn(service: Service, vault: Vault): String {
        val result = Utils.parseShareResult(
            vault.handle(Utils.createShareIntent(context, pushedEntry(), requestCode = SIGN_UP_CODE)).data,
        )
        assertNotNull(result)
        assertNotNull(service.signUp(result!!))
        return result.publicKey!!
    }

    companion object {
        /** A value distinctive enough that its appearance in any rendering is unmistakable. */
        private const val SENTINEL_NAME = "Ada-SENTINEL-4f91c2"

        /** Deliberately the same for both profiles below. See the test that relies on it. */
        private const val SHARED_EMAIL = "shared@example.com"

        /**
         * What a client has to put in `Entry.publicKey` on a first sign-up: it holds no key — the
         * vault mints the keypair — and a blank one is encoded but then refused on arrival.
         */
        private const val NO_KEY_YET = "no-key-yet"

        private const val SIGN_UP_CODE = "signup-1"
        private const val QUERY_CODE = "query-1"
        private const val LOGIN_CODE = "login-1"

        private const val SIGN_ALGORITHM = "SHA256withRSA"

        private lateinit var profileKeyPair: KeyPair
        private lateinit var otherProfileKeyPair: KeyPair

        /** The public key of a profile this service does not hold, for the wrong-key control. */
        private lateinit var otherPublicKey: String

        /** 2048-bit RSA generation is slow (~100ms each); do it once for the whole class. */
        @JvmStatic
        @BeforeClass
        fun generateKeys() {
            val generator = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }
            profileKeyPair = generator.generateKeyPair()
            otherProfileKeyPair = generator.generateKeyPair()
            otherPublicKey = Base64.encodeToString(otherProfileKeyPair.public.encoded, Base64.NO_WRAP)
        }
    }
}
