package dev.eryalabs.lim

import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.content.IntentFilter
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
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature

/**
 * The code `docs/INTEGRATION.md` prints, in the file that runs it.
 *
 * Every fenced Kotlin block in the guide is a `// region snippet:name` … `// endregion
 * snippet:name` span of this file, quoted verbatim, and `GuideSnippetTest` is what holds the two
 * together: it fails if a block drifts from its region, if a region is quoted by no block or by
 * two, if a marker names a region that is not here, or — the property that makes a printed snippet
 * evidence rather than paste — if a region's enclosing function is not annotated `@Test`. So every
 * line the guide shows an integrator is a line JUnit executed to get this suite green.
 *
 * **Written in an integrator's voice, and the assertions stay outside the regions** so the guide
 * shows integration code rather than JUnit. What is inside a region is what a client app would
 * write; what is outside it is this file proving the snippet does what the guide says it does.
 *
 * The division of labour against the two neighbours worth knowing about: [ClientIntegrationExampleTest]
 * is the *sequence* — sign-up, query and login against one profile, both halves of the wire — and
 * `RequestParsingTest` / `ResultParsingTest` pin each builder and parser field for field. This file
 * repeats neither. Its subject is the published prose, and its [FixtureVault] exists only so the
 * guide's client-side snippets have something to talk to.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class GuideExamplesTest {

    private val context = ApplicationProvider.getApplicationContext<Context>()

    private val vault = FixtureVault(vaultKeyPair, PROFILE)

    /** A service's own account table, keyed the one way the protocol allows. */
    private val accounts = mutableMapOf<String, String>()

    // ── Before you start: is there a vault? ───────────────────────────────

    /**
     * The step before sign-up, and the one wall every snippet below assumes away: the device may
     * have no vault on it at all.
     *
     * [Utils.shareEntry] is the only function in this library whose return value answers that, so
     * the guide's first block is the branch an app writes around it. Both states are driven through
     * the region's own code — a vault registered with Robolectric's `ShadowPackageManager`, and
     * none — and the dispatch is **counted** rather than inferred: a `false` that still handed an
     * intent to the system would be a different bug than the one the guide describes, and asserting
     * only the return value could not tell the two apart.
     *
     * `ShareEntryTest` is the fuller version of this — every branch of `shareEntry`, the flags on
     * both share paths, and the two ways resolving and starting can disagree. The two branches
     * below are deliberately that file's two simple ones, because they are the two a *snippet* can
     * show; what this file repeats is neither the vault that vanishes between the resolve and the
     * launch nor the refused launch that propagates.
     */
    @Test
    fun `nothing is dispatched unless a vault is installed, and the return value says which`() {
        // region snippet:vault-present
        // A device may have no vault on it at all, and that is the first wall an integration
        // hits. `shareEntry` dispatches the sign-up and its return value is the answer: `false`
        // means nothing received the intent, so no consent dialog opened and nothing is coming.
        fun signUpIfAVaultIsInstalled(context: Context, entry: Entry): Boolean {
            if (Utils.shareEntry(context, entry)) return true
            // Nothing handled it. Offer to install a vault — but declare the vault in your own
            // manifest's `<queries>` element first, or on Android 11+ a `false` here also means
            // "this app was not allowed to look", and you would be telling the user to install
            // an app they already have.
            // promptToInstallAVault()
            return false
        }
        // endregion snippet:vault-present

        val withoutAVault = CountingContext(context)
        assertFalse(
            "no vault is registered, so nothing on the device can receive the share",
            signUpIfAVaultIsInstalled(withoutAVault, pushedEntry()),
        )
        assertEquals(
            "…and nothing may be dispatched when nothing can receive it — asserted by count, " +
                "because a `false` that still started an activity is a different failure",
            0,
            withoutAVault.attempts,
        )

        installVault()
        val withAVault = CountingContext(context)
        assertTrue(
            "control: with a vault registered the same code takes the other branch",
            signUpIfAVaultIsInstalled(withAVault, pushedEntry()),
        )
        assertEquals("…having really handed the intent to the system", 1, withAVault.attempts)
    }

    // ── Sign-up ──────────────────────────────────────────────────────────

    @Test
    fun `sign-up sends the fields you need and keeps the key the vault answers with`() {
        // region snippet:signup-request
        // The fields your service needs, each with the type you expect. You supply no values —
        // the user fills those in the vault's own form. `publicKey` is a slot the vault fills,
        // so send a placeholder: a blank one is encoded here and then refused on arrival.
        val entry = Entry(
            id = "signup-form",
            fields = linkedMapOf(
                "name" to TypedField(value = "", type = FieldType.STRING),
                "email" to TypedField(value = "", type = FieldType.EMAIL),
            ),
            publicKey = "no-key-yet",
        )
        // Pass `requestCode` **by name**. The positional three-argument call resolves to the
        // `targetPackage` overload instead, addressing the intent at a package named
        // "signup-1", and nothing ever answers it.
        val request = Utils.createShareIntent(context, entry, requestCode = SIGN_UP_REQUEST)
        // startActivityForResult(request, VAULT_RESULT)
        // endregion snippet:signup-request

        val answer = vault.answer(request)
        val resultCode = answer.resultCode
        val data = answer.data

        // region snippet:signup-result
        // In onActivityResult, once `resultCode` is RESULT_OK.
        val result = Utils.parseShareResult(data)
        // The handle to keep is the key the *result* carried. The vault mints the keypair, so
        // whatever you put in the slot on the way out was never an identifier.
        val accountKey = result?.publicKey
        // endregion snippet:signup-result

        assertEquals(Activity.RESULT_OK, resultCode)
        assertNotNull("a share answer must parse", result)
        assertEquals("the vault answers with the key it minted", vault.publicKey, accountKey)
        assertEquals(
            "the type you declared is metadata and survives the round trip",
            FieldType.EMAIL,
            result!!.fields["email"]?.type,
        )
        assertEquals(
            "and the value is the one the user typed into the vault, not the blank you sent",
            PROFILE_EMAIL,
            result.fields["email"]?.value,
        )
    }

    // ── Query ────────────────────────────────────────────────────────────

    @Test
    fun `a query asks about one key and gets back what the user consented to disclose`() {
        val accountKey = signUpOnTheFixtureVault()

        // region snippet:query-request
        // A query asks about one profile, by the key you stored at sign-up. The vault decides
        // what it discloses. The request code is yours: it is what tells answers apart when
        // more than one request is in flight.
        val request = Utils.createQueryIntent(context, accountKey, QUERY_REQUEST)
        // startActivityForResult(request, VAULT_RESULT)
        // endregion snippet:query-request

        val answer = vault.answer(request)
        val resultCode = answer.resultCode
        val data = answer.data

        // region snippet:query-result
        // In onActivityResult. Check the correlation first — this answer may belong to a
        // different request you still have outstanding.
        val mine = Utils.matchesRequestCode(data, QUERY_REQUEST)
        val disclosure =
            if (mine && resultCode == Activity.RESULT_OK) Utils.parseQueryResult(data) else null
        val email = disclosure?.fields?.get("email")?.value
        // A disclosure is not a login. Nothing in a query answer is signed, so this says "the
        // vault told us this", never "the holder of the key is here".
        // endregion snippet:query-result

        assertTrue("the answer is the one this query was waiting for", mine)
        assertEquals(PROFILE_EMAIL, email)
        assertEquals("the answer is about the key that was asked about", accountKey, disclosure?.publicKey)
        assertFalse(
            "and it is not an answer to any other request in flight",
            Utils.matchesRequestCode(data, LOGIN_REQUEST),
        )
    }

    // ── Login ────────────────────────────────────────────────────────────

    @Test
    fun `login proves the holder of the stored key is present`() {
        val storedPublicKey = signUpOnTheFixtureVault()

        // region snippet:login-request
        // Mint the challenge and keep it. It carries its own timestamp, so there is no
        // server-side state to expire; declaring the format is what lets a vault read that
        // timestamp and apply a freshness policy of its own.
        val nonce = Utils.generateNonce()
        val request = Utils.createSignChallengeIntent(
            context,
            storedPublicKey,
            nonce,
            LOGIN_REQUEST,
            nonceFormat = Utils.NONCE_FORMAT_TIMESTAMPED,
        )
        // startActivityForResult(request, VAULT_RESULT)
        // endregion snippet:login-request

        val answer = vault.answer(request)
        val resultCode = answer.resultCode
        val data = answer.data

        // region snippet:login-result
        // In onActivityResult. Verify against the key your account table already holds and the
        // nonce you generated — never against either one read back out of the result, or the
        // sender gets to choose both sides of the proof.
        val result = Utils.parseSignChallengeResult(data)
        val loggedIn = resultCode == Activity.RESULT_OK &&
            Utils.matchesRequestCode(data, LOGIN_REQUEST) &&
            Utils.isNonceFresh(nonce, maxAgeMillis = 60_000L) &&
            result?.isVerified(storedPublicKey, nonce) == true
        // endregion snippet:login-result

        assertTrue("the genuine answer logs this profile in", loggedIn)
        assertNotNull(result)
        assertFalse(
            "the same signature proves nothing about any other key",
            result!!.isVerified(otherPublicKey, nonce),
        )
        assertFalse(
            "nor about a challenge it did not answer — this is the replay the nonce stops",
            result.isVerified(storedPublicKey, Utils.generateNonce()),
        )
    }

    // ── When the user says no ─────────────────────────────────────────────

    @Test
    fun `a refusal is an answer, and the result code is the only thing that says so`() {
        val accountKey = signUpOnTheFixtureVault()
        vault.consents = false

        val answer = vault.answer(Utils.createQueryIntent(context, accountKey, QUERY_REQUEST))
        val resultCode = answer.resultCode
        val data = answer.data

        // region snippet:declined
        // Branch on the result code, never on the parse. A refused query parses into a
        // perfectly good QueryResult with no fields — exactly what a vault that consented and
        // disclosed nothing returns — so the parse cannot tell you which of the two happened.
        val declined = resultCode != Activity.RESULT_OK
        // Correlation survives a refusal: the echoed request code is the one thing a declining
        // vault still sends, so you know which request the user said no to.
        val whichRequest = Utils.matchesRequestCode(data, QUERY_REQUEST)
        // There is no structured reason to show the user. A refusal is deliberately
        // uninformative; tell them nothing was sent and let them ask again.
        // endregion snippet:declined

        assertTrue(declined)
        assertTrue("a refusal is still correlated", whichRequest)
        // The trap the snippet above avoids, pinned so it cannot quietly stop being a trap: the
        // parse of a refusal is indistinguishable from a consenting vault's empty disclosure.
        val parsed = Utils.parseQueryResult(data)
        assertNotNull("a refusal still parses", parsed)
        assertTrue("with nothing disclosed", parsed!!.fields.isEmpty())
        assertNull("and no key echoed", parsed.publicKey)
        assertNull("there is no signature in a refusal", Utils.parseSignChallengeResult(data))
        // "The vault refused" and "nothing came back at all" are different facts.
        assertFalse("a null intent correlates with nothing", Utils.matchesRequestCode(null, QUERY_REQUEST))
        // The control that the refusal is the user's doing and not the flow's.
        vault.consents = true
        assertEquals(
            Activity.RESULT_OK,
            vault.answer(Utils.createQueryIntent(context, accountKey, QUERY_REQUEST)).resultCode,
        )
    }

    // ── Rules you must not break ──────────────────────────────────────────

    @Test
    fun `the account identifier is the public key and never a disclosed field`() {
        val first = FixtureVault(vaultKeyPair, PROFILE)
        val second = FixtureVault(otherKeyPair, OTHER_PROFILE)

        // region snippet:rules-account-key
        // `accounts` is your own table and the public key is its key. Key on a disclosed field
        // instead — email above all — and two people who happen to share an address land on one
        // row, each able to read the other's disclosures, with nothing in the protocol able to
        // object. The user can also change an email, and the vault may decline to disclose it
        // next time; neither is true of the key.
        fun signUp(data: Intent?): String? {
            val key = Utils.parseShareResult(data)?.publicKey ?: return null
            return accounts.getOrPut(key) { "account-${accounts.size + 1}" }
        }
        // endregion snippet:rules-account-key

        val firstAnswer = shareAnswerFrom(first)
        val secondAnswer = shareAnswerFrom(second)
        assertEquals(
            "precondition: these two profiles really do share one email address",
            PROFILE_EMAIL,
            Utils.parseShareResult(firstAnswer)?.fields?.get("email")?.value,
        )
        assertEquals(
            PROFILE_EMAIL,
            Utils.parseShareResult(secondAnswer)?.fields?.get("email")?.value,
        )

        assertEquals("account-1", signUp(firstAnswer))
        assertEquals("account-2", signUp(secondAnswer))
        assertEquals("one shared email did not merge two people", 2, accounts.size)
        assertNull("and nothing files without a key to file it under", signUp(null))
    }

    @Test
    fun `a parsed result is not an authenticated one`() {
        val storedPublicKey = signUpOnTheFixtureVault()
        val nonce = Utils.generateNonce()

        // region snippet:rules-not-authenticated
        // Parsing says the bytes were well formed. It says nothing about who made them:
        // anything on the device can put a signature-shaped extra in an intent, and it parses
        // exactly as well as a genuine answer does. `isVerified`, against your own stored key
        // and your own nonce, is the only success signal this library offers.
        fun authenticated(data: Intent?, storedKey: String, challenge: ByteArray): Boolean =
            Utils.parseSignChallengeResult(data)?.isVerified(storedKey, challenge) == true
        // endregion snippet:rules-not-authenticated

        val forged = Intent()
            .putExtra(Utils.EXTRA_SIGNATURE, Base64.encodeToString(ByteArray(256) { 9 }, Base64.NO_WRAP))
            .putExtra(Utils.EXTRA_SHARE_REQUEST_CODE, LOGIN_REQUEST)
        assertNotNull("a forged answer parses", Utils.parseSignChallengeResult(forged))
        assertFalse("and authenticates nobody", authenticated(forged, storedPublicKey, nonce))

        val genuine = vault.answer(
            Utils.createSignChallengeIntent(context, storedPublicKey, nonce, LOGIN_REQUEST),
        ).data
        assertTrue("control: the genuine answer does", authenticated(genuine, storedPublicKey, nonce))
    }

    @Test
    fun `a re-spelled key verifies perfectly and matches no account at all`() {
        val storedPublicKey = signUpOnTheFixtureVault()
        val nonce = Utils.generateNonce()
        val result = Utils.parseSignChallengeResult(
            vault.answer(
                Utils.createSignChallengeIntent(context, storedPublicKey, nonce, LOGIN_REQUEST),
            ).data,
        )

        // region snippet:rules-exact-key
        // Store the exact string you verified, character for character. Base64 decoding skips
        // characters outside its alphabet, so `key` and `key + "\n"` decode to the same bytes
        // and verify the same signatures — but a profile is looked up by the key *string*, so
        // the two are different account identifiers. Trim, re-wrap or re-encode a key you have
        // already stored and the account it names can never be reached again.
        val verifiedKey = storedPublicKey        // exactly as the sign-up result spelled it
        val account = accounts[verifiedKey]      // and exactly what you look it up by
        // endregion snippet:rules-exact-key

        assertNotNull(result)
        assertNotNull("control: the exact spelling finds the account", account)

        val respelled = storedPublicKey + "\n"
        assertTrue("the re-spelled key verifies just as well", result!!.isVerified(respelled, nonce))
        assertNull("and yet it names no account this service holds", accounts[respelled])
    }

    // ── Shared setup, all of it outside the regions ───────────────────────

    /** The entry a client pushes on sign-up: field keys and types, no values, no key of its own. */
    private fun pushedEntry() = Entry(
        id = "signup-form",
        fields = linkedMapOf(
            "name" to TypedField(value = "", type = FieldType.STRING),
            "email" to TypedField(value = "", type = FieldType.EMAIL),
        ),
        publicKey = "no-key-yet",
    )

    /** A sign-up answer from [target], as `onActivityResult` would be handed it. */
    private fun shareAnswerFrom(target: FixtureVault): Intent? =
        target.answer(Utils.createShareIntent(context, pushedEntry(), requestCode = SIGN_UP_REQUEST)).data

    /**
     * Register an activity that handles the share action for the default vault package.
     *
     * `ShareEntryTest:51`'s registration, for its reason: `Intent.resolveActivity` matches with
     * `MATCH_DEFAULT_ONLY`, so a filter without `CATEGORY_DEFAULT` would resolve to nothing here
     * and a real vault's filter has to carry it too.
     */
    private fun installVault() {
        val target = Utils.DEFAULT_ENDEAVOR_PACKAGE
        val component = ComponentName(target, "$target.ShareActivity")
        shadowOf(context.packageManager).addActivityIfNotPresent(component)
        shadowOf(context.packageManager).addIntentFilterForActivity(
            component,
            IntentFilter(Utils.shareDataAction(target)).apply {
                addCategory(Intent.CATEGORY_DEFAULT)
            },
        )
    }

    /**
     * A context that counts the activities started through it, and still starts them.
     *
     * `ShareEntryTest`'s `FailingContext` counts attempts for the same reason this does: "returned
     * `false`" and "dispatched nothing" are two claims, and a test that asserted only the first
     * would pass against a `shareEntry` that launched the intent anyway.
     */
    private class CountingContext(base: Context) : ContextWrapper(base) {
        var attempts = 0
            private set

        override fun startActivity(intent: Intent?) {
            attempts++
            super.startActivity(intent)
        }
    }

    /** Scene one against [vault], registered in [accounts]. Returns the key to keep. */
    private fun signUpOnTheFixtureVault(): String {
        val result = Utils.parseShareResult(shareAnswerFrom(vault))
        assertNotNull("the fixture vault must answer a sign-up", result)
        val key = result!!.publicKey
        assertNotNull(key)
        accounts.getOrPut(key!!) { "account-${accounts.size + 1}" }
        return key
    }

    // ── The fixture vault ─────────────────────────────────────────────────

    /** What `onActivityResult` is handed: a result code and, perhaps, some data. */
    private class VaultAnswer(val resultCode: Int, val data: Intent?)

    /**
     * Just enough of a vault for the guide's client-side snippets to have something to talk to:
     * this library's request parsers on the way in, its result builders on the way out, which is
     * what the reference vault does and what keeps the two halves of the wire from drifting.
     *
     * [ClientIntegrationExampleTest] is the fuller version of this fixture and the file to read
     * if you are writing a vault. The one hand-built intent here is [refuse], for the reason it
     * gives.
     */
    private class FixtureVault(
        private val keyPair: KeyPair,
        private val profile: Map<String, TypedField>,
    ) {
        /** The public half, and the only thing this vault ever hands out. */
        val publicKey: String = Base64.encodeToString(keyPair.public.encoded, Base64.NO_WRAP)

        /** The user's answer at the consent dialog. */
        var consents: Boolean = true

        private var stored: Entry? = null

        fun answer(request: Intent): VaultAnswer = when (request.action) {
            // A share and a query travel under the same action; the payload is what tells them
            // apart, and the two request parsers are the disambiguation.
            Utils.shareDataAction() ->
                Utils.parseShareRequest(request)?.let(::store)
                    ?: Utils.parseQueryRequest(request)?.let(::disclose)
                    ?: refuse(null)

            Utils.signChallengeAction() ->
                Utils.parseSignChallengeRequest(request)?.let(::sign) ?: refuse(null)

            else -> refuse(null)
        }

        private fun store(request: ShareRequest): VaultAnswer {
            if (!consents) return refuse(request.requestCode)
            // The client's entry declares which fields it wants and what type each one is; the
            // values come from this vault's own form, and the key is the one it minted.
            val created = Entry(
                id = request.entry.id,
                fields = request.entry.fields.mapValues { (key, declared) ->
                    TypedField(value = profile[key]?.value ?: "", type = declared.type)
                },
                publicKey = publicKey,
            )
            stored = created
            return VaultAnswer(
                Activity.RESULT_OK,
                Utils.createShareResultIntent(request, publicKey, created.fields),
            )
        }

        private fun disclose(request: QueryRequest): VaultAnswer {
            val held = stored?.fields
            // An unknown key and a refused consent collapse into one answer on purpose:
            // answering "no such profile" tells the caller a profile exists for every key it is
            // not told that about.
            if (held == null || !consents || request.publicKey != publicKey) {
                return refuse(request.requestCode)
            }
            return VaultAnswer(
                Activity.RESULT_OK,
                Utils.createQueryResultIntent(request, publicKey, held),
            )
        }

        private fun sign(request: SignChallengeRequest): VaultAnswer {
            val held = stored
            if (held == null || !consents || request.publicKey != publicKey) {
                return refuse(request.requestCode)
            }
            // The check a signing device owes every signature it makes: these bytes are whatever
            // the caller chose, and they could be a signed statement's pre-image rather than a
            // challenge. Only this side can tell the two apart.
            if (Utils.isStatementPreImage(request.nonce)) return refuse(request.requestCode)
            val signature = Signature.getInstance(SIGN_ALGORITHM).run {
                initSign(keyPair.private)
                update(request.nonce)
                sign()
            }
            return VaultAnswer(
                Activity.RESULT_OK,
                Utils.createSignChallengeResultIntent(request, signature, held.fields, SIGN_ALGORITHM),
            )
        }

        /**
         * A refusal as a vault sends one today: `RESULT_CANCELED` carrying the echoed request
         * code and nothing else. Hand-built on purpose — every result builder in this library
         * attaches `extra_protocol_version` unconditionally, and a refusal honoured nothing, so
         * routing one through a builder would change the wire rather than tidy the fixture.
         */
        private fun refuse(requestCode: String?) = VaultAnswer(
            Activity.RESULT_CANCELED,
            Intent().apply { requestCode?.let { putExtra(Utils.EXTRA_SHARE_REQUEST_CODE, it) } },
        )
    }

    companion object {
        /** Deliberately the same in both profiles below. See the account-identifier rule. */
        private const val PROFILE_EMAIL = "shared@example.com"

        private val PROFILE = linkedMapOf(
            "name" to TypedField("Ada", FieldType.STRING),
            "email" to TypedField(PROFILE_EMAIL, FieldType.EMAIL),
        )

        /** A second person who happens to use the same email address. */
        private val OTHER_PROFILE = linkedMapOf(
            "name" to TypedField("Grace", FieldType.STRING),
            "email" to TypedField(PROFILE_EMAIL, FieldType.EMAIL),
        )

        private const val SIGN_UP_REQUEST = "signup-1"
        private const val QUERY_REQUEST = "query-1"
        private const val LOGIN_REQUEST = "login-1"

        private const val SIGN_ALGORITHM = "SHA256withRSA"

        private lateinit var vaultKeyPair: KeyPair
        private lateinit var otherKeyPair: KeyPair

        /** The public key of a profile this service holds no account for. */
        private lateinit var otherPublicKey: String

        /** 2048-bit RSA generation is slow (~100ms each); do it once for the whole class. */
        @JvmStatic
        @BeforeClass
        fun generateKeys() {
            val generator = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }
            vaultKeyPair = generator.generateKeyPair()
            otherKeyPair = generator.generateKeyPair()
            otherPublicKey = Base64.encodeToString(otherKeyPair.public.encoded, Base64.NO_WRAP)
        }
    }
}
