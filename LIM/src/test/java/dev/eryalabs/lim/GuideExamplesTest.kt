package dev.eryalabs.lim

import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.content.IntentFilter
import android.os.Bundle
import android.os.Parcel
import android.util.Base64
import android.util.Log
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNotSame
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
import java.security.SecureRandom
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

    /**
     * *Required and optional fields*: one field named optional, a vault implementing required
     * fields that lets the user leave it blank, and the handler the guide prints.
     *
     * [RequiredFieldsVault] answers the first call. The user has typed a name and an email and
     * nothing for `phone`, so the vault stores the two and drops the third, and the handler
     * creates the account from [FieldRequirements.committed] with the verdict `HONOURED`. The
     * four controls run the **same** handler against the answers it has to survive: a vault
     * built before required fields, which acknowledges nothing (`NOT_ACKNOWLEDGED`, and its blank
     * `phone` dropped by `committed` rather than stored as `""`); the same vault where the user
     * skipped a required field (`INCOMPLETE`, naming it); an answer that hand-writes the
     * acknowledgement over that incomplete payload (`VIOLATED`); and a complete *query* answer,
     * which this handler cannot read at all. Every assertion is outside the regions.
     */
    @Test
    fun `a sign-up can leave named fields optional and reads what the vault did with them`() {
        // region snippet:signup-optional-request
        // Every field you declare is required unless you name it here. Names match exactly, so
        // a misspelt name is simply not sent and that field stays required. All five arguments
        // are needed, the vault's package included: with no defaults, no shorter call can
        // resolve to this overload, so every call written before it still means what it did.
        val entry = Entry(
            id = "signup-form",
            fields = linkedMapOf(
                "name" to TypedField(value = "", type = FieldType.STRING),
                "email" to TypedField(value = "", type = FieldType.EMAIL),
                "phone" to TypedField(value = "", type = FieldType.PHONE),
            ),
            publicKey = "no-key-yet",
        )
        val requirements = FieldRequirements(entry.fields.keys, setOf("phone"))
        val request = Utils.createShareIntent(
            context,
            entry,
            SIGN_UP_REQUEST,
            requirements.optionalFields,
            Utils.DEFAULT_ENDEAVOR_PACKAGE,
        )
        // startActivityForResult(request, VAULT_RESULT)
        // endregion snippet:signup-optional-request

        val answer = RequiredFieldsVault(vaultKeyPair, PROFILE).answer(request)
        val delivered = answer.data

        // region snippet:signup-optional-result
        // In onActivityResult, once `resultCode` is RESULT_OK and the request code matches.
        fun onSignUpAnswer(data: Intent?) {
            val result = Utils.parseShareResult(data) ?: return
            // Keep the key whatever follows: the profile now exists in the vault, bound to you.
            val accountKey = result.publicKey ?: return
            // Gate on the data, never on a version number. `committed` is null exactly when a
            // required field is missing or blank. It drops a blank optional field too, whether
            // the vault left it out or, as an older vault may, sent it as an empty value.
            val profile = requirements.committed(result.fields)
            when (Utils.checkFieldRequirements(requirements, data)) {
                FieldRequirementsVerdict.HONOURED,
                FieldRequirementsVerdict.MISMATCHED,
                FieldRequirementsVerdict.NOT_ACKNOWLEDGED -> createAccount(accountKey, profile!!)
                FieldRequirementsVerdict.INCOMPLETE ->
                    accountIncomplete(accountKey, requirements.missingRequired(result.fields))
                else -> reportVault(accountKey) // VIOLATED, and any verdict a later release adds
            }
        }
        // endregion snippet:signup-optional-result

        onSignUpAnswer(delivered)
        assertEquals(Activity.RESULT_OK, answer.resultCode)
        assertTrue("the request names the optional field", request.hasExtra(Utils.EXTRA_OPTIONAL_FIELDS))
        assertEquals(
            "a vault implementing required fields stores what was filled in, and the handler " +
                "creates the account from exactly that",
            listOf("created [name, email]"),
            signUpOutcomes,
        )
        assertEquals(
            FieldRequirementsVerdict.HONOURED,
            Utils.checkFieldRequirements(requirements, delivered),
        )
        assertFalse(
            "phone was left blank, so it is absent rather than an empty value",
            "phone" in Utils.parseShareResult(delivered)!!.fields,
        )

        // An older vault answers the same request: no acknowledgement, and its blank `phone` comes
        // back as an empty value, which `committed` drops rather than keeps.
        signUpOutcomes.clear()
        val older = FixtureVault(vaultKeyPair, PROFILE).answer(request).data
        assertEquals("", Utils.parseShareResult(older)!!.fields["phone"]?.value)
        onSignUpAnswer(older)
        assertEquals(listOf("created [name, email]"), signUpOutcomes)
        assertEquals(
            FieldRequirementsVerdict.NOT_ACKNOWLEDGED,
            Utils.checkFieldRequirements(requirements, older),
        )

        // The same older vault where the user skipped a field that was required.
        signUpOutcomes.clear()
        val skipped = FixtureVault(
            vaultKeyPair,
            linkedMapOf("name" to TypedField("Ada", FieldType.STRING)),
        ).answer(request).data
        onSignUpAnswer(skipped)
        assertEquals(listOf("incomplete [email]"), signUpOutcomes)

        // An acknowledgement nobody's builder would write over that payload.
        signUpOutcomes.clear()
        val forged = skipped!!.apply { putExtra(Utils.EXTRA_APPLIED_OPTIONAL_FIELDS, """["phone"]""") }
        onSignUpAnswer(forged)
        assertEquals(listOf("reported"), signUpOutcomes)

        // And the misuse: a *query* answer, disclosing all three fields, handed to this handler.
        // A query's fields travel under another extra, so this handler reads none of them — it
        // keeps the key and calls the account incomplete over a disclosure that had both required
        // fields in it. Reuse one handler for both flows and you re-prompt a user who already
        // consented, for ever. `FieldRequirementsVerdictTest` measures why; this is what it costs.
        signUpOutcomes.clear()
        onSignUpAnswer(
            Utils.createQueryResultIntent(
                FAKE_PUBLIC_KEY,
                linkedMapOf(
                    "name" to TypedField("Ada", FieldType.STRING),
                    "email" to TypedField(PROFILE_EMAIL, FieldType.EMAIL),
                    "phone" to TypedField("555-0100", FieldType.PHONE),
                ),
                SIGN_UP_REQUEST,
            ),
        )
        assertEquals(listOf("incomplete [name, email]"), signUpOutcomes)
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

    /**
     * Login is the one flow that proves something, so it is the one flow whose handler being
     * green on the happy path alone would be an authentication bypass rather than a gap.
     *
     * The guide's `login-result` block is therefore a **function**, and this test calls it four
     * times: on the genuine answer, and on three it must refuse — an expired challenge, another
     * account's stored key, and an answer from a different flow that parses as something else.
     * As straight-line code in a region it could only ever be run once, on the answer it was
     * always going to accept; re-running it meant copying it, which pins nothing.
     *
     * The other two flows' blocks are deliberately left as they are. A share or a query answer is
     * data a user consented to disclose; a login answer is a proof, and the refusal paths worth
     * executing are the ones where accepting a bad answer authenticates somebody.
     *
     * `SignatureVerificationTest` and `NonceTest` own the full behaviour of the two calls this
     * handler leans on, and `DecoderFuzzTest` owns what an arbitrary intent does to the parsers.
     * What is new here is only that the *published handler*, as printed, refuses.
     */
    @Test
    fun `login proves the holder of the stored key is present, and refuses three answers`() {
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

        // region snippet:login-result
        // In onActivityResult — and a function, not four lines inline, because this is the one
        // handler worth running in your own tests against answers it must refuse. Verify
        // against the key your account table already holds and the challenge you generated,
        // never against either one read back out of the result, or the sender gets to choose
        // both sides of the proof.
        fun loginSucceeded(
            resultCode: Int,
            data: Intent?,
            storedKey: String,
            challenge: ByteArray,
        ): Boolean {
            val result = Utils.parseSignChallengeResult(data)
            return resultCode == Activity.RESULT_OK &&
                Utils.matchesRequestCode(data, LOGIN_REQUEST) &&
                Utils.isNonceFresh(challenge, maxAgeMillis = 60_000L) &&
                result?.isVerified(storedKey, challenge) == true
        }
        // endregion snippet:login-result

        assertTrue(
            "the genuine answer logs this profile in",
            loginSucceeded(answer.resultCode, answer.data, storedPublicKey, nonce),
        )

        val parsed = Utils.parseSignChallengeResult(answer.data)
        assertNotNull(parsed)
        assertFalse(
            "the same signature proves nothing about any other key",
            parsed!!.isVerified(otherPublicKey, nonce),
        )
        assertFalse(
            "nor about a challenge it did not answer — this is the replay the nonce stops",
            parsed.isVerified(storedPublicKey, Utils.generateNonce()),
        )

        // Refusal 1: an expired challenge. Staleness is minted, never slept for — both halves
        // take the clock, so a challenge stamped two minutes before now is older than the
        // block's own 60-second window by construction. It is the *stale* nonce the vault
        // signs: a nonce nobody signed would be refused on the signature instead and would
        // prove nothing about freshness.
        val staleNonce = Utils.generateNonce(SecureRandom(), System.currentTimeMillis() - 120_000L)
        val staleAnswer = vault.answer(
            Utils.createSignChallengeIntent(
                context,
                storedPublicKey,
                staleNonce,
                LOGIN_REQUEST,
                nonceFormat = Utils.NONCE_FORMAT_TIMESTAMPED,
            ),
        )
        assertEquals("precondition: the vault answered it", Activity.RESULT_OK, staleAnswer.resultCode)
        assertTrue(
            "control: the signature over the stale challenge is genuine, so the refusal below " +
                "is about the window and nothing else — without this pairing it could as well " +
                "be a broken signature",
            Utils.parseSignChallengeResult(staleAnswer.data)!!.isVerified(storedPublicKey, staleNonce),
        )
        assertFalse(
            "and an expired challenge logs nobody in, however genuine the signature over it",
            loginSucceeded(staleAnswer.resultCode, staleAnswer.data, storedPublicKey, staleNonce),
        )

        // Refusal 2: the genuine answer, checked against an account this service holds no
        // signature for. Nothing about the intent changes; the stored key does.
        assertFalse(
            "the genuine answer authenticates nobody against another account's stored key",
            loginSucceeded(answer.resultCode, answer.data, otherPublicKey, nonce),
        )

        // Refusal 3: an answer from a different flow — a share result, which carries a public
        // key the handler must not read. `LOGIN_REQUEST` is echoed on it **on purpose**: a
        // hostile sender would echo it, and without it the handler would refuse at
        // `matchesRequestCode` and prove nothing about the clause this call is named for. The
        // refusal has to land at the parse, so do not simplify the fixture.
        val wrongFlow = Utils.createShareResultIntent(
            publicKey = storedPublicKey,
            fields = linkedMapOf("email" to TypedField(value = PROFILE_EMAIL, type = FieldType.EMAIL)),
            requestCode = LOGIN_REQUEST,
        )
        assertTrue(
            "precondition: it correlates, so the handler gets as far as the parse",
            Utils.matchesRequestCode(wrongFlow, LOGIN_REQUEST),
        )
        assertEquals(
            "precondition: and it is a perfectly good answer of its own flow",
            storedPublicKey,
            Utils.parseShareResult(wrongFlow)?.publicKey,
        )
        assertNull(
            "…which the login parser reads as nothing at all",
            Utils.parseSignChallengeResult(wrongFlow),
        )
        assertFalse(
            "a share answer carrying a public key authenticates nobody, and nothing is thrown",
            loginSucceeded(Activity.RESULT_OK, wrongFlow, storedPublicKey, nonce),
        )
    }

    // ── Surviving process death ───────────────────────────────────────────

    /**
     * The wall that is invisible on a desk and routine in the field: while the vault's consent
     * dialog is in the foreground the client app is in the background, and Android may kill it.
     *
     * [SignChallengeResult.isVerified] takes **the exact bytes that were sent**, so an activity
     * that kept its challenge in a field comes back to nothing and one that regenerates comes back
     * to the wrong bytes. Either way the login fails, intermittently and only on some devices —
     * the class of bug an afternoon integration never finds and blames the library for.
     *
     * **The death is a real one, not a hand-off.** The `Bundle` is written to a [Parcel] and read
     * back out of it — `EntryParcelTest:21-29`'s shape, for the same reason — and the assertions
     * below check that it travelled as bytes rather than as a reference. Passing the same `Bundle`
     * object along would satisfy every other assertion here and prove nothing at all.
     *
     * What the section argues is the **contrast**, so both halves are asserted: the vault's answer
     * verifies against the challenge that survived, and does not verify against a freshly generated
     * one. `SignatureVerificationTest` owns the full behaviour of that call; what is new here is
     * only that the bytes a saved `Bundle` gives back are still the bytes it proves.
     *
     * **Saved state answers one clause of the login handler and not the other.** A restored
     * challenge satisfies `isVerified`; it carries its own timestamp, so it goes on ageing while
     * the activity is dead and `isNonceFresh` can still refuse it. Both directions are asserted,
     * with the clock injected rather than waited for: the challenge this test restores is fresh
     * now, and the *same* restored bytes judged an hour later verify and are refused anyway. That
     * pairing is what backs the section's sentence about an app resumed from recents.
     *
     * The restored request code is deliberately **not** asserted, and the guide says so: the
     * guide's own request codes are constants, so the `putString` line is there for an app that
     * *mints* a correlation token per request, and no test here can make a claim about an app that
     * does not exist. What that leaves unpinned is the line's own mechanics — a save under the
     * wrong key would reach the guide unnoticed — which is recorded in T48's Progress entry as a
     * planning candidate rather than widened into here.
     */
    @Test
    fun `a challenge that outlives the process still verifies, and a regenerated one never does`() {
        val storedPublicKey = signUpOnTheFixtureVault()
        val nonce = Utils.generateNonce()
        val request = Utils.createSignChallengeIntent(
            context,
            storedPublicKey,
            nonce,
            LOGIN_REQUEST,
            nonceFormat = Utils.NONCE_FORMAT_TIMESTAMPED,
        )

        // region snippet:saved-state
        // While the vault's dialog is up your activity is in the background, where Android may
        // kill it. What comes back is a new object: the field you kept the challenge in is
        // empty, and `isVerified` takes the exact bytes you sent, so a challenge you regenerate
        // instead verifies nothing. Save it.
        fun saveLoginState(outState: Bundle, challenge: ByteArray, requestCode: String) {
            outState.putByteArray(STATE_CHALLENGE, challenge)
            // Only if your app mints a correlation token per request rather than declaring one
            // as a constant — a constant is back in your code without ever being saved.
            outState.putString(STATE_REQUEST_CODE, requestCode)
        }

        // In onCreate, or onRestoreInstanceState, before any answer is handled. A null is an
        // activity that had no login in flight, which is not a failure.
        fun restoreChallenge(savedInstanceState: Bundle?): ByteArray? =
            savedInstanceState?.getByteArray(STATE_CHALLENGE)
        // endregion snippet:saved-state

        val outState = Bundle().also { saveLoginState(it, nonce, LOGIN_REQUEST) }
        val parcel = Parcel.obtain()
        val revived = try {
            parcel.writeBundle(outState)
            assertTrue(
                "precondition: saved state has to leave as bytes. The bound is the challenge's " +
                    "own length rather than zero, because an empty Bundle also writes a magic " +
                    "number and a count and would satisfy `> 0` — what rules out a hand-off is " +
                    "the identity check further down, not this line",
                parcel.dataSize() > nonce.size,
            )
            parcel.setDataPosition(0)
            parcel.readBundle()
        } finally {
            parcel.recycle()
        }
        assertNotNull("precondition: …and come back as a Bundle", revived)

        val restored = restoreChallenge(revived)
        assertNotNull("the challenge outlived the process that minted it", restored)
        assertNotSame(
            "…and it came back through the parcel rather than by reference: a test that handed " +
                "the same Bundle object along would pass every assertion here and prove nothing",
            nonce,
            restored,
        )
        assertArrayEquals("…as the very same bytes, which is all that matters", nonce, restored)

        val answer = vault.answer(request)
        val result = Utils.parseSignChallengeResult(answer.data)
        assertNotNull("precondition: the vault signed the challenge", result)
        assertTrue(
            "the answer verifies against the challenge that survived: saved state answers the " +
                "`isVerified` clause of the login handler, which is the one process death breaks",
            result!!.isVerified(storedPublicKey, restored!!),
        )
        assertFalse(
            "and against a freshly generated challenge it verifies nothing — the hazard an " +
                "activity that regenerates instead of restoring walks into, and the whole " +
                "argument of the section",
            result.isVerified(storedPublicKey, Utils.generateNonce()),
        )
        assertTrue(
            "…and the restored bytes still have to clear the *other* clause: a challenge carries " +
                "its own timestamp, so surviving the process does not stop it ageing out. This " +
                "one is seconds old, so it clears the window the handler applies",
            Utils.isNonceFresh(restored, maxAgeMillis = 60_000L),
        )
        assertFalse(
            "…while the same restored bytes, judged an hour later, verify and are refused anyway. " +
                "The clock is injected rather than waited for, and this is the pairing that makes " +
                "the section's sentence about recents an assertion instead of a promise",
            Utils.isNonceFresh(
                restored,
                maxAgeMillis = 60_000L,
                now = System.currentTimeMillis() + 3_600_000L,
            ),
        )

        assertNull(
            "an activity that had no login in flight restores nothing rather than throwing",
            restoreChallenge(Bundle()),
        )
        assertNull("…and neither does one recreated with no saved state at all", restoreChallenge(null))
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

    // ── Testing your integration without a vault ──────────────────────────

    /**
     * The second hour of the afternoon. The first is the request; this is the test that proves the
     * `onActivityResult` half works, on a build machine with no vault installed on it.
     *
     * The machinery is already here and was already published: [Utils.createShareResultIntent] is
     * one of the three result builders [FixtureVault] above calls on the way out, so an integrator's
     * own test can mint the answer their handler will be handed. What the two regions cannot assert
     * about themselves, and this function therefore asserts outside them:
     *
     *  - the built answer is a *real* answer rather than an intent that happens to parse — the key
     *    comes back out as it went in and the echoed request code correlates, neither of which an
     *    empty envelope could do;
     *  - the diagnosis line the second block tells an integrator to log carries no value the user
     *    disclosed *under the key that carries one*. The field value asserted absent is spelled to
     *    collide with nothing any renderer in [Utils.describeIntent] emits: a short value like
     *    `"1"` is a substring of `1 field`, of a byte count and of the protocol version, and
     *    asserting its absence would manufacture a leak that is not there. The limit on that
     *    claim, which the snippet states rather than hides, is the four tokens the line prints
     *    close to verbatim — a peer that files personal data under one of those is printed as it
     *    wrote it, and `Utils.describeIntent`'s own KDoc is where that trade-off is argued.
     *
     * `ResultBuilderTest` pins the builder extra by extra and `IntentDescriptionTest` pins the
     * description; this file's subject is only the published prose, so it repeats neither.
     */
    @Test
    fun `an integrator tests their own handler, and describes an answer that will not parse`() {
        // region snippet:testing-your-handler
        // Factor the `onActivityResult` half into something a unit test can call. This library's
        // own result builders mint the answer, so the test needs no vault, no device and no
        // keystore — but it does need Robolectric: `Intent` is an unimplemented stub in a plain
        // JVM unit test, and constructing one there throws rather than failing an assertion.
        fun onVaultAnswer(resultCode: Int, data: Intent?): String? {
            if (resultCode != Activity.RESULT_OK) return null
            if (!Utils.matchesRequestCode(data, SIGN_UP_REQUEST)) return null
            return Utils.parseShareResult(data)?.publicKey
        }

        // The answer a consenting vault sends after a sign-up.
        val answer = Utils.createShareResultIntent(
            publicKey = FAKE_PUBLIC_KEY,
            fields = linkedMapOf(
                "email" to TypedField(value = FAKE_EMAIL, type = FieldType.EMAIL),
            ),
            requestCode = SIGN_UP_REQUEST,
        )
        val accountKey = onVaultAnswer(Activity.RESULT_OK, answer)
        // endregion snippet:testing-your-handler

        assertEquals(
            "the handler keeps the key the builder was given",
            FAKE_PUBLIC_KEY,
            accountKey,
        )
        assertTrue(
            "…and the built answer is a real answer, not an intent that merely parses: it " +
                "correlates with the request code it echoed, which an empty envelope cannot do",
            Utils.matchesRequestCode(answer, SIGN_UP_REQUEST),
        )
        assertNull(
            "control: the same handler keeps nothing when the vault refused",
            onVaultAnswer(Activity.RESULT_CANCELED, answer),
        )

        // region snippet:testing-diagnosis
        // When a parse returns null and it is not obvious why, describe the intent rather than
        // guess. One line: the action, the package, the state of every extra the protocol
        // defines, and last the flows this library's own parsers accept it as.
        val proof = Utils.parseSignChallengeResult(answer)
        if (proof == null) {
            Log.w("MyApp", Utils.describeIntent(answer))
            // `shareResult` is in that `flows=[…]` set and `signChallengeResult` is not: this is
            // a share answer, nothing signed it, and the login parser was never going to read
            // it. Route on the parser that returned the null — never on this wording, which is
            // prose for a human and is not wire format.
        }
        // Safe to log, with one limit worth knowing. The keys that carry a user's data are
        // reduced — a field payload to a count, a nonce and a signature to byte lengths — and the
        // public key is truncated rather than hidden, because it is the handle this design hands
        // out freely. But the four protocol tokens the line quotes are printed as the sender
        // wrote them, so a peer that files personal data under one of those puts it on your line.
        // That is the peer's bug; `describeIntent`'s own KDoc says so and caps the width.
        // endregion snippet:testing-diagnosis

        assertNull("precondition: a share answer is not a login answer", proof)
        val described = Utils.describeIntent(answer)
        assertTrue(
            "the diagnosis names the flow that would have parsed it: $described",
            described.contains("shareResult"),
        )
        assertFalse(
            "and does not name the one that did not: $described",
            described.contains("signChallengeResult"),
        )
        assertFalse(
            "the line an integrator is told to log must carry no value disclosed under the key " +
                "that carries one — the field payload is reduced to a count. The value looked " +
                "for here is spelled to collide with nothing any renderer in `describeIntent` " +
                "emits, so a hit would be a leak rather than a collision with `1 field`, a byte " +
                "count or the protocol version: $described",
            described.contains(FAKE_EMAIL),
        )
    }

    /**
     * The same section's third block: the answer a vault implementing required fields sends,
     * minted in an integrator's own test with the vault-side functions this library publishes.
     *
     * The request and the requirements are the ones *Required and optional fields* builds, set up
     * outside the region because the guide has already shown them. What the region cannot assert
     * about itself is asserted below it: the verdict is `HONOURED`, the applied set is the one the
     * client declared, and the same builder over a payload missing a required field writes no
     * acknowledgement at all — so the verdict the test sees is the one a real vault produces, not
     * one the builder hands out regardless.
     */
    @Test
    fun `an integrator meets the optional-field verdict their handler will get, with no vault`() {
        val entry = optionalPhoneEntry()
        val requirements = FieldRequirements(entry.fields.keys, setOf("phone"))
        val request = Utils.createShareIntent(
            context,
            entry,
            SIGN_UP_REQUEST,
            requirements.optionalFields,
            Utils.DEFAULT_ENDEAVOR_PACKAGE,
        )

        // region snippet:testing-optional-fields
        // A vault that implements required fields reads your declaration off the request, stores
        // what the user filled in, and acknowledges the declaration only when what it stored
        // satisfies it. Build that answer and your handler meets the verdict it will really get:
        // here the user filled in both required fields and left the optional "phone" blank.
        val declared = Utils.parseFieldRequirements(request)!!
        val answer = Utils.createShareResultIntent(
            FAKE_PUBLIC_KEY,
            linkedMapOf(
                "name" to TypedField(value = "Ada", type = FieldType.STRING),
                "email" to TypedField(value = FAKE_EMAIL, type = FieldType.EMAIL),
            ),
            SIGN_UP_REQUEST,
            declared,
        )
        val verdict = Utils.checkFieldRequirements(requirements, answer)
        // The optional set the vault says it applied. `null` means the answer acknowledges
        // nothing: a vault older than this release, one answering through the builder that
        // writes none, or one whose payload did not satisfy your declaration, with a required
        // field missing or a blank value left in.
        val applied = Utils.parseAppliedOptionalFields(answer)
        // endregion snippet:testing-optional-fields

        assertEquals("the vault read what the client declared", requirements, declared)
        assertEquals(FieldRequirementsVerdict.HONOURED, verdict)
        assertEquals(setOf("phone"), applied)
        assertTrue(Utils.matchesRequestCode(answer, SIGN_UP_REQUEST))

        val missingAName = Utils.createShareResultIntent(
            FAKE_PUBLIC_KEY,
            linkedMapOf("email" to TypedField(value = FAKE_EMAIL, type = FieldType.EMAIL)),
            SIGN_UP_REQUEST,
            declared,
        )
        assertNull(
            "control: over a payload missing a required field the same builder acknowledges " +
                "nothing, so the HONOURED above was earned rather than handed out",
            Utils.parseAppliedOptionalFields(missingAName),
        )
        assertEquals(
            FieldRequirementsVerdict.INCOMPLETE,
            Utils.checkFieldRequirements(requirements, missingAName),
        )
    }

    // ── Shared setup, all of it outside the regions ───────────────────────

    /** What *Required and optional fields*' handler did, one line per call. */
    private val signUpOutcomes = mutableListOf<String>()

    /** The handler's three outcomes, recorded so the test can say which one it took. */
    private fun createAccount(accountKey: String, profile: Map<String, TypedField>) {
        accounts.getOrPut(accountKey) { "account-${accounts.size + 1}" }
        signUpOutcomes += "created ${profile.keys.toList()}"
    }

    private fun accountIncomplete(accountKey: String, missing: List<String>) {
        accounts.getOrPut(accountKey) { "account-${accounts.size + 1}" }
        signUpOutcomes += "incomplete $missing"
    }

    private fun reportVault(@Suppress("UNUSED_PARAMETER") accountKey: String) {
        signUpOutcomes += "reported"
    }

    /** The guide's optional-field sign-up entry, for the test that does not re-print it. */
    private fun optionalPhoneEntry() = Entry(
        id = "signup-form",
        fields = linkedMapOf(
            "name" to TypedField(value = "", type = FieldType.STRING),
            "email" to TypedField(value = "", type = FieldType.EMAIL),
            "phone" to TypedField(value = "", type = FieldType.PHONE),
        ),
        publicKey = "no-key-yet",
    )

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

    /**
     * Just enough of a vault implementing required fields for *Required and optional fields* to
     * have something to talk to — the sign-up half only, which is all that section shows.
     *
     * What the user typed is [profile]; a declared field it has no value for is one the user left
     * blank. The vault reads the declaration with [Utils.parseFieldRequirements], keeps Save
     * blocked while a required field is blank (the user backs out, and the client sees a refusal),
     * stores [FieldRequirements.committed], and answers through the requirements-aware builder.
     * `ClientIntegrationExampleTest` and `RequirementsCompatibilityMatrixTest` hold the fuller
     * versions of this.
     */
    private class RequiredFieldsVault(
        keyPair: KeyPair,
        private val profile: Map<String, TypedField>,
    ) {
        private val publicKey: String = Base64.encodeToString(keyPair.public.encoded, Base64.NO_WRAP)

        fun answer(request: Intent): VaultAnswer {
            val share = Utils.parseShareRequest(request)
                ?: return VaultAnswer(Activity.RESULT_CANCELED, null)
            val requirements = Utils.parseFieldRequirements(request)
                ?: return VaultAnswer(Activity.RESULT_CANCELED, null)
            val draft = requirements.fieldNames.associateWith { name ->
                TypedField(profile[name]?.value ?: "", share.entry.fields.getValue(name).type)
            }
            if (requirements.missingRequired(draft).isNotEmpty()) {
                return VaultAnswer(
                    Activity.RESULT_CANCELED,
                    Intent().apply {
                        share.requestCode?.let { putExtra(Utils.EXTRA_SHARE_REQUEST_CODE, it) }
                    },
                )
            }
            val stored = requirements.committed(draft)!!
            return VaultAnswer(
                Activity.RESULT_OK,
                Utils.createShareResultIntent(publicKey, stored, share.requestCode, requirements),
            )
        }
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

        /**
         * An app's own saved-state keys, which is all they are: nothing in this library reads
         * them, and no wire format is involved. Spelled out here rather than in the region for the
         * reason the request codes are — a snippet shows an integrator's code, and these are the
         * one part of it their own app names.
         */
        private const val STATE_CHALLENGE = "login-challenge"
        private const val STATE_REQUEST_CODE = "login-request-code"

        private const val SIGN_ALGORITHM = "SHA256withRSA"

        /**
         * The stand-in key an integrator's own test puts in a built answer.
         *
         * Not a real one, and it does not have to be: the handler under test stores whatever the
         * result carried and verifies nothing, which is the point of the section. A *login* test
         * needs a genuine keypair, and `ClientIntegrationExampleTest` is the file for that.
         */
        private const val FAKE_PUBLIC_KEY = "a-fake-public-key-from-a-test"

        /**
         * A disclosed value distinctive enough that finding it in a diagnosis line is evidence.
         *
         * `describeIntent` renders a field payload as a count, so this must never appear in it.
         * Asserting that of a short value would prove nothing — `"1"` is a substring of `1 field`,
         * of a byte count and of the protocol version — so it is spelled to collide with nothing
         * any renderer in that function emits.
         */
        private const val FAKE_EMAIL = "qwyx-zarquon-73f1@example.invalid"

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
