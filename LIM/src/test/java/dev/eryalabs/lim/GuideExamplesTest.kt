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
import org.junit.Assert.assertNotEquals
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
     * creates the account from [FieldRequirements.committed] with the verdict `HONOURED`.
     *
     * **The printed handler is driven fourteen times in all, and every assertion is outside the
     * regions.** Four more answers carry data it reads: a vault built before required fields,
     * which acknowledges nothing (`NOT_ACKNOWLEDGED`, and its blank `phone` dropped by
     * `committed` rather than stored as `""`); the same vault where the user skipped a required
     * field (`INCOMPLETE`, naming it); an answer that hand-writes the acknowledgement over that
     * incomplete payload (`VIOLATED`); and a complete *query* answer, which this handler cannot
     * read at all.
     *
     * **Four are answers it refuses, and each names the clause that refused it** — until they
     * were driven here, neither of the handler's two early returns had ever been the clause that
     * returned. Grouped here by that clause rather than in the order the body drives them: `null`
     * data and [RequiredFieldsVault]'s unreadable-request refusal stop at `parseShareResult`
     * returning `null`. The refusal the guide promises an integrator — a user who will not fill a
     * required field backs out, and it arrives as `RESULT_CANCELED` carrying the echoed request
     * code and nothing else — *parses*, so the absent `publicKey` is the clause that stops it;
     * and a **login** answer parses too. That last one is the sharper misuse: a
     * login answer's fields travel under the share flow's key, so [Utils.checkFieldRequirements]
     * reads it as a *complete* sign-up and the only thing between it and `createAccount` is the
     * missing key. It stays a misuse rather than a hole in the protocol because the guide's own
     * preamble checks the result code and the correlation first, and [Utils.matchesRequestCode]
     * is asserted `false` about that answer here.
     *
     * **Three of the last five calls are controls, the fourth is a fifth input and the last is its
     * control** — said that way round because a header reading "the last five are controls" would
     * be the very thing this paragraph is here to stop. The `HONOURED` answer is re-driven *after*
     * the four silent ones, so "recorded nothing" cannot be a broken recorder. Then each of the
     * two answers that *parsed* is re-driven with a key put on it, which is what makes those two
     * silences the absent key and not the result code — this handler never reads one: the refusal
     * reaches `INCOMPLETE`, and the login answer reaches `createAccount` and records what a
     * genuine sign-up records, so the sentence above is driven rather than inferred. The input is
     * the one verdict arm no call had ever taken, `MISMATCHED` — the complete answer acknowledging
     * a *different* optional set — and its control is the same answer acknowledging the declared
     * one, which is `HONOURED` down the same arm and records the same line, so the pair measures
     * the arm's identity rather than the branch the two share.
     *
     * **One path this handler cannot be shown, stated rather than implied.** The key-only profile
     * the guide promises — every field optional, every one left blank, `HONOURED` over an empty
     * field map — needs a different declaration, and the printed handler closes over the one
     * declared below. `RequirementsCompatibilityMatrixTest:379-400` pins that path end to end
     * instead.
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

        // Everything above hands this handler something it can read. Neither of its two early
        // returns has ever been the clause that refused, so the four answers below are the ones
        // that make them fire — and each asserts *which* one fired rather than reasoning about it.
        // The two are named by their expressions and never by a line number: this file's line
        // numbers move whenever anything above them does, and a stale attribution in an assertion
        // message is a lie told at exactly the moment somebody needs it to be true.

        // `onActivityResult` with no data at all. Nothing recorded, nothing thrown, and the parse
        // is asserted beside it so the clause that refused is measured rather than reasoned.
        signUpOutcomes.clear()
        onSignUpAnswer(null)
        assertEquals("a null answer records no outcome at all", emptyList<String>(), signUpOutcomes)
        assertNull(
            "and `parseShareResult(data) ?: return` is the clause that refused it",
            Utils.parseShareResult(null),
        )

        // The refusal the guide promises: the user will not fill a required field, backs out, and
        // this is what reaches the client. `RequiredFieldsVault` sends the shape `FixtureVault`
        // does — `RESULT_CANCELED`, the echoed request code, nothing else.
        signUpOutcomes.clear()
        val unwilling = RequiredFieldsVault(
            vaultKeyPair,
            linkedMapOf("email" to TypedField(PROFILE_EMAIL, FieldType.EMAIL)),
        ).answer(request)
        assertEquals(Activity.RESULT_CANCELED, unwilling.resultCode)
        val refusal = unwilling.data
        assertEquals(
            "a refusal carries the echoed request code and nothing else",
            setOf(Utils.EXTRA_SHARE_REQUEST_CODE),
            refusal!!.extras!!.keySet(),
        )
        onSignUpAnswer(refusal)
        assertEquals(emptyList<String>(), signUpOutcomes)
        assertNotNull(
            "the request code alone makes a refusal parse, so `parseShareResult(data) ?: return` " +
                "passed over it",
            Utils.parseShareResult(refusal),
        )
        assertNull(
            "and the absent key is what refused it — `result.publicKey ?: return`, which nothing " +
                "had reached before now",
            Utils.parseShareResult(refusal)!!.publicKey,
        )

        // The same vault's other refusal: a request it could not read at all, answered with no
        // intent. The null input again, arriving from a fixture rather than from a literal.
        signUpOutcomes.clear()
        val unreadable = RequiredFieldsVault(vaultKeyPair, PROFILE).answer(Intent())
        assertEquals(Activity.RESULT_CANCELED, unreadable.resultCode)
        assertNull("that refusal carries no intent", unreadable.data)
        onSignUpAnswer(unreadable.data)
        assertEquals(emptyList<String>(), signUpOutcomes)

        // And a *login* answer, handed to the sign-up handler. A login answer's fields travel
        // under the share flow's key, so it parses as a keyless share result and the verdict reads
        // its payload as a complete sign-up: the only thing between it and `createAccount` is the
        // key it does not carry. The guide's preamble checks the result code and the correlation
        // first, and this answer echoes a *login* request code — so this is the misuse where
        // neither was done, not a hole in the protocol.
        signUpOutcomes.clear()
        val storedKey = signUpOnTheFixtureVault()
        val loginAnswer = vault.answer(
            Utils.createSignChallengeIntent(context, storedKey, Utils.generateNonce(), LOGIN_REQUEST),
        ).data
        onSignUpAnswer(loginAnswer)
        assertEquals(emptyList<String>(), signUpOutcomes)
        assertNotNull("a login answer parses as a share result", Utils.parseShareResult(loginAnswer))
        assertNull(
            "without a key, which is the only thing that refuses it",
            Utils.parseShareResult(loginAnswer)!!.publicKey,
        )
        assertEquals(
            "the verdict reads a login answer's fields as a complete sign-up",
            FieldRequirementsVerdict.NOT_ACKNOWLEDGED,
            Utils.checkFieldRequirements(requirements, loginAnswer),
        )
        assertFalse(
            "the correlation the guide checks first would have refused it, which is what makes " +
                "this a misuse rather than a protocol hole",
            Utils.matchesRequestCode(loginAnswer, SIGN_UP_REQUEST),
        )

        // Control: the first answer re-driven, *after* the four silent calls. Without it every
        // "records nothing" above could be passing because the recorder stopped recording.
        signUpOutcomes.clear()
        onSignUpAnswer(delivered)
        assertEquals(
            "the recorder still records, so the four silences above are the handler's",
            listOf("created [name, email]"),
            signUpOutcomes,
        )

        // Control: the same refusal with a key put on it reaches the verdict. That is what says
        // the silence above was the absent key and not the result code — which this handler,
        // printed as the guide prints it, never reads.
        signUpOutcomes.clear()
        onSignUpAnswer(refusal.apply { putExtra(Utils.EXTRA_PUBLIC_KEY, FAKE_PUBLIC_KEY) })
        assertEquals(listOf("incomplete [name, email]"), signUpOutcomes)

        // Control: the login answer with a key put on it the same way, and this is the one worth
        // looking at. It does not merely reach the verdict — it reaches `createAccount`, and
        // records the same line a genuine sign-up records. That is the claim above, driven rather
        // than inferred: the only thing between a login answer and a created account is the key it
        // does not carry, so a handler that skipped the result code and the correlation would read
        // an answer that authenticated nothing as a successful sign-up.
        signUpOutcomes.clear()
        onSignUpAnswer(loginAnswer!!.apply { putExtra(Utils.EXTRA_PUBLIC_KEY, FAKE_PUBLIC_KEY) })
        assertEquals(listOf("created [name, email]"), signUpOutcomes)

        // `MISMATCHED`: the older vault's complete answer, acknowledging an optional set that is
        // not the one declared. No call had ever taken this arm, so the three-way grouping at the
        // top of the `when` was assumed rather than measured.
        signUpOutcomes.clear()
        val acknowledgedWrong = older!!.apply {
            putExtra(Utils.EXTRA_APPLIED_OPTIONAL_FIELDS, """["name"]""")
        }
        assertEquals(
            FieldRequirementsVerdict.MISMATCHED,
            Utils.checkFieldRequirements(requirements, acknowledgedWrong),
        )
        onSignUpAnswer(acknowledgedWrong)
        assertEquals(listOf("created [name, email]"), signUpOutcomes)

        // Control: the same answer acknowledging the set that *was* declared. Same arm, same
        // recorded line, different verdict — so the call above measures the arm's identity rather
        // than just the branch it shares with `HONOURED`.
        signUpOutcomes.clear()
        acknowledgedWrong.putExtra(Utils.EXTRA_APPLIED_OPTIONAL_FIELDS, """["phone"]""")
        assertEquals(
            FieldRequirementsVerdict.HONOURED,
            Utils.checkFieldRequirements(requirements, acknowledgedWrong),
        )
        onSignUpAnswer(acknowledgedWrong)
        assertEquals(listOf("created [name, email]"), signUpOutcomes)
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

    /**
     * *When the answer comes back short*: the same query, answered with one field where two were
     * stored.
     *
     * This is not a vault misbehaving. Consent is per disclosure, so [FixtureVault.discloses] is
     * the user releasing the name this time and holding the email back, and the answer is still
     * built by [Utils.createQueryResultIntent] like every other one here.
     *
     * The guide's block is a **function** for the reason `login-result` is: the claim is that it
     * survives answers it must not take at face value, and straight-line code could only ever meet
     * the one answer it was written for. Six answers run through it:
     *
     *  1. the short one — one field where two were stored;
     *  2. the whole profile, without which the check could be failing for every input and every
     *     other assertion here would still pass;
     *  3. an over-disclosing vault's answer carrying a field this screen never declared, which
     *     [FieldRequirements.committed] drops rather than stores — the property that stops a vault
     *     putting a key of its choosing into a client's profile table;
     *  4. a field sent **blank** rather than omitted, which has to take the same branch as an
     *     absent one or the block's "absent — or blank" is a guess about which vault answered;
     *  5. `null`, the answer an app gets when there is none;
     *  6. a refusal, which parses to no fields at all.
     *
     * The outcome is asserted by **name** — `[email]`, not "something was missing" — because
     * "which field is short" is the only version of this a user can be told about, and a handler
     * that merely knew the answer was incomplete would pass an emptiness check just as well.
     *
     * The last assertions are the edge the section warns about and this handler does not reach:
     * with **nothing** required there is no required field left to be short, so `committed` of an
     * answer that parsed to nothing is an empty map rather than `null`, and a refusal would read
     * as a stored profile with nothing in it. The **result code** is what refuses that, and only
     * it: a refusal is still correlated — `a refusal is still correlated` below pins that — so
     * `matchesRequestCode` says `true` about one. Which is why the printed block's first line is
     * the precondition rather than a remark.
     *
     * [Utils.checkFieldRequirements] is deliberately not in the handler: it reads the sign-up
     * fields key and only that, so a query answer reaches it carrying nothing.
     * `FieldRequirementsVerdictTest` measures both arms of that over a real query answer, and the
     * guide's prose cites it rather than repeating the measurement here.
     */
    @Test
    fun `a query answer can disclose less than was stored, and the handler names what is short`() {
        val accountKey = signUpOnTheFixtureVault()
        // The user releases the name this time and not the email.
        vault.discloses = setOf("name")
        val shortAnswer = vault.answer(Utils.createQueryIntent(context, accountKey, QUERY_REQUEST))

        // region snippet:query-short
        // In onActivityResult, once `resultCode` is RESULT_OK and the request code matches. A
        // disclosure can be shorter than the profile you stored: consent is per disclosure, so a
        // field the user released at sign-up they may hold back now. `fields["email"]` is then
        // absent — or blank, from a vault that sends the field anyway — and both read alike here.
        fun onDisclosure(data: Intent?) {
            val needed = FieldRequirements(listOf("name", "email"))
            val disclosed = Utils.parseQueryResult(data)?.fields ?: emptyMap()
            // `committed` is null while a required field is absent or blank, and otherwise keeps
            // the declared fields that arrived with something in them — an undeclared one is
            // dropped; `missingRequired` names the required ones to ask for again.
            val profile = needed.committed(disclosed)
            if (profile != null) keepProfile(profile) else askAgainFor(needed.missingRequired(disclosed))
        }
        // endregion snippet:query-short

        assertEquals(Activity.RESULT_OK, shortAnswer.resultCode)
        assertTrue(
            "the checks the block above shows come first, and this answer passes them",
            Utils.matchesRequestCode(shortAnswer.data, QUERY_REQUEST),
        )
        assertEquals(
            "the name arrived — so the handler is reading a disclosure, not failing to parse one",
            listOf("name"),
            Utils.parseQueryResult(shortAnswer.data)!!.fields.keys.toList(),
        )

        onDisclosure(shortAnswer.data)
        assertEquals(
            "the one field the user held back is the one the handler asks for again",
            listOf("ask again [email]"),
            queryOutcomes,
        )

        // The whole profile, through the same handler: nothing missing, and both fields kept.
        queryOutcomes.clear()
        vault.discloses = null
        val whole = vault.answer(Utils.createQueryIntent(context, accountKey, QUERY_REQUEST)).data
        onDisclosure(whole)
        assertEquals(listOf("kept [name, email]"), queryOutcomes)

        // And a vault that discloses more than was asked about: `phone` is in the answer, it is
        // not in what this screen declared, and it is not in what the handler would store.
        queryOutcomes.clear()
        val over = overDisclosingVault()
        val generous = over.answer(Utils.createQueryIntent(context, over.publicKey, QUERY_REQUEST)).data
        assertEquals(
            listOf("name", "email", "phone"),
            Utils.parseQueryResult(generous)!!.fields.keys.toList(),
        )
        onDisclosure(generous)
        assertEquals(listOf("kept [name, email]"), queryOutcomes)

        // A vault that sends a field it holds nothing for rather than omitting it. Blank and
        // absent take the same branch, which is what makes the block's "absent — or blank" true
        // rather than a guess about which vault you are talking to.
        queryOutcomes.clear()
        onDisclosure(
            Utils.createQueryResultIntent(
                accountKey,
                linkedMapOf(
                    "name" to TypedField("Ada", FieldType.STRING),
                    "email" to TypedField("", FieldType.EMAIL),
                ),
                QUERY_REQUEST,
            ),
        )
        assertEquals(listOf("ask again [email]"), queryOutcomes)

        // No answer at all, and a refusal: neither parses to any fields, so both required names
        // are short and the handler asks again rather than storing an empty profile.
        queryOutcomes.clear()
        onDisclosure(null)
        vault.consents = false
        val refused = vault.answer(Utils.createQueryIntent(context, accountKey, QUERY_REQUEST))
        assertEquals(Activity.RESULT_CANCELED, refused.resultCode)
        onDisclosure(refused.data)
        assertEquals(
            listOf("ask again [name, email]", "ask again [name, email]"),
            queryOutcomes,
        )

        // And the edge the section warns about, measured rather than asserted of the printed
        // block: declare nothing required and there is no required field left to be short, so
        // `committed` of an answer that parsed to nothing is an empty map, not `null` — the arm
        // where a refusal would read as a stored profile with nothing in it. The result code is
        // what refuses that and the only thing that does, since the refusal driven through the
        // handler above was correlated; this gate cannot see either.
        val allOptional = FieldRequirements(listOf("name", "email"), setOf("name", "email"))
        assertEquals(emptyList<String>(), allOptional.missingRequired(emptyMap()))
        assertEquals(emptyMap<String, TypedField>(), allOptional.committed(emptyMap()))
        assertTrue(
            "and the refusal this handler was handed is correlated, which is why the section " +
                "puts the result code and not `matchesRequestCode` between it and a stored " +
                "empty profile",
            Utils.matchesRequestCode(refused.data, QUERY_REQUEST),
        )
    }

    // ── Login ────────────────────────────────────────────────────────────

    /**
     * Login is the one flow that proves something, so it is the one flow whose handler being
     * green on the happy path alone would be an authentication bypass rather than a gap.
     *
     * The guide's `login-result` block is therefore a **function**, and this test drives it twelve
     * times: four times on an answer it must accept, and eight times on one it must refuse — an
     * expired challenge, another account's stored key, an answer from a different flow that parses
     * as something else, a result code that is not `RESULT_OK`, no intent at all, a genuine answer
     * replayed against a challenge it did not answer, a genuine answer to a *different login
     * request* of this same service, and a genuine answer to a challenge the integrator minted
     * themselves. As straight-line code in a region it could only ever be run
     * once, on the answer it was always going to accept; re-running it meant copying it, which
     * pins nothing.
     *
     * **Three of the four acceptances are the same call, and that is the point of them.** Nothing
     * in this library makes a challenge single-use, so the identical `(resultCode, data,
     * storedKey, challenge)` is accepted a second and a third time, with the 60-second window
     * asserted open on either side of the pair so the attribution is the window still being open
     * rather than the handler being indifferent to its challenge. Every *other* repeat in this
     * test changes one argument and lands on a refusal, so none of them asks that question; the
     * fourth acceptance is refusal 6's own, a genuinely different login that keeps "true three
     * times" from reading as a handler that is true of everything. The closed window is refusal
     * 1's, cited rather than minted twice, and the matching refusal — *a* genuine answer against a
     * challenge it did not answer — is refusal 6's `assertFalse`, over that answer rather than
     * this one, because only refusal 6 asserts it as a pair through the handler. The repeats
     * themselves discriminate nothing in the present tense: `loginSucceeded` holds no state, so
     * they cannot fail while the first acceptance passes and the window stays open — the clock is
     * the one way they could diverge, and the controls are what witness it. What they buy is the
     * statement that today nothing makes an answer single-use plus a canary for the day
     * something does.
     * What this says is what *this library* does not do: it is not a claim that any particular
     * attacker can obtain a login answer, and whether a challenge should be single-use *on the
     * wire* is the standing peer-freshness question and not this test's.
     *
     * **Refusals 4, 5 and 7 exist to reach the clauses nothing here had ever refused at**, and
     * they are not equally attributable. Refusals 4 and 5 both pass the *genuine* answer's
     * arguments, identical to the accepting call at the top of this test, and change exactly one
     * of them. Refusal 4 is therefore the result-code clause and nothing else: the other three
     * are satisfied by that accepting call's own `true`. Refusal 5 pins that a `null` intent is
     * refused and nothing is thrown; *which* clause refuses it is said by the paired parse
     * assertion and the comment beside it, not by the call — which is written there rather than
     * left to be inferred.
     *
     * **Refusal 7 is the correlation clause, and it is attributable by construction** — which is
     * the property refusal 5 has to borrow from a comment. [Utils.matchesRequestCode] exists for
     * one accident, two requests in flight and the wrong answer handled, and until this call no
     * published handler in this file had ever been refused *for that reason* — refusal 5's `null`
     * reaches the same clause, but by being nothing rather than by belonging elsewhere, which is
     * a different fault and does not exercise the accident. It is refusal 6's
     * mirror image: there a second *challenge* under the same request code, here a second
     * *request* over the same challenge and the same stored key. So the handler's other three
     * clauses are each asserted true over the very arguments the refusing call is given, and the
     * correlation is the only clause left that can have produced the `false`. Those three
     * controls are load-bearing, not decoration: drop one and the suite stays green while the
     * attribution quietly stops holding.
     *
     * **The replay is a real one.** Refusal 6 is a second challenge this service really minted,
     * really signed by the key the account table really holds, carrying the same request code: a
     * well-formed answer from the right signer, whose only fault is which challenge it answers. It
     * is asserted as a **pair** — accepted against its own challenge, refused against the earlier
     * one — because only the pair separates "this answer is bad" from "this answer is not the
     * answer to *this* challenge", and the second is the whole reason a nonce exists. Both nonces
     * are asserted fresh, so that refusal is the signature and not the window.
     *
     * **Refusal 8 is the one no device, clock or retry can ever turn into a success**, and it is
     * the first-week failure the guide's own prose now warns about: a challenge the integrator
     * minted themselves rather than with [Utils.generateNonce]. [Utils.isNonceFresh] reads the
     * first eight bytes of whatever it is handed as a big-endian millisecond timestamp — its own
     * `@param` says exactly that — so forty bytes of an integrator's choosing are signed by this
     * test's vault, verify against the stored key, correlate, and are refused by the freshness
     * clause anyway. It is attributable by construction, refusal 7's way: the other three clauses
     * are each asserted true over the very arguments the refusing call is given.
     *
     * **Those bytes are fixed rather than random, and that is the substance of the refusal.**
     * Forty random bytes are refused with overwhelming probability but not by construction, and
     * "almost always refused" and "refused, and here is the timestamp that refuses it" are
     * different claims — only the second is a pin. Forty `0x5A` bytes spell
     * [HAND_ROLLED_TIMESTAMP] and nothing else, so the number is printed and asserted rather than
     * the behaviour averaged.
     *
     * **A noise header is not itself new, and the narrow claim is the one worth making.**
     * `NonceTest` already owns the unit-level behaviour over arrays nobody signed: the
     * short-nonce case (`:261-265`), the big-endian anchor (`:243-246`), and — nearest to this
     * one — `extreme timestamps fail closed` (`:186-221`), which hands [Utils.isNonceFresh]
     * full-length 40-byte nonces whose headers were laid out by hand. What is new here is the
     * rest of it: a hand-rolled challenge really signed by the account's key, correlating,
     * verifying, and refused by the *published handler* anyway — plus the declaration below.
     *
     * **The second half is the peer obligation, and it is the half nothing else pins.** The same
     * request declares [Utils.NONCE_FORMAT_TIMESTAMPED] over those bytes, so the declaration is
     * *false on the wire* while being perfectly well formed — and [Utils.nonceTimestamp]'s KDoc
     * tells a vault to trust the value exactly when the sender declared it. A vault applying its
     * own freshness policy is then reading noise as a time because the client said it could. The
     * minted request is asserted beside it as the honest pairing: the same literal, over a
     * timestamp that is real and inside the client's own window. What a vault *should* do about a
     * declaration it cannot trust is the standing peer-freshness question, not this test's.
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
    fun `login proves the holder of the stored key is present, and refuses eight answers`() {
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

        // And again, twice, on the *identical* four arguments — because nothing in this library
        // makes a challenge single-use, and until this pair nothing here said so. Every other
        // repeat in this test changes one argument and lands on a refusal, so none of them asks
        // this question.
        //
        // The freshness clause is the only bound, which is why the window is asserted open on
        // either side of the pair: without that the repeated `true` could as well be a handler
        // indifferent to its challenge, and with it the attribution is the window still being
        // open. Both control assertions are load-bearing in exactly that sense — delete either
        // and the suite stays green while the attribution quietly stops holding.
        //
        // The closed window is measured by refusal 1 below rather than minted a second time
        // here, and the other half of the pair — *a* genuine answer against a challenge it did
        // not answer, refused through this same handler — is refusal 6's `assertFalse`. It is
        // that answer and not this one, deliberately: refusal 6 asserts the pair, accepted
        // against its own challenge and refused against the earlier one, and only a pair
        // separates "this handler accepts anything" from "this answer is still the answer to
        // *this* challenge". The same-object version of it is the direct `isVerified` assertion
        // a few lines below, which is not a handler refusal and so is not the citation.
        //
        // What the repeats do **not** add is present-tense discrimination. `loginSucceeded`
        // holds no state, so these two calls are the same expression on the same arguments as
        // the one above and cannot fail while that one passes *and the window stays open* —
        // the freshness clause reads the ambient clock, which is the one way they could
        // diverge and exactly what the two controls below witness. What they buy is a canary
        // against a future change that makes an answer single-use, and the statement that
        // today nothing does.
        assertTrue(
            "control: the challenge is still inside the block's own 60-second window before the " +
                "repeats below, so what they measure is the window being open and not the " +
                "handler being indifferent",
            Utils.isNonceFresh(nonce, maxAgeMillis = 60_000L),
        )
        assertTrue(
            "the same answer, against the same challenge, logs the same profile in a second time",
            loginSucceeded(answer.resultCode, answer.data, storedPublicKey, nonce),
        )
        assertTrue(
            "…and a third: an answer is not spent by being acted on, so treating one as consumed " +
                "is the client's rule to keep and never this library's to enforce",
            loginSucceeded(answer.resultCode, answer.data, storedPublicKey, nonce),
        )
        assertTrue(
            "control: and the window was still open after them, so neither acceptance above was " +
                "bought by a clause that had already stopped applying",
            Utils.isNonceFresh(nonce, maxAgeMillis = 60_000L),
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

        // Refusal 4: the block's first clause, which until now was never the one that refused —
        // every call above passes `RESULT_OK`. The arguments are the genuine answer's, identical
        // to the accepting call at the top of this test, so the other three clauses are satisfied
        // by that call's own `true` and this refusal is the result-code clause alone.
        assertFalse(
            "a cancelled answer logs nobody in, however genuine the signature it carries",
            loginSucceeded(Activity.RESULT_CANCELED, answer.data, storedPublicKey, nonce),
        )

        // Refusal 5: no intent at all, the shape `onActivityResult` is handed when a vault
        // returns without one. What this pins is that the printed handler refuses it *and throws
        // nothing* — a handler on a page has to survive the absent case, not merely reject it.
        //
        // The limit, stated rather than implied: driving the handler with `data = null` does not
        // pin which clause refused. The assertion beside it is what says that, by measuring the
        // step the comment names: the parse has already run and returned `null`, and the refusal
        // lands at correlation, where `matchesRequestCode(null, …)` is `false` (`Utils.kt:2782`)
        // and `&&` short-circuits before `result?.isVerified` is reached. If a later change made
        // the parse throw instead, this call would redden for a reason its name does not name.
        assertNull(
            "the login parser reads a missing intent as nothing at all",
            Utils.parseSignChallengeResult(null),
        )
        assertFalse(
            "…and the handler refuses it rather than throwing",
            loginSucceeded(Activity.RESULT_OK, null, storedPublicKey, nonce),
        )

        // Refusal 6, and the replay the nonce exists to stop — asserted *through* the handler
        // rather than around it. The vault signs a second challenge this service really minted,
        // under the same request code, so the answer is well formed, the signer is the right one
        // and the signature is genuine: the only thing wrong is which challenge it answers.
        val secondNonce = Utils.generateNonce()
        val replayed = vault.answer(
            Utils.createSignChallengeIntent(
                context,
                storedPublicKey,
                secondNonce,
                LOGIN_REQUEST,
                nonceFormat = Utils.NONCE_FORMAT_TIMESTAMPED,
            ),
        )
        assertEquals(
            "precondition: the vault signed the second challenge too",
            Activity.RESULT_OK,
            replayed.resultCode,
        )
        assertTrue(
            "control: the earlier challenge is still inside the block's own 60-second window",
            Utils.isNonceFresh(nonce, maxAgeMillis = 60_000L),
        )
        assertTrue(
            "control: and so is the one this answer signed — so the verdicts below are about " +
                "which challenge was signed, not about the clock",
            Utils.isNonceFresh(secondNonce, maxAgeMillis = 60_000L),
        )
        // The pair is the point: either verdict alone would be explained by the answer being
        // good or bad in general, and only both together say "not the answer to *this* one".
        assertTrue(
            "the second answer logs the profile in against the challenge it actually answered",
            loginSucceeded(replayed.resultCode, replayed.data, storedPublicKey, secondNonce),
        )
        assertFalse(
            "…and that very same answer, replayed against the earlier challenge, logs nobody in",
            loginSucceeded(replayed.resultCode, replayed.data, storedPublicKey, nonce),
        )

        // Refusal 7: the correlation clause refusing for the reason it exists — an answer that
        // belongs to a *different request*, which no call here had ever been refused for. Every
        // call above hands this handler an answer tagged `LOGIN_REQUEST` or no answer at all, so
        // while refusal 5's `null` does reach this clause (see the note there), the hazard the
        // clause was written for — two login requests in flight, and the handler given the answer
        // to the other one — had never been driven. Both requests are this service's own, over
        // the same challenge and the same stored key, so nothing is wrong with this answer
        // except which request it belongs to.
        //
        // The attribution is **by construction, not by inference**, which is the thing refusal 5
        // cannot say about itself: the handler's other three clauses are each asserted true just
        // below, over these very arguments, so the `false` that follows leaves the correlation as
        // the only clause that can have produced it. Drop any one of those three and the suite
        // stays green while the attribution quietly stops holding — they are load-bearing.
        val otherRequest = vault.answer(
            Utils.createSignChallengeIntent(
                context,
                storedPublicKey,
                nonce,
                SECOND_LOGIN_REQUEST,
                nonceFormat = Utils.NONCE_FORMAT_TIMESTAMPED,
            ),
        )
        assertEquals(
            "the result-code clause is satisfied: the vault signed this second challenge rather " +
                "than refusing it, and `RESULT_OK` is what the refused call below passes",
            Activity.RESULT_OK,
            otherRequest.resultCode,
        )
        assertTrue(
            "the answer *is* correlated — to its own request, which is the whole point. So the " +
                "handler's correlation clause is false because the two codes differ, not " +
                "because the extra is absent, blank or unreadable",
            Utils.matchesRequestCode(otherRequest.data, SECOND_LOGIN_REQUEST),
        )
        assertTrue(
            "the freshness clause is satisfied: the challenge is inside the block's own window",
            Utils.isNonceFresh(nonce, maxAgeMillis = 60_000L),
        )
        assertTrue(
            "the verify clause is satisfied: the signature is genuine, by the key this service " +
                "stores, over the very bytes it sent",
            Utils.parseSignChallengeResult(otherRequest.data)!!.isVerified(storedPublicKey, nonce),
        )
        assertFalse(
            "…and yet the answer to another request logs nobody in: three clauses measured true " +
                "on these arguments leave the correlation as the clause that refused",
            loginSucceeded(Activity.RESULT_OK, otherRequest.data, storedPublicKey, nonce),
        )

        // Refusal 8: a challenge of the integrator's own forty bytes rather than
        // `generateNonce`'s. `isNonceFresh` reads the first eight bytes of whatever it is handed
        // as a big-endian millisecond timestamp, so there is nothing to find and it finds one
        // anyway — and this is the first-week failure "my login never succeeds", landing on a
        // clause nobody is looking at.
        //
        // The array is **fixed, not random**, and that is the point: forty random bytes are
        // refused with overwhelming probability but not by construction, and only "refused, and
        // here is the timestamp that refuses it" is a pin. Forty `0x5A` bytes spell exactly one
        // "time", asserted below and printed, and it is ~206 million years from now — so no
        // device, clock or retry can ever make this call true.
        val handRolled = ByteArray(40) { 0x5A }
        assertFalse(
            "precondition: these bytes are not a signed statement's pre-image, so the fixture " +
                "vault signs them rather than refusing them as one — the refusal below is the " +
                "client's freshness clause and not the vault's signing-oracle guard",
            Utils.isStatementPreImage(handRolled),
        )
        assertEquals(
            "the header these bytes spell, read out of them rather than asserted loosely",
            HAND_ROLLED_TIMESTAMP,
            Utils.nonceTimestamp(handRolled),
        )
        println(
            "GuideExamplesTest: a hand-rolled 40-byte challenge of 0x5A declares the timestamp " +
                "$HAND_ROLLED_TIMESTAMP ms, which is in the future and therefore never fresh",
        )
        assertFalse(
            "…which is why the freshness clause can never be satisfied by it: the window is " +
                "measured against a timestamp the client's own clock cannot postdate",
            Utils.isNonceFresh(handRolled, maxAgeMillis = 60_000L),
        )

        // Declared `NONCE_FORMAT_TIMESTAMPED` on purpose: an integrator who hand-rolls the
        // challenge is exactly the one who copies the declaration across with it, and that is
        // the second half of this — a well-formed claim about a layout the bytes do not have.
        val handRolledRequest = Utils.createSignChallengeIntent(
            context,
            storedPublicKey,
            handRolled,
            LOGIN_REQUEST,
            nonceFormat = Utils.NONCE_FORMAT_TIMESTAMPED,
        )
        val handRolledAnswer = vault.answer(handRolledRequest)
        assertEquals(
            "precondition: the vault signed it — *these* bytes are refused by nothing on the " +
                "vault side (a hand-rolled challenge that happened to be a statement pre-image " +
                "would be, which is what the assertion above rules out), so the client's own " +
                "freshness clause is the only place this answer can fail",
            Activity.RESULT_OK,
            handRolledAnswer.resultCode,
        )
        assertTrue(
            "the correlation clause is satisfied: this is the answer to this very request",
            Utils.matchesRequestCode(handRolledAnswer.data, LOGIN_REQUEST),
        )
        assertTrue(
            "the verify clause is satisfied: a genuine signature, by the key this service " +
                "stores, over exactly the bytes it sent",
            Utils.parseSignChallengeResult(handRolledAnswer.data)!!.isVerified(storedPublicKey, handRolled),
        )
        assertFalse(
            "…and yet a challenge the integrator minted themselves logs nobody in, for ever: " +
                "`RESULT_OK` above and three clauses measured true on these very arguments " +
                "leave the freshness clause as the one that refused",
            loginSucceeded(
                handRolledAnswer.resultCode,
                handRolledAnswer.data,
                storedPublicKey,
                handRolled,
            ),
        )

        // And the claim the request puts on the wire, which is the part a vault acts on.
        // `nonceTimestamp`'s KDoc tells a peer to trust the header *exactly when* the sender
        // declared this literal — so a declaration over bytes that carry no timestamp hands a
        // vault noise to apply its own freshness policy to, with the protocol's own permission.
        assertEquals(
            "the hand-rolled request declares the timestamped layout, read back off the wire",
            Utils.NONCE_FORMAT_TIMESTAMPED,
            handRolledRequest.getStringExtra(Utils.EXTRA_NONCE_FORMAT),
        )
        assertEquals(
            "…over a nonce whose declared timestamp is the far-off constant above: the " +
                "declaration is false on the wire while being perfectly well formed",
            HAND_ROLLED_TIMESTAMP,
            Utils.nonceTimestamp(Utils.parseSignChallengeRequest(handRolledRequest)!!.nonce),
        )

        // The honest pairing, without which the refusal above could be the signing path, the
        // request code or the fixture rather than the eight bytes: the same request shape over a
        // `generateNonce` challenge declares the same literal, and the timestamp a vault reads on
        // the strength of it is a real one, inside this client's own window.
        assertEquals(
            "the minted request declares the same literal",
            Utils.NONCE_FORMAT_TIMESTAMPED,
            request.getStringExtra(Utils.EXTRA_NONCE_FORMAT),
        )
        assertTrue(
            "and the nonce it declares really does carry a timestamp inside the block's window",
            Utils.isNonceFresh(
                Utils.parseSignChallengeRequest(request)!!.nonce,
                maxAgeMillis = 60_000L,
            ),
        )
    }

    /**
     * What else a login answer carries, measured rather than assumed — and the reason the section
     * above no longer ends "Nothing leaves the device but a signature."
     *
     * [Utils.createSignChallengeResultIntent] writes [Utils.EXTRA_FIELDS_JSON] unconditionally, and
     * [FixtureVault.sign] — the vault that answers the guide's own login scene — hands it the whole
     * stored profile. So the answer the printed handler verifies carries `name` and `email` with
     * their real values, and an integrator who read that sentence the way it is written would store
     * or log personal data they never asked for.
     *
     * **Narrow on two axes, which is what makes it new.** A sign-challenge result's fields are read
     * elsewhere: `ResultBuilderTest:486` round-trips a field map through the builder, `:269-289`
     * pins the empty case, `DecoderFuzzTest:502-503` reads them under fuzz. The claim here is
     * smaller — **no test read the fields of the login answer in this guide's own scene** (the ten
     * `loginSucceeded` calls above branch on four clauses, none of which touches the payload), and
     * **nothing anywhere said that a login, as the page teaches it, discloses the stored profile**.
     * [SignChallengeResult]'s class KDoc has always described the data correctly; it was the page
     * that contradicted it.
     *
     * **The whole [TypedField] is compared, never `fields["email"]?.value`, and the reason is the
     * opposite of the obvious one.** [TypedField.toString] *is* the redacted rendering, so a failed
     * comparison of `TypedField`s prints a type and a length while a failed comparison of raw
     * `String`s prints the address verbatim into the build log. The sign-up test at the top of this
     * file compares the raw value and has exactly that property; this one does not copy it.
     *
     * **The control is the share answer, not the empty payload.** The same scene's *share* answer
     * carries the same profile under the same extra key, which is what makes "a login is a proof,
     * not a disclosure" a statement about the request rather than a false one about the wire: a
     * share asked for those fields and a login did not. That the payload is written even for an
     * empty map is already bought by `ResultBuilderTest`'s *an empty fields map is still an answer*
     * (`:269-289`) and is cited rather than re-measured.
     *
     * **How much of this file depends on a login answer carrying data, measured.** Make
     * [FixtureVault.sign] pass `emptyMap()` instead of `held.fields` and **two** tests redden: this
     * one, and *a sign-up can leave named fields optional…*, whose misuse case feeds a login answer
     * to the sign-up handler and reads `NOT_ACKNOWLEDGED` off its payload — `INCOMPLETE` once the
     * payload is gone. Neither is a login: the ten `loginSucceeded` calls and all eight refusals
     * above stay green under that mutation, because no clause of the published login handler reads
     * a field. That is why the sentence this test corrects survived as long as it did.
     *
     * **The limit, and it is the whole limit.** This measures this repository's [FixtureVault] and
     * this library's builder. It is not a claim about what any particular vault discloses in the
     * field — LIM cannot enforce a vault's behaviour — and it takes no position on whether a vault
     * *should* disclose on a login, which is a standing question for a human.
     */
    @Test
    fun `a login answer carries the whole stored profile beside the proof`() {
        // One sign-up, used twice: the login below and the share answer it is compared against
        // come out of the same vault and the same stored profile.
        val shareAnswer = shareAnswerFrom(vault)
        val storedPublicKey = Utils.parseShareResult(shareAnswer)?.publicKey
        assertNotNull("precondition: the fixture vault must answer a sign-up", storedPublicKey)

        val nonce = Utils.generateNonce()
        val answer = vault.answer(
            Utils.createSignChallengeIntent(
                context,
                storedPublicKey!!,
                nonce,
                LOGIN_REQUEST,
                nonceFormat = Utils.NONCE_FORMAT_TIMESTAMPED,
            ),
        )
        assertEquals(
            "precondition: the vault answered the challenge",
            Activity.RESULT_OK,
            answer.resultCode,
        )

        // The login answer carries a field payload at all — asserted on the extra, because a
        // parsed empty map and an absent payload are the same reading on the way out.
        assertTrue(
            "a login answer carries a field payload, under the share result's own key",
            answer.data!!.hasExtra(Utils.EXTRA_FIELDS_JSON),
        )

        // …and it is the whole stored profile, read out of the answer rather than asserted
        // loosely: the names come back as a list and are compared against the profile the vault
        // holds, so a disclosure of one field or of three fails here.
        val parsed = Utils.parseSignChallengeResult(answer.data)
        assertNotNull("precondition: the login answer parses", parsed)
        assertEquals(
            "a login discloses every field the vault stored, though the challenge asked for none",
            PROFILE.keys.toList(),
            parsed!!.fields.keys.toList(),
        )

        // One value arrives intact. The whole `TypedField` is compared, not its `value`:
        // `TypedField.toString` is the redacted rendering, so this comparison prints a length on
        // failure where a raw-String one would print the address.
        assertEquals(
            "…carrying the value the user typed, not a placeholder or a blank",
            TypedField(PROFILE_EMAIL, FieldType.EMAIL),
            parsed.fields["email"],
        )

        // And the proof is untouched: a disclosure riding along with a genuine login, not a
        // broken answer that happens to carry data.
        assertTrue(
            "the same answer still verifies against the stored key and the challenge sent",
            parsed.isVerified(storedPublicKey, nonce),
        )

        // The control. The share answer from the same sign-up carries the same payload under the
        // same key, so what separates the two flows is not the wire but the request: a share
        // asked for those fields and a login did not.
        assertEquals(
            "control: the share answer discloses the same fields under the same key, so the " +
                "difference a login makes is in what was asked for, never in what is sent",
            parsed.fields,
            Utils.parseShareResult(shareAnswer)!!.fields,
        )

        // A restatement of `ResultBuilderTest`'s *an empty fields map is still an answer*
        // (`:269-289`), kept for readability and not this test's evidence. It is why a vault
        // cannot opt out of the payload by omission: on this wire "disclosed nothing" and "sent
        // no payload" are the same answer.
        assertEquals(
            "restatement, pinned elsewhere: the payload is written even for an empty map",
            "{}",
            Utils.createSignChallengeResultIntent(parsed.signature)
                .getStringExtra(Utils.EXTRA_FIELDS_JSON),
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
     * **The restored request code is pinned too, and narrowly.** The guide's own request codes are
     * constants, so the `putString` line is there for an app that *mints* a correlation token per
     * request — and no test here can make a claim about an app that does not exist. What a test
     * here can pin, and now does, is the line's own mechanics: the value it saves, the key it saves
     * it under, and that both come back out of the parcel. A save of the wrong value, or under the
     * wrong key, no longer reaches the guide unnoticed — and no wider than that: the pin reads the
     * value and the key, not where the value came from, so a line that ignored its own parameter
     * for a constant of the same text would still pass.
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
        assertEquals(
            "and the save line's other half travelled too: the request code comes back out of " +
                "the key that line names, which is the mechanics of the line and no claim about " +
                "an app that mints a correlation token per request",
            LOGIN_REQUEST,
            revived!!.getString(STATE_REQUEST_CODE),
        )

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
        // perfectly good QueryResult with no fields — exactly the field payload a vault that
        // consented and disclosed nothing returns — so the fields cannot tell you which of the
        // two happened. The echoed public key often does differ, and is still not the signal:
        // it is the vault's own claim, a refusal that echoed one would read as a disclosure,
        // and a consenting vault with no key to give sends none either.
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
        // field payload of a refusal is indistinguishable from a consenting vault's empty
        // disclosure. The key is not, and the pin for that is at the end of this test.
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

        // The corrected clause in the block above, pinned over this fixture's own two answers:
        // the *fields* read alike and it is the key that differs. Scoped to these two on
        // purpose — `createQueryResultIntent` writes the key through `putPresentExtra`, which
        // omits a blank one, so a consenting vault with no key to give answers without one too.
        // A general "the key tells them apart" would be this same defect one layer along, which
        // is why the block says the key is not the signal rather than offering it as one.
        vault.discloses = emptySet()
        val disclosedNothing =
            vault.answer(Utils.createQueryIntent(context, accountKey, QUERY_REQUEST))
        assertEquals(
            "precondition: consent with nothing released is still consent",
            Activity.RESULT_OK,
            disclosedNothing.resultCode,
        )
        val consenting = Utils.parseQueryResult(disclosedNothing.data)
        assertNotNull("precondition: and it parses, like the refusal", consenting)
        assertEquals(
            "the two answers' fields are equal, which is the half of the old clause that was " +
                "true: an empty payload says nothing about which happened",
            parsed.fields,
            consenting!!.fields,
        )
        assertEquals(
            "…and the half that was not: this builder echoes the key it was given",
            accountKey,
            consenting.publicKey,
        )
        assertNull(
            "…while the refusal echoes none, so the parse is not as blind as the block used to " +
                "claim — and the result code is still the only thing that says which answer it is",
            parsed.publicKey,
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
     *  - **all three of the handler's clauses refuse something, and each refusal names itself.**
     *    The printed handler is driven four times: once on the answer it keeps, and three times on
     *    answers it must not — one refusal per clause. Until the last two were written only the
     *    result-code clause had ever returned, which made the other two lines paste, not behaviour.
     *    Each of the two new calls asserts the clauses it is *not* about: the answer belonging to
     *    another request would parse to a key, so its `null` is the correlation; and the refusal
     *    carrying only a request code correlates *and* parses, so its `null` is the absent key.
     *    That second one is handed `RESULT_OK` deliberately — the handler reads no result code out
     *    of the intent, and attributing its silence to the first clause would be wrong;
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

        // The handler has three clauses and only the result code had ever been the one that
        // returned. The two calls below reach the other two, and each is paired with the clause
        // *above* it measured true, so the refusal is attributed by construction rather than
        // asserted by comment.
        //
        // Refused at the correlation: the same built answer, echoing a different request of the
        // same flow. This is the two-requests-in-flight accident `matchesRequestCode` exists for,
        // and it is a genuine answer — a user really consented to this disclosure — so there is
        // nothing else for the handler to object to.
        val anotherRequestsAnswer = Utils.createShareResultIntent(
            publicKey = FAKE_PUBLIC_KEY,
            fields = linkedMapOf(
                "email" to TypedField(value = FAKE_EMAIL, type = FieldType.EMAIL),
            ),
            requestCode = SECOND_SIGN_UP_REQUEST,
        )
        assertEquals(
            "the clause below the correlation would have succeeded: the parse hands back a key",
            FAKE_PUBLIC_KEY,
            Utils.parseShareResult(anotherRequestsAnswer)?.publicKey,
        )
        assertNull(
            "…so an answer belonging to another request is kept by nothing, and the correlation " +
                "is the clause that refused it rather than the parse",
            onVaultAnswer(Activity.RESULT_OK, anotherRequestsAnswer),
        )

        // Refused at the key: a refusal as a vault really sends one — `RESULT_CANCELED` carrying
        // the echoed request code and nothing else, `FixtureVault.refuse`'s shape. It is handed
        // over with `RESULT_OK` on purpose, so the first clause cannot be what refuses it: this
        // handler never reads a result code out of the intent, and an integrator who forgot the
        // code check would land exactly here.
        val keyless = Intent().putExtra(Utils.EXTRA_SHARE_REQUEST_CODE, SIGN_UP_REQUEST)
        assertTrue(
            "the correlation passes, so the handler gets past the clause above",
            Utils.matchesRequestCode(keyless, SIGN_UP_REQUEST),
        )
        assertNotNull(
            "and the parse passes too — a refusal is a readable answer, not an empty envelope",
            Utils.parseShareResult(keyless),
        )
        assertNull(
            "…but it carries no public key, which is what leaves the key as the only clause " +
                "that can refuse here",
            Utils.parseShareResult(keyless)?.publicKey,
        )
        assertNull(
            "so the handler keeps nothing, and throws nothing",
            onVaultAnswer(Activity.RESULT_OK, keyless),
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

    /**
     * The same section's fourth block, and the one answer the other three cannot mint.
     *
     * The three builders that section publishes all produce a vault's *consent*. A refusal is
     * produced by none of them — [FixtureVault.refuse] says why: every result builder in this
     * library attaches [Utils.EXTRA_PROTOCOL_VERSION] unconditionally, and a refusal honoured
     * nothing, so a refusal is hand-built or it is not a refusal. That left the section minting
     * every answer except the one *When the user says no* calls the answer an integration has not
     * been written without.
     *
     * What the region cannot assert about itself, and this function therefore asserts outside it:
     *
     *  - **the four readings a handler branches on**, spelled out rather than implied:
     *    [Utils.matchesRequestCode] true, [Utils.parseQueryResult] non-null with no fields,
     *    [Utils.parseShareResult] non-null with a `null` key, [Utils.parseSignChallengeResult]
     *    `null`. A refusal is a *readable* answer, which is exactly why the result code is the
     *    only thing that says it was one;
     *  - **that the two hand-written lines are the refusal this repository's vaults really
     *    send**, and not a shape of their own. [FixtureVault] is asked about a key it does not
     *    hold — the `request.publicKey != publicKey` arm of [FixtureVault.disclose], which no
     *    test in this file had ever executed — and its answer gives the same four readings and
     *    the same extras, key for key.
     *
     * **Two refusal *extras* shapes exist in this repository and this test asserts over both.**
     * [FixtureVault.refuse] sends the request code alone; `RequirementsCompatibilityMatrixTest`
     * sends the request code *and* the version echo, hand-built there as it is here — no builder
     * in this library produces either shape, because all three write a field payload alongside
     * the version, which is the reason [FixtureVault.refuse] gives for being hand-built at all.
     * The integrator's two lines match the first exactly and
     * the second but for that one extra — read as `vaultProtocolVersion`, and gated on by
     * nothing, per *Gate on the data, never on the version*. A handler that behaved differently
     * between the two would be the defect. Extras are therefore compared only *within* a shape;
     * across the two they differ by construction and an equality assertion would simply be false.
     * A third variant exists and is not this test's: no payload at all, `VaultAnswer(
     * RESULT_CANCELED, null)`, which [RequiredFieldsVault] sends and the saved-state section
     * drives.
     *
     * **The limit, stated where the assertion is.** This compares an integrator's fixture against
     * the fixtures *this repository* uses. It is not a claim about any vault in the field: LIM
     * cannot enforce what a vault sends, and the guide's sentence about the shape of a refusal is
     * a statement of today's shape rather than a guarantee.
     */
    @Test
    fun `an integrator mints the refusal too, and it reads exactly as a vault's does`() {
        val accountKey = signUpOnTheFixtureVault()

        // region snippet:refusal
        // The fourth answer, and the one no result builder mints: a refusal. Two lines, because
        // there is nothing in one but the code you echoed — the vault honoured nothing, so it
        // attaches nothing. Drive your handler with this as well as with the answers above.
        val refusedCode = Activity.RESULT_CANCELED
        val refused = Intent().putExtra(Utils.EXTRA_SHARE_REQUEST_CODE, QUERY_REQUEST)
        // endregion snippet:refusal

        assertEquals(
            "precondition: the two lines above are a refusal, which is a result code and not a " +
                "property of the payload",
            Activity.RESULT_CANCELED,
            refusedCode,
        )
        assertEquals(
            "the four readings a handler branches on, off an integrator's own two lines",
            REFUSAL_READINGS,
            refusalReadings(refused),
        )

        // The cross-check that makes those two lines honest rather than a shape of their own: the
        // refusal `FixtureVault` really sends, for a key it does not hold. An unknown key and a
        // refused consent collapse into one answer on purpose — see `FixtureVault.disclose` — so
        // this is also the first time in this file that arm runs.
        val unknownKey = vault.answer(Utils.createQueryIntent(context, otherPublicKey, QUERY_REQUEST))
        assertNotEquals(
            "precondition: the vault genuinely does not hold this key",
            accountKey,
            otherPublicKey,
        )
        assertEquals(
            "precondition: a key it does not hold is refused, not answered",
            Activity.RESULT_CANCELED,
            unknownKey.resultCode,
        )
        assertEquals(
            "the hand-built refusal and the one the fixture vault sends read the same, reading " +
                "for reading",
            refusalReadings(refused),
            refusalReadings(unknownKey.data),
        )
        assertEquals(
            "…and carry the same extras, key for key: within this shape the integrator's two " +
                "lines are the vault's refusal and not merely something that reads like it",
            refused.extras!!.keySet(),
            unknownKey.data!!.extras!!.keySet(),
        )

        // The second shape: the request code *and* the version echo, as
        // `RequirementsCompatibilityMatrixTest`'s vaults send it. One extra more, read as
        // `vaultProtocolVersion` and gated on by nothing.
        val withVersionEcho = Intent()
            .putExtra(Utils.EXTRA_SHARE_REQUEST_CODE, QUERY_REQUEST)
            .putExtra(Utils.EXTRA_PROTOCOL_VERSION, Utils.PROTOCOL_VERSION.toString())
        assertEquals(
            "the same four readings over the second shape, so a handler written against the " +
                "integrator's two lines meets no surprise from a vault that echoes its version",
            REFUSAL_READINGS,
            refusalReadings(withVersionEcho),
        )
        assertEquals(
            "…and the one extra that separates the shapes is the version, which the readings " +
                "above show changes none of them",
            setOf(Utils.EXTRA_SHARE_REQUEST_CODE, Utils.EXTRA_PROTOCOL_VERSION),
            withVersionEcho.extras!!.keySet(),
        )
        assertEquals(
            "…and it reads back as the version a client would read, rather than as an opaque " +
                "extra nothing parses",
            Utils.PROTOCOL_VERSION,
            Utils.parseQueryResult(withVersionEcho)?.vaultProtocolVersion,
        )

        // The echoed request code is what makes a refusal *correlated*, and an integrator's
        // fixture that forgets it is not the refusal a vault sends. Two spellings of the same
        // mistake, because the second is the one somebody actually types: left out, and written
        // as `""` — which `presentStringExtra` maps to absent, so both land here.
        assertFalse(
            "a refusal with no echoed code correlates with nothing",
            Utils.matchesRequestCode(Intent(), QUERY_REQUEST),
        )
        assertFalse(
            "…and neither does one whose code is present but blank",
            Utils.matchesRequestCode(
                Intent().putExtra(Utils.EXTRA_SHARE_REQUEST_CODE, ""),
                QUERY_REQUEST,
            ),
        )
    }

    // ── Shared setup, all of it outside the regions ───────────────────────

    /**
     * The four readings a handler branches on, taken off one answer and reduced to strings.
     *
     * One list rather than four assertions, so "the integrator's refusal and the vault's read
     * alike" is a single comparison whose failure prints which reading differed — and so that a
     * reading added here is added to every answer the refusal test compares, rather than to
     * whichever one somebody remembered.
     */
    private fun refusalReadings(data: Intent?): List<String> {
        val query = Utils.parseQueryResult(data)
        val share = Utils.parseShareResult(data)
        return listOf(
            "matchesRequestCode=${Utils.matchesRequestCode(data, QUERY_REQUEST)}",
            "parseQueryResult=" + if (query == null) "null" else "fields=${query.fields.keys.toList()}",
            "parseShareResult=" + if (share == null) "null" else "publicKey=${share.publicKey}",
            "parseSignChallengeResult=" +
                if (Utils.parseSignChallengeResult(data) == null) "null" else "present",
        )
    }

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

    /** What *When the answer comes back short*'s handler did, one line per call. */
    private val queryOutcomes = mutableListOf<String>()

    /** That handler's two outcomes: the profile it would store, or the names to ask for again. */
    private fun keepProfile(profile: Map<String, TypedField>) {
        queryOutcomes += "kept ${profile.keys.toList()}"
    }

    private fun askAgainFor(missing: List<String>) {
        queryOutcomes += "ask again $missing"
    }

    /**
     * A vault holding a third field, signed up for and ready to disclose all three.
     *
     * Needed because [FixtureVault] stores exactly the fields the sign-up request declared, so an
     * answer carrying a field a *query*'s caller never named cannot come out of the two-field
     * sign-up the rest of this file does. Nothing here is a guide snippet; it is the only way to
     * build the over-disclosing answer the handler has to drop a field from.
     */
    private fun overDisclosingVault(): FixtureVault {
        val vault = FixtureVault(
            vaultKeyPair,
            PROFILE + ("phone" to TypedField("555-0100", FieldType.PHONE)),
        )
        val request = Utils.createShareIntent(context, optionalPhoneEntry(), requestCode = SIGN_UP_REQUEST)
        val answer = vault.answer(request)
        // Asserted on the parsed result, not on `answer.data`: a refusal carries a non-null
        // intent too, so a guard on the intent alone would pass over a vault that stored nothing
        // and leave this helper handing back an empty profile for the handler to read.
        assertEquals(Activity.RESULT_OK, answer.resultCode)
        assertEquals(
            "the over-disclosing vault must store all three fields for this to over-disclose",
            listOf("name", "email", "phone"),
            Utils.parseShareResult(answer.data)!!.fields.keys.toList(),
        )
        return vault
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

        /**
         * The field names the user releases on a query, or `null` for the whole stored profile.
         *
         * Consent is per disclosure in this protocol, so a vault may answer with less than it
         * holds — and that is the one thing a client's query handler has to survive. `null` by
         * default, so every call written before this knob discloses everything exactly as it did.
         */
        var discloses: Set<String>? = null

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
            // What the user released, which may be less than what is stored. See [discloses].
            val held = stored?.fields?.let { fields ->
                discloses?.let { released -> fields.filterKeys { it in released } } ?: fields
            }
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
         * What a refusal that *carries a payload* reads as, written down rather than computed.
         *
         * Such a refusal parses, and that is the whole point of the four: a handler meets a
         * readable answer with no fields, no key and no signature, and only the result code says
         * it was a refusal. Spelled as a literal so the refusal test compares each answer against
         * a constant somebody wrote, not against another answer's output.
         *
         * Scoped to the two payload-bearing shapes deliberately. The third variant — no data
         * intent at all, which [RequiredFieldsVault] sends — reads as none of this: every one of
         * the four comes back `false` or `null`, because there is nothing there to parse. That is
         * a different answer with the same result code, not this one.
         */
        private val REFUSAL_READINGS = listOf(
            "matchesRequestCode=true",
            "parseQueryResult=fields=[]",
            "parseShareResult=publicKey=null",
            "parseSignChallengeResult=null",
        )

        /**
         * A second token for each of those two flows, and the only reason either exists: a
         * published handler has to be driven with a genuine answer that belongs to a **different
         * request**. That is the one accident [Utils.matchesRequestCode] is there for — two
         * requests in flight, the wrong answer handled — and no snippet's handler had ever
         * refused on it. Neither token reaches a region: a guide that showed an integrator two
         * request codes per flow would be teaching the hazard rather than the loop.
         */
        private const val SECOND_LOGIN_REQUEST = "login-2"
        private const val SECOND_SIGN_UP_REQUEST = "signup-2"

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
         * The "time" a hand-rolled challenge of forty `0x5A` bytes declares: `0x5A5A5A5A5A5A5A5A`
         * milliseconds since the epoch, which is roughly 206 million years from now.
         *
         * Spelled as a constant rather than computed, so the login test's assertion reads the
         * value out of the bytes and compares it against a number written down independently. It
         * is what makes refusal 8 a pin instead of a probability: [Utils.isNonceFresh] refuses
         * *this* nonce because its header is a future timestamp, not because forty arbitrary
         * bytes usually fail.
         */
        private const val HAND_ROLLED_TIMESTAMP = 6_510_615_555_426_900_570L

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
