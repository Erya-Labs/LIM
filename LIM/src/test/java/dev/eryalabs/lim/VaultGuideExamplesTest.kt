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
import java.security.PrivateKey
import java.security.Signature

/**
 * The code `docs/VAULT.md` prints, in the file that runs it.
 *
 * [GuideExamplesTest]'s arrangement, pointed at the other audience: every fenced Kotlin block on
 * the vault page is a `// region snippet:name` … `// endregion snippet:name` span of this file,
 * quoted verbatim, and `GuideSnippetTest` holds the two together. It fails if a block drifts from
 * its region, if a region is quoted by no block or by two, if a marker names a region that is not
 * here, or — the property that makes a printed snippet evidence rather than paste — if a region's
 * enclosing function is not annotated `@Test`. So every line the vault page shows is a line JUnit
 * executed to get this suite green.
 *
 * **Why this file exists at all, when seven fixture vaults already do.** This repository runs the
 * vault half of the wire in seven places — [ClientIntegrationExampleTest]'s `Vault` and
 * `SignUpVault`, [GuideExamplesTest]'s `FixtureVault` and `RequiredFieldsVault`, and
 * `RequirementsCompatibilityMatrixTest`'s `V0`, `V1` and `V2` — and not one line of any of them
 * can be published as a snippet. Every one is a **nested** class, so the JUnit4 runner collects
 * none of their methods, and `GuideSnippetTest`'s rule 5 reports a region in any of them as code
 * that compiles and never runs. That is not a technicality to route around: it is the rule that
 * makes a snippet evidence, so the page's blocks are written here as straight-line code in the
 * bodies of real `@Test` methods of a top-level class.
 *
 * **Written in a vault author's voice, and the assertions stay outside the regions** — what is
 * inside a region is what a vault app would write; what is outside it is this file proving the
 * snippet does what the page says it does. The division of labour against the neighbours:
 * `RequestParsingTest` pins each parser field for field over hostile input, and
 * [ClientIntegrationExampleTest] is the whole sequence with both halves answering. This file
 * repeats neither; its subject is the published prose.
 *
 * The page now covers both halves of a vault's turn: routing and reading a request, and building
 * the answer — or the refusal — the client reads back. **What makes the answering half evidence
 * rather than three builder calls is the read-back**: every test holding one of those regions
 * parses the intent it built with the function the client half really calls, so a page block that
 * built the wrong thing cannot stay green.
 *
 * **And the page's *What a vault must do* section cites into this file**, which is the one thing to
 * know before renaming a test here. That section states eight obligations and names a `@Test` for
 * each; most of those citations are methods of this class, and `GuideSnippetTest` resolves every
 * one of them by reflection, so a rename that leaves the page behind reddens there rather than
 * being discovered by a reader. Seven of the eight are demonstrated by tests that already existed
 * for other reasons — the obligations were published in KDoc long before the page collected them.
 * The eighth needed writing, and is the last test in this file: a refusal for a key the vault does
 * not hold has to be the refusal for a withheld consent, which nothing here had ever asked a
 * fixture vault to prove.
 *
 * **The limit, and it is the whole of what the answering half can claim.** Every test here holds a
 * *fixture* vault — this file — to the shape of an answer. The shape is all this library can speak
 * about: what the user is asked, what is stored, what is disclosed and when a refusal is the right
 * answer are the vault's own decisions, no function here checks one of them, and a vault in the
 * field is in another repository entirely. So a green run means the page's blocks build what the
 * client half reads back. It does not mean any vault behaves as the page's prose describes, and
 * the page says so where it shows the builders.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class VaultGuideExamplesTest {

    private val context = ApplicationProvider.getApplicationContext<Context>()

    // ── Routing an incoming request ───────────────────────────────────────

    /**
     * The action, which is the first thing a vault reads and the only thing that distinguishes a
     * login from the other two flows.
     *
     * Both actions are **scoped to the vault's own package** — `shareDataAction` and
     * `signChallengeAction` append a fixed suffix to it — so a client that disagrees about the
     * package resolves nothing at all. The region's own `when` is driven over all three inputs
     * that matter: a share-or-query action, a sign-challenge action, and an action addressed to
     * some other package, which is the arm a vault must not treat as its own.
     */
    @Test
    fun `the action says which flow arrived, and the vault's own package scopes it`() {
        // region snippet:vault-routing
        // A request reaches a vault as an `Intent` on an exported activity, and the action is the
        // first thing to read. Exactly two actions address a vault, and both are scoped to the
        // vault's own package name — a client that disagrees about the package resolves nothing,
        // so pass your own package and never a hard-coded string.
        fun flowOf(incoming: Intent, myPackage: String): String = when (incoming.action) {
            // Sign-up and query both travel under this one. The action does not tell them apart;
            // the payload does, and reading it is the next step.
            Utils.shareDataAction(myPackage) -> "a share or a query"
            // Login carries one flow only, so this arm needs no further disambiguation.
            Utils.signChallengeAction(myPackage) -> "a sign-challenge"
            // Anything else was not addressed to this vault. Answer nothing.
            else -> "not ours"
        }
        // endregion snippet:vault-routing

        val myPackage = Utils.DEFAULT_ENDEAVOR_PACKAGE
        assertEquals(
            "a sign-up travels under the share-data action",
            "a share or a query",
            flowOf(signUpIntent(), myPackage),
        )
        assertEquals(
            "…and so does a query, which is why the action cannot be the whole answer",
            "a share or a query",
            flowOf(queryIntent(), myPackage),
        )
        assertEquals(
            "a login travels under the sign-challenge action",
            "a sign-challenge",
            flowOf(challenge(), myPackage),
        )
        assertEquals(
            "…and the same intent read by a vault that believes it is installed under another " +
                "package is not addressed to it — the scoping is the whole point of taking the " +
                "package as a parameter",
            "not ours",
            flowOf(challenge(), "com.example.other.vault"),
        )
        assertEquals(
            "an intent with no action at all takes the same arm, rather than throwing",
            "not ours",
            flowOf(Intent(), myPackage),
        )
    }

    /**
     * The payload, which is what tells a share from a query once the action has said only "one of
     * those two".
     *
     * The claim the region rests on is that **no intent parses as both**, and it is asserted here
     * in all three directions rather than taken from the parsers' KDoc: a share parses as a share
     * and not a query, a query the other way round, and an intent carrying neither an entry
     * payload nor a usable public key parses as nothing at all. That last arm is the one worth
     * writing a test for — fail-closed is a claim about what a vault does with junk, and any app
     * on the device can send junk.
     */
    @Test
    fun `a share and a query are told apart by their payload, and neither parses as both`() {
        val incoming = signUpIntent()

        // region snippet:vault-share-or-query
        // A share and a query arrive under the same action, so what tells them apart is the
        // payload — never a hand-read extra, and never the order they happened to arrive in.
        // Hand the intent to both parsers: no intent parses as both, because one carrying an
        // entry payload is a share and `parseQueryRequest` refuses it for exactly that reason.
        val share = Utils.parseShareRequest(incoming)
        val query = Utils.parseQueryRequest(incoming)
        // Both `null` is the fail-closed arm, and it is the common one: a missing or malformed
        // entry payload, a blank public key, an entry whose identity `decodeEntry` refused. Any
        // app on the device can fire an intent at an exported activity, so there is nothing here
        // to show a user or to ask them to consent to. Answer nothing.
        // endregion snippet:vault-share-or-query

        assertNotNull("a sign-up intent is a share", share)
        assertNull("…and the same intent is not a query, because it carries an entry", query)

        val asQuery = queryIntent()
        assertNull(
            "the mirror: a query intent carries no entry payload, so it is not a share",
            Utils.parseShareRequest(asQuery),
        )
        assertEquals(
            "…and it parses as a query naming the key the client asked about",
            storedKey,
            Utils.parseQueryRequest(asQuery)?.publicKey,
        )

        val junk = shareIntentCarrying("not json at all")
        assertNull("a malformed entry payload is not a share", Utils.parseShareRequest(junk))
        assertNull(
            "…and it is not quietly read as a query either: the payload is present, so this " +
                "intent is a broken share rather than a request naming a key",
            Utils.parseQueryRequest(junk),
        )
    }

    // ── Reading a share request ───────────────────────────────────────────

    /**
     * What a vault gets back from `parseShareRequest`, and the reason there is no hostile-input
     * handling left to write after it.
     *
     * The region's claim is that the returned [Entry] is safe to dereference, and the assertions
     * drive the two inputs that would break a hand-rolled reader: `{}`, which Gson decodes to an
     * `Entry` whose three non-null properties are all genuinely `null`, and a payload whose
     * identity is blank. Both come back as a refusal rather than an object that throws on first
     * use — which is the half of [Utils.decodeEntry]'s contract worth stating precisely. It
     * *repairs* a `null` field map and drops `null` values; it *refuses* an absent or blank
     * identity or key. Nothing it returns has a `null` in it, and `{}` returns nothing.
     */
    @Test
    fun `a parsed share request carries an entry that is safe to read`() {
        // region snippet:vault-share-request
        // `parseShareRequest` is a vault's whole entry point for a sign-up, and it is the only
        // hostile-input handling there is to write: it returns `null` instead of throwing, and
        // what it does return is safe to dereference. Gson builds an entry without running the
        // Kotlin constructor, so a payload of `{}` decodes to one whose three non-null
        // properties are all null at runtime — `decodeEntry` refuses that outright, and repairs
        // the shapes that can be repaired, so `fields` here is never null.
        fun fieldsToAskFor(incoming: Intent): List<String>? {
            val request = Utils.parseShareRequest(incoming) ?: return null
            // `requestCode` is the correlation token to echo back in the result; `null` means the
            // client attached none. `protocolVersion` is `null` when the client declared nothing
            // usable, which means "it did not say" and never "version 1 confirmed".
            return request.entry.fields.keys.toList()
        }
        // endregion snippet:vault-share-request

        assertEquals(
            "the form to show is the entry's own field names, in the entry's own order",
            listOf("name", "email", "phone"),
            fieldsToAskFor(signUpIntent()),
        )
        assertNull(
            "an entry payload of `{}` decodes to an object whose three non-null properties are " +
                "all null at runtime, so the parser refuses it rather than handing one on",
            fieldsToAskFor(shareIntentCarrying("{}")),
        )
        assertNull(
            "…and so is a payload whose identity is blank: a profile keyed to nothing is one " +
                "nobody could authenticate against later",
            fieldsToAskFor(
                shareIntentCarrying("""{"id":"","fields":{},"publicKey":"no-key-yet"}"""),
            ),
        )
        assertNull("and a request intent with no payload at all is refused", fieldsToAskFor(Intent()))
    }

    /**
     * `parseFieldRequirements`, and the two properties a vault must not get wrong about it: a
     * broken declaration means **every field required**, and the answer is made off the same parse
     * as the entry it describes.
     *
     * The assertions drive three clients: one that declared `phone` optional, one that declared
     * nothing (an app built before the extra existed), and one whose declaration is unreadable.
     * The last two must be indistinguishable from each other and from "everything is required" —
     * a vault that read an unreadable declaration as "nothing is required" would let the user save
     * an empty profile and then answer a client that asked for a full one.
     */
    @Test
    fun `an absent or unreadable optional-fields declaration leaves every field required`() {
        val incoming = Utils.createShareIntent(
            context,
            pushedEntry(),
            REQUEST_CODE,
            setOf("phone"),
            Utils.DEFAULT_ENDEAVOR_PACKAGE,
        )

        // region snippet:vault-field-requirements
        // Which rows the user may leave blank is the client's declaration, and
        // `parseFieldRequirements` is the way to read it. It answers off the same parse
        // `parseShareRequest` makes, so a declaration can never be paired with an entry it did
        // not travel with, and it is `null` in exactly the cases that parser is — there is no
        // share request to read requirements off.
        val requirements = Utils.parseFieldRequirements(incoming)
        // One form row per `fieldNames`, in the entry's own order; `requiredFields` are the ones
        // that block Save. A declaration that is absent, blank, malformed or wrong-typed reads as
        // **every field required** — the same answer an app built before this extra existed gets
        // — so there is no "the client said nothing, so anything goes" arm to write.
        val rows = requirements?.fieldNames.orEmpty()
        val blocking = requirements?.requiredFields.orEmpty()
        // endregion snippet:vault-field-requirements

        assertEquals("one row per declared field, in the entry's order", FIELD_NAMES, rows)
        assertEquals(
            "the declared optional field is the one the user may leave blank",
            setOf("name", "email"),
            blocking,
        )
        assertTrue(
            "…and Save is gated on the required ones only: a draft with the optional field " +
                "empty is savable",
            requirements?.missingRequired(
                linkedMapOf(
                    "name" to TypedField("Ada", FieldType.STRING),
                    "email" to TypedField("ada@example.test", FieldType.EMAIL),
                ),
            )?.isEmpty() == true,
        )

        val declaredNothing = Utils.parseFieldRequirements(
            signUpIntent(),
        )
        assertEquals(
            "a client that declared nothing — an app older than the extra — requires every field",
            FIELD_NAMES.toSet(),
            declaredNothing?.requiredFields,
        )

        val unreadable = Utils.parseFieldRequirements(
            signUpIntent()
                .putExtra(Utils.EXTRA_OPTIONAL_FIELDS, "not a name list"),
        )
        assertEquals(
            "…and an unreadable declaration must be indistinguishable from that, rather than " +
                "read as `nothing is required`: the quiet direction of that mistake is a vault " +
                "saving an empty profile for a client that asked for a full one",
            FIELD_NAMES.toSet(),
            unreadable?.requiredFields,
        )
        assertEquals(
            "the parse is `null` exactly when `parseShareRequest` is, so a refused entry has no " +
                "requirements to read either",
            null,
            Utils.parseFieldRequirements(shareIntentCarrying("{}")),
        )
    }

    // ── Answering a request ───────────────────────────────────────────────

    /**
     * The sign-up answer: the key the vault minted and the fields it stored, correlated to the
     * request it answers.
     *
     * The region's claim is that the **request-taking overload reads one value off the request —
     * the correlation token — and nothing else**, so the assertions read the answer back with
     * `parseShareResult` and check both halves of that: the token survives, and the key the
     * client gets is the vault's rather than the placeholder its own request carried. The second
     * is the one worth asserting, because a builder that echoed the request's key would let a
     * client choose the identifier naming its own account and nothing would look wrong.
     */
    @Test
    fun `a share answer carries the key the vault minted and the token the request came with`() {
        val request = Utils.parseShareRequest(signUpIntent())!!

        // region snippet:vault-answer-share
        // The answer to a sign-up is the key this vault minted for the new profile and the
        // fields it stored. Hand the parsed request to the overload that takes one: it carries
        // the correlation token across, which is the only value it reads off the request. The
        // key and the fields stay explicit because they are the vault's — a builder that echoed
        // the request's own would let the client decide what its answer says.
        val answer = Utils.createShareResultIntent(
            request,
            publicKey = storedKey,
            fields = heldProfile,
        )
        // Then `setResult(Activity.RESULT_OK, answer)` and finish. The result code is what makes
        // this an answer rather than a refusal; nothing in the payload says which it is.
        // endregion snippet:vault-answer-share

        val asTheClientReadsIt = Utils.parseShareResult(answer)!!
        assertEquals(
            "the client's account identifier is the key the vault minted",
            storedKey,
            asTheClientReadsIt.publicKey,
        )
        assertEquals(
            "…and the fields are the ones the vault stored",
            heldProfile,
            asTheClientReadsIt.fields,
        )
        assertEquals(
            "…and the correlation token came off the request rather than being re-typed",
            REQUEST_CODE,
            asTheClientReadsIt.requestCode,
        )
        assertTrue(
            "which is what `matchesRequestCode` answers on the client's side of the same wire",
            Utils.matchesRequestCode(answer, REQUEST_CODE),
        )
        assertEquals(
            "precondition: the request carried a placeholder key, as a sign-up request does",
            "no-key-yet",
            request.entry.publicKey,
        )
        assertNotEquals(
            "…and it is not what the answer names: the key explicit in the call is the vault's",
            request.entry.publicKey,
            asTheClientReadsIt.publicKey,
        )
    }

    /**
     * The query answer: what the user released at the consent dialog, which may be less than the
     * vault holds.
     *
     * Two claims, both read back the way a client reads them. The disclosure arrives under the
     * **query flow's own field key**, so a share-shaped read of it discloses nothing — the two
     * extras are separate points in the protocol and are not interchangeable, which
     * `ResultBuilderTest > a result built for one flow discloses no fields to the other` owns in
     * both directions over both builders. And the key in the answer is the vault's, not the one
     * the caller asked about: this is the flow that rule exists for.
     */
    @Test
    fun `a query answer discloses only what was released, under the query flow's own field key`() {
        val request = Utils.parseQueryRequest(queryIntent())!!
        val released = linkedMapOf("email" to TypedField("ada@example.test", FieldType.EMAIL))

        // region snippet:vault-answer-query
        // A query is answered with what the user released at the consent dialog, which may be
        // less than the profile holds: consent is per disclosure, so one field of three is a
        // complete answer rather than a partial one. An empty map is a legitimate answer too —
        // "nothing disclosed" is not the same as not answering.
        val answer = Utils.createQueryResultIntent(request, publicKey = storedKey, fields = released)
        // The key is still passed explicitly, and this is the flow that rule exists for: the
        // request's own key is the one the *caller* chose to ask about, so echoing it would let
        // the caller name the profile its own disclosure claims to come from.
        // endregion snippet:vault-answer-query

        val asTheClientReadsIt = Utils.parseQueryResult(answer)!!
        assertEquals("the disclosure is what the user released", released, asTheClientReadsIt.fields)
        assertEquals("…under the key the vault holds", storedKey, asTheClientReadsIt.publicKey)
        assertTrue(
            "…correlated to the request it answers",
            Utils.matchesRequestCode(answer, REQUEST_CODE),
        )
        assertTrue(
            "and a disclosure travels under `extra_query_result_fields`, so the share flow's " +
                "reader finds no fields in it: the two builders are not interchangeable, which " +
                "is the mistake the request-taking pair exists to remove",
            Utils.parseShareResult(answer)!!.fields.isEmpty(),
        )

        // "The request's key is not echoed" is invisible while the caller asks about the key
        // this vault holds, so it is measured over a request naming another key. A real vault
        // would refuse that request rather than answer it — which key is answerable is a consent
        // decision and not this builder's business; what is measured here is only that the key
        // in the answer came from the parameter and not from the request.
        val askingAboutAnotherKey = Utils.parseQueryRequest(
            Utils.createQueryIntent(context, publicKey = otherKey, requestCode = REQUEST_CODE),
        )!!
        assertEquals(
            "a builder that echoed the request's key would let a caller name the profile its " +
                "own disclosure claims to come from",
            storedKey,
            Utils.parseQueryResult(
                Utils.createQueryResultIntent(askingAboutAnotherKey, storedKey, released),
            )!!.publicKey,
        )
    }

    /**
     * The login answer: a signature over the nonce the request carried, made with the private key
     * of the named profile.
     *
     * The read-back here is the strongest one available, because the client's own check is
     * cryptographic: [SignChallengeResult.isVerified] against the public key it already stores
     * and the nonce it generated. So the region is held to the only thing that matters about a
     * login answer — that it authenticates — and to the two ways it could fail to: a signature
     * over the wrong bytes, and a signature from the wrong key.
     *
     * The region signs with a `PrivateKey` passed in, which is what a vault has: a Keystore
     * handle for the profile's key. This library never holds one, never sees one, and does no
     * signing — `createSignChallengeResultIntent` writes what the vault says it signed, and only
     * the client's verification decides whether that is true.
     *
     * **And the region refuses before it signs**, which is why it is a nine-line function and not
     * a two-line one. This is the first page in this repository to show a vault signing anything,
     * so a block without [Utils.isStatementPreImage] in it would be a copyable signing oracle:
     * the nonce is caller-chosen bytes, a statement's pre-image is exactly such bytes, and a
     * signature over one is a valid key rotation obtained from a "prove your identity" dialog.
     * The obligation is the protocol's and the enforcement is the vault's — nothing in LIM
     * refuses such a nonce, and whether `parseSignChallengeRequest` should is a narrowing drafted
     * under "Blocked on human" and not this task's to answer.
     */
    @Test
    fun `a login answer is a signature the client verifies against the key it already holds`() {
        val incoming = challenge()
        val nonce = Utils.parseSignChallengeRequest(incoming)!!.nonce

        // region snippet:vault-answer-login
        // A login is answered with a signature over the nonce the request carried. The bytes to
        // sign come off the parsed request; the key is the one this vault minted for the named
        // profile — a Keystore handle in a real vault, and never anything this library holds.
        fun answerLogin(incoming: Intent, profileKey: PrivateKey): Intent? {
            val request = Utils.parseSignChallengeRequest(incoming) ?: return null
            // The check a signing device owes every signature it makes, and the reason this is
            // not a two-line function: these bytes are whatever the caller chose, and they could
            // be the pre-image of a statement this key authorises rather than a login challenge.
            // Get one signed under a "prove your identity" dialog and the answer is a valid key
            // rotation. Only this side can tell the two apart, and nothing in LIM refuses on a
            // vault's behalf — the parser hands the bytes over and this is the call that stops.
            if (Utils.isStatementPreImage(request.nonce)) return null
            val algorithm = "SHA256withRSA"
            val signature = Signature.getInstance(algorithm).run {
                initSign(profileKey)
                update(request.nonce)
                sign()
            }
            // `algorithm` is informational and is honoured by nothing: the client's verification
            // hardcodes `SHA256withRSA`, because taking the algorithm from the sender is how
            // algorithm confusion gets in. Declare it for a reader, not for a verifier.
            return Utils.createSignChallengeResultIntent(request, signature, heldProfile, algorithm)
        }
        // endregion snippet:vault-answer-login

        val answer = answerLogin(incoming, profileKeyPair.private)!!
        val asTheClientReadsIt = Utils.parseSignChallengeResult(answer)!!
        assertTrue(
            "the client authenticates the answer against the key it already stores and the " +
                "nonce it generated — the whole point of the flow, and the only check that " +
                "decides whether a login happened",
            asTheClientReadsIt.isVerified(storedKey, nonce),
        )
        assertEquals("the profile travels beside the proof", heldProfile, asTheClientReadsIt.fields)
        assertTrue(
            "…correlated to the request it answers",
            Utils.matchesRequestCode(answer, REQUEST_CODE),
        )
        assertFalse(
            "a signature over bytes the client did not send authenticates nothing, which is " +
                "what makes the nonce the client's to choose",
            asTheClientReadsIt.isVerified(storedKey, Utils.generateNonce()),
        )
        assertFalse(
            "…and neither does one from a key the client does not hold",
            asTheClientReadsIt.isVerified(otherKey, nonce),
        )

        // The one nonce the region refuses, and the reason the refusal is in the published block
        // rather than only in prose: a page a vault author copies from must not hand them a
        // signing oracle. `ClientIntegrationExampleTest > the vault refuses to sign a statement
        // pre-image handed to it as a challenge` holds the same property over a different
        // fixture; what is asserted here is that *this* block refuses.
        val preImage = Utils.rotationStatementBytes(
            RotationStatement(
                oldPublicKey = storedKey,
                newPublicKey = otherKey,
                statementId = "rotation-dressed-as-a-login",
                issuedAtMillis = 1_770_000_000_000L,
                expiresAtMillis = 1_770_000_600_000L,
            ),
        )
        assertTrue("precondition: these bytes are a statement", Utils.isStatementPreImage(preImage))
        assertNull(
            "a statement's pre-image offered as a challenge is refused, unsigned: signing it " +
                "would answer a `prove your identity` dialog with a valid key rotation",
            answerLogin(
                Utils.createSignChallengeIntent(context, storedKey, preImage, REQUEST_CODE),
                profileKeyPair.private,
            ),
        )
        assertFalse(
            "…and the refusal is the pre-image's doing rather than a function that refuses " +
                "everything: a generated nonce is never one",
            Utils.isStatementPreImage(nonce),
        )
    }

    /**
     * The one answer that acknowledges the optional-fields declaration, and the two things a vault
     * must not get wrong about it: the acknowledgement rides on the **answer** only, and it is
     * written only when the stored payload satisfies what the client declared.
     *
     * The assertions read the acknowledgement back with `parseAppliedOptionalFields` and then with
     * `checkFieldRequirements`, which is the verdict the client's own handler branches on — so the
     * page's claim is held to what the client concludes rather than to an extra being present.
     * `ResultBuilderTest` owns the exhaustive version of the "only when satisfied" rule, over
     * every shape of payload; what is asserted here is the one pair the page shows.
     */
    @Test
    fun `the requirements-aware answer acknowledges a declaration the stored payload satisfies`() {
        val incoming = Utils.createShareIntent(
            context,
            pushedEntry(),
            REQUEST_CODE,
            setOf("phone"),
            Utils.DEFAULT_ENDEAVOR_PACKAGE,
        )
        val request = Utils.parseShareRequest(incoming)!!
        val declared = Utils.parseFieldRequirements(incoming)!!
        // What the user typed: both required rows filled in, the optional one left blank.
        val draft = linkedMapOf(
            "name" to TypedField("Ada", FieldType.STRING),
            "email" to TypedField("ada@example.test", FieldType.EMAIL),
            "phone" to TypedField("", FieldType.PHONE),
        )

        // region snippet:vault-answer-optional
        // A vault that enforces the optional-fields declaration says what it enforced, and says
        // it on the answer only — there is no extra on the request to echo back. `committed` is
        // the Save gate and the payload in one: it is `null` exactly while a required row is
        // still blank, and it drops the optional rows the user left empty rather than storing
        // them as blank values.
        val stored = declared.committed(draft)
        // The acknowledgement rides on this overload, which has no request-taking sibling — pass
        // the token off the parsed request yourself. It writes the acknowledgement only when the
        // payload satisfies the declaration, so the answer can never claim more than it carries.
        val answer = stored?.let {
            Utils.createShareResultIntent(storedKey, it, request.requestCode, declared)
        }
        // endregion snippet:vault-answer-optional

        assertEquals(
            "the optional row the user left blank is dropped, not stored empty",
            setOf("name", "email"),
            stored?.keys,
        )
        assertEquals(
            "the answer says which fields it applied the declaration to",
            setOf("phone"),
            Utils.parseAppliedOptionalFields(answer),
        )
        assertEquals(
            "…and the verdict the client's handler branches on is the honoured one",
            FieldRequirementsVerdict.HONOURED,
            Utils.checkFieldRequirements(declared, answer!!),
        )
        // The rest of the envelope, read back the way the other three answers are. Neither
        // assertion above reaches it — `parseAppliedOptionalFields` and `checkFieldRequirements`
        // read the two field extras and nothing else — so without these two the published block
        // could pass a blank key and a dropped token and stay green, which is the one failure
        // this file exists to make impossible.
        assertEquals(
            "the answer still names the key the profile was stored under",
            storedKey,
            Utils.parseShareResult(answer)!!.publicKey,
        )
        assertTrue(
            "…and still carries the token off the parsed request, which this overload does not " +
                "do for you",
            Utils.matchesRequestCode(answer, REQUEST_CODE),
        )
        assertNull(
            "a draft with a required row still blank has nothing to answer with: Save is " +
                "blocked, and the client sees a refusal rather than a short profile",
            declared.committed(draft + ("name" to TypedField("", FieldType.STRING))),
        )
        assertNull(
            "and an answer whose payload does not satisfy the declaration acknowledges " +
                "nothing, rather than claiming a declaration it broke — the client reads it as " +
                "an answer from a vault that enforced nothing",
            Utils.parseAppliedOptionalFields(
                Utils.createShareResultIntent(storedKey, draft, request.requestCode, declared),
            ),
        )
    }

    // ── Refusing ──────────────────────────────────────────────────────────

    /**
     * The fourth answer, and the one no builder in this library mints: `RESULT_CANCELED` carrying
     * the echoed correlation token and nothing else.
     *
     * Two properties, and both are the section's whole claim. **The token has to be there** —
     * strip it and `matchesRequestCode` goes false, so the client cannot tell which request was
     * refused, which is asserted here rather than argued. And **a refusal is a result code, not a
     * payload**: the intent above parses as a readable envelope with nothing in it, so a handler
     * that branched on the payload would read a refusal as an answer that disclosed nothing.
     *
     * **Why no builder, measured rather than asserted in prose.** Every result builder here
     * attaches `extra_protocol_version` unconditionally, so routing a refusal through one would
     * tell the caller that something on this side understood the request — one bit more than a
     * bare refusal gives. The extras of both shapes are compared below. Whether LIM should
     * publish a refusal builder, and whether a refusal should carry the version, is a protocol
     * decision drafted under "Blocked on human"; this test pins today's shape so that question
     * has to be answered rather than drift.
     */
    @Test
    fun `a refusal is a result code and the echoed token, and a builder would say more than that`() {
        val request = Utils.parseQueryRequest(queryIntent())!!

        // region snippet:vault-refusal
        // Refusal is a first-class answer — the user declined, or this vault holds no such
        // profile — and it is the one answer no builder here mints. Two lines: the result code,
        // and the correlation token echoed back. Not an empty intent, because correlation has to
        // survive a refusal or the client cannot tell which request was refused.
        val refusalCode = Activity.RESULT_CANCELED
        val refusal = Intent().apply {
            request.requestCode?.let { putExtra(Utils.EXTRA_SHARE_REQUEST_CODE, it) }
        }
        // `setResult(refusalCode, refusal)` and finish. Attach nothing else: no reason, no
        // status, no version echo. A refusal that said why would also be saying that something
        // on this side understood the request, and that is a disclosure of its own.
        // endregion snippet:vault-refusal

        assertEquals(
            "precondition: a refusal is a result code, and the payload is not what says so",
            Activity.RESULT_CANCELED,
            refusalCode,
        )
        assertTrue(
            "the echoed token is what makes a refusal correlatable at all",
            Utils.matchesRequestCode(refusal, REQUEST_CODE),
        )
        assertFalse(
            "…and dropping it is the one way to get this wrong: the client is then holding a " +
                "refusal it cannot attribute to a request",
            Utils.matchesRequestCode(Intent(), REQUEST_CODE),
        )
        assertEquals(
            "one extra and no more",
            setOf(Utils.EXTRA_SHARE_REQUEST_CODE),
            refusal.extras!!.keySet(),
        )
        assertEquals(
            "the refusal still parses — it is a readable envelope with nothing in it, so the " +
                "result code is the only thing that says it is a refusal",
            QueryResult(emptyMap(), null, REQUEST_CODE, null),
            Utils.parseQueryResult(refusal),
        )

        // The measurement behind "no builder": the nearest thing a builder can mint carries
        // three extras the refusal does not, including the version echo.
        val throughABuilder = Utils.createQueryResultIntent(request, storedKey, emptyMap())
        assertEquals(
            "a builder-minted answer with nothing disclosed is not this refusal: it names the " +
                "key, carries an empty payload and echoes the protocol version",
            setOf(
                Utils.EXTRA_SHARE_REQUEST_CODE,
                Utils.EXTRA_PUBLIC_KEY,
                Utils.EXTRA_QUERY_RESULT_FIELDS,
                Utils.EXTRA_PROTOCOL_VERSION,
            ),
            throughABuilder.extras!!.keySet(),
        )
        assertEquals(
            "…and that version echo is the bit at stake: the refusal declares nothing, so a " +
                "refused client cannot tell a current vault's decision from a legacy vault " +
                "ignoring a request it did not understand",
            null,
            Utils.parseQueryResult(refusal)!!.vaultProtocolVersion,
        )
        assertEquals(
            Utils.PROTOCOL_VERSION,
            Utils.parseQueryResult(throughABuilder)!!.vaultProtocolVersion,
        )
    }

    /**
     * The obligation the *What a vault must do* section states and no test in this repository held:
     * **a refusal does not say which of its two reasons it is.**
     *
     * "The user declined" and "this vault holds no such profile" have to be one answer. A vault
     * that distinguished them would answer every key it was *not* told "no such profile" about with
     * the news that a profile for it exists, which turns a refusal into a disclosure about the key
     * — and the key is the account identifier, so that is a disclosure about the account.
     *
     * **Why this needs a vault-shaped fixture rather than two hand-built intents.** Two refusals
     * written side by side are equal because one author typed them that way; the obligation is
     * about a *decision*, so the fixture below has to make it. `answerQuery` is the whole of a
     * vault's query handling as this page describes it, and the two causes meet in one arm of one
     * `if` deliberately. Give that arm a second branch — a reason extra, a different result code,
     * a `null` payload for the unknown key — and the comparison below reddens, which is what makes
     * this a test of the obligation and not of `Intent`'s equality.
     *
     * `GuideExamplesTest > an integrator mints the refusal too, and it reads exactly as a vault's
     * does` is the nearest existing assertion and a different claim: it compares an integrator's
     * hand-built refusal against the one `FixtureVault` sends for a key it does not hold. That pins
     * the *shape* an integrator should test against. It never asks the vault for the other cause,
     * so it cannot see a vault that answered the two differently — which is this test's subject.
     */
    @Test
    fun `a refusal for a key this vault does not hold is the refusal for a consent the user withheld`() {
        // A vault's query handling, entire. The two causes of a refusal are one arm on purpose:
        // the vault holds no such profile, or the user said no, and the client learns neither.
        fun answerQuery(incoming: Intent, consents: Boolean): Pair<Int, Intent> {
            val request = Utils.parseQueryRequest(incoming)
                ?: return Activity.RESULT_CANCELED to Intent()
            if (request.publicKey != storedKey || !consents) {
                return Activity.RESULT_CANCELED to Intent().apply {
                    request.requestCode?.let { putExtra(Utils.EXTRA_SHARE_REQUEST_CODE, it) }
                }
            }
            return Activity.RESULT_OK to
                Utils.createQueryResultIntent(request, storedKey, heldProfile)
        }

        val askingAboutTheHeldKey = queryIntent()
        val askingAboutAKeyThisVaultNeverMinted =
            Utils.createQueryIntent(context, publicKey = otherKey, requestCode = REQUEST_CODE)

        // Cause one: the vault holds the profile and the user declined to disclose it.
        val withheld = answerQuery(askingAboutTheHeldKey, consents = false)
        // Cause two: the user would have consented, and there is no such profile to consent about.
        val noSuchProfile = answerQuery(askingAboutAKeyThisVaultNeverMinted, consents = true)

        assertEquals(
            "precondition: the second request names a key this vault did not mint, so the two " +
                "refusals really do have different causes",
            false,
            Utils.parseQueryRequest(askingAboutAKeyThisVaultNeverMinted)!!.publicKey == storedKey,
        )
        assertEquals(
            "both causes are refusals, and the result code is the whole of what a client is told",
            withheld.first,
            noSuchProfile.first,
        )
        assertEquals(
            "…and the two payloads are the same extras with the same *values*: a vault that " +
                "attached a reason, a status or a different envelope to one of them would be " +
                "telling every caller that a profile exists for every key it is not told that " +
                "about",
            extrasOf(withheld.second),
            extrasOf(noSuchProfile.second),
        )
        assertEquals(
            "…and read back the way a client reads them, the two are the same answer rather " +
                "than two answers that happen to share a shape",
            Utils.parseQueryResult(withheld.second),
            Utils.parseQueryResult(noSuchProfile.second),
        )
        assertTrue(
            "both stay correlatable, which is the one thing a refusal must carry",
            Utils.matchesRequestCode(withheld.second, REQUEST_CODE) &&
                Utils.matchesRequestCode(noSuchProfile.second, REQUEST_CODE),
        )

        // The floor under all of that: a refusal is distinguishable from the answer the same
        // function gives when it does consent, or the comparisons above would hold of a vault
        // that refused nothing and disclosed everything.
        val disclosed = answerQuery(askingAboutTheHeldKey, consents = true)
        assertEquals(
            "precondition: consent is answerable, so refusing is a decision and not this " +
                "fixture's only behaviour",
            Activity.RESULT_OK,
            disclosed.first,
        )
        assertNotEquals(
            "…and the answer is not the refusal: what the two refusals share is not shared by " +
                "everything this vault sends",
            extrasOf(withheld.second),
            extrasOf(disclosed.second),
        )

        // The other half of the same obligation, and the arm `answerQuery` reaches first: an
        // intent that does not parse is answered with the refusal and no payload at all. There
        // is nothing to echo — the token is read off a parse that did not happen — and nothing
        // to show a user, so this is the shape "answer nothing" has on the wire.
        val nothingParsesIt = Intent(Utils.shareDataAction(context.packageName))
        assertNull(
            "precondition: this intent really does reach the arm under test — it names no key, " +
                "so no request parses out of it. Without this the two assertions below would " +
                "still pass off the *refusal* arm, which also answers RESULT_CANCELED with no " +
                "extras when a request carries no token, and would stop testing what they cite",
            Utils.parseQueryRequest(nothingParsesIt),
        )
        val unparseable = answerQuery(nothingParsesIt, true)
        assertEquals(
            "an intent no parser accepts is refused rather than answered",
            Activity.RESULT_CANCELED,
            unparseable.first,
        )
        assertEquals(
            "…and carries nothing: not an error, not a reason, and not a correlation token, " +
                "because the token is read off a parse that did not happen",
            emptyList<String>(),
            extrasOf(unparseable.second),
        )
    }

    /**
     * An intent's extras as `key=value` strings, sorted — what the refusals above are compared by.
     *
     * **Keys alone are not enough, and that is the one thing to understand about this helper.** A
     * vault leaking which reason a refusal has would most naturally do it by writing one extra
     * whose *value* differs — `putExtra("reason", "no_such_profile")` against
     * `putExtra("reason", "declined")` — and a comparison of key sets reads those two as the same
     * answer. So the values are in the comparison. (It is also why this is not
     * `extras.keySet()`: that view's `toString` is its identity, so a failure printed two hash
     * codes and named neither the extra that differed nor the refusal carrying it.)
     *
     * What it still does not reach: a reason smuggled into the result intent's action, data or
     * flags rather than its extras. No vault in this repository does that and no builder here
     * writes one, so the comparison is drawn where the payload is — but it is a limit rather than
     * a complete answer.
     */
    @Suppress("DEPRECATION")
    private fun extrasOf(intent: Intent): List<String> =
        intent.extras?.let { bundle ->
            bundle.keySet().sorted().map { key -> "$key=${bundle.get(key)}" }
        } ?: emptyList()

    // ── Fixtures ──────────────────────────────────────────────────────────

    /** A sign-up as a client sends one: keys and types filled in, values for the user to type. */
    private fun pushedEntry(): Entry = Entry(
        id = "signup-form",
        fields = linkedMapOf(
            "name" to TypedField("", FieldType.STRING),
            "email" to TypedField("", FieldType.EMAIL),
            "phone" to TypedField("", FieldType.PHONE),
        ),
        publicKey = "no-key-yet",
    )

    /**
     * A sign-up request as a client sends one, with the correlation token **named**.
     *
     * `requestCode` is named rather than passed third, and that is not a style choice: there are
     * three `createShareIntent` overloads and the third parameter is a `String` in two of them —
     * `requestCode` in one, `targetPackage` in the other, which has a default. Kotlin resolves
     * three positional arguments to the overload that uses no default, so a bare
     * `createShareIntent(context, entry, "sign-up-1")` compiles, builds an intent addressed to a
     * package called `sign-up-1`, and attaches no correlation token at all. Measured here, not
     * reasoned about: that spelling made the routing test above read `not ours`.
     */
    private fun signUpIntent(): Intent =
        Utils.createShareIntent(context, pushedEntry(), requestCode = REQUEST_CODE)

    /** A query naming the key this vault holds. */
    private fun queryIntent(): Intent =
        Utils.createQueryIntent(context, publicKey = storedKey, requestCode = REQUEST_CODE)

    /** A share-shaped intent carrying [payload] verbatim, so a hostile one can be driven through. */
    private fun shareIntentCarrying(payload: String): Intent =
        Intent(Utils.shareDataAction(Utils.DEFAULT_ENDEAVOR_PACKAGE))
            .putExtra(Utils.EXTRA_ENTRY_JSON, payload)

    private fun challenge(): Intent = Utils.createSignChallengeIntent(
        context,
        publicKey = storedKey,
        nonce = Utils.generateNonce(),
        requestCode = REQUEST_CODE,
    )

    /** The profile this vault holds, as the user filled it in — what an answer discloses from. */
    private val heldProfile = linkedMapOf(
        "name" to TypedField("Ada", FieldType.STRING),
        "email" to TypedField("ada@example.test", FieldType.EMAIL),
        "phone" to TypedField("+44 7700 900123", FieldType.PHONE),
    )

    companion object {
        private const val REQUEST_CODE = "sign-up-1"

        private val FIELD_NAMES = listOf("name", "email", "phone")

        /**
         * The keypair this vault minted for its one profile.
         *
         * A **real** 2048-bit RSA pair rather than a placeholder string, because the login answer
         * below is a genuine signature and the only read-back worth making of one is the client's
         * own `isVerified`. Generation costs ~100ms, so it happens once for the class — the
         * arrangement `GuideExamplesTest` and `ClientIntegrationExampleTest` both use.
         */
        private lateinit var profileKeyPair: KeyPair

        /**
         * The key as a vault hands it out: the Base64 public half, opaque to everybody, and the
         * account identifier for ever after. The client stores this and nothing else.
         */
        private lateinit var storedKey: String

        /** A second key, so "verifies against the wrong key" can be asserted rather than asserted of nothing. */
        private lateinit var otherKey: String

        @JvmStatic
        @BeforeClass
        fun mintTheProfilesKeys() {
            val generator = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }
            profileKeyPair = generator.generateKeyPair()
            storedKey = Base64.encodeToString(profileKeyPair.public.encoded, Base64.NO_WRAP)
            otherKey = Base64.encodeToString(
                generator.generateKeyPair().public.encoded,
                Base64.NO_WRAP,
            )
        }
    }
}
