package dev.eryalabs.lim

import android.content.Context
import android.content.Intent
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

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
 * This task's page is the **reading** half of a vault's work — routing a request and reading a
 * share. Answering one, and the obligations a vault owes, are later instalments, and nothing here
 * pretends to show them.
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
            STORED_KEY,
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

    /** A query naming a key the vault is assumed to hold already. */
    private fun queryIntent(): Intent =
        Utils.createQueryIntent(context, publicKey = STORED_KEY, requestCode = REQUEST_CODE)

    /** A share-shaped intent carrying [payload] verbatim, so a hostile one can be driven through. */
    private fun shareIntentCarrying(payload: String): Intent =
        Intent(Utils.shareDataAction(Utils.DEFAULT_ENDEAVOR_PACKAGE))
            .putExtra(Utils.EXTRA_ENTRY_JSON, payload)

    private fun challenge(): Intent = Utils.createSignChallengeIntent(
        context,
        publicKey = STORED_KEY,
        nonce = Utils.generateNonce(),
        requestCode = REQUEST_CODE,
    )

    private companion object {
        private const val REQUEST_CODE = "sign-up-1"

        /** A key as a vault holds one: opaque to everybody, and the account identifier. */
        private const val STORED_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A-fixture"

        private val FIELD_NAMES = listOf("name", "email", "phone")
    }
}
