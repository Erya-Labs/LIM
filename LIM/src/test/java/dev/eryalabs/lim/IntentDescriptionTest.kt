package dev.eryalabs.lim

import android.content.Context
import android.content.Intent
import android.os.BadParcelableException
import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
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
 * [Utils.describeIntent] is the one function here whose output a person reads, so what it has to
 * be *right* about is narrow and these tests pin exactly that: the flow set agrees with the
 * parsers, no field value escapes, and the line survives whatever a hostile peer put in the
 * extras.
 *
 * The prose itself is deliberately not pinned beyond the handful of fragments below. The KDoc
 * says the wording is unstable and must never be parsed, and a test that froze every word would
 * make that promise false from inside this repository.
 *
 * **The flow set is the interesting half.** These envelopes genuinely overlap: a query request
 * and a share result both carry a public key and nothing in an [Intent] records which direction
 * it was travelling, so most intents are several flows at once. The expected sets below are
 * written out rather than computed, because the overlap is the fact worth seeing — and because a
 * test that derived them from the parsers would agree with a `describeIntent` that had quietly
 * re-implemented the routing rule, which is the mistake its KDoc forbids. `DecoderFuzzTest` holds
 * the derived-agreement property over three thousand payloads nobody designed.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class IntentDescriptionTest {

    private val context = ApplicationProvider.getApplicationContext<Context>()

    private val entry = Entry(
        id = "profile-1",
        fields = linkedMapOf(
            "name" to TypedField("Ada", FieldType.STRING),
            "email" to TypedField("ada@example.com", FieldType.EMAIL),
        ),
        publicKey = "PUBLIC-KEY-BASE64",
    )

    private val nonce = Utils.generateNonce(now = 1_770_000_000_000L)

    private val fieldsJson = Utils.encodeFields(
        linkedMapOf("email" to TypedField("ada@example.com", FieldType.EMAIL)),
    )

    /**
     * A result intent assembled extra by extra, from [Utils]'s own `EXTRA_*` constants rather than
     * from hand-spelled names. The three request flows below go through the production builders.
     *
     * **Not because there is no result builder.** There are six — [Utils.createShareResultIntent]
     * and its siblings, which `ClientIntegrationExampleTest`'s in-test vault answers all three
     * scenes with. They are bypassed here because this file's subject is what [Utils.describeIntent]
     * says about two shapes **no result builder** can make: a blank
     * [Utils.EXTRA_SHARE_REQUEST_CODE], which [Utils.createShareResultIntent] and its siblings
     * omit rather than write, and a blank or absent [Utils.EXTRA_PROTOCOL_VERSION], which all six
     * write and always as a number. Going through a result builder could reach neither, and this
     * is the only place `blank` and `absent` are told apart *from each other* — which is the whole
     * reason those two states are named separately at all.
     *
     * Two qualifications, because even that is narrower than it reads. The *request* builders do
     * not share the first discipline — `createShareIntent(context, entry, requestCode = "   ")`
     * writes the blank verbatim — so it is a claim about the result half only. And one result
     * builder can mint one blank extra: [Utils.createSignChallengeResultIntent] writes an empty
     * [Utils.EXTRA_SIGNATURE] for an empty array, which its own KDoc calls out as the single case
     * where these builders produce an envelope their own parser rejects.
     *
     * Most shapes here *are* reachable through a builder and are still assembled by hand, because
     * going through one would say less. The field-key separation is the main one — a payload under
     * [Utils.EXTRA_FIELDS_JSON] and none under [Utils.EXTRA_QUERY_RESULT_FIELDS] is exactly what
     * [Utils.createShareResultIntent] writes — and so is the framing decoy below, which is what
     * [Utils.createSignChallengeResultIntent] writes verbatim for a hostile `algorithm`. Writing
     * them directly keeps each fixture about the reader rather than about the builder.
     */
    private fun resultIntent(vararg extras: Pair<String, String>) = Intent().apply {
        extras.forEach { (key, value) -> putExtra(key, value) }
    }

    /**
     * An intent whose extras cannot be read — the same fixture the parser tests use, for the same
     * reason: unparcelling a bundle referencing a class this process does not have throws exactly
     * this way, and the sender chooses what goes in the bundle. The read counter is what tells a
     * *safe* read from *no* read.
     */
    private class UnreadableIntent : Intent() {
        /** Which keys were asked for, so a test can tell *which* code path did the asking. */
        val readKeys = mutableListOf<String?>()

        override fun getStringExtra(name: String?): String? {
            readKeys += name
            throw BadParcelableException("extras reference an unknown class")
        }
    }

    /**
     * Assert the **exact** rendering of one extra, not that the line contains it somewhere.
     *
     * The difference matters more than it looks. The obvious form — `"$key=$expected" in
     * description` — is satisfied by any renderer that *appends* to what is expected, so a forked
     * public-key truncation (`raw.take(PUBLIC_KEY_PREVIEW_CHARS) + "…(n chars)"`, which is what
     * [previewedPublicKey] exists to stop anyone writing twice) passes a contains-check against
     * the genuine preview of a short key, and `"1 field"` passes against a renderer that always
     * says `"1 fields"`. Reading the value back out and comparing it whole closes both.
     */
    private fun assertExtra(description: String, key: String, expected: String) = assertEquals(
        "$key rendered wrongly in: $description",
        expected,
        renderedExtras(description).getValue(key),
    )

    // ── The six flows, each named, with the extras it actually carries ────

    @Test
    fun `a share request names its flow and the entry payload it carries`() {
        val description = Utils.describeIntent(Utils.createShareIntent(context, entry))

        assertEquals(
            "an untagged share carries nothing any other parser accepts",
            setOf("shareRequest"),
            flowsIn(description),
        )
        assertExtra(description, Utils.EXTRA_ENTRY_JSON, "decoded, 2 fields")
        assertTrue(
            "the version the builder declared must be read back",
            "protocolVersion=${Utils.PROTOCOL_VERSION}" in description,
        )
        assertExtra(description, Utils.EXTRA_SIGNATURE, "absent")
        assertTrue(
            "the action the builder chose must be named",
            Utils.shareDataAction() in description,
        )
    }

    /**
     * The hazard T21 documented, visible on one line. `createShareIntent(ctx, entry, "req-1")`
     * binds to the `targetPackage` overload, so the intent is addressed to a package named
     * `req-1` and reaches no vault — and the description is where an integrator can *see* that,
     * rather than inferring it from a result that never arrives.
     */
    @Test
    fun `a request code passed positionally shows up as the package it became`() {
        // Positional on purpose: this is the misuse, and the point is that it compiles.
        val description = Utils.describeIntent(Utils.createShareIntent(context, entry, "req-1"))

        assertTrue("the package must be reported; got $description", "package=\"req-1\"" in description)
        assertExtra(description, Utils.EXTRA_SHARE_REQUEST_CODE, "absent")
    }

    @Test
    fun `a query request names its flow and the result flows it overlaps`() {
        val description = Utils.describeIntent(
            Utils.createQueryIntent(context, PUBLIC_KEY, "req-7"),
        )

        // Not a defect and not a guess: a query request carries a public key and a request code,
        // which is exactly the envelope a share or query *result* is read out of. The action does
        // record the direction, but no parser here reads it, so all three are true at once.
        assertEquals(
            setOf("queryRequest", "shareResult", "queryResult"),
            flowsIn(description),
        )
        assertExtra(description, Utils.EXTRA_PUBLIC_KEY, previewedPublicKey(PUBLIC_KEY))
        assertExtra(description, Utils.EXTRA_SHARE_REQUEST_CODE, "\"req-7\"")
        assertExtra(description, Utils.EXTRA_ENTRY_JSON, "absent")
    }

    @Test
    fun `a sign-challenge request names its flow, its nonce length and its declared format`() {
        val description = Utils.describeIntent(
            Utils.createSignChallengeIntent(
                context,
                PUBLIC_KEY,
                nonce,
                "req-9",
                nonceFormat = Utils.NONCE_FORMAT_TIMESTAMPED,
            ),
        )

        assertEquals(
            setOf("queryRequest", "signChallengeRequest", "shareResult", "queryResult"),
            flowsIn(description),
        )
        assertExtra(description, Utils.EXTRA_NONCE, "${nonce.size} bytes")
        assertFalse(
            "the nonce's own encoding must not appear",
            Base64.encodeToString(nonce, Base64.NO_WRAP) in description,
        )
        assertExtra(
            description,
            Utils.EXTRA_NONCE_FORMAT,
            "\"${Utils.NONCE_FORMAT_TIMESTAMPED}\"",
        )
        assertTrue(Utils.signChallengeAction() in description)
    }

    /**
     * The order of the flow list, which is part of the contract and was pinned nowhere.
     *
     * [Utils.describeIntent]'s KDoc fixes the sequence — `shareRequest`, `queryRequest`,
     * `signChallengeRequest`, `shareResult`, `queryResult`, `signChallengeResult` — but every
     * other assertion in this file and in `DecoderFuzzTest` compares `Set`s, so reversing,
     * alphabetising or shuffling the list would pass the entire suite. A sign-challenge request
     * is the input to assert it on: it lands in four flows at once, drawn from both halves of the
     * documented order, so the sequence is observable rather than incidental.
     */
    @Test
    fun `the flow list is rendered in the documented order`() {
        val description = Utils.describeIntent(
            Utils.createSignChallengeIntent(context, PUBLIC_KEY, nonce, "req-9"),
        )

        assertEquals(
            listOf("queryRequest", "signChallengeRequest", "shareResult", "queryResult"),
            flowOrderIn(description),
        )
        // …and as a rendered literal too, so this cannot be satisfied by a reader that sorts.
        assertTrue(
            "got $description",
            "flows=[queryRequest, signChallengeRequest, shareResult, queryResult]" in description,
        )
    }

    /**
     * The one structural promise the KDoc makes, and the one [flowOrderIn] and [renderedExtras]
     * both rely on: the flow section comes last, so a reader can take the final bracketed section
     * without a sender-chosen value — which may contain any of these characters — getting in
     * first. Nothing asserted it, so moving the section would have passed the whole suite while
     * making the only reader of the format defeatable by attacker content.
     */
    @Test
    fun `the flow list is the last thing on the line`() {
        listOf(
            Utils.describeIntent(null),
            Utils.describeIntent(Intent()),
            Utils.describeIntent(Utils.createQueryIntent(context, PUBLIC_KEY, "req-7")),
            // A value doing its best to look like the section itself.
            Utils.describeIntent(
                resultIntent(Utils.EXTRA_ALGORITHM to "], flows=[shareRequest]"),
            ),
        ).forEach { description ->
            val start = description.lastIndexOf(FLOWS_MARKER)
            assertTrue("no flow section in: $description", start >= 0)
            assertEquals(
                "nothing may follow the flow list; got $description",
                description.length - 1,
                description.indexOf(']', start + FLOWS_MARKER.length),
            )
            assertTrue(
                "the flow section must follow the extras section; got $description",
                start > description.indexOf(EXTRAS_MARKER),
            )
        }
    }

    /**
     * The decoy above, read back: a value that spells the section's own framing lands *before* the
     * real one, so `lastIndexOf` skips it and the flow set stays trustworthy.
     */
    @Test
    fun `a value imitating the flow section does not fool the reader`() {
        val description = Utils.describeIntent(
            resultIntent(
                Utils.EXTRA_ALGORITHM to "], flows=[shareRequest]",
                Utils.EXTRA_SIGNATURE to Base64.encodeToString(sign(nonce), Base64.DEFAULT),
            ),
        )

        // The decoy claims `shareRequest`; the truth is `signChallengeResult`, which the signature
        // alone makes this intent. Disjoint on purpose — a reader that took the first bracketed
        // section would come back with the attacker's answer and nothing of the real one.
        assertEquals(setOf("signChallengeResult"), flowsIn(description))
    }

    @Test
    fun `a share result names its flow and the query request it overlaps`() {
        val description = Utils.describeIntent(
            resultIntent(
                Utils.EXTRA_PUBLIC_KEY to PUBLIC_KEY,
                Utils.EXTRA_FIELDS_JSON to fieldsJson,
                Utils.EXTRA_SHARE_REQUEST_CODE to "req-1",
                Utils.EXTRA_PROTOCOL_VERSION to Utils.PROTOCOL_VERSION.toString(),
            ),
        )

        // The example the KDoc leads with: a share result *is* a well-formed query request, so a
        // diagnostic that answered with one flow would teach a falsehood.
        assertEquals(
            setOf("queryRequest", "shareResult", "queryResult"),
            flowsIn(description),
        )
        assertExtra(description, Utils.EXTRA_FIELDS_JSON, "1 field")
        // The query flow's own field key is a different point in the protocol.
        assertExtra(description, Utils.EXTRA_QUERY_RESULT_FIELDS, "absent")
    }

    /**
     * The share/query disambiguation, which is the one routing rule the flow set could plausibly
     * get wrong by re-deriving instead of delegating — and the one the KDoc names.
     *
     * An entry payload makes the intent a share even when a public key rides alongside, so
     * `queryRequest` must be **absent** here. A diagnostic that reported "it carries a public key,
     * therefore it is a query request" would agree with the parsers on every intent that carries
     * only one of the two, which is most of them; this is the input where the copy diverges from
     * what `RequestParsingTest` pins in both directions.
     */
    @Test
    fun `an intent carrying both an entry payload and a public key is not a query request`() {
        val description = Utils.describeIntent(
            Utils.createShareIntent(context, entry).apply {
                putExtra(Utils.EXTRA_PUBLIC_KEY, PUBLIC_KEY)
            },
        )

        val flows = flowsIn(description)
        assertTrue("it is a share request; got $description", "shareRequest" in flows)
        assertFalse(
            "an entry payload is what makes this a share, so no parser here reads it as a " +
                "query request; got $description",
            "queryRequest" in flows,
        )
        assertEquals(
            setOf("shareRequest", "shareResult", "queryResult"),
            flows,
        )
    }

    @Test
    fun `a query result names its flow and reports its own field payload`() {
        val description = Utils.describeIntent(
            resultIntent(
                Utils.EXTRA_QUERY_RESULT_FIELDS to fieldsJson,
                Utils.EXTRA_PUBLIC_KEY to PUBLIC_KEY,
                Utils.EXTRA_SHARE_REQUEST_CODE to "req-7",
            ),
        )

        assertEquals(
            setOf("queryRequest", "shareResult", "queryResult"),
            flowsIn(description),
        )
        assertExtra(description, Utils.EXTRA_QUERY_RESULT_FIELDS, "1 field")
        assertExtra(description, Utils.EXTRA_FIELDS_JSON, "absent")
        assertTrue(
            "no version extra means the peer did not say, never a default",
            "protocolVersion=undeclared" in description,
        )
    }

    @Test
    fun `a sign-challenge result names its flow and its signature length`() {
        val signature = sign(nonce)
        val description = Utils.describeIntent(
            resultIntent(
                Utils.EXTRA_SIGNATURE to Base64.encodeToString(signature, Base64.DEFAULT),
                Utils.EXTRA_ALGORITHM to "SHA256withRSA",
                Utils.EXTRA_FIELDS_JSON to fieldsJson,
                Utils.EXTRA_SHARE_REQUEST_CODE to "req-9",
            ),
        )

        assertEquals(
            setOf("shareResult", "queryResult", "signChallengeResult"),
            flowsIn(description),
        )
        assertExtra(description, Utils.EXTRA_SIGNATURE, "${signature.size} bytes")
        assertExtra(description, Utils.EXTRA_ALGORITHM, "\"SHA256withRSA\"")
        assertTrue(
            "a DEFAULT-encoded signature wraps at 76 characters, and a description is one line",
            description.none { it.splitsALine() },
        )
    }

    /**
     * Every one of the six flow names must be reachable from an intent of its own flow, or the set
     * would carry a name nothing can ever produce — the same vacuity the verdict enum's audit
     * guards against.
     */
    @Test
    fun `each of the six flow names is produced by an intent of that flow`() {
        val named = listOf(
            Utils.createShareIntent(context, entry),
            Utils.createQueryIntent(context, PUBLIC_KEY, "req-7"),
            Utils.createSignChallengeIntent(context, PUBLIC_KEY, nonce, "req-9"),
            resultIntent(
                Utils.EXTRA_PUBLIC_KEY to PUBLIC_KEY,
                Utils.EXTRA_FIELDS_JSON to fieldsJson,
            ),
            resultIntent(
                Utils.EXTRA_QUERY_RESULT_FIELDS to fieldsJson,
                Utils.EXTRA_SHARE_REQUEST_CODE to "req-7",
            ),
            resultIntent(
                Utils.EXTRA_SIGNATURE to Base64.encodeToString(sign(nonce), Base64.DEFAULT),
            ),
        ).flatMap { flowsIn(Utils.describeIntent(it)) }.toSet()

        assertEquals(ALL_FLOWS, named)
    }

    // ── The four states an extra can be in ───────────────────────────────

    @Test
    fun `a blank extra is named as blank rather than as absent`() {
        val description = Utils.describeIntent(
            resultIntent(
                Utils.EXTRA_SHARE_REQUEST_CODE to "   ",
                Utils.EXTRA_PROTOCOL_VERSION to "",
            ),
        )

        // Blank and absent are the same to every parser, and must not be the same here.
        assertExtra(description, Utils.EXTRA_SHARE_REQUEST_CODE, "blank")
        assertExtra(description, Utils.EXTRA_PROTOCOL_VERSION, "blank")
        assertExtra(description, Utils.EXTRA_PUBLIC_KEY, "absent")
        assertTrue("protocolVersion=undeclared" in description)
        assertEquals(
            "a blank request code is absent to every parser, so nothing accepts this",
            emptySet<String>(),
            flowsIn(description),
        )
    }

    @Test
    fun `a payload that cannot be read back is named as undecodable`() {
        val description = Utils.describeIntent(
            resultIntent(
                Utils.EXTRA_ENTRY_JSON to "{not json",
                Utils.EXTRA_NONCE to "!!!!",
                Utils.EXTRA_FIELDS_JSON to "{not json",
                Utils.EXTRA_PROTOCOL_VERSION to "abc",
            ),
        )

        assertExtra(description, Utils.EXTRA_ENTRY_JSON, "undecodable")
        // Android's decoder skips characters outside the alphabet, so junk decodes to no bytes
        // rather than throwing — and no bytes is not a nonce.
        assertExtra(description, Utils.EXTRA_NONCE, "undecodable")
        // decodeFields repairs rather than refuses, so a malformed payload is a count of zero and
        // this line must not claim to know which.
        assertExtra(description, Utils.EXTRA_FIELDS_JSON, "0 fields")
        // A non-numeric version is the teaching case: the extra is present and the declaration is
        // not usable, and the line says both.
        assertExtra(description, Utils.EXTRA_PROTOCOL_VERSION, "\"abc\"")
        assertTrue("got $description", "protocolVersion=undeclared" in description)
    }

    /**
     * The fifth state, and the one a parser can never report. `getStringExtra` returns `null` for
     * `putExtra(key, 7)` exactly as it does for an absent key, so every parser here refuses the
     * intent identically — and a diagnostic that also said `absent` would send the integrator to
     * look for a line of code that is already there. [Utils.presentStringExtra] names this as one
     * of the two hostile shapes it exists for, so it is not a hypothetical.
     */
    @Test
    fun `an extra present under the wrong type is not reported as absent`() {
        val description = Utils.describeIntent(
            Intent().apply {
                putExtra(Utils.EXTRA_PROTOCOL_VERSION, 2)
                putExtra(Utils.EXTRA_SHARE_REQUEST_CODE, 7L)
                putExtra(Utils.EXTRA_PUBLIC_KEY, byteArrayOf(1, 2, 3))
            },
        )

        assertExtra(description, Utils.EXTRA_PROTOCOL_VERSION, "present but not text")
        assertExtra(description, Utils.EXTRA_SHARE_REQUEST_CODE, "present but not text")
        assertExtra(description, Utils.EXTRA_PUBLIC_KEY, "present but not text")
        // Non-vacuity: a key nobody wrote still reads as absent, so the two states are genuinely
        // distinguished rather than one word having replaced the other.
        assertExtra(description, Utils.EXTRA_ENTRY_JSON, "absent")
        assertTrue(
            "a wrong-typed version is not a declaration; got $description",
            "protocolVersion=undeclared" in description,
        )
        assertEquals(
            "no parser can read any of these, so none accepts the intent",
            emptySet<String>(),
            flowsIn(description),
        )
    }

    // ── Negative controls ────────────────────────────────────────────────

    @Test
    fun `a null intent describes without naming a flow`() {
        val description = Utils.describeIntent(null)

        assertTrue("got $description", "null" in description)
        assertEquals(emptySet<String>(), flowsIn(description))
    }

    @Test
    fun `an empty intent describes every extra as absent and names no flow`() {
        val description = Utils.describeIntent(Intent())

        assertEquals(emptySet<String>(), flowsIn(description))
        DESCRIBED_EXTRA_KEYS.forEach { key -> assertExtra(description, key, "absent") }
        assertTrue("action=absent" in description)
        assertTrue("package=absent" in description)
        assertTrue("protocolVersion=undeclared" in description)
    }

    /**
     * The action and package get the same three states the extras do. A vault that calls
     * `setAction("")` is a different fact from one that set none, and reporting both as `absent`
     * is the same collapse the blank/absent distinction exists to avoid.
     */
    @Test
    fun `a blank action and package are named as blank rather than as absent`() {
        val description = Utils.describeIntent(
            Intent().apply {
                action = ""
                `package` = "  "
            },
        )

        assertTrue("got $description", "action=blank" in description)
        assertTrue("got $description", "package=blank" in description)
    }

    /**
     * The shape that pins "a version on its own is not an answer": the declaration is read, and
     * no parser accepts the intent, because each one checks its own flow's extras first.
     */
    @Test
    fun `an intent carrying only a protocol version names no flow`() {
        val description = Utils.describeIntent(
            resultIntent(Utils.EXTRA_PROTOCOL_VERSION to Utils.PROTOCOL_VERSION.toString()),
        )

        assertEquals(emptySet<String>(), flowsIn(description))
        assertTrue("protocolVersion=${Utils.PROTOCOL_VERSION}" in description)
    }

    @Test
    fun `an intent whose extras cannot be unparcelled describes as unreadable`() {
        val intent = UnreadableIntent()
        val description = Utils.describeIntent(intent)

        assertEquals(emptySet<String>(), flowsIn(description))
        DESCRIBED_EXTRA_KEYS.forEach { key ->
            // Unreadable, not absent: a bundle that throws is a different fact from an extra
            // nobody sent.
            assertExtra(description, key, "unreadable")
        }
        // Non-vacuity, and the counting has to be done carefully to be worth anything. A bare
        // `reads > 0` — or even `reads >= 10` — is satisfied by the six parsers' own reads, which
        // happen whatever the extras section does: between them they ask for the entry payload,
        // the public key, the request code, both field payloads and the signature a dozen times.
        // These three keys are the ones *no* parser reads on an intent whose first read throws,
        // so asking for them is proof that the extras section itself reached the intent.
        listOf(Utils.EXTRA_NONCE, Utils.EXTRA_NONCE_FORMAT, Utils.EXTRA_ALGORITHM).forEach { key ->
            assertTrue(
                "$key is read by no parser here, so the extras section must have asked for it " +
                    "itself — otherwise this test passes against a function that never touched " +
                    "the intent; read ${intent.readKeys}",
                key in intent.readKeys,
            )
        }
    }

    /**
     * The whole point of the function, stated as the property it must never break. A sentinel goes
     * into every place a profile value can hide — an entry payload's `id` and its nested
     * [TypedField]s, both field payloads — and none of it may reach the line.
     *
     * One of the sentinels is a field **name**, not a value, which is the site a redaction review
     * is most likely to miss: `Entry.toString()` prints the keys of its field map by design, and a
     * description that followed that precedent would leak here while still honouring the letter of
     * "a field value never appears". A key is as likely to be something the vault invented about
     * one user as it is to be `email`, so the count is all this line may say.
     */
    @Test
    fun `no sentinel field value or field name appears in a description`() {
        val sentinel = "SENTINEL-c4f9-DO-NOT-LOG"
        val loaded = Entry(
            id = "$sentinel-id",
            fields = linkedMapOf(
                "email" to TypedField("$sentinel@example.com", FieldType.EMAIL),
                "$sentinel-key" to TypedField(sentinel, FieldType.STRING),
            ),
            publicKey = PUBLIC_KEY,
        )
        val sentinelFields = Utils.encodeFields(
            linkedMapOf("$sentinel-dob" to TypedField(sentinel, FieldType.DATE)),
        )

        val description = Utils.describeIntent(
            Utils.createShareIntent(context, loaded).apply {
                putExtra(Utils.EXTRA_FIELDS_JSON, sentinelFields)
                putExtra(Utils.EXTRA_QUERY_RESULT_FIELDS, sentinelFields)
            },
        )

        assertFalse(
            "a profile value or field name reached a log line: $description",
            sentinel in description,
        )
        // Non-vacuity: the payloads were genuinely read, so the absence above is redaction
        // rather than a function that ignored them.
        assertExtra(description, Utils.EXTRA_ENTRY_JSON, "decoded, 2 fields")
        assertExtra(description, Utils.EXTRA_FIELDS_JSON, "1 field")
        assertExtra(description, Utils.EXTRA_QUERY_RESULT_FIELDS, "1 field")
    }

    /**
     * Redaction is opt-out, not opt-in: `describedValue`'s `else` branch reduces a value to its
     * length, and only the four protocol tokens the KDoc lists are printed close to verbatim.
     *
     * Without this, the arrangement is an allow-list of *redactions* with a verbatim default, and
     * the next extra added to the described list prints whatever it holds with no diff to notice.
     * That is not hypothetical: the per-field query request drafted under "Blocked on human"
     * carries the names of the fields a service asked about.
     */
    @Test
    fun `every described extra has a deliberate renderer rather than the generic fallback`() {
        val value = "0123456789"
        val fallback = "<${value.length} chars>"

        DESCRIBED_EXTRA_KEYS.forEach { key ->
            val description = Utils.describeIntent(resultIntent(key to value))
            assertNotEquals(
                "$key fell through to the generic length redaction, which means it has no " +
                    "deliberate arm in describedValue; got $description",
                fallback,
                renderedExtras(description).getValue(key),
            )
        }

        // Non-vacuity, and the reason this test can tell the two apart at all: the fallback string
        // is what `redactedValue` renders, so a key that *did* fall through would equal it.
        assertEquals(fallback, redactedValue(value))
    }

    /**
     * The public key is the one value printed rather than hidden — it is the opaque handle the
     * design hands out freely, and what makes a log line identifiable at all. It goes through
     * T19's published [previewedPublicKey] and not a second truncation rule, which is what the
     * boundary assertions below are measured against rather than against a hand-written 64.
     */
    @Test
    fun `a real public key appears only previewed`() {
        val description = Utils.describeIntent(
            resultIntent(Utils.EXTRA_PUBLIC_KEY to realKeyNoWrap),
        )

        // Precondition, so the assertions below are about truncation and not about a key that
        // happened to be short.
        assertTrue(
            "a 2048-bit X.509 key must be longer than the preview boundary",
            realKeyNoWrap.length > PUBLIC_KEY_PREVIEW_CHARS,
        )
        assertTrue(
            "the preview must be exactly what Redaction.kt renders; got $description",
            previewedPublicKey(realKeyNoWrap) in description,
        )
        assertFalse("the whole key must not appear", realKeyNoWrap in description)
        assertFalse(
            "nothing past the preview boundary may appear",
            realKeyNoWrap.substring(PUBLIC_KEY_PREVIEW_CHARS) in description,
        )
        assertTrue(
            "…and the part inside the boundary must, or this is not a preview at all",
            realKeyNoWrap.take(PUBLIC_KEY_PREVIEW_CHARS) in description,
        )
    }

    /**
     * A key encoded with [Base64.DEFAULT] — what the vault uses, and what wraps at 76 characters
     * — is still previewed rather than printed whole.
     *
     * Note what this does *not* pin, because it looks as though it should: the wrapping never
     * reaches the preview, since [PUBLIC_KEY_PREVIEW_CHARS] is 64 and the first newline lands at
     * 76. The one-line property is pinned by the test below, which puts a control character
     * somewhere it genuinely survives to the output.
     */
    @Test
    fun `a wrapped public key is previewed like any other`() {
        val wrapped = Base64.encodeToString(keyPair.public.encoded, Base64.DEFAULT)
        assertTrue("precondition: DEFAULT encoding should wrap", '\n' in wrapped)

        val description = Utils.describeIntent(resultIntent(Utils.EXTRA_PUBLIC_KEY to wrapped))
        assertFalse("the whole key must not appear", wrapped in description)
        assertTrue(previewedPublicKey(wrapped) in description)
    }

    /**
     * One call is one line, whatever the sender chose. A peer writes the extras, so a newline in
     * a request code would otherwise split a client's log entry in two — and the second half,
     * which is where the flow set lives, would read as an unrelated line.
     */
    @Test
    fun `a sender's control characters do not split the description`() {
        val description = Utils.describeIntent(
            resultIntent(
                Utils.EXTRA_SHARE_REQUEST_CODE to "req\n1",
                Utils.EXTRA_ALGORITHM to "SHA256\twithRSA",
                // The NUL spelled numerically, never as a literal: a control character typed
                // into a source file is one the next editor silently eats, which is the reason
                // `DecoderFuzzTest`'s corpus spells its own the same way.
                Utils.EXTRA_NONCE_FORMAT to "lim${NUL}ts1",
            ),
        )

        assertTrue(
            "a line-splitting character reached the output; got $description",
            description.none { it.splitsALine() },
        )
        // Non-vacuity: the values were rendered, so the absence above is escaping rather than a
        // function that dropped them.
        assertExtra(description, Utils.EXTRA_SHARE_REQUEST_CODE, "\"req.1\"")
        assertExtra(description, Utils.EXTRA_ALGORITHM, "\"SHA256.withRSA\"")
        assertExtra(description, Utils.EXTRA_NONCE_FORMAT, "\"lim.ts1\"")
    }

    /**
     * `\n` and `\r` are not the only characters that end a line. U+2028 LINE SEPARATOR and U+2029
     * PARAGRAPH SEPARATOR are line terminators by Unicode definition — `Scanner` and most log
     * viewers break on them — and `Char.isISOControl()`, the obvious predicate, covers neither. A
     * peer chooses the bytes in an extra, so a diagnostic that only handled the ASCII controls
     * could still be split in two by a request code.
     */
    @Test
    fun `the Unicode line separators do not split the description either`() {
        val description = Utils.describeIntent(
            resultIntent(
                Utils.EXTRA_SHARE_REQUEST_CODE to "req${LINE_SEPARATOR}1",
                Utils.EXTRA_ALGORITHM to "SHA256${PARAGRAPH_SEPARATOR}withRSA",
            ),
        )

        assertExtra(description, Utils.EXTRA_SHARE_REQUEST_CODE, "\"req.1\"")
        assertExtra(description, Utils.EXTRA_ALGORITHM, "\"SHA256.withRSA\"")
        // Asserted against the code points directly rather than against `isISOControl`, which
        // would agree with an implementation that had let both through.
        assertFalse("U+2028 reached the output; got $description", LINE_SEPARATOR in description)
        assertFalse("U+2029 reached the output; got $description", PARAGRAPH_SEPARATOR in description)
    }

    /**
     * A lone surrogate is not an encodable string, and a peer can put one in an extra.
     *
     * This is the same promise as the line-splitting one and fails the same way: a client logging
     * through a strict UTF-8 or JSON encoder can get an exception out of half a surrogate pair,
     * which is the second failure on top of the first that this function exists not to add. A
     * *well-formed* pair must survive, or the fix would be mangling legitimate astral characters —
     * an emoji in a request code is a peculiar choice but not a malformed one.
     */
    @Test
    fun `an unpaired surrogate is replaced but a well-formed pair survives`() {
        val lonely = "req${HIGH_SURROGATE}1"
        val emoji = "$HIGH_SURROGATE$LOW_SURROGATE"
        val description = Utils.describeIntent(
            resultIntent(
                Utils.EXTRA_SHARE_REQUEST_CODE to lonely,
                Utils.EXTRA_ALGORITHM to "SHA256${emoji}withRSA",
            ),
        )

        assertExtra(description, Utils.EXTRA_SHARE_REQUEST_CODE, "\"req.1\"")
        assertExtra(description, Utils.EXTRA_ALGORITHM, "\"SHA256${emoji}withRSA\"")
        // The property behind both: what comes out can be encoded. A lone surrogate does not
        // survive a UTF-8 round trip — the JDK substitutes `?` for it on the way out — so this
        // identity comparison is the honest form of "a strict encoder would not have objected",
        // and it holds only because the output no longer contains one.
        assertEquals(
            "the description must survive a UTF-8 round trip; got $description",
            description,
            String(description.toByteArray(Charsets.UTF_8), Charsets.UTF_8),
        )
    }

    /**
     * A diagnostic nobody can log is not a diagnostic: a peer that files sixteen kilobytes under
     * a text extra must not put sixteen kilobytes in a client's log line.
     *
     * The cap itself is private and deliberately not restated here — asserting the number would
     * freeze a value the KDoc says may be tuned. What is asserted is the property: the rendering
     * is a genuine prefix of what arrived, it is far shorter than the input, and it says how long
     * the real value was.
     */
    @Test
    fun `an oversized text extra is truncated rather than logged whole`() {
        val huge = "A".repeat(4_000)
        val description = Utils.describeIntent(resultIntent(Utils.EXTRA_ALGORITHM to huge))
        val rendered = renderedExtras(description).getValue(Utils.EXTRA_ALGORITHM)

        assertNotEquals("the whole value must not be printed", "\"$huge\"", rendered)
        assertTrue(
            "the real length must be reported, or a reader cannot tell truncation from a short " +
                "value; got $rendered",
            rendered.endsWith("…(${huge.length} chars)"),
        )
        val printed = rendered.removePrefix("\"").substringBefore("\"…(")
        assertTrue("what is printed must be a prefix of what arrived", huge.startsWith(printed))
        assertTrue("…and must be a short one; got ${printed.length}", printed.length < 200)
        assertTrue(
            "the whole line stays loggable; got ${description.length} characters",
            description.length < 1_000,
        )
    }

    /** The "not a constant" floor: a description that said the same thing every time would pass
     * every assertion above that uses `in`. */
    @Test
    fun `two different intents describe differently`() {
        val share = Utils.describeIntent(Utils.createShareIntent(context, entry))
        val query = Utils.describeIntent(Utils.createQueryIntent(context, PUBLIC_KEY, "req-7"))
        val empty = Utils.describeIntent(Intent())
        val none = Utils.describeIntent(null)

        assertNotEquals(share, query)
        assertNotEquals(share, empty)
        assertNotEquals(empty, none)
        assertTrue("a description must say something", share.length > 50)
    }

    /**
     * Advisory, the [Utils.validateEntry] precedent: describing an intent changes nothing about
     * what any parser accepts, so the same intent parses identically before and after.
     */
    @Test
    fun `describing an intent changes what no parser accepts`() {
        val intent = Utils.createShareIntent(context, entry, requestCode = "req-1")

        val before = Utils.parseShareRequest(intent)
        Utils.describeIntent(intent)
        val after = Utils.parseShareRequest(intent)

        assertEquals(before, after)
        assertEquals(entry, after?.entry)
        assertEquals("req-1", after?.requestCode)
    }

    private fun sign(data: ByteArray): ByteArray = Signature.getInstance("SHA256withRSA").run {
        initSign(keyPair.private)
        update(data)
        sign()
    }

    companion object {
        private const val PUBLIC_KEY = "PUBLIC-KEY-BASE64"

        /** A NUL, so no source file has to carry one. */
        private val NUL = 0x0000.toChar()

        /** U+2028 LINE SEPARATOR, spelled numerically for the same reason as [NUL]. */
        val LINE_SEPARATOR = 0x2028.toChar()

        /** U+2029 PARAGRAPH SEPARATOR, likewise. */
        val PARAGRAPH_SEPARATOR = 0x2029.toChar()

        /** The high half of a surrogate pair, alone an unencodable character. */
        private val HIGH_SURROGATE = 0xD83D.toChar()

        /** Its matching low half; together they are one astral character. */
        private val LOW_SURROGATE = 0xDE00.toChar()

        /**
         * Whether a character would end the line a description is written on — the production
         * predicate, restated because it is private.
         *
         * Spelled by code point rather than by literal, so this file carries no line terminator
         * of its own. `isISOControl` alone is not it: see the U+2028 test.
         */
        fun Char.splitsALine(): Boolean =
            isISOControl() || this == LINE_SEPARATOR || this == PARAGRAPH_SEPARATOR

        /** The section [Utils.describeIntent] documents as last. */
        private const val FLOWS_MARKER = "flows=["

        /** The extras section, which the flow section is documented to follow. */
        private const val EXTRAS_MARKER = "extras=["

        /** Where the extras section ends and the flow section begins. */
        private const val EXTRAS_END = "], $FLOWS_MARKER"

        /** Every flow name the function can produce, in its documented order. */
        val ALL_FLOWS = setOf(
            "shareRequest", "queryRequest", "signChallengeRequest",
            "shareResult", "queryResult", "signChallengeResult",
        )

        /**
         * Every extra [Utils.describeIntent] lists. Spelled through the published constants, so a
         * renamed literal breaks the wire tests rather than silently skipping a key here.
         */
        val DESCRIBED_EXTRA_KEYS = listOf(
            Utils.EXTRA_ENTRY_JSON,
            Utils.EXTRA_PUBLIC_KEY,
            Utils.EXTRA_NONCE,
            Utils.EXTRA_NONCE_FORMAT,
            Utils.EXTRA_SIGNATURE,
            Utils.EXTRA_ALGORITHM,
            Utils.EXTRA_FIELDS_JSON,
            Utils.EXTRA_QUERY_RESULT_FIELDS,
            Utils.EXTRA_SHARE_REQUEST_CODE,
            Utils.EXTRA_PROTOCOL_VERSION,
        )

        /**
         * The `flows=[…]` section, read back out of a description.
         *
         * The KDoc forbids parsing the wording, and this is the one reader that exists — inside
         * the repository that owns the format, which is the distinction that clause draws. Shared
         * with `DecoderFuzzTest` rather than copied into it, because two readers of one format is
         * one reader that drifts.
         *
         * `lastIndexOf`, not `indexOf`: every value on the line is chosen by the sender and may
         * contain these very characters, and the flows section is documented to come last.
         */
        fun flowsIn(description: String): Set<String> = flowOrderIn(description).toSet()

        /**
         * The same section, **keeping the order it was rendered in**.
         *
         * [flowsIn] returns a `Set`, which is what almost every assertion wants — but it is also
         * why the order went unpinned: `describeIntent`'s KDoc fixes the sequence as part of its
         * contract, and a set comparison cannot tell a reversed, alphabetical or random list from
         * the documented one. One test asserts this directly.
         */
        fun flowOrderIn(description: String): List<String> {
            val start = description.lastIndexOf(FLOWS_MARKER)
            check(start >= 0) { "no flows section in: $description" }
            val end = description.indexOf(']', start + FLOWS_MARKER.length)
            check(end >= 0) { "unterminated flows section in: $description" }
            val body = description.substring(start + FLOWS_MARKER.length, end)
            val flows = if (body.isEmpty()) emptyList() else body.split(", ")
            check(flows.all { it in ALL_FLOWS }) { "unknown flow name in: $description" }
            check(flows.distinct() == flows) { "a flow named twice in: $description" }
            return flows
        }

        /**
         * Every extra's rendering, read back out of the `extras=[…]` section.
         *
         * Walks [DESCRIBED_EXTRA_KEYS] in order and requires each label exactly where the next one
         * is due, so the reader doubles as a pin on two things no individual assertion states: that
         * the line lists every protocol extra, and that it lists them in the documented order.
         *
         * **The limit of that, stated rather than implied, since this is a reader of
         * attacker-chosen content.** Walking left to right means a value containing a
         * *non-adjacent* later key's label cannot move the split, because the cut for key *i* is
         * searched only from the end of key *i*'s own label. A value that spells the label of the
         * key **immediately after it** — `"; extra_signature=…"` inside `extra_nonce_format` —
         * genuinely does move the cut, and the `startsWith` check then passes because the sender
         * wrote the label. No test here feeds that, and production is unaffected either way: the
         * flow set is read by [flowOrderIn], which is safe because the section it reads is
         * documented and tested to be last. Do not build a hostile-input test on this helper
         * without closing that first.
         */
        fun renderedExtras(description: String): Map<String, String> {
            val start = description.indexOf(EXTRAS_MARKER)
            check(start >= 0) { "no extras section in: $description" }
            val end = description.lastIndexOf(EXTRAS_END)
            check(end > start) { "extras section does not run into the flows section: $description" }
            val body = description.substring(start + EXTRAS_MARKER.length, end)

            val rendered = LinkedHashMap<String, String>()
            var cursor = 0
            DESCRIBED_EXTRA_KEYS.forEachIndexed { index, key ->
                val label = "$key="
                check(body.startsWith(label, cursor)) {
                    "expected $label at offset $cursor of the extras section: $body"
                }
                cursor += label.length
                val nextLabel = DESCRIBED_EXTRA_KEYS.getOrNull(index + 1)?.let { "; $it=" }
                val cut = if (nextLabel == null) body.length else body.indexOf(nextLabel, cursor)
                check(cut >= cursor) { "could not find $nextLabel after $key in: $body" }
                rendered[key] = body.substring(cursor, cut)
                cursor = if (nextLabel == null) cut else cut + 2
            }
            return rendered
        }

        /**
         * The six parsers, as the set of flow names that accept [intent] — the independent
         * computation `DecoderFuzzTest` holds [Utils.describeIntent] against, so that its flow
         * set provably comes from calling the parsers rather than from a second copy of the
         * routing rule.
         */
        fun parserFlows(intent: Intent?): Set<String> = buildSet {
            if (Utils.parseShareRequest(intent) != null) add("shareRequest")
            if (Utils.parseQueryRequest(intent) != null) add("queryRequest")
            if (Utils.parseSignChallengeRequest(intent) != null) add("signChallengeRequest")
            if (Utils.parseShareResult(intent) != null) add("shareResult")
            if (Utils.parseQueryResult(intent) != null) add("queryResult")
            if (Utils.parseSignChallengeResult(intent) != null) add("signChallengeResult")
        }

        private lateinit var keyPair: KeyPair

        /**
         * Unwrapped on purpose: the preview assertions are about the truncation boundary, and a
         * `Base64.DEFAULT` key carries newlines the description replaces, which would make the
         * comparison about escaping instead. The wrapped case has its own test.
         */
        private lateinit var realKeyNoWrap: String

        /** 2048-bit RSA generation is slow (~100ms); do it once for the whole class. */
        @JvmStatic
        @BeforeClass
        fun generateKeys() {
            keyPair = KeyPairGenerator.getInstance("RSA")
                .apply { initialize(2048) }
                .generateKeyPair()
            realKeyNoWrap = Base64.encodeToString(keyPair.public.encoded, Base64.NO_WRAP)
        }
    }
}
