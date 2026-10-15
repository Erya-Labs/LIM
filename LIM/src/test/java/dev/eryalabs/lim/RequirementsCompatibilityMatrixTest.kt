package dev.eryalabs.lim

import android.app.Activity
import android.content.Context
import android.content.Intent
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Required and optional fields across every pairing of client and vault that can meet on a device.
 *
 * Three fixture vaults, each built only from what that generation of vault had:
 *
 *  - **V0** — a vault on the 1.0.0 API: no field is required, blank fields are dropped, at least
 *    one value is needed, and the answer comes from the three-argument builder.
 *  - **V1** — the interim vault: every declared field required, the declaration never read, and
 *    the three-argument builder, so no acknowledgement.
 *  - **V2** — a vault implementing required fields: [Utils.parseFieldRequirements], Save gated on
 *    [FieldRequirements.missingRequired], [FieldRequirements.committed] stored, and the
 *    requirements-aware builder.
 *
 * Two clients: **C0**, which sends no declaration — an app built against 1.0.0, or one still on
 * its overloads — and **C1**, which names `phone` optional and reads the verdict. One row adds a
 * C1 that names nothing optional, the one-argument [FieldRequirements] constructor's default.
 *
 * Every cell asserts the four things the design names: the set the vault blocked Save on, the
 * fields that came back, the extras on the answer, and — for C1 — the verdict. A refusal is
 * `RESULT_CANCELED` carrying the request code and the version and nothing else, in every cell.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class RequirementsCompatibilityMatrixTest {

    private val context = ApplicationProvider.getApplicationContext<Context>()

    private val entry = Entry(
        id = "signup-form",
        fields = linkedMapOf(
            "name" to TypedField("", FieldType.STRING),
            "email" to TypedField("", FieldType.EMAIL),
            "phone" to TypedField("", FieldType.PHONE),
        ),
        publicKey = "no-key-yet",
    )

    private val c1Requirements = FieldRequirements(entry.fields.keys, setOf("phone"))

    private fun c0Request(): Intent = Utils.createShareIntent(context, entry, requestCode = CODE)

    private fun c1Request(): Intent =
        Utils.createShareIntent(context, entry, CODE, c1Requirements.optionalFields, VAULT)

    // ── The user ─────────────────────────────────────────────────────────

    /**
     * What a person does at a vault's sign-up form: types [volunteered] unprompted, and types
     * [ifRequired] only when Save is blocked on that field. A blocked field they have nothing for
     * makes them back out.
     */
    private class User(val volunteered: Map<String, String>, val ifRequired: Map<String, String>)

    /** Fills in name and email, skips phone unless made to fill it in. */
    private val diligent = User(
        volunteered = mapOf("name" to NAME, "email" to EMAIL),
        ifRequired = mapOf("phone" to PHONE),
    )

    /** Fills in only the name unless made to do more. */
    private val lazy = User(
        volunteered = mapOf("name" to NAME),
        ifRequired = mapOf("email" to EMAIL, "phone" to PHONE),
    )

    // ── The vaults ───────────────────────────────────────────────────────

    /** What came back, and what the vault would not let the user save without. */
    private class Answer(val resultCode: Int, val data: Intent, val enforced: Set<String>)

    private abstract class Vault {
        abstract fun answer(request: Intent, user: User): Answer

        /** The user's draft against a form that blocks Save on [enforced]. */
        protected fun draft(share: ShareRequest, enforced: Set<String>, user: User): Map<String, TypedField> =
            share.entry.fields.mapValues { (name, declared) ->
                val typed = user.volunteered[name] ?: if (name in enforced) user.ifRequired[name] else null
                TypedField(typed ?: "", declared.type)
            }

        /** Back or Up: the request code and the version, and nothing else. */
        protected fun refusal(share: ShareRequest?, enforced: Set<String>) = Answer(
            Activity.RESULT_CANCELED,
            Intent().apply {
                share?.requestCode?.let { putExtra(Utils.EXTRA_SHARE_REQUEST_CODE, it) }
                putExtra(Utils.EXTRA_PROTOCOL_VERSION, Utils.PROTOCOL_VERSION.toString())
            },
            enforced,
        )
    }

    /** V0: a vault on the 1.0.0 API. */
    private class V0 : Vault() {
        override fun answer(request: Intent, user: User): Answer {
            val share = Utils.parseShareRequest(request) ?: return refusal(null, emptySet())
            val stored = draft(share, emptySet(), user).filterValues { it.value.isNotBlank() }
            // "No fields to save": at least one value is needed, so a user with none backs out.
            if (stored.isEmpty()) return refusal(share, emptySet())
            return Answer(
                Activity.RESULT_OK,
                Utils.createShareResultIntent(KEY, stored, share.requestCode),
                emptySet(),
            )
        }
    }

    /** V1: the interim vault — everything required, the declaration never read. */
    private class V1 : Vault() {
        override fun answer(request: Intent, user: User): Answer {
            val share = Utils.parseShareRequest(request) ?: return refusal(null, emptySet())
            val enforced = share.entry.fields.keys.toSet()
            val draft = draft(share, enforced, user)
            if (draft.values.any { it.value.isBlank() }) return refusal(share, enforced)
            return Answer(
                Activity.RESULT_OK,
                Utils.createShareResultIntent(KEY, draft, share.requestCode),
                enforced,
            )
        }
    }

    /** V2: a vault implementing required fields with this library's functions. */
    private class V2 : Vault() {
        override fun answer(request: Intent, user: User): Answer {
            val share = Utils.parseShareRequest(request) ?: return refusal(null, emptySet())
            val requirements = Utils.parseFieldRequirements(request) ?: return refusal(share, emptySet())
            val enforced = requirements.requiredFields
            val draft = draft(share, enforced, user)
            if (requirements.missingRequired(draft).isNotEmpty()) return refusal(share, enforced)
            val stored = requirements.committed(draft)!!
            return Answer(
                Activity.RESULT_OK,
                Utils.createShareResultIntent(KEY, stored, share.requestCode, requirements),
                enforced,
            )
        }
    }

    // ── What each cell asserts ────────────────────────────────────────────

    private fun assertCell(
        cell: String,
        answer: Answer,
        enforced: Set<String>,
        fields: Map<String, String>,
        extras: Set<String>,
    ) {
        assertEquals("$cell: the answer is a sign-up", Activity.RESULT_OK, answer.resultCode)
        assertEquals("$cell: what the vault blocked Save on", enforced, answer.enforced)
        val result = Utils.parseShareResult(answer.data)
        assertNotNull("$cell: the answer parses", result)
        assertEquals("$cell: the fields that came back", fields, result!!.fields.mapValues { it.value.value })
        assertEquals("$cell: the extras on the answer", extras, answer.data.extras!!.keySet())
        assertEquals("$cell: the key to keep", KEY, result.publicKey)
        assertEquals("$cell: correlation", true, Utils.matchesRequestCode(answer.data, CODE))
    }

    private fun c1Verdict(answer: Answer) = Utils.checkFieldRequirements(c1Requirements, answer.data)

    // ── Row C0: a client that declares nothing ────────────────────────────

    @Test
    fun `C0 x V0 - unchanged, every field skippable`() {
        val answer = V0().answer(c0Request(), diligent)
        assertCell("C0xV0", answer, emptySet(), mapOf("name" to NAME, "email" to EMAIL), WITHOUT_ACK)
    }

    @Test
    fun `C0 x V1 - every field required, no acknowledgement`() {
        val answer = V1().answer(c0Request(), diligent)
        assertCell("C0xV1", answer, ALL, mapOf("name" to NAME, "email" to EMAIL, "phone" to PHONE), WITHOUT_ACK)
    }

    /**
     * The deliberate behaviour change for apps that never opted in: everything is required. The
     * acknowledgement rides along as `[]`, and a 1.0.0 client's parse of the answer is exactly the
     * parse of the same answer without it.
     */
    @Test
    fun `C0 x V2 - every field required, an empty acknowledgement the old client never reads`() {
        val answer = V2().answer(c0Request(), diligent)
        assertCell("C0xV2", answer, ALL, mapOf("name" to NAME, "email" to EMAIL, "phone" to PHONE), WITH_ACK)
        assertEquals("[]", answer.data.getStringExtra("extra_applied_optional_fields"))
        val withoutAck = Intent(answer.data).apply { removeExtra(Utils.EXTRA_APPLIED_OPTIONAL_FIELDS) }
        assertEquals(Utils.parseShareResult(withoutAck), Utils.parseShareResult(answer.data))
    }

    // ── Row C1: a client that names phone optional ────────────────────────

    @Test
    fun `C1 x V0 - the declaration is ignored, and only the data says what happened`() {
        val diligentAnswer = V0().answer(c1Request(), diligent)
        assertCell("C1xV0", diligentAnswer, emptySet(), mapOf("name" to NAME, "email" to EMAIL), WITHOUT_ACK)
        assertEquals(FieldRequirementsVerdict.NOT_ACKNOWLEDGED, c1Verdict(diligentAnswer))

        val lazyAnswer = V0().answer(c1Request(), lazy)
        assertCell("C1xV0 lazy", lazyAnswer, emptySet(), mapOf("name" to NAME), WITHOUT_ACK)
        assertEquals(FieldRequirementsVerdict.INCOMPLETE, c1Verdict(lazyAnswer))
        assertEquals(
            listOf("email"),
            c1Requirements.missingRequired(Utils.parseShareResult(lazyAnswer.data)!!.fields),
        )
        assertEquals(
            "the version echo is identical to an implementing vault's, which is why it is not the signal",
            Utils.parseShareResult(V2().answer(c1Request(), diligent).data)!!.vaultProtocolVersion,
            Utils.parseShareResult(lazyAnswer.data)!!.vaultProtocolVersion,
        )
    }

    /** The interim vault over-collects from a new client, and the only sign is no acknowledgement. */
    @Test
    fun `C1 x V1 - optional fields forced, detectable only as NOT_ACKNOWLEDGED`() {
        val answer = V1().answer(c1Request(), diligent)
        assertCell("C1xV1", answer, ALL, mapOf("name" to NAME, "email" to EMAIL, "phone" to PHONE), WITHOUT_ACK)
        assertEquals(FieldRequirementsVerdict.NOT_ACKNOWLEDGED, c1Verdict(answer))
    }

    @Test
    fun `C1 x V2 - honoured, and the blank optional field is absent`() {
        val answer = V2().answer(c1Request(), diligent)
        assertCell("C1xV2", answer, setOf("name", "email"), mapOf("name" to NAME, "email" to EMAIL), WITH_ACK)
        assertEquals("""["phone"]""", answer.data.getStringExtra("extra_applied_optional_fields"))
        assertEquals(FieldRequirementsVerdict.HONOURED, c1Verdict(answer))

        val lazyAnswer = V2().answer(c1Request(), lazy)
        assertCell("C1xV2 lazy", lazyAnswer, setOf("name", "email"), mapOf("name" to NAME, "email" to EMAIL), WITH_ACK)
        assertEquals(
            "a lazy user is made to fill in email and may still skip phone",
            FieldRequirementsVerdict.HONOURED,
            c1Verdict(lazyAnswer),
        )
    }

    /** The client's own broken declaration: the vault applies nothing and says so. */
    @Test
    fun `C1 x V2 with a malformed declaration - everything asked for, MISMATCHED`() {
        val broken = c1Request().apply { putExtra(Utils.EXTRA_OPTIONAL_FIELDS, """["phone"""") }
        val answer = V2().answer(broken, diligent)

        assertCell("C1xV2 malformed", answer, ALL, mapOf("name" to NAME, "email" to EMAIL, "phone" to PHONE), WITH_ACK)
        assertEquals("[]", answer.data.getStringExtra("extra_applied_optional_fields"))
        assertEquals(FieldRequirementsVerdict.MISMATCHED, c1Verdict(answer))
    }

    /**
     * A client that reads the verdict but names nothing optional — `FieldRequirements(names)`, the
     * one-argument constructor's default. The implementing vault acknowledges `[]`, which is
     * exactly that declaration, so the verdict is `HONOURED`: the only answer that says a vault
     * enforced every field. The interim vault returns the same data with no acknowledgement, which
     * can only read `NOT_ACKNOWLEDGED`, because the user may simply have filled everything in; the
     * 1.0.0-API vault lets phone be skipped, `INCOMPLETE`. A client still on the 1.0.0 overloads
     * that reads the verdict anyway gets the same answers, since no declaration and an empty one
     * read alike — and an acknowledgement naming anything at all is `MISMATCHED`.
     */
    @Test
    fun `C1 naming nothing optional x every vault - HONOURED only from the vault that enforced it`() {
        val allRequired = FieldRequirements(entry.fields.keys)
        val request = Utils.createShareIntent(context, entry, CODE, allRequired.optionalFields, VAULT)
        assertEquals("[]", request.getStringExtra("extra_optional_fields"))
        val everything = mapOf("name" to NAME, "email" to EMAIL, "phone" to PHONE)
        fun verdictOf(answer: Answer) = Utils.checkFieldRequirements(allRequired, answer.data)

        val v2 = V2().answer(request, diligent)
        assertCell("C1(nothing optional)xV2", v2, ALL, everything, WITH_ACK)
        assertEquals("[]", v2.data.getStringExtra("extra_applied_optional_fields"))
        assertEquals(FieldRequirementsVerdict.HONOURED, verdictOf(v2))

        val v1 = V1().answer(request, diligent)
        assertCell("C1(nothing optional)xV1", v1, ALL, everything, WITHOUT_ACK)
        assertEquals(FieldRequirementsVerdict.NOT_ACKNOWLEDGED, verdictOf(v1))

        val v0 = V0().answer(request, diligent)
        assertCell("C1(nothing optional)xV0", v0, emptySet(), mapOf("name" to NAME, "email" to EMAIL), WITHOUT_ACK)
        assertEquals(FieldRequirementsVerdict.INCOMPLETE, verdictOf(v0))

        for ((vault, expected) in listOf(
            V2() to FieldRequirementsVerdict.HONOURED,
            V1() to FieldRequirementsVerdict.NOT_ACKNOWLEDGED,
            V0() to FieldRequirementsVerdict.INCOMPLETE,
        )) {
            assertEquals(
                "a C0 request read with the same requirements, from ${vault.javaClass.simpleName}",
                expected,
                verdictOf(vault.answer(c0Request(), diligent)),
            )
        }

        val claimsPhone = Intent(v2.data).putExtra(Utils.EXTRA_APPLIED_OPTIONAL_FIELDS, """["phone"]""")
        assertEquals(
            "a vault claiming to have made phone optional, to a client that made nothing optional",
            FieldRequirementsVerdict.MISMATCHED,
            Utils.checkFieldRequirements(allRequired, claimsPhone),
        )
    }

    /** Names that are not fields are dropped by both sides, so there is nothing to disagree about. */
    @Test
    fun `C1 x V2 with an optional name the entry does not declare - still HONOURED`() {
        val request = Utils.createShareIntent(context, entry, CODE, setOf("phone", "stray"), VAULT)
        val requirements = FieldRequirements(entry.fields.keys, setOf("phone", "stray"))
        val answer = V2().answer(request, diligent)

        assertEquals(FieldRequirementsVerdict.HONOURED, Utils.checkFieldRequirements(requirements, answer.data))
        assertEquals(c1Requirements, requirements)
    }

    /**
     * A client may declare its fields in the order its own form wants rather than its entry's, and
     * nothing between the two sides depends on order: the declaration goes out in entry order, the
     * vault acknowledges in entry order, and the verdict compares sets.
     */
    @Test
    fun `C1 x V2 with the client's field order differing from the entry's - still HONOURED`() {
        val reordered = FieldRequirements(listOf("phone", "email", "name"), setOf("phone", "email"))
        val request = Utils.createShareIntent(context, entry, CODE, reordered.optionalFields, VAULT)
        assertEquals("""["email","phone"]""", request.getStringExtra("extra_optional_fields"))
        assertEquals(listOf("phone", "email"), reordered.optionalFields.toList())

        val answer = V2().answer(request, diligent)

        assertEquals("""["email","phone"]""", answer.data.getStringExtra("extra_applied_optional_fields"))
        assertEquals(FieldRequirementsVerdict.HONOURED, Utils.checkFieldRequirements(reordered, answer.data))
    }

    /**
     * A field whose [TypedField] is `null` in the client's own [Entry] — Java, or a template Gson
     * built — is never encoded, so the vault never sees it. The documented recipe builds the
     * requirements from the keys whose value is not `null`, and an honest vault's answer is
     * `HONOURED`. Built from every key instead, the client would require a field it never sent,
     * and the same honest answer would read as `VIOLATED` — the consequence the docs warn of.
     */
    @Suppress("UNCHECKED_CAST", "USELESS_CAST", "SENSELESS_COMPARISON")
    @Test
    fun `a client field whose value is null is never sent, and requirements built without it are HONOURED`() {
        val withNull = Entry(
            id = "signup-form",
            fields = linkedMapOf<String, TypedField?>(
                "name" to TypedField("", FieldType.STRING),
                "email" to TypedField("", FieldType.EMAIL),
                "nick" to null,
                "phone" to TypedField("", FieldType.PHONE),
            ) as Map<String, TypedField>,
            publicKey = "no-key-yet",
        )
        val sent = withNull.fields.filterValues { (it as TypedField?) != null }.keys
        val requirements = FieldRequirements(sent, setOf("phone"))
        val request = Utils.createShareIntent(context, withNull, CODE, requirements.optionalFields, VAULT)

        assertEquals(listOf("name", "email", "phone"), Utils.parseFieldRequirements(request)!!.fieldNames)
        val answer = V2().answer(request, diligent)
        assertCell("null-valued field", answer, setOf("name", "email"), mapOf("name" to NAME, "email" to EMAIL), WITH_ACK)
        assertEquals(FieldRequirementsVerdict.HONOURED, Utils.checkFieldRequirements(requirements, answer.data))

        assertEquals(
            "requiring the field that was never sent blames an honest vault",
            FieldRequirementsVerdict.VIOLATED,
            Utils.checkFieldRequirements(FieldRequirements(withNull.fields.keys, setOf("phone")), answer.data),
        )
    }

    /**
     * The owner's answer for an all-optional sign-up left wholly blank: a profile that is a key and
     * nothing else. The vault commits an empty map, the builder writes `"{}"` and acknowledges every
     * name, the client parses an empty field map, and the verdict is `HONOURED`.
     */
    @Test
    fun `a sign-up with every field optional and every field left blank is a key-only profile, end to end`() {
        val everyOptional = FieldRequirements(entry.fields.keys, entry.fields.keys)
        val request = Utils.createShareIntent(context, entry, CODE, everyOptional.optionalFields, VAULT)
        val nobody = User(volunteered = emptyMap(), ifRequired = emptyMap())

        val answer = V2().answer(request, nobody)

        assertCell("key-only", answer, emptySet(), emptyMap(), WITH_ACK)
        assertEquals("{}", answer.data.getStringExtra("extra_fields_json"))
        assertEquals(
            """["name","email","phone"]""",
            answer.data.getStringExtra("extra_applied_optional_fields"),
        )
        assertEquals(emptyMap<String, TypedField>(), Utils.parseShareResult(answer.data)!!.fields)
        assertEquals(emptyMap<String, TypedField>(), everyOptional.committed(Utils.parseShareResult(answer.data)!!.fields))
        assertEquals(FieldRequirementsVerdict.HONOURED, Utils.checkFieldRequirements(everyOptional, answer.data))

        // The older vaults cannot produce it: V0 needs one value and V1 needs every one.
        assertEquals(Activity.RESULT_CANCELED, V0().answer(request, nobody).resultCode)
        assertEquals(Activity.RESULT_CANCELED, V1().answer(request, nobody).resultCode)
    }

    /** Back or Up on a blocked field: the same refusal shape from every vault, and no acknowledgement. */
    @Test
    fun `a user who will not fill a required field backs out, in the same shape everywhere`() {
        val unwilling = User(volunteered = mapOf("name" to NAME), ifRequired = emptyMap())

        listOf(V1(), V2()).forEach { vault ->
            val answer = vault.answer(c1Request(), unwilling)
            assertEquals(Activity.RESULT_CANCELED, answer.resultCode)
            assertEquals(REFUSAL, answer.data.extras!!.keySet())
            assertEquals(FieldRequirementsVerdict.INCOMPLETE, c1Verdict(answer))
        }
    }

    /**
     * **The declaration has to reach the answer, and a client that loses it blames an honest
     * vault.** The third cause of `VIOLATED` is the client's own: a declaration that is not the one
     * that was sent. One V2 answer here — the page's optional-`phone` sign-up, fields
     * `{name, email}` with the acknowledgement `["phone"]`, which an honest vault really sends —
     * read against three declarations, and then a fourth.
     *
     *  - **The one that was sent** — `HONOURED`.
     *  - **The same names with the optional set lost**, which is what an activity recreated after
     *    process death holds if it saved only the field names: `phone` is required again, so the
     *    honest answer reads as `VIOLATED` and the guide's printed handler takes its `else` arm and
     *    reports the vault. Nothing about the answer changed.
     *  - **Rebuilt from the entry the request was built from** — the same construction, asserted
     *    equal to the one that was sent by [FieldRequirements]'s own equality rather than assumed
     *    equal, and `HONOURED` again.
     *
     * [FieldRequirements.committed] is asserted beside each verdict, which applies the partition
     * `FieldRequirementsVerdictTest` pins (`:276-300`) to a *drift* in the declaration rather than
     * to a payload, and is what makes the blame measurable: the client's own gate and the verdict
     * it would blame the vault on agree, and both are wrong about the vault. Those three
     * assertions detect nothing on their own — deleting them leaves the test green — and are here
     * for what they say.
     *
     * A fourth reading is the drift that fails the *other* way, which the guide now warns of: a
     * declaration restored with no field names at all requires nothing, so there is no verdict to
     * catch it and `committed` hands back an empty profile rather than `null`.
     */
    @Test
    fun `a declaration that is not the one that was sent blames an honest vault`() {
        val answer = V2().answer(c1Request(), diligent)
        assertCell("drift", answer, setOf("name", "email"), mapOf("name" to NAME, "email" to EMAIL), WITH_ACK)
        assertEquals("""["phone"]""", answer.data.getStringExtra("extra_applied_optional_fields"))
        val fields = Utils.parseShareResult(answer.data)!!.fields

        // The declaration that was sent. Without this the VIOLATED below could be a property of
        // the answer rather than of the declaration read against it.
        assertEquals(FieldRequirementsVerdict.HONOURED, Utils.checkFieldRequirements(c1Requirements, answer.data))
        assertNotNull(c1Requirements.committed(fields))

        // The optional set lost: every field required again, and the answer is suddenly a defect.
        val drifted = FieldRequirements(entry.fields.keys)
        assertEquals(FieldRequirementsVerdict.VIOLATED, Utils.checkFieldRequirements(drifted, answer.data))
        assertNull("the client's own gate agrees with the verdict, and both blame the vault", drifted.committed(fields))
        assertEquals(listOf("phone"), drifted.missingRequired(fields))

        // Rebuilt from the same source the request was built from.
        val rebuilt = FieldRequirements(entry.fields.keys, setOf("phone"))
        assertEquals(c1Requirements, rebuilt)
        assertEquals(FieldRequirementsVerdict.HONOURED, Utils.checkFieldRequirements(rebuilt, answer.data))
        assertNotNull(rebuilt.committed(fields))

        // The verdict turns on an acknowledgement being present, so this measures drift against an
        // acknowledging vault and not merely a short payload: the same drifted declaration over the
        // 1.0.0-API vault's answer, which acknowledges nothing, is INCOMPLETE rather than VIOLATED.
        val withoutAck = V0().answer(c1Request(), diligent)
        assertEquals(FieldRequirementsVerdict.INCOMPLETE, Utils.checkFieldRequirements(drifted, withoutAck.data))

        // Drift the other way and nothing refuses it: a declaration restored with no names
        // requires nothing, so the verdict is MISMATCHED — which the guide's handler routes to
        // createAccount — and `committed` is an empty profile rather than null.
        val nameless = FieldRequirements(emptyList())
        assertEquals(FieldRequirementsVerdict.MISMATCHED, Utils.checkFieldRequirements(nameless, answer.data))
        assertEquals(emptyMap<String, TypedField>(), nameless.committed(fields))
    }

    /** Cell 8: a vault that writes the acknowledgement by hand over data that does not support it. */
    @Test
    fun `a vault writing the acknowledgement by hand over incomplete data is VIOLATED`() {
        val answer = V0().answer(c1Request(), lazy)
        answer.data.putExtra(Utils.EXTRA_APPLIED_OPTIONAL_FIELDS, """["phone"]""")

        assertEquals(FieldRequirementsVerdict.VIOLATED, c1Verdict(answer))
    }

    private companion object {
        private const val CODE = "signup-1"
        private const val VAULT = Utils.DEFAULT_ENDEAVOR_PACKAGE
        private const val KEY = "a-fake-public-key-from-a-test"
        private const val NAME = "Ada"
        private const val EMAIL = "ada@example.com"
        private const val PHONE = "555-0100"

        private val ALL = setOf("name", "email", "phone")

        private val WITHOUT_ACK = setOf(
            "extra_public_key",
            "extra_fields_json",
            "extra_share_request_code",
            "extra_protocol_version",
        )

        /** A new success result carries exactly one extra more than a 1.0.0 one. */
        private val WITH_ACK = WITHOUT_ACK + "extra_applied_optional_fields"

        private val REFUSAL = setOf("extra_share_request_code", "extra_protocol_version")
    }
}
