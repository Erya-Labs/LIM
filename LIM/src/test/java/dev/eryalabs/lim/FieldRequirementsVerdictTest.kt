package dev.eryalabs.lim

import android.content.Intent
import android.os.BadParcelableException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * [Utils.checkFieldRequirements], one answer per verdict and then the property the design turns
 * on: **the verdict splits exactly on whether the data is complete.** `committed` of the result's
 * own fields is non-`null` for `HONOURED`, `MISMATCHED` and `NOT_ACKNOWLEDGED` and for nothing else,
 * so a client gating its account on the data and one switching on the verdict cannot disagree
 * about whether a required field arrived.
 *
 * Each verdict is produced by the answer it describes, built the way that answer is really built:
 * the requirements-aware builder for an acknowledging vault, the 1.0.0 builder for an older one,
 * and a hand-written extra for the vault that lies. Robolectric is required for [Intent].
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class FieldRequirementsVerdictTest {

    /** `name`, `email` required; `phone` optional. */
    private val requirements = FieldRequirements(listOf("name", "email", "phone"), setOf("phone"))

    private val complete = linkedMapOf(
        "name" to TypedField("Ada", FieldType.STRING),
        "email" to TypedField("ada@example.com", FieldType.EMAIL),
    )

    private val incomplete = linkedMapOf("name" to TypedField("Ada", FieldType.STRING))

    private fun acknowledging(fields: Map<String, TypedField>, applied: FieldRequirements = requirements) =
        Utils.createShareResultIntent(KEY, fields, CODE, applied)

    private fun older(fields: Map<String, TypedField>) = Utils.createShareResultIntent(KEY, fields, CODE)

    private fun verdict(result: Intent?) = Utils.checkFieldRequirements(requirements, result)

    @Test
    fun `an acknowledgement of exactly the declared set over complete data is HONOURED`() {
        assertEquals(FieldRequirementsVerdict.HONOURED, verdict(acknowledging(complete)))
        assertEquals(
            "a filled optional field changes nothing",
            FieldRequirementsVerdict.HONOURED,
            verdict(acknowledging(complete + ("phone" to TypedField("555-0100", FieldType.PHONE)))),
        )
        assertEquals(
            "the comparison is of sets, so a name the acknowledgement repeats counts once",
            FieldRequirementsVerdict.HONOURED,
            verdict(older(complete).putExtra(Utils.EXTRA_APPLIED_OPTIONAL_FIELDS, """["phone","phone"]""")),
        )

        // …and the order does not matter either: two optional names, acknowledged the other way
        // round from the order the requirements hold them in.
        val twoOptional = FieldRequirements(listOf("name", "email", "phone", "nickname"), setOf("phone", "nickname"))
        assertEquals(listOf("phone", "nickname"), twoOptional.optionalFields.toList())
        assertEquals(
            "the comparison is of sets, so the acknowledgement's order does not matter",
            FieldRequirementsVerdict.HONOURED,
            Utils.checkFieldRequirements(
                twoOptional,
                older(complete).putExtra(Utils.EXTRA_APPLIED_OPTIONAL_FIELDS, """["nickname","phone"]"""),
            ),
        )
    }

    /**
     * The one claim the verdict cannot check, and the reason `committed` is the profile to keep: an
     * acknowledgement written by hand beside a blank optional value, or a blank key nobody
     * declared, over data whose required fields are all there. `HONOURED` reads the required
     * fields and the acknowledged set, as documented, and nothing else; this library's own builder
     * would have written no acknowledgement over that payload, and `committed` drops both blanks.
     */
    @Test
    fun `a hand-written acknowledgement beside a blank optional value is HONOURED, and committed drops it`() {
        val withBlanks = complete + ("phone" to TypedField("  ", FieldType.PHONE)) + ("stray" to TypedField(""))
        val handWritten = older(withBlanks).putExtra(Utils.EXTRA_APPLIED_OPTIONAL_FIELDS, """["phone"]""")

        assertEquals(FieldRequirementsVerdict.HONOURED, verdict(handWritten))
        val fields = Utils.parseShareResult(handWritten)!!.fields
        assertEquals("the blank optional value arrives as it was sent", "  ", fields["phone"]?.value)
        assertEquals("", fields["stray"]?.value)
        assertEquals(
            "committed keeps the declared, non-blank fields and nothing else",
            listOf("name", "email"),
            requirements.committed(fields)?.keys?.toList(),
        )
        assertFalse(
            "this library's builder writes no acknowledgement over the same payload",
            acknowledging(withBlanks).hasExtra(Utils.EXTRA_APPLIED_OPTIONAL_FIELDS),
        )
    }

    @Test
    fun `an acknowledgement of another set over complete data is MISMATCHED`() {
        // The usual cause: the vault could not read the declaration, so it applied nothing and
        // asked for everything — which it then acknowledges as the empty set. That `[]` is a
        // mismatch only because this client named phone optional; to a client that named nothing
        // optional, the same `[]` is exactly what it declared, and HONOURED (the next test).
        val appliedNothing = acknowledging(
            complete + ("phone" to TypedField("555-0100", FieldType.PHONE)),
            FieldRequirements(requirements.fieldNames),
        )
        assertEquals("[]", appliedNothing.getStringExtra("extra_applied_optional_fields"))
        assertEquals(FieldRequirementsVerdict.MISMATCHED, verdict(appliedNothing))
        assertEquals(
            "a partial application is a mismatch too",
            FieldRequirementsVerdict.MISMATCHED,
            verdict(older(complete).putExtra(Utils.EXTRA_APPLIED_OPTIONAL_FIELDS, """["phone","name"]""")),
        )
        assertEquals(
            "…and so is a claim to have made optional a field the sign-up never declared: the " +
                "acknowledged set is compared whole, and an undeclared name is not dropped from it",
            FieldRequirementsVerdict.MISMATCHED,
            verdict(older(complete).putExtra(Utils.EXTRA_APPLIED_OPTIONAL_FIELDS, """["phone","stray"]""")),
        )
    }

    /**
     * A declaration with nothing optional — what the one-argument [FieldRequirements] constructor
     * builds, and so what every client gets that names no optional field. An implementing vault
     * acknowledges it as `[]`, and set equality makes that `HONOURED`: the one answer that says a
     * vault enforced every field, where the same data with no acknowledgement can only be
     * `NOT_ACKNOWLEDGED`, because the user may simply have filled everything in. Any non-empty
     * acknowledgement to the same client is `MISMATCHED`, whatever it names.
     */
    @Test
    fun `with nothing optional, the empty acknowledgement is HONOURED and any other is MISMATCHED`() {
        val allRequired = FieldRequirements(listOf("name", "email", "phone"))
        assertTrue(allRequired.optionalFields.isEmpty())
        val completeAll = complete + ("phone" to TypedField("555-0100", FieldType.PHONE))
        fun verdictOf(result: Intent) = Utils.checkFieldRequirements(allRequired, result)

        val answer = acknowledging(completeAll, allRequired)
        assertEquals("[]", answer.getStringExtra(Utils.EXTRA_APPLIED_OPTIONAL_FIELDS))
        assertEquals(FieldRequirementsVerdict.HONOURED, verdictOf(answer))
        assertEquals(
            "the empty set is an acknowledgement however it is spelt",
            FieldRequirementsVerdict.HONOURED,
            verdictOf(older(completeAll).putExtra(Utils.EXTRA_APPLIED_OPTIONAL_FIELDS, "[ ]")),
        )
        assertEquals(
            "the same data with no acknowledgement says nothing about what the vault enforced",
            FieldRequirementsVerdict.NOT_ACKNOWLEDGED,
            verdictOf(older(completeAll)),
        )

        for (claimed in listOf("""["phone"]""", """["name","email","phone"]""", """["stray"]""")) {
            assertEquals(
                "an acknowledgement of $claimed to a client that made nothing optional",
                FieldRequirementsVerdict.MISMATCHED,
                verdictOf(older(completeAll).putExtra(Utils.EXTRA_APPLIED_OPTIONAL_FIELDS, claimed)),
            )
        }

        // A sign-up that declares no field at all has nothing optional either.
        val nothingDeclared = FieldRequirements(emptyList())
        val keyOnly = Utils.createShareResultIntent(KEY, emptyMap(), CODE, nothingDeclared)
        assertEquals("[]", keyOnly.getStringExtra(Utils.EXTRA_APPLIED_OPTIONAL_FIELDS))
        assertEquals(FieldRequirementsVerdict.HONOURED, Utils.checkFieldRequirements(nothingDeclared, keyOnly))
    }

    @Test
    fun `complete data with no acknowledgement is NOT_ACKNOWLEDGED`() {
        assertEquals(FieldRequirementsVerdict.NOT_ACKNOWLEDGED, verdict(older(complete)))
        assertEquals(
            "an unreadable acknowledgement is no acknowledgement",
            FieldRequirementsVerdict.NOT_ACKNOWLEDGED,
            verdict(older(complete).putExtra(Utils.EXTRA_APPLIED_OPTIONAL_FIELDS, "[phone]")),
        )
        assertEquals(
            "…and so is the request's own key reflected back, which is why the two keys differ",
            FieldRequirementsVerdict.NOT_ACKNOWLEDGED,
            verdict(older(complete).putExtra(Utils.EXTRA_OPTIONAL_FIELDS, """["phone"]""")),
        )
    }

    @Test
    fun `a missing required field with no acknowledgement is INCOMPLETE`() {
        assertEquals(FieldRequirementsVerdict.INCOMPLETE, verdict(older(incomplete)))
        assertEquals(
            "a blank value is as missing as an absent one",
            FieldRequirementsVerdict.INCOMPLETE,
            verdict(older(complete + ("email" to TypedField("  ", FieldType.EMAIL)))),
        )
        assertEquals(
            "…and this library's own builder will not acknowledge it either, so it is INCOMPLETE " +
                "rather than VIOLATED",
            FieldRequirementsVerdict.INCOMPLETE,
            verdict(acknowledging(incomplete)),
        )
    }

    @Test
    fun `an acknowledgement over a missing required field is VIOLATED`() {
        val handWritten = older(incomplete).putExtra(Utils.EXTRA_APPLIED_OPTIONAL_FIELDS, """["phone"]""")
        assertEquals(FieldRequirementsVerdict.VIOLATED, verdict(handWritten))
    }

    /**
     * The owner's yes/no rule, read from the client's side: a required question the user left
     * unanswered — sent absent or as an empty value — is missing, so this library's builder will
     * not acknowledge it and a hand-written acknowledgement over it is `VIOLATED`. An unanswered
     * optional one is dropped, and an answered "false" is an answer.
     */
    @Test
    fun `an unanswered required yes-no question is missing on both sides of the wire`() {
        val yesNo = FieldRequirements(listOf("subscribed", "newsletter"), setOf("newsletter"))
        fun answered(value: String) = TypedField(value, FieldType.BOOLEAN)

        for (unanswered in listOf<Map<String, TypedField>>(emptyMap(), mapOf("subscribed" to answered("")))) {
            val built = Utils.createShareResultIntent(KEY, unanswered, CODE, yesNo)
            assertFalse("no acknowledgement over $unanswered", built.hasExtra(Utils.EXTRA_APPLIED_OPTIONAL_FIELDS))
            assertEquals(FieldRequirementsVerdict.INCOMPLETE, Utils.checkFieldRequirements(yesNo, built))
            val handWritten = older(unanswered).putExtra(Utils.EXTRA_APPLIED_OPTIONAL_FIELDS, """["newsletter"]""")
            assertEquals(FieldRequirementsVerdict.VIOLATED, Utils.checkFieldRequirements(yesNo, handWritten))
        }

        val saidNo = yesNo.committed(mapOf("subscribed" to answered("false"), "newsletter" to answered("")))!!
        val answer = Utils.createShareResultIntent(KEY, saidNo, CODE, yesNo)
        assertEquals("""["newsletter"]""", answer.getStringExtra(Utils.EXTRA_APPLIED_OPTIONAL_FIELDS))
        assertEquals(FieldRequirementsVerdict.HONOURED, Utils.checkFieldRequirements(yesNo, answer))
    }

    /**
     * A refusal carries the request code and the version and nothing else, so it reads as an
     * answer with no fields: `INCOMPLETE` when something was required, `NOT_ACKNOWLEDGED` when
     * nothing was. Which is why the result code comes first.
     */
    @Test
    fun `a refusal reads as INCOMPLETE, or NOT_ACKNOWLEDGED when nothing is required`() {
        val refusal = Intent()
            .putExtra(Utils.EXTRA_SHARE_REQUEST_CODE, CODE)
            .putExtra(Utils.EXTRA_PROTOCOL_VERSION, Utils.PROTOCOL_VERSION.toString())

        assertEquals(FieldRequirementsVerdict.INCOMPLETE, verdict(refusal))
        val nothingRequired = FieldRequirements(listOf("phone"), setOf("phone"))
        assertEquals(
            FieldRequirementsVerdict.NOT_ACKNOWLEDGED,
            Utils.checkFieldRequirements(nothingRequired, refusal),
        )
        assertEquals(FieldRequirementsVerdict.INCOMPLETE, verdict(null))
    }

    /**
     * The partition, over every combination of a payload, an acknowledgement and a declaration
     * that this file can name — designed shapes; `DecoderFuzzTest` holds the same property over its
     * corpus of payloads nobody designed.
     */
    @Test
    fun `the verdict splits exactly on whether the data is complete`() {
        val payloads = listOf(
            null,
            "{}",
            Utils.encodeFields(complete),
            Utils.encodeFields(incomplete),
            Utils.encodeFields(complete + ("phone" to TypedField("", FieldType.PHONE))),
            Utils.encodeFields(complete + ("email" to TypedField(" "))),
            "not json",
            """{"name":null,"email":{"value":"x"}}""",
        )
        val acknowledgements = listOf(null, "[]", """["phone"]""", """["name"]""", "[phone]", "", "{}")
        val declarations = listOf(
            requirements,
            FieldRequirements(listOf("name", "email", "phone")),
            FieldRequirements(listOf("name", "phone"), setOf("name", "phone")),
            FieldRequirements(emptyList()),
        )
        val seen = mutableSetOf<FieldRequirementsVerdict>()

        for (payload in payloads) for (ack in acknowledgements) for (declared in declarations) {
            val result = Intent().apply {
                putExtra(Utils.EXTRA_PUBLIC_KEY, KEY)
                if (payload != null) putExtra(Utils.EXTRA_FIELDS_JSON, payload)
                if (ack != null) putExtra(Utils.EXTRA_APPLIED_OPTIONAL_FIELDS, ack)
            }
            val verdict = Utils.checkFieldRequirements(declared, result)
            val fields = Utils.parseShareResult(result)!!.fields
            val dataComplete = declared.committed(fields) != null
            assertEquals(
                "payload=$payload ack=$ack declared=$declared gave $verdict",
                dataComplete,
                verdict in COMPLETE_VERDICTS,
            )
            seen += verdict
        }

        assertEquals(
            "every verdict must occur in the sweep, or the partition was checked over a subset",
            FieldRequirementsVerdict.values().toSet(),
            seen,
        )
    }

    /** Total over the hostile shapes an answer can take. */
    @Test
    fun `checkFieldRequirements never throws on a hostile answer`() {
        val unreadable = object : Intent() {
            override fun getStringExtra(name: String?): String? =
                throw BadParcelableException("extras reference an unknown class")
        }
        val shapes = listOf(
            null,
            Intent(),
            unreadable,
            Intent().putExtra(Utils.EXTRA_FIELDS_JSON, 7).putExtra(Utils.EXTRA_APPLIED_OPTIONAL_FIELDS, 7),
            Intent().putExtra(Utils.EXTRA_APPLIED_OPTIONAL_FIELDS, "[".repeat(50_000)),
            // The field payload's depth is `DecoderFuzzTest`'s NEST range, which that file proves
            // the JSON parser survives; the acknowledgement above needs no such care, because the
            // strict reader refuses a nested opener at the first element.
            Intent().putExtra(Utils.EXTRA_FIELDS_JSON, "{\"a\":".repeat(1_000)),
        )
        shapes.forEach { shape ->
            val verdict = runCatching { verdict(shape) }
            assertTrue("checkFieldRequirements threw on $shape: ${verdict.exceptionOrNull()}", verdict.isSuccess)
            assertEquals(FieldRequirementsVerdict.INCOMPLETE, verdict.getOrNull())
        }
    }

    /**
     * The enum's order is published: anything persisting a verdict by ordinal depends on it, and
     * a new value must go at the end. Listed rather than counted, so a rename names itself.
     */
    @Test
    fun `the verdict enum exposes exactly the documented values in order`() {
        assertEquals(
            listOf("HONOURED", "MISMATCHED", "NOT_ACKNOWLEDGED", "INCOMPLETE", "VIOLATED"),
            FieldRequirementsVerdict.values().map { it.name },
        )
        assertEquals(FieldRequirementsVerdict.VIOLATED, FieldRequirementsVerdict.valueOf("VIOLATED"))
        assertEquals(FieldRequirementsVerdict.values().toList(), FieldRequirementsVerdict.entries)
    }

    private companion object {
        private const val KEY = "a-fake-public-key-from-a-test"
        private const val CODE = "signup-1"

        /** The verdicts under which every required field arrived non-blank. */
        private val COMPLETE_VERDICTS = setOf(
            FieldRequirementsVerdict.HONOURED,
            FieldRequirementsVerdict.MISMATCHED,
            FieldRequirementsVerdict.NOT_ACKNOWLEDGED,
        )
    }
}
