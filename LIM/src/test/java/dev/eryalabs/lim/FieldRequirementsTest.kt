package dev.eryalabs.lim

import com.google.gson.Gson
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.TreeMap
import java.util.TreeSet

/**
 * [FieldRequirements] is the one definition of "blank" this protocol has, so it is pinned here as
 * a table rather than as a handful of examples: every shape a vault's draft or a client's decoded
 * result can carry, and which side of the line it falls on.
 *
 * The line itself, stated once so the table can be read against it: **absent, `null`, or
 * Kotlin-`isBlank`** is blank — a no-break space included — and nothing else is. A zero-width
 * space is *not* blank, and neither are `"0"` and `"false"`: required means "the user put
 * something here", never "the user put something valid here". Nothing is trimmed or rewritten.
 *
 * No Robolectric: the class is plain Kotlin over JDK collections, and a [TypedField] is constructed
 * without touching anything Android implements.
 */
class FieldRequirementsTest {

    private val name = TypedField("Ada", FieldType.STRING)
    private val email = TypedField("ada@example.com", FieldType.EMAIL)
    private val phone = TypedField("555-0100", FieldType.PHONE)

    /** `name`, `email` required; `phone` optional — the guide's sign-up. */
    private val requirements = FieldRequirements(listOf("name", "email", "phone"), setOf("phone"))

    /**
     * A [TypedField] whose `value` is genuinely `null`, the way Gson builds one through `Unsafe` —
     * the hazard `Utils.decodeEntry` documents. Built through Gson rather than a cast, because
     * that is the route by which one actually exists.
     */
    private fun nullValued(type: String = FieldType.STRING): TypedField =
        Gson().fromJson("""{"type":"$type"}""", TypedField::class.java)

    @Test
    fun `names are de-duplicated, ordered and intersected`() {
        val built = FieldRequirements(
            listOf("name", "email", "name", "phone", "email"),
            linkedSetOf("phone", "stray", "name"),
        )

        assertEquals(listOf("name", "email", "phone"), built.fieldNames)
        assertEquals(
            "the optional set is the declared names it names, in declaration order, and a name " +
                "that is not declared is dropped rather than added",
            listOf("name", "phone"),
            built.optionalFields.toList(),
        )
        assertEquals(listOf("email"), built.requiredFields.toList())
        assertEquals(
            "with no optional list, every declared field is required",
            listOf("name", "email", "phone"),
            FieldRequirements(listOf("name", "email", "phone")).requiredFields.toList(),
        )
        assertTrue(FieldRequirements(listOf("name")).optionalFields.isEmpty())
    }

    /** Reachable from Java, which honours no element nullability; skipped rather than kept. */
    @Suppress("UNCHECKED_CAST")
    @Test
    fun `Java null elements are skipped rather than kept`() {
        val names = arrayListOf<String?>("name", null, "email") as List<String>
        val optional = hashSetOf<String?>(null, "email") as Set<String>

        val built = FieldRequirements(names, optional)

        assertEquals(listOf("name", "email"), built.fieldNames)
        assertEquals(setOf("email"), built.optionalFields)
        assertEquals(setOf("name"), built.requiredFields)
    }

    @Test
    fun `matching is exact, with no trimming and no case folding`() {
        val built = FieldRequirements(listOf("email"), listOf("Email", " email", "email "))
        assertTrue("no spelling but the exact one makes a field optional", built.optionalFields.isEmpty())

        // A collection with its own idea of equality must not be able to widen that either.
        val folding = TreeSet(String.CASE_INSENSITIVE_ORDER).apply { add("EMAIL") }
        assertTrue(
            "a case-insensitive set naming EMAIL must not make email optional",
            FieldRequirements(listOf("email"), folding).optionalFields.isEmpty(),
        )
        val foldingValues = TreeMap<String, TypedField>(String.CASE_INSENSITIVE_ORDER)
            .apply { put("EMAIL", email) }
        assertEquals(
            "…and a case-insensitive map holding EMAIL does not answer for email",
            listOf("email"),
            FieldRequirements(listOf("email")).missingRequired(foldingValues),
        )
        assertEquals(
            listOf("email"),
            FieldRequirements(listOf("email")).missingRequired(mapOf("Email" to email, " email" to email)),
        )

        // All three members that take a map match its keys exactly, not just missingRequired.
        // The map itself would say otherwise, and that is the whole point: it encodes as "EMAIL",
        // so a client looking up email finds nothing, and a vault that trusted the map's own
        // lookup would acknowledge a payload whose wire keys lack a required field.
        val onlyEmail = FieldRequirements(listOf("email"))
        assertTrue("precondition: the map answers for email by itself", foldingValues.containsKey("email"))
        assertFalse(
            "a case-insensitive map holding EMAIL does not satisfy a requirement for email, so the " +
                "requirements-aware builder writes no acknowledgement over it",
            onlyEmail.isSatisfiedBy(foldingValues),
        )
        assertNull(
            "…and there is no profile to commit from it: committed is null exactly when " +
                "missingRequired is non-empty",
            onlyEmail.committed(foldingValues),
        )
        val foldingDraft = TreeMap<String, TypedField>(String.CASE_INSENSITIVE_ORDER)
            .apply { put("name", name); put("EMAIL", email) }
        assertEquals(
            "with email optional the draft commits, but EMAIL's value is not filed under email: EMAIL " +
                "is not declared, so it is dropped like any other undeclared key",
            mapOf("name" to name),
            FieldRequirements(listOf("name", "email"), setOf("email")).committed(foldingDraft),
        )
        val exactKey = TreeMap<String, TypedField>(String.CASE_INSENSITIVE_ORDER).apply { put("email", email) }
        assertTrue(
            "control: the exact spelling, held by the same kind of map, satisfies the requirement",
            onlyEmail.isSatisfiedBy(exactKey),
        )
        assertEquals(mapOf("email" to email), onlyEmail.committed(exactKey))
    }

    /**
     * The table. Every blank shape against a required field must be reported missing, and every
     * present shape must not be — asserted in both directions so that neither "everything is
     * blank" nor "nothing is" can pass. And over every declared type: blank never depends on
     * [TypedField.type], so a rule that read an empty yes/no as "false", or an empty number as
     * zero, would turn a row of this table red.
     */
    @Test
    fun `missingRequired treats every blank shape as missing and nothing else`() {
        val nbsp = 0x00A0.toChar().toString()
        val zeroWidthSpace = 0x200B.toChar().toString()
        val only = FieldRequirements(listOf("f"))
        // Every type this library names, and one a peer made up.
        val types = FieldType.KNOWN + "Colour"

        @Suppress("UNCHECKED_CAST")
        val nullField = hashMapOf<String, TypedField?>("f" to null) as Map<String, TypedField>
        val blankValues = mapOf(
            "empty" to "",
            "spaces" to "  ",
            "tab and newline" to "\t\n",
            "no-break space only" to nbsp + nbsp,
        )
        val blank = linkedMapOf<String, Map<String, TypedField>>(
            "absent" to emptyMap(),
            "a null field, as Java can pass one" to nullField,
        )
        for (type in types) {
            blankValues.forEach { (shape, value) -> blank["$shape, as $type"] = mapOf("f" to TypedField(value, type)) }
            blank["a null value, as Gson builds one, as $type"] = mapOf("f" to nullValued(type))
        }
        val present = mapOf(
            "zero" to "0",
            "false" to "false",
            "a zero-width space" to zeroWidthSpace,
            "padded" to "  x  ",
        )

        assertTrue("the table covers a yes/no field", blank.keys.any { it.endsWith("as ${FieldType.BOOLEAN}") })
        blank.forEach { (shape, values) ->
            assertEquals("$shape must be missing", listOf("f"), only.missingRequired(values))
            assertNull("$shape must not commit", only.committed(values))
        }
        for (type in types) {
            present.forEach { (shape, value) ->
                val values = mapOf("f" to TypedField(value, type))
                assertEquals("$shape, as $type, must be present", emptyList<String>(), only.missingRequired(values))
                assertEquals(
                    "$shape, as $type, is kept exactly as given — never trimmed or rewritten",
                    value,
                    only.committed(values)?.get("f")?.value,
                )
            }
        }
        assertEquals(
            "the order is the declaration order, and only required names are reported",
            listOf("name", "email"),
            requirements.missingRequired(mapOf("phone" to phone)),
        )
    }

    /**
     * The owner's rule for yes/no fields, which a vault offering "Not answered" relies on: a
     * question the user has not answered is blank whether the vault sends it as an absent field or
     * as an empty value, so a required one blocks Save and an optional one is dropped. Only an
     * answer the user gave — `"true"` or `"false"` — is present.
     */
    @Test
    fun `an unanswered yes-no question is blank whether it arrives absent or empty`() {
        val yesNo = FieldRequirements(listOf("subscribed", "newsletter"), setOf("newsletter"))
        fun answered(value: String) = TypedField(value, FieldType.BOOLEAN)

        for ((shape, draft) in listOf<Pair<String, Map<String, TypedField>>>(
            "absent" to emptyMap(),
            "empty" to mapOf("subscribed" to answered("")),
            "whitespace" to mapOf("subscribed" to answered(" ")),
            "empty, beside an unanswered optional one" to mapOf(
                "subscribed" to answered(""),
                "newsletter" to answered(""),
            ),
        )) {
            assertEquals("$shape: a required unanswered question blocks", listOf("subscribed"), yesNo.missingRequired(draft))
            assertNull("$shape: nothing is committed", yesNo.committed(draft))
            assertFalse("$shape: nothing is acknowledged", yesNo.isSatisfiedBy(draft))
        }

        val saidNo = mapOf("subscribed" to answered("false"), "newsletter" to answered(""))
        assertEquals("\"false\" is an answer", emptyList<String>(), yesNo.missingRequired(saidNo))
        assertEquals(
            "an unanswered optional question is dropped",
            mapOf("subscribed" to answered("false")),
            yesNo.committed(saidNo),
        )
        assertFalse("…and a payload still carrying it is not one to acknowledge", yesNo.isSatisfiedBy(saidNo))
        assertTrue(yesNo.isSatisfiedBy(mapOf("subscribed" to answered("false"), "newsletter" to answered("true"))))
        assertTrue(yesNo.isSatisfiedBy(mapOf("subscribed" to answered("true"))))
    }

    @Test
    fun `a blank optional value in the payload is not satisfied`() {
        val complete = mapOf("name" to name, "email" to email)
        assertTrue("the required fields alone satisfy", requirements.isSatisfiedBy(complete))
        assertTrue(
            "a filled optional field satisfies too",
            requirements.isSatisfiedBy(complete + ("phone" to phone)),
        )
        assertFalse(
            "a blank optional field still in the payload does not: it should have been dropped",
            requirements.isSatisfiedBy(complete + ("phone" to TypedField(""))),
        )
        assertFalse(
            "…nor does a blank undeclared one",
            requirements.isSatisfiedBy(complete + ("stray" to TypedField(" "))),
        )
        assertTrue(
            "an undeclared non-blank key is not this check's business",
            requirements.isSatisfiedBy(complete + ("stray" to TypedField("x"))),
        )
        assertFalse(
            "a missing required field never satisfies",
            requirements.isSatisfiedBy(mapOf("name" to name)),
        )
    }

    @Test
    fun `committed drops blank optional fields and undeclared keys`() {
        val draft = linkedMapOf(
            "stray" to TypedField("kept nowhere"),
            "phone" to TypedField("   "),
            "email" to email,
            "name" to name,
        )

        val kept = requirements.committed(draft)

        assertEquals(
            "declared, non-blank, in declaration order — not the draft's order",
            listOf("name", "email"),
            kept?.keys?.toList(),
        )
        assertEquals(email, kept?.get("email"))
        assertEquals(
            "a filled optional field is kept",
            listOf("name", "email", "phone"),
            requirements.committed(draft + ("phone" to phone))?.keys?.toList(),
        )
        assertNull(
            "null exactly when a required field is missing",
            requirements.committed(mapOf("name" to name, "phone" to phone)),
        )
    }

    /**
     * The owner's answer to "every field optional, every field blank": a profile that is a key and
     * nothing else. The library's half is that `committed` is an empty map rather than `null`, and
     * that an empty payload satisfies — the end-to-end half is in
     * `RequirementsCompatibilityMatrixTest`.
     */
    @Test
    fun `every field optional and every field blank commits an empty profile`() {
        val allOptional = FieldRequirements(listOf("name", "phone"), setOf("name", "phone"))
        val blankDraft = mapOf("name" to TypedField(""), "phone" to TypedField(" "))

        assertTrue(allOptional.requiredFields.isEmpty())
        assertEquals(emptyList<String>(), allOptional.missingRequired(blankDraft))
        assertEquals(emptyMap<String, TypedField>(), allOptional.committed(blankDraft))
        assertTrue("the committed empty map is what may be acknowledged", allOptional.isSatisfiedBy(emptyMap()))
        assertFalse("…and the blank draft itself is not", allOptional.isSatisfiedBy(blankDraft))
    }

    /**
     * The gate and the stored map are one decision: whatever a vault blocks Save on is exactly what
     * makes `committed` refuse. Over every combination of the table's shapes in three fields.
     */
    @Test
    fun `missingRequired and committed agree on every draft`() {
        // `null` here means "the key is absent from the draft", the shape a form never wrote.
        val shapes = listOf<TypedField?>(null, TypedField(""), TypedField(" "), TypedField("x"), nullValued())
        var compared = 0
        for (a in shapes) for (b in shapes) for (c in shapes) {
            val draft = LinkedHashMap<String, TypedField>()
            listOf("name" to a, "email" to b, "phone" to c).forEach { (key, field) ->
                if (field != null) draft[key] = field
            }
            val missing = requirements.missingRequired(draft)
            val committed = requirements.committed(draft)
            assertEquals(
                "committed must be null exactly when something required is missing: $draft",
                missing.isNotEmpty(),
                committed == null,
            )
            if (committed != null) {
                assertTrue(
                    "a committed map must itself satisfy the requirements: $draft",
                    requirements.isSatisfiedBy(committed),
                )
            }
            compared++
        }
        assertEquals(125, compared)
    }

    @Test
    fun `equality is the ordered names and the optional set`() {
        val a = FieldRequirements(listOf("name", "email"), setOf("email"))
        val b = FieldRequirements(listOf("name", "email", "name"), listOf("email", "stray"))

        assertEquals("built from different inputs, the same requirements", a, b)
        assertEquals(a.hashCode(), b.hashCode())
        assertNotEquals(
            "the order is part of it: it is the form's row order",
            a,
            FieldRequirements(listOf("email", "name"), setOf("email")),
        )
        assertNotEquals(a, FieldRequirements(listOf("name", "email")))
        assertNotEquals(a, FieldRequirements(listOf("name", "email"), setOf("name")))
        assertFalse("not equal to an unrelated object", a.equals(listOf("name", "email")))
        assertFalse(a.equals(null))
    }

    @Test
    fun `toString shows counts and never a name`() {
        val probe = FieldRequirements(listOf("SECRET_FIELD_NAME", "other"), setOf("SECRET_FIELD_NAME"))

        assertEquals("FieldRequirements(fields=2, optional=1)", probe.toString())
        assertFalse("SECRET_FIELD_NAME" in probe.toString())
    }

    /** Immutable, with defensive copies: neither the caller's collections nor its casts reach in. */
    @Suppress("UNCHECKED_CAST")
    @Test
    fun `the collections in and out are copies, and the ones out are read-only`() {
        val names = mutableListOf("name", "email")
        val optional = mutableSetOf("email")
        val built = FieldRequirements(names, optional)
        names += "phone"
        optional += "name"

        assertEquals(listOf("name", "email"), built.fieldNames)
        assertEquals(setOf("email"), built.optionalFields)

        val attempts = listOf<() -> Any?>(
            { (built.fieldNames as MutableList<String>).add("x") },
            { (built.optionalFields as MutableSet<String>).add("x") },
            { (built.requiredFields as MutableSet<String>).add("x") },
            { (built.missingRequired(emptyMap()) as MutableList<String>).add("x") },
            { (built.committed(mapOf("name" to name)) as MutableMap<String, TypedField>).put("x", name) },
        )
        attempts.forEachIndexed { index, attempt ->
            val thrown = runCatching { attempt() }.exceptionOrNull()
            assertTrue(
                "handed-out collection #$index must refuse a write, got $thrown",
                thrown is UnsupportedOperationException,
            )
        }
    }
}
