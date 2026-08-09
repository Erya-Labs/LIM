package dev.eryalabs.lim

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [FieldType] is pure Kotlin with no Android dependencies, so it runs on the bare JVM —
 * no Robolectric needed. Keeping it that way is deliberate: it is the fastest possible
 * feedback on the part of the protocol most likely to be extended.
 */
class FieldTypeTest {

    @Test
    fun `canonical spellings normalize to themselves`() {
        FieldType.KNOWN.forEach { canonical ->
            assertEquals(
                "canonical type $canonical should be a fixed point of normalize()",
                canonical,
                FieldType.normalize(canonical),
            )
        }
    }

    @Test
    fun `documented aliases fold to canonical spellings`() {
        val cases = mapOf(
            "str" to FieldType.STRING,
            "text" to FieldType.STRING,
            "int" to FieldType.INTEGER,
            "double" to FieldType.DECIMAL,
            "float" to FieldType.DECIMAL,
            "number" to FieldType.DECIMAL,
            "bool" to FieldType.BOOLEAN,
            "datetime" to FieldType.DATE,
            "timestamp" to FieldType.DATE,
            "e-mail" to FieldType.EMAIL,
            "mail" to FieldType.EMAIL,
            "tel" to FieldType.PHONE,
            "telephone" to FieldType.PHONE,
            "uri" to FieldType.URL,
            "link" to FieldType.URL,
        )
        cases.forEach { (raw, expected) ->
            assertEquals("normalize(\"$raw\")", expected, FieldType.normalize(raw))
        }
    }

    @Test
    fun `normalize is case and whitespace insensitive`() {
        assertEquals(FieldType.EMAIL, FieldType.normalize("  EMAIL  "))
        assertEquals(FieldType.INTEGER, FieldType.normalize("\tInT\n"))
        assertEquals(FieldType.DECIMAL, FieldType.normalize("Number"))
    }

    /**
     * Forward compatibility is the whole reason types are strings and not an enum: an app
     * built against an older library must be able to send a type this version has never
     * heard of, and have it survive the round trip unchanged.
     */
    @Test
    fun `unknown types pass through unchanged rather than collapsing to String`() {
        assertEquals("Iban", FieldType.normalize("Iban"))
        assertEquals("PostalCode", FieldType.normalize("  PostalCode "))
        assertFalse(
            "an unknown type must not be silently rewritten to STRING",
            FieldType.normalize("Iban") == FieldType.STRING,
        )
    }

    @Test
    fun `blank input falls back to String`() {
        assertEquals(FieldType.STRING, FieldType.normalize(""))
        assertEquals(FieldType.STRING, FieldType.normalize("   "))
        assertEquals(FieldType.STRING, FieldType.normalize("\t\n"))
    }

    /**
     * Negative control. If normalize() were replaced by the identity function, every other
     * assertion above about aliases would still need this one to fail — it pins the fact
     * that normalization actually changes something.
     */
    @Test
    fun `normalize is not the identity function`() {
        assertTrue(
            "normalize() must actually transform aliases, not return input verbatim",
            FieldType.normalize("int") != "int",
        )
    }

    @Test
    fun `KNOWN contains exactly the documented types`() {
        assertEquals(8, FieldType.KNOWN.size)
        assertTrue(FieldType.KNOWN.containsAll(
            listOf("String", "Integer", "Decimal", "Boolean", "Date", "Email", "Phone", "Url")
        ))
    }
}
