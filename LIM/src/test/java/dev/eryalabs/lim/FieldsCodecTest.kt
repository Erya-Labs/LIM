package dev.eryalabs.lim

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * [Utils.encodeFields] / [Utils.decodeFields] are the wire format between a client app and
 * the vault. A silent change here does not crash — it quietly hands the client the wrong
 * profile data, which is why the round trip is pinned field-by-field.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class FieldsCodecTest {

    private val sample = linkedMapOf(
        "name" to TypedField("Ada Lovelace", FieldType.STRING),
        "age" to TypedField("36", FieldType.INTEGER),
        "email" to TypedField("ada@example.com", FieldType.EMAIL),
        "subscribed" to TypedField("true", FieldType.BOOLEAN),
    )

    @Test
    fun `round trip preserves every key, value and type`() {
        val decoded = Utils.decodeFields(Utils.encodeFields(sample))
        assertEquals(sample.keys, decoded.keys)
        sample.forEach { (key, expected) ->
            assertEquals("value of $key", expected.value, decoded[key]?.value)
            assertEquals("type of $key", expected.type, decoded[key]?.type)
        }
    }

    @Test
    fun `round trip survives an empty map`() {
        assertEquals(emptyMap<String, TypedField>(), Utils.decodeFields(Utils.encodeFields(emptyMap())))
    }

    /**
     * Names, addresses and free-text fields are exactly the payload this protocol exists to
     * carry, so non-ASCII and JSON metacharacters are the realistic case, not the exotic one.
     */
    @Test
    fun `round trip survives unicode, quotes and newlines in values`() {
        val hostile = mapOf(
            "名前" to TypedField("山田 太郎", FieldType.STRING),
            "quote" to TypedField("she said \"hello\"", FieldType.STRING),
            "backslash" to TypedField("C:\\Users\\tomsa", FieldType.STRING),
            "newline" to TypedField("line one\nline two", FieldType.STRING),
            "emoji" to TypedField("🔐", FieldType.STRING),
            "brace" to TypedField("{\"injected\": true}", FieldType.STRING),
        )
        val decoded = Utils.decodeFields(Utils.encodeFields(hostile))
        hostile.forEach { (key, expected) ->
            assertEquals("value of $key", expected.value, decoded[key]?.value)
        }
    }

    @Test
    fun `an unknown field type survives the round trip`() {
        val forwardCompatible = mapOf("iban" to TypedField("GB33BUKB20201555555555", "Iban"))
        val decoded = Utils.decodeFields(Utils.encodeFields(forwardCompatible))
        assertEquals("Iban", decoded["iban"]?.type)
    }

    // ── Untrusted input: JSON arriving from another app over IPC ────────
    //
    // Gson builds TypedField through Unsafe without running the Kotlin constructor, so a
    // key absent from the JSON leaves a declared-non-null property genuinely null at
    // runtime. Kotlin inserts no null check when reading its own non-null property, so the
    // null escapes silently and NPEs somewhere far away. These three pin the repair.

    @Test
    fun `a field with no declared type defaults to String`() {
        val decoded = Utils.decodeFields("""{"nickname":{"value":"Ada"}}""")
        assertEquals("Ada", decoded["nickname"]?.value)
        assertEquals(FieldType.STRING, decoded["nickname"]?.type)
    }

    @Test
    fun `a field with no value decodes to an empty string, not null`() {
        val decoded = Utils.decodeFields("""{"nickname":{"type":"Email"}}""")
        assertEquals("", decoded["nickname"]?.value)
        assertEquals(FieldType.EMAIL, decoded["nickname"]?.type)
    }

    @Test
    fun `a null field entry is dropped rather than yielding a null value`() {
        val decoded = Utils.decodeFields("""{"good":{"value":"x","type":"String"},"bad":null}""")
        assertEquals(setOf("good"), decoded.keys)
        assertEquals("x", decoded["good"]?.value)
    }

    /**
     * The payoff: a decoded field can be fed straight to [FieldType.normalize] without the
     * caller defending against a null the type system already promised was impossible.
     */
    @Test
    fun `decoded fields are safe to dereference`() {
        val decoded = Utils.decodeFields("""{"a":{"value":"x"},"b":{"type":"int"},"c":{}}""")
        decoded.forEach { (key, field) ->
            assertEquals("$key length is readable", field.value.length, field.value.length)
            assertTrue("$key type normalizes", FieldType.normalize(field.type).isNotEmpty())
        }
        assertEquals(FieldType.STRING, decoded["c"]?.type)
        assertEquals("", decoded["c"]?.value)
    }

    // ── Negative controls: malformed input must degrade, never throw ─────

    @Test
    fun `malformed input decodes to an empty map instead of throwing`() {
        assertEquals(emptyMap<String, TypedField>(), Utils.decodeFields(null))
        assertEquals(emptyMap<String, TypedField>(), Utils.decodeFields(""))
        assertEquals(emptyMap<String, TypedField>(), Utils.decodeFields("   "))
        assertEquals(emptyMap<String, TypedField>(), Utils.decodeFields("not json at all"))
        assertEquals(emptyMap<String, TypedField>(), Utils.decodeFields("""{"unclosed": """))
    }

    /**
     * Negative control for the round-trip tests above: if [Utils.encodeFields] returned a
     * constant, or [Utils.decodeFields] ignored its argument, the assertions would still
     * pass. This one fails in that world.
     */
    @Test
    fun `encode actually reflects its input`() {
        val a = Utils.encodeFields(mapOf("k" to TypedField("one", FieldType.STRING)))
        val b = Utils.encodeFields(mapOf("k" to TypedField("two", FieldType.STRING)))
        assertNotEquals("encodeFields must depend on its input", a, b)
        assertTrue("encoded JSON should contain the value", a.contains("one"))
    }
}
