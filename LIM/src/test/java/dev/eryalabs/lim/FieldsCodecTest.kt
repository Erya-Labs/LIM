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
     *
     * Every assertion here names the value it expects. The two it replaces did not —
     * `assertEquals(field.value.length, field.value.length)` and
     * `assertTrue(normalize(field.type).isNotEmpty())` — and neither could fail for any input:
     * the first compares an expression with itself, and `normalize` folds a blank type to
     * `"String"`, so its result is never empty whatever it is handed. They went red today only
     * as a side effect, by throwing an NPE on the way to asserting nothing, and would have
     * stopped doing even that the day `TypedField.value` was declared nullable. What the
     * repair actually promises is a *specific* value and a *specific* type per malformed
     * shape, so that is what is written down.
     */
    @Test
    fun `decoded fields are safe to dereference`() {
        val decoded = Utils.decodeFields("""{"a":{"value":"x"},"b":{"type":"int"},"c":{}}""")

        assertEquals(setOf("a", "b", "c"), decoded.keys)
        assertEquals("x", decoded["a"]!!.value)
        assertEquals(1, decoded["a"]!!.value.length)
        assertEquals(FieldType.STRING, decoded["a"]!!.type)

        assertEquals("a missing value becomes empty, not null", "", decoded["b"]!!.value)
        assertEquals(0, decoded["b"]!!.value.length)
        assertEquals("an unknown spelling is kept verbatim", "int", decoded["b"]!!.type)
        assertEquals("...and still normalizes", FieldType.INTEGER, FieldType.normalize(decoded["b"]!!.type))

        assertEquals("", decoded["c"]!!.value)
        assertEquals(FieldType.STRING, decoded["c"]!!.type)
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
     * The case broken JSON does not cover, and the one a peer app is most likely to send by
     * accident: a document that parses perfectly and is simply not a field map. Gson is
     * type-directed, so the failure here is not a syntax error — it is an adapter asked for a
     * `Map<String, TypedField>` and handed a number, and what it does about that is Gson's
     * business rather than something this library states. [Utils.decodeEntry] has had this
     * pinned since T1; its sibling had only broken-syntax cases.
     */
    @Test
    fun `well-formed json of the wrong shape decodes to an empty map`() {
        val wrongShapes = listOf(
            "null",
            "42",
            "true",
            "\"just a string\"",
            "[]",
            "[1,2,3]",
            """[{"value":"x","type":"String"}]""",
            """{"a":7}""",
            """{"a":"x"}""",
            """{"a":[{"value":"x"}]}""",
            """{"a":{"value":{"nested":"x"}}}""",
            """{"a":{"value":"x"}} trailing junk""",
        )
        wrongShapes.forEach { json ->
            assertEquals("[$json] must degrade to an empty map", emptyMap<String, TypedField>(), Utils.decodeFields(json))
        }
    }

    /**
     * The other shape a hostile sender reaches for: not JSON at all, just bytes. A field
     * payload and a Base64 blob travel in sibling extras of the same intent, so a vault that
     * crosses its own wires puts one where the other belongs, and control characters are what
     * arrives when the string is really binary.
     */
    @Test
    fun `binary and base64-shaped junk decodes to an empty map`() {
        val junk = listOf(
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA",
            "!!!!",
            "====",
            " ",
            String(CharArray(64) { (it % 256).toChar() }),
            "🔐�",
        )
        junk.forEach { text ->
            assertEquals("[$text] must degrade to an empty map", emptyMap<String, TypedField>(), Utils.decodeFields(text))
        }
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
