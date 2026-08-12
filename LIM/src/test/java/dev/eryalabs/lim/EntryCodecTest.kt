package dev.eryalabs.lim

import com.google.gson.Gson
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * [Utils.decodeEntry] is the trust boundary for the share payload: the JSON it is handed
 * came from another app over IPC and may be anything at all.
 *
 * Gson builds [Entry] through `Unsafe` without running the Kotlin constructor, so `id`,
 * `publicKey` and `fields` can each be genuinely `null` at runtime despite being declared
 * non-null, and Kotlin emits no null check when reading its own non-null property. A raw
 * `Gson().fromJson` of `{}` therefore yields an [Entry] that NPEs the first time anyone
 * touches it. These tests pin the repair.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class EntryCodecTest {

    private val sample = Entry(
        id = "profile-1",
        fields = linkedMapOf(
            "name" to TypedField("Ada Lovelace", FieldType.STRING),
            "age" to TypedField("36", FieldType.INTEGER),
            "email" to TypedField("ada@example.com", FieldType.EMAIL),
        ),
        publicKey = "MIIBIjANBgkq",
    )

    // ── Well-formed input ────────────────────────────────────────────────

    @Test
    fun `round trip returns a well-formed entry unchanged`() {
        val decoded = Utils.decodeEntry(Gson().toJson(sample))
        assertEquals(sample, decoded)
    }

    @Test
    fun `round trip preserves every field key, value and type`() {
        val decoded = Utils.decodeEntry(Gson().toJson(sample))
        assertNotNull(decoded)
        assertEquals(sample.fields.keys, decoded!!.fields.keys)
        sample.fields.forEach { (key, expected) ->
            assertEquals("value of $key", expected.value, decoded.fields[key]?.value)
            assertEquals("type of $key", expected.type, decoded.fields[key]?.type)
        }
    }

    @Test
    fun `round trip survives unicode, quotes and newlines`() {
        val hostile = Entry(
            id = "識別子",
            fields = mapOf(
                "quote" to TypedField("she said \"hello\"", FieldType.STRING),
                "backslash" to TypedField("C:\\Users\\tomsa", FieldType.STRING),
                "newline" to TypedField("line one\nline two", FieldType.STRING),
                "brace" to TypedField("{\"injected\": true}", FieldType.STRING),
            ),
            publicKey = "🔐key",
        )
        assertEquals(hostile, Utils.decodeEntry(Gson().toJson(hostile)))
    }

    @Test
    fun `an entry with no fields decodes to an empty map, not null`() {
        val decoded = Utils.decodeEntry("""{"id":"x","publicKey":"k"}""")
        assertNotNull(decoded)
        assertEquals(emptyMap<String, TypedField>(), decoded!!.fields)
        assertEquals("x", decoded.id)
        assertEquals("k", decoded.publicKey)
    }

    // ── Hostile input: identity missing ──────────────────────────────────
    //
    // id and publicKey are the entry's identity. A payload carrying neither is not
    // repairable into something a vault could ever authenticate, so it is rejected.

    @Test
    fun `an empty json object decodes to null rather than an entry that throws`() {
        assertNull(Utils.decodeEntry("{}"))
    }

    @Test
    fun `an entry with only an id decodes to null`() {
        assertNull(Utils.decodeEntry("""{"id":"x"}"""))
    }

    @Test
    fun `an entry with only a public key decodes to null`() {
        assertNull(Utils.decodeEntry("""{"publicKey":"k"}"""))
    }

    /**
     * The strictest and most surprising thing this library does, so it is pinned as a table
     * rather than as a handful of examples.
     *
     * Surprising because it is asymmetric: [Utils.createShareIntent] will happily *encode* an
     * entry with a blank identity, and this refuses to decode the same bytes back. That
     * asymmetry is deliberate and is logged for a human under "Blocked on human" — which means
     * it is exactly the behaviour somebody will one day be tempted to "fix" by loosening a
     * condition here. Every combination is asserted so that loosening either half goes red on
     * its own: dropping the `id` check alone, dropping the `publicKey` check alone, and
     * dropping `isBlank` in favour of a null check alone are three different edits and each
     * one has rows here that no other row covers.
     *
     * The whitespace rows are the ones that separate `isBlank()` from `isEmpty()`. The
     * non-breaking space is there because Kotlin's `isBlank` is *broader* than Java's: it asks
     * `Character.isWhitespace(c) || Character.isSpaceChar(c)`, and U+00A0 fails the first test
     * and passes the second. So a payload whose whole identity is a non-breaking space is
     * refused, which is not what reading `Character.isWhitespace` alone would predict — the note
     * T6 left in the progress log predicted the opposite. Pinned here because it is the kind of
     * thing that gets "corrected" by someone reasoning from the Java method.
     *
     * The positive controls at the end pin that this rejects blanks rather than rejecting
     * everything.
     */
    @Test
    fun `a blank id or public key decodes to null`() {
        val blanks = listOf("\"\"", "\"   \"", "\"\\t\"", "\"\\n\"", "\"\\r\\n\"", "\" \\t \"")

        blanks.forEach { blank ->
            assertNull("blank id, real key: $blank", Utils.decodeEntry("""{"id":$blank,"publicKey":"k"}"""))
            assertNull("real id, blank key: $blank", Utils.decodeEntry("""{"id":"x","publicKey":$blank}"""))
            assertNull("both blank: $blank", Utils.decodeEntry("""{"id":$blank,"publicKey":$blank}"""))
            assertNull("blank id, absent key: $blank", Utils.decodeEntry("""{"id":$blank}"""))
            assertNull("absent id, blank key: $blank", Utils.decodeEntry("""{"publicKey":$blank}"""))
        }

        // Absent is a different code path from blank — a null property out of Gson rather than
        // an empty string — and each half must reject on its own.
        assertNull("id absent", Utils.decodeEntry("""{"publicKey":"k"}"""))
        assertNull("publicKey absent", Utils.decodeEntry("""{"id":"x"}"""))
        assertNull("both absent", Utils.decodeEntry("""{"fields":{"a":{"value":"v"}}}"""))
        assertNull("explicit nulls", Utils.decodeEntry("""{"id":null,"publicKey":null}"""))
        assertNull("explicit null id", Utils.decodeEntry("""{"id":null,"publicKey":"k"}"""))
        assertNull("explicit null key", Utils.decodeEntry("""{"id":"x","publicKey":null}"""))

        // Positive controls. Without these the whole table passes against a decodeEntry that
        // returns null for everything, which is the mutant a file of assertNulls cannot see.
        assertNotNull("a real identity must survive", Utils.decodeEntry("""{"id":"x","publicKey":"k"}"""))
        assertNotNull(
            "one non-whitespace character is enough on either side",
            Utils.decodeEntry("""{"id":" x ","publicKey":" k "}"""),
        )
        assertEquals(
            "surrounding whitespace is kept, not trimmed — only all-blank is refused",
            " x ",
            Utils.decodeEntry("""{"id":" x ","publicKey":" k "}""")?.id,
        )
        assertNull(
            "Kotlin's isBlank also asks isSpaceChar, so U+00A0 alone is blank and is refused",
            Utils.decodeEntry("{\"id\":\"\u00A0\",\"publicKey\":\"\u00A0\"}"),
        )
        assertNotNull(
            "...but a non-breaking space *inside* a token leaves it non-blank and live",
            Utils.decodeEntry("{\"id\":\"a\u00A0b\",\"publicKey\":\"k\"}"),
        )
    }

    /**
     * The hole this closes: `Gson().fromJson("{}", Entry::class.java)` hands back an
     * object whose declared-non-null properties are null, and reading one NPEs. If this
     * ever stops throwing, the premise of [Utils.decodeEntry] has changed and it should be
     * revisited — but the repair must stay either way.
     */
    @Test
    fun `raw gson parsing of the same payload is the hazard being fixed`() {
        val raw = Gson().fromJson("{}", Entry::class.java)
        val threw = try {
            raw.id.length
            raw.publicKey.length
            raw.fields.size
            false
        } catch (_: NullPointerException) {
            true
        }
        assertTrue("raw Gson output should be unsafe to dereference", threw)
    }

    // ── Hostile input: fields payload ────────────────────────────────────

    @Test
    fun `a null field entry is dropped rather than yielding a null value`() {
        val decoded = Utils.decodeEntry(
            """{"id":"x","publicKey":"k","fields":{"good":{"value":"v","type":"String"},"bad":null}}"""
        )
        assertNotNull(decoded)
        assertEquals(setOf("good"), decoded!!.fields.keys)
        assertEquals("v", decoded.fields["good"]?.value)
    }

    @Test
    fun `fields missing a value or a type are repaired with safe defaults`() {
        val decoded = Utils.decodeEntry(
            """{"id":"x","publicKey":"k","fields":{"a":{"value":"v"},"b":{"type":"Email"},"c":{}}}"""
        )
        assertNotNull(decoded)
        assertEquals(FieldType.STRING, decoded!!.fields["a"]?.type)
        assertEquals("", decoded.fields["b"]?.value)
        assertEquals(FieldType.EMAIL, decoded.fields["b"]?.type)
        assertEquals("", decoded.fields["c"]?.value)
        assertEquals(FieldType.STRING, decoded.fields["c"]?.type)
    }

    @Test
    fun `a fields payload of the wrong shape decodes to null instead of throwing`() {
        assertNull(Utils.decodeEntry("""{"id":"x","publicKey":"k","fields":"not a map"}"""))
        assertNull(Utils.decodeEntry("""{"id":"x","publicKey":"k","fields":[1,2,3]}"""))
        assertNull(Utils.decodeEntry("""{"id":"x","publicKey":"k","fields":{"a":7}}"""))
        assertNull(Utils.decodeEntry("""{"id":"x","publicKey":"k","fields":{"a":{"value":{"x":1}}}}"""))
    }

    @Test
    fun `an explicitly null fields member decodes to an empty map`() {
        val decoded = Utils.decodeEntry("""{"id":"x","publicKey":"k","fields":null}""")
        assertNotNull(decoded)
        assertEquals(emptyMap<String, TypedField>(), decoded!!.fields)
    }

    /**
     * Gson insists on consuming the whole document, so a payload with a valid entry
     * followed by junk is rejected outright. Pinned so a future Gson upgrade cannot
     * quietly start accepting a prefix.
     */
    @Test
    fun `trailing garbage after a valid entry decodes to null`() {
        assertNull(Utils.decodeEntry("""{"id":"x","publicKey":"k"} and then some"""))
    }

    /**
     * The payoff: every property of a decoded hostile payload can be dereferenced without
     * the caller defending against a null the type system already promised was impossible.
     */
    @Test
    fun `every property of a decoded hostile payload is safe to dereference`() {
        val decoded = Utils.decodeEntry(
            """{"id":"x","publicKey":"k","fields":{"a":{"value":"v"},"b":{"type":"int"},"c":{},"d":null}}"""
        )
        assertNotNull(decoded)
        val entry = decoded!!
        assertTrue("id is readable", entry.id.length > 0)
        assertTrue("publicKey is readable", entry.publicKey.length > 0)
        assertEquals("the null field is dropped", 3, entry.fields.size)
        // Concrete expectations, not `field.value.length == field.value.length`: those
        // would go red today (dereferencing a null throws) but would silently stop
        // testing anything the day TypedField.value became nullable.
        assertEquals("v", entry.fields["a"]!!.value)
        assertEquals(FieldType.STRING, entry.fields["a"]!!.type)
        assertEquals("", entry.fields["b"]!!.value)
        assertEquals(FieldType.INTEGER, FieldType.normalize(entry.fields["b"]!!.type))
        assertEquals("", entry.fields["c"]!!.value)
        assertEquals(FieldType.STRING, entry.fields["c"]!!.type)
    }

    @Test
    fun `field order of a decoded payload follows the json`() {
        val decoded = Utils.decodeEntry(
            """{"id":"x","publicKey":"k","fields":{"c":{"value":"3"},"a":{"value":"1"},"b":{"value":"2"}}}"""
        )
        assertEquals(listOf("c", "a", "b"), decoded?.fields?.keys?.toList())
    }

    /**
     * Gson's string adapter coerces a JSON number or boolean to its text, so a hostile app
     * can hand over a non-string identity. Pinned rather than asserted to be right: the
     * result is a live entry with `id = "123"`, which is odd but harmless — every consumer
     * treats the id as an opaque string. If this ever needs to be rejected, this test is
     * where that decision gets recorded.
     */
    @Test
    fun `a numeric or boolean identity is coerced to its text form`() {
        val decoded = Utils.decodeEntry("""{"id":123,"publicKey":true}""")
        assertNotNull(decoded)
        assertEquals("123", decoded!!.id)
        assertEquals("true", decoded.publicKey)
    }

    // ── Negative controls: malformed input must degrade, never throw ─────

    @Test
    fun `malformed input decodes to null instead of throwing`() {
        assertNull(Utils.decodeEntry(null))
        assertNull(Utils.decodeEntry(""))
        assertNull(Utils.decodeEntry("   "))
        assertNull(Utils.decodeEntry("garbage"))
        assertNull(Utils.decodeEntry("null"))
        assertNull(Utils.decodeEntry("42"))
        assertNull(Utils.decodeEntry("[]"))
        assertNull(Utils.decodeEntry("""{"id":"x","publicKey":"""))
    }

    /**
     * Negative control for the round-trip tests: if [Utils.decodeEntry] returned a
     * constant, or ignored its argument, they would still pass. This one fails in that
     * world.
     */
    @Test
    fun `decoding actually reflects its input`() {
        val a = Utils.decodeEntry("""{"id":"one","publicKey":"k"}""")
        val b = Utils.decodeEntry("""{"id":"two","publicKey":"k"}""")
        assertNotEquals("decodeEntry must depend on its input", a, b)
        assertEquals("one", a?.id)
    }
}
