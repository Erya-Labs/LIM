package dev.eryalabs.lim

import android.content.Context
import android.content.Intent
import android.os.BadParcelableException
import android.os.Bundle
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
 * [Utils.parseFieldRequirements], the vault's reading of a sign-up's declaration — and the strict
 * decoder behind it, which is what every hostile shape below actually meets.
 *
 * Two properties carry the file. **A declaration that cannot be read means every field is
 * required**: absent, blank, the wrong extra type, an unreadable bundle and every malformed
 * spelling all land on the same answer, and none of them refuses the share or throws. And **the
 * reader is null exactly when [Utils.parseShareRequest] is**, because it is answered from that
 * parse: designed cases here, and the same property over three thousand payloads nobody designed
 * in `DecoderFuzzTest`, which owns that corpus.
 *
 * Robolectric is required: [Intent] extras are unimplemented stubs in a plain JVM unit test.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class FieldRequirementsParsingTest {

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

    private val declared = listOf("name", "email", "phone")

    /** The vault the optional-fields overload is addressed to: it has no default, by design. */
    private val vault = Utils.DEFAULT_ENDEAVOR_PACKAGE

    /** A request as a 1.0.0 client builds it — no declaration — with [marker] added by hand. */
    private fun requestWith(marker: Intent.() -> Unit): Intent =
        Utils.createShareIntent(context, entry, requestCode = "req-1").apply(marker)

    /**
     * A share request whose declaration alone cannot be read: the entry and every other extra read
     * normally, and reading [Utils.EXTRA_OPTIONAL_FIELDS] throws the way unparcelling a bundle that
     * names a class this process lacks does.
     */
    private class UnreadableDeclaration(base: Intent) : Intent(base) {
        override fun getStringExtra(name: String?): String? {
            if (name == Utils.EXTRA_OPTIONAL_FIELDS) {
                throw BadParcelableException("extras reference an unknown class")
            }
            return super.getStringExtra(name)
        }
    }

    @Test
    fun `a declaration from the builder is read back in entry order`() {
        val request = Utils.createShareIntent(context, entry, "req-1", linkedSetOf("phone", "name"), vault)
        val requirements = Utils.parseFieldRequirements(request)

        assertNotNull(requirements)
        assertEquals(declared, requirements!!.fieldNames)
        assertEquals(listOf("name", "phone"), requirements.optionalFields.toList())
        assertEquals(setOf("email"), requirements.requiredFields)
        assertEquals(
            "and the requirements equal the client's own, so the two sides agree by construction",
            FieldRequirements(entry.fields.keys, setOf("phone", "name")),
            requirements,
        )
    }

    /**
     * Every shape the design lists as "nothing is optional". Each must still be a share the vault
     * can answer — the declaration never refuses the request — and each must make every declared
     * field required.
     */
    @Test
    fun `every declaration that cannot be read means every field is required`() {
        val stringArrayList = arrayListOf("phone")
        val shapes: Map<String, Intent> = mapOf(
            "absent" to requestWith { },
            "blank" to requestWith { putExtra(Utils.EXTRA_OPTIONAL_FIELDS, "   ") },
            "an Int extra" to requestWith { putExtra(Utils.EXTRA_OPTIONAL_FIELDS, 7) },
            "a String[] extra" to requestWith { putExtra(Utils.EXTRA_OPTIONAL_FIELDS, arrayOf("phone")) },
            "a String ArrayList extra" to requestWith {
                putStringArrayListExtra(Utils.EXTRA_OPTIONAL_FIELDS, stringArrayList)
            },
            "a Bundle extra" to requestWith {
                putExtra(Utils.EXTRA_OPTIONAL_FIELDS, Bundle().apply { putString("0", "phone") })
            },
            "an unreadable bundle" to UnreadableDeclaration(
                requestWith { putExtra(Utils.EXTRA_OPTIONAL_FIELDS, """["phone"]""") },
            ),
            "[]" to marker("[]"),
            "a number among the names" to marker("""["phone",1]"""),
            "a null element" to marker("[null]"),
            "an object" to marker("{}"),
            "a bare string" to marker("\"phone\""),
            "a nested array" to marker("""[["phone"]]"""),
            "trailing content" to marker("""["phone"] x"""),
            "a second document" to marker("""["phone"]["name"]"""),
            "single quotes" to marker("['phone']"),
            "an unquoted name" to marker("[phone]"),
            "a trailing comma" to marker("""["phone",]"""),
            "a block comment" to marker("""["phone"] /* c */"""),
            "a line comment" to marker("""["phone"] // c"""),
            "unterminated" to marker("""["phone""""),
            "an invalid escape" to marker("""["ph\'one"]"""),
        )

        shapes.forEach { (shape, request) ->
            assertNotNull("$shape must not refuse the share", Utils.parseShareRequest(request))
            val requirements = Utils.parseFieldRequirements(request)
            assertNotNull("$shape must still be read as a share's requirements", requirements)
            assertEquals("$shape: the entry's own names", declared, requirements!!.fieldNames)
            assertEquals(
                "$shape must mean nothing is optional — every field required",
                declared.toSet(),
                requirements.requiredFields,
            )
        }

        // Control: the same request with the canonical spelling is read, so the refusals above are
        // the decoder's and not a reader that answers "nothing" for everything.
        assertEquals(setOf("phone"), Utils.parseFieldRequirements(marker("""["phone"]"""))!!.optionalFields)
    }

    private fun marker(value: String): Intent =
        requestWith { putExtra(Utils.EXTRA_OPTIONAL_FIELDS, value) }

    /**
     * Depth costs nothing and size is bounded only by the input: a nested opener is refused at the
     * first element, before any recursion could begin, and a megabyte of names is read as a stream.
     */
    @Test
    fun `a deeply nested and a megabyte declaration are read without throwing`() {
        val deep = Utils.parseFieldRequirements(marker("[".repeat(10_000) + "]".repeat(10_000)))
        assertEquals(declared.toSet(), deep!!.requiredFields)

        val big = buildString {
            append('[')
            while (length < 1_000_000) append("\"phone\",")
            append("\"name\"]")
        }
        val read = Utils.parseFieldRequirements(marker(big))
        assertEquals(
            "a megabyte of duplicated names collapses to the entry's own names",
            listOf("name", "phone"),
            read!!.optionalFields.toList(),
        )
    }

    /**
     * The spellings that tell `Strictness.STRICT` from Gson's default, `LEGACY_STRICT`: the `\'`
     * escape, a backslash before a raw line feed, and a raw control character. The entry here
     * declares a field by each name those spellings would decode to, so a reader that accepted one
     * would make that field optional — a refusal and an acceptance cannot look alike, as they do
     * when the decoded name is not a field and is dropped either way. The control reads the same
     * three names in valid JSON, so the refusals are of the spelling and not of the name.
     */
    @Test
    fun `a spelling only a lenient reader accepts is refused, even when it would name a real field`() {
        val names = listOf("ph'one", "ph\none", "ph" + 0x0001.toChar() + "one")
        val awkward = Entry("signup-form", names.associateWithTo(LinkedHashMap()) { TypedField("") }, "k")
        fun declaring(marker: String) = Utils.createShareIntent(context, awkward, requestCode = "req-1")
            .apply { putExtra(Utils.EXTRA_OPTIONAL_FIELDS, marker) }

        // Assembled rather than typed, the file's habit for escapes: a backslash is "\\".
        val lenientOnly = listOf(
            "[\"ph" + "\\" + "'one\"]",
            "[\"ph" + "\\" + "\n" + "one\"]",
            "[\"ph" + 0x0001.toChar() + "one\"]",
        )
        assertEquals("the first fixture really is the \' escape", 11, lenientOnly[0].length)
        lenientOnly.forEachIndexed { index, marker ->
            val requirements = Utils.parseFieldRequirements(declaring(marker))
            assertEquals("spelling #$index: the entry's own names", names, requirements!!.fieldNames)
            assertTrue("spelling #$index must not be read: nothing is optional", requirements.optionalFields.isEmpty())
        }

        val valid = listOf(
            "[\"ph'one\"]",
            "[\"ph" + "\\" + "none\"]",
            "[\"ph" + "\\" + "u0001one\"]",
        )
        valid.forEachIndexed { index, marker ->
            assertEquals(
                "control #$index: the same name in valid JSON is read",
                setOf(names[index]),
                Utils.parseFieldRequirements(declaring(marker))!!.optionalFields,
            )
        }
    }

    @Test
    fun `names the entry does not declare are dropped, duplicates collapse and the order is the entry's`() {
        val requirements = Utils.parseFieldRequirements(marker("""["stray","phone","name","phone"]"""))

        assertEquals(listOf("name", "phone"), requirements!!.optionalFields.toList())
        assertEquals(setOf("email"), requirements.requiredFields)
    }

    @Test
    fun `matching is exact, and a valid escape reads like the canonical spelling`() {
        assertTrue(
            "neither a case variant nor an untrimmed name matches",
            Utils.parseFieldRequirements(marker("""["Phone"," phone","phone "]"""))!!.optionalFields.isEmpty(),
        )
        // `p` spelled as a JSON unicode escape, assembled rather than typed so that no tool between
        // here and the compiler can turn the escape back into the letter it names.
        val escaped = "[\"" + "\\" + "u0070hone\"]"
        assertEquals("the fixture really is an escape", 14, escaped.length)
        assertEquals(
            "any valid JSON spelling of a name is read; nothing depends on the canonical form",
            setOf("phone"),
            Utils.parseFieldRequirements(marker(escaped))!!.optionalFields,
        )
    }

    /** Parity with [Utils.parseShareRequest], which keeps a blank field name; refusing it is vault policy. */
    @Test
    fun `a blank field name is kept, as the share parser keeps it`() {
        val blankNamed = Entry("signup-form", linkedMapOf("" to TypedField(""), "name" to TypedField("")), "k")
        val request = Utils.createShareIntent(context, blankNamed, "req-1", setOf(""), vault)

        val requirements = Utils.parseFieldRequirements(request)

        assertEquals(listOf("", "name"), requirements!!.fieldNames)
        assertEquals(setOf(""), requirements.optionalFields)
    }

    /** The declaration never changes what the share parser says, and never reaches another flow. */
    @Test
    fun `the share request is the same with and without a declaration, and other flows ignore it`() {
        val plain = Utils.createShareIntent(context, entry, requestCode = "req-1")
        val declaring = Utils.createShareIntent(context, entry, "req-1", setOf("phone"), vault)
        assertEquals(Utils.parseShareRequest(plain), Utils.parseShareRequest(declaring))

        val query = Utils.createQueryIntent(context, "PUBLIC-KEY-BASE64", "req-2")
        val queryWithMarker = Utils.createQueryIntent(context, "PUBLIC-KEY-BASE64", "req-2").apply {
            putExtra(Utils.EXTRA_OPTIONAL_FIELDS, """["phone"]""")
        }
        assertEquals(Utils.parseQueryRequest(query), Utils.parseQueryRequest(queryWithMarker))
        assertNull("a query is not a share, so it declares no requirements", Utils.parseFieldRequirements(queryWithMarker))

        val nonce = Utils.generateNonce(now = 1_770_000_000_000L)
        val sign = Utils.createSignChallengeIntent(context, "PUBLIC-KEY-BASE64", nonce, "req-3")
        val signWithMarker = Utils.createSignChallengeIntent(context, "PUBLIC-KEY-BASE64", nonce, "req-3")
            .apply { putExtra(Utils.EXTRA_OPTIONAL_FIELDS, """["phone"]""") }
        assertEquals(Utils.parseSignChallengeRequest(sign), Utils.parseSignChallengeRequest(signWithMarker))
        assertNull(Utils.parseFieldRequirements(signWithMarker))
    }

    /**
     * Null exactly when the share parser is — the designed half. Each case is a reason
     * [Utils.parseShareRequest] refuses, and each carries a perfectly good declaration beside it,
     * so the refusal cannot be coming from the declaration.
     */
    @Test
    fun `the reader is null exactly when the share parser is`() {
        fun withDeclaration(entryJson: String?) = Intent().apply {
            if (entryJson != null) putExtra(Utils.EXTRA_ENTRY_JSON, entryJson)
            putExtra(Utils.EXTRA_OPTIONAL_FIELDS, """["phone"]""")
        }
        val cases: List<Intent?> = listOf(
            null,
            withDeclaration(null),
            withDeclaration(""),
            withDeclaration("not json"),
            withDeclaration("""{"id":"","publicKey":"k"}"""),
            withDeclaration("""{"id":"x","publicKey":"   "}"""),
            withDeclaration("""{"id":"x","publicKey":"k","fields":[]}"""),
            UnreadableIntent(),
            // …and the accepted shapes, so the property is about both answers.
            withDeclaration("""{"id":"x","publicKey":"k"}"""),
            withDeclaration("""{"id":"x","publicKey":"k","fields":{"phone":{"value":"","type":"Phone"}}}"""),
        )

        cases.forEachIndexed { index, intent ->
            assertEquals(
                "case #$index: parseFieldRequirements must be null exactly when parseShareRequest is",
                Utils.parseShareRequest(intent) == null,
                Utils.parseFieldRequirements(intent) == null,
            )
        }
        assertEquals(
            "both answers must occur, or the property is about one of them",
            setOf(true, false),
            cases.map { Utils.parseShareRequest(it) == null }.toSet(),
        )
        assertEquals(
            "an entry with no fields declares nothing to require",
            emptyList<String>(),
            Utils.parseFieldRequirements(cases[8])!!.fieldNames,
        )
        assertEquals(setOf("phone"), Utils.parseFieldRequirements(cases[9])!!.optionalFields)
    }

    /** Every read throws: the shape `ResultParsingTest` and `RequestParsingTest` use. */
    private class UnreadableIntent : Intent() {
        override fun getStringExtra(name: String?): String? =
            throw BadParcelableException("extras reference an unknown class")
    }
}
