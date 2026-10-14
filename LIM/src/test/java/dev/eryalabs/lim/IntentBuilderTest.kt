package dev.eryalabs.lim

import android.content.Intent
import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import com.google.gson.Gson
import com.google.gson.JsonParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * The intents are the protocol. Action strings and extra keys are matched literally by the
 * vault's manifest and its intent handlers, so a typo here is a silent no-op in production —
 * the intent simply resolves to nothing. Every wire constant is pinned to a literal below,
 * deliberately not to the `Utils` constant, so that renaming a constant cannot quietly
 * rename the wire format.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class IntentBuilderTest {

    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()
    private val vault = Utils.DEFAULT_ENDEAVOR_PACKAGE

    private val entry = Entry(
        id = "profile-1",
        fields = linkedMapOf(
            "name" to TypedField("Ada", FieldType.STRING),
            "age" to TypedField("36", FieldType.INTEGER),
        ),
        publicKey = "PUBLIC-KEY-BASE64",
    )

    // ── Action strings ───────────────────────────────────────────────────

    @Test
    fun `action strings are scoped to the target package`() {
        assertEquals(
            "com.github.adaydreamaway.endeavor.ACTION_SHARE_DATA",
            Utils.shareDataAction(),
        )
        assertEquals(
            "com.github.adaydreamaway.endeavor.ACTION_SIGN_CHALLENGE",
            Utils.signChallengeAction(),
        )
        assertEquals("dev.other.vault.ACTION_SHARE_DATA", Utils.shareDataAction("dev.other.vault"))
        assertEquals(
            "dev.other.vault.ACTION_SIGN_CHALLENGE",
            Utils.signChallengeAction("dev.other.vault"),
        )
    }

    @Test
    fun `the default vault package is Endeavor`() {
        assertEquals("com.github.adaydreamaway.endeavor", Utils.DEFAULT_ENDEAVOR_PACKAGE)
    }

    // ── Share ────────────────────────────────────────────────────────────

    @Test
    fun `share intent targets the vault and carries the entry as JSON`() {
        val intent = Utils.createShareIntent(context, entry)

        assertEquals("com.github.adaydreamaway.endeavor.ACTION_SHARE_DATA", intent.action)
        assertEquals(vault, intent.`package`)

        val json = intent.getStringExtra("extra_entry_json")
        val decoded = Gson().fromJson(json, Entry::class.java)
        assertEquals(entry.id, decoded.id)
        assertEquals(entry.publicKey, decoded.publicKey)
        assertEquals("Ada", decoded.fields["name"]?.value)
        assertEquals(FieldType.INTEGER, decoded.fields["age"]?.type)
    }

    /**
     * **The encoded payload, as an exact literal — the encode-side wire format.**
     *
     * The test above reads `extra_entry_json` and hands it straight back to
     * `Gson().fromJson(json, Entry::class.java)`. That is a round trip through the same class and
     * so it is **name-blind by construction**: rename a property and both halves move together
     * with every assertion still green. `EntryCodecTest`'s literals pin the names on the decode
     * side, against the library a unit test loads — not against the bytes a consumer's app puts on
     * the wire. So until this assertion existed, `"id"`, `"fields"`, `"publicKey"`, `"value"` and
     * `"type"` appeared in no encoder, no constant and no pinned encoded string anywhere in this
     * repository, and this is the file STOP RULE 10 calls the wire format.
     *
     * Three things are pinned here that nothing else pins, and all three are protocol:
     *
     *  - **The five key spellings**, on the side that writes them.
     *  - **Property declaration order.** Gson writes fields in declaration order, so the order of
     *    `Entry`'s and `TypedField`'s properties is part of the encoded payload. Reordering them
     *    is a source-level edit that looks like tidying and moves the bytes.
     *  - **Field insertion order**, which `linkedMapOf` fixes and [Utils.encodeFields] promises.
     *
     * It is deliberately an equality against one string rather than a parse-and-check: a parse
     * would re-admit the blindness the round-trip test has.
     */
    @Test
    fun `the encoded share payload is exactly this JSON`() {
        val json = Utils.createShareIntent(context, entry).getStringExtra("extra_entry_json")
        println("encoded EXTRA_ENTRY_JSON: $json")
        assertEquals(
            """{"id":"profile-1","fields":{"name":{"value":"Ada","type":"String"},""" +
                """"age":{"value":"36","type":"Integer"}},"publicKey":"PUBLIC-KEY-BASE64"}""",
            json,
        )
    }

    /**
     * Pins the reasoning in [Utils.createShareIntent]'s comment: CLEAR_TOP delivers to an
     * existing vault instance via onNewIntent, while NEW_TASK would put the vault in a
     * separate task and silently break `startActivityForResult` delivery. Adding NEW_TASK
     * here would be an easy, plausible, and completely invisible regression.
     */
    @Test
    fun `share intent sets CLEAR_TOP but not NEW_TASK`() {
        val flags = Utils.createShareIntent(context, entry).flags
        assertTrue("CLEAR_TOP must be set", flags and Intent.FLAG_ACTIVITY_CLEAR_TOP != 0)
        assertFalse(
            "NEW_TASK must NOT be set — it breaks result delivery",
            flags and Intent.FLAG_ACTIVITY_NEW_TASK != 0,
        )
    }

    @Test
    fun `share intent omits the request code unless one is given`() {
        assertNull(Utils.createShareIntent(context, entry).getStringExtra("extra_share_request_code"))
    }

    @Test
    fun `share intent echoes the request code when given`() {
        val intent = Utils.createShareIntent(context, entry, requestCode = "req-42")
        assertEquals("req-42", intent.getStringExtra("extra_share_request_code"))
        assertEquals("com.github.adaydreamaway.endeavor.ACTION_SHARE_DATA", intent.action)
    }

    // ── Query ────────────────────────────────────────────────────────────

    @Test
    fun `query intent reuses the share action and carries the public key`() {
        val intent = Utils.createQueryIntent(context, "PUBLIC-KEY-BASE64", "req-7")

        assertEquals("com.github.adaydreamaway.endeavor.ACTION_SHARE_DATA", intent.action)
        assertEquals(vault, intent.`package`)
        assertEquals("PUBLIC-KEY-BASE64", intent.getStringExtra("extra_public_key"))
        assertEquals("req-7", intent.getStringExtra("extra_share_request_code"))
        assertNull(
            "a query carries no entry payload",
            intent.getStringExtra("extra_entry_json"),
        )
    }

    // ── Sign challenge ───────────────────────────────────────────────────

    @Test
    fun `sign challenge intent carries key, nonce and request code`() {
        val nonce = byteArrayOf(1, 2, 3, 4, 5)
        val intent = Utils.createSignChallengeIntent(context, "PUBLIC-KEY-BASE64", nonce, "req-9")

        assertEquals("com.github.adaydreamaway.endeavor.ACTION_SIGN_CHALLENGE", intent.action)
        assertEquals(vault, intent.`package`)
        assertEquals("PUBLIC-KEY-BASE64", intent.getStringExtra("extra_public_key"))
        assertEquals("req-9", intent.getStringExtra("extra_share_request_code"))

        val roundTripped = Base64.decode(intent.getStringExtra("extra_nonce"), Base64.DEFAULT)
        assertTrue("nonce must survive base64 intact", nonce.contentEquals(roundTripped))
    }

    /**
     * A long nonce is the realistic case (32 random bytes plus a timestamp). `NO_WRAP` is
     * what keeps the encoding free of newlines; DEFAULT would wrap at 76 characters and hand
     * the vault a value that naive parsers split on.
     */
    @Test
    fun `a long nonce is encoded without line breaks`() {
        val nonce = ByteArray(64) { it.toByte() }
        val intent = Utils.createSignChallengeIntent(context, "PUBLIC-KEY-BASE64", nonce, "req-10")
        val encoded = intent.getStringExtra("extra_nonce")!!

        assertFalse("nonce encoding must not wrap", encoded.contains("\n"))
        assertTrue(nonce.contentEquals(Base64.decode(encoded, Base64.DEFAULT)))
    }

    /**
     * The nonce is generated on this side, Base64'd onto the wire, and its freshness is read
     * back out of the same bytes. A wrapping or padding slip anywhere along that path would
     * corrupt the timestamp and expire every challenge instantly, so the whole path is
     * walked once here rather than trusting the two halves in isolation.
     */
    @Test
    fun `a generated nonce survives the intent and is still fresh`() {
        val clock = 1_770_000_000_000L
        val nonce = Utils.generateNonce(now = clock)
        val intent = Utils.createSignChallengeIntent(context, "PUBLIC-KEY-BASE64", nonce, "req-11")

        val roundTripped = Base64.decode(intent.getStringExtra("extra_nonce"), Base64.DEFAULT)
        assertTrue(nonce.contentEquals(roundTripped))
        assertTrue(Utils.isNonceFresh(roundTripped, 60_000, now = clock + 30_000))
        assertFalse(Utils.isNonceFresh(roundTripped, 60_000, now = clock + 60_001))
    }

    @Test
    fun `intents can be aimed at a vault other than Endeavor`() {
        val other = "dev.eryalabs.othervault"
        val share = Utils.createShareIntent(context, entry, targetPackage = other)
        val query = Utils.createQueryIntent(context, "K", "r", targetPackage = other)
        val sign = Utils.createSignChallengeIntent(context, "K", byteArrayOf(1), "r", targetPackage = other)

        listOf(share, query, sign).forEach { assertEquals(other, it.`package`) }
        assertEquals("$other.ACTION_SHARE_DATA", share.action)
        assertEquals("$other.ACTION_SHARE_DATA", query.action)
        assertEquals("$other.ACTION_SIGN_CHALLENGE", sign.action)
    }

    // ── Extra-key constants are wire format ──────────────────────────────

    @Test
    fun `extra keys match the literals the vault reads`() {
        assertEquals("extra_entry_json", Utils.EXTRA_ENTRY_JSON)
        assertEquals("extra_share_request_code", Utils.EXTRA_SHARE_REQUEST_CODE)
        assertEquals("extra_query_result_fields", Utils.EXTRA_QUERY_RESULT_FIELDS)
        assertEquals("extra_public_key", Utils.EXTRA_PUBLIC_KEY)
        assertEquals("extra_nonce", Utils.EXTRA_NONCE)
        assertEquals("extra_signature", Utils.EXTRA_SIGNATURE)
        assertEquals("extra_algorithm", Utils.EXTRA_ALGORITHM)
        assertEquals("extra_fields_json", Utils.EXTRA_FIELDS_JSON)
    }

    // ── Required and optional fields ─────────────────────────────────────

    /**
     * The two keys required fields added, pinned the way the ten before them are. Two keys and not
     * one, on purpose: the acknowledgement must not be the request's key, or a vault answering
     * with the incoming intent would echo a "yes" it never said.
     */
    @Test
    fun `the required-fields extra keys match their wire literals`() {
        assertEquals("extra_optional_fields", Utils.EXTRA_OPTIONAL_FIELDS)
        assertEquals("extra_applied_optional_fields", Utils.EXTRA_APPLIED_OPTIONAL_FIELDS)
    }

    private val signUp = Entry(
        id = "signup-form",
        fields = linkedMapOf(
            "name" to TypedField("", FieldType.STRING),
            "phone" to TypedField("", FieldType.PHONE),
            "nickname" to TypedField("", FieldType.STRING),
        ),
        publicKey = "no-key-yet",
    )

    @Test
    fun `the optional names are written in entry order, without strays or duplicates`() {
        val intent = Utils.createShareIntent(context, signUp, "r", linkedSetOf("nickname", "phone", "stray"), vault)

        assertEquals("""["phone","nickname"]""", intent.getStringExtra("extra_optional_fields"))
    }

    @Test
    fun `an empty optional set is written as an empty array`() {
        val intent = Utils.createShareIntent(context, signUp, "r", emptySet(), vault)

        assertEquals("[]", intent.getStringExtra("extra_optional_fields"))
        assertEquals(
            "…and so is a set naming no field of the entry",
            "[]",
            Utils.createShareIntent(context, signUp, "r", setOf("stray"), vault).getStringExtra("extra_optional_fields"),
        )
    }

    /**
     * Escaped exactly as `Gson().toJson(list)` escapes it — the entry payload's own HTML-safe
     * escaping — and read back by the vault as the name that was meant. The comparison is against
     * Gson itself rather than a literal, because "the same escaping as the entry payload" is the
     * claim.
     */
    @Test
    fun `a name needing escaping is written as Gson writes it and read back as itself`() {
        val awkward = "a<b>&'=\"\\" + 0x2028.toChar() + 0x0000.toChar() + "é"
        val entry = Entry("signup-form", linkedMapOf(awkward to TypedField(""), "plain" to TypedField("")), "k")

        val intent = Utils.createShareIntent(context, entry, "r", setOf(awkward), vault)

        val encoded = intent.getStringExtra("extra_optional_fields")!!
        assertEquals(Gson().toJson(listOf(awkward)), encoded)
        // The same claim stated without Gson on the right-hand side, so a Gson that stopped
        // escaping could not take this builder with it: none of these reaches the wire raw.
        // Spelled by code point, the file's own habit for characters a source file mangles:
        // `<`, `>`, `&`, the apostrophe, `=`, U+2028 and NUL.
        val escapedOnTheWire = listOf(0x3C, 0x3E, 0x26, 0x27, 0x3D, 0x2028, 0x0000).map { it.toChar() }
        escapedOnTheWire.forEach { raw ->
            assertFalse("U+%04X must be escaped on the wire: $encoded".format(raw.code), raw in encoded)
        }
        assertTrue("the non-ASCII letter itself needs no escape", "é" in encoded)
        assertEquals(setOf(awkward), Utils.parseFieldRequirements(intent)?.optionalFields)
    }

    /**
     * The negative control: apart from the one new key, the intent is the 1.0.0 request-code
     * overload's, byte for byte — action, package, flags and every other extra and its value.
     */
    @Test
    fun `apart from the one new key, the optional-fields intent is the request-code intent`() {
        val plain = Utils.createShareIntent(context, signUp, requestCode = "r")
        val declaring = Utils.createShareIntent(context, signUp, "r", setOf("phone"), vault)
        val elsewhere = Utils.createShareIntent(context, signUp, "r", setOf("phone"), "dev.other.vault")
        val plainElsewhere = Utils.createShareIntent(context, signUp, "r", "dev.other.vault")

        for ((expected, actual) in listOf(plain to declaring, plainElsewhere to elsewhere)) {
            assertEquals(expected.action, actual.action)
            assertEquals(expected.`package`, actual.`package`)
            assertEquals(expected.flags, actual.flags)
            assertEquals(
                expected.extras!!.keySet() + "extra_optional_fields",
                actual.extras!!.keySet(),
            )
            expected.extras!!.keySet().forEach { key ->
                assertEquals("extra $key", expected.getStringExtra(key), actual.getStringExtra(key))
            }
        }
        assertEquals("dev.other.vault.ACTION_SHARE_DATA", elsewhere.action)
    }

    /**
     * An [Entry] Gson built with no `fields` at all — the `Unsafe` hazard `Utils.decodeEntry`
     * documents, here on the way *out*. The 1.0.0 overload this one wraps encodes it without
     * complaint, so this one must too: no throw, nothing declared, and the rest of the intent the
     * request-code overload's.
     */
    @Test
    fun `an entry with no fields map declares nothing and does not throw`() {
        val hollow = Gson().fromJson("""{"id":"x","publicKey":"k"}""", Entry::class.java)
        @Suppress("SENSELESS_COMPARISON")
        assertTrue("the fixture really has a null fields map", hollow.fields == null)

        val plain = Utils.createShareIntent(context, hollow, "r", vault)
        val declaring = Utils.createShareIntent(context, hollow, "r", setOf("a", "b"), vault)

        assertEquals("[]", declaring.getStringExtra("extra_optional_fields"))
        assertEquals(plain.action, declaring.action)
        assertEquals(plain.`package`, declaring.`package`)
        assertEquals(plain.extras!!.keySet() + "extra_optional_fields", declaring.extras!!.keySet())
        plain.extras!!.keySet().forEach { key ->
            assertEquals("extra $key", plain.getStringExtra(key), declaring.getStringExtra(key))
        }
    }

    /**
     * A field whose [TypedField] is `null` — Java, or a template Gson built from `"nick": null` —
     * is not encoded, because Gson drops a `null` map value. So the vault never sees it, and the
     * declaration does not name it either: every name on the wire is a field of the entry on the
     * wire, which is what [Utils.EXTRA_OPTIONAL_FIELDS] promises.
     */
    @Suppress("UNCHECKED_CAST")
    @Test
    fun `a field whose value is null is neither encoded nor declared`() {
        val withNull = Entry(
            id = "signup-form",
            fields = linkedMapOf<String, TypedField?>(
                "name" to TypedField("", FieldType.STRING),
                "nick" to null,
                "phone" to TypedField("", FieldType.PHONE),
            ) as Map<String, TypedField>,
            publicKey = "no-key-yet",
        )

        val intent = Utils.createShareIntent(context, withNull, "r", setOf("nick", "phone"), vault)

        val wireFields = JsonParser.parseString(intent.getStringExtra("extra_entry_json"))
            .asJsonObject.getAsJsonObject("fields")
        assertEquals("the null-valued field is not on the wire", setOf("name", "phone"), wireFields.keySet())
        assertEquals("""["phone"]""", intent.getStringExtra("extra_optional_fields"))
        val read = Utils.parseFieldRequirements(intent)!!
        assertEquals(listOf("name", "phone"), read.fieldNames)
        assertEquals(setOf("phone"), read.optionalFields)
    }
}
