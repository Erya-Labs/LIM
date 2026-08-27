package dev.eryalabs.lim

import android.util.Base64
import com.google.gson.Gson
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

/**
 * A data class prints every property verbatim from its generated `toString()`, so before this
 * was overridden a single `Log.d("entry: $entry")` in any client app wrote the user's name,
 * email and date of birth into logcat — and from there into every bug report, crash reporter
 * and attached debugger that captured it. For a library whose whole promise is that personal
 * data does not leave the device, that is the leak that matters most, and it is the kind that
 * is only discovered after it has already happened.
 *
 * Every test here puts a distinctive sentinel in the values and asserts it appears *nowhere*
 * in the rendering, while the keys and declared types still do — a redaction that returned a
 * constant would pass the first half and fail the second.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ToStringRedactionTest {

    companion object {
        /** The string that must never appear in any rendering. */
        private const val SENTINEL = "SECRET_SENTINEL_9f3a"

        private lateinit var keyPair: KeyPair
        private lateinit var otherKeyPair: KeyPair

        /** 2048-bit RSA generation is slow (~100ms each); do it once for the whole class. */
        @JvmStatic
        @BeforeClass
        fun generateKeys() {
            val gen = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }
            keyPair = gen.generateKeyPair()
            otherKeyPair = gen.generateKeyPair()
        }

        private fun publicKeyOf(kp: KeyPair): String =
            Base64.encodeToString(kp.public.encoded, Base64.NO_WRAP)
    }

    /** Every value carries the sentinel; no key and no type does. */
    private val personal = linkedMapOf(
        "name" to TypedField("Ada $SENTINEL Lovelace", FieldType.STRING),
        "email" to TypedField("$SENTINEL@example.com", FieldType.EMAIL),
        "dob" to TypedField("1815-12-10 $SENTINEL", FieldType.DATE),
    )

    private val entry = Entry(
        id = "profile-$SENTINEL",
        fields = personal,
        publicKey = "MIIBIjANBgkq-not-a-real-key",
    )

    // ── The leak itself ──────────────────────────────────────────────────

    @Test
    fun `typed field toString does not print its value`() {
        val rendered = TypedField("$SENTINEL name", FieldType.STRING).toString()
        assertFalse("TypedField.toString leaked its value: $rendered", rendered.contains(SENTINEL))
    }

    /**
     * The nested map is where a naive override leaks: interpolating `fields` renders each
     * [TypedField] through *its* `toString()`, so redacting [Entry] alone would look right and
     * still print every value in the profile.
     */
    @Test
    fun `entry toString does not print any field value, including through the nested map`() {
        val rendered = entry.toString()
        assertFalse("Entry.toString leaked a field value: $rendered", rendered.contains(SENTINEL))
    }

    @Test
    fun `entry toString does not print the id`() {
        // The id is chosen by the client app and is as likely to be an email address as an
        // opaque token, so it is redacted like a value rather than previewed like a key.
        val rendered = entry.toString()
        assertFalse("Entry.toString leaked the id: $rendered", rendered.contains(SENTINEL))
        assertTrue(rendered.contains("id=<${entry.id.length} chars>"))
    }

    /**
     * The sentinel must not survive anywhere in the rendering — not in a suffix, not
     * lower-cased, not in a partial. A crude check, deliberately: it is what a grep of a real
     * logcat capture would do.
     */
    @Test
    fun `no fragment of a value survives in the rendering`() {
        val rendered = entry.toString()
        listOf("Ada", "Lovelace", "example.com", "1815-12-10", SENTINEL.lowercase())
            .forEach { fragment ->
                assertFalse("leaked $fragment: $rendered", rendered.contains(fragment, true))
            }
    }

    // ── ...but the rendering is still useful ─────────────────────────────

    @Test
    fun `entry toString names every field key`() {
        val rendered = entry.toString()
        personal.keys.forEach {
            assertTrue("key $it is missing from $rendered", rendered.contains(it))
        }
    }

    @Test
    fun `entry toString names every declared type`() {
        val rendered = entry.toString()
        listOf(FieldType.STRING, FieldType.EMAIL, FieldType.DATE).forEach {
            assertTrue("type $it is missing from $rendered", rendered.contains(it))
        }
    }

    @Test
    fun `a value is rendered as its length`() {
        assertEquals(
            "TypedField(type=Email, value=<11 chars>)",
            TypedField("12345678901", FieldType.EMAIL).toString(),
        )
        assertEquals(
            "TypedField(type=String, value=<0 chars>)",
            TypedField("").toString(),
        )
    }

    /**
     * Negative control for every "does not contain the sentinel" assertion above: a
     * `toString()` that returned a constant, or ignored the object entirely, would satisfy all
     * of them. Two entries that differ only in their field shape must render differently.
     */
    @Test
    fun `the rendering still depends on the entry`() {
        val a = Entry("id-1", mapOf("email" to TypedField("a@b.com", FieldType.EMAIL)), "key-1")
        val b = Entry("id-1", mapOf("phone" to TypedField("0123456", FieldType.PHONE)), "key-1")
        val c = Entry("id-1", mapOf("email" to TypedField("longer@b.com", FieldType.EMAIL)), "key-1")
        assertNotEquals("different keys and types must render differently", a.toString(), b.toString())
        assertNotEquals("different value lengths must render differently", a.toString(), c.toString())
    }

    // ── The public key: truncated, not hidden ────────────────────────────

    @Test
    fun `a short public key is printed whole`() {
        val short = "MIIBIjANBgkq"
        assertTrue(Entry("id", emptyMap(), short).toString().contains("publicKey=$short"))
    }

    /** The `<=` boundary: a key of exactly the preview length is short, one longer is not. */
    @Test
    fun `the truncation boundary is inclusive`() {
        val exact = "k".repeat(PUBLIC_KEY_PREVIEW_CHARS)
        assertEquals(exact, previewedPublicKey(exact))
        val oneLonger = "k".repeat(PUBLIC_KEY_PREVIEW_CHARS + 1)
        assertEquals(
            exact + "…(${PUBLIC_KEY_PREVIEW_CHARS + 1} chars)",
            previewedPublicKey(oneLonger),
        )
    }

    @Test
    fun `a full-length public key is truncated with its length`() {
        val key = publicKeyOf(keyPair)
        val rendered = Entry("id", emptyMap(), key).toString()
        assertFalse("the whole key should not be printed: $rendered", rendered.contains(key))
        assertTrue(rendered.contains("publicKey=${key.take(PUBLIC_KEY_PREVIEW_CHARS)}"))
        assertTrue("the full length should still be reported: $rendered",
            rendered.contains("(${key.length} chars)"))
    }

    /**
     * Why the preview is 64 characters and not a token 8 or 12. The first 44 characters of a
     * Base64 X.509 RSA-2048 key are a fixed DER header, identical for every key ever
     * generated — the first assertion pins exactly that — so a shorter preview would print the
     * same string for every user and identify nobody. The second assertion is the property
     * that actually matters: two real keys must be told apart.
     */
    @Test
    fun `two real public keys are distinguishable in the preview`() {
        val a = publicKeyOf(keyPair)
        val b = publicKeyOf(otherKeyPair)
        assertEquals(
            "premise of the 64-character preview: the DER header is a constant prefix",
            a.take(44),
            b.take(44),
        )
        assertNotEquals(
            previewedPublicKey(a),
            previewedPublicKey(b),
        )
    }

    // ── Nothing else about the data classes may change ───────────────────

    @Test
    fun `equals and hashCode are unaffected`() {
        val same = entry.copy()
        assertEquals(entry, same)
        assertEquals(entry.hashCode(), same.hashCode())
        assertNotEquals(entry, entry.copy(id = "other"))
        val field = TypedField("$SENTINEL v", FieldType.EMAIL)
        assertEquals(field, TypedField("$SENTINEL v", FieldType.EMAIL))
        assertEquals(field.hashCode(), TypedField("$SENTINEL v", FieldType.EMAIL).hashCode())
        assertNotEquals(field, field.copy(type = FieldType.STRING))
    }

    @Test
    fun `copy still carries the real values`() {
        val copied = entry.copy(id = "profile-2")
        assertEquals("profile-2", copied.id)
        assertEquals("Ada $SENTINEL Lovelace", copied.fields["name"]?.value)
        assertEquals(entry.publicKey, copied.publicKey)
        assertEquals("$SENTINEL v", TypedField("$SENTINEL v").copy(type = FieldType.URL).value)
    }

    /**
     * The wire format is not redacted — only the rendering is. If serialisation ever started
     * going through `toString()`, every client would silently receive empty profiles.
     */
    @Test
    fun `gson serialisation still carries the real values`() {
        val json = Gson().toJson(entry)
        assertTrue("the encoded payload must contain the real value", json.contains(SENTINEL))
        assertEquals(entry, Utils.decodeEntry(json))
    }

    @Test
    fun `the typed-field wire format still carries the real values`() {
        val encoded = Utils.encodeFields(personal)
        assertTrue(encoded.contains(SENTINEL))
        val decoded = Utils.decodeFields(encoded)
        assertEquals(personal.keys, decoded.keys)
        personal.forEach { (key, expected) ->
            assertEquals("value of $key", expected.value, decoded[key]?.value)
            assertEquals("type of $key", expected.type, decoded[key]?.type)
        }
    }

    // ── The other two field-carrying result classes ──────────────────────
    //
    // Both hold a Map<String, TypedField> of disclosed profile data and both use a generated
    // toString(), so each was a third and fourth copy of this leak. They are closed by
    // TypedField's override rather than by one of their own — which is exactly why they need
    // asserting: the fix is one indirection away from them.

    @Test
    fun `sign-challenge result toString does not print disclosed field values`() {
        val rendered = SignChallengeResult(
            signature = byteArrayOf(1, 2, 3),
            algorithm = "SHA256withRSA",
            fields = personal,
            requestCode = "req-1",
        ).toString()
        assertFalse("SignChallengeResult leaked a field value: $rendered", rendered.contains(SENTINEL))
        assertTrue("the field keys should still be named: $rendered", rendered.contains("email"))
    }

    @Test
    fun `query result toString does not print disclosed field values`() {
        val rendered = QueryResult(
            fields = personal,
            publicKey = "MIIBIjANBgkq",
            requestCode = "req-1",
        ).toString()
        assertFalse("QueryResult leaked a field value: $rendered", rendered.contains(SENTINEL))
        assertTrue("the field keys should still be named: $rendered", rendered.contains("email"))
    }

    @Test
    fun `share result toString does not print stored field values`() {
        val rendered = ShareResult(
            publicKey = "MIIBIjANBgkq",
            fields = personal,
            requestCode = "req-1",
        ).toString()
        assertFalse("ShareResult leaked a field value: $rendered", rendered.contains(SENTINEL))
        assertTrue("the field keys should still be named: $rendered", rendered.contains("email"))
    }

    // ── Hostile input: a rendering must never be the thing that throws ───

    /**
     * `toString()` is called from log statements and crash handlers, so it is the last place
     * that may throw. Gson builds these classes through `Unsafe` without running the Kotlin
     * constructor, so a payload that omitted a key leaves a declared-non-null property
     * genuinely `null` at runtime (the hazard [Utils.decodeEntry] exists to repair) — and an
     * object in that state can reach a log line before anything repairs it.
     */
    @Test
    fun `rendering a raw Gson-built object with null properties does not throw`() {
        // Each of these would NPE if a redaction assumed its own non-null declaration. The
        // expected rendering is asserted in full rather than merely "it did not throw", so the
        // test says what it is protecting instead of leaving it to the absence of an exception.
        val rawEntry = Gson().fromJson("{}", Entry::class.java)
        assertEquals("Entry(id=null, publicKey=null, fields=null)", rawEntry.toString())
        val rawField = Gson().fromJson("{}", TypedField::class.java)
        assertEquals("TypedField(type=null, value=null)", rawField.toString())

        // The composed shape, which reaches TypedField.toString through the map rather than
        // directly: a hollow field nested inside an otherwise well-formed entry. This is the
        // path the override's own commentary calls the trap, so it is the one to pin.
        val nested = Gson().fromJson(
            """{"id":"a","publicKey":"k","fields":{"email":{}}}""",
            Entry::class.java,
        )
        assertEquals(
            "Entry(id=<1 chars>, publicKey=k, fields={email=TypedField(type=null, value=null)})",
            nested.toString(),
        )
    }
}
