package dev.eryalabs.lim

import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import com.google.gson.Gson
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature

/**
 * [Utils.validateEntry] tells a client *why* an entry will be rejected before it is sent.
 *
 * Two properties matter and are asserted separately throughout. First, each problem is
 * reported for the input that has it and for no other — the assertions compare the whole
 * returned list, so a check that fires on everything fails here. Second, the function is
 * advisory: it must not have narrowed what [Utils.createShareIntent] encodes or what
 * [Utils.decodeEntry] accepts, which the last section pins directly.
 *
 * Robolectric is required because the Base64 check runs through `android.util.Base64`, a
 * stub that returns null under plain JVM unit tests. The RSA parse is ordinary JCE.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class EntryValidationTest {

    companion object {
        private lateinit var keyPair: KeyPair

        /** 2048-bit RSA generation is slow (~100ms); do it once for the whole class. */
        @JvmStatic
        @BeforeClass
        fun generateKey() {
            keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        }

        /** A genuine key, encoded the way the vault encodes one. */
        private fun realKey(): String = Base64.encodeToString(keyPair.public.encoded, Base64.DEFAULT)
    }

    private val fields = linkedMapOf(
        "name" to TypedField("Ada Lovelace", FieldType.STRING),
        "email" to TypedField("ada@example.com", FieldType.EMAIL),
    )

    private fun entry(
        id: String = "profile-1",
        publicKey: String = realKey(),
        fields: Map<String, TypedField> = this.fields,
    ) = Entry(id = id, fields = fields, publicKey = publicKey)

    // ── The one case that must report nothing ────────────────────────────

    @Test
    fun `a well-formed entry reports no problems`() {
        assertEquals(emptyList<String>(), Utils.validateEntry(entry()))
    }

    /**
     * `Base64.DEFAULT` wraps at 76 characters, so every key the vault produces arrives with
     * newlines embedded. A Base64 check that counted those against the alphabet would reject
     * every real key and nothing else.
     */
    @Test
    fun `a real key carrying DEFAULT-encoding newlines is accepted`() {
        val encoded = realKey()
        assertTrue("precondition: DEFAULT encoding should wrap", encoded.contains("\n"))
        assertEquals(emptyList<String>(), Utils.validateEntry(entry(publicKey = encoded)))
    }

    // ── One problem per issue ────────────────────────────────────────────

    @Test
    fun `a blank id is reported`() {
        assertEquals(listOf("id is missing or blank"), Utils.validateEntry(entry(id = "")))
        assertEquals(listOf("id is missing or blank"), Utils.validateEntry(entry(id = "   ")))
    }

    @Test
    fun `a blank public key is reported once, not as three cascading problems`() {
        assertEquals(
            listOf("publicKey is missing or blank"),
            Utils.validateEntry(entry(publicKey = "")),
        )
        assertEquals(
            listOf("publicKey is missing or blank"),
            Utils.validateEntry(entry(publicKey = "  \n ")),
        )
    }

    @Test
    fun `a public key that is not valid Base64 is reported`() {
        assertEquals(
            listOf("publicKey is not valid Base64"),
            Utils.validateEntry(entry(publicKey = "!!!not base64!!!")),
        )
    }

    /**
     * Android's `Base64.decode` *skips* characters outside the alphabet rather than
     * rejecting them (the same trap T3 hit), so junk mixed into an otherwise valid key
     * decodes silently to bytes the sender never encoded. The alphabet check is what
     * catches this; without it, this input would be reported as "not an RSA public key",
     * which points the developer at the wrong thing.
     */
    @Test
    fun `alphabet junk inside an otherwise valid key is reported as bad Base64`() {
        val poisoned = realKey().replace("\n", "").let { it.take(20) + "*!*!" + it.drop(24) }
        assertEquals(
            listOf("publicKey is not valid Base64"),
            Utils.validateEntry(entry(publicKey = poisoned)),
        )
    }

    /**
     * Base64 has no one-character group, so a length leaving one character over is not an
     * encoding of anything. Android's decoder agrees and throws on it; this asserts the
     * outcome rather than which of the two mechanisms produced it.
     */
    @Test
    fun `a key whose length leaves one character over is reported as bad Base64`() {
        assertEquals(
            listOf("publicKey is not valid Base64"),
            Utils.validateEntry(entry(publicKey = "aGVsb")),
        )
        val truncated = realKey().replace("\n", "").dropLast(3)
        assertEquals("precondition: one character over a group", 1, truncated.length % 4)
        assertEquals(
            listOf("publicKey is not valid Base64"),
            Utils.validateEntry(entry(publicKey = truncated)),
        )
    }

    /**
     * Padding is optional in Base64 and Android decodes an unpadded string happily, so this
     * must *not* be reported as bad Base64 — it is reported at the RSA gate behind it, which
     * is where the real fault is.
     *
     * This is not hypothetical. An RSA-2048 X.509 key is 294 bytes, divisible by three, so
     * it encodes with no padding at all and cannot expose the difference; a 3072-bit key is
     * 422 bytes and does need padding, so a vault encoding with `NO_PADDING` would have had
     * every one of its keys called invalid by a check that insisted on a multiple of four.
     */
    @Test
    fun `an unpadded key is valid Base64 and is judged on whether it is a key`() {
        val unpadded = "aGVsbG8gd29ybGQ"
        assertEquals("precondition: this is the unpadded form", 3, unpadded.length % 4)
        assertEquals(
            listOf("publicKey is not an RSA public key"),
            Utils.validateEntry(entry(publicKey = unpadded)),
        )
    }

    /**
     * Padding that does not land on a group boundary. The alphabet pattern allows at most
     * two trailing `=` and the decoder throws on the rest; either way the report must name
     * the encoding, not the key.
     */
    @Test
    fun `misplaced padding is reported as bad Base64`() {
        listOf("====", "A===", "aGVs====").forEach { bad ->
            assertEquals(
                "publicKey $bad",
                listOf("publicKey is not valid Base64"),
                Utils.validateEntry(entry(publicKey = bad)),
            )
        }
    }

    /**
     * The URL-safe alphabet is excluded on purpose: the vault encodes with [Base64.DEFAULT],
     * and `-`/`_` mean nothing to that decoder — it *skips* them, so a URL-safe key would
     * decode to bytes nobody encoded and be reported as "not an RSA public key", pointing the
     * developer at the key when the fault is the encoding.
     *
     * The substitution is done by hand rather than by re-encoding the generated key with
     * `Base64.URL_SAFE`, so that the test does not depend on that particular key happening to
     * contain a `+` or a `/`.
     */
    @Test
    fun `a key in the URL-safe alphabet is reported as bad Base64`() {
        val urlSafe = realKey().replace("\n", "").let { it.take(20) + "-_" + it.drop(22) }
        assertEquals("precondition: length is unchanged", 0, urlSafe.length % 4)
        assertEquals(
            listOf("publicKey is not valid Base64"),
            Utils.validateEntry(entry(publicKey = urlSafe)),
        )
    }

    /**
     * The pair that proves the check parses rather than pattern-matches: this is
     * well-formed Base64 (of the text "hello world"), so it clears the Base64 gate and
     * must fall at the RSA one.
     */
    @Test
    fun `well-formed Base64 that is not a key is reported as not an RSA key`() {
        assertEquals(
            listOf("publicKey is not an RSA public key"),
            Utils.validateEntry(entry(publicKey = "aGVsbG8gd29ybGQ=")),
        )
    }

    /**
     * An EC key is a real, well-formed X.509 public key — it fails only because it is not
     * RSA. Nothing but an actual `KeyFactory` parse tells this apart from the key above.
     */
    @Test
    fun `a well-formed public key of another algorithm is reported as not an RSA key`() {
        val ec = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
        val encoded = Base64.encodeToString(ec.public.encoded, Base64.DEFAULT)
        assertEquals(
            listOf("publicKey is not an RSA public key"),
            Utils.validateEntry(entry(publicKey = encoded)),
        )
    }

    @Test
    fun `an empty fields map is reported`() {
        assertEquals(listOf("fields is empty"), Utils.validateEntry(entry(fields = emptyMap())))
    }

    @Test
    fun `a blank field key is reported with its position`() {
        val withBlank = linkedMapOf(
            "name" to TypedField("Ada", FieldType.STRING),
            "" to TypedField("orphan", FieldType.STRING),
            "email" to TypedField("ada@example.com", FieldType.EMAIL),
        )
        assertEquals(
            listOf("fields entry 1 has a missing or blank key"),
            Utils.validateEntry(entry(fields = withBlank)),
        )
    }

    @Test
    fun `a whitespace-only field key is blank too, and every offender is reported`() {
        val withBlanks = linkedMapOf(
            "" to TypedField("a", FieldType.STRING),
            "name" to TypedField("Ada", FieldType.STRING),
            "   " to TypedField("b", FieldType.STRING),
        )
        assertEquals(
            listOf(
                "fields entry 0 has a missing or blank key",
                "fields entry 2 has a missing or blank key",
            ),
            Utils.validateEntry(entry(fields = withBlanks)),
        )
    }

    // ── Several problems at once ─────────────────────────────────────────

    @Test
    fun `every problem in one entry is reported, identity first`() {
        assertEquals(
            listOf(
                "id is missing or blank",
                "publicKey is not valid Base64",
                "fields is empty",
            ),
            Utils.validateEntry(entry(id = " ", publicKey = "!!!", fields = emptyMap())),
        )
    }

    // ── Hostile input: this must not be the thing that throws ────────────

    /**
     * Gson builds [Entry] through `Unsafe` without running the Kotlin constructor, so its
     * declared-non-null properties can all be genuinely `null` at runtime — the hazard
     * [Utils.decodeEntry] exists for. A validity check is exactly where such an object
     * plausibly turns up, so it reports rather than NPEs.
     */
    @Test
    fun `an entry whose properties are all really null reports problems instead of throwing`() {
        val hollow = Gson().fromJson("{}", Entry::class.java)
        assertEquals(
            listOf(
                "id is missing or blank",
                "publicKey is missing or blank",
                "fields is empty",
            ),
            Utils.validateEntry(hollow),
        )
    }

    /**
     * The remaining null-hostile path. A Kotlin caller cannot put a null key in a
     * `Map<String, TypedField>`, but a Java one can and an unchecked cast is all it takes —
     * and nothing in `forEachIndexed` null-checks the element, so the guard in
     * [Utils.validateEntry] is the only thing between that map and an NPE inside a function
     * documented never to throw. `LinkedHashMap` because a `HashMap` would not fix the
     * position the report names.
     */
    @Test
    fun `a null field key is reported rather than dereferenced`() {
        val hostile = LinkedHashMap<String?, TypedField>()
        hostile[null] = TypedField("orphan", FieldType.STRING)
        hostile["name"] = TypedField("Ada", FieldType.STRING)

        @Suppress("UNCHECKED_CAST")
        val fields = hostile as Map<String, TypedField>
        assertEquals(
            listOf("fields entry 0 has a missing or blank key"),
            Utils.validateEntry(entry(fields = fields)),
        )
    }

    // ── Agreement with the verifier it is advising about ─────────────────

    /** A signature over [nonce] by the class's key, for the agreement tests below. */
    private val nonce = "challenge-nonce-1770000000".toByteArray()

    private fun signature(): ByteArray = Signature.getInstance("SHA256withRSA").run {
        initSign(keyPair.private)
        update(nonce)
        sign()
    }

    /**
     * "Valid here" is only useful if it means "usable there" — [Utils.verifySignature] is the
     * function whose failure this advice exists to predict, and the two reach that answer
     * through separate code. This asserts they agree across the *whole* path, decode as well
     * as parse: a false "invalid" is worse than useless advice, because it tells a developer
     * to go and fix a key that works.
     *
     * The agreement asserted here is over **padding and wrapping**, not over every string
     * `verifySignature` would accept, and the difference is deliberate rather than a gap.
     * Android's decoder skips characters outside the alphabet, so a real key with a stray
     * character wedged into it still verifies while [Utils.validateEntry] reports it — see
     * the alphabet tests above and [Utils.validateEntry]'s own note on why that is the right
     * advice. Scoping this to the encodings a legitimate sender actually produces is what
     * keeps the claim true: `DEFAULT` is what the vault emits and wraps at 76 characters, and
     * the other two are what a client re-encoding the key by hand would produce.
     */
    @Test
    fun `every padding and wrapping of a real key that verifies is also accepted`() {
        val noWrap = Base64.encodeToString(keyPair.public.encoded, Base64.NO_WRAP)
        val noPadding = Base64.encodeToString(keyPair.public.encoded, Base64.NO_WRAP or Base64.NO_PADDING)
        // At this key size the third case cannot carry the padding property: an X.509 RSA-2048
        // key is 294 bytes, divisible by three, so it encodes with no padding either way and
        // the two strings are identical. Asserted rather than left implicit, so the redundancy
        // announces itself if the fixture key size ever changes. What actually pins the
        // unpadded rule is `an unpadded key is valid Base64 and is judged on whether it is a key`.
        assertEquals("NO_PADDING is a no-op at this key size", noWrap, noPadding)

        val encodings = mapOf(
            "DEFAULT" to Base64.encodeToString(keyPair.public.encoded, Base64.DEFAULT),
            "NO_WRAP" to noWrap,
            "NO_PADDING" to noPadding,
        )
        encodings.forEach { (label, key) ->
            assertTrue(
                "precondition: verifySignature accepts the $label encoding",
                Utils.verifySignature(key, nonce, signature()),
            )
            assertEquals(
                "validateEntry must not call the $label encoding invalid",
                emptyList<String>(),
                Utils.validateEntry(entry(publicKey = key)),
            )
        }
    }

    /**
     * The one direction in which the two deliberately disagree, asserted rather than left as
     * a remark: a real key with a stray character wedged into it still *verifies*, because
     * Android's decoder skips what is not in the alphabet and recovers the 392 real
     * characters around it — and [Utils.validateEntry] reports it anyway.
     *
     * That is the right advice, not a false positive. The protocol identifies a profile by
     * the public-key *string* and the vault looks it up by equality, so a key that works only
     * because a decoder was forgiving is a key that will match nothing on the far side.
     *
     * Pinned because the neighbouring agreement test is the kind a future change could keep
     * green by loosening the alphabet check. This one goes red if that happens.
     */
    @Test
    fun `a real key with a stray character verifies but is reported anyway`() {
        val poisoned = realKey().replace("\n", "") + "!!"
        assertTrue(
            "precondition: the decoder skips the junk, so this key still verifies",
            Utils.verifySignature(poisoned, nonce, signature()),
        )
        assertEquals(
            listOf("publicKey is not valid Base64"),
            Utils.validateEntry(entry(publicKey = poisoned)),
        )
    }

    @Test
    fun `keys validateEntry rejects are keys verifySignature cannot use either`() {
        val bad = listOf(
            "",
            "!!!not base64!!!",
            "aGVsbG8gd29ybGQ=",
            "aGVsb",
            realKey().replace("\n", "").let { it.take(20) + "-_" + it.drop(22) },
        )
        bad.forEach {
            assertTrue("validateEntry should flag $it", Utils.validateEntry(entry(publicKey = it)).isNotEmpty())
            assertFalse("verifySignature should refuse $it", Utils.verifySignature(it, nonce, signature()))
        }
    }

    // ── Advisory only: nothing about the protocol may have changed ───────

    /**
     * The point of the task, asserted rather than assumed: an entry this reports problems
     * for is still encoded by [Utils.createShareIntent] and still decoded by
     * [Utils.decodeEntry]. Narrowing either is a decision for a human — if this test ever
     * goes red, the advisory check has quietly become a gate.
     */
    @Test
    fun `an entry with problems is still encoded and still decoded`() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val flagged = entry(publicKey = "aGVsbG8gd29ybGQ=", fields = emptyMap())
        assertEquals(
            listOf("publicKey is not an RSA public key", "fields is empty"),
            Utils.validateEntry(flagged),
        )

        val json = Utils.createShareIntent(context, flagged).getStringExtra(Utils.EXTRA_ENTRY_JSON)
        assertNotNull("createShareIntent must still encode a flagged entry", json)

        val decoded = Utils.decodeEntry(json)
        assertEquals("decodeEntry must still accept a flagged entry", flagged, decoded)
    }

    /**
     * The converse asymmetry, kept explicit: a payload [Utils.decodeEntry] rejects outright
     * is one this reports on rather than refusing to look at. Validation is a report, not a
     * verdict, so it never has an answer that means "I will not say".
     */
    @Test
    fun `an entry decodeEntry would reject is still described, not refused`() {
        val problems = Utils.validateEntry(entry(id = ""))
        assertEquals(listOf("id is missing or blank"), problems)
        assertEquals(
            "precondition: decodeEntry rejects this payload",
            null,
            Utils.decodeEntry("""{"id":"","publicKey":"k","fields":{}}"""),
        )
    }

    // ── Negative control ─────────────────────────────────────────────────

    /**
     * If [Utils.validateEntry] returned a constant — always empty, or always the same list —
     * most of the tests above would still pass. This one fails in either world.
     */
    @Test
    fun `validation actually depends on its input`() {
        assertTrue(Utils.validateEntry(entry()).isEmpty())
        assertTrue(Utils.validateEntry(entry(id = "")).isNotEmpty())
        assertEquals(
            "different inputs must not produce the same report",
            false,
            Utils.validateEntry(entry(id = "")) == Utils.validateEntry(entry(fields = emptyMap())),
        )
    }
}
