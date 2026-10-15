package dev.eryalabs.lim

import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import com.google.gson.Gson
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File
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

        /** The document the sign-up entry is read out of, rather than copied from. */
        private const val GUIDE_PATH = "docs/INTEGRATION.md"

        /** The marker above the guide's sign-up block — the one block this test reads. */
        private const val SIGN_UP_MARKER = "<!-- snippet: GuideExamplesTest.kt#signup-request -->"

        /** A `publicKey = "…"` assignment, however it is spaced. */
        private val PUBLIC_KEY_ASSIGNMENT = Regex("publicKey\\s*=\\s*\"([^\"]*)\"")

        /** An `id = "…"` assignment, with the word boundary that keeps it off other names. */
        private val ID_ASSIGNMENT = Regex("\\bid\\s*=\\s*\"([^\"]*)\"")

        /** One entry of the field map the block builds: name, value and declared type. */
        private val FIELD_ENTRY =
            Regex("\"([^\"]*)\"\\s+to\\s+TypedField\\(value = \"([^\"]*)\", type = FieldType\\.(\\w+)\\)")

        /** Every mention of the type, however the call after it is spelled. */
        private val TYPED_FIELD_MENTION = Regex("TypedField")

        /** A fixture document: the real marker, a closed Kotlin fence, and [body]. */
        private fun markedBlock(body: String) = "$SIGN_UP_MARKER\n```kotlin\n$body\n```\n"

        /** A sign-up block the parser must read whole — the template the fixtures below bend. */
        private val FIXTURE_BODY = """
            val entry = Entry(
                id = "signup-form",
                fields = linkedMapOf(
                    "name" to TypedField(value = "", type = FieldType.STRING),
                ),
                publicKey = "no-key-yet",
            )
        """.trimIndent()

        /** The same block reflowed onto one line — two fields the parser must both read. */
        private val FIXTURE_ONE_LINE =
            "val entry = Entry(id = \"signup-form\", fields = linkedMapOf(" +
                "\"name\" to TypedField(value = \"\", type = FieldType.STRING), " +
                "\"email\" to TypedField(value = \"\", type = FieldType.EMAIL)), " +
                "publicKey = \"no-key-yet\")"

        /**
         * Documents the locator must refuse, each keyed by the phrase its failure has to carry.
         * One defect each, so the phrase identifies which clause fired rather than merely
         * proving that something did.
         *
         * The first carries a perfectly good sign-up block and fails only because nothing says
         * it is the sign-up one. The last two are the field-map drifts: a block that builds no
         * field at all, which would otherwise reach [Utils.validateEntry] as `fields is empty`,
         * and a block with one field spelled a way [FIELD_ENTRY] does not read, which is the
         * silent drop the count in `fieldsIn` exists to catch — the two take different branches
         * of that guard and their phrases say which.
         */
        private val LOCATOR_FIXTURES = listOf(
            "no line" to markedBlock(FIXTURE_BODY).replace(SIGN_UP_MARKER, "<!-- snippet: Other.kt#x -->"),
            "no fenced block" to "$SIGN_UP_MARKER\nprose, and no block under it at all\n",
            "never closed" to "$SIGN_UP_MARKER\n```kotlin\n$FIXTURE_BODY\n",
            "found 0" to markedBlock(FIXTURE_BODY.replace("    publicKey = \"no-key-yet\",\n", "")),
            "found 2" to markedBlock("$FIXTURE_BODY\nval other = entry.copy(publicKey = \"no-key-either\")"),
            "in 0 place(s) and this read 0" to markedBlock(
                "val entry = Entry(id = \"signup-form\", fields = emptyMap(), publicKey = \"no-key-yet\")",
            ),
            "in 2 place(s) and this read 1" to markedBlock(
                FIXTURE_BODY.replace(
                    "        \"name\" to TypedField(value = \"\", type = FieldType.STRING),",
                    "        \"name\" to TypedField(value = \"\", type = FieldType.STRING),\n" +
                        "        \"email\" to TypedField(\"\", FieldType.EMAIL),",
                ),
            ),
        )
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

    // ── The one entry every integration builds first ─────────────────────

    /**
     * The sign-up entry the guide prints reports a problem, and that is the expected answer.
     *
     * `publicKey` is a slot the vault fills, so a sign-up sends a placeholder — and the
     * placeholder the documents print is not in the Base64 alphabet, so this reports it. The
     * entry is **read off `docs/INTEGRATION.md`** rather than copied in, so the pin re-measures
     * what the guide actually tells an integrator to send: change the placeholder in the document
     * to something that is valid Base64, or empty the field map the block builds, and this test
     * says so instead of agreeing with a copy of yesterday's block.
     *
     * The two controls are what make the assertion about the placeholder rather than about the
     * entry. The same entry with a genuine key reports nothing, so neither the id nor the blank
     * field values is the cause; and a placeholder that *is* valid Base64 falls at the RSA gate
     * behind it instead, so the problem reported here is the alphabet rule and not a rule about
     * placeholders.
     *
     * The locator's own failures are asserted too, each against the message it must produce. A
     * scanner that silently finds nothing passes for ever, and this one's whole subject is a
     * handful of lines in a file it does not own.
     */
    @Test
    fun `the sign-up entry the guide prints reports exactly the placeholder problem`() {
        val entry = signUpEntryIn(guideText(), GUIDE_PATH)
        println(
            "EntryValidationTest: the block under `$SIGN_UP_MARKER` in $GUIDE_PATH builds " +
                "id = \"${entry.id}\", publicKey = \"${entry.publicKey}\", fields " +
                entry.fields.entries.joinToString(", ", "[", "]") { (name, field) ->
                    "\"$name\": ${field.type} = \"${field.value}\""
                },
        )

        assertEquals(
            "the entry the guide tells every integrator to send first reports this one problem",
            listOf("publicKey is not valid Base64"),
            Utils.validateEntry(entry),
        )

        assertEquals(
            "control: the same entry with a genuine key reports nothing, so the placeholder is " +
                "the cause and not the id or the blank field values",
            emptyList<String>(),
            Utils.validateEntry(entry.copy(publicKey = realKey())),
        )
        assertEquals(
            "control: a placeholder that is valid Base64 falls at the RSA gate instead, so the " +
                "assertion above is about the alphabet rule and not about placeholders",
            listOf("publicKey is not an RSA public key"),
            Utils.validateEntry(entry.copy(publicKey = "bm8ta2V5LXlldA==")),
        )

        assertEquals(
            "control: the fixture template itself parses, so each fixture below fails for its " +
                "own defect and not because the parser cannot read the template",
            Entry(
                id = "signup-form",
                fields = linkedMapOf("name" to TypedField(value = "", type = FieldType.STRING)),
                publicKey = "no-key-yet",
            ),
            signUpEntryIn(markedBlock(FIXTURE_BODY), "fixture"),
        )
        assertEquals(
            "control: two fields on one line are both read, so the count that guards against a " +
                "dropped field is not satisfied by reading one of them",
            setOf("name", "email"),
            signUpEntryIn(markedBlock(FIXTURE_ONE_LINE), "fixture").fields.keys,
        )
        LOCATOR_FIXTURES.forEach { (named, fixture) ->
            val failure = runCatching { signUpEntryIn(fixture, "fixture") }.exceptionOrNull()
            assertNotNull("the locator must fail loudly on:\n$fixture", failure)
            assertTrue(
                "the failure must say `$named`, and said: ${failure?.message}",
                failure?.message?.contains(named) == true,
            )
        }
    }

    /**
     * The other half of the same fact, measured rather than argued: the entry this reports a
     * problem for is the entry a sign-up sends, and nothing on the way to the vault's parser
     * objects to it.
     *
     * [Utils.createShareIntent] encodes it, [Utils.decodeEntry] accepts the payload, and
     * [Utils.parseShareRequest] — the vault's half of the request — hands it over with the
     * placeholder intact. What that pins is the client-side path only; what a vault does with the
     * entry afterwards is the vault's, and the key the client keeps is the one the *result*
     * carries ([ShareResult.publicKey]), never the slot it sent.
     *
     * The control is the asymmetry that keeps this from being a restatement of the test above: a
     * *blank* slot is refused outright by [Utils.decodeEntry] and so never reaches a vault at all
     * (`EntryCodecTest.a blank id or public key decodes to null`), which is what the guide's
     * sign-up block means by "a blank one is encoded here and then refused on arrival". The
     * placeholder is reported and travels; a blank is reported differently and does not.
     */
    @Test
    fun `the sign-up entry reaches the vault's parser with its placeholder intact`() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val entry = signUpEntryIn(guideText(), GUIDE_PATH)
        assertEquals(
            "precondition: this is the entry the test above reports on",
            listOf("publicKey is not valid Base64"),
            Utils.validateEntry(entry),
        )

        val request = Utils.createShareIntent(context, entry)
        val payload = request.getStringExtra(Utils.EXTRA_ENTRY_JSON)
        assertNotNull("createShareIntent must encode the sign-up entry", payload)
        assertEquals("decodeEntry must accept its payload", entry, Utils.decodeEntry(payload))

        val parsed = Utils.parseShareRequest(request)
        assertNotNull("the vault's request parser must accept the sign-up request", parsed)
        assertEquals(
            "the placeholder arrives as it was sent — it is the slot, not an identifier",
            entry.publicKey,
            parsed!!.entry.publicKey,
        )
        assertEquals("and the rest of the entry with it", entry, parsed.entry)

        val blank = Utils.createShareIntent(context, entry.copy(publicKey = ""))
        assertEquals(
            "control: a blank slot is reported by a different problem",
            listOf("publicKey is missing or blank"),
            Utils.validateEntry(entry.copy(publicKey = "")),
        )
        assertNull(
            "control: and is refused on arrival, so it never reaches a vault",
            Utils.parseShareRequest(blank),
        )
        assertNull(
            "control: because the payload itself does not decode",
            Utils.decodeEntry(blank.getStringExtra(Utils.EXTRA_ENTRY_JSON)),
        )
    }

    /**
     * The entry the guide's `signup-request` block builds, parsed out of [markdown].
     *
     * Everything that decides what [Utils.validateEntry] reports is read from the document —
     * the id, every field name, and the `publicKey` slot — because a hand-copied shape lets the
     * guide drift while the pin stays green on an entry nobody is told to send.
     *
     * Fails naming [where] and what it looked for when the marker is absent, when the block
     * under it is unfenced or never closed, when the block assigns no `id` or no `publicKey` or
     * builds no field, and when two lines disagree about a value — every way this could
     * otherwise find nothing and report success.
     */
    private fun signUpEntryIn(markdown: String, where: String): Entry {
        val block = signUpBlock(markdown, where)
        return Entry(
            id = soleValueOf(ID_ASSIGNMENT, "id", block, where),
            fields = fieldsIn(block, where),
            publicKey = soleValueOf(PUBLIC_KEY_ASSIGNMENT, "publicKey", block, where),
        )
    }

    /** The lines inside the fenced block under [SIGN_UP_MARKER], or an [AssertionError]. */
    private fun signUpBlock(markdown: String, where: String): List<String> {
        val lines = markdown.lines()
        val marker = lines.indexOfFirst { it.trim() == SIGN_UP_MARKER }
        if (marker < 0) {
            throw AssertionError(
                "$where: no line `$SIGN_UP_MARKER`, so the sign-up block this test measures the " +
                    "entry out of is not there",
            )
        }
        val open = (marker + 1 until lines.size).firstOrNull { lines[it].trim().startsWith("```") }
            ?: throw AssertionError("$where: `$SIGN_UP_MARKER` is followed by no fenced block")
        val close = (open + 1 until lines.size).firstOrNull { lines[it].trim() == "```" }
            ?: throw AssertionError("$where: the block under `$SIGN_UP_MARKER` is never closed")
        return lines.subList(open + 1, close)
    }

    /** The one value [block] assigns to [named], or an [AssertionError] saying how many it found. */
    private fun soleValueOf(
        assignment: Regex,
        named: String,
        block: List<String>,
        where: String,
    ): String {
        val assigned = block.mapNotNull { assignment.find(it)?.groupValues?.get(1) }.distinct()
        if (assigned.size != 1) {
            throw AssertionError(
                "$where: looked for exactly one distinct `$named = \"…\"` in the block under " +
                    "`$SIGN_UP_MARKER` and found ${assigned.size} $assigned",
            )
        }
        return assigned.single()
    }

    /**
     * The fields [block] builds, in the order it builds them.
     *
     * A `TypedField` spelled some way this regex does not read would otherwise vanish from the
     * entry and quietly weaken the pin, so the count is checked against how many times the type
     * is named at all — and an empty map fails rather than being validated as "fields is empty".
     *
     * Counted by occurrence rather than by line, and read with `findAll` rather than `find`, so
     * that two fields written on one line are both parsed instead of one being dropped past a
     * guard that a line-wise count would have satisfied. The guide puts one field per line
     * today; the claim above should not depend on it.
     */
    private fun fieldsIn(block: List<String>, where: String): Map<String, TypedField> {
        val named = block.sumOf { line -> TYPED_FIELD_MENTION.findAll(line).count() }
        val parsed = block.flatMap { FIELD_ENTRY.findAll(it) }.associate { match ->
            val (name, value, type) = match.destructured
            name to TypedField(value = value, type = fieldTypeNamed(type, where))
        }
        if (parsed.isEmpty() || parsed.size != named) {
            throw AssertionError(
                "$where: the block under `$SIGN_UP_MARKER` names `TypedField` in $named place(s) " +
                    "and this read ${parsed.size} field(s) ${parsed.keys} off it — a field " +
                    "spelled a way this does not read would be dropped from the pin",
            )
        }
        return parsed
    }

    /**
     * The wire value of the `FieldType.`[name] the block writes.
     *
     * [FieldType] is constants rather than an enum, so the name has to be resolved against the
     * published object — which also means a block naming a type this library does not have
     * fails here instead of being read as something else.
     */
    private fun fieldTypeNamed(name: String, where: String): String =
        runCatching { FieldType::class.java.getField(name).get(null) as String }.getOrNull()
            ?: throw AssertionError(
                "$where: the block under `$SIGN_UP_MARKER` names `FieldType.$name`, which this " +
                    "library does not publish",
            )

    /**
     * `docs/INTEGRATION.md`, located by walking up from the working directory.
     *
     * `GuideSnippetTest`'s walk-up, for its reason: the working directory of a Gradle unit test
     * is the module directory, but that is a default rather than a promise. If no ancestor holds
     * the guide the test fails naming every absolute path it tried, because a pin that reads a
     * document must never pass by failing to find it.
     */
    private fun guideText(): String {
        val workingDirectory = File(".").absoluteFile.normalize()
        val tried = mutableListOf<File>()
        var directory: File? = workingDirectory
        while (directory != null) {
            for (candidate in listOf(File(directory, GUIDE_PATH), File(directory, "LIM/$GUIDE_PATH"))) {
                tried += candidate
                if (candidate.exists()) return candidate.readText()
            }
            directory = directory.parentFile
        }
        throw AssertionError(
            "cannot find `$GUIDE_PATH` — this test reads the placeholder out of the guide and " +
                "must not be silently skipped. Working directory: $workingDirectory. Tried:\n" +
                tried.map { it.absolutePath }.distinct().joinToString("\n"),
        )
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
