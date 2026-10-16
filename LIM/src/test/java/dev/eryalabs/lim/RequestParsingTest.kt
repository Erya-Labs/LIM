package dev.eryalabs.lim

import android.content.Intent
import android.os.BadParcelableException
import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import com.google.gson.annotations.SerializedName
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.lang.reflect.Modifier

/**
 * The request parsers are the vault's half of the wire format, and these tests close the
 * loop the builders left open: every `create*Intent` output round-trips through its parser
 * field-for-field, so both ends of each flow are now pinned inside one repo instead of one
 * end here and the other as a vault's hand-rolled convention.
 *
 * A request intent is the most hostile input a vault handles — any installed app can fire
 * one at it — so the other half of this file is refusals: every malformed shape degrades to
 * `null` instead of throwing in the vault's intent handler, and the share/query
 * disambiguation (same action, different payload) is pinned in both directions so no intent
 * can parse as both.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class RequestParsingTest {

    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()

    private val entry = Entry(
        id = "profile-1",
        fields = linkedMapOf(
            "name" to TypedField("Ada", FieldType.STRING),
            "email" to TypedField("ada@example.com", FieldType.EMAIL),
        ),
        publicKey = "PUBLIC-KEY-BASE64",
    )

    /** A hand-built request, standing in for a client that does not use the builders. */
    private fun requestIntent(vararg extras: Pair<String, String>) = Intent().apply {
        extras.forEach { (key, value) -> putExtra(key, value) }
    }

    /**
     * An intent whose extras cannot be read — the same fixture `ResultParsingTest` uses, for
     * the same reason: unparcelling a bundle that references a class this process does not
     * have throws exactly this way, and the sender chooses what goes in the bundle. The read
     * counter is what tells a *safe* read from *no* read, since `null` is also what a parser
     * that never touched the intent would return.
     */
    private class UnreadableIntent : Intent() {
        var reads = 0
            private set

        override fun getStringExtra(name: String?): String? {
            reads++
            throw BadParcelableException("extras reference an unknown class")
        }
    }

    // ── Builder → parser round trips: both ends of the wire in one assertion ──

    @Test
    fun `a share intent round-trips through parseShareRequest field-for-field`() {
        val request = Utils.parseShareRequest(Utils.createShareIntent(context, entry))

        assertNotNull(request)
        assertEquals("the decoded entry must be the one that was sent", entry, request!!.entry)
        assertEquals("Ada", request.entry.fields["name"]?.value)
        assertEquals(FieldType.EMAIL, request.entry.fields["email"]?.type)
        assertNull("the untagged overload attaches no request code", request.requestCode)
        assertEquals(
            "the builder declares this library's protocol version",
            Utils.PROTOCOL_VERSION,
            request.protocolVersion,
        )
    }

    @Test
    fun `a tagged share intent carries its request code through`() {
        val request = Utils.parseShareRequest(
            Utils.createShareIntent(context, entry, requestCode = "req-42"),
        )
        assertEquals("req-42", request?.requestCode)
        assertEquals(entry, request?.entry)
    }

    @Test
    fun `a query intent round-trips through parseQueryRequest field-for-field`() {
        val request = Utils.parseQueryRequest(
            Utils.createQueryIntent(context, "PUBLIC-KEY-BASE64", "req-7"),
        )

        assertNotNull(request)
        assertEquals("PUBLIC-KEY-BASE64", request!!.publicKey)
        assertEquals("req-7", request.requestCode)
        assertEquals(Utils.PROTOCOL_VERSION, request.protocolVersion)
    }

    @Test
    fun `a sign-challenge intent round-trips through parseSignChallengeRequest field-for-field`() {
        val nonce = Utils.generateNonce(now = 1_770_000_000_000L)
        val request = Utils.parseSignChallengeRequest(
            Utils.createSignChallengeIntent(context, "PUBLIC-KEY-BASE64", nonce, "req-9"),
        )

        assertNotNull(request)
        assertEquals("PUBLIC-KEY-BASE64", request!!.publicKey)
        assertTrue("nonce bytes must survive the wire intact", nonce.contentEquals(request.nonce))
        assertEquals("req-9", request.requestCode)
        assertEquals(Utils.PROTOCOL_VERSION, request.protocolVersion)
        // The decoded nonce is the same bytes the client generated, so the vault-side
        // freshness path works end-to-end: header extraction and the window agree with
        // what the issuing side would compute.
        assertEquals(1_770_000_000_000L, Utils.nonceTimestamp(request.nonce))
    }

    @Test
    fun `an undeclared nonce format arrives as null and a declared one arrives verbatim`() {
        val nonce = Utils.generateNonce(now = 1_770_000_000_000L)

        val undeclared = Utils.parseSignChallengeRequest(
            Utils.createSignChallengeIntent(context, "K", nonce, "r"),
        )
        assertNull("the default declares nothing", undeclared?.nonceFormat)

        val declared = Utils.parseSignChallengeRequest(
            Utils.createSignChallengeIntent(
                context, "K", nonce, "r",
                nonceFormat = Utils.NONCE_FORMAT_TIMESTAMPED,
            ),
        )
        assertEquals("lim-ts1", declared?.nonceFormat)

        // A declaration is a string the client chose, not an enum this library polices: an
        // unknown format is reported to the vault verbatim, and what to do with it is the
        // vault's policy decision.
        val custom = Utils.parseSignChallengeRequest(
            requestIntent(
                Utils.EXTRA_PUBLIC_KEY to "K",
                Utils.EXTRA_NONCE to Base64.encodeToString(nonce, Base64.NO_WRAP),
                Utils.EXTRA_NONCE_FORMAT to "acme-v3",
            ),
        )
        assertEquals("acme-v3", custom?.nonceFormat)
    }

    // ── Share vs query: one action, two payloads, no overlap ─────────────

    @Test
    fun `a query-shaped intent is not a share request`() {
        assertNull(
            "a query carries no entry payload, so it must not parse as a share",
            Utils.parseShareRequest(Utils.createQueryIntent(context, "PUBLIC-KEY-BASE64", "req-7")),
        )
    }

    @Test
    fun `an intent carrying an entry payload is never a query request`() {
        assertNull(
            "a share intent must not parse as a query",
            Utils.parseQueryRequest(Utils.createShareIntent(context, entry)),
        )

        // The load-bearing half: even with a public key riding alongside, the entry payload
        // makes it a share. Presence of EXTRA_ENTRY_JSON is how the vault routes, so the two
        // parsers must split on exactly that line or an intent could parse as both.
        val both = Utils.createShareIntent(context, entry).apply {
            putExtra(Utils.EXTRA_PUBLIC_KEY, "PUBLIC-KEY-BASE64")
        }
        assertNull("entry payload wins the routing", Utils.parseQueryRequest(both))
        assertEquals(
            "and the same intent still parses as the share it is",
            entry,
            Utils.parseShareRequest(both)?.entry,
        )
    }

    /**
     * Blank reads as absent on every extra in this protocol, and the routing extra is no
     * exception: a blank entry payload does not make an intent a share, so a query carrying
     * one — a buggy client zeroing a field rather than dropping it — still parses as a query.
     */
    @Test
    fun `a blank entry payload does not capture the routing`() {
        val request = Utils.parseQueryRequest(
            requestIntent(
                Utils.EXTRA_ENTRY_JSON to "   ",
                Utils.EXTRA_PUBLIC_KEY to "PUBLIC-KEY-BASE64",
            ),
        )
        assertEquals("PUBLIC-KEY-BASE64", request?.publicKey)
        assertNull("and it is still not a share", Utils.parseShareRequest(requestIntent(Utils.EXTRA_ENTRY_JSON to "   ")))
    }

    // ── Refusals: every malformed shape degrades to null ─────────────────

    @Test
    fun `a null intent yields null`() {
        assertNull(Utils.parseShareRequest(null))
        assertNull(Utils.parseQueryRequest(null))
        assertNull(Utils.parseSignChallengeRequest(null))
    }

    @Test
    fun `an intent with no extras yields null`() {
        assertNull(Utils.parseShareRequest(Intent()))
        assertNull(Utils.parseQueryRequest(Intent()))
        assertNull(Utils.parseSignChallengeRequest(Intent()))
    }

    /**
     * The share parser holds entries to the [Utils.decodeEntry] bar — the same one the rest
     * of the protocol applies — so a payload that decoder refuses never becomes a request.
     */
    @Test
    fun `a rejected entry payload yields no share request`() {
        listOf(
            "{}" to "an empty object has no identity",
            "garbage" to "not JSON at all",
            """{"id":"","publicKey":"k","fields":{}}""" to "a blank id is refused",
            """{"id":"x","publicKey":"","fields":{}}""" to "a blank publicKey is refused",
            """[{"id":"x","publicKey":"k"}]""" to "wrong shape",
        ).forEach { (payload, why) ->
            assertNull(why, Utils.parseShareRequest(requestIntent(Utils.EXTRA_ENTRY_JSON to payload)))
        }
    }

    // ── Minification: the five keys the consumer rules name, lost one at a time ──

    /**
     * `docs/INTEGRATION.md`'s *Minification* section tells an integrator to know the failure by
     * sight — "sign-up opens no consent dialog at all" — and that is true of two of the five keys
     * the keep rules name. The other three fail *silently*: the request arrives, degraded, and
     * neither app says so. This census is which is which.
     *
     * **Why one key at a time is the useful question.** That same section tells every
     * vendored-AAR consumer — "the only install path this guide can offer today" — to copy the
     * rules into their own ProGuard file **by hand**. A hand copy is partial sometimes, and a
     * partial copy is exactly the per-key case. The asymmetry comes from [Utils.decodeEntry]
     * (`Utils.kt:3441-3449`) delegating to two `repaired()` extensions: the [Entry] one returns
     * `null` when identity is missing (`Utils.kt:3459-3460`) but turns an absent `fields` map into
     * `emptyMap()` (`:3462`), and the [TypedField] one repairs a missing value to `""` and a
     * missing type to [FieldType.STRING] (`:3484-3485`).
     *
     * **The decoder's half of every cell is already pinned, and this test cites it rather than
     * buying it twice.** `EntryCodecTest` asserts that an absent `fields` member decodes non-null
     * with an empty map (`:72-79`), an explicitly null one likewise (`:221-226`), an `id`-only or
     * `publicKey`-only payload decodes `null` (`:92-94`, `:97-99`), `{}` decodes `null` (`:87-89`),
     * and a field missing its `value` or its `type` is repaired (`:200-211`). On the parser side the
     * loud pair is covered by `a rejected entry payload yields no share request`, just above, with
     * `{}` among its refusals, and the `fields`-absent cell by `FieldRequirementsParsingTest:288`
     * and `:304-308`, which read `fieldNames` off `{"id":"x","publicKey":"k"}` and so can only pass
     * if it became a `ShareRequest`.
     * **Those three cells are here for the census's shape, not as new coverage.** What is new is
     * the two silent member-loss cells — `value` and `type`, driven by `DecoderFuzzTest` but
     * asserted there only as no-throw plus the entry invariants — and the grouping.
     *
     * **What the grouping is worth, stated narrowly, because two other files already own most of
     * it.** A sixth serialised key added to [Entry] or [TypedField] and *not* given a keep rule
     * reddens `ConsumerRulesTest`'s rule 3 (`:331-354`, asserted at `:515-524`), which builds its
     * uncovered set by reflection over these same two classes (`:1245`); one added without an annotation
     * reddens `WireKeyAnnotationTest:85-91`. So the only case this census is the sole **wire-key**
     * detector of is a key that is **both** annotated **and** keep-ruled but has no cell here — a
     * real increment, and that narrow one. (A sixth key that is also a *public* property would
     * additionally move `ApiBaselineTest` and `PublicApiAuditTest`'s member manifest, but neither
     * of those is about wire keys; the case that escapes everything else is a non-public
     * serialised field.) Note also that the key set below is derived from the
     * declared fields of two hard-coded classes, not from the rules file: it is
     * `ConsumerRulesTest` rule 3 that ties the two together, and a third `-keep class` block added
     * to `consumer-rules.pro` later would be invisible here.
     *
     * **Why this file and not `ConsumerRulesTest`**, which owns the document section: that class
     * carries no `@RunWith` (`:121`, one of 13 of the 49 Kotlin test classes without one), and
     * `Intent`, `Context` and `android.util.Base64` are unimplemented stubs without Robolectric
     * (`LIM/build.gradle.kts:58-60`). This class carries `@RunWith(RobolectricTestRunner::class)`
     * and owns the parser being measured, so the cells run here. The mutual citation is with the
     * guide, not with `ConsumerRulesTest`: this KDoc names the *Minification* section and
     * `docs/INTEGRATION.md` names this census, while the reference to `ConsumerRulesTest` is
     * one-way, since T64 requires that file to pass unmodified.
     * In-file citations are by test name rather than by line throughout the paragraphs above: a
     * line number into the file the citation itself lives in goes stale on the commit that writes
     * it, which the first draft of this KDoc demonstrated twice.
     *
     * **Three limits, all three measured rather than reasoned.** (1) R8 never runs in this
     * repository — `isMinifyEnabled = false` is correct for a library, and the guide says so at its
     * *Minification* section — so the single-letter keys below are a *model* of its output, matching
     * the guide's own `"a"`, `"b"`, `"c"`. What is measured is the **absence** of each key, which is
     * the mechanism; nothing here is a claim about what R8 actually names anything.
     * (2) This is a property of the renamed *member*, not of the annotation. Deleting
     * `@SerializedName("fields")` from [Entry] was probed and reverted: `WireKeyAnnotationTest`
     * reddened twice and the annotation census at the foot of this test reddened once, while all
     * six cells below printed **byte-identically** — the annotation's value is spelled the same as
     * the property it sits on, so it is load-bearing only once R8 has renamed the field underneath
     * it, which is precisely why the keep rules exist.
     * (3) The guide sentence this test backs is **not pinned by anything**, and deleting it was
     * probed too: the whole suite stayed green, because `GuideSnippetTest` deliberately pins the
     * fenced blocks and not the prose. The measurement lives here; the sentence there is a
     * citation, and keeping the two in step is a human's job.
     */
    @Test
    fun `each wire key the keep rules name is lost loudly or silently, and the census says which`() {
        val allFive = "all five"
        val canonical = Utils.createShareIntent(context, entry)
        val payload = canonical.getStringExtra(Utils.EXTRA_ENTRY_JSON)!!

        // Rename quoted JSON keys in the builder's own payload, asserting the edit landed: a
        // rename that matched nothing would make every `null` below this test's own doing rather
        // than the decoder's. Every occurrence goes, because R8 renames the field, not a use of it.
        fun rename(vararg swaps: Pair<String, String>): String =
            swaps.fold(payload) { text, (from, to) ->
                val token = """"$from":"""
                val replacement = """"$to":"""
                val hits = text.windowed(token.length).count { it == token }
                assertTrue("`$token` must occur in the builder's payload to be renamed", hits > 0)
                val renamed = text.replace(token, replacement)
                assertFalse("`$token` must be gone after the rename", renamed.contains(token))
                assertEquals(
                    "every `$token` must have become `$replacement`",
                    hits,
                    renamed.windowed(replacement.length).count { it == replacement },
                )
                renamed
            }

        // The published vault-side parser, not just the decoder: every other extra is still
        // exactly what the builder wrote, so only the payload differs between cells.
        fun parse(json: String): ShareRequest? = Utils.parseShareRequest(
            Intent(canonical).apply { putExtra(Utils.EXTRA_ENTRY_JSON, json) },
        )

        // Control, asserted before any absence claim: the un-renamed payload through this exact
        // path is the entry that was sent. Without it the instrument could be dead.
        assertEquals(
            "the un-renamed payload must round-trip, or this census measures nothing",
            entry,
            parse(payload)?.entry,
        )

        val cells = linkedMapOf(
            "id" to parse(rename("id" to "a")),
            "fields" to parse(rename("fields" to "b")),
            "publicKey" to parse(rename("publicKey" to "c")),
            "value" to parse(rename("value" to "d")),
            "type" to parse(rename("type" to "e")),
            // The guide's literal sentence: all five gone at once.
            allFive to parse(
                rename("id" to "a", "fields" to "b", "publicKey" to "c", "value" to "d", "type" to "e"),
            ),
        )

        // Values are rendered as lengths, the way `SignChallengeRequest.toString()` renders a
        // nonce: blankness is the whole finding and a length shows it without printing a field.
        println(
            "Wire-key census — one key renamed, through createShareIntent → parseShareRequest:\n" +
                cells.entries.joinToString("\n") { (key, request) ->
                    val outcome = if (request == null) {
                        "DROPPED  — no request arrives, so no consent dialog opens"
                    } else {
                        "ARRIVES  — " + if (request.entry.fields.isEmpty()) {
                            "no fields at all"
                        } else {
                            request.entry.fields.entries.joinToString(", ") { (name, field) ->
                                "$name=<${field.value.length} chars, ${field.type}>"
                            }
                        }
                    }
                    "  ${key.padEnd(10)} $outcome"
                },
        )

        // ── Loud: identity is unrepairable, so nothing reaches the vault's handler ──

        assertNull("a renamed `id` must drop the request", cells.getValue("id"))
        assertNull("a renamed `publicKey` must drop the request", cells.getValue("publicKey"))
        assertNull(
            "all five renamed — the sentence the guide actually prints — must drop the request",
            cells.getValue(allFive),
        )

        // ── Silent: the request arrives, degraded, and neither app logs a reason ──

        val noFields = cells.getValue("fields")
        assertNotNull("a renamed `fields` must still arrive", noFields)
        assertEquals(
            "…carrying no fields at all, because an absent map is repaired to emptyMap()",
            emptyMap<String, TypedField>(),
            noFields!!.entry.fields,
        )
        assertEquals("with the identity intact", entry.id, noFields.entry.id)
        assertEquals(entry.publicKey, noFields.entry.publicKey)

        val blankValues = cells.getValue("value")
        assertNotNull("a renamed `value` must still arrive", blankValues)
        assertEquals(
            "…with every field still declared",
            entry.fields.keys,
            blankValues!!.entry.fields.keys,
        )
        assertEquals("but blank", "", blankValues.entry.fields.getValue("name").value)
        assertEquals("", blankValues.entry.fields.getValue("email").value)
        assertEquals(
            "the declared type survives, so only the data is gone",
            FieldType.EMAIL,
            blankValues.entry.fields.getValue("email").type,
        )

        val stringTypes = cells.getValue("type")
        assertNotNull("a renamed `type` must still arrive", stringTypes)
        assertEquals(entry.fields.keys, stringTypes!!.entry.fields.keys)
        assertEquals(
            "the values survive",
            "ada@example.com",
            stringTypes.entry.fields.getValue("email").value,
        )
        assertEquals(
            "but an Email field is now read as a String — the quietest loss of the six",
            FieldType.STRING,
            stringTypes.entry.fields.getValue("email").type,
        )

        // ── Every serialised key of the payload classes has a cell above ──
        //
        // Taken from the two classes that declare them rather than from a literal here, so a sixth
        // serialised field cannot ship with no cell. This is *not* the only guard on that — see the
        // KDoc: a sixth key without a keep rule reddens `ConsumerRulesTest` rule 3 and one without
        // an annotation reddens `WireKeyAnnotationTest`. What is only caught here is a key that has
        // both and no cell. Nor is this derived from `consumer-rules.pro`: `ConsumerRulesTest` is
        // what ties these fields to the rules file.
        val wireKeys = listOf(Entry::class.java, TypedField::class.java)
            .flatMap { type -> type.declaredFields.toList() }
            .filterNot { Modifier.isStatic(it.modifiers) || it.isSynthetic }
            .map { field ->
                val named: SerializedName? = field.getAnnotation(SerializedName::class.java)
                assertNotNull(
                    "${field.declaringClass.simpleName}.${field.name} is serialised but names no " +
                        "wire key, so this census cannot cover it",
                    named,
                )
                named!!.value
            }
        assertEquals(
            "every serialised member key of the payload classes must have a cell above",
            wireKeys.toSet(),
            cells.keys - allFive,
        )
        assertEquals("…each exactly once", wireKeys.size, wireKeys.toSet().size)

        // The control that separates members from data, and the reason the keep rules name five
        // fields and not the profile: a *field name* is payload, so R8 never touches it and
        // renaming one costs nothing but the name.
        val renamedField = parse(rename("name" to "a"))
        assertNotNull("a renamed user field must not drop the request", renamedField)
        assertEquals(
            "field names are payload: the request survives and the field is simply called `a`",
            setOf("a", "email"),
            renamedField!!.entry.fields.keys,
        )
        assertEquals("Ada", renamedField.entry.fields.getValue("a").value)
    }

    /**
     * Two different refusals, the same pair `ResultParsingTest` pins for signatures:
     * Android's Base64 *skips* characters outside the alphabet, so `"!!!!"` decodes to zero
     * bytes without throwing while `"!!! not base64 !!!"` throws on a leftover character.
     * Both must read as "no nonce", or the vault would sign a challenge over nothing.
     */
    @Test
    fun `a garbage nonce yields no sign-challenge request`() {
        listOf(
            "!!! not base64 !!!" to "junk that throws",
            "!!!!" to "junk that silently decodes to no bytes",
            "====" to "base64 of no bytes",
            "" to "blank",
            "   " to "whitespace",
        ).forEach { (nonce, why) ->
            assertNull(
                why,
                Utils.parseSignChallengeRequest(
                    requestIntent(Utils.EXTRA_PUBLIC_KEY to "K", Utils.EXTRA_NONCE to nonce),
                ),
            )
        }
        assertNull(
            "no nonce extra at all",
            Utils.parseSignChallengeRequest(requestIntent(Utils.EXTRA_PUBLIC_KEY to "K")),
        )
    }

    @Test
    fun `a blank public key yields no request`() {
        assertNull(
            Utils.parseQueryRequest(
                requestIntent(Utils.EXTRA_PUBLIC_KEY to "   ", Utils.EXTRA_SHARE_REQUEST_CODE to "req-1"),
            ),
        )
        assertNull(
            Utils.parseSignChallengeRequest(
                requestIntent(Utils.EXTRA_PUBLIC_KEY to "", Utils.EXTRA_NONCE to "AAAA"),
            ),
        )
        assertNull(
            "no public key extra at all",
            Utils.parseQueryRequest(requestIntent(Utils.EXTRA_SHARE_REQUEST_CODE to "req-1")),
        )
    }

    @Test
    fun `a blank request code reads as absent`() {
        val query = Utils.parseQueryRequest(
            requestIntent(Utils.EXTRA_PUBLIC_KEY to "K", Utils.EXTRA_SHARE_REQUEST_CODE to "  "),
        )
        assertNotNull(query)
        assertNull(query!!.requestCode)
    }

    /** The sender picks the extra's type, not just its value. */
    @Test
    fun `wrong-typed extras read as absent`() {
        val query = Intent().apply {
            putExtra(Utils.EXTRA_PUBLIC_KEY, 42)
            putExtra(Utils.EXTRA_SHARE_REQUEST_CODE, "req-1")
        }
        assertNull("a non-String public key is no public key", Utils.parseQueryRequest(query))

        val sign = Intent().apply {
            putExtra(Utils.EXTRA_PUBLIC_KEY, "K")
            putExtra(Utils.EXTRA_NONCE, byteArrayOf(1, 2, 3))
        }
        assertNull("a non-String nonce is no nonce", Utils.parseSignChallengeRequest(sign))
    }

    /**
     * The counts pin the parsers' required-extra structure, not just their safety: a request
     * parser bails at its first missing *required* extra, so an unreadable bundle stops the
     * share parser at the entry payload (1 read), the query parser at the routing check plus
     * its public key (2), and the sign parser at its public key (1). If a count moves, a
     * required extra was reordered or a read was skipped — both worth noticing.
     */
    @Test
    fun `an intent whose extras cannot be read yields null rather than throwing`() {
        val share = UnreadableIntent()
        assertNull(Utils.parseShareRequest(share))
        assertEquals("the entry read must actually have been attempted", 1, share.reads)

        val query = UnreadableIntent()
        assertNull(Utils.parseQueryRequest(query))
        assertEquals("the routing check and the key read must both survive", 2, query.reads)

        val sign = UnreadableIntent()
        assertNull(Utils.parseSignChallengeRequest(sign))
        assertEquals("the key read must actually have been attempted", 1, sign.reads)
    }

    /**
     * The declared version is hostile like every other extra — same rule, request side:
     * unusable degrades to `null`, absent means legacy, and nothing defaults to modern.
     */
    @Test
    fun `an unusable declared protocol version reads as null`() {
        listOf("", "   ", "abc", "-1", "0", "2147483648", "2.0").forEach { value ->
            val request = Utils.parseQueryRequest(
                requestIntent(
                    Utils.EXTRA_PUBLIC_KEY to "K",
                    Utils.EXTRA_PROTOCOL_VERSION to value,
                ),
            )
            assertNotNull("the request must survive version '$value'", request)
            assertNull("version for '$value'", request!!.protocolVersion)
        }

        val legacy = Utils.parseQueryRequest(requestIntent(Utils.EXTRA_PUBLIC_KEY to "K"))
        assertNull("a legacy client declares nothing", legacy?.protocolVersion)
    }

    // ── Redaction: a request is a profile in transit ─────────────────────

    /**
     * A [ShareRequest] carries the whole [Entry], so it is the fifth copy of the T5 leak —
     * closed transitively through [Entry.toString] and [TypedField.toString], which is
     * exactly why it needs asserting: the fix is two indirections away from this class.
     */
    @Test
    fun `no request toString prints a field value`() {
        val sentinel = "SENTINEL-7QX-VALUE"
        val idSentinel = "SENTINEL-7QX-ID"
        val request = Utils.parseShareRequest(
            Utils.createShareIntent(
                context,
                Entry(
                    id = idSentinel,
                    fields = linkedMapOf("email" to TypedField(sentinel, FieldType.EMAIL)),
                    publicKey = "PUBLIC-KEY-BASE64",
                ),
                requestCode = "req-42",
            ),
        )!!

        val rendered = request.toString()
        assertFalse("a field value must never be printed", rendered.contains(sentinel))
        assertFalse("the id is redacted like a value", rendered.contains(idSentinel))
        assertTrue("field keys must appear, or this is just a constant", rendered.contains("email"))
        assertTrue("declared types must appear", rendered.contains(FieldType.EMAIL))
        assertTrue("the request code is not personal data", rendered.contains("req-42"))

        // The sign-challenge request renders its nonce as a length, never the bytes: a nonce
        // is a live challenge, and a log line is one more place to read it back from.
        val nonce = "SECRET-CHALLENGE-BYTES".toByteArray()
        val sign = SignChallengeRequest("PUBLIC-KEY-BASE64", nonce, "req-9")
        assertEquals(
            "SignChallengeRequest(publicKey=PUBLIC-KEY-BASE64, nonce=<22 bytes>, " +
                "requestCode=req-9, nonceFormat=null, protocolVersion=null)",
            sign.toString(),
        )
    }

    // ── The data-class contract on the new types ─────────────────────────

    @Test
    fun `a share request destructures into its three properties`() {
        val (decoded, requestCode, protocolVersion) = ShareRequest(entry, "req-1", 2)
        assertEquals(entry, decoded)
        assertEquals("req-1", requestCode)
        assertEquals(2, protocolVersion)
    }

    @Test
    fun `a query request destructures into its three properties`() {
        val (publicKey, requestCode, protocolVersion) = QueryRequest("pk", "req-1", 2)
        assertEquals("pk", publicKey)
        assertEquals("req-1", requestCode)
        assertEquals(2, protocolVersion)
    }

    @Test
    fun `a sign-challenge request destructures into its five properties`() {
        val (publicKey, nonce, requestCode, nonceFormat, protocolVersion) =
            SignChallengeRequest("pk", byteArrayOf(1, 2, 3), "req-1", "lim-ts1", 2)
        assertEquals("pk", publicKey)
        assertTrue(byteArrayOf(1, 2, 3).contentEquals(nonce))
        assertEquals("req-1", requestCode)
        assertEquals("lim-ts1", nonceFormat)
        assertEquals(2, protocolVersion)
    }

    @Test
    fun `share requests carrying the same values are equal`() {
        val a = ShareRequest(entry, "req-1", 2)
        val b = ShareRequest(entry, "req-1", 2)

        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
        assertNotEquals(a, a.copy(requestCode = "req-2"))
        assertNotEquals(a, a.copy(protocolVersion = null))
        assertEquals("copy must carry the values it was not asked to change", entry, a.copy(requestCode = "z").entry)
    }

    @Test
    fun `query requests carrying the same values are equal`() {
        val a = QueryRequest("pk", "req-1", 2)
        val b = QueryRequest("pk", "req-1", 2)

        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
        assertNotEquals(a, a.copy(publicKey = "other"))
        assertNotEquals(a, a.copy(requestCode = null))
        assertEquals("pk", a.copy(requestCode = "z").publicKey)
    }

    /**
     * The hand-written contract: a `ByteArray` property makes the generated `equals` compare
     * array *identity*, so like [SignChallengeResult] this class writes its own. Two requests
     * decoded from the same wire bytes must be equal, and every property must still count.
     */
    @Test
    fun `sign-challenge requests carrying the same nonce bytes are equal`() {
        val a = SignChallengeRequest("pk", byteArrayOf(1, 2, 3), "req-1", "lim-ts1", 2)
        val b = SignChallengeRequest("pk", byteArrayOf(1, 2, 3), "req-1", "lim-ts1", 2)

        assertEquals("array identity must not decide equality", a, b)
        assertEquals(a.hashCode(), b.hashCode())
        assertNotEquals(a, a.copy(nonce = byteArrayOf(9, 9, 9)))
        assertNotEquals(a, a.copy(publicKey = "other"))
        assertNotEquals(a, a.copy(requestCode = null))
        assertNotEquals(a, a.copy(nonceFormat = null))
        assertNotEquals(a, a.copy(protocolVersion = null))
        assertEquals("pk", a.copy(requestCode = "z").publicKey)
    }
}
