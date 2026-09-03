package dev.eryalabs.lim

import android.util.Base64
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.RuntimeEnvironment
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.Locale

/**
 * The bytes that get signed.
 *
 * Every signature scheme lives or dies on the exact pre-image: if signer and verifier can
 * disagree by one byte the mechanism is theatre, and if two *different* statements can produce
 * the same bytes then a signature over one is a signature over the other. So this file pins the
 * format as a literal, the way `IntentBuilderTest` pins the wire, and then attacks it — one test
 * per component that must be inside the signed bytes, a collision pair that a naive
 * concatenation would merge, and the same assertions re-run under a locale whose digits are not
 * ASCII.
 *
 * The other half is the signing-oracle guard. `Utils.createSignChallengeIntent` will carry any
 * bytes at all and `Utils.parseSignChallengeRequest` accepts any non-empty Base64-decodable
 * nonce, so a rotation pre-image can arrive at a vault dressed as a login challenge. The domain
 * prefix is what lets the signing device notice, and the tests below feed a pre-image through
 * that exact round trip rather than merely asserting the predicate on bytes built in place.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class StatementPreImageTest {

    /**
     * The statement the frozen literal below is the pre-image of. Values are short and boring on
     * purpose: a reader checking the layout by eye should be able to find each one in the bytes.
     */
    private val fixed = RotationStatement(
        oldPublicKey = "K-OLD",
        newPublicKey = "K-NEW",
        statementId = "rot-0001",
        issuedAtMillis = 1_770_000_000_000L,
        expiresAtMillis = 1_770_000_600_000L,
    )

    /** Every assertion that touches [Locale] restores it here, whether it passed or failed. */
    private val defaultLocale: Locale = Locale.getDefault()

    @After
    fun restoreLocale() {
        Locale.setDefault(defaultLocale)
    }

    // ── The format, frozen ───────────────────────────────────────────────

    @Test
    fun `the domain prefix and the kind tag match the wire literals`() {
        // Spelled out rather than referenced: these strings travel inside signatures that a peer
        // implementation has to reproduce, so changing one is changing the protocol.
        assertEquals("lim.statement.v1", Utils.STATEMENT_DOMAIN_V1)
        assertEquals("lim.rotate.v1", Utils.STATEMENT_ROTATE_V1)
    }

    /**
     * The pinned pre-image, checked two ways.
     *
     * The Base64 literal is the change-detector: a format edit moves it, and moving it is then a
     * deliberate act in a diff rather than a silent break of every signature ever issued. The
     * hand-built comparison beside it is what makes the literal mean something on the day it was
     * written — [handBuiltPreImage] encodes the documented layout through a completely different
     * mechanism ([ByteBuffer], not a shift loop) and does not call [Utils] at all, so a literal
     * captured from a buggy encoder would not survive it.
     */
    @Test
    fun `the pre-image of a fixed statement is frozen`() {
        val actual = Utils.rotationStatementBytes(fixed)

        assertArrayEquals(
            "the encoder disagrees with the documented layout",
            handBuiltPreImage(
                kind = "lim.rotate.v1",
                texts = listOf("K-OLD", "K-NEW", "rot-0001"),
                timestamps = listOf(1_770_000_000_000L, 1_770_000_600_000L),
            ),
            actual,
        )
        assertEquals(
            "the canonical pre-image changed. Every signature ever issued verifies against the " +
                "old bytes, so this literal moves only when the format is deliberately revised " +
                "— and revising it means a new domain or kind tag, not an edit to this line",
            PINNED_PRE_IMAGE,
            Base64.encodeToString(actual, Base64.NO_WRAP),
        )
        assertEquals("the layout is a fixed 79 bytes for these components", 79, actual.size)
    }

    @Test
    fun `the same statement always produces the same bytes`() {
        val once = Utils.rotationStatementBytes(fixed)
        val twice = Utils.rotationStatementBytes(fixed)
        assertArrayEquals("repeated calls must not differ", once, twice)

        // Independently constructed, not copied: `copy()` would share the same strings, and
        // string identity is exactly what a canonical encoding must not depend on.
        val rebuilt = RotationStatement(
            oldPublicKey = buildString { append("K-"); append("OLD") },
            newPublicKey = buildString { append("K-"); append("NEW") },
            statementId = buildString { append("rot-"); append("0001") },
            issuedAtMillis = 1_770_000_000_000L,
            expiresAtMillis = 1_770_000_600_000L,
        )
        assertEquals("the two statements must be equal to begin with", fixed, rebuilt)
        assertArrayEquals(
            "two equal statements must sign to identical bytes",
            once,
            Utils.rotationStatementBytes(rebuilt),
        )
    }

    /**
     * The length prefixes make the pre-image *readable*, not merely comparable — which is what a
     * transport envelope carrying one depends on. Pinned here rather than left an accident of
     * the layout: [PreImageReader] walks the bytes back to components with no knowledge of the
     * statement it came from, and finishes exactly at the end.
     */
    @Test
    fun `the pre-image reads back component for component`() {
        val reader = PreImageReader(Utils.rotationStatementBytes(fixed))

        assertEquals("lim.statement.v1", reader.fixedText("lim.statement.v1".length))
        assertEquals("lim.rotate.v1", reader.text())
        assertEquals("K-OLD", reader.text())
        assertEquals("K-NEW", reader.text())
        assertEquals("rot-0001", reader.text())
        assertEquals(1_770_000_000_000L, reader.long())
        assertEquals(1_770_000_600_000L, reader.long())
        assertTrue("nothing may be left over after the last component", reader.atEnd())
    }

    /**
     * A multi-byte component still delimits, because the prefix counts *bytes* and not
     * characters. A prefix counting characters would under-run by exactly the number of
     * continuation bytes and drag the next component's head into this one — a decoder that then
     * reads a different statement out of the same signed bytes.
     */
    @Test
    fun `a multi-byte component is length-prefixed in bytes`() {
        // A letter that survives a UTF-8 source file unchanged, unlike the NUL and lone
        // surrogate `DecoderFuzzTest` has to spell numerically. The control below is what says
        // it is genuinely multi-byte, so a build that mangled the encoding fails loudly here
        // rather than passing with a one-byte character.
        val multiByte = "rot-ééé"
        val statement = fixed.copy(statementId = multiByte)
        val reader = PreImageReader(Utils.rotationStatementBytes(statement))

        assertEquals(
            "control: this id must genuinely take more bytes than characters",
            multiByte.length + 3,
            multiByte.toByteArray(Charsets.UTF_8).size,
        )
        reader.fixedText("lim.statement.v1".length)
        reader.text()
        reader.text()
        reader.text()
        assertEquals(multiByte, reader.text())
        assertEquals(1_770_000_000_000L, reader.long())
        assertEquals(1_770_000_600_000L, reader.long())
        assertTrue(reader.atEnd())
    }

    // ── Negative controls: every component is in there ───────────────────
    //
    // One test apiece rather than a loop, so a failure names the component that fell out of the
    // signature. The one that matters most is `newPublicKey`: a pre-image omitting it would let
    // any key at all be swapped in under a genuine signature.

    @Test
    fun `changing the old public key changes the bytes`() =
        assertDistinct(fixed, fixed.copy(oldPublicKey = "K-OTHER"))

    @Test
    fun `changing the new public key changes the bytes`() =
        assertDistinct(fixed, fixed.copy(newPublicKey = "K-ATTACKER"))

    @Test
    fun `changing the statement id changes the bytes`() =
        assertDistinct(fixed, fixed.copy(statementId = "rot-0002"))

    @Test
    fun `changing the issued timestamp changes the bytes`() =
        assertDistinct(fixed, fixed.copy(issuedAtMillis = fixed.issuedAtMillis + 1))

    @Test
    fun `changing the expiry timestamp changes the bytes`() =
        assertDistinct(fixed, fixed.copy(expiresAtMillis = fixed.expiresAtMillis + 1))

    /**
     * A negative timestamp is two's complement and round-trips like any other value.
     *
     * The encoder's KDoc claims this and nothing else asserted it. It is not a curiosity: a
     * statement's timestamps arrive from a peer, so `Long.MIN_VALUE` and `-1` are exactly what a
     * hostile or clock-broken device puts there, and T15 will compare those values against a
     * window. A `shr` in place of `ushr` is equivalent under the encoder's `and 0xFF` mask, so
     * the mutant this kills is a *width* or sign-extension slip that collapses two distinct
     * negative timestamps onto one pre-image.
     */
    @Test
    fun `negative timestamps encode distinctly and read back`() {
        assertDistinct(
            fixed.copy(issuedAtMillis = Long.MIN_VALUE),
            fixed.copy(issuedAtMillis = -1L),
        )
        assertDistinct(fixed.copy(expiresAtMillis = -1L), fixed.copy(expiresAtMillis = 0L))

        val extreme = fixed.copy(issuedAtMillis = Long.MIN_VALUE, expiresAtMillis = Long.MAX_VALUE)
        val reader = PreImageReader(Utils.rotationStatementBytes(extreme))
        reader.fixedText("lim.statement.v1".length)
        repeat(4) { reader.text() }
        assertEquals(Long.MIN_VALUE, reader.long())
        assertEquals(Long.MAX_VALUE, reader.long())
        assertTrue("eight bytes each, whatever the sign", reader.atEnd())
    }

    /**
     * The degenerate end of the collision family below: an empty component is still a component,
     * and its zero-length prefix is what keeps it from vanishing. Without the prefix, `("", "AB")`
     * and `("A", "B")` would both encode as `AB` — a rotation onto no key at all sharing bytes
     * with a rotation onto a real one.
     */
    @Test
    fun `an empty component does not vanish from the pre-image`() {
        val empty = RotationStatement("", "AB", "id", 1L, 2L)
        val split = RotationStatement("A", "B", "id", 1L, 2L)

        assertNotEquals(empty, split)
        assertDistinct(empty, split)

        val reader = PreImageReader(Utils.rotationStatementBytes(empty))
        reader.fixedText("lim.statement.v1".length)
        reader.text()
        assertEquals("the empty component must read back as empty, not be skipped", "", reader.text())
        assertEquals("AB", reader.text())
    }

    /**
     * The collision a naive encoder makes. Both statements below concatenate to the same string
     * — `"AB" + "C"` and `"A" + "BC"` — so an encoder joining components without delimiting them
     * would hand the same bytes to the signer for a rotation onto `"C"` and a rotation onto
     * `"BC"`. Length prefixes are what stop one signature from being both.
     */
    @Test
    fun `two statements that concatenate alike produce different bytes`() {
        val left = RotationStatement("AB", "C", "id", 1L, 2L)
        val right = RotationStatement("A", "BC", "id", 1L, 2L)

        assertNotEquals("the two statements must genuinely differ", left, right)
        assertDistinct(left, right)
    }

    /**
     * The same trap one component further along: a `statementId` that ends exactly where the
     * next component would begin. Here the boundary is between text and a timestamp, so the
     * bytes an undelimited encoder would produce line up digit for digit.
     */
    @Test
    fun `a statement id ending at a component boundary does not collide`() {
        val left = RotationStatement("K", "K2", "abc", 1L, 2L)
        val right = RotationStatement("K", "K2a", "bc", 1L, 2L)

        assertNotEquals(left, right)
        assertDistinct(left, right)
    }

    /**
     * The check that catches a `String.format("%d")` hidden in the encoder.
     *
     * Under `ar-EG` the JDK's locale-sensitive number formatting emits Eastern Arabic-Indic
     * digits, so a pre-image built from formatted numbers would come out different bytes on a
     * phone set to Arabic — a signature that verifies in one language and not another. The
     * timestamps here travel as raw milliseconds precisely so that no calendar, timezone or
     * locale can reach them.
     */
    @Test
    fun `the pre-image does not change under another locale`() {
        val expected = Utils.rotationStatementBytes(fixed)

        Locale.setDefault(Locale.forLanguageTag("ar-EG"))

        assertArrayEquals("the locale must not reach the pre-image", expected, Utils.rotationStatementBytes(fixed))
        assertEquals(
            "the pinned literal must hold under any locale too",
            PINNED_PRE_IMAGE,
            Base64.encodeToString(Utils.rotationStatementBytes(fixed), Base64.NO_WRAP),
        )
        // The control: without it this test would pass on a JDK where `ar-EG` happens to format
        // digits as ASCII anyway, and would then be asserting nothing about locale sensitivity.
        // Stated as "not ASCII" rather than pinning the Arabic-Indic digits, because the exact
        // glyphs come from the JDK's locale data and are not this library's to freeze.
        assertNotEquals(
            "control: this locale must genuinely format digits differently, or the test above " +
                "cannot fail",
            "123",
            String.format(Locale.getDefault(), "%d", 123),
        )
    }

    /**
     * Recorded rather than discovered later: no `String` can encode an unpaired surrogate to
     * UTF-8, so one collides with the `?` the encoder substitutes. The equivalence is real and
     * it is documented on `Utils.rotationStatementBytes`; it is out of reach of this protocol,
     * whose components are Base64 keys and opaque printable ids.
     */
    @Test
    fun `an unpaired surrogate is the one input the encoding cannot separate`() {
        val surrogate = fixed.copy(statementId = "\ud83d")
        val substitute = fixed.copy(statementId = "?")

        assertNotEquals("the two statements differ", surrogate, substitute)
        assertArrayEquals(
            "known and documented: UTF-8 has no encoding for a lone surrogate",
            Utils.rotationStatementBytes(substitute),
            Utils.rotationStatementBytes(surrogate),
        )
    }

    // ── toString ─────────────────────────────────────────────────────────

    @Test
    fun `toString previews both real keys, truncated and distinct`() {
        val statement = RotationStatement(oldKeyBase64, newKeyBase64, "rot-0001", 1L, 2L)
        val rendered = statement.toString()

        assertFalse("the whole old key must not be printed", rendered.contains(oldKeyBase64))
        assertFalse("the whole new key must not be printed", rendered.contains(newKeyBase64))
        assertTrue(
            "each key must appear previewed; got $rendered",
            rendered.contains(oldKeyBase64.take(PUBLIC_KEY_PREVIEW_CHARS)) &&
                rendered.contains(newKeyBase64.take(PUBLIC_KEY_PREVIEW_CHARS)),
        )
        // The property a preview exists for: two X.509 RSA keys share their first 44 characters,
        // so a shorter preview would render every rotation identically.
        assertEquals(
            "two real keys must share the fixed DER header",
            oldKeyBase64.take(44),
            newKeyBase64.take(44),
        )
        assertNotEquals(
            "the two previews must still be distinguishable",
            oldKeyBase64.take(PUBLIC_KEY_PREVIEW_CHARS),
            newKeyBase64.take(PUBLIC_KEY_PREVIEW_CHARS),
        )
        // Named in full rather than by `contains("rot-0001")` alone: dropping the timestamps from
        // the override left the whole suite green, and a window is the first thing a reader wants
        // from a rotation that a service just refused as expired.
        assertEquals(
            "the id and both timestamps must print in full",
            "RotationStatement(oldPublicKey=${previewedPublicKey(oldKeyBase64)}, " +
                "newPublicKey=${previewedPublicKey(newKeyBase64)}, statementId=rot-0001, " +
                "issuedAtMillis=1, expiresAtMillis=2)",
            rendered,
        )
    }

    // ── The signing-oracle guard ─────────────────────────────────────────

    @Test
    fun `a real pre-image is recognised`() {
        assertTrue(Utils.isStatementPreImage(Utils.rotationStatementBytes(fixed)))
        // Trailing bytes are irrelevant: this is a prefix test, and a statement wrapped in
        // anything longer is still a statement about to be signed.
        assertTrue(Utils.isStatementPreImage(Utils.rotationStatementBytes(fixed) + byteArrayOf(9, 9)))
        // And the prefix alone, which is the shortest thing that must be refused by a signer.
        assertTrue(Utils.isStatementPreImage(Utils.STATEMENT_DOMAIN_V1.toByteArray(Charsets.UTF_8)))
    }

    /**
     * The attack shape, played out rather than asserted on bytes built in place: the pre-image
     * travels as the `nonce` of an ordinary sign-challenge request, exactly as an attacker would
     * send it, and the vault's own parser hands it back. The predicate has to hold on *that*
     * array — the one a vault is holding when it decides whether to sign.
     */
    @Test
    fun `a pre-image arriving as a sign-challenge nonce is recognised`() {
        val preImage = Utils.rotationStatementBytes(
            RotationStatement(oldKeyBase64, newKeyBase64, "rot-attack", 1L, 2L),
        )
        val intent = Utils.createSignChallengeIntent(
            context = RuntimeEnvironment.getApplication(),
            publicKey = oldKeyBase64,
            nonce = preImage,
            requestCode = "req-1",
        )

        val request = Utils.parseSignChallengeRequest(intent)
        assertNotNull("the hostile request must parse — refusing it is a human decision", request)
        assertArrayEquals("the nonce must survive the round trip", preImage, request!!.nonce)
        assertTrue(
            "a vault holding this nonce must be able to see it is a statement, or the whole " +
                "domain prefix buys nothing",
            Utils.isStatementPreImage(request.nonce),
        )
    }

    @Test
    fun `a generated nonce is not a pre-image`() {
        repeat(50) {
            val nonce = Utils.generateNonce()
            assertFalse(
                "a genuine challenge must never be mistaken for a statement",
                Utils.isStatementPreImage(nonce),
            )
        }
        assertFalse(Utils.isStatementPreImage(Utils.generateNonce(now = 1_770_000_000_000L)))
    }

    @Test
    fun `isStatementPreImage refuses null, empty and anything short of the prefix`() {
        assertFalse("null", Utils.isStatementPreImage(null))
        assertFalse("empty", Utils.isStatementPreImage(ByteArray(0)))

        val prefix = Utils.STATEMENT_DOMAIN_V1.toByteArray(Charsets.UTF_8)
        assertFalse(
            "one byte short of the prefix must not match, not read past the end",
            Utils.isStatementPreImage(prefix.copyOf(prefix.size - 1)),
        )
        assertFalse("a zero-filled array of the right length", Utils.isStatementPreImage(ByteArray(prefix.size)))

        // The last byte differing is the case a length-only check would wave through.
        val nearMiss = prefix.copyOf()
        nearMiss[nearMiss.size - 1] = (nearMiss[nearMiss.size - 1] + 1).toByte()
        assertFalse("a prefix differing in its last byte", Utils.isStatementPreImage(nearMiss))

        // And the first, which is the case a check starting at the wrong offset would.
        val firstByteWrong = prefix.copyOf()
        firstByteWrong[0] = (firstByteWrong[0] + 1).toByte()
        assertFalse("a prefix differing in its first byte", Utils.isStatementPreImage(firstByteWrong))

        assertFalse("the domain prefix shifted by one byte", Utils.isStatementPreImage(byteArrayOf(0) + prefix))
    }

    // ── Composition with the existing verifier ───────────────────────────

    /**
     * Nothing in this library signs. So the proof that the bytes are usable is that a real key
     * signs them with the primitive the protocol already uses, and `Utils.verifySignature` — the
     * one this library ships, untouched — accepts it. A statement tampered with after signing
     * does not verify, which is the end-to-end complement of the byte-level controls above.
     */
    @Test
    fun `a statement signed with a real key verifies through verifySignature`() {
        val preImage = Utils.rotationStatementBytes(fixed)
        val signature = Signature.getInstance("SHA256withRSA").run {
            initSign(oldKeyPair.private)
            update(preImage)
            sign()
        }

        assertTrue(
            "the pre-image must be signable and verifiable with the library's own verifier",
            Utils.verifySignature(oldKeyBase64, preImage, signature),
        )
        assertFalse(
            "a statement edited after signing must not verify",
            Utils.verifySignature(
                oldKeyBase64,
                Utils.rotationStatementBytes(fixed.copy(newPublicKey = "K-ATTACKER")),
                signature,
            ),
        )
        assertFalse(
            "another key must not verify it",
            Utils.verifySignature(newKeyBase64, preImage, signature),
        )
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    private fun assertDistinct(left: RotationStatement, right: RotationStatement) {
        val leftBytes = Utils.rotationStatementBytes(left)
        val rightBytes = Utils.rotationStatementBytes(right)
        assertFalse(
            "two different statements share a pre-image, so a signature over one is a " +
                "signature over the other:\n  $left\n  $right",
            leftBytes.contentEquals(rightBytes),
        )
    }

    private fun assertArrayEquals(message: String, expected: ByteArray, actual: ByteArray) {
        assertTrue(
            "$message\n  expected = ${Base64.encodeToString(expected, Base64.NO_WRAP)}" +
                "\n  actual   = ${Base64.encodeToString(actual, Base64.NO_WRAP)}",
            expected.contentEquals(actual),
        )
    }

    /**
     * The documented layout, encoded independently of [Utils]: a fixed domain prefix, then each
     * text component as a four-byte big-endian *byte* length followed by its UTF-8 bytes, then
     * each timestamp as eight big-endian bytes. Written through [ByteBuffer] rather than through
     * a shift loop, so an endianness slip in the encoder cannot be mirrored here by accident.
     */
    private fun handBuiltPreImage(
        kind: String,
        texts: List<String>,
        timestamps: List<Long>,
    ): ByteArray {
        val pieces = mutableListOf<ByteArray>()
        pieces += "lim.statement.v1".toByteArray(Charsets.UTF_8)
        (listOf(kind) + texts).forEach { text ->
            val encoded = text.toByteArray(Charsets.UTF_8)
            pieces += ByteBuffer.allocate(4).putInt(encoded.size).array()
            pieces += encoded
        }
        timestamps.forEach { pieces += ByteBuffer.allocate(8).putLong(it).array() }

        val out = ByteArray(pieces.sumOf { it.size })
        var offset = 0
        pieces.forEach { piece ->
            piece.copyInto(out, offset)
            offset += piece.size
        }
        return out
    }

    /**
     * Walks a pre-image back to its components knowing only the layout — no statement, no
     * expected lengths. If a length prefix were wrong, or a component could run into the next,
     * this would read the wrong string or run off the end rather than quietly agreeing.
     */
    private class PreImageReader(private val bytes: ByteArray) {
        private var offset = 0

        fun fixedText(length: Int): String {
            val text = String(bytes, offset, length, Charsets.UTF_8)
            offset += length
            return text
        }

        fun text(): String {
            val length = readInt()
            check(length >= 0 && offset + length <= bytes.size) {
                "component length $length does not fit in the remaining ${bytes.size - offset} bytes"
            }
            return fixedText(length)
        }

        fun long(): Long {
            var value = 0L
            repeat(8) {
                value = (value shl 8) or (bytes[offset].toLong() and 0xFF)
                offset++
            }
            return value
        }

        fun atEnd(): Boolean = offset == bytes.size

        private fun readInt(): Int {
            var value = 0
            repeat(4) {
                value = (value shl 8) or (bytes[offset].toInt() and 0xFF)
                offset++
            }
            return value
        }
    }

    companion object {
        /**
         * The frozen canonical pre-image of the statement in [fixed], Base64 with no wrapping.
         *
         * Captured once from a run that also passed the hand-built comparison beside it, and a
         * change-detector from then on: every signature any device has ever issued verifies
         * against these bytes and no others, so a format revision means a new domain or kind
         * tag, never an edit to this line.
         */
        private const val PINNED_PRE_IMAGE =
            "bGltLnN0YXRlbWVudC52MQAAAA1saW0ucm90YXRlLnYxAAAABUstT0xEAAAABUstTkVXAAAACHJvdC0wMDAxAAABnBw4pAAAAAGcHEHLwA=="

        private lateinit var oldKeyPair: KeyPair
        private lateinit var oldKeyBase64: String
        private lateinit var newKeyBase64: String

        /** 2048-bit RSA generation is slow (~100ms each); do it once for the whole class. */
        @JvmStatic
        @BeforeClass
        fun generateKeys() {
            fun generate() = KeyPairGenerator.getInstance("RSA")
                .apply { initialize(2048) }
                .generateKeyPair()

            oldKeyPair = generate()
            oldKeyBase64 = Base64.encodeToString(oldKeyPair.public.encoded, Base64.NO_WRAP)
            newKeyBase64 = Base64.encodeToString(generate().public.encoded, Base64.NO_WRAP)
        }
    }
}
