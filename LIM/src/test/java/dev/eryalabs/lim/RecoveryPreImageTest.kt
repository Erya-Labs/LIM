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
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.util.Locale

/**
 * The bytes the other two statement kinds are signed over.
 *
 * `StatementPreImageTest` pins the encoder itself against a rotation; this pins what the same
 * encoder produces for a [RecoveryAuthorization] and a [Revocation], and — the part that only
 * becomes expressible once more than one kind exists — that the three kinds cannot be confused
 * for one another.
 *
 * **Why cross-type confusion is the test that matters here.** A rotation and a recovery
 * authorization carry the same shapes of component: two keys, an opaque id, two 64-bit numbers.
 * If the kind tag were absent from the signed bytes, a signature the user made over a rotation —
 * "replace my key today, inside this ten-minute window" — would also be a valid signature over an
 * authorization saying "this device may replace my key at any time, for ever, with no expiry".
 * The tag is the only thing standing between those two sentences, so it is asserted directly
 * rather than trusted to be in there somewhere.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class RecoveryPreImageTest {

    /**
     * The instances the frozen literals below are the pre-images of. Short, boring values on
     * purpose: a reader checking the layout by eye should be able to find each one in the bytes.
     */
    private val authorization = RecoveryAuthorization(
        subjectPublicKey = "K-SUBJECT",
        recoveryPublicKey = "K-RECOVERY",
        authorizationId = "rec-0001",
        sequence = 7L,
        issuedAtMillis = 1_770_000_000_000L,
    )

    private val revocation = Revocation(
        subjectPublicKey = "K-SUBJECT",
        revokedAuthorizationId = "rec-0001",
        sequence = 8L,
        issuedAtMillis = 1_770_000_000_000L,
    )

    /** Every assertion that touches [Locale] restores it here, whether it passed or failed. */
    private val defaultLocale: Locale = Locale.getDefault()

    @After
    fun restoreLocale() {
        Locale.setDefault(defaultLocale)
    }

    // ── The format, frozen ───────────────────────────────────────────────

    @Test
    fun `the recovery and revocation kind tags match the wire literals`() {
        // Spelled out rather than referenced: these strings travel inside signatures a peer
        // implementation has to reproduce, so changing one is changing the protocol.
        assertEquals("lim.recover.v1", Utils.STATEMENT_RECOVER_V1)
        assertEquals("lim.revoke.v1", Utils.STATEMENT_REVOKE_V1)

        // And they are three distinct strings, which is the property the whole domain separation
        // rests on. Asserted rather than assumed: two tags that happened to be equal would make
        // every cross-type control below pass for the wrong reason — by never being reached.
        assertEquals(
            "the three kind tags must be distinct",
            3,
            setOf(
                Utils.STATEMENT_ROTATE_V1,
                Utils.STATEMENT_RECOVER_V1,
                Utils.STATEMENT_REVOKE_V1,
            ).size,
        )
    }

    /**
     * The pinned pre-image, checked two ways — the pattern `StatementPreImageTest` sets. The
     * Base64 literal is the change-detector; [handBuiltPreImage] beside it encodes the documented
     * layout through a different mechanism ([ByteBuffer], not a shift loop) and does not call
     * [Utils] at all, so a literal captured from a buggy encoder would not survive it.
     */
    @Test
    fun `the pre-image of a fixed recovery authorization is frozen`() {
        val actual = Utils.recoveryAuthorizationBytes(authorization)

        assertArrayEquals(
            "the encoder disagrees with the documented layout",
            handBuiltPreImage(
                kind = "lim.recover.v1",
                texts = listOf("K-SUBJECT", "K-RECOVERY", "rec-0001"),
                longs = listOf(7L, 1_770_000_000_000L),
            ),
            actual,
        )
        assertEquals(
            "the canonical pre-image changed. Every authorization ever signed verifies against " +
                "the old bytes — and an authorization has no expiry, so old ones stay live " +
                "indefinitely. Revising the format means a new kind tag, not an edit to this line",
            PINNED_RECOVERY_PRE_IMAGE,
            Base64.encodeToString(actual, Base64.NO_WRAP),
        )
        assertEquals("the layout is a fixed 89 bytes for these components", 89, actual.size)
    }

    @Test
    fun `the pre-image of a fixed revocation is frozen`() {
        val actual = Utils.revocationBytes(revocation)

        assertArrayEquals(
            "the encoder disagrees with the documented layout",
            handBuiltPreImage(
                kind = "lim.revoke.v1",
                texts = listOf("K-SUBJECT", "rec-0001"),
                longs = listOf(8L, 1_770_000_000_000L),
            ),
            actual,
        )
        assertEquals(
            "the canonical pre-image changed; a revocation nobody can verify is a stolen device " +
                "nobody can shut off",
            PINNED_REVOCATION_PRE_IMAGE,
            Base64.encodeToString(actual, Base64.NO_WRAP),
        )
        assertEquals("the layout is a fixed 74 bytes for these components", 74, actual.size)
    }

    @Test
    fun `equal statements always produce the same bytes`() {
        assertArrayEquals(
            "repeated calls must not differ",
            Utils.recoveryAuthorizationBytes(authorization),
            Utils.recoveryAuthorizationBytes(authorization),
        )
        assertArrayEquals(
            "repeated calls must not differ",
            Utils.revocationBytes(revocation),
            Utils.revocationBytes(revocation),
        )

        // Independently constructed, not copied: `copy()` would share the same string instances,
        // and string identity is exactly what a canonical encoding must not depend on.
        val rebuiltAuthorization = RecoveryAuthorization(
            subjectPublicKey = buildString { append("K-"); append("SUBJECT") },
            recoveryPublicKey = buildString { append("K-"); append("RECOVERY") },
            authorizationId = buildString { append("rec-"); append("0001") },
            sequence = 7L,
            issuedAtMillis = 1_770_000_000_000L,
        )
        val rebuiltRevocation = Revocation(
            subjectPublicKey = buildString { append("K-"); append("SUBJECT") },
            revokedAuthorizationId = buildString { append("rec-"); append("0001") },
            sequence = 8L,
            issuedAtMillis = 1_770_000_000_000L,
        )

        assertEquals("the two must be equal to begin with", authorization, rebuiltAuthorization)
        assertEquals("the two must be equal to begin with", revocation, rebuiltRevocation)
        assertArrayEquals(
            "two equal authorizations must sign to identical bytes",
            Utils.recoveryAuthorizationBytes(authorization),
            Utils.recoveryAuthorizationBytes(rebuiltAuthorization),
        )
        assertArrayEquals(
            "two equal revocations must sign to identical bytes",
            Utils.revocationBytes(revocation),
            Utils.revocationBytes(rebuiltRevocation),
        )
    }

    /**
     * The length prefixes make each pre-image readable back rather than merely comparable, which
     * is what T18's envelope depends on. [PreImageReader] walks the bytes with no knowledge of the
     * statement they came from and must finish exactly at the end — and the kind tag it reads is
     * asserted here, since that is the component the cross-type controls below turn on.
     */
    @Test
    fun `each pre-image reads back component for component`() {
        val recovery = PreImageReader(Utils.recoveryAuthorizationBytes(authorization))
        assertEquals("lim.statement.v1", recovery.fixedText(Utils.STATEMENT_DOMAIN_V1.length))
        assertEquals("the kind must be inside the signed bytes", "lim.recover.v1", recovery.text())
        assertEquals("K-SUBJECT", recovery.text())
        assertEquals("K-RECOVERY", recovery.text())
        assertEquals("rec-0001", recovery.text())
        assertEquals(7L, recovery.long())
        assertEquals(1_770_000_000_000L, recovery.long())
        assertTrue("nothing may be left over after the last component", recovery.atEnd())

        val revoke = PreImageReader(Utils.revocationBytes(revocation))
        assertEquals("lim.statement.v1", revoke.fixedText(Utils.STATEMENT_DOMAIN_V1.length))
        assertEquals("the kind must be inside the signed bytes", "lim.revoke.v1", revoke.text())
        assertEquals("K-SUBJECT", revoke.text())
        assertEquals("rec-0001", revoke.text())
        assertEquals(8L, revoke.long())
        assertEquals(1_770_000_000_000L, revoke.long())
        assertTrue("nothing may be left over after the last component", revoke.atEnd())
    }

    // ── Cross-type confusion ─────────────────────────────────────────────

    /**
     * The control this whole task exists around. Two statements whose components are *pairwise
     * identical* — same keys, same id, same two numbers — differ only in what they mean, and what
     * they mean is the kind tag. A rotation says "replace my key inside this window"; an
     * authorization says "this device may replace my key at any time, for ever". A signature over
     * one must never be a signature over the other.
     */
    @Test
    fun `a rotation and a recovery authorization with identical components differ in bytes`() {
        val rotation = RotationStatement(
            oldPublicKey = authorization.subjectPublicKey,
            newPublicKey = authorization.recoveryPublicKey,
            statementId = authorization.authorizationId,
            issuedAtMillis = authorization.sequence,
            expiresAtMillis = authorization.issuedAtMillis,
        )

        val rotationBytes = Utils.rotationStatementBytes(rotation)
        val recoveryBytes = Utils.recoveryAuthorizationBytes(authorization)

        // The control: everything except the kind is the same, so if these bytes were to differ
        // for some other reason the test would be pinning the wrong thing.
        assertEquals(
            "control: the two pre-images must differ by exactly the kind tag's bytes, or this " +
                "test is passing for an unrelated reason",
            recoveryBytes.size - rotationBytes.size,
            "lim.recover.v1".length - "lim.rotate.v1".length,
        )
        assertFalse(
            "a rotation and an authorization built from the same components share a pre-image, " +
                "so a signature over a ten-minute rotation is also a signature over a permanent " +
                "standing credential",
            rotationBytes.contentEquals(recoveryBytes),
        )
        assertEquals(
            "and the difference must be the kind, not an accident of length",
            "lim.recover.v1",
            PreImageReader(recoveryBytes)
                .also { it.fixedText(Utils.STATEMENT_DOMAIN_V1.length) }
                .text(),
        )
    }

    /**
     * The third pair. A revocation carries one fewer component than an authorization, so a naive
     * encoder might still separate them by length alone — this asserts the kind rather than
     * relying on that, since a revocation and an authorization sharing bytes would mean cancelling
     * a device and blessing one were the same signature.
     */
    @Test
    fun `a revocation and a recovery authorization do not share a pre-image`() {
        assertFalse(
            "cancelling a device and blessing one must not be the same bytes",
            Utils.revocationBytes(revocation)
                .contentEquals(Utils.recoveryAuthorizationBytes(authorization)),
        )

        // The sharper version: an authorization whose recovery key is empty encodes the same
        // *components* a revocation does — a zero-length text where the second key would be — so
        // only the kind tag separates the two.
        val degenerate = RecoveryAuthorization(
            subjectPublicKey = revocation.subjectPublicKey,
            recoveryPublicKey = "",
            authorizationId = revocation.revokedAuthorizationId,
            sequence = revocation.sequence,
            issuedAtMillis = revocation.issuedAtMillis,
        )
        assertFalse(
            "an empty component must not let the two kinds collapse together",
            Utils.revocationBytes(revocation)
                .contentEquals(Utils.recoveryAuthorizationBytes(degenerate)),
        )
    }

    /**
     * The third pairing, completing the triangle — and the one whose kind tags are the same
     * length, which makes it the place a future edit is most likely to make two kinds
     * indistinguishable by size alone: `lim.rotate.v1` and `lim.revoke.v1` are both thirteen bytes
     * and differ only from their fourth character.
     *
     * **What each assertion below actually carries**, stated because the first is weaker than it
     * looks. The two layouts differ in *arity* — a rotation has a third text component where a
     * revocation has none — so the `contentEquals` refusal holds whatever tag is used: it is a
     * structural check, not a tag-driven one, and planting `STATEMENT_ROTATE_V1` into
     * `revocationBytes` leaves it green (the frozen literal and the read-back test are what kill
     * that mutant). The load-bearing lines here are the other two — the equal-tag-length control,
     * which is what makes this pair worth its own test, and the tag read back out of the bytes.
     */
    @Test
    fun `a rotation and a revocation do not share a pre-image`() {
        // A rotation whose components are the revocation's, in the same slots, with the one extra
        // component a rotation carries left empty — the closest the two shapes can be brought.
        val rotation = RotationStatement(
            oldPublicKey = revocation.subjectPublicKey,
            newPublicKey = "",
            statementId = revocation.revokedAuthorizationId,
            issuedAtMillis = revocation.sequence,
            expiresAtMillis = revocation.issuedAtMillis,
        )

        assertFalse(
            "moving an account and cancelling a recovery device must not be the same bytes",
            Utils.rotationStatementBytes(rotation)
                .contentEquals(Utils.revocationBytes(revocation)),
        )
        assertEquals(
            "control: the two kind tags are the same length, so only their contents separate " +
                "these kinds",
            Utils.STATEMENT_ROTATE_V1.length,
            Utils.STATEMENT_REVOKE_V1.length,
        )
        assertEquals(
            "lim.rotate.v1",
            PreImageReader(Utils.rotationStatementBytes(rotation))
                .also { it.fixedText(Utils.STATEMENT_DOMAIN_V1.length) }
                .text(),
        )
    }

    // ── Negative controls: every component is in the signed bytes ─────────
    //
    // One test apiece rather than a loop, so a failure names the component that fell out. The
    // sequence is the one to watch: a pre-image blind to it would let a captured revocation be
    // renumbered, and the monotonic ordering that makes revocation safe would be decoration.

    @Test
    fun `changing the authorization subject key changes the bytes`() =
        assertAuthorizationsDistinct(authorization, authorization.copy(subjectPublicKey = "K-OTHER"))

    @Test
    fun `changing the recovery key changes the bytes`() =
        assertAuthorizationsDistinct(
            authorization,
            authorization.copy(recoveryPublicKey = "K-ATTACKER"),
        )

    @Test
    fun `changing the authorization id changes the bytes`() =
        assertAuthorizationsDistinct(authorization, authorization.copy(authorizationId = "rec-0002"))

    @Test
    fun `changing the authorization sequence changes the bytes`() =
        assertAuthorizationsDistinct(authorization, authorization.copy(sequence = 8L))

    @Test
    fun `changing the authorization issue timestamp changes the bytes`() =
        assertAuthorizationsDistinct(
            authorization,
            authorization.copy(issuedAtMillis = authorization.issuedAtMillis + 1),
        )

    @Test
    fun `changing the revocation subject key changes the bytes`() =
        assertRevocationsDistinct(revocation, revocation.copy(subjectPublicKey = "K-OTHER"))

    @Test
    fun `changing the revoked authorization id changes the bytes`() =
        assertRevocationsDistinct(
            revocation,
            revocation.copy(revokedAuthorizationId = "rec-0002"),
        )

    @Test
    fun `changing the revocation sequence changes the bytes`() =
        assertRevocationsDistinct(revocation, revocation.copy(sequence = 9L))

    @Test
    fun `changing the revocation issue timestamp changes the bytes`() =
        assertRevocationsDistinct(
            revocation,
            revocation.copy(issuedAtMillis = revocation.issuedAtMillis + 1),
        )

    /**
     * A negative sequence is two's complement and stays distinct from its neighbours. Not a
     * curiosity: a sequence arrives from a peer, so `Long.MIN_VALUE` and `-1` are exactly what a
     * hostile or buggy device puts there, and T17 will compare those values with a strict
     * inequality.
     */
    @Test
    fun `extreme sequences encode distinctly and read back`() {
        assertAuthorizationsDistinct(
            authorization.copy(sequence = Long.MIN_VALUE),
            authorization.copy(sequence = -1L),
        )
        assertRevocationsDistinct(
            revocation.copy(sequence = Long.MAX_VALUE),
            revocation.copy(sequence = 0L),
        )

        val reader = PreImageReader(
            Utils.revocationBytes(
                revocation.copy(sequence = Long.MIN_VALUE, issuedAtMillis = Long.MAX_VALUE),
            ),
        )
        reader.fixedText(Utils.STATEMENT_DOMAIN_V1.length)
        repeat(3) { reader.text() }
        assertEquals(Long.MIN_VALUE, reader.long())
        assertEquals(Long.MAX_VALUE, reader.long())
        assertTrue("eight bytes each, whatever the sign", reader.atEnd())
    }

    /**
     * The collision a naive encoder makes, in both new kinds: `"AB" + "C"` and `"A" + "BC"`
     * concatenate alike, so an encoder joining components without delimiting them would hand the
     * same bytes to the signer for two different statements. Length prefixes are what stop one
     * signature from being both.
     */
    @Test
    fun `statements that concatenate alike produce different bytes`() {
        assertAuthorizationsDistinct(
            RecoveryAuthorization("AB", "C", "id", 1L, 2L),
            RecoveryAuthorization("A", "BC", "id", 1L, 2L),
        )
        assertRevocationsDistinct(
            Revocation("AB", "C", 1L, 2L),
            Revocation("A", "BC", 1L, 2L),
        )

        // And the trap one component further along, where a text component ends exactly where a
        // fixed-width number begins.
        assertRevocationsDistinct(
            Revocation("K", "abc", 1L, 2L),
            Revocation("Ka", "bc", 1L, 2L),
        )
    }

    /**
     * The check that catches a `String.format("%d")` hidden in the encoder. Under `ar-EG` the
     * JDK's locale-sensitive number formatting emits Eastern Arabic-Indic digits, so a pre-image
     * built from formatted numbers would come out different bytes on a phone set to Arabic — a
     * signature that verifies in one language and not another. This matters more here than for a
     * rotation: the `sequence` is a number that exists only to be compared, and it is now inside
     * signed bytes.
     */
    @Test
    fun `neither pre-image changes under another locale`() {
        val expectedRecovery = Utils.recoveryAuthorizationBytes(authorization)
        val expectedRevocation = Utils.revocationBytes(revocation)

        Locale.setDefault(Locale.forLanguageTag("ar-EG"))

        assertArrayEquals(
            "the locale must not reach the pre-image",
            expectedRecovery,
            Utils.recoveryAuthorizationBytes(authorization),
        )
        assertArrayEquals(
            "the locale must not reach the pre-image",
            expectedRevocation,
            Utils.revocationBytes(revocation),
        )
        assertEquals(
            "the pinned literal must hold under any locale too",
            PINNED_RECOVERY_PRE_IMAGE,
            Base64.encodeToString(Utils.recoveryAuthorizationBytes(authorization), Base64.NO_WRAP),
        )
        assertEquals(
            "the pinned literal must hold under any locale too",
            PINNED_REVOCATION_PRE_IMAGE,
            Base64.encodeToString(Utils.revocationBytes(revocation), Base64.NO_WRAP),
        )
        // The control: without it this test would pass on a JDK where `ar-EG` happens to format
        // digits as ASCII anyway, and would then assert nothing about locale sensitivity.
        assertNotEquals(
            "control: this locale must genuinely format digits differently, or the assertions " +
                "above cannot fail",
            "123",
            String.format(Locale.getDefault(), "%d", 123),
        )
    }

    // ── The signing-oracle guard extends to both new kinds ───────────────

    /**
     * One predicate, three kinds. The prefix comes before the kind tag, so a vault refusing to
     * sign a nonce that matches refuses all three without a second mechanism — which is the whole
     * reason the prefix is separate from the tag.
     *
     * The authorization is the kind it matters most for: a rotation obtained by trickery expires,
     * and an authorization obtained the same way never does.
     */
    @Test
    fun `both new pre-images are recognised by the oracle guard`() {
        assertTrue(Utils.isStatementPreImage(Utils.recoveryAuthorizationBytes(authorization)))
        assertTrue(Utils.isStatementPreImage(Utils.revocationBytes(revocation)))
    }

    /**
     * The attack shape, played out rather than asserted on bytes built in place: the pre-image
     * travels as the `nonce` of an ordinary sign-challenge request, exactly as an attacker would
     * send it, and the vault's own parser hands it back. The predicate has to hold on *that*
     * array — the one a vault is holding when it decides whether to sign.
     */
    @Test
    fun `an authorization pre-image arriving as a sign-challenge nonce is recognised`() {
        val preImage = Utils.recoveryAuthorizationBytes(
            RecoveryAuthorization(subjectKeyBase64, recoveryKeyBase64, "rec-attack", 1L, 2L),
        )
        val intent = Utils.createSignChallengeIntent(
            context = RuntimeEnvironment.getApplication(),
            publicKey = subjectKeyBase64,
            nonce = preImage,
            requestCode = "req-1",
        )

        val request = Utils.parseSignChallengeRequest(intent)
        assertNotNull("the hostile request must parse — refusing it is a human decision", request)
        assertArrayEquals("the nonce must survive the round trip", preImage, request!!.nonce)
        assertTrue(
            "a vault holding this nonce must be able to see it is a standing credential it is " +
                "about to sign for ever",
            Utils.isStatementPreImage(request.nonce),
        )
    }

    // ── toString ─────────────────────────────────────────────────────────

    @Test
    fun `authorization toString previews both real keys, truncated and distinct`() {
        val rendered = RecoveryAuthorization(
            subjectKeyBase64,
            recoveryKeyBase64,
            "rec-0001",
            7L,
            9L,
        ).toString()

        assertFalse("the whole subject key must not be printed", rendered.contains(subjectKeyBase64))
        assertFalse("the whole recovery key must not be printed", rendered.contains(recoveryKeyBase64))
        assertNotEquals(
            "the two previews must be distinguishable, or a log cannot tell one device from " +
                "another",
            subjectKeyBase64.take(PUBLIC_KEY_PREVIEW_CHARS),
            recoveryKeyBase64.take(PUBLIC_KEY_PREVIEW_CHARS),
        )
        // Named in full rather than by `contains` alone: dropping the sequence from the override
        // would leave a suite of `contains` assertions green, and the sequence is the first thing
        // a reader wants from an authorization a service just found stale.
        assertEquals(
            "RecoveryAuthorization(subjectPublicKey=${previewedPublicKey(subjectKeyBase64)}, " +
                "recoveryPublicKey=${previewedPublicKey(recoveryKeyBase64)}, " +
                "authorizationId=rec-0001, sequence=7, issuedAtMillis=9)",
            rendered,
        )
    }

    @Test
    fun `revocation toString previews its key and names what it revokes`() {
        val rendered = Revocation(subjectKeyBase64, "rec-0001", 8L, 9L).toString()

        assertFalse("the whole subject key must not be printed", rendered.contains(subjectKeyBase64))
        assertEquals(
            "Revocation(subjectPublicKey=${previewedPublicKey(subjectKeyBase64)}, " +
                "revokedAuthorizationId=rec-0001, sequence=8, issuedAtMillis=9)",
            rendered,
        )
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    private fun assertAuthorizationsDistinct(
        left: RecoveryAuthorization,
        right: RecoveryAuthorization,
    ) {
        assertNotEquals("control: the two must genuinely differ", left, right)
        assertFalse(
            "two different authorizations share a pre-image, so a signature over one is a " +
                "signature over the other:\n  $left\n  $right",
            Utils.recoveryAuthorizationBytes(left)
                .contentEquals(Utils.recoveryAuthorizationBytes(right)),
        )
    }

    private fun assertRevocationsDistinct(left: Revocation, right: Revocation) {
        assertNotEquals("control: the two must genuinely differ", left, right)
        assertFalse(
            "two different revocations share a pre-image:\n  $left\n  $right",
            Utils.revocationBytes(left).contentEquals(Utils.revocationBytes(right)),
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
     * each 64-bit value as eight big-endian bytes. Written through [ByteBuffer] rather than
     * through a shift loop, so an endianness slip in the encoder cannot be mirrored here by
     * accident.
     */
    private fun handBuiltPreImage(
        kind: String,
        texts: List<String>,
        longs: List<Long>,
    ): ByteArray {
        val pieces = mutableListOf<ByteArray>()
        pieces += "lim.statement.v1".toByteArray(Charsets.UTF_8)
        (listOf(kind) + texts).forEach { text ->
            val encoded = text.toByteArray(Charsets.UTF_8)
            pieces += ByteBuffer.allocate(4).putInt(encoded.size).array()
            pieces += encoded
        }
        longs.forEach { pieces += ByteBuffer.allocate(8).putLong(it).array() }

        val out = ByteArray(pieces.sumOf { it.size })
        var offset = 0
        pieces.forEach { piece ->
            piece.copyInto(out, offset)
            offset += piece.size
        }
        return out
    }

    /**
     * Walks a pre-image back to its components knowing only the layout. Deliberately a second copy
     * of `StatementPreImageTest`'s reader rather than a shared helper: this one is an *independent
     * statement of the layout*, and a shared reader that drifted with the encoder would agree with
     * it for the wrong reason.
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
         * The frozen canonical pre-images, Base64 with no wrapping. Captured once from a run that
         * also passed the hand-built comparison beside them, and change-detectors from then on.
         *
         * These are worth more than the rotation's equivalent, not less: a recovery authorization
         * has no expiry, so every one ever signed stays verifiable indefinitely and a format
         * revision would strand the lot.
         */
        private const val PINNED_RECOVERY_PRE_IMAGE =
            "bGltLnN0YXRlbWVudC52MQAAAA5saW0ucmVjb3Zlci52MQAAAAlLLVNVQkpFQ1QAAAAKSy1SRUNPVkVSWQAAAAhyZWMtMDAwMQAAAAAAAAAHAAABnBw4pAA="

        private const val PINNED_REVOCATION_PRE_IMAGE =
            "bGltLnN0YXRlbWVudC52MQAAAA1saW0ucmV2b2tlLnYxAAAACUstU1VCSkVDVAAAAAhyZWMtMDAwMQAAAAAAAAAIAAABnBw4pAA="

        private lateinit var subjectKeyBase64: String
        private lateinit var recoveryKeyBase64: String

        /** 2048-bit RSA generation is slow (~100ms each); do it once for the whole class. */
        @JvmStatic
        @BeforeClass
        fun generateKeys() {
            fun generate(): KeyPair =
                KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

            subjectKeyBase64 = Base64.encodeToString(generate().public.encoded, Base64.NO_WRAP)
            recoveryKeyBase64 = Base64.encodeToString(generate().public.encoded, Base64.NO_WRAP)
        }
    }
}
