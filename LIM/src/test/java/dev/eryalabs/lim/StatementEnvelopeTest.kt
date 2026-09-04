package dev.eryalabs.lim

import android.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.Signature

/**
 * The envelope: one text form a relay can carry, and one parser that reads it back.
 *
 * Two halves, deliberately kept apart, because collapsing them is the tempting mistake:
 *
 * - Damage to the **framing** — a missing section, an unknown tag, a section that is not Base64,
 *   trailing garbage — yields `null`. There is nothing to hand a verifier.
 * - Damage to the **signed payload**, with the framing left intact, still *parses*, and then
 *   verifies [StatementVerdict.SIGNATURE_INVALID]. A parser that rejected anything failing to
 *   verify would have collapsed the parse/verify distinction this whole library keeps — and it
 *   would need a public key it has no business holding, since parsing happens on a relay that
 *   stores none.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class StatementEnvelopeTest {

    private val rotation get() = RotationStatement(
        oldPublicKey = oldKeyBase64,
        newPublicKey = newKeyBase64,
        statementId = "rot-0001",
        issuedAtMillis = 1_770_000_000_000L,
        expiresAtMillis = 1_770_000_600_000L,
    )

    private val authorization get() = RecoveryAuthorization(
        subjectPublicKey = oldKeyBase64,
        recoveryPublicKey = newKeyBase64,
        authorizationId = "rec-0001",
        sequence = 7L,
        issuedAtMillis = 1_770_000_000_000L,
    )

    private val revocation get() = Revocation(
        subjectPublicKey = oldKeyBase64,
        revokedAuthorizationId = "rec-0001",
        sequence = 8L,
        issuedAtMillis = 1_770_000_100_000L,
    )

    // ── Round trips ──────────────────────────────────────────────────────

    @Test
    fun `a rotation envelope round-trips field-for-field and still verifies`() {
        val statement = rotation
        val signature = sign(Utils.rotationStatementBytes(statement))

        val parsed = Utils.parseSignedStatement(
            Utils.encodeRotationStatement(statement, signature),
        )

        assertTrue("the router must return the rotation case; got $parsed", parsed is SignedStatement.Rotate)
        val carried = (parsed as SignedStatement.Rotate).statement
        assertEquals(oldKeyBase64, carried.oldPublicKey)
        assertEquals(newKeyBase64, carried.newPublicKey)
        assertEquals("rot-0001", carried.statementId)
        assertEquals(1_770_000_000_000L, carried.issuedAtMillis)
        assertEquals(1_770_000_600_000L, carried.expiresAtMillis)
        assertTrue("the signature must survive the crossing", signature.contentEquals(parsed.signature))

        // The property the envelope exists for: the pre-image survived, so the same signature
        // still verifies against the same stored key on the far side.
        assertEquals(
            StatementVerdict.VALID,
            Utils.verifyRotationStatement(
                carried,
                parsed.signature,
                oldKeyBase64,
                now = 1_770_000_300_000L,
            ),
        )
    }

    @Test
    fun `a recovery envelope round-trips field-for-field and still verifies`() {
        val statement = authorization
        val signature = sign(Utils.recoveryAuthorizationBytes(statement))

        val parsed = Utils.parseSignedStatement(
            Utils.encodeRecoveryAuthorization(statement, signature),
        )

        assertTrue("the router must return the recovery case; got $parsed", parsed is SignedStatement.Recover)
        val carried = (parsed as SignedStatement.Recover).authorization
        assertEquals(oldKeyBase64, carried.subjectPublicKey)
        assertEquals(newKeyBase64, carried.recoveryPublicKey)
        assertEquals("rec-0001", carried.authorizationId)
        assertEquals(7L, carried.sequence)
        assertEquals(1_770_000_000_000L, carried.issuedAtMillis)
        assertTrue(signature.contentEquals(parsed.signature))

        assertEquals(
            StatementVerdict.VALID,
            Utils.verifyRecoveryAuthorization(carried, parsed.signature, oldKeyBase64),
        )
    }

    @Test
    fun `a revocation envelope round-trips field-for-field and still verifies`() {
        val statement = revocation
        val signature = sign(Utils.revocationBytes(statement))

        val parsed = Utils.parseSignedStatement(Utils.encodeRevocation(statement, signature))

        assertTrue("the router must return the revocation case; got $parsed", parsed is SignedStatement.Revoke)
        val carried = (parsed as SignedStatement.Revoke).revocation
        assertEquals(oldKeyBase64, carried.subjectPublicKey)
        assertEquals("rec-0001", carried.revokedAuthorizationId)
        assertEquals(8L, carried.sequence)
        assertEquals(1_770_000_100_000L, carried.issuedAtMillis)
        assertTrue(signature.contentEquals(parsed.signature))

        assertEquals(
            StatementVerdict.VALID,
            Utils.verifyRevocation(carried, parsed.signature, oldKeyBase64),
        )
    }

    /**
     * The framing, pinned as literals the way `IntentBuilderTest` pins the wire format. A peer
     * implementation has to be able to produce this from a one-line description, so the
     * description is asserted rather than described: marker, kind tag, Base64 pre-image, Base64
     * signature, colon-separated, one line.
     */
    @Test
    fun `the envelope is four colon-separated sections on one line`() {
        assertEquals("lim.env.v1", Utils.STATEMENT_ENVELOPE_V1)

        val statement = rotation
        val signature = sign(Utils.rotationStatementBytes(statement))
        val text = Utils.encodeRotationStatement(statement, signature)

        val sections = text.split(':')
        assertEquals("marker, kind, pre-image, signature; got $sections", 4, sections.size)
        assertEquals("lim.env.v1", sections[0])
        assertEquals("lim.rotate.v1", sections[1])
        assertFalse("the envelope must be one line, so it fits a file or a QR frame", '\n' in text)
        assertTrue(
            "the pre-image travels verbatim, not as re-listed fields",
            Utils.rotationStatementBytes(statement)
                .contentEquals(Base64.decode(sections[2], Base64.NO_WRAP)),
        )
        assertTrue(signature.contentEquals(Base64.decode(sections[3], Base64.NO_WRAP)))

        // The other two kinds are the same framing under a different tag, which is the whole of
        // what "self-describing" buys the router.
        assertEquals(
            "lim.recover.v1",
            Utils.encodeRecoveryAuthorization(authorization, signature).split(':')[1],
        )
        assertEquals(
            "lim.revoke.v1",
            Utils.encodeRevocation(revocation, signature).split(':')[1],
        )
    }

    /**
     * A relay writes an envelope to a file and reads it back with the line ending attached, so
     * surrounding whitespace is ignored rather than fatal. Base64 wrapped at 76 characters — what
     * [Base64.DEFAULT] produces, and what a peer implementation might well emit — also parses,
     * because the decoder strips whitespace inside a section too.
     */
    @Test
    fun `surrounding and internal whitespace does not stop an envelope parsing`() {
        val statement = rotation
        val signature = sign(Utils.rotationStatementBytes(statement))
        val text = Utils.encodeRotationStatement(statement, signature)

        assertNotNull("a trailing newline is what reading a file gives you", Utils.parseSignedStatement("$text\n"))
        assertNotNull(Utils.parseSignedStatement("  \n$text\t "))

        val wrapped = "lim.env.v1:lim.rotate.v1:" +
            Base64.encodeToString(Utils.rotationStatementBytes(statement), Base64.DEFAULT) + ":" +
            Base64.encodeToString(signature, Base64.DEFAULT)
        val parsed = Utils.parseSignedStatement(wrapped)
        assertTrue("a wrapped section must still decode; got $parsed", parsed is SignedStatement.Rotate)
        assertEquals(statement, (parsed as SignedStatement.Rotate).statement)
    }

    /**
     * A multi-byte component crosses intact, which is the reader's half of what T14's byte-length
     * prefixes bought: a reader counting characters would drag the next component's head into
     * this one and hand back a *different* statement out of the same signed bytes.
     */
    @Test
    fun `a multi-byte component survives the crossing`() {
        val statement = rotation.copy(statementId = "rot-ééé-0001")
        val signature = sign(Utils.rotationStatementBytes(statement))

        val parsed = Utils.parseSignedStatement(
            Utils.encodeRotationStatement(statement, signature),
        ) as? SignedStatement.Rotate

        assertNotNull(parsed)
        assertEquals("rot-ééé-0001", parsed!!.statement.statementId)
        assertEquals(
            StatementVerdict.VALID,
            Utils.verifyRotationStatement(parsed.statement, parsed.signature, oldKeyBase64, 1_770_000_300_000L),
        )
    }

    // ── Negative controls: damage to the framing yields null ─────────────

    @Test
    fun `a null, empty or blank envelope is null`() {
        assertNull(Utils.parseSignedStatement(null))
        assertNull(Utils.parseSignedStatement(""))
        assertNull(Utils.parseSignedStatement("   \n\t "))
    }

    @Test
    fun `a truncated envelope is null`() {
        val text = Utils.encodeRotationStatement(rotation, sign(Utils.rotationStatementBytes(rotation)))

        // Every prefix of a genuine envelope, sampled across its whole length: cut anywhere and
        // there is either a section missing or a section that is no longer what was signed.
        var reachedTheVerifier = 0
        for (fraction in 1..19) {
            val cut = text.substring(0, text.length * fraction / 20)
            val parsed = Utils.parseSignedStatement(cut)
            if (parsed != null) {
                reachedTheVerifier++
                // A cut inside the trailing signature can leave four well-formed sections, so
                // "parsed" is allowed there — what must never survive is the *statement*.
                assertTrue(
                    "a truncated envelope may not yield a usable rotation: cut at $fraction/20",
                    parsed is SignedStatement.Rotate &&
                        Utils.verifyRotationStatement(
                            parsed.statement,
                            parsed.signature,
                            oldKeyBase64,
                            1_770_000_300_000L,
                        ) == StatementVerdict.SIGNATURE_INVALID,
                )
            }
        }

        // The floor: the assertion above lives inside a branch, so without this the test would
        // quietly degrade to "nothing threw" if the framing rules ever rejected every cut. A cut
        // inside the trailing signature leaves four well-formed sections, so at least one must
        // get as far as the verifier — and it is that case, not the null ones, that this test is
        // actually about.
        assertTrue(
            "no truncation reached the verifier, so the real assertion never ran",
            reachedTheVerifier > 0,
        )
    }

    @Test
    fun `an unknown kind tag is refused rather than guessed`() {
        val statement = rotation
        val signature = sign(Utils.rotationStatementBytes(statement))
        val preImage = Base64.encodeToString(Utils.rotationStatementBytes(statement), Base64.NO_WRAP)
        val signatureB64 = Base64.encodeToString(signature, Base64.NO_WRAP)

        // The case this exists for: a newer peer sending a format this version cannot know.
        assertNull(Utils.parseSignedStatement("lim.env.v1:lim.rotate.v2:$preImage:$signatureB64"))
        assertNull(Utils.parseSignedStatement("lim.env.v1::$preImage:$signatureB64"))
        assertNull(Utils.parseSignedStatement("lim.env.v1:lim.statement.v1:$preImage:$signatureB64"))
        // And an unknown *framing*, which is versioned separately for exactly this reason.
        assertNull(Utils.parseSignedStatement("lim.env.v2:lim.rotate.v1:$preImage:$signatureB64"))
        assertNull(Utils.parseSignedStatement("LIM.ENV.V1:lim.rotate.v1:$preImage:$signatureB64"))
    }

    @Test
    fun `the wrong number of sections is null`() {
        val statement = rotation
        val signature = Base64.encodeToString(sign(Utils.rotationStatementBytes(statement)), Base64.NO_WRAP)
        val preImage = Base64.encodeToString(Utils.rotationStatementBytes(statement), Base64.NO_WRAP)

        assertNull("a missing signature section", Utils.parseSignedStatement("lim.env.v1:lim.rotate.v1:$preImage"))
        assertNull("a missing kind tag", Utils.parseSignedStatement("lim.env.v1:$preImage:$signature"))
        assertNull("nothing but the marker", Utils.parseSignedStatement("lim.env.v1"))
        assertNull(
            "a fifth section, which is what an appended field looks like",
            Utils.parseSignedStatement("lim.env.v1:lim.rotate.v1:$preImage:$signature:extra"),
        )
    }

    @Test
    fun `an undecodable Base64 section is null`() {
        val statement = rotation
        val signature = Base64.encodeToString(sign(Utils.rotationStatementBytes(statement)), Base64.NO_WRAP)
        val preImage = Base64.encodeToString(Utils.rotationStatementBytes(statement), Base64.NO_WRAP)

        assertNull(Utils.parseSignedStatement("lim.env.v1:lim.rotate.v1:!!!!:$signature"))
        assertNull(Utils.parseSignedStatement("lim.env.v1:lim.rotate.v1:$preImage:!!!!"))
        assertNull("an empty pre-image section", Utils.parseSignedStatement("lim.env.v1:lim.rotate.v1::$signature"))
        assertNull("an empty signature section", Utils.parseSignedStatement("lim.env.v1:lim.rotate.v1:$preImage:"))
    }

    /**
     * A signature is the one section an encoder cannot fix up for the caller: an empty one
     * encodes to an empty section, and the parser refuses it. That is the fail-closed direction —
     * an envelope carrying no signature must not be something a relay can pass on and have read.
     */
    @Test
    fun `an envelope built with an empty signature does not parse`() {
        val text = Utils.encodeRotationStatement(rotation, ByteArray(0))
        assertTrue("the signature section is genuinely empty; got $text", text.endsWith(":"))
        assertEquals("everything before it is intact", 4, text.split(':').size)
        assertNull(Utils.parseSignedStatement(text))
    }

    /**
     * Trailing junk, and an honest account of *why* each case lands where it does — because the
     * parser has no trailing-garbage rule at all. It has a Base64 rule, and the two coincide only
     * for junk the alphabet rejects.
     */
    @Test
    fun `trailing garbage is refused`() {
        val text = Utils.encodeRotationStatement(rotation, sign(Utils.rotationStatementBytes(rotation)))

        // Unconditional: these characters are outside the alphabet, whatever the key size.
        assertNull("characters outside the Base64 alphabet", Utils.parseSignedStatement("$text <- appended"))
        assertNull(Utils.parseSignedStatement("prefix$text"))
        assertNull("a fifth section", Utils.parseSignedStatement("$text:cafe"))

        // Alphabet characters land null here too, but only because an RSA-2048 signature is 256
        // bytes, 256 % 3 == 1, so its Base64 ends in `==` and padding is accepted only as a
        // suffix. That is a property of the key size, not of the parser, and nothing in this
        // library pins the key size — with a 3072-bit key the signature is 384 bytes, needs no
        // padding, and the same junk would decode.
        assertNull("alphabet characters after the padding", Utils.parseSignedStatement(text + "cafe"))

        // So the property that holds for *any* key size is asserted separately, against a
        // signature section built without padding: appended junk is refused either by the framing
        // or by the signature, never accepted.
        val unpadded = "lim.env.v1:lim.rotate.v1:" +
            Base64.encodeToString(Utils.rotationStatementBytes(rotation), Base64.NO_WRAP) +
            ":AAAA"
        var reachedTheVerifier = 0
        listOf("", "cafe").forEach { junk ->
            val parsed = Utils.parseSignedStatement(unpadded + junk)
            if (parsed != null) {
                reachedTheVerifier++
                assertEquals(
                    "an unpadded signature section with '$junk' appended must never verify",
                    StatementVerdict.SIGNATURE_INVALID,
                    Utils.verifyRotationStatement(
                        (parsed as SignedStatement.Rotate).statement,
                        parsed.signature,
                        oldKeyBase64,
                        1_770_000_300_000L,
                    ),
                )
            }
        }
        // The same floor the truncation test carries. A `null` here is a legitimate refusal, so
        // the branch is honest rather than vacuous by design — but if the parser ever regressed
        // to always-`null` this block would silently stop asserting anything.
        assertTrue(
            "no unpadded-signature case reached the verifier, so nothing here was checked",
            reachedTheVerifier > 0,
        )
    }

    /**
     * The consequence of that Base64 leniency, asserted rather than left to be discovered: the
     * envelope *text* is not canonical. Whitespace inside a section is stripped, an unpadded tail
     * decodes the same as a padded one, and the last quantum carries bits the decoder throws
     * away — so unboundedly many distinct strings carry the identical statement and signature.
     *
     * This forges nothing: the signature covers the pre-image, not the text. It matters because a
     * service that deduplicates relayed statements on the envelope string has no uniqueness at
     * all — an attacker can respell one at will — and must key on the statement instead.
     */
    @Test
    fun `distinct envelope strings can carry the identical statement`() {
        val statement = rotation
        val signature = sign(Utils.rotationStatementBytes(statement))
        val text = Utils.encodeRotationStatement(statement, signature)
        val canonical = Utils.parseSignedStatement(text)

        assertNotNull(canonical)
        val respellings = listOf(
            "a newline inside a section" to text.replaceFirst(":lim.rotate.v1:", ":lim.rotate.v1:\n"),
            "the padding dropped" to text.dropLast(2),
        )

        respellings.forEach { (how, variant) ->
            assertNotEquals("control: $how must give a different string", text, variant)
            assertEquals(
                "$how must still carry the same statement — dedupe on statementId, not on this",
                canonical,
                Utils.parseSignedStatement(variant),
            )
        }
    }

    // ── Negative controls: damage inside the signed payload ──────────────

    /**
     * The other half, and the one that must NOT be `null`. An attacker who edits a component and
     * re-frames the result produces a perfectly well-formed envelope; catching that is the
     * verifier's job, with the key the service already stores, and a parser that tried to do it
     * would need a key it does not have.
     */
    @Test
    fun `a component edited after signing still parses and then fails verification`() {
        val statement = rotation
        val signature = sign(Utils.rotationStatementBytes(statement))

        val tampered = listOf(
            statement.copy(newPublicKey = attackerKeyBase64),
            statement.copy(oldPublicKey = attackerKeyBase64),
            statement.copy(statementId = "rot-0002"),
            statement.copy(issuedAtMillis = statement.issuedAtMillis - 1),
            statement.copy(expiresAtMillis = statement.expiresAtMillis + 86_400_000L),
        )

        tampered.forEach { edited ->
            val parsed = Utils.parseSignedStatement(Utils.encodeRotationStatement(edited, signature))
            assertTrue("an edited statement must still parse: $edited", parsed is SignedStatement.Rotate)
            assertEquals(
                "…and must then fail at the signature: $edited",
                StatementVerdict.SIGNATURE_INVALID,
                Utils.verifyRotationStatement(
                    (parsed as SignedStatement.Rotate).statement,
                    parsed.signature,
                    oldKeyBase64,
                    now = 1_770_000_300_000L,
                ),
            )
        }
    }

    /**
     * The framing's kind tag is not signed; the one inside the pre-image is. So they must agree,
     * or the envelope would carry an unsigned claim about what the signature means — precisely
     * what T16 put the kind tag inside the signed bytes to prevent.
     */
    @Test
    fun `a framing tag that disagrees with the signed kind tag is null`() {
        val signature = Base64.encodeToString(sign(Utils.recoveryAuthorizationBytes(authorization)), Base64.NO_WRAP)
        val recoverPreImage =
            Base64.encodeToString(Utils.recoveryAuthorizationBytes(authorization), Base64.NO_WRAP)

        assertNull(
            "a recovery pre-image announced as a rotation",
            Utils.parseSignedStatement("lim.env.v1:lim.rotate.v1:$recoverPreImage:$signature"),
        )
        assertNull(
            "and the reverse",
            Utils.parseSignedStatement(
                "lim.env.v1:lim.recover.v1:" +
                    Base64.encodeToString(Utils.rotationStatementBytes(rotation), Base64.NO_WRAP) +
                    ":$signature",
            ),
        )
    }

    @Test
    fun `a pre-image that is not canonical is null`() {
        val signature = Base64.encodeToString(sign(Utils.rotationStatementBytes(rotation)), Base64.NO_WRAP)
        val genuine = Utils.rotationStatementBytes(rotation)

        fun envelopeOf(preImage: ByteArray) = Utils.parseSignedStatement(
            "lim.env.v1:lim.rotate.v1:" +
                Base64.encodeToString(preImage, Base64.NO_WRAP) + ":$signature",
        )

        assertNull("nothing may be left over after the last component", envelopeOf(genuine + 0))
        assertNull("a truncated pre-image", envelopeOf(genuine.copyOf(genuine.size - 1)))
        assertNull("a pre-image with no domain prefix", envelopeOf(ByteArray(64) { it.toByte() }))
        assertNull("an empty pre-image", envelopeOf(ByteArray(0)))

        // A length prefix claiming more bytes than are present — the shape that would index past
        // the end of the array in a reader that trusted it.
        val overlong = genuine.copyOf()
        // The domain prefix, then the kind tag's four-byte length and its bytes: the next byte
        // begins `oldPublicKey`'s own length prefix.
        val oldKeyLengthPrefix = Utils.STATEMENT_DOMAIN_V1.length + 4 + Utils.STATEMENT_ROTATE_V1.length
        overlong[oldKeyLengthPrefix] = 0x7F
        assertNull("an overlong component length", envelopeOf(overlong))

        // Malformed UTF-8 inside a component. A `String` decode replaces it with U+FFFD rather
        // than failing, so the reader alone would hand back a statement whose re-encoding is not
        // the bytes that were signed; the re-encode check is what refuses it.
        val badUtf8 = genuine.copyOf()
        badUtf8[badUtf8.size - 8 - 8 - 4] = 0xC3.toByte()
        assertNull("a component that is not valid UTF-8", envelopeOf(badUtf8))
    }

    // ── Parsed is not verified ───────────────────────────────────────────

    /**
     * The structural pin T3 established, extended to the sealed type: no argument-free `Boolean`
     * accessor anywhere in it. Such a thing is exactly what a later change would reach for —
     * `isValid`, `isSigned` — and it would be a success signal a caller could read, and a sender
     * could influence, without a key ever being consulted.
     */
    @Test
    fun `no case of the sealed type exposes an argument-free success signal`() {
        val types = listOf(
            SignedStatement::class.java,
            SignedStatement.Rotate::class.java,
            SignedStatement.Recover::class.java,
            SignedStatement.Revoke::class.java,
        )

        val offenders = types.flatMap { type ->
            type.declaredMethods
                .filter { !it.isSynthetic }
                .filter { it.parameterCount == 0 }
                .filter {
                    it.returnType == java.lang.Boolean.TYPE ||
                        it.returnType == java.lang.Boolean::class.java
                }
                .map { "${type.simpleName}.${it.name}" }
        }

        assertEquals(
            "a parsed statement must carry no verdict of its own; found $offenders",
            emptyList<String>(),
            offenders,
        )
    }

    @Test
    fun `envelopes carrying the same bytes are equal, and toString hides the signature`() {
        val signature = sign(Utils.rotationStatementBytes(rotation))
        val a = SignedStatement.Rotate(rotation, signature)
        val b = SignedStatement.Rotate(rotation, signature.copyOf())

        assertEquals("array identity must not decide equality", a, b)
        assertEquals(a.hashCode(), b.hashCode())
        assertNotEquals(a, a.copy(statement = rotation.copy(statementId = "rot-0002")))
        assertNotEquals(
            "two kinds carrying the same signature are not the same statement",
            a as SignedStatement,
            SignedStatement.Recover(authorization, signature) as SignedStatement,
        )

        val printed = a.toString()
        assertFalse(
            "a live signature has no business in a log line; got $printed",
            Base64.encodeToString(signature, Base64.NO_WRAP).take(32) in printed,
        )
        assertTrue("its length is what a debugging session needs", "<${signature.size} bytes>" in printed)
        assertTrue("and which rotation this is", "rot-0001" in printed)
        assertFalse(
            "the keys stay previewed, the RotationStatement precedent",
            oldKeyBase64 in printed,
        )

        val recover = SignedStatement.Recover(authorization, signature)
        assertEquals(recover, SignedStatement.Recover(authorization, signature.copyOf()))
        assertTrue("rec-0001" in recover.toString())
        val revoke = SignedStatement.Revoke(revocation, signature)
        assertEquals(revoke, SignedStatement.Revoke(revocation, signature.copyOf()))
        assertTrue("rec-0001" in revoke.toString())
    }

    companion object {
        private lateinit var oldKeyPair: KeyPair
        private lateinit var oldKeyBase64: String
        private lateinit var newKeyBase64: String
        private lateinit var attackerKeyBase64: String

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
            attackerKeyBase64 = Base64.encodeToString(generate().public.encoded, Base64.NO_WRAP)
        }

        private fun signWith(key: PrivateKey, bytes: ByteArray): ByteArray =
            Signature.getInstance("SHA256withRSA").run {
                initSign(key)
                update(bytes)
                sign()
            }
    }

    private fun sign(bytes: ByteArray): ByteArray = signWith(oldKeyPair.private, bytes)
}
