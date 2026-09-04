package dev.eryalabs.lim

import android.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
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
 * What a *service* does with a recovery authorization and with a revocation.
 *
 * `RecoveryPreImageTest` pins the bytes; this pins the decision made about them. Both verifiers
 * mirror [Utils.verifyRotationStatement] — signature first, against the key the service already
 * stores — and both deliberately check **no window**, for two different reasons that are worth
 * keeping apart: an authorization has no expiry because one that expired before the emergency
 * would be worthless, and a revocation has none because a revocation that could go stale would
 * *un-revoke* a stolen device.
 *
 * That absence is asserted rather than assumed. Each verifier's reachable verdicts are collected
 * across every input this file exercises and compared against the documented domain, so a value
 * an integrator can never see does not sit in their exhaustive `when` looking like a case they
 * must handle — and, in the other direction, a verdict this file never expected cannot appear
 * unnoticed.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class RecoveryVerificationTest {

    private fun authorization(
        subject: String = storedKeyBase64,
        recovery: String = recoveryKeyBase64,
        id: String = "rec-0001",
        sequence: Long = 7L,
        issued: Long = 1_770_000_000_000L,
    ) = RecoveryAuthorization(subject, recovery, id, sequence, issued)

    private fun revocation(
        subject: String = storedKeyBase64,
        revoked: String = "rec-0001",
        sequence: Long = 8L,
        issued: Long = 1_770_000_000_000L,
    ) = Revocation(subject, revoked, sequence, issued)

    /** Sign a pre-image the way a vault's Keystore would. */
    private fun sign(preImage: ByteArray, key: PrivateKey): ByteArray =
        Signature.getInstance("SHA256withRSA").run {
            initSign(key)
            update(preImage)
            sign()
        }

    private fun signed(a: RecoveryAuthorization, key: PrivateKey = storedKeyPair.private) =
        sign(Utils.recoveryAuthorizationBytes(a), key)

    private fun signed(r: Revocation, key: PrivateKey = storedKeyPair.private) =
        sign(Utils.revocationBytes(r), key)

    // ── The happy paths ──────────────────────────────────────────────────

    @Test
    fun `a real authorization signed by the stored key verifies VALID`() {
        val a = authorization()

        assertEquals(
            StatementVerdict.VALID,
            Utils.verifyRecoveryAuthorization(a, signed(a), storedKeyBase64),
        )
    }

    @Test
    fun `a real revocation signed by the stored key verifies VALID`() {
        val r = revocation()

        assertEquals(
            StatementVerdict.VALID,
            Utils.verifyRevocation(r, signed(r), storedKeyBase64),
        )
    }

    /**
     * The absence of a window, asserted as behaviour rather than left as a property of the type.
     *
     * An authorization signed in the distant past and one dated far in the future are both
     * accepted, because neither verifier looks at a clock at all — there is nothing in either
     * signature to compare one against, and a library that applied a lifetime of its own would be
     * enforcing a policy the signature does not state. For a revocation this is the safety
     * property outright: a revocation that aged out would bring a stolen device back to life.
     */
    @Test
    fun `neither verifier consults a clock`() {
        listOf(
            "issued at the epoch" to 0L,
            "issued before the epoch" to Long.MIN_VALUE,
            "issued far in the future" to Long.MAX_VALUE,
        ).forEach { (why, issued) ->
            val a = authorization(issued = issued)
            assertEquals(
                "an authorization $why must still verify — it declares no window",
                StatementVerdict.VALID,
                Utils.verifyRecoveryAuthorization(a, signed(a), storedKeyBase64),
            )

            val r = revocation(issued = issued)
            assertEquals(
                "a revocation $why must still verify — one that could go stale would un-revoke " +
                    "a stolen device",
                StatementVerdict.VALID,
                Utils.verifyRevocation(r, signed(r), storedKeyBase64),
            )
        }
    }

    // ── One test per reachable verdict ───────────────────────────────────

    @Test
    fun `another keypair's signature over the same authorization is SIGNATURE_INVALID`() {
        val a = authorization()

        assertEquals(
            StatementVerdict.SIGNATURE_INVALID,
            Utils.verifyRecoveryAuthorization(
                a,
                signed(a, attackerKeyPair.private),
                storedKeyBase64,
            ),
        )
    }

    @Test
    fun `another keypair's signature over the same revocation is SIGNATURE_INVALID`() {
        val r = revocation()

        assertEquals(
            StatementVerdict.SIGNATURE_INVALID,
            Utils.verifyRevocation(r, signed(r, attackerKeyPair.private), storedKeyBase64),
        )
    }

    /**
     * A genuine authorization about somebody else's profile. The signature verifies — this
     * service's stored key really did make it — but the authorization says nothing about the
     * account this service would apply it to, so it must not be applied.
     */
    @Test
    fun `a genuine authorization naming another profile is WRONG_SUBJECT`() {
        val elsewhere = authorization(subject = otherProfileKeyBase64)

        assertEquals(
            StatementVerdict.WRONG_SUBJECT,
            Utils.verifyRecoveryAuthorization(elsewhere, signed(elsewhere), storedKeyBase64),
        )
    }

    /**
     * The same for a revocation, and here it carries an extra consequence worth naming: an
     * `authorizationId` is minted per device and two profiles can easily mint the same one, so
     * without the subject check a revocation issued for one account would silently cancel a
     * recovery device on another. That is a denial of service against the very feature that
     * exists for the day the primary device is gone.
     */
    @Test
    fun `a genuine revocation naming another profile is WRONG_SUBJECT`() {
        val elsewhere = revocation(subject = otherProfileKeyBase64)

        assertEquals(
            StatementVerdict.WRONG_SUBJECT,
            Utils.verifyRevocation(elsewhere, signed(elsewhere), storedKeyBase64),
        )
    }

    /** A device authorizing itself is not a recovery plan: it names no second device at all. */
    @Test
    fun `an authorization naming the stored key as its recovery device is SAME_KEY`() {
        val noop = authorization(recovery = storedKeyBase64)

        assertEquals(
            StatementVerdict.SAME_KEY,
            Utils.verifyRecoveryAuthorization(noop, signed(noop), storedKeyBase64),
        )
    }

    /**
     * The shapes of unusable recovery key, each genuinely signed so that only the key check can be
     * what refuses them. A service that recorded one of these has blessed a device that can never
     * sign anything — a recovery plan that fails at the only moment it is ever needed, and by then
     * the primary device is gone and no better authorization can be issued.
     */
    @Test
    fun `a blank, non-Base64 or non-key recovery device is NEW_KEY_UNUSABLE`() {
        listOf(
            "blank" to "",
            "whitespace only" to "   ",
            "outside the Base64 alphabet" to "not base64 at all!!",
            // Well-formed Base64 that decodes cleanly and simply is not a key. Paired with the
            // valid case at the top of this file, this is what proves the check parses rather
            // than pattern-matches.
            "well-formed Base64 that is not a key" to "QUJDREVGRw==",
        ).forEach { (why, key) ->
            val a = authorization(recovery = key)
            assertEquals(
                "a recovery device that is $why must be refused",
                StatementVerdict.NEW_KEY_UNUSABLE,
                Utils.verifyRecoveryAuthorization(a, signed(a), storedKeyBase64),
            )
        }
    }

    /**
     * An EC key is a real, well-formed X.509 public key; it fails only because it is not RSA — the
     * same bar [Utils.validateEntry] and [Utils.verifyRotationStatement] apply, and it has to be
     * the same one: a key this verifier waved through would be a key [Utils.verifySignature] could
     * never use.
     */
    @Test
    fun `a well-formed recovery key of another algorithm is NEW_KEY_UNUSABLE`() {
        val ec = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
        val a = authorization(recovery = Base64.encodeToString(ec.public.encoded, Base64.NO_WRAP))

        assertEquals(
            StatementVerdict.NEW_KEY_UNUSABLE,
            Utils.verifyRecoveryAuthorization(a, signed(a), storedKeyBase64),
        )
    }

    // ── The verdict domain ───────────────────────────────────────────────

    /**
     * The declared reachable domain of each verifier, asserted as an equality over a broad input
     * set rather than as prose.
     *
     * Both directions matter. **Containment** is the integrator-facing half: neither verifier can
     * ever answer [StatementVerdict.EXPIRED] or [StatementVerdict.NOT_YET_VALID], so a `when`
     * branch for those is a branch no input can take, and a verifier that started returning one
     * would mean a window had appeared where the design says there is none. **Reachability** is
     * what stops the assertion being vacuous: every verdict in the declared domain must actually
     * be produced by some row here, or the domain is a wish rather than a description.
     *
     * The rows are the same inputs the individual tests above use. That is deliberate — this test
     * adds no new behaviour, it closes the set.
     */
    @Test
    fun `each verifier returns only the verdicts it declares, and reaches all of them`() {
        val ec = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()

        val authorizationVerdicts = listOf(
            "genuine" to (authorization() to storedKeyPair.private),
            "signed by an attacker" to (authorization() to attackerKeyPair.private),
            "naming another profile" to
                (authorization(subject = otherProfileKeyBase64) to storedKeyPair.private),
            "authorizing itself" to
                (authorization(recovery = storedKeyBase64) to storedKeyPair.private),
            "a blank recovery key" to (authorization(recovery = "") to storedKeyPair.private),
            "a recovery key outside the alphabet" to
                (authorization(recovery = "!!!") to storedKeyPair.private),
            "a recovery key of the wrong algorithm" to (
                authorization(
                    recovery = Base64.encodeToString(ec.public.encoded, Base64.NO_WRAP),
                ) to storedKeyPair.private
                ),
            "an extreme sequence" to
                (authorization(sequence = Long.MIN_VALUE) to storedKeyPair.private),
            "an id of 200k characters" to
                (authorization(id = "x".repeat(200_000)) to storedKeyPair.private),
        ).map { (why, input) ->
            why to Utils.verifyRecoveryAuthorization(
                input.first,
                signed(input.first, input.second),
                storedKeyBase64,
            )
        }

        assertEquals(
            "verifyRecoveryAuthorization's reachable domain changed; got $authorizationVerdicts",
            setOf(
                StatementVerdict.VALID,
                StatementVerdict.SIGNATURE_INVALID,
                StatementVerdict.WRONG_SUBJECT,
                StatementVerdict.SAME_KEY,
                StatementVerdict.NEW_KEY_UNUSABLE,
            ),
            authorizationVerdicts.map { it.second }.toSet(),
        )

        val revocationVerdicts = listOf(
            "genuine" to (revocation() to storedKeyPair.private),
            "signed by an attacker" to (revocation() to attackerKeyPair.private),
            "naming another profile" to
                (revocation(subject = otherProfileKeyBase64) to storedKeyPair.private),
            "revoking a blank id" to (revocation(revoked = "") to storedKeyPair.private),
            "an extreme sequence" to
                (revocation(sequence = Long.MAX_VALUE) to storedKeyPair.private),
            "an id of 200k characters" to
                (revocation(revoked = "x".repeat(200_000)) to storedKeyPair.private),
        ).map { (why, input) ->
            why to Utils.verifyRevocation(
                input.first,
                signed(input.first, input.second),
                storedKeyBase64,
            )
        }

        assertEquals(
            "verifyRevocation names no second key, so SAME_KEY and NEW_KEY_UNUSABLE have nothing " +
                "to be about and no window verdict can occur; got $revocationVerdicts",
            setOf(
                StatementVerdict.VALID,
                StatementVerdict.SIGNATURE_INVALID,
                StatementVerdict.WRONG_SUBJECT,
            ),
            revocationVerdicts.map { it.second }.toSet(),
        )
    }

    // ── Cross-type confusion, end to end ─────────────────────────────────

    /**
     * The byte-level control in `RecoveryPreImageTest` says a rotation and an authorization with
     * identical components encode differently. This is what that buys: a signature the user
     * genuinely made over one is refused by the other's verifier.
     *
     * The direction that matters is the second one. A user consenting to "move my account to this
     * new phone, in the next ten minutes" must not thereby have signed "this device may take my
     * account over at any time, for ever" — and only the kind tag inside the pre-image stands
     * between the two.
     */
    @Test
    fun `a signature over one statement kind is refused by the other kind's verifier`() {
        val a = authorization()
        val equivalentRotation = RotationStatement(
            oldPublicKey = a.subjectPublicKey,
            newPublicKey = a.recoveryPublicKey,
            statementId = a.authorizationId,
            issuedAtMillis = a.sequence,
            expiresAtMillis = a.issuedAtMillis,
        )

        val rotationSignature = sign(
            Utils.rotationStatementBytes(equivalentRotation),
            storedKeyPair.private,
        )
        val authorizationSignature = signed(a)

        assertTrue(
            "control: the rotation signature must be genuine, or the refusal below is about a " +
                "bad signature rather than about the kind",
            Utils.verifySignature(
                storedKeyBase64,
                Utils.rotationStatementBytes(equivalentRotation),
                rotationSignature,
            ),
        )
        assertEquals(
            "a genuine rotation signature must not authorize a permanent recovery device",
            StatementVerdict.SIGNATURE_INVALID,
            Utils.verifyRecoveryAuthorization(a, rotationSignature, storedKeyBase64),
        )
        assertEquals(
            "and an authorization's signature must not pass as a rotation",
            StatementVerdict.SIGNATURE_INVALID,
            Utils.verifyRotationStatement(
                equivalentRotation,
                authorizationSignature,
                storedKeyBase64,
                now = a.issuedAtMillis,
            ),
        )
        assertEquals(
            "control: each verifier accepts its own kind, so the two refusals above are the " +
                "kind tag's doing",
            StatementVerdict.VALID,
            Utils.verifyRecoveryAuthorization(a, authorizationSignature, storedKeyBase64),
        )
    }

    /**
     * The other pair, and the one with the sharper motive: blessing a device and cancelling one
     * must not be the same signature, or a user cancelling a lost tablet would be handing out a
     * fresh standing credential for it.
     */
    @Test
    fun `an authorization signature is refused by the revocation verifier and the reverse`() {
        val a = authorization(id = "rec-0001", sequence = 7L)
        val r = revocation(revoked = "rec-0001", sequence = 7L)

        assertEquals(
            StatementVerdict.SIGNATURE_INVALID,
            Utils.verifyRevocation(r, signed(a), storedKeyBase64),
        )
        assertEquals(
            StatementVerdict.SIGNATURE_INVALID,
            Utils.verifyRecoveryAuthorization(a, signed(r), storedKeyBase64),
        )
        assertEquals(
            "control: each verifies its own",
            StatementVerdict.VALID,
            Utils.verifyRevocation(r, signed(r), storedKeyBase64),
        )
        assertEquals(
            "control: each verifies its own",
            StatementVerdict.VALID,
            Utils.verifyRecoveryAuthorization(a, signed(a), storedKeyBase64),
        )
    }

    // ── Tampering after signing ──────────────────────────────────────────
    //
    // One test per component rather than a loop, so a failure names the component that fell out of
    // the signature. This is the end-to-end complement of the byte-level controls in
    // `RecoveryPreImageTest`: there, changing a component changes the bytes; here, changing it
    // after signing costs the statement its verdict.

    @Test
    fun `the authorization subject key tampered after signing is SIGNATURE_INVALID`() =
        assertAuthorizationTamperingRejected { it.copy(subjectPublicKey = attackerKeyBase64) }

    /**
     * The one that matters most: a verifier blind to `recoveryPublicKey` would let an attacker
     * substitute their own device into a standing credential the user genuinely signed — and
     * unlike a rotation, that credential never expires. Note the verdict is `SIGNATURE_INVALID`
     * and not `NEW_KEY_UNUSABLE`: the substituted key is a perfectly good RSA key, which is
     * exactly why only the signature can catch it.
     */
    @Test
    fun `the recovery key tampered after signing is SIGNATURE_INVALID`() =
        assertAuthorizationTamperingRejected { it.copy(recoveryPublicKey = attackerKeyBase64) }

    /**
     * Renaming the authorization is how a thief survives a revocation: a revocation names an id,
     * so an authorization whose id can be edited in flight is one no revocation can ever point at.
     */
    @Test
    fun `the authorization id tampered after signing is SIGNATURE_INVALID`() =
        assertAuthorizationTamperingRejected { it.copy(authorizationId = "rec-0002") }

    /**
     * And renumbering it is the other half of the same attack: T17's rule is that a revocation
     * kills an authorization only at a *strictly greater* sequence, so raising an authorization's
     * number past the revocation that killed it would bring a revoked device straight back.
     */
    @Test
    fun `the authorization sequence tampered after signing is SIGNATURE_INVALID`() =
        assertAuthorizationTamperingRejected { it.copy(sequence = it.sequence + 1_000L) }

    @Test
    fun `the authorization timestamp tampered after signing is SIGNATURE_INVALID`() =
        assertAuthorizationTamperingRejected { it.copy(issuedAtMillis = it.issuedAtMillis - 1) }

    @Test
    fun `the revocation subject key tampered after signing is SIGNATURE_INVALID`() =
        assertRevocationTamperingRejected { it.copy(subjectPublicKey = attackerKeyBase64) }

    /**
     * Repointing a revocation at a different authorization is how a captured revocation becomes a
     * weapon: it would cancel a device its signer never meant to touch.
     */
    @Test
    fun `the revoked authorization id tampered after signing is SIGNATURE_INVALID`() =
        assertRevocationTamperingRejected { it.copy(revokedAuthorizationId = "rec-0002") }

    /**
     * Lowering a revocation's sequence below the authorization it names is precisely the mutation
     * that stops it revoking anything, so it must not survive the signature either.
     */
    @Test
    fun `the revocation sequence tampered after signing is SIGNATURE_INVALID`() =
        assertRevocationTamperingRejected { it.copy(sequence = it.sequence - 1_000L) }

    @Test
    fun `the revocation timestamp tampered after signing is SIGNATURE_INVALID`() =
        assertRevocationTamperingRejected { it.copy(issuedAtMillis = it.issuedAtMillis + 1) }

    // ── Check order ──────────────────────────────────────────────────────

    /**
     * The signature gate, generalised across every other refusal each verifier can make. Each row
     * is a statement an attacker signed with their own key, and each is *also* wrong in the way one
     * of the later checks looks for — so a verifier that ran any of those checks first would answer
     * with that check's verdict instead.
     *
     * The subject row is the one worth naming: hoisting the subject comparison above the signature
     * would turn a forgery aimed at somebody else's account into `WRONG_SUBJECT`, an answer that
     * says the bytes were genuine.
     *
     * The second half is what stops the whole test being vacuous: signed properly, every one of
     * these earns the verdict its own defect deserves, so the rows really do reach the later
     * checks and the signature really is what pre-empts them.
     */
    @Test
    fun `a forged statement is SIGNATURE_INVALID whatever else is wrong with it`() {
        val authorizationCases = listOf(
            "otherwise perfectly valid" to (authorization() to StatementVerdict.VALID),
            "naming another profile" to
                (authorization(subject = otherProfileKeyBase64) to StatementVerdict.WRONG_SUBJECT),
            "authorizing itself" to
                (authorization(recovery = storedKeyBase64) to StatementVerdict.SAME_KEY),
            "an unusable recovery key" to
                (authorization(recovery = "!!!") to StatementVerdict.NEW_KEY_UNUSABLE),
        )

        authorizationCases.forEach { (why, expectation) ->
            assertEquals(
                "an authorization that is $why but signed by the wrong key must fail at the " +
                    "signature",
                StatementVerdict.SIGNATURE_INVALID,
                Utils.verifyRecoveryAuthorization(
                    expectation.first,
                    signed(expectation.first, attackerKeyPair.private),
                    storedKeyBase64,
                ),
            )
        }
        authorizationCases.forEach { (why, expectation) ->
            val (a, expected) = expectation
            assertEquals(
                "control: signed genuinely, an authorization that is $why must reach the check " +
                    "that objects to it — otherwise the row above tests no ordering at all",
                expected,
                Utils.verifyRecoveryAuthorization(a, signed(a), storedKeyBase64),
            )
        }

        val forgedElsewhere = revocation(subject = otherProfileKeyBase64)
        assertEquals(
            "a revocation for another profile signed by the wrong key must fail at the signature",
            StatementVerdict.SIGNATURE_INVALID,
            Utils.verifyRevocation(
                forgedElsewhere,
                signed(forgedElsewhere, attackerKeyPair.private),
                storedKeyBase64,
            ),
        )
        assertEquals(
            "control: signed genuinely it must reach the subject check",
            StatementVerdict.WRONG_SUBJECT,
            Utils.verifyRevocation(forgedElsewhere, signed(forgedElsewhere), storedKeyBase64),
        )
    }

    /**
     * Subject before recovery key: an authorization about another profile is refused as such even
     * when its recovery key happens to be the one this service stores. Without the ordering this
     * would come back `SAME_KEY`, which reads as "nothing to do here" about a statement that is in
     * fact somebody else's.
     */
    @Test
    fun `another profile's authorization naming the stored key is WRONG_SUBJECT`() {
        val elsewhere = authorization(subject = otherProfileKeyBase64, recovery = storedKeyBase64)

        assertEquals(
            StatementVerdict.WRONG_SUBJECT,
            Utils.verifyRecoveryAuthorization(elsewhere, signed(elsewhere), storedKeyBase64),
        )
    }

    /**
     * And subject before the key *parse*, which is the other transposition available: an
     * authorization for somebody else that also carries an unusable recovery key must be reported
     * as somebody else's, not as a fixable formatting problem this service should chase.
     */
    @Test
    fun `another profile's authorization with an unusable key is still WRONG_SUBJECT`() {
        val elsewhere = authorization(subject = otherProfileKeyBase64, recovery = "!!!")

        assertEquals(
            StatementVerdict.WRONG_SUBJECT,
            Utils.verifyRecoveryAuthorization(elsewhere, signed(elsewhere), storedKeyBase64),
        )
    }

    /**
     * The no-op check must come before the key check, and this is the only input on which that
     * order is observable at all — everywhere else a key equal to the stored one is trivially a
     * usable key, so the two checks agree and the transposition survives every other test in this
     * file. Found by planting exactly that mutant.
     *
     * A service whose stored key is itself spelled with characters outside the Base64 alphabet,
     * handed an authorization naming that same spelling, is being told nothing: it would be
     * blessing the device it already is. Reported as `NEW_KEY_UNUSABLE` instead, the service would
     * go looking for a better-formed recovery key for an authorization that was never going
     * anywhere.
     */
    @Test
    fun `an authorization onto the stored key is SAME_KEY even when that key is spelled with stray characters`() {
        val dirty = strayCharacters(storedKeyBase64)
        val a = authorization(subject = dirty, recovery = dirty)
        val signature = signed(a)

        assertTrue(
            "control: the signature must verify against this spelling, so the verdict below is " +
                "the no-op rule's and not the signature gate's",
            Utils.verifySignature(dirty, Utils.recoveryAuthorizationBytes(a), signature),
        )
        assertEquals(
            "control: this spelling must genuinely be one the key check refuses, or the ordering " +
                "is not being tested",
            StatementVerdict.NEW_KEY_UNUSABLE,
            Utils.verifyRecoveryAuthorization(
                authorization(subject = dirty, recovery = strayCharacters(recoveryKeyBase64)),
                signed(authorization(subject = dirty, recovery = strayCharacters(recoveryKeyBase64))),
                dirty,
            ),
        )
        assertEquals(
            StatementVerdict.SAME_KEY,
            Utils.verifyRecoveryAuthorization(a, signature, dirty),
        )
    }

    // ── The identity-matching hazard, reached from this side ─────────────

    /**
     * The same exact-equality rule [Utils.verifyRotationStatement] carries, pinned here because a
     * `trim()` on either side of this comparison would survive every other test in this file.
     *
     * The control is what gives it teeth: the whitespace spelling verifies the signature perfectly
     * well — `verifySignature` decodes it to the same key — so the refusal can only be coming from
     * the string comparison.
     */
    @Test
    fun `a subject differing only by surrounding whitespace is WRONG_SUBJECT`() {
        listOf(
            "a trailing newline" to storedKeyBase64 + "\n",
            "a leading space" to " " + storedKeyBase64,
        ).forEach { (why, spelling) ->
            val a = authorization(subject = spelling)
            val signature = signed(a)

            assertNotEquals("control: $why must genuinely change the string", storedKeyBase64, spelling)
            assertTrue(
                "control: $why must still verify the signature, or this refusal is the crypto's " +
                    "and not the comparison's",
                Utils.verifySignature(spelling, Utils.recoveryAuthorizationBytes(a), signature),
            )
            assertEquals(
                "a key string with $why is a different account identifier",
                StatementVerdict.WRONG_SUBJECT,
                Utils.verifyRecoveryAuthorization(a, signature, storedKeyBase64),
            )

            val r = revocation(subject = spelling)
            assertEquals(
                "and the same for a revocation, where normalising would let one profile's " +
                    "revocation cancel another's device",
                StatementVerdict.WRONG_SUBJECT,
                Utils.verifyRevocation(r, signed(r), storedKeyBase64),
            )
        }
    }

    /**
     * The limit of the no-op check, recorded rather than quietly closed — the counterpart of
     * `RotationVerificationTest`'s whitespace-padded replacement key, reached from the other side.
     *
     * A recovery key spelled as the stored key plus a newline decodes to *exactly* the stored key,
     * so this authorization blesses the device that already holds the account — and it comes back
     * `VALID` rather than `SAME_KEY`, because `base64Bytes` strips whitespace while the equality
     * comparison does not. Refusing the spelling is not available: [Base64.DEFAULT] wraps real keys
     * at 76 characters, so a check strict enough to catch this would refuse every legitimately
     * wrapped key, and loosening the equality would merge two strings the protocol deliberately
     * keeps apart.
     *
     * The consequence here is milder than the rotation's — a service records a standing credential
     * that is really itself, rather than locking an account out — but it is the same hazard, it is
     * logged for a human as the canonicalisation decision, and the guidance is the same: **store
     * the exact string you verified**, and encode keys one way.
     */
    @Test
    fun `a whitespace-padded self-authorization is VALID, and that is the recorded limit`() {
        val padded = storedKeyBase64 + "\n"
        val a = authorization(recovery = padded)

        assertTrue(
            "control: this spelling must decode to exactly the stored key, or the verdict below " +
                "is about different bytes rather than about the string",
            Base64.decode(padded, Base64.DEFAULT)
                .contentEquals(Base64.decode(storedKeyBase64, Base64.DEFAULT)),
        )
        assertNotEquals("control: the spelling must genuinely differ", storedKeyBase64, padded)
        assertEquals(
            "recorded, not endorsed: whitespace cannot be refused without refusing every " +
                "Base64.DEFAULT-wrapped key, and the equality cannot be loosened without merging " +
                "two account identifiers",
            StatementVerdict.VALID,
            Utils.verifyRecoveryAuthorization(a, signed(a), storedKeyBase64),
        )
        assertEquals(
            "control: spelled the same way the service stores it, the very same authorization is " +
                "the no-op it really is — which is what makes the line above a spelling problem " +
                "and not a missing check",
            StatementVerdict.SAME_KEY,
            Utils.verifyRecoveryAuthorization(
                authorization(recovery = storedKeyBase64),
                signed(authorization(recovery = storedKeyBase64)),
                storedKeyBase64,
            ),
        )
    }

    // ── Hostile input: a verdict, never a throw ──────────────────────────

    /**
     * Everything reaching these functions crossed a relay somebody else controls, so none of it may
     * take a service's process down. Each input below earns a verdict rather than an exception —
     * and since none of them is a genuine signature, that verdict is `SIGNATURE_INVALID`.
     */
    @Test
    fun `empty, garbage and blank inputs return a verdict rather than throwing`() {
        val a = authorization()
        val r = revocation()
        val genuineAuthorization = signed(a)
        val genuineRevocation = signed(r)

        listOf(
            "an empty signature" to ByteArray(0),
            "a single byte" to byteArrayOf(0),
            "garbage of signature length" to ByteArray(genuineAuthorization.size) { 0x5A },
            "a signature one byte short" to
                genuineAuthorization.copyOf(genuineAuthorization.size - 1),
            "a signature with a byte appended" to genuineAuthorization + byteArrayOf(0),
        ).forEach { (why, bytes) ->
            assertEquals(
                "$why must earn a verdict from verifyRecoveryAuthorization",
                StatementVerdict.SIGNATURE_INVALID,
                Utils.verifyRecoveryAuthorization(a, bytes, storedKeyBase64),
            )
            assertEquals(
                "$why must earn a verdict from verifyRevocation",
                StatementVerdict.SIGNATURE_INVALID,
                Utils.verifyRevocation(r, bytes, storedKeyBase64),
            )
        }

        listOf(
            "a blank stored key" to "",
            "a whitespace stored key" to "   ",
            "a stored key outside the Base64 alphabet" to "!!!!",
            "a stored key that is not a key" to "QUJDREVGRw==",
        ).forEach { (why, key) ->
            assertEquals(
                "$why must earn a verdict from verifyRecoveryAuthorization",
                StatementVerdict.SIGNATURE_INVALID,
                Utils.verifyRecoveryAuthorization(a, genuineAuthorization, key),
            )
            assertEquals(
                "$why must earn a verdict from verifyRevocation",
                StatementVerdict.SIGNATURE_INVALID,
                Utils.verifyRevocation(r, genuineRevocation, key),
            )
        }
    }

    // ── The delegation ───────────────────────────────────────────────────

    /**
     * There must be exactly one verifier in this library, and both of these must reach it.
     *
     * Stated as an agreement in both directions over a matrix of keys and signatures: the verdict
     * is `SIGNATURE_INVALID` on precisely the inputs [Utils.verifySignature] refuses and something
     * else on precisely the ones it accepts. A second, subtly different parse-and-verify — a
     * stricter key parse, another algorithm, a missing empty-signature guard — would break the
     * agreement on one row rather than on all of them, which is why the matrix carries refusals of
     * several different shapes.
     */
    @Test
    fun `the signature gate agrees with verifySignature on every input`() {
        val a = authorization()
        val preImage = Utils.recoveryAuthorizationBytes(a)
        val genuine = signed(a)
        var accepted = 0

        listOf(
            "the genuine signature" to (storedKeyBase64 to genuine),
            "the genuine signature under the attacker's key" to (attackerKeyBase64 to genuine),
            "a signature by the wrong key" to
                (storedKeyBase64 to signed(a, attackerKeyPair.private)),
            "a signature over a different authorization" to
                (storedKeyBase64 to signed(authorization(id = "rec-0002"))),
            "an empty signature" to (storedKeyBase64 to ByteArray(0)),
            "garbage bytes" to (storedKeyBase64 to ByteArray(genuine.size) { 0x5A }),
            "a blank stored key" to ("" to genuine),
            "a stored key that is not a key" to ("QUJDREVGRw==" to genuine),
        ).forEach { (why, input) ->
            val (key, signature) = input
            val direct = Utils.verifySignature(key, preImage, signature)
            val verdict = Utils.verifyRecoveryAuthorization(a, signature, key)
            if (direct) accepted++
            assertEquals(
                "$why: the verdict's signature gate must agree with verifySignature (which said " +
                    "$direct), or this function checks signatures its own way",
                !direct,
                verdict == StatementVerdict.SIGNATURE_INVALID,
            )
        }

        // Non-vacuity: an agreement that only ever compared `false` against `SIGNATURE_INVALID`
        // would hold against a function hardcoded to that verdict.
        assertEquals("exactly one row above must be a genuine acceptance", 1, accepted)
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    /**
     * The same key, spelled with four characters the Base64 alphabet does not contain.
     *
     * Four and not one: `base64Bytes` refuses a length leaving one character over before it looks
     * at the alphabet at all, so a single insertion would be refused by the length rule and the
     * alphabet rule would never run — the test would pass while pinning the wrong thing.
     */
    private fun strayCharacters(key: String): String = key.take(4) + "!!!!" + key.drop(4)

    /**
     * Sign the reference statement, then hand the verifier a *different* one alongside that
     * signature — the shape of a statement edited in transit.
     *
     * The two controls matter as much as the assertion: without them a `tamper` that returned its
     * input unchanged would make the test pass for the wrong reason, and every one of these is a
     * one-line `copy` that could quietly become a no-op.
     */
    private fun assertAuthorizationTamperingRejected(
        tamper: (RecoveryAuthorization) -> RecoveryAuthorization,
    ) {
        val original = authorization()
        val signature = signed(original)
        val tampered = tamper(original)

        assertNotEquals("control: the tamper must actually change the statement", original, tampered)
        assertEquals(
            "control: the untampered authorization must verify, or this proves nothing",
            StatementVerdict.VALID,
            Utils.verifyRecoveryAuthorization(original, signature, storedKeyBase64),
        )
        assertEquals(
            "an authorization edited after signing must not verify",
            StatementVerdict.SIGNATURE_INVALID,
            Utils.verifyRecoveryAuthorization(tampered, signature, storedKeyBase64),
        )
    }

    private fun assertRevocationTamperingRejected(tamper: (Revocation) -> Revocation) {
        val original = revocation()
        val signature = signed(original)
        val tampered = tamper(original)

        assertNotEquals("control: the tamper must actually change the statement", original, tampered)
        assertEquals(
            "control: the untampered revocation must verify, or this proves nothing",
            StatementVerdict.VALID,
            Utils.verifyRevocation(original, signature, storedKeyBase64),
        )
        assertEquals(
            "a revocation edited after signing must not verify",
            StatementVerdict.SIGNATURE_INVALID,
            Utils.verifyRevocation(tampered, signature, storedKeyBase64),
        )
    }

    companion object {
        private lateinit var storedKeyPair: KeyPair
        private lateinit var attackerKeyPair: KeyPair
        private lateinit var storedKeyBase64: String
        private lateinit var recoveryKeyBase64: String
        private lateinit var attackerKeyBase64: String
        private lateinit var otherProfileKeyBase64: String

        /** 2048-bit RSA generation is slow (~100ms each); do it once for the whole class. */
        @JvmStatic
        @BeforeClass
        fun generateKeys() {
            fun generate(): KeyPair =
                KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

            storedKeyPair = generate()
            attackerKeyPair = generate()
            storedKeyBase64 = Base64.encodeToString(storedKeyPair.public.encoded, Base64.NO_WRAP)
            attackerKeyBase64 = Base64.encodeToString(attackerKeyPair.public.encoded, Base64.NO_WRAP)
            recoveryKeyBase64 = Base64.encodeToString(generate().public.encoded, Base64.NO_WRAP)
            otherProfileKeyBase64 = Base64.encodeToString(generate().public.encoded, Base64.NO_WRAP)
        }
    }
}
