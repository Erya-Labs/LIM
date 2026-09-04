package dev.eryalabs.lim

import android.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
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
 * The afternoon-integration example, written as a test so it can never go stale.
 *
 * Prose in a README describes an API as it was on the day somebody wrote the paragraph. This
 * plays the whole migration the way a third-party integrator would have to build it — a service
 * holding accounts **keyed by public key**, device A signing a statement, an envelope crossing
 * the device gap, the service verifying against the key it already stores and swapping it — so
 * if the flow ever stops working, this fails rather than the documentation quietly lying.
 *
 * [Service] below is deliberately the whole of the server side. That is the claim the design
 * makes and the thing worth demonstrating: a service needs a map from public key to account and
 * two calls into this library, no backend redesign beyond the second verb, and no secret of the
 * user's anywhere in it.
 *
 * Referenced from the KDoc of [Utils.parseSignedStatement] and [SignedStatement].
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class MigrationEndToEndTest {

    /**
     * A service as an integrator would write one: accounts keyed by the public key, which is the
     * account identifier, and nothing else about the user held at all.
     *
     * Everything it does with a statement it does through this library: parse the envelope, route
     * on the case, verify against the key it stores, act only on [StatementVerdict.VALID].
     *
     * Two things it does that the library cannot do for it, both found by review of an earlier
     * version of this file that did neither, and both pinned by tests below: it refuses a
     * rotation onto a key that already names an account, and it drops standing recovery
     * statements when the account's key changes. Neither is a detail — the first is an account
     * takeover and the second resurrects a revoked device.
     */
    private class Service {
        /** Public key → the service's own local account id. The whole of the account table. */
        private val accounts = mutableMapOf<String, String>()

        /** Recovery authorizations and revocations, held per profile as they are relayed in. */
        private val authorizations = mutableMapOf<String, MutableList<RecoveryAuthorization>>()
        private val revocations = mutableMapOf<String, MutableList<Revocation>>()

        fun signUp(publicKey: String, accountId: String) {
            accounts[publicKey] = accountId
        }

        fun accountFor(publicKey: String): String? = accounts[publicKey]

        fun keyOf(accountId: String): String? =
            accounts.entries.firstOrNull { it.value == accountId }?.key

        /**
         * Take one relayed envelope. Returns the verdict the library gave, or `null` when the
         * text was not a statement this service could read or names no profile it holds — which
         * is the answer for every profile whose app was never installed, the relay gap.
         */
        fun accept(envelope: String?, now: Long): StatementVerdict? =
            when (val signed = Utils.parseSignedStatement(envelope)) {
                null -> null

                is SignedStatement.Rotate -> {
                    val stored = signed.statement.oldPublicKey.takeIf { it in accounts }
                    stored?.let { key ->
                        val verdict = Utils.verifyRotationStatement(
                            signed.statement,
                            signed.signature,
                            key,
                            now,
                        )
                        // The service's own check, which the library cannot make for it: a
                        // VALID says the holder of the stored key asked for this swap, not that
                        // the key they asked to swap to is free. Without this, an attacker who
                        // signs up with their own key can rotate it, genuinely and validly, onto
                        // a victim's public key — which this service already stores and a breach
                        // hands out — and write their account over the victim's row.
                        val available = signed.statement.newPublicKey !in accounts
                        if (verdict == StatementVerdict.VALID && available) {
                            // The swap: the account moves to the new key and the old one stops
                            // naming anything.
                            accounts[signed.statement.newPublicKey] = accounts.remove(key)!!
                            // Authorizations for the old key are *dropped*, and the reasoning is
                            // the whole of it: an authorization names the old key as its subject,
                            // so after this rotation the only key that could ever revoke it is
                            // the one the user has just stopped holding. Carrying one across
                            // would leave a standing credential nobody can withdraw, and would
                            // bring a device revoked before the migration back to life after it.
                            // The recovery plan is re-issued under the new key instead.
                            authorizations.remove(key)
                            // Revocations are kept, and the asymmetry is deliberate. A revocation
                            // is a monotonic negative fact that never needs renewing, and it
                            // costs one map entry to hold forever. Discard it and a captured
                            // authorization envelope becomes live again the moment this key ever
                            // names an account a second time — which a later rotation back onto
                            // it permits, since the swap above frees the old key.
                        }
                        verdict
                    }
                }

                is SignedStatement.Recover -> {
                    val stored = signed.authorization.subjectPublicKey.takeIf { it in accounts }
                    stored?.let { key ->
                        val verdict = Utils.verifyRecoveryAuthorization(
                            signed.authorization,
                            signed.signature,
                            key,
                        )
                        if (verdict == StatementVerdict.VALID) {
                            // At most one entry per authorizationId, and a replay of one already
                            // held changes nothing. Appending blindly would let anyone holding a
                            // captured envelope grow this list without bound just by relaying it
                            // again — and `Utils.liveAuthorizations` filters rather than
                            // deduplicates, exactly as its KDoc says, so the dedupe is the
                            // service's to do. A genuine re-issue carries a higher sequence and
                            // replaces; anything at or below what is held is stale.
                            val held = authorizations.getOrPut(key) { mutableListOf() }
                            val existing = held.firstOrNull {
                                it.authorizationId == signed.authorization.authorizationId
                            }
                            if (existing == null || existing.sequence < signed.authorization.sequence) {
                                if (existing != null) held.remove(existing)
                                held += signed.authorization
                            }
                        }
                        verdict
                    }
                }

                is SignedStatement.Revoke -> {
                    val stored = signed.revocation.subjectPublicKey.takeIf { it in accounts }
                    stored?.let { key ->
                        val verdict = Utils.verifyRevocation(signed.revocation, signed.signature, key)
                        if (verdict == StatementVerdict.VALID) {
                            revocations.getOrPut(key) { mutableListOf() } += signed.revocation
                        }
                        verdict
                    }
                }
            }

        /** Which devices may still take this account over, after the arithmetic T17 defines. */
        fun liveRecoveryKeys(publicKey: String): List<String> =
            Utils.liveAuthorizations(
                authorizations[publicKey].orEmpty(),
                revocations[publicKey].orEmpty(),
            ).map { it.recoveryPublicKey }
    }

    // ── Migration: the old device still works ────────────────────────────

    @Test
    fun `a user moves three accounts to a new phone`() {
        // Three services the user signed up to, each holding only the public key.
        val services = listOf(Service(), Service(), Service())
        services.forEachIndexed { i, service -> service.signUp(oldKeyBase64, "account-$i") }

        // Device B shows K_new; device A signs one statement per profile and relays it. One
        // statement per profile is the design: each service verifies for itself, and nothing the
        // user holds is shared between them.
        val envelope = Utils.encodeRotationStatement(
            RotationStatement(
                oldPublicKey = oldKeyBase64,
                newPublicKey = newKeyBase64,
                statementId = "rot-morning-1",
                issuedAtMillis = NOW,
                expiresAtMillis = NOW + 600_000L,
            ),
            signWith(oldKeyPair.private, statementBytes(oldKeyBase64, newKeyBase64, "rot-morning-1")),
        )

        services.forEachIndexed { i, service ->
            assertEquals(
                "service $i must accept a statement signed by the key it stores",
                StatementVerdict.VALID,
                service.accept(envelope, NOW + 1_000L),
            )
            assertEquals("the account moved", "account-$i", service.accountFor(newKeyBase64))
            assertNull("and the old key names nothing", service.accountFor(oldKeyBase64))
        }
    }

    /**
     * The negative twin, and the one that matters: an attacker who has the user's public key —
     * which every service they signed up to already has, and which a breach leaks — signs a
     * rotation onto their own key with their own device. The service must end with its stored
     * key **unchanged**.
     */
    @Test
    fun `an attacker signing with their own key changes nothing`() {
        val service = Service()
        service.signUp(oldKeyBase64, "account-1")

        val theft = RotationStatement(
            oldPublicKey = oldKeyBase64,
            newPublicKey = attackerKeyBase64,
            statementId = "rot-theft-1",
            issuedAtMillis = NOW,
            expiresAtMillis = NOW + 600_000L,
        )
        val envelope = Utils.encodeRotationStatement(
            theft,
            signWith(attackerKeyPair.private, Utils.rotationStatementBytes(theft)),
        )

        assertEquals(
            "a statement signed by anyone but the stored key stops at the signature",
            StatementVerdict.SIGNATURE_INVALID,
            service.accept(envelope, NOW + 1_000L),
        )
        assertEquals("the account is exactly where it was", "account-1", service.accountFor(oldKeyBase64))
        assertNull("and the attacker's key names nothing", service.accountFor(attackerKeyBase64))
        assertEquals(oldKeyBase64, service.keyOf("account-1"))
    }

    /**
     * The window is the signer's, and a service applies it: a statement relayed too late is
     * refused with a verdict that says why, rather than silently doing nothing.
     */
    @Test
    fun `a statement that arrives after its window is refused as expired`() {
        val service = Service()
        service.signUp(oldKeyBase64, "account-1")

        val statement = RotationStatement(
            oldPublicKey = oldKeyBase64,
            newPublicKey = newKeyBase64,
            statementId = "rot-late-1",
            issuedAtMillis = NOW,
            expiresAtMillis = NOW + 600_000L,
        )
        val envelope = Utils.encodeRotationStatement(
            statement,
            signWith(oldKeyPair.private, Utils.rotationStatementBytes(statement)),
        )

        assertEquals(
            StatementVerdict.EXPIRED,
            service.accept(envelope, NOW + 600_001L),
        )
        assertEquals("account-1", service.accountFor(oldKeyBase64))

        // And the same envelope, relayed inside the window, still works — so the refusal above is
        // the clock's doing and not the envelope's.
        assertEquals(StatementVerdict.VALID, service.accept(envelope, NOW + 600_000L))
        assertEquals("account-1", service.accountFor(newKeyBase64))
    }

    @Test
    fun `a profile the service never held is not its business`() {
        val service = Service()
        service.signUp(oldKeyBase64, "account-1")

        val stranger = RotationStatement(
            oldPublicKey = attackerKeyBase64,
            newPublicKey = newKeyBase64,
            statementId = "rot-stranger-1",
            issuedAtMillis = NOW,
            expiresAtMillis = NOW + 600_000L,
        )
        val envelope = Utils.encodeRotationStatement(
            stranger,
            signWith(attackerKeyPair.private, Utils.rotationStatementBytes(stranger)),
        )

        assertNull("no account, no verdict", service.accept(envelope, NOW + 1_000L))
        assertEquals("account-1", service.accountFor(oldKeyBase64))
        // Garbage off the relay is the same non-event.
        assertNull(service.accept("not an envelope", NOW))
        assertNull(service.accept(null, NOW))
    }

    // ── Recovery: the old device is gone ─────────────────────────────────

    /**
     * Mechanism 2, end to end: device A blesses a device the user already owns, the service
     * records it, and a later revocation — relayed on its own, possibly much later — takes it
     * back. The revocation is the only kill switch an authorization has, which is why the leg
     * that carries it is worth a test of its own.
     */
    @Test
    fun `a blessed device is recorded and a later revocation takes it back`() {
        val service = Service()
        service.signUp(oldKeyBase64, "account-1")

        val authorization = RecoveryAuthorization(
            subjectPublicKey = oldKeyBase64,
            recoveryPublicKey = newKeyBase64,
            authorizationId = "rec-tablet-1",
            sequence = 3L,
            issuedAtMillis = NOW,
        )
        assertEquals(
            StatementVerdict.VALID,
            service.accept(
                Utils.encodeRecoveryAuthorization(
                    authorization,
                    signWith(oldKeyPair.private, Utils.recoveryAuthorizationBytes(authorization)),
                ),
                NOW,
            ),
        )
        assertEquals(listOf(newKeyBase64), service.liveRecoveryKeys(oldKeyBase64))

        // A revocation at a lower sequence is a captured old one, and must change nothing.
        val stale = Revocation(oldKeyBase64, "rec-tablet-1", 2L, NOW + 1_000L)
        assertEquals(
            StatementVerdict.VALID,
            service.accept(
                Utils.encodeRevocation(stale, signWith(oldKeyPair.private, Utils.revocationBytes(stale))),
                NOW,
            ),
        )
        assertEquals(
            "a revocation at a lower sequence must not cancel anything",
            listOf(newKeyBase64),
            service.liveRecoveryKeys(oldKeyBase64),
        )

        val genuine = Revocation(oldKeyBase64, "rec-tablet-1", 4L, NOW + 2_000L)
        assertEquals(
            StatementVerdict.VALID,
            service.accept(
                Utils.encodeRevocation(genuine, signWith(oldKeyPair.private, Utils.revocationBytes(genuine))),
                NOW,
            ),
        )
        assertEquals(emptyList<String>(), service.liveRecoveryKeys(oldKeyBase64))
    }

    /**
     * The recovery leg's negative twin: a stranger's authorization for a profile this service
     * holds never gets recorded, so no device of theirs is ever live against it.
     */
    @Test
    fun `an authorization signed by anyone else is never recorded`() {
        val service = Service()
        service.signUp(oldKeyBase64, "account-1")

        val forged = RecoveryAuthorization(
            subjectPublicKey = oldKeyBase64,
            recoveryPublicKey = attackerKeyBase64,
            authorizationId = "rec-theft-1",
            sequence = 9L,
            issuedAtMillis = NOW,
        )

        assertEquals(
            StatementVerdict.SIGNATURE_INVALID,
            service.accept(
                Utils.encodeRecoveryAuthorization(
                    forged,
                    signWith(attackerKeyPair.private, Utils.recoveryAuthorizationBytes(forged)),
                ),
                NOW,
            ),
        )
        assertEquals(emptyList<String>(), service.liveRecoveryKeys(oldKeyBase64))
    }

    // ── Where the two mechanisms meet ────────────────────────────────────

    /**
     * The case neither mechanism's own tests reach, and the one that had a real bug in it: a
     * revocation and a rotation in the same service.
     *
     * A device is blessed, then stolen, then revoked — and then the user migrates to a new phone.
     * If the migration carried the authorization across but left the revocation behind, the
     * stolen device would be live again the moment the user did the most ordinary thing in the
     * product, which is exactly what T17's ordering exists to make impossible. Worse, it could
     * never be revoked a second time: a revocation must be signed by the subject key the
     * authorization names, and that key is the one the user just migrated away from.
     */
    @Test
    fun `a revoked device does not come back to life across a migration`() {
        val service = Service()
        service.signUp(oldKeyBase64, "account-1")

        val stolen = RecoveryAuthorization(oldKeyBase64, attackerKeyBase64, "rec-stolen", 3L, NOW)
        service.accept(
            Utils.encodeRecoveryAuthorization(
                stolen,
                signWith(oldKeyPair.private, Utils.recoveryAuthorizationBytes(stolen)),
            ),
            NOW,
        )
        assertEquals(
            "control: the device must genuinely be live before it is revoked",
            listOf(attackerKeyBase64),
            service.liveRecoveryKeys(oldKeyBase64),
        )

        val revoked = Revocation(oldKeyBase64, "rec-stolen", 4L, NOW + 1_000L)
        service.accept(
            Utils.encodeRevocation(revoked, signWith(oldKeyPair.private, Utils.revocationBytes(revoked))),
            NOW,
        )
        assertEquals(emptyList<String>(), service.liveRecoveryKeys(oldKeyBase64))

        val migration = RotationStatement(oldKeyBase64, newKeyBase64, "rot-1", NOW, NOW + 600_000L)
        assertEquals(
            StatementVerdict.VALID,
            service.accept(
                Utils.encodeRotationStatement(
                    migration,
                    signWith(oldKeyPair.private, Utils.rotationStatementBytes(migration)),
                ),
                NOW + 1_000L,
            ),
        )

        assertEquals(
            "the revoked device must not be live under the new key",
            emptyList<String>(),
            service.liveRecoveryKeys(newKeyBase64),
        )
        assertEquals(
            "nor left behind under the old one, which now names no account",
            emptyList<String>(),
            service.liveRecoveryKeys(oldKeyBase64),
        )
    }

    /**
     * The same rule applied to an authorization that was never revoked: it goes too. Not an
     * oversight — an authorization names the old key as its subject, so after the migration the
     * only key that could revoke it is the one the user has just stopped holding. A standing
     * credential nobody can withdraw is worse than no recovery plan, so the plan is re-issued
     * under the new key instead, which this test also plays.
     */
    @Test
    fun `a live authorization does not survive a migration either, and is re-issued`() {
        val service = Service()
        service.signUp(oldKeyBase64, "account-1")

        val tablet = RecoveryAuthorization(oldKeyBase64, attackerKeyBase64, "rec-tablet", 3L, NOW)
        service.accept(
            Utils.encodeRecoveryAuthorization(
                tablet,
                signWith(oldKeyPair.private, Utils.recoveryAuthorizationBytes(tablet)),
            ),
            NOW,
        )
        assertEquals(listOf(attackerKeyBase64), service.liveRecoveryKeys(oldKeyBase64))

        val migration = RotationStatement(oldKeyBase64, newKeyBase64, "rot-1", NOW, NOW + 600_000L)
        service.accept(
            Utils.encodeRotationStatement(
                migration,
                signWith(oldKeyPair.private, Utils.rotationStatementBytes(migration)),
            ),
            NOW + 1_000L,
        )
        assertEquals(emptyList<String>(), service.liveRecoveryKeys(newKeyBase64))
        // Asked of the *old* key, and this is the assertion that pins the drop rather than
        // observing an empty bucket the authorization was never in: the tablet was filed under
        // `oldKeyBase64` and nothing re-files it, so a service that merely failed to carry it
        // across would still answer `[attackerKeyBase64]` here. No revocation exists in this
        // test, so nothing else can be making it empty.
        assertEquals(
            "the authorization must be discarded, not just left behind under the old key",
            emptyList<String>(),
            service.liveRecoveryKeys(oldKeyBase64),
        )

        // Re-issued by the device that now holds the account, and live again — so the rule above
        // costs the user a re-blessing rather than the feature.
        val reissued = RecoveryAuthorization(newKeyBase64, attackerKeyBase64, "rec-tablet-2", 1L, NOW + 2_000L)
        assertEquals(
            StatementVerdict.VALID,
            service.accept(
                Utils.encodeRecoveryAuthorization(
                    reissued,
                    signWith(newKeyPair.private, Utils.recoveryAuthorizationBytes(reissued)),
                ),
                NOW + 2_000L,
            ),
        )
        assertEquals(listOf(attackerKeyBase64), service.liveRecoveryKeys(newKeyBase64))
    }

    /**
     * Why the revocation is *kept* when the authorization it cancels is dropped — the half of the
     * rule that only a second migration can distinguish.
     *
     * A user can migrate back: the first rotation frees the old key, so a later rotation onto it
     * is allowed and the key names an account again. If the service had thrown the revocation
     * away with the authorization, an attacker who kept a copy of the original authorization
     * envelope off the relay could replay it now — it is genuinely signed, its subject key names
     * an account again, and it verifies VALID — and the device revoked long ago would be live.
     * A revocation never expires precisely so that it can still answer this; holding it costs a
     * row.
     */
    @Test
    fun `a captured authorization replayed after migrating back is still revoked`() {
        val service = Service()
        service.signUp(oldKeyBase64, "account-1")

        val stolen = RecoveryAuthorization(oldKeyBase64, attackerKeyBase64, "rec-stolen", 3L, NOW)
        // The envelope an attacker sitting on the relay keeps a copy of.
        val captured = Utils.encodeRecoveryAuthorization(
            stolen,
            signWith(oldKeyPair.private, Utils.recoveryAuthorizationBytes(stolen)),
        )
        service.accept(captured, NOW)

        val revoked = Revocation(oldKeyBase64, "rec-stolen", 4L, NOW + 1_000L)
        service.accept(
            Utils.encodeRevocation(revoked, signWith(oldKeyPair.private, Utils.revocationBytes(revoked))),
            NOW,
        )
        assertEquals(emptyList<String>(), service.liveRecoveryKeys(oldKeyBase64))

        // Out to the new phone…
        val out = RotationStatement(oldKeyBase64, newKeyBase64, "rot-out", NOW, NOW + 600_000L)
        assertEquals(
            StatementVerdict.VALID,
            service.accept(
                Utils.encodeRotationStatement(out, signWith(oldKeyPair.private, Utils.rotationStatementBytes(out))),
                NOW + 1_000L,
            ),
        )
        // …and back again, which the freed key permits.
        val back = RotationStatement(newKeyBase64, oldKeyBase64, "rot-back", NOW, NOW + 600_000L)
        assertEquals(
            StatementVerdict.VALID,
            service.accept(
                Utils.encodeRotationStatement(back, signWith(newKeyPair.private, Utils.rotationStatementBytes(back))),
                NOW + 2_000L,
            ),
        )
        assertEquals("account-1", service.accountFor(oldKeyBase64))

        // The replay: genuine, correctly signed, and accepted as a statement…
        assertEquals(
            StatementVerdict.VALID,
            service.accept(captured, NOW + 3_000L),
        )
        // …and still dead, because the revocation that cancelled it was never thrown away.
        assertEquals(
            "a revocation is a permanent fact; discarding it would resurrect the device here",
            emptyList<String>(),
            service.liveRecoveryKeys(oldKeyBase64),
        )
    }

    /**
     * The limit of discarding, recorded rather than papered over — and the reason the KDoc tells
     * a vault to revoke before it strands anything.
     *
     * Dropping an authorization is *local forgetting*. It is not a fact about the world, and the
     * previous test's twin shows the difference: replay a captured envelope for an authorization
     * that was never revoked, once the key names an account again, and the credential is back. A
     * revocation would have stopped it — that is what the test above proves — but only the device
     * holding the old key can sign one, so the moment to do it is *during* the migration, while
     * that key is still in hand. Afterwards nobody can, for ever.
     *
     * Asserted as the behaviour it is, so that a future change which fixes it fails here loudly
     * rather than quietly disagreeing with the documentation.
     */
    @Test
    fun `an unrevoked authorization replayed after migrating back is live again, the recorded limit`() {
        val service = Service()
        service.signUp(oldKeyBase64, "account-1")

        val tablet = RecoveryAuthorization(oldKeyBase64, attackerKeyBase64, "rec-tablet", 3L, NOW)
        val captured = Utils.encodeRecoveryAuthorization(
            tablet,
            signWith(oldKeyPair.private, Utils.recoveryAuthorizationBytes(tablet)),
        )
        service.accept(captured, NOW)

        val out = RotationStatement(oldKeyBase64, newKeyBase64, "rot-out", NOW, NOW + 600_000L)
        service.accept(
            Utils.encodeRotationStatement(out, signWith(oldKeyPair.private, Utils.rotationStatementBytes(out))),
            NOW + 1_000L,
        )
        val back = RotationStatement(newKeyBase64, oldKeyBase64, "rot-back", NOW, NOW + 600_000L)
        service.accept(
            Utils.encodeRotationStatement(back, signWith(newKeyPair.private, Utils.rotationStatementBytes(back))),
            NOW + 2_000L,
        )
        assertEquals("control: the key names an account again", "account-1", service.accountFor(oldKeyBase64))
        assertEquals(
            "control: discarding really did clear it",
            emptyList<String>(),
            service.liveRecoveryKeys(oldKeyBase64),
        )

        assertEquals(StatementVerdict.VALID, service.accept(captured, NOW + 3_000L))
        assertEquals(
            "this is the limit of discarding: only a revocation would have made it stick",
            listOf(attackerKeyBase64),
            service.liveRecoveryKeys(oldKeyBase64),
        )
    }

    /**
     * Relaying the same authorization twice is not two authorizations, and a re-issue at a higher
     * sequence replaces rather than accumulates.
     *
     * The list this service keeps is fed straight off a relay an attacker can write to, so
     * "append whatever verifies" is an unbounded-growth path reachable by replaying one captured
     * envelope. [Utils.liveAuthorizations] deliberately filters rather than deduplicates — its
     * KDoc says so — which makes this the service's job, and the reference service is where an
     * integrator will read it.
     */
    @Test
    fun `a replayed authorization does not accumulate, and a re-issue replaces it`() {
        val service = Service()
        service.signUp(oldKeyBase64, "account-1")

        val tablet = RecoveryAuthorization(oldKeyBase64, attackerKeyBase64, "rec-tablet", 3L, NOW)
        val captured = Utils.encodeRecoveryAuthorization(
            tablet,
            signWith(oldKeyPair.private, Utils.recoveryAuthorizationBytes(tablet)),
        )

        repeat(4) { assertEquals(StatementVerdict.VALID, service.accept(captured, NOW)) }
        assertEquals(
            "four relays of one envelope must leave one authorization",
            listOf(attackerKeyBase64),
            service.liveRecoveryKeys(oldKeyBase64),
        )

        // A genuine re-issue of the same id at a higher sequence — what brings a device back
        // after a revocation at 4 — replaces rather than adding a second row.
        val reissued = tablet.copy(sequence = 5L, issuedAtMillis = NOW + 1_000L)
        assertEquals(
            StatementVerdict.VALID,
            service.accept(
                Utils.encodeRecoveryAuthorization(
                    reissued,
                    signWith(oldKeyPair.private, Utils.recoveryAuthorizationBytes(reissued)),
                ),
                NOW + 1_000L,
            ),
        )
        assertEquals(listOf(attackerKeyBase64), service.liveRecoveryKeys(oldKeyBase64))

        // And it really did replace: a revocation at 5 no longer reaches it, because the live
        // authorization is now at 5 and revocation is strictly-greater. Had the seq-3 row
        // survived alongside, this would still cancel that one and the device would drop out.
        val stale = Revocation(oldKeyBase64, "rec-tablet", 5L, NOW + 2_000L)
        service.accept(
            Utils.encodeRevocation(stale, signWith(oldKeyPair.private, Utils.revocationBytes(stale))),
            NOW + 2_000L,
        )
        assertEquals(
            "the held authorization must be the re-issued one, not the original",
            listOf(attackerKeyBase64),
            service.liveRecoveryKeys(oldKeyBase64),
        )
    }

    /**
     * The takeover the library cannot refuse for you. Every check in `verifyRotationStatement`
     * passes — the attacker really does hold the key they are rotating away from — and the
     * verdict really is VALID. Only the service's own account table can say that the key being
     * rotated *onto* is somebody else's, and if it does not, the victim's row is overwritten and
     * their account is gone.
     */
    @Test
    fun `a rotation onto a key that already names an account leaves that account alone`() {
        val service = Service()
        service.signUp(oldKeyBase64, "victim")
        service.signUp(attackerKeyBase64, "attacker")

        val takeover = RotationStatement(
            oldPublicKey = attackerKeyBase64,
            newPublicKey = oldKeyBase64,
            statementId = "rot-takeover-1",
            issuedAtMillis = NOW,
            expiresAtMillis = NOW + 600_000L,
        )
        val verdict = service.accept(
            Utils.encodeRotationStatement(
                takeover,
                signWith(attackerKeyPair.private, Utils.rotationStatementBytes(takeover)),
            ),
            NOW + 1_000L,
        )

        assertEquals(
            "the library has nothing to object to: the attacker signed for their own key",
            StatementVerdict.VALID,
            verdict,
        )
        assertEquals("the victim keeps their account", "victim", service.accountFor(oldKeyBase64))
        assertEquals("and the attacker keeps theirs", "attacker", service.accountFor(attackerKeyBase64))
    }

    private fun statementBytes(oldKey: String, newKey: String, id: String): ByteArray =
        Utils.rotationStatementBytes(
            RotationStatement(oldKey, newKey, id, NOW, NOW + 600_000L),
        )

    companion object {
        /** A fixed clock, so every window in this file means the same thing on every run. */
        private const val NOW = 1_770_000_000_000L

        private lateinit var oldKeyPair: KeyPair
        private lateinit var newKeyPair: KeyPair
        private lateinit var attackerKeyPair: KeyPair
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
            newKeyPair = generate()
            attackerKeyPair = generate()
            oldKeyBase64 = Base64.encodeToString(oldKeyPair.public.encoded, Base64.NO_WRAP)
            newKeyBase64 = Base64.encodeToString(newKeyPair.public.encoded, Base64.NO_WRAP)
            attackerKeyBase64 = Base64.encodeToString(attackerKeyPair.public.encoded, Base64.NO_WRAP)
        }

        private fun signWith(key: PrivateKey, bytes: ByteArray): ByteArray =
            Signature.getInstance("SHA256withRSA").run {
                initSign(key)
                update(bytes)
                sign()
            }
    }
}
