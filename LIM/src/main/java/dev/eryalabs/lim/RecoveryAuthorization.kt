package dev.eryalabs.lim

/**
 * A signed claim by the holder of one key that a *second device the user already owns* may take
 * over from it later: the standing credential mechanism 2 of the approved recovery design rests
 * on.
 *
 * The difference from a [RotationStatement] is when it is signed, and it is the whole point.
 * A rotation is signed while the old device still works, naming the replacement the user is
 * holding at that moment. A recovery authorization is signed *in advance*, while the device is
 * healthy, so that when it is lost — stolen, drowned, dead — a device that was blessed months ago
 * can rotate the user onto a new key with nothing left to sign for it. The trust model is a spare
 * house key: whoever holds the recovery device can take over the accounts.
 *
 * **There is deliberately no expiry, and that is a design commitment rather than an omission.**
 * An authorization that expires before the emergency is worthless — the emergency is exactly the
 * situation in which nobody can refresh it, because the device that would sign the refresh is
 * gone. So the only kill switch is a [Revocation], and the consequence has to be accepted
 * explicitly: an authorization is live until a service is *shown* a revocation, so a service that
 * is never shown one honours this forever. Distributing revocations is therefore load-bearing,
 * and ordering them is what stops a superseded authorization coming back — see [sequence].
 *
 * Nothing in this class signs anything. The private key lives in the vault's Keystore and never
 * leaves the signing device, so this library supplies the bytes to sign
 * ([Utils.recoveryAuthorizationBytes]) and the verification a service performs
 * ([Utils.verifyRecoveryAuthorization]).
 *
 * **The oracle hazard applies here too.** Its pre-image carries the same
 * [Utils.STATEMENT_DOMAIN_V1] prefix a rotation's does, so [Utils.isStatementPreImage] covers all
 * three statement kinds with one predicate — and a vault must still call it on every nonce before
 * signing and refuse a match. Being tricked into signing one of *these* is worse than being
 * tricked into signing a rotation: a rotation names a window, and this names none.
 *
 * **No personal data, structurally.** An authorization has no slot for a field value, which is
 * why it can cross a relay the profile data never touches. [toString] previews the two keys for
 * readability, the [RotationStatement] precedent.
 *
 * @property subjectPublicKey  The Base64 RSA public key this authorization is about: the key the
 *                            service stores today, and the key whose holder must sign. Compared
 *                            against the stored key by exact string equality — the protocol
 *                            identifies a profile by the key *string*.
 * @property recoveryPublicKey The Base64 RSA public key of the device being blessed. A service
 *                            that accepts a key it cannot parse has blessed a device that can
 *                            never actually be used, so it is checked rather than trusted
 *                            because it was signed.
 * @property authorizationId   An opaque identifier the signer mints. It is what a [Revocation]
 *                            names, so it is the handle by which this authorization can later be
 *                            cancelled; two authorizations sharing an id cannot be revoked apart.
 * @property sequence          A monotonic counter the signer controls. A revocation kills this
 *                            authorization only when it carries a *strictly greater* sequence,
 *                            which is what lets a revoked device be re-authorized later at a
 *                            higher number and what makes a captured old revocation useless
 *                            against a newer authorization.
 * @property issuedAtMillis    Milliseconds since the epoch, raw. Not a formatted date: a
 *                            timestamp inside a signature must never depend on a calendar, a
 *                            timezone or a locale's digits. Nothing verifies it — there is no
 *                            window here — so it is a record for a human reading an audit trail,
 *                            not an input to a decision.
 */
data class RecoveryAuthorization(
    val subjectPublicKey: String,
    val recoveryPublicKey: String,
    val authorizationId: String,
    val sequence: Long,
    val issuedAtMillis: Long,
) {

    /**
     * Both keys previewed rather than printed whole — the [RotationStatement] precedent. Two full
     * X.509 keys is most of a log line for a pair of strings identical in their first 44
     * characters; a truncated pair still says which authorization this is.
     */
    override fun toString(): String =
        "RecoveryAuthorization(subjectPublicKey=${previewedPublicKey(subjectPublicKey)}, " +
            "recoveryPublicKey=${previewedPublicKey(recoveryPublicKey)}, " +
            "authorizationId=$authorizationId, sequence=$sequence, " +
            "issuedAtMillis=$issuedAtMillis)"
}
