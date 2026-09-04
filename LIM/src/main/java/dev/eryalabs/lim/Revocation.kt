package dev.eryalabs.lim

/**
 * A signed cancellation of a [RecoveryAuthorization]: the only kill switch a standing credential
 * has, because an authorization deliberately carries no expiry.
 *
 * A pre-signed authorization is a spare house key, and a user who loses the spare — or falls out
 * with whoever held it — needs to change the lock. That is this. The healthy device signs a
 * revocation naming the authorization, it is distributed the same way the authorization was, and
 * a fresh authorization can be issued afterwards at a higher [sequence].
 *
 * **This is a small PKI, with the freshness problem that implies.** A revocation is only
 * effective once a service has actually seen it, so a thief holding a stolen recovery device
 * races the revocation to whichever service it reaches first. Nothing in this library can close
 * that gap — LIM has no network leg, which is the property the whole design exists for — so what
 * it can do instead is make the ordering decidable from statements that arrive in any order:
 * see [sequence].
 *
 * **No window, on purpose.** A revocation that could go stale would *un-revoke* a stolen device,
 * which is the worst failure this feature has, so [Utils.verifyRevocation] checks no window and
 * this class declares none.
 *
 * Nothing in this class signs anything. The private key lives in the vault's Keystore, so this
 * library supplies the bytes to sign ([Utils.revocationBytes]) and the verification a service
 * performs ([Utils.verifyRevocation]). Its pre-image carries the same [Utils.STATEMENT_DOMAIN_V1]
 * prefix the other two kinds do, so [Utils.isStatementPreImage] covers it and a vault must refuse
 * to sign a nonce that matches.
 *
 * @property subjectPublicKey       The Base64 RSA public key this revocation is about, and the
 *                                  key whose holder must sign it. Compared against the stored key
 *                                  by exact string equality, so a revocation cannot reach across
 *                                  to another profile even if an id happens to collide.
 * @property revokedAuthorizationId The [RecoveryAuthorization.authorizationId] being cancelled.
 *                                  Matched exactly — no trimming, no case folding: these are
 *                                  opaque handles the signer minted, and normalising one merges
 *                                  two things it deliberately kept apart.
 * @property sequence               The monotonic counter that makes ordering decidable. A
 *                                  revocation cancels an authorization only when its sequence is
 *                                  *strictly greater*, so a captured old revocation cannot kill a
 *                                  newer re-issue and a revoked device can be brought back
 *                                  deliberately at a higher number.
 * @property issuedAtMillis         Milliseconds since the epoch, raw — a record for an audit
 *                                  trail rather than an input to any decision, since ordering
 *                                  here is by [sequence] and never by clock. Two devices'
 *                                  clocks disagree; their sequences are minted by one signer.
 */
data class Revocation(
    val subjectPublicKey: String,
    val revokedAuthorizationId: String,
    val sequence: Long,
    val issuedAtMillis: Long,
) {

    /**
     * The one key previewed rather than printed whole, matching [RotationStatement] and
     * [RecoveryAuthorization]. The id prints in full: it is minted by the signing device, so —
     * like `RotationStatement.statementId` — it is a nonce rather than somewhere a user's data
     * ends up, and it is the first thing a reader needs when a revocation did not match.
     */
    override fun toString(): String =
        "Revocation(subjectPublicKey=${previewedPublicKey(subjectPublicKey)}, " +
            "revokedAuthorizationId=$revokedAuthorizationId, sequence=$sequence, " +
            "issuedAtMillis=$issuedAtMillis)"
}
