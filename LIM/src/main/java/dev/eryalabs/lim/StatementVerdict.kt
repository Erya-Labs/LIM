package dev.eryalabs.lim

/**
 * The answer a service gets when it checks a signed statement against the key it already stores.
 *
 * A verdict rather than a `Boolean`, and deliberately so: an integrator handed `false` learns
 * that something is wrong and nothing about what, and "why did this rotation fail" is the
 * support question this feature generates. Each value below names one refusal a service can act
 * on and, where it matters, tell the user about.
 *
 * **A verdict is not a permission.** [VALID] says the holder of the stored key signed exactly
 * these bytes inside the window the statement declares — nothing more. In particular it cannot
 * say whether they signed them *knowingly*: see [Utils.verifyRotationStatement] for the oracle
 * limit, which is enforced on the signing device by [Utils.isStatementPreImage] and is not
 * something any verifier can check afterwards.
 *
 * Not every value is reachable from every verifier. A verifier documents the subset it can
 * return, so an integrator writing an exhaustive `when` knows which branches are real: a
 * statement with no window can never be [EXPIRED], and one naming no second key can never be
 * [SAME_KEY] or [NEW_KEY_UNUSABLE].
 */
enum class StatementVerdict {

    /**
     * The statement is genuine, addressed to this profile, names a usable new key, and `now`
     * falls inside its declared window. This is the only value on which a service should act.
     */
    VALID,

    /**
     * The signature is not a genuine `SHA256withRSA` signature over this statement's canonical
     * pre-image by the private key paired to the stored public key.
     *
     * Checked first, and that ordering is part of the contract: a forged, tampered or unsigned
     * statement can only ever come back as this, and never as a verdict describing it as merely
     * expired or addressed elsewhere. Those verdicts describe what a *genuine* statement says;
     * saying them about bytes nobody signed would dress an attacker's payload up as an ordinary
     * failure.
     */
    SIGNATURE_INVALID,

    /**
     * The statement is genuinely signed, but it is about a different profile: its subject key is
     * not the key this service stores.
     *
     * This is what stops a valid statement being replayed onto another account. The comparison
     * is exact string equality, because the protocol identifies a profile by the public-key
     * *string* — see [Utils.verifyRotationStatement].
     */
    WRONG_SUBJECT,

    /**
     * The statement names the key already stored as its replacement, so honouring it would
     * change nothing. A no-op rotation is either noise or an attempt to make a service act on a
     * statement that says nothing, so it is refused rather than silently applied.
     */
    SAME_KEY,

    /**
     * The replacement key is blank, is not standard Base64, or does not parse as an X.509 RSA
     * public key.
     *
     * Checked *before* the swap and not trusted because it was signed: a service that stores a
     * key it cannot parse has locked the user out permanently, and no later statement can help
     * because there is no longer a key that can sign one.
     */
    NEW_KEY_UNUSABLE,

    /** `now` is past the statement's `expiresAtMillis`. The end is inclusive: exactly the
     *  expiry instant is still valid, one millisecond later is not. */
    EXPIRED,

    /** `now` is before the statement's `issuedAtMillis` — a statement from the future, which is
     *  what a skewed clock on either device produces. The start is inclusive too. */
    NOT_YET_VALID,
}
