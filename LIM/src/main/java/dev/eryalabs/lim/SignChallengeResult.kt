package dev.eryalabs.lim

/**
 * The contents of a sign-challenge result intent, decoded by [Utils.parseSignChallengeResult].
 *
 * **Parsed is not authenticated.** Everything in here was written by another app and is
 * unverified until [isVerified] says otherwise — including [fields], which is the profile
 * data the vault chose to disclose. Nothing on this class reports success on its own: the
 * only way to learn whether the signature is genuine is to hand [isVerified] the public key
 * and the nonce *you* sent, because those are the two values a hostile result cannot supply
 * for you.
 *
 * @property signature   Raw signature bytes, Base64-decoded from [Utils.EXTRA_SIGNATURE].
 * @property algorithm   The algorithm the vault reported in [Utils.EXTRA_ALGORITHM], or `null`
 *                       when it sent none. Informational only — [Utils.verifySignature] always
 *                       verifies with `SHA256withRSA` and never with a caller- or peer-supplied
 *                       algorithm, because honouring this value is an algorithm-confusion
 *                       attack surface.
 * @property fields      The profile's typed fields, decoded from [Utils.EXTRA_FIELDS_JSON].
 *                       Empty when the payload was absent or malformed. Do not act on these
 *                       until [isVerified] has returned `true`.
 * @property requestCode The correlation token echoed back by the vault, or `null` when absent
 *                       or blank.
 * @property vaultProtocolVersion The protocol version the vault echoed under
 *                       [Utils.EXTRA_PROTOCOL_VERSION], or `null` when it echoed nothing
 *                       usable — a legacy vault, or a peer that sent a blank, non-numeric or
 *                       non-positive value. `null` means "the vault did not say", never
 *                       "version 1 confirmed". Unverified like everything else here: it says
 *                       which protocol the sender claims to speak, not that the signature is
 *                       genuine.
 */
data class SignChallengeResult(
    val signature: ByteArray,
    val algorithm: String?,
    val fields: Map<String, TypedField>,
    val requestCode: String?,
    val vaultProtocolVersion: Int? = null,
) {

    /**
     * Verify this result against the challenge you issued: `true` only when [signature] is a
     * genuine `SHA256withRSA` signature over [nonce] by the private key paired to
     * [publicKeyBase64].
     *
     * Pass the values you kept from your own [Utils.createSignChallengeIntent] call — never
     * a public key or nonce read back out of the result intent, which would let the sender
     * choose both sides of the proof. Freshness is a separate question: check the nonce with
     * [Utils.isNonceFresh] as well, or a signature captured today can be replayed tomorrow.
     *
     * **Example**, verbatim from `docs/INTEGRATION.md`'s *Login (sign-challenge)* section —
     * this call is the last of the four clauses, and the only one that proves anything:
     *
     * <!-- example: INTEGRATION.md#login-result -->
     * ```kotlin
     * // In onActivityResult. Verify against the key your account table already holds and the
     * // nonce you generated — never against either one read back out of the result, or the
     * // sender gets to choose both sides of the proof.
     * val result = Utils.parseSignChallengeResult(data)
     * val loggedIn = resultCode == Activity.RESULT_OK &&
     *     Utils.matchesRequestCode(data, LOGIN_REQUEST) &&
     *     Utils.isNonceFresh(nonce, maxAgeMillis = 60_000L) &&
     *     result?.isVerified(storedPublicKey, nonce) == true
     * ```
     *
     * @param publicKeyBase64 The Base64 RSA public key you already store for this profile — the
     *                        account identifier. Never [Utils.EXTRA_PUBLIC_KEY] off this result's
     *                        own intent: that is the sender's claim about whose key it is, and
     *                        verifying against it proves only that the sender holds the key the
     *                        sender named.
     * @param nonce           The exact challenge bytes you sent, kept from your own
     *                        [Utils.createSignChallengeIntent] call. Freshness is not checked
     *                        here — this answers "is the signature genuine", not "is it recent".
     */
    fun isVerified(publicKeyBase64: String, nonce: ByteArray): Boolean =
        Utils.verifySignature(publicKeyBase64, nonce, signature)

    // A data class compares an array property by identity, so the generated equals() would
    // call two results with identical bytes unequal. Compare the contents instead.
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SignChallengeResult) return false
        return signature.contentEquals(other.signature) &&
            algorithm == other.algorithm &&
            fields == other.fields &&
            requestCode == other.requestCode &&
            vaultProtocolVersion == other.vaultProtocolVersion
    }

    override fun hashCode(): Int {
        var result = signature.contentHashCode()
        result = 31 * result + (algorithm?.hashCode() ?: 0)
        result = 31 * result + fields.hashCode()
        result = 31 * result + (requestCode?.hashCode() ?: 0)
        result = 31 * result + (vaultProtocolVersion?.hashCode() ?: 0)
        return result
    }
}
