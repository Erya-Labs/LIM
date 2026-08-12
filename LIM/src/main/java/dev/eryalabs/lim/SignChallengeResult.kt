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
 */
data class SignChallengeResult(
    val signature: ByteArray,
    val algorithm: String?,
    val fields: Map<String, TypedField>,
    val requestCode: String?,
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
            requestCode == other.requestCode
    }

    override fun hashCode(): Int {
        var result = signature.contentHashCode()
        result = 31 * result + (algorithm?.hashCode() ?: 0)
        result = 31 * result + fields.hashCode()
        result = 31 * result + (requestCode?.hashCode() ?: 0)
        return result
    }
}
