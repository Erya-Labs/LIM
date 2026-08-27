package dev.eryalabs.lim

/**
 * The contents of a sign-challenge request intent, decoded by
 * [Utils.parseSignChallengeRequest].
 *
 * This is the vault's half of the authentication flow: a client built the intent with
 * [Utils.createSignChallengeIntent] and the vault decodes it here, instead of hand-reading
 * extras and Base64-decoding the nonce itself. Everything in it arrived from another app —
 * a hostile peer can send any bytes it likes, so the parser fails closed on a request whose
 * nonce is not decodable non-empty Base64, and nothing about a parsed request implies the
 * caller is entitled to a signature. Whether to sign is the vault's consent decision.
 *
 * @property publicKey   The Base64 public key naming the profile to authenticate. Never
 *                       blank — a challenge that names no profile cannot be answered, so the
 *                       parser returns `null` instead.
 * @property nonce       The decoded challenge bytes the client wants signed. Never empty.
 *                       Its layout is undeclared unless [nonceFormat] says otherwise; do not
 *                       read a timestamp out of an undeclared nonce, because any bytes have
 *                       a first eight and random ones read as a time.
 * @property requestCode The correlation token the client attached, or `null` when absent or
 *                       blank. Echo it back in the result so the client can match the answer
 *                       to its request.
 * @property nonceFormat The nonce layout the client declared under
 *                       [Utils.EXTRA_NONCE_FORMAT], or `null` when it declared none — the
 *                       legacy shape, and what every hand-rolled nonce stays. When it equals
 *                       [Utils.NONCE_FORMAT_TIMESTAMPED], the client is volunteering that
 *                       [Utils.nonceTimestamp] can read a real timestamp out of [nonce], so a
 *                       vault may apply its own freshness policy. The value travels
 *                       verbatim: it is a declaration, not an enum, and an unknown format is
 *                       reported rather than refused.
 * @property protocolVersion The protocol version the client declared under
 *                       [Utils.EXTRA_PROTOCOL_VERSION], or `null` when it declared nothing
 *                       usable — a legacy client, or a peer that sent a blank, non-numeric or
 *                       non-positive value. `null` means "the client did not say", never
 *                       "version 1 confirmed".
 */
data class SignChallengeRequest(
    val publicKey: String,
    val nonce: ByteArray,
    val requestCode: String?,
    val nonceFormat: String? = null,
    val protocolVersion: Int? = null,
) {

    // A data class compares an array property by identity, so the generated equals() would
    // call two requests with identical bytes unequal. Compare the contents instead.
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SignChallengeRequest) return false
        return publicKey == other.publicKey &&
            nonce.contentEquals(other.nonce) &&
            requestCode == other.requestCode &&
            nonceFormat == other.nonceFormat &&
            protocolVersion == other.protocolVersion
    }

    override fun hashCode(): Int {
        var result = publicKey.hashCode()
        result = 31 * result + nonce.contentHashCode()
        result = 31 * result + (requestCode?.hashCode() ?: 0)
        result = 31 * result + (nonceFormat?.hashCode() ?: 0)
        result = 31 * result + (protocolVersion?.hashCode() ?: 0)
        return result
    }

    /**
     * Renders the nonce as its length, not its bytes. A nonce is not personal data, but it is
     * a live challenge: a log line carrying the exact bytes a client is waiting to have signed
     * is one more place those bytes can be read from, and its length is all a debugging
     * session needs. The public key prints in full, the [QueryResult] precedent — it is the
     * opaque handle the design hands out freely, and what makes the line identifiable.
     */
    override fun toString(): String =
        "SignChallengeRequest(publicKey=$publicKey, nonce=<${nonce.size} bytes>, " +
            "requestCode=$requestCode, nonceFormat=$nonceFormat, protocolVersion=$protocolVersion)"
}
