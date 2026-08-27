package dev.eryalabs.lim

/**
 * The contents of a share result intent, decoded by [Utils.parseShareResult].
 *
 * A share pushes an [Entry] into the vault with [Utils.createShareIntent] +
 * `startActivityForResult`; the vault answers with the public key it stored the profile
 * under. Nothing here is authenticated — a share result says "the vault told us this", not
 * "this profile proved it holds the private key". Use [Utils.createSignChallengeIntent] and
 * [SignChallengeResult.isVerified] when you need proof of possession.
 *
 * @property publicKey   The Base64 public key the vault stored the entry under, or `null`
 *                       when the vault echoed none. This is the handle to keep: it is how the
 *                       profile is queried and authenticated from now on.
 * @property fields      The stored typed fields as the vault echoed them, decoded from
 *                       [Utils.EXTRA_FIELDS_JSON]. Empty when the payload was absent or
 *                       malformed.
 * @property requestCode The correlation token echoed back by the vault, or `null` when absent
 *                       or blank — the vault only echoes one when the share was created with
 *                       the [Utils.createShareIntent] overload that carries one.
 * @property vaultProtocolVersion The protocol version the vault echoed under
 *                       [Utils.EXTRA_PROTOCOL_VERSION], or `null` when it echoed nothing
 *                       usable — a legacy vault, or a peer that sent a blank, non-numeric or
 *                       non-positive value. `null` means "the vault did not say", never
 *                       "version 1 confirmed": only a non-null value proves the vault speaks
 *                       a versioned protocol and saw yours.
 */
data class ShareResult(
    val publicKey: String?,
    val fields: Map<String, TypedField>,
    val requestCode: String?,
    val vaultProtocolVersion: Int? = null,
)
