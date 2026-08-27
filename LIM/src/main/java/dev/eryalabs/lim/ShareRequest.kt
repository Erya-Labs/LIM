package dev.eryalabs.lim

/**
 * The contents of a share request intent, decoded by [Utils.parseShareRequest].
 *
 * This is the vault's half of the share flow: a client built the intent with
 * [Utils.createShareIntent] and the vault decodes it here, instead of hand-reading extras.
 * Everything in it crossed an IPC boundary from another app, so nothing is trusted — the
 * parser only returns a request whose [entry] passed [Utils.decodeEntry], which is the same
 * bar the rest of the protocol holds entry payloads to.
 *
 * @property entry       The pushed entry, decoded and repaired by [Utils.decodeEntry]: fully
 *                       populated, safe to dereference, and carrying a non-blank identity.
 * @property requestCode The correlation token the client attached, or `null` when absent or
 *                       blank — only the [Utils.createShareIntent] overload taking one attaches
 *                       it. Echo it back in the result so the client can match the answer to
 *                       its request.
 * @property protocolVersion The protocol version the client declared under
 *                       [Utils.EXTRA_PROTOCOL_VERSION], or `null` when it declared nothing
 *                       usable — a legacy client, or a peer that sent a blank, non-numeric or
 *                       non-positive value. `null` means "the client did not say", never
 *                       "version 1 confirmed".
 */
data class ShareRequest(
    val entry: Entry,
    val requestCode: String?,
    val protocolVersion: Int? = null,
)
