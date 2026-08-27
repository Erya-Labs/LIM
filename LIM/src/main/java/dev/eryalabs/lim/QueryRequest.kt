package dev.eryalabs.lim

/**
 * The contents of a query request intent, decoded by [Utils.parseQueryRequest].
 *
 * This is the vault's half of the query flow: a client built the intent with
 * [Utils.createQueryIntent] and the vault decodes it here, instead of hand-reading extras.
 * A query and a share travel under the same action, distinguished by their payload — an
 * intent carrying an entry payload is a share, so [Utils.parseQueryRequest] refuses it and
 * [Utils.parseShareRequest] is the parser that accepts it.
 *
 * Nothing here is authenticated: any app can put a public key in an intent. A query request
 * says "someone asked about this key", and what the vault discloses in response is a consent
 * decision, not something this class settles.
 *
 * @property publicKey   The Base64 public key the client is asking about. Never blank — a
 *                       query that names no profile is not a query, so the parser returns
 *                       `null` instead of a request with nothing to look up.
 * @property requestCode The correlation token the client attached, or `null` when absent or
 *                       blank. Echo it back in the result so the client can match the answer
 *                       to its request.
 * @property protocolVersion The protocol version the client declared under
 *                       [Utils.EXTRA_PROTOCOL_VERSION], or `null` when it declared nothing
 *                       usable — a legacy client, or a peer that sent a blank, non-numeric or
 *                       non-positive value. `null` means "the client did not say", never
 *                       "version 1 confirmed".
 */
data class QueryRequest(
    val publicKey: String,
    val requestCode: String?,
    val protocolVersion: Int? = null,
)
