package dev.eryalabs.lim

/**
 * The contents of a query result intent, decoded by [Utils.parseQueryResult].
 *
 * A query asks the vault for a stored profile by public key; the vault answers with whatever
 * the user consented to disclose. There is no signature in this flow, so nothing here is
 * authenticated — a query result says "the vault told us this", not "this profile proved it
 * holds the private key". Use [Utils.createSignChallengeIntent] and
 * [SignChallengeResult.isVerified] when you need proof of possession.
 *
 * @property fields      The disclosed typed fields, decoded from
 *                       [Utils.EXTRA_QUERY_RESULT_FIELDS]. Empty when the payload was absent
 *                       or malformed — an empty map means "nothing disclosed", which is a
 *                       legitimate answer.
 * @property publicKey   The Base64 public key the result is about, or `null` when the vault
 *                       echoed none.
 * @property requestCode The correlation token echoed back by the vault, or `null` when absent
 *                       or blank.
 */
data class QueryResult(
    val fields: Map<String, TypedField>,
    val publicKey: String?,
    val requestCode: String?,
)
