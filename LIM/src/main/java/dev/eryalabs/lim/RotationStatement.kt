package dev.eryalabs.lim

/**
 * A signed claim by the holder of one key that another key replaces it: `K_old` authorizing
 * `K_new` for a single profile, inside a window it declares itself.
 *
 * This is the migration statement the approved device-migration design turns on. The public key
 * *is* the account identifier in this protocol, so moving a user to a new device means telling
 * every service that stored the old key to store the new one instead — and the only thing that
 * can say so credibly is a signature by the key the service already holds.
 *
 * Nothing in this class signs anything. The private key lives in the vault's Keystore and never
 * leaves the signing device, so this library supplies the bytes to sign
 * ([Utils.rotationStatementBytes]) and the verification a service performs; the signature itself
 * is produced on the device, over exactly those bytes.
 *
 * **The oracle hazard, because it is what the pre-image's domain prefix exists for.** The
 * sign-challenge flow signs *arbitrary caller-supplied bytes* with the very key a rotation is
 * verified against, and every component below is public or attacker-chosen: `oldPublicKey` is the
 * identifier the service already stores, `newPublicKey` would be the attacker's own key, and the
 * id and timestamps are free. So an attacker can hand a vault a rotation pre-image dressed as a
 * login challenge and present the answer as a rotation. A verifier cannot tell the two apart —
 * the bytes are the bytes — which is why the check belongs on the signing device:
 * [Utils.isStatementPreImage] is what a vault calls on every nonce before signing, and it must
 * refuse a match.
 *
 * **No personal data, structurally.** A rotation statement has no slot for a field value, which
 * is why it can cross a relay that the profile data never touches. [toString] therefore redacts
 * nothing — it previews the two keys for readability, the [Entry] precedent, so a log line says
 * which rotation it is looking at without running to two full keys.
 *
 * The properties are non-null by construction and nothing in this library builds one through
 * Gson, so — unlike [Entry] — the `Unsafe` hazard [Utils.decodeEntry] exists for does not reach
 * here.
 *
 * @property oldPublicKey    The Base64 RSA public key being replaced: the key the service stores
 *                           today, and the key whose holder must sign this statement. Compared
 *                           against the stored key by exact string equality — the protocol
 *                           identifies a profile by the key *string*, and two spellings of one
 *                           key are two different accounts to every service.
 * @property newPublicKey    The Base64 RSA public key that replaces it. A service that swaps in
 *                           a key it cannot parse has locked the user out permanently, so it is
 *                           checked before the swap rather than trusted because it was signed.
 * @property statementId     An opaque identifier the signer mints, distinguishing one rotation
 *                           from another so a captured statement cannot be passed off as a
 *                           second one. Printed in full by [toString]: unlike `Entry.id` this is
 *                           minted by the signing device rather than supplied by an integrating
 *                           client, so it is a nonce, not somewhere a user's email ends up.
 * @property issuedAtMillis  Milliseconds since the epoch, raw. Not a formatted date: a
 *                           timestamp inside a signature must never depend on a calendar, a
 *                           timezone or a locale's digits.
 * @property expiresAtMillis Milliseconds since the epoch after which this statement is stale.
 *                           The window is the signer's own declaration and both ends are
 *                           inclusive; no default is baked in here, because a lifetime this
 *                           library chose would silently become the one the protocol enforces.
 */
data class RotationStatement(
    val oldPublicKey: String,
    val newPublicKey: String,
    val statementId: String,
    val issuedAtMillis: Long,
    val expiresAtMillis: Long,
) {

    /**
     * Both keys previewed rather than printed whole — the [Entry] precedent, not
     * [SignChallengeRequest]'s print-in-full. A statement carries *two* keys, and two full
     * X.509 keys is most of a log line for a pair of strings that are identical in their first
     * 44 characters; a truncated pair still tells a debugging session which rotation this is.
     */
    override fun toString(): String =
        "RotationStatement(oldPublicKey=${previewedPublicKey(oldPublicKey)}, " +
            "newPublicKey=${previewedPublicKey(newPublicKey)}, statementId=$statementId, " +
            "issuedAtMillis=$issuedAtMillis, expiresAtMillis=$expiresAtMillis)"
}
