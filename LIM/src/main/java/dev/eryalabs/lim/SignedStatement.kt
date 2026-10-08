package dev.eryalabs.lim

/**
 * A signed statement as it arrived from another device: the statement itself, and the raw
 * signature over its canonical pre-image. One case per statement kind, produced by
 * [Utils.parseSignedStatement].
 *
 * **A statement nobody can transmit is not a protocol.** Device A's signed statements have to
 * reach device B and then each installed app, so this library defines one text form
 * ([Utils.encodeRotationStatement] and its two siblings) and one parser for it. Without that,
 * every relay would invent its own shape and the vault would have to guess.
 *
 * **Parsed is not verified, and this type deliberately offers no way to confuse the two.** There
 * is no success flag, no `isValid`, nothing a caller can read to feel reassured: the only thing
 * that settles whether a statement is genuine is handing it — with the public key the service
 * *already stores* — to [Utils.verifyRotationStatement], [Utils.verifyRecoveryAuthorization] or
 * [Utils.verifyRevocation]. That separation is the same one [SignChallengeResult] keeps, and it
 * is pinned by a reflection test in `StatementEnvelopeTest` that fails if anyone adds an
 * argument-free `Boolean` accessor to any case here.
 *
 * A `when` over the three cases is exhaustive, so a kind added later breaks the compilation of
 * an integrator who must then decide what to do about it — which is the right place for that
 * decision, rather than a silent `else` that drops it.
 *
 * See `MigrationEndToEndTest` for the whole flow written the way an integrator would write it:
 * device A signs, the envelope crosses, a service verifies against the key it stores and swaps.
 *
 * @property signature The raw signature bytes over the statement's canonical pre-image. Present
 *                     on every case; meaningless until verified against a stored public key.
 */
sealed class SignedStatement {

    abstract val signature: ByteArray

    /**
     * A [RotationStatement] and its signature — `K_old` authorizing `K_new` for one profile,
     * inside the window the statement declares.
     *
     * Named for the kind tag it travels under ([Utils.STATEMENT_ROTATE_V1]), like its two
     * siblings, so the case a reader is looking at names the bytes on the wire.
     *
     * @property statement The rotation the envelope carried, read back out of the signed
     *                     pre-image itself rather than from fields listed alongside it — which is
     *                     why re-encoding it with [Utils.rotationStatementBytes] reproduces the
     *                     bytes the relay delivered, and why a verifier can be handed this object
     *                     instead of the transmitted bytes.
     */
    data class Rotate(
        val statement: RotationStatement,
        override val signature: ByteArray,
    ) : SignedStatement() {

        // A data class compares an array property by identity, so the generated equals() would
        // call two envelopes carrying identical bytes unequal. Compare the contents instead —
        // the `SignChallengeRequest` precedent.
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Rotate) return false
            return statement == other.statement && signature.contentEquals(other.signature)
        }

        override fun hashCode(): Int = 31 * statement.hashCode() + signature.contentHashCode()

        /**
         * The statement renders itself (both keys previewed); the signature renders as its
         * length. Printing 344 characters of Base64 that nobody can read at a glance would push
         * the part a debugging session needs off the end of the line.
         */
        override fun toString(): String =
            "SignedStatement.Rotate(statement=$statement, signature=<${signature.size} bytes>)"
    }

    /**
     * A [RecoveryAuthorization] and its signature — a standing credential for a device the user
     * already owns, live until a [Revocation] cancels it.
     *
     * @property authorization The authorization the envelope carried, read back out of the signed
     *                         pre-image, so [Utils.recoveryAuthorizationBytes] of it reproduces
     *                         the transmitted bytes exactly.
     */
    data class Recover(
        val authorization: RecoveryAuthorization,
        override val signature: ByteArray,
    ) : SignedStatement() {

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Recover) return false
            return authorization == other.authorization && signature.contentEquals(other.signature)
        }

        override fun hashCode(): Int = 31 * authorization.hashCode() + signature.contentHashCode()

        override fun toString(): String =
            "SignedStatement.Recover(authorization=$authorization, " +
                "signature=<${signature.size} bytes>)"
    }

    /**
     * A [Revocation] and its signature — the only kill switch a recovery authorization has, so
     * the one whose delivery is load-bearing rather than housekeeping.
     *
     * @property revocation The revocation the envelope carried, read back out of the signed
     *                      pre-image, so [Utils.revocationBytes] of it reproduces the transmitted
     *                      bytes exactly.
     */
    data class Revoke(
        val revocation: Revocation,
        override val signature: ByteArray,
    ) : SignedStatement() {

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Revoke) return false
            return revocation == other.revocation && signature.contentEquals(other.signature)
        }

        override fun hashCode(): Int = 31 * revocation.hashCode() + signature.contentHashCode()

        override fun toString(): String =
            "SignedStatement.Revoke(revocation=$revocation, signature=<${signature.size} bytes>)"
    }
}
