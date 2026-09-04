package dev.eryalabs.lim

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Which recovery authorizations are still live, given the revocations a service has been shown.
 *
 * `RecoveryVerificationTest` answers "did the subject's key sign this?"; this answers the question
 * that comes next and is entirely separate from it — "does this statement still count?". The two
 * are kept apart on purpose: [Utils.isRevoked] and [Utils.liveAuthorizations] make **no
 * authenticity claim at all**, so every input here is constructed rather than signed, exactly as an
 * integrator's already-verified statements would arrive.
 *
 * The rule under test is one line — a revocation kills an authorization when it carries the same
 * subject key, names its id, and has a *strictly greater* sequence — and almost every test below
 * exists because one plausible mis-reading of that line is a real security failure: `>=` for `>`
 * quietly kills every re-issued device, a fuzzy id match merges two handles the signer kept apart,
 * and a blank id matching another blank id lets a revocation naming nobody cancel everything.
 *
 * Pure Kotlin, no Android surface, so it runs on the bare JVM without Robolectric.
 */
class RevocationOrderingTest {

    private companion object {
        const val SUBJECT = "subject-key-base64"
        const val OTHER_SUBJECT = "other-profile-key-base64"
    }

    private fun authorization(
        subject: String = SUBJECT,
        recovery: String = "recovery-key-base64",
        id: String = "rec-0001",
        sequence: Long = 7L,
        issued: Long = 1_770_000_000_000L,
    ) = RecoveryAuthorization(subject, recovery, id, sequence, issued)

    private fun revocation(
        subject: String = SUBJECT,
        revoked: String = "rec-0001",
        sequence: Long = 8L,
        issued: Long = 1_770_000_000_100L,
    ) = Revocation(subject, revoked, sequence, issued)

    /**
     * A `List<Revocation>` carrying a genuine `null`, which Kotlin's type will not admit but a
     * Java caller reaches with an unchecked cast — the hazard [Utils.validateEntry] already
     * defends against, arriving here through a list instead of through a Gson-built object.
     */
    @Suppress("UNCHECKED_CAST")
    private fun <T> listWithNull(vararg items: T?): List<T> = listOf(*items) as List<T>

    // ── The rule ─────────────────────────────────────────────────────────

    @Test
    fun `a revocation at a higher sequence revokes its authorization`() {
        val a = authorization(sequence = 7L)

        assertTrue(Utils.isRevoked(a, listOf(revocation(sequence = 8L))))
    }

    /**
     * The positive case as a service asks it, plus the non-vacuity floor the whole file rests on:
     * exactly one authorization goes, and the other two — one for the same profile, one for
     * another — stay. A `liveAuthorizations` that returned everything or returned nothing would
     * pass a suite written only around [Utils.isRevoked].
     */
    @Test
    fun `a revocation removes exactly its own authorization and leaves the others live`() {
        val revoked = authorization(id = "rec-0001", sequence = 7L)
        val sibling = authorization(id = "rec-0002", sequence = 7L)
        val otherProfile = authorization(subject = OTHER_SUBJECT, id = "rec-0003", sequence = 7L)
        val all = listOf(revoked, sibling, otherProfile)

        val live = Utils.liveAuthorizations(all, listOf(revocation(revoked = "rec-0001")))

        assertEquals(listOf(sibling, otherProfile), live)
        assertNotEquals("floor: it must not be returning everything", all, live)
        assertTrue("floor: it must not be returning nothing", live.isNotEmpty())
    }

    /**
     * Why the comparison is *strictly* greater rather than "has been revoked at all": a device
     * that was revoked can be deliberately blessed again, and the only thing that says so is a
     * fresh authorization numbered above the revocation.
     */
    @Test
    fun `re-authorizing above the revocation brings the device back`() {
        val revocations = listOf(revocation(sequence = 8L))

        assertTrue(
            "the original authorization is below the revocation and must be dead",
            Utils.isRevoked(authorization(sequence = 7L), revocations),
        )
        assertFalse(
            "a re-issue above the revocation must be live again",
            Utils.isRevoked(authorization(sequence = 9L), revocations),
        )
    }

    /**
     * The mutation this pins is `>=` for `>`, which looks like a harmless off-by-one and is
     * actually the bug that kills every re-issued device: a re-authorization minted at the
     * revocation's own number would come back dead. Both the equal and the lower case are asserted
     * because only the pair distinguishes `>` from `>=` from `!=`.
     */
    @Test
    fun `a revocation at the same or a lower sequence does not revoke`() {
        val a = authorization(sequence = 7L)

        assertFalse(
            "equal is not strictly greater — this is the re-issue case",
            Utils.isRevoked(a, listOf(revocation(sequence = 7L))),
        )
        assertFalse(
            "a captured older revocation must be useless against a newer authorization",
            Utils.isRevoked(a, listOf(revocation(sequence = 6L))),
        )
        assertEquals(
            listOf(a),
            Utils.liveAuthorizations(
                listOf(a),
                listOf(revocation(sequence = 7L), revocation(sequence = 6L)),
            ),
        )
    }

    // ── Matching: exact, and scoped to one profile ───────────────────────

    @Test
    fun `a revocation naming a different authorization revokes nothing`() {
        val a = authorization(id = "rec-0001")

        assertFalse(Utils.isRevoked(a, listOf(revocation(revoked = "rec-0002", sequence = 99L))))
    }

    /**
     * The cross-profile guard. Ids are minted per signer, so two profiles can easily both hold a
     * `rec-0001`; without the subject-key check one user's revocation would reach into another
     * user's account.
     */
    @Test
    fun `a revocation for a different subject revokes nothing even when the id matches`() {
        val a = authorization(subject = SUBJECT, id = "rec-0001", sequence = 7L)
        val theirs = revocation(subject = OTHER_SUBJECT, revoked = "rec-0001", sequence = 99L)

        assertFalse(Utils.isRevoked(a, listOf(theirs)))
        assertEquals(listOf(a), Utils.liveAuthorizations(listOf(a), listOf(theirs)))
    }

    /**
     * An id is an opaque handle the signer minted, so it is compared byte for byte. Trimming or
     * case-folding it would merge two authorizations the signer deliberately kept apart — and
     * merging them means one revocation cancelling both.
     */
    @Test
    fun `an id differing only by whitespace or case does not match`() {
        val a = authorization(id = "rec-0001")

        listOf(" rec-0001", "rec-0001 ", "\trec-0001\n", "REC-0001", "Rec-0001").forEach { spelling ->
            assertNotEquals("control: the spelling must actually differ", "rec-0001", spelling)
            assertFalse(
                "a revocation naming '$spelling' must not cancel 'rec-0001'",
                Utils.isRevoked(a, listOf(revocation(revoked = spelling, sequence = 99L))),
            )
        }
    }

    /**
     * "Nothing equals nothing", the trap [Utils.matchesRequestCode] exists to prevent, arriving
     * where it would revoke by naming nobody: a revocation minted with a blank id must not cancel
     * an authorization that also carries one.
     *
     * The consequence — a blank-id authorization is unrevocable — is the documented and safer half
     * of the trade, and it is asserted here rather than left as a surprise, since it is a state a
     * careless signer can mint.
     */
    @Test
    fun `a blank authorization id does not match another blank one`() {
        listOf("", "   ", "\t\n").forEach { blank ->
            val a = authorization(id = blank, sequence = 1L)

            assertFalse(
                "a revocation naming '' must not cancel an authorization named ''",
                Utils.isRevoked(a, listOf(revocation(revoked = blank, sequence = 99L))),
            )
            assertEquals(
                "and the filter must agree — a blank id is unrevocable, not everything's id",
                listOf(a),
                Utils.liveAuthorizations(listOf(a), listOf(revocation(revoked = blank, sequence = 99L))),
            )
        }
    }

    // ── Order, duplication, idempotence ──────────────────────────────────

    /**
     * Statements arrive in whatever order a relay delivered them, and a service may well be shown
     * the same one twice, so neither may change the answer. Both lists are permuted and duplicated
     * at once.
     *
     * "Identical result" here means *which* authorizations survive: the function is a stable
     * filter, so the returned order tracks the order it was given — that half is asserted
     * separately below, and the two together are the whole contract.
     */
    @Test
    fun `shuffling and duplicating both input lists does not change which authorizations survive`() {
        val first = authorization(id = "rec-0001", sequence = 7L)
        val second = authorization(id = "rec-0002", sequence = 7L)
        val third = authorization(id = "rec-0003", sequence = 4L)
        val authorizations = listOf(first, second, third)
        val revocations = listOf(
            revocation(revoked = "rec-0001", sequence = 8L),
            revocation(revoked = "rec-0003", sequence = 3L), // too low: does not bite
        )

        val expected = Utils.liveAuthorizations(authorizations, revocations)
        assertEquals("control: this scenario must leave a mixture", listOf(second, third), expected)

        val permuted = listOf(
            listOf(third, first, second) to revocations.reversed(),
            listOf(second, third, first) to (revocations + revocations),
            (authorizations + authorizations) to (revocations.reversed() + revocations),
        )
        permuted.forEach { (a, r) ->
            assertEquals(
                "survivors must not depend on input order or on duplicates: $a / $r",
                expected.toSet(),
                Utils.liveAuthorizations(a, r).toSet(),
            )
            assertEquals(
                "and the result must stay a stable filter of the input it was given",
                a.filter { it in expected },
                Utils.liveAuthorizations(a, r),
            )
        }
    }

    @Test
    fun `filtering twice with the same revocations changes nothing`() {
        val authorizations = listOf(
            authorization(id = "rec-0001", sequence = 7L),
            authorization(id = "rec-0002", sequence = 7L),
        )
        val revocations = listOf(revocation(revoked = "rec-0001", sequence = 8L))

        val once = Utils.liveAuthorizations(authorizations, revocations)
        assertEquals(1, once.size)
        assertEquals(once, Utils.liveAuthorizations(once, revocations))
    }

    /**
     * The replay itself: a thief who kept a copy of the authorization presents it again after the
     * revocation reached the service. Re-presenting it changes nothing, because the decision is
     * made from the statements' own sequence numbers and never from when either turned up.
     */
    @Test
    fun `re-presenting a revoked authorization leaves it dead`() {
        val a = authorization(id = "rec-0001", sequence = 7L)
        val revocations = listOf(revocation(revoked = "rec-0001", sequence = 8L))

        assertTrue(Utils.isRevoked(a, revocations))
        assertEquals(emptyList<RecoveryAuthorization>(), Utils.liveAuthorizations(listOf(a), revocations))
        // The replay: the very same authorization offered a second time, and a fresh copy of it.
        assertEquals(
            emptyList<RecoveryAuthorization>(),
            Utils.liveAuthorizations(listOf(a, a, authorization(id = "rec-0001", sequence = 7L)), revocations),
        )
    }

    // ── Hostile and degenerate input ─────────────────────────────────────

    @Test
    fun `empty lists on either side return without throwing`() {
        val a = authorization()

        assertFalse(Utils.isRevoked(a, emptyList()))
        assertEquals(listOf(a), Utils.liveAuthorizations(listOf(a), emptyList()))
        assertEquals(emptyList<RecoveryAuthorization>(), Utils.liveAuthorizations(emptyList(), listOf(revocation())))
        assertEquals(emptyList<RecoveryAuthorization>(), Utils.liveAuthorizations(emptyList(), emptyList()))
    }

    /**
     * A null element in either list, which only a Java caller can produce. Neither function may
     * throw, and — the half worth stating — a null must not come back out inside a list whose
     * element type says it cannot be there.
     */
    @Suppress("SENSELESS_COMPARISON") // the point of the last assertion is that Kotlin is wrong
    @Test
    fun `a null element in either list does not throw`() {
        val a = authorization(id = "rec-0001", sequence = 7L)
        val real = revocation(revoked = "rec-0001", sequence = 8L)

        assertFalse(
            "a null revocation revokes nothing",
            Utils.isRevoked(a, listWithNull(null, null)),
        )
        assertTrue(
            "a null alongside a genuine revocation must not mask it",
            Utils.isRevoked(a, listWithNull(null, real)),
        )

        val live = Utils.liveAuthorizations(
            listWithNull(null, authorization(id = "rec-0002", sequence = 7L), null),
            listWithNull(null, real),
        )
        assertEquals(listOf(authorization(id = "rec-0002", sequence = 7L)), live)
        assertTrue("no null may survive into the result", live.none { it == null })
    }

    // ── The arithmetic edges of the one load-bearing rule ────────────────

    /**
     * Nothing is strictly greater than [Long.MAX_VALUE], so an authorization minted there can
     * never be revoked. That is a genuine consequence of "strictly greater" rather than a defect
     * to paper over — the fix belongs in how a signer mints sequences, and the KDoc says so — but
     * it is pinned here so it can never become a surprise found in production.
     */
    @Test
    fun `an authorization at Long MAX_VALUE is permanently unrevocable`() {
        val a = authorization(sequence = Long.MAX_VALUE)

        assertFalse(Utils.isRevoked(a, listOf(revocation(sequence = Long.MAX_VALUE))))
        assertFalse(Utils.isRevoked(a, listOf(revocation(sequence = Long.MIN_VALUE))))
        assertEquals(
            listOf(a),
            Utils.liveAuthorizations(listOf(a), listOf(revocation(sequence = Long.MAX_VALUE))),
        )
    }

    /** The other end: a revocation at the bottom of the range revokes nothing above it. */
    @Test
    fun `a revocation at Long MIN_VALUE revokes nothing`() {
        val bottom = listOf(revocation(sequence = Long.MIN_VALUE))

        assertFalse(Utils.isRevoked(authorization(sequence = Long.MIN_VALUE), bottom))
        assertFalse(Utils.isRevoked(authorization(sequence = 0L), bottom))
        assertFalse(Utils.isRevoked(authorization(sequence = Long.MAX_VALUE), bottom))
    }

    /**
     * Negative sequences on either side. They are ordinary numbers to the rule, and asserting so
     * catches a comparison written over magnitudes or over unsigned arithmetic — where -1 would
     * outrank 1.
     */
    @Test
    fun `negative sequences compare as ordinary numbers`() {
        assertTrue(
            "-1 is strictly greater than -2",
            Utils.isRevoked(authorization(sequence = -2L), listOf(revocation(sequence = -1L))),
        )
        assertFalse(
            "-2 is not strictly greater than -1",
            Utils.isRevoked(authorization(sequence = -1L), listOf(revocation(sequence = -2L))),
        )
        assertFalse(
            "a negative revocation must not outrank a positive authorization",
            Utils.isRevoked(authorization(sequence = 1L), listOf(revocation(sequence = -1L))),
        )
        assertTrue(
            "a zero authorization is revoked by a positive revocation",
            Utils.isRevoked(authorization(sequence = 0L), listOf(revocation(sequence = 1L))),
        )
    }
}
