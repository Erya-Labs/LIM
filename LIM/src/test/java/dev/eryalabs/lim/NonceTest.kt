package dev.eryalabs.lim

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

/**
 * A nonce is the whole of what stops a captured signature being replayed forever, so both
 * halves of it are pinned here: the random half must genuinely come from the injected
 * source, and the timestamp half must survive the round trip byte for byte.
 *
 * No Robolectric — [Utils.generateNonce] and [Utils.isNonceFresh] touch no Android API, and
 * both take their randomness and their clock by injection, so every case below is exact
 * rather than timing-dependent.
 */
class NonceTest {

    /**
     * Deterministic stand-in for the real entropy source: same seed, same bytes, on every
     * JDK. `SecureRandom.getInstance("SHA1PRNG").setSeed(...)` is not reproducible across
     * instances on this toolchain — the algorithm self-seeds — so the injected source is
     * pinned with an explicit double rather than by leaning on a provider's behaviour.
     * Production passes a real [SecureRandom]; this only ever substitutes for it in tests.
     */
    private class SeededRandom(seed: Long) : SecureRandom() {
        private val bytes = java.util.Random(seed)
        override fun nextBytes(bytes: ByteArray) = this.bytes.nextBytes(bytes)
    }

    private fun seededRandom(seed: Long): SecureRandom = SeededRandom(seed)

    private val clock = 1_770_000_000_000L
    private val timestampBytes = 8
    private val nonceSize = 40

    // ── Shape ────────────────────────────────────────────────────────────

    @Test
    fun `a nonce is a timestamp followed by at least 32 random bytes`() {
        val nonce = Utils.generateNonce(seededRandom(1), clock)
        assertEquals(nonceSize, nonce.size)
        assertTrue(
            "at least 32 bytes must be random",
            nonce.size - timestampBytes >= 32,
        )
    }

    @Test
    fun `the random half comes from the injected source`() {
        val a = Utils.generateNonce(seededRandom(42), clock)
        val b = Utils.generateNonce(seededRandom(42), clock)
        val c = Utils.generateNonce(seededRandom(43), clock)

        assertTrue("same seed and clock must produce the same nonce", a.contentEquals(b))
        assertFalse("a different seed must produce a different nonce", a.contentEquals(c))
    }

    /**
     * The realistic call: one generator, two challenges. If the random half were ever
     * derived from the clock alone these would collide and a challenge would be guessable.
     */
    @Test
    fun `two successive nonces differ`() {
        val random = seededRandom(7)
        val first = Utils.generateNonce(random, clock)
        val second = Utils.generateNonce(random, clock)

        assertFalse("successive nonces must not repeat", first.contentEquals(second))
        assertTrue(
            "only the random half may differ when the clock has not moved",
            first.copyOfRange(0, timestampBytes)
                .contentEquals(second.copyOfRange(0, timestampBytes)),
        )
    }

    // ── The timestamp round-trips exactly ────────────────────────────────

    /**
     * `maxAgeMillis = 0` makes [Utils.isNonceFresh] an equality test on the timestamp: it
     * can only pass when the decoded value is exactly the value stamped in. That pins the
     * round trip without exposing a reader function purely for the test's benefit.
     */
    @Test
    fun `the timestamp round-trips exactly`() {
        val nonce = Utils.generateNonce(seededRandom(1), clock)
        assertTrue(Utils.isNonceFresh(nonce, maxAgeMillis = 0, now = clock))
        assertFalse(Utils.isNonceFresh(nonce, maxAgeMillis = 0, now = clock + 1))
        assertFalse(Utils.isNonceFresh(nonce, maxAgeMillis = 0, now = clock - 1))
    }

    /**
     * Every byte of the timestamp above 0x7F, which is where a decoder that sign-extends
     * instead of masking goes wrong. `0x00FFFFFFFFFFFFFF` is unreachable from a real clock
     * but reachable from a peer app's bytes.
     */
    @Test
    fun `a timestamp with the high bits set round-trips exactly`() {
        val awkward = 0x00FF_FFFF_FFFF_FFFFL
        val nonce = Utils.generateNonce(seededRandom(1), awkward)
        assertTrue(Utils.isNonceFresh(nonce, maxAgeMillis = 0, now = awkward))
        assertFalse(Utils.isNonceFresh(nonce, maxAgeMillis = 0, now = awkward + 1))
    }

    @Test
    fun `the epoch round-trips exactly`() {
        val nonce = Utils.generateNonce(seededRandom(1), 0L)
        assertTrue(Utils.isNonceFresh(nonce, maxAgeMillis = 0, now = 0L))
        assertTrue(Utils.isNonceFresh(nonce, maxAgeMillis = 1_000, now = 1_000))
        assertFalse(Utils.isNonceFresh(nonce, maxAgeMillis = 1_000, now = 1_001))
    }

    // ── The freshness boundary ───────────────────────────────────────────

    @Test
    fun `a nonce exactly maxAgeMillis old is still fresh`() {
        val nonce = Utils.generateNonce(seededRandom(1), clock)
        val maxAge = 30_000L

        assertTrue(
            "one millisecond inside the window is fresh",
            Utils.isNonceFresh(nonce, maxAge, now = clock + maxAge - 1),
        )
        assertTrue(
            "exactly maxAgeMillis old is fresh",
            Utils.isNonceFresh(nonce, maxAge, now = clock + maxAge),
        )
        assertFalse(
            "one millisecond past maxAgeMillis is stale",
            Utils.isNonceFresh(nonce, maxAge, now = clock + maxAge + 1),
        )
    }

    @Test
    fun `a long-expired nonce is stale`() {
        val nonce = Utils.generateNonce(seededRandom(1), clock)
        assertFalse(Utils.isNonceFresh(nonce, 60_000, now = clock + 86_400_000))
    }

    // ── Hostile input: never throws, always fails closed ─────────────────

    @Test
    fun `a nonce timestamped in the future is rejected`() {
        val nonce = Utils.generateNonce(seededRandom(1), clock)
        assertFalse(
            "one millisecond in the future is already too much",
            Utils.isNonceFresh(nonce, 60_000, now = clock - 1),
        )
        assertFalse(Utils.isNonceFresh(nonce, 60_000, now = clock - 86_400_000))
    }

    @Test
    fun `a nonce shorter than the layout is rejected rather than throwing`() {
        val nonce = Utils.generateNonce(seededRandom(1), clock)

        assertFalse("empty", Utils.isNonceFresh(ByteArray(0), 60_000, now = clock))
        assertFalse(
            "header only, no randomness",
            Utils.isNonceFresh(nonce.copyOfRange(0, timestampBytes), 60_000, now = clock),
        )
        assertFalse(
            "shorter than the header",
            Utils.isNonceFresh(nonce.copyOfRange(0, 3), 60_000, now = clock),
        )
        assertFalse(
            "one byte short",
            Utils.isNonceFresh(nonce.copyOfRange(0, nonceSize - 1), 60_000, now = clock),
        )
    }

    @Test
    fun `trailing bytes beyond the layout are ignored`() {
        val padded = Utils.generateNonce(seededRandom(1), clock) + ByteArray(16) { 9 }
        assertTrue(Utils.isNonceFresh(padded, 60_000, now = clock))
    }

    @Test
    fun `a negative maxAgeMillis accepts nothing`() {
        val nonce = Utils.generateNonce(seededRandom(1), clock)
        assertFalse(Utils.isNonceFresh(nonce, maxAgeMillis = -1, now = clock))
        assertFalse(Utils.isNonceFresh(nonce, maxAgeMillis = Long.MIN_VALUE, now = clock))
    }

    /**
     * Timestamps a peer app can write but a clock never would. The last case is the one that
     * matters: `now - timestamp` overflows there, and a wrapped result must read as "not
     * fresh" rather than as a small age.
     */
    @Test
    fun `extreme timestamps fail closed`() {
        fun nonceStampedWith(vararg timestamp: Byte) = timestamp + ByteArray(32) { 0 }

        val allOnes = nonceStampedWith(-1, -1, -1, -1, -1, -1, -1, -1)
        val maxLong = nonceStampedWith(0x7F, -1, -1, -1, -1, -1, -1, -1)
        val minLong = nonceStampedWith(0x80.toByte(), 0, 0, 0, 0, 0, 0, 0)

        assertFalse(
            "all-ones — one millisecond before the epoch, decades stale",
            Utils.isNonceFresh(allOnes, 60_000, now = clock),
        )
        assertFalse(
            "Long.MAX_VALUE — the future check must dominate any window",
            Utils.isNonceFresh(maxLong, Long.MAX_VALUE, now = clock),
        )
        assertFalse(
            "Long.MIN_VALUE — the subtraction overflows here",
            Utils.isNonceFresh(minLong, Long.MAX_VALUE, now = clock),
        )
        assertFalse(
            "Long.MIN_VALUE against Long.MAX_VALUE — overflow wraps to an age of -1",
            Utils.isNonceFresh(minLong, Long.MAX_VALUE, now = Long.MAX_VALUE),
        )
        // The one input the future check catches and the overflow check does not: this
        // subtraction wraps to an age of exactly 1, which would sail through any window.
        assertFalse(
            "Long.MAX_VALUE against a far-negative clock",
            Utils.isNonceFresh(maxLong, 60_000, now = Long.MIN_VALUE),
        )
    }

    // ── Defaults ─────────────────────────────────────────────────────────

    /**
     * The injected parameters are for tests; production calls neither. This is the only
     * case that uses the real clock and the real entropy source.
     */
    @Test
    fun `the default random and clock produce a fresh nonce`() {
        val nonce = Utils.generateNonce()
        assertEquals(nonceSize, nonce.size)
        assertTrue(
            "a just-generated nonce must be fresh against the real clock",
            Utils.isNonceFresh(nonce, maxAgeMillis = 60_000),
        )
        assertFalse(
            "two nonces from the real entropy source must not collide",
            nonce.contentEquals(Utils.generateNonce()),
        )
    }
}
