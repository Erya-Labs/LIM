package dev.eryalabs.lim

import android.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.Signature

/**
 * What a *service* does with a rotation statement.
 *
 * `StatementPreImageTest` pins the bytes that get signed; this pins the decision made about
 * them. The two halves meet in the first test below, where a real 2048-bit keypair signs a real
 * statement's canonical pre-image and the verifier — delegating to the same
 * [Utils.verifySignature] every login already uses — returns [StatementVerdict.VALID].
 *
 * Most of the file is negative controls, and they fall into two groups that matter for different
 * reasons. The *forgery* group says nothing an attacker can construct is ever accepted. The
 * *check-order* group says that when several things are wrong at once, the verdict names the one
 * that should stop a service dead: a statement that is both expired and unsigned is
 * [StatementVerdict.SIGNATURE_INVALID], and one that is correctly signed but addressed to
 * another profile is [StatementVerdict.WRONG_SUBJECT] even when it has also expired — because
 * "expired" is a comfortable answer to give a cross-account replay, and a comfortable answer is
 * the wrong one.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class RotationVerificationTest {

    /**
     * A ten-minute window, the lifetime the migration design sketches. The numbers are only ever
     * compared against an injected clock, so nothing here depends on when the suite runs.
     */
    private val issuedAt = 1_770_000_000_000L
    private val expiresAt = 1_770_000_600_000L

    /** Inside the window, comfortably away from either boundary. */
    private val duringWindow = 1_770_000_300_000L

    private fun statement(
        oldPublicKey: String = storedKeyBase64,
        newPublicKey: String = replacementKeyBase64,
        statementId: String = "rot-0001",
        issued: Long = issuedAt,
        expires: Long = expiresAt,
    ) = RotationStatement(oldPublicKey, newPublicKey, statementId, issued, expires)

    /** Sign a statement's canonical pre-image the way a vault's Keystore would. */
    private fun sign(statement: RotationStatement, key: PrivateKey): ByteArray =
        Signature.getInstance("SHA256withRSA").run {
            initSign(key)
            update(Utils.rotationStatementBytes(statement))
            sign()
        }

    // ── The happy path ───────────────────────────────────────────────────

    @Test
    fun `a real statement signed by the stored key verifies VALID`() {
        val rotation = statement()

        assertEquals(
            StatementVerdict.VALID,
            Utils.verifyRotationStatement(
                statement = rotation,
                signature = sign(rotation, storedKeyPair.private),
                storedPublicKey = storedKeyBase64,
                now = duringWindow,
            ),
        )
    }

    /**
     * The verifier must be reading the *statement's* window and not one of its own. Pinned
     * because a library that quietly applied a default lifetime would be verifying something the
     * signature does not say — the signer declared this window and no other.
     */
    @Test
    fun `a long window and an instantaneous one are both honoured as declared`() {
        val wide = statement(issued = 0L, expires = 4_000_000_000_000L)
        val instant = statement(issued = duringWindow, expires = duringWindow)

        assertEquals(StatementVerdict.VALID, verdictFor(wide, now = duringWindow))
        assertEquals(StatementVerdict.VALID, verdictFor(instant, now = duringWindow))
        assertEquals(StatementVerdict.EXPIRED, verdictFor(instant, now = duringWindow + 1))
        assertEquals(StatementVerdict.NOT_YET_VALID, verdictFor(instant, now = duringWindow - 1))
    }

    // ── The window boundary ──────────────────────────────────────────────

    @Test
    fun `exactly the expiry instant is still valid and one millisecond later is not`() {
        val rotation = statement()

        assertEquals(
            "the end of the window is inclusive",
            StatementVerdict.VALID,
            verdictFor(rotation, now = expiresAt),
        )
        assertEquals(StatementVerdict.EXPIRED, verdictFor(rotation, now = expiresAt + 1))
    }

    @Test
    fun `exactly the issue instant is valid and one millisecond earlier is not`() {
        val rotation = statement()

        assertEquals(
            "the start of the window is inclusive",
            StatementVerdict.VALID,
            verdictFor(rotation, now = issuedAt),
        )
        assertEquals(StatementVerdict.NOT_YET_VALID, verdictFor(rotation, now = issuedAt - 1))
    }

    /**
     * `expiresAtMillis < issuedAtMillis` is not a shape any honest signer produces, so nothing
     * fixes what it "should" mean — only that it can never be acted on. Swept across the line
     * rather than sampled at one point, because the two window checks are separate branches and a
     * clock landing between the two values is exactly where an implementation that tested only
     * one of them would answer `VALID`.
     */
    @Test
    fun `a nonsensical window is never valid at any instant`() {
        val inverted = statement(issued = expiresAt, expires = issuedAt)
        val signature = sign(inverted, storedKeyPair.private)

        listOf(
            Long.MIN_VALUE, 0L, issuedAt - 1, issuedAt, duringWindow, expiresAt, expiresAt + 1,
            Long.MAX_VALUE,
        ).forEach { now ->
            val verdict = Utils.verifyRotationStatement(inverted, signature, storedKeyBase64, now)
            assertNotEquals(
                "a statement whose window closes before it opens must never be acted on; " +
                    "now=$now gave $verdict",
                StatementVerdict.VALID,
                verdict,
            )
        }
    }

    // ── Forgery: nothing an attacker builds is ever accepted ─────────────

    @Test
    fun `a different keypair's signature over the same statement is SIGNATURE_INVALID`() {
        val rotation = statement()

        assertEquals(
            StatementVerdict.SIGNATURE_INVALID,
            Utils.verifyRotationStatement(
                statement = rotation,
                signature = sign(rotation, attackerKeyPair.private),
                storedPublicKey = storedKeyBase64,
                now = duringWindow,
            ),
        )
    }

    // One test per component rather than a loop, so a failure names the component that fell out
    // of the signature. This is the end-to-end complement of `StatementPreImageTest`'s byte-level
    // controls: there, changing a component changes the bytes; here, changing it after signing
    // costs the statement its verdict.

    @Test
    fun `the old public key tampered after signing is SIGNATURE_INVALID`() =
        assertTamperingRejected { it.copy(oldPublicKey = attackerKeyBase64) }

    /**
     * The one that matters most, and the reason the pre-image carries every component: a verifier
     * blind to `newPublicKey` would let an attacker swap their own key in under a signature the
     * user genuinely made. Note the verdict is `SIGNATURE_INVALID` and not `NEW_KEY_UNUSABLE` —
     * the replacement here is a perfectly good RSA key, which is precisely why only the signature
     * can catch it.
     */
    @Test
    fun `the new public key tampered after signing is SIGNATURE_INVALID`() =
        assertTamperingRejected { it.copy(newPublicKey = attackerKeyBase64) }

    @Test
    fun `the statement id tampered after signing is SIGNATURE_INVALID`() =
        assertTamperingRejected { it.copy(statementId = "rot-0002") }

    @Test
    fun `the issue timestamp tampered after signing is SIGNATURE_INVALID`() =
        assertTamperingRejected { it.copy(issuedAtMillis = it.issuedAtMillis - 1) }

    /**
     * Extending the window is the tamper with the obvious motive: a captured statement that has
     * gone stale is worthless, and moving its expiry is the cheapest way to revive it.
     */
    @Test
    fun `the expiry timestamp tampered after signing is SIGNATURE_INVALID`() =
        assertTamperingRejected { it.copy(expiresAtMillis = it.expiresAtMillis + 86_400_000L) }

    // ── Check order ──────────────────────────────────────────────────────

    /**
     * A genuine statement about somebody else's profile. The signature verifies — it was made by
     * this service's stored key — but the statement says nothing about the account this service
     * would be applying it to, so it must not be.
     */
    @Test
    fun `a genuine statement naming another profile is WRONG_SUBJECT`() {
        val elsewhere = statement(oldPublicKey = otherProfileKeyBase64)

        assertEquals(
            StatementVerdict.WRONG_SUBJECT,
            Utils.verifyRotationStatement(
                statement = elsewhere,
                signature = sign(elsewhere, storedKeyPair.private),
                storedPublicKey = storedKeyBase64,
                now = duringWindow,
            ),
        )
    }

    /**
     * The first of the two inputs that pin the order. Everything about this statement is wrong,
     * and the answer must be the one that stops a service dead: an unsigned statement is not a
     * stale statement, and reporting it as merely expired invites an integrator to treat it as an
     * ordinary timing problem the user can retry their way out of.
     */
    @Test
    fun `an expired and wrongly-signed statement is SIGNATURE_INVALID`() {
        val rotation = statement()

        assertEquals(
            StatementVerdict.SIGNATURE_INVALID,
            Utils.verifyRotationStatement(
                statement = rotation,
                signature = sign(rotation, attackerKeyPair.private),
                storedPublicKey = storedKeyBase64,
                now = expiresAt + 1,
            ),
        )
    }

    /**
     * The signature gate generalised across every other refusal, because the expired case above
     * pins only one of them. Each row is a statement an attacker signed with their own key, and
     * each is *also* wrong in the way one of the later checks looks for — so a verifier that ran
     * any of those checks first would answer with that check's verdict instead.
     *
     * The subject row is the one worth naming: moving the subject comparison above the signature
     * would leave every other test in this file green while turning a forgery aimed at somebody
     * else's account into `WRONG_SUBJECT`, an answer that says the bytes were genuine.
     *
     * The second half is what stops the whole test being vacuous: signed properly, every one of
     * these statements earns the verdict its own defect deserves, so the rows really do reach the
     * later checks and the signature really is what pre-empts them.
     */
    @Test
    fun `a forged statement is SIGNATURE_INVALID whatever else is wrong with it`() {
        val cases = listOf(
            "otherwise perfectly valid" to (statement() to StatementVerdict.VALID),
            "naming another profile" to
                (statement(oldPublicKey = otherProfileKeyBase64) to StatementVerdict.WRONG_SUBJECT),
            "a no-op rotation" to
                (statement(newPublicKey = storedKeyBase64) to StatementVerdict.SAME_KEY),
            "an unusable replacement key" to
                (statement(newPublicKey = "!!!") to StatementVerdict.NEW_KEY_UNUSABLE),
            "expired" to
                (statement(expires = duringWindow - 1) to StatementVerdict.EXPIRED),
            "not yet issued" to
                (statement(issued = duringWindow + 1, expires = Long.MAX_VALUE) to
                    StatementVerdict.NOT_YET_VALID),
        )

        cases.forEach { (why, expectation) ->
            val rotation = expectation.first
            assertEquals(
                "a statement that is $why but signed by the wrong key must fail at the signature",
                StatementVerdict.SIGNATURE_INVALID,
                Utils.verifyRotationStatement(
                    statement = rotation,
                    signature = sign(rotation, attackerKeyPair.private),
                    storedPublicKey = storedKeyBase64,
                    now = duringWindow,
                ),
            )
        }

        cases.forEach { (why, expectation) ->
            val (rotation, expected) = expectation
            assertEquals(
                "control: signed genuinely, a statement that is $why must reach the check that " +
                    "objects to it — otherwise the row above is not testing the ordering at all",
                expected,
                Utils.verifyRotationStatement(
                    statement = rotation,
                    signature = sign(rotation, storedKeyPair.private),
                    storedPublicKey = storedKeyBase64,
                    now = duringWindow,
                ),
            )
        }
    }

    /**
     * The second, and the one that matters more: this *is* a cross-account replay, and `EXPIRED`
     * would be the misleading answer — it describes a statement that was once meant for you,
     * which this never was.
     */
    @Test
    fun `a genuine statement for another profile that has also expired is WRONG_SUBJECT`() {
        val elsewhere = statement(oldPublicKey = otherProfileKeyBase64)

        assertEquals(
            StatementVerdict.WRONG_SUBJECT,
            Utils.verifyRotationStatement(
                statement = elsewhere,
                signature = sign(elsewhere, storedKeyPair.private),
                storedPublicKey = storedKeyBase64,
                now = expiresAt + 1,
            ),
        )
    }

    /**
     * Subject before replacement: a statement about another profile is refused as such even when
     * its replacement key happens to be the one this service stores. Without the ordering this
     * would come back `SAME_KEY`, which reads as "nothing to do here" about a statement that is
     * in fact somebody else's.
     */
    @Test
    fun `another profile's statement naming the stored key as replacement is WRONG_SUBJECT`() {
        val elsewhere = statement(
            oldPublicKey = otherProfileKeyBase64,
            newPublicKey = storedKeyBase64,
        )

        assertEquals(
            StatementVerdict.WRONG_SUBJECT,
            Utils.verifyRotationStatement(
                statement = elsewhere,
                signature = sign(elsewhere, storedKeyPair.private),
                storedPublicKey = storedKeyBase64,
                now = duringWindow,
            ),
        )
    }

    /**
     * Replacement before window: an unusable key is reported as such, not as a timing problem.
     * A user can wait out an expiry and try again; a replacement key that does not parse will
     * never improve, and telling the integrator "expired" or "not yet valid" sends them to retry
     * a rotation that cannot ever succeed.
     *
     * Both sides of the window, because they are separate branches: pinning only the expiry side
     * would leave the `NOT_YET_VALID` transposition free to survive.
     */
    @Test
    fun `an unusable replacement key is reported before the window is considered`() {
        val rotation = statement(newPublicKey = "not base64 at all!!")
        val signature = sign(rotation, storedKeyPair.private)

        listOf("after expiry" to expiresAt + 1, "before issue" to issuedAt - 1).forEach { (why, now) ->
            assertEquals(
                "an unusable key must be reported as such $why, not as a timing problem",
                StatementVerdict.NEW_KEY_UNUSABLE,
                Utils.verifyRotationStatement(rotation, signature, storedKeyBase64, now),
            )
        }
    }

    /**
     * Subject before replacement *and* before the window, on both sides of it. The no-op has to
     * be reported as a no-op whenever the statement is otherwise genuine: told `EXPIRED`, a
     * service would wait for a fresh statement that says exactly as little as this one.
     */
    @Test
    fun `a no-op rotation is SAME_KEY even when the window has also closed`() {
        listOf(
            "expired" to statement(newPublicKey = storedKeyBase64, expires = duringWindow - 1),
            "not yet issued" to statement(
                newPublicKey = storedKeyBase64,
                issued = duringWindow + 1,
                expires = Long.MAX_VALUE,
            ),
        ).forEach { (why, rotation) ->
            assertEquals(
                "a no-op rotation that is also $why must still be reported as a no-op",
                StatementVerdict.SAME_KEY,
                Utils.verifyRotationStatement(
                    statement = rotation,
                    signature = sign(rotation, storedKeyPair.private),
                    storedPublicKey = storedKeyBase64,
                    now = duringWindow,
                ),
            )
        }
    }

    // ── The identity-matching hazard, reached from this side ─────────────
    //
    // Android's Base64 decoder *skips* characters outside its alphabet rather than rejecting
    // them, so one RSA key has many spellings that all decode to the same bytes and all verify
    // the same signature — the hazard `Utils.validateEntry` documents and `DecoderFuzzTest`
    // measures. It reaches this function twice, from opposite directions, and the two tests below
    // are the only ones in this file whose fixtures a clean Base64 spelling cannot produce.

    /**
     * A subject that differs from the stored key only by surrounding whitespace is a *different
     * account*, and the comparison is exact for that reason: the protocol looks a profile up by
     * the key string, so a service normalising it here would apply somebody else's statement.
     *
     * The control is what gives the test its teeth. The whitespace spelling verifies the
     * signature perfectly well — `verifySignature` decodes it to the same key — so the refusal
     * below can only be coming from the string comparison. Without it, a verifier that quietly
     * called `trim()` on both sides would pass every other test in this file.
     */
    @Test
    fun `a subject differing only by surrounding whitespace is WRONG_SUBJECT`() {
        listOf(
            "a trailing newline" to storedKeyBase64 + "\n",
            "a leading space" to " " + storedKeyBase64,
        ).forEach { (why, spelling) ->
            val elsewhere = statement(oldPublicKey = spelling)
            val signature = sign(elsewhere, storedKeyPair.private)

            assertNotEquals("control: $why must genuinely change the string", storedKeyBase64, spelling)
            assertTrue(
                "control: $why must still verify the signature, or this refusal is the crypto's " +
                    "and not the comparison's",
                Utils.verifySignature(spelling, Utils.rotationStatementBytes(elsewhere), signature),
            )
            assertEquals(
                "a key string with $why is a different account identifier, not the same one",
                StatementVerdict.WRONG_SUBJECT,
                Utils.verifyRotationStatement(elsewhere, signature, storedKeyBase64, duringWindow),
            )
        }
    }

    /**
     * The other direction: a replacement key that only a *forgiving* decoder can read.
     *
     * These bytes are the real key — the control below decodes them and proves it — and the
     * signature over the statement is genuine, so nothing about the crypto objects. It is refused
     * because the protocol identifies a profile by the key string and a vault looks it up by
     * equality: a service that stored this spelling would hold a key that authenticates fine and
     * matches no profile anywhere, which is the same lockout `NEW_KEY_UNUSABLE` exists to
     * prevent, arriving by a route a lenient parse would wave straight through.
     */
    @Test
    fun `a replacement key only a forgiving decoder can read is NEW_KEY_UNUSABLE`() {
        val dirty = strayCharacters(replacementKeyBase64)
        val rotation = statement(newPublicKey = dirty)

        assertTrue(
            "control: a forgiving decoder must recover exactly the real key from this spelling, " +
                "or the refusal below is about the bytes rather than about the string",
            Base64.decode(dirty, Base64.DEFAULT)
                .contentEquals(Base64.decode(replacementKeyBase64, Base64.DEFAULT)),
        )
        assertEquals(
            StatementVerdict.NEW_KEY_UNUSABLE,
            Utils.verifyRotationStatement(
                statement = rotation,
                signature = sign(rotation, storedKeyPair.private),
                storedPublicKey = storedKeyBase64,
                now = duringWindow,
            ),
        )
    }

    /**
     * The limit of the key check, recorded rather than quietly closed — the case
     * [strayCharacters] deliberately does *not* cover.
     *
     * A replacement key padded with whitespace is accepted, and it has to be: [Base64.DEFAULT] is
     * what the vault encodes keys with and it wraps at 76 characters, so `base64Bytes` strips
     * whitespace before it looks at the alphabet at all. Refusing this spelling would refuse
     * every legitimately wrapped key.
     *
     * The second half is the consequence, and it is why this is a test and not a comment: the
     * service now stores a spelling its own exact-equality lookup will never find, and the next
     * genuine rotation off that key — naming the clean spelling, as the holder of it would —
     * comes back `WRONG_SUBJECT`. Nothing further can recover the account. That is the
     * identity-matching hazard the whole protocol carries; narrowing what a key may look like is
     * a change the vault has to agree to, so it is logged for a human rather than decided here,
     * and the guidance in the KDoc is to store the exact string you verified.
     */
    @Test
    fun `a whitespace-padded replacement key is accepted, and that is the recorded limit`() {
        val padded = replacementKeyBase64 + "\n"
        val rotation = statement(newPublicKey = padded)

        assertEquals(
            "recorded, not endorsed: whitespace cannot be refused here without refusing every " +
                "Base64.DEFAULT-wrapped key",
            StatementVerdict.VALID,
            Utils.verifyRotationStatement(
                statement = rotation,
                signature = sign(rotation, storedKeyPair.private),
                storedPublicKey = storedKeyBase64,
                now = duringWindow,
            ),
        )

        // The service stored `padded`. Now the holder of that key tries to rotate off it, naming
        // the key the only way they know how to spell it.
        val next = statement(oldPublicKey = replacementKeyBase64, newPublicKey = attackerKeyBase64)
        val signature = sign(next, replacementKeyPair.private)

        assertTrue(
            "control: the signature genuinely is by the key the service stored, so what refuses " +
                "it below is the spelling and nothing else",
            Utils.verifySignature(padded, Utils.rotationStatementBytes(next), signature),
        )
        assertEquals(
            "a rotation off the stored key must name the exact spelling that was stored, or the " +
                "account cannot be moved again",
            StatementVerdict.WRONG_SUBJECT,
            Utils.verifyRotationStatement(next, signature, padded, duringWindow),
        )
    }

    /**
     * And the case where the two meet: a service whose stored key is itself spelled with stray
     * characters, handed a rotation onto that same spelling.
     *
     * The verdict must be `SAME_KEY` — it is a no-op, and that is the honest answer. It is the
     * one input on which the order of the no-op check and the key check is observable at all,
     * because everywhere else a key equal to the stored one is trivially a usable key. Reported
     * as `NEW_KEY_UNUSABLE` instead, it would send a service looking for a better-formed
     * replacement for a rotation that was never going anywhere.
     */
    @Test
    fun `a no-op rotation is SAME_KEY even when the stored key is spelled with stray characters`() {
        val dirty = strayCharacters(storedKeyBase64)
        val rotation = statement(oldPublicKey = dirty, newPublicKey = dirty)
        val signature = sign(rotation, storedKeyPair.private)

        assertTrue(
            "control: the signature must verify against this spelling, so that the verdict below " +
                "is the no-op rule's and not the signature gate's",
            Utils.verifySignature(dirty, Utils.rotationStatementBytes(rotation), signature),
        )
        assertEquals(
            StatementVerdict.SAME_KEY,
            Utils.verifyRotationStatement(rotation, signature, dirty, duringWindow),
        )
    }

    // ── The other refusals ───────────────────────────────────────────────

    /**
     * A rotation onto the key already stored changes nothing, so it is either noise or an attempt
     * to have a service act on a statement that says nothing. Note this is a *genuinely signed*
     * statement inside its window: only the verifier's own rule refuses it.
     */
    @Test
    fun `a rotation onto the key already stored is SAME_KEY`() {
        val noop = statement(newPublicKey = storedKeyBase64)

        assertEquals(
            StatementVerdict.SAME_KEY,
            Utils.verifyRotationStatement(
                statement = noop,
                signature = sign(noop, storedKeyPair.private),
                storedPublicKey = storedKeyBase64,
                now = duringWindow,
            ),
        )
    }

    /**
     * The shapes of unusable replacement, each genuinely signed so that only the key check can be
     * what refuses them. A service that stored any of these would have locked the user out
     * permanently: there would no longer be a key that could sign a correcting statement.
     */
    @Test
    fun `a blank, non-Base64 or non-key replacement is NEW_KEY_UNUSABLE`() {
        listOf(
            "blank" to "",
            "whitespace only" to "   ",
            "outside the Base64 alphabet" to "not base64 at all!!",
            // Well-formed Base64 that decodes cleanly and is simply not a key. Paired with the
            // valid case at the top of this file, this is what proves the check parses rather
            // than pattern-matches.
            "well-formed Base64 that is not a key" to "QUJDREVGRw==",
        ).forEach { (why, replacement) ->
            val rotation = statement(newPublicKey = replacement)
            assertEquals(
                "a replacement key that is $why must be refused",
                StatementVerdict.NEW_KEY_UNUSABLE,
                Utils.verifyRotationStatement(
                    statement = rotation,
                    signature = sign(rotation, storedKeyPair.private),
                    storedPublicKey = storedKeyBase64,
                    now = duringWindow,
                ),
            )
        }
    }

    /**
     * An EC key is a real, well-formed X.509 public key; it fails only because it is not RSA.
     * The same bar [Utils.validateEntry] applies, and the reason it has to be the same one: a key
     * this verifier waved through would be a key [Utils.verifySignature] could never use, so the
     * user would be locked out by a rotation that reported success.
     */
    @Test
    fun `a well-formed key of another algorithm is NEW_KEY_UNUSABLE`() {
        val ec = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
        val rotation = statement(
            newPublicKey = Base64.encodeToString(ec.public.encoded, Base64.NO_WRAP),
        )

        assertEquals(
            StatementVerdict.NEW_KEY_UNUSABLE,
            Utils.verifyRotationStatement(
                statement = rotation,
                signature = sign(rotation, storedKeyPair.private),
                storedPublicKey = storedKeyBase64,
                now = duringWindow,
            ),
        )
    }

    // ── Hostile input: a verdict, never a throw ──────────────────────────

    /**
     * Everything reaching this function crossed a relay somebody else controls, so none of it may
     * take a service's process down. Each input below earns a verdict rather than an exception —
     * and since none of them is a genuine signature, that verdict is `SIGNATURE_INVALID`.
     */
    @Test
    fun `empty, garbage and blank inputs return a verdict rather than throwing`() {
        val rotation = statement()
        val genuine = sign(rotation, storedKeyPair.private)

        listOf(
            "an empty signature" to ByteArray(0),
            "a single byte" to byteArrayOf(0),
            "garbage of signature length" to ByteArray(genuine.size) { 0x5A },
            "a signature one byte short" to genuine.copyOf(genuine.size - 1),
            "a signature with a byte appended" to genuine + byteArrayOf(0),
        ).forEach { (why, bytes) ->
            assertEquals(
                "$why must earn a verdict",
                StatementVerdict.SIGNATURE_INVALID,
                Utils.verifyRotationStatement(rotation, bytes, storedKeyBase64, duringWindow),
            )
        }

        listOf(
            "a blank stored key" to "",
            "a whitespace stored key" to "   ",
            "a stored key outside the Base64 alphabet" to "!!!!",
            "a stored key that is not a key" to "QUJDREVGRw==",
        ).forEach { (why, key) ->
            assertEquals(
                "$why must earn a verdict",
                StatementVerdict.SIGNATURE_INVALID,
                Utils.verifyRotationStatement(rotation, genuine, key, duringWindow),
            )
        }
    }

    /**
     * Extreme components, and the exact verdict each one earns. Written as a table rather than as
     * a flat "never VALID", because two of these genuinely *are* valid and saying otherwise would
     * pin behaviour this function must not have: a statement is not suspicious for carrying a
     * long id or a wide window, and a verifier that started refusing declarations it merely found
     * unusual would be applying a policy the signature does not state. What a service should
     * accept as a maximum lifetime is a human's decision, recorded as such in the queue.
     */
    @Test
    fun `extreme statement components earn a verdict rather than a throw`() {
        val huge = "x".repeat(200_000)

        listOf(
            // No identity at all: not this service's profile, so refused as somebody else's.
            Triple("a blank subject", statement(oldPublicKey = ""), StatementVerdict.WRONG_SUBJECT),
            Triple(
                "components of 200k characters",
                statement(oldPublicKey = huge, newPublicKey = huge, statementId = huge),
                StatementVerdict.WRONG_SUBJECT,
            ),
            Triple(
                "a window spanning the whole Long range",
                statement(issued = Long.MIN_VALUE, expires = Long.MAX_VALUE),
                StatementVerdict.VALID,
            ),
            Triple(
                "a window that opens at the end of time",
                statement(issued = Long.MAX_VALUE, expires = Long.MIN_VALUE),
                StatementVerdict.NOT_YET_VALID,
            ),
            Triple(
                "an id full of JSON metacharacters, which this encoding does not care about",
                statement(statementId = """{"a":[1,2]}"""),
                StatementVerdict.VALID,
            ),
        ).forEach { (why, rotation, expected) ->
            assertEquals(
                "$why must earn exactly this verdict",
                expected,
                Utils.verifyRotationStatement(
                    statement = rotation,
                    signature = sign(rotation, storedKeyPair.private),
                    storedPublicKey = storedKeyBase64,
                    now = duringWindow,
                ),
            )
        }
    }

    // ── The delegation, and the limit ────────────────────────────────────

    /**
     * There must be exactly one verifier in this library, and this one must reach it.
     *
     * Stated as an agreement in both directions over a matrix of keys and signatures: the verdict
     * is `SIGNATURE_INVALID` on precisely the inputs [Utils.verifySignature] refuses, and
     * something else on precisely the ones it accepts. A second, subtly different implementation
     * of the parse-and-verify — a stricter key parse, a different algorithm, a missing
     * empty-signature guard — would break the agreement on one of the rows below rather than on
     * all of them, which is why the matrix carries refusals of several different shapes.
     */
    @Test
    fun `the signature gate agrees with verifySignature on every input`() {
        val rotation = statement()
        val genuine = sign(rotation, storedKeyPair.private)
        val overAnother = sign(statement(statementId = "rot-0002"), storedKeyPair.private)
        val preImage = Utils.rotationStatementBytes(rotation)
        var accepted = 0

        listOf(
            "the genuine signature" to (storedKeyBase64 to genuine),
            "the genuine signature under the attacker's key" to (attackerKeyBase64 to genuine),
            "a signature by the wrong key" to
                (storedKeyBase64 to sign(rotation, attackerKeyPair.private)),
            "a signature over a different statement" to (storedKeyBase64 to overAnother),
            "an empty signature" to (storedKeyBase64 to ByteArray(0)),
            "garbage bytes" to (storedKeyBase64 to ByteArray(genuine.size) { 0x5A }),
            "a blank stored key" to ("" to genuine),
            "a stored key that is not a key" to ("QUJDREVGRw==" to genuine),
        ).forEach { (why, input) ->
            val (key, signature) = input
            val direct = Utils.verifySignature(key, preImage, signature)
            val verdict = Utils.verifyRotationStatement(rotation, signature, key, duringWindow)
            if (direct) accepted++
            assertEquals(
                "$why: the verdict's signature gate must agree with verifySignature (which said " +
                    "$direct), or this function checks signatures its own way",
                !direct,
                verdict == StatementVerdict.SIGNATURE_INVALID,
            )
        }

        // Non-vacuity: an agreement that only ever compared `false` against `SIGNATURE_INVALID`
        // would hold against a function hardcoded to that verdict.
        assertEquals("exactly one row above must be a genuine acceptance", 1, accepted)
    }

    /**
     * The limit the KDoc states, made concrete: a signature obtained through the sign-challenge
     * flow — a vault answering "prove your identity" over bytes the caller supplied — verifies as
     * a rotation, because it *is* the same key over the same bytes. No verifier can tell the two
     * apart, which is why the guard lives on the signing device, and why this test asserts the
     * hazard rather than a defence against it. A future reader meets it as a statement rather
     * than as a surprise.
     */
    @Test
    fun `a signature obtained as a login challenge verifies as a rotation`() {
        val rotation = statement(newPublicKey = attackerKeyBase64)
        val preImage = Utils.rotationStatementBytes(rotation)

        // The vault's side of an ordinary sign-challenge: it signs the nonce it was handed.
        val challengeAnswer = Signature.getInstance("SHA256withRSA").run {
            initSign(storedKeyPair.private)
            update(preImage)
            sign()
        }

        assertEquals(
            "this is the attack, and it succeeds against any verifier — the separation is made " +
                "at the signing device by isStatementPreImage, not here",
            StatementVerdict.VALID,
            Utils.verifyRotationStatement(rotation, challengeAnswer, storedKeyBase64, duringWindow),
        )
        assertTrue(
            "so the signing device must be able to see what it is being asked to sign, or the " +
                "attack above has no defence anywhere",
            Utils.isStatementPreImage(preImage),
        )
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    /**
     * The same key, spelled with four characters the Base64 alphabet does not contain.
     *
     * Four and not one: `base64Bytes` refuses a length leaving one character over before it looks
     * at the alphabet at all, so a single insertion would be refused by the length rule and the
     * alphabet rule would never run — the test would pass while pinning the wrong thing.
     */
    private fun strayCharacters(key: String): String = key.take(4) + "!!!!" + key.drop(4)

    private fun verdictFor(rotation: RotationStatement, now: Long): StatementVerdict =
        Utils.verifyRotationStatement(
            statement = rotation,
            signature = sign(rotation, storedKeyPair.private),
            storedPublicKey = storedKeyBase64,
            now = now,
        )

    /**
     * Sign the reference statement, then hand the verifier a *different* one alongside that
     * signature — the shape of a statement edited in transit.
     *
     * The two controls matter as much as the assertion: without them a `tamper` that returned its
     * input unchanged would make the test pass for the wrong reason, and every one of these is a
     * one-line `copy` that could quietly become a no-op.
     */
    private fun assertTamperingRejected(tamper: (RotationStatement) -> RotationStatement) {
        val original = statement()
        val signature = sign(original, storedKeyPair.private)
        val tampered = tamper(original)

        assertNotEquals("control: the tamper must actually change the statement", original, tampered)
        assertEquals(
            "control: the untampered statement must verify, or this proves nothing",
            StatementVerdict.VALID,
            Utils.verifyRotationStatement(original, signature, storedKeyBase64, duringWindow),
        )
        assertEquals(
            "a statement edited after signing must not verify",
            StatementVerdict.SIGNATURE_INVALID,
            Utils.verifyRotationStatement(tampered, signature, storedKeyBase64, duringWindow),
        )
    }

    companion object {
        private lateinit var storedKeyPair: KeyPair
        private lateinit var attackerKeyPair: KeyPair

        /** Kept whole, not just as Base64: one test signs *as* the replacement key, playing the
         *  device the user has just rotated onto. */
        private lateinit var replacementKeyPair: KeyPair
        private lateinit var storedKeyBase64: String
        private lateinit var replacementKeyBase64: String
        private lateinit var attackerKeyBase64: String
        private lateinit var otherProfileKeyBase64: String

        /** 2048-bit RSA generation is slow (~100ms each); do it once for the whole class. */
        @JvmStatic
        @BeforeClass
        fun generateKeys() {
            fun generate(): KeyPair =
                KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

            storedKeyPair = generate()
            attackerKeyPair = generate()
            replacementKeyPair = generate()
            storedKeyBase64 = Base64.encodeToString(storedKeyPair.public.encoded, Base64.NO_WRAP)
            attackerKeyBase64 = Base64.encodeToString(attackerKeyPair.public.encoded, Base64.NO_WRAP)
            replacementKeyBase64 =
                Base64.encodeToString(replacementKeyPair.public.encoded, Base64.NO_WRAP)
            otherProfileKeyBase64 = Base64.encodeToString(generate().public.encoded, Base64.NO_WRAP)
        }
    }
}
