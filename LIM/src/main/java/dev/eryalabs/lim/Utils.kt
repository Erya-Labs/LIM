package dev.eryalabs.lim

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.util.Base64
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import java.io.ByteArrayOutputStream
import java.security.KeyFactory
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

object Utils {

    const val DEFAULT_ENDEAVOR_PACKAGE = "com.github.adaydreamaway.endeavor"

    /**
     * The protocol generation this library speaks. Version 1 is the implicit legacy
     * protocol: nothing on the wire ever says "1", absence says it instead. Every outgoing
     * request carries this value under [EXTRA_PROTOCOL_VERSION], and a vault that
     * understands it echoes its own version in the result — which is what finally lets a
     * client tell "the vault honoured this" from "the vault ignored what it did not know",
     * the question every future protocol addition has to be able to answer.
     */
    const val PROTOCOL_VERSION = 2

    /**
     * Carries [PROTOCOL_VERSION] as a decimal string, in both directions: attached to every
     * outgoing request intent, and read back out of result intents into the parsers'
     * `vaultProtocolVersion`. A legacy vault ignores the extra and echoes nothing, so its
     * results parse exactly as before with a `null` version — never a default that fakes a
     * modern vault.
     */
    const val EXTRA_PROTOCOL_VERSION = "extra_protocol_version"

    // ── Intent extras ────────────────────────────────────────────────────
    const val EXTRA_ENTRY_JSON          = "extra_entry_json"
    const val EXTRA_SHARE_REQUEST_CODE  = "extra_share_request_code"
    const val EXTRA_QUERY_RESULT_FIELDS = "extra_query_result_fields"
    const val EXTRA_PUBLIC_KEY          = "extra_public_key"
    const val EXTRA_NONCE               = "extra_nonce"
    const val EXTRA_SIGNATURE           = "extra_signature"
    const val EXTRA_ALGORITHM           = "extra_algorithm"

    /**
     * JSON-encoded `Map<String, TypedField>` returned by the vault app on a successful
     * sign-challenge. Decode with [decodeFields] after verifying the signature to obtain
     * the profile's field values and their declared datatypes.
     */
    const val EXTRA_FIELDS_JSON = "extra_fields_json"

    private const val SIGN_ALGORITHM = "SHA256withRSA"
    private const val ACTION_SHARE_DATA    = "ACTION_SHARE_DATA"
    private const val ACTION_SIGN_CHALLENGE = "ACTION_SIGN_CHALLENGE"

    private val FIELDS_TYPE = object : TypeToken<Map<String, TypedField>>() {}.type

    // ── Intent action helpers ────────────────────────────────────────────

    /** Returns the share-data action string scoped to [targetPackage]. */
    fun shareDataAction(targetPackage: String = DEFAULT_ENDEAVOR_PACKAGE) =
        "$targetPackage.$ACTION_SHARE_DATA"

    /** Returns the sign-challenge action string scoped to [targetPackage]. */
    fun signChallengeAction(targetPackage: String = DEFAULT_ENDEAVOR_PACKAGE) =
        "$targetPackage.$ACTION_SIGN_CHALLENGE"

    // ── Share intents ────────────────────────────────────────────────────

    /**
     * Create an intent that pushes [entry] into the vault app identified by [targetPackage].
     *
     * Launch with `startActivityForResult` / `ActivityResultContracts.StartActivityForResult`
     * when you need a result (e.g. the vault's confirmation), and decode that result with
     * [parseShareResult]. For fire-and-forget use [shareEntry] instead.
     *
     * No validation happens here: an [Entry] with a blank `id` or `publicKey` is encoded
     * verbatim, and [decodeEntry] on the far side will reject it. Populate both before
     * sending.
     */
    fun createShareIntent(
        context: Context,
        entry: Entry,
        targetPackage: String = DEFAULT_ENDEAVOR_PACKAGE,
    ): Intent {
        val json = Gson().toJson(entry)
        return Intent(shareDataAction(targetPackage)).apply {
            setPackage(targetPackage)
            putExtra(EXTRA_ENTRY_JSON, json)
            putExtra(EXTRA_PROTOCOL_VERSION, PROTOCOL_VERSION.toString())
            // CLEAR_TOP ensures an existing vault instance receives onNewIntent instead of
            // stacking a second copy. FLAG_ACTIVITY_NEW_TASK is intentionally NOT set here —
            // it would put the vault in a separate task and block result delivery.
            addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP)
        }
    }

    /**
     * Create an intent that pushes [entry] into the vault app, tagging it with [requestCode]
     * so the vault can echo it back in the result for correlation.
     */
    fun createShareIntent(
        context: Context,
        entry: Entry,
        requestCode: String,
        targetPackage: String = DEFAULT_ENDEAVOR_PACKAGE,
    ): Intent = createShareIntent(context, entry, targetPackage).apply {
        putExtra(EXTRA_SHARE_REQUEST_CODE, requestCode)
    }

    /**
     * Fire-and-forget share: send [entry] to the vault app without waiting for a result.
     *
     * Use [createShareIntent] + `startActivityForResult` instead when you need confirmation.
     *
     * **Package visibility is your responsibility, not this library's.** On Android 11+ a
     * caller that cannot see [targetPackage] gets no match even when the vault is installed,
     * and `setPackage` does not exempt it. Declare the vault in a `<queries>` element in your
     * own manifest, or `false` will mean "I am not allowed to look" rather than "not there".
     * This library ships no `<queries>` of its own — that is a manifest change, and manifest
     * changes here are a human decision.
     *
     * @return `true` when the intent was dispatched; `false` when no vault was reachable —
     *         none installed, none visible to you (see above), or one that disappeared between
     *         the lookup and the launch. A `false` return is the only signal a client gets that
     *         the share went nowhere; the alternative is a button that does nothing with
     *         nothing to show for it, so it must be handled rather than discarded. Prompt the
     *         user to install a vault only once you have confirmed your `<queries>`, since
     *         until then `false` cannot distinguish "absent" from "invisible". `true` means the
     *         intent was handed to the system, not that the user consented to the disclosure;
     *         nothing here waits for that answer.
     * @throws SecurityException if a vault matches but refuses the launch — an activity that
     *         is not exported, or one behind a permission you do not hold. That is a
     *         misconfiguration on one side or the other, not a device without a vault, and
     *         reporting it as `false` would send the client to tell the user to install an app
     *         they already have. It is deliberately not caught.
     */
    fun shareEntry(
        context: Context,
        entry: Entry,
        targetPackage: String = DEFAULT_ENDEAVOR_PACKAGE,
    ): Boolean {
        val intent = createShareIntent(context, entry, targetPackage).apply {
            // Unlike createShareIntent's own flags, NEW_TASK belongs here: there is no result
            // to deliver back, and without it a non-Activity context cannot start anything.
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        }
        if (intent.resolveActivity(context.packageManager) == null) return false
        return try {
            context.startActivity(intent)
            true
        } catch (_: ActivityNotFoundException) {
            // Resolving and starting are two separate lookups: the vault can be uninstalled or
            // disabled in between. "The intent was not dispatched" is precisely what this
            // function returns false for, so this is the contract, not a swallowed failure.
            false
        }
    }

    // ── Query intent ─────────────────────────────────────────────────────

    /**
     * Create an intent that asks the vault to look up a stored profile by [publicKey].
     * Tag with [requestCode] so you can correlate responses when handling multiple queries.
     *
     * Decode the result intent with [parseQueryResult]. A query is a disclosure, not a login:
     * nothing in the answer is signed, so use [createSignChallengeIntent] when you need proof
     * that the holder of [publicKey] is present.
     */
    fun createQueryIntent(
        context: Context,
        publicKey: String,
        requestCode: String,
        targetPackage: String = DEFAULT_ENDEAVOR_PACKAGE,
    ): Intent = Intent(shareDataAction(targetPackage)).apply {
        setPackage(targetPackage)
        putExtra(EXTRA_PUBLIC_KEY, publicKey)
        putExtra(EXTRA_SHARE_REQUEST_CODE, requestCode)
        putExtra(EXTRA_PROTOCOL_VERSION, PROTOCOL_VERSION.toString())
    }

    // ── Nonces ───────────────────────────────────────────────────────────

    /**
     * Optional declaration, attached to a sign-challenge request via
     * [createSignChallengeIntent]'s `nonceFormat` parameter, naming the layout of the nonce
     * the request carries. Absent means undeclared — the legacy shape, and what every
     * hand-rolled nonce stays.
     *
     * This exists for the *vault's* benefit: a vault cannot enforce nonce freshness across
     * the board, because rejecting stale-looking nonces would break every client whose
     * hand-rolled nonce carries no timestamp at all — it cannot tell which kind it holds.
     * A client that declares its format is volunteering exactly the fact the vault is
     * missing. Whether a vault then enforces anything for declaring clients is its own
     * policy decision; this key only makes the declaration expressible.
     */
    const val EXTRA_NONCE_FORMAT = "extra_nonce_format"

    /**
     * The one format this library can declare: [generateNonce]'s layout, an 8-byte
     * big-endian millisecond timestamp followed by 32 random bytes. Declare it only for a
     * nonce that genuinely has that shape — [generateNonce]'s output, not a hand-rolled
     * one — or a peer reading the header with [nonceTimestamp] will extract random bytes
     * as a time.
     */
    const val NONCE_FORMAT_TIMESTAMPED = "lim-ts1"

    /** Big-endian millisecond timestamp prefixed to every nonce from [generateNonce]. */
    private const val NONCE_TIMESTAMP_BYTES = 8

    /** Random bytes following the timestamp. 32 bytes = 256 bits of unguessable challenge. */
    private const val NONCE_RANDOM_BYTES = 32

    private const val NONCE_SIZE = NONCE_TIMESTAMP_BYTES + NONCE_RANDOM_BYTES

    /**
     * Generate a challenge nonce for [createSignChallengeIntent].
     *
     * The layout is 8 bytes of big-endian millisecond timestamp followed by 32 random bytes.
     * The random half makes the challenge unguessable; the timestamp half is what lets you
     * expire it with [isNonceFresh], so a signature captured today cannot be replayed
     * tomorrow. Callers were previously told to "include a timestamp" and given nothing to
     * do it with, which is exactly the kind of detail every integrator gets subtly wrong.
     *
     * Keep the nonce you sent: verification needs the same bytes back, and [isNonceFresh]
     * reads the timestamp out of them rather than out of any state you have to store.
     *
     * **A vault must not sign every nonce it is handed.** This flow signs arbitrary
     * caller-supplied bytes with a profile's key, and those same bytes could be a signed
     * statement's pre-image — a rotation authorizing an attacker's key, obtained under a consent
     * dialog that said "prove your identity". Call [isStatementPreImage] on an incoming nonce
     * and refuse a match; the signing device is the only place that check can be made, because
     * no verifier can tell the two signatures apart afterwards. A nonce from this function never
     * matches: a random 40-byte challenge cannot begin with [STATEMENT_DOMAIN_V1].
     *
     * @param random Source of randomness; injected so tests can pin it. Defaults to a fresh
     *               [SecureRandom] — do not pass a plain `Random`.
     * @param now    Milliseconds since the epoch to stamp into the nonce; injected so tests
     *               can pin the clock.
     */
    fun generateNonce(
        random: SecureRandom = SecureRandom(),
        now: Long = System.currentTimeMillis(),
    ): ByteArray {
        val nonce = ByteArray(NONCE_SIZE)
        for (i in 0 until NONCE_TIMESTAMP_BYTES) {
            val shift = 8 * (NONCE_TIMESTAMP_BYTES - 1 - i)
            nonce[i] = ((now ushr shift) and 0xFF).toByte()
        }
        val randomBytes = ByteArray(NONCE_RANDOM_BYTES)
        random.nextBytes(randomBytes)
        randomBytes.copyInto(nonce, NONCE_TIMESTAMP_BYTES)
        return nonce
    }

    /**
     * Report whether [nonce] was generated by [generateNonce] no more than [maxAgeMillis]
     * ago. An age of exactly [maxAgeMillis] is still fresh; one millisecond older is not.
     *
     * A nonce may reach you from a peer app, so this is hostile input and never throws.
     * It fails closed on everything it cannot vouch for: a nonce too short to carry the
     * layout above (including an empty one), a negative [maxAgeMillis], and a timestamp in
     * the future — there is no clock-skew grace, because a nonce you issued yourself cannot
     * legitimately be stamped after your own clock. Trailing bytes beyond the 40 the layout
     * defines are ignored rather than rejected.
     *
     * This is a freshness check and nothing more. It says the challenge has not expired; it
     * does not say anyone proved possession of a key — only [verifySignature] does that.
     *
     * @param now Milliseconds since the epoch to measure against; injected so tests can pin
     *            the clock.
     */
    fun isNonceFresh(
        nonce: ByteArray,
        maxAgeMillis: Long,
        now: Long = System.currentTimeMillis(),
    ): Boolean {
        val timestamp = nonceTimestamp(nonce) ?: return false
        if (timestamp > now) return false
        val age = now - timestamp
        // A hostile timestamp far enough below `now` overflows the subtraction and wraps
        // negative; that must read as "not fresh", not as a small age.
        if (age < 0) return false
        return age <= maxAgeMillis
    }

    /**
     * Read the big-endian millisecond timestamp out of a [generateNonce]-layout nonce, or
     * `null` for anything shorter than the full 40-byte layout — the same rule
     * [isNonceFresh] applies (they share this extraction, so they cannot disagree).
     * Trailing bytes beyond the layout are ignored. A nonce reaches a peer from another
     * app, so this is hostile input and never throws.
     *
     * This is the raw header for a *peer* to apply its own policy to; it deliberately
     * decides nothing. [isNonceFresh] assumes the checker issued the nonce — it allows no
     * clock skew, because your own clock cannot legitimately postdate your own nonce — and
     * that assumption is exactly what a peer on a different device's clock does not get to
     * make. Such a peer needs the timestamp itself, plus its own skew grace and its own
     * freshness window. Only trust the value when the sender declared
     * [NONCE_FORMAT_TIMESTAMPED] under [EXTRA_NONCE_FORMAT]: any 40 bytes have a first
     * eight, and an undeclared nonce's header is just random bytes read as a time.
     */
    fun nonceTimestamp(nonce: ByteArray): Long? {
        if (nonce.size < NONCE_SIZE) return null
        var timestamp = 0L
        for (i in 0 until NONCE_TIMESTAMP_BYTES) {
            timestamp = (timestamp shl 8) or (nonce[i].toLong() and 0xFF)
        }
        return timestamp
    }

    // ── Proof-of-possession ──────────────────────────────────────────────

    /**
     * Create an intent that asks the vault app to sign [nonce] with the private key
     * paired to [publicKey].
     *
     * Launch with `ActivityResultContracts.StartActivityForResult`. On `Activity.RESULT_OK`
     * pass the result intent to [parseSignChallengeResult], then authenticate it with
     * [SignChallengeResult.isVerified], handing it this same [publicKey] and [nonce]. Parsing
     * alone proves nothing — it only reports what the vault said.
     *
     * @param publicKey   Base64-encoded RSA public key identifying the profile to authenticate.
     * @param nonce       Challenge bytes you generated. Use [generateNonce], which embeds the
     *                    timestamp [isNonceFresh] needs to reject a replayed challenge.
     * @param requestCode Correlation token echoed back in the result intent.
     * @param targetPackage Package name of the vault app; defaults to [DEFAULT_ENDEAVOR_PACKAGE].
     * @param nonceFormat Optional declaration of [nonce]'s layout, attached under
     *                    [EXTRA_NONCE_FORMAT]. Pass [NONCE_FORMAT_TIMESTAMPED] when — and only
     *                    when — [nonce] came from [generateNonce], so a vault that understands
     *                    the declaration can read the embedded timestamp and apply its own
     *                    freshness policy. The default `null` attaches nothing and leaves the
     *                    intent identical to what this function built before the parameter
     *                    existed: a nonce whose shape you have not declared makes no claim a
     *                    vault could act on.
     */
    fun createSignChallengeIntent(
        context: Context,
        publicKey: String,
        nonce: ByteArray,
        requestCode: String,
        targetPackage: String = DEFAULT_ENDEAVOR_PACKAGE,
        nonceFormat: String? = null,
    ): Intent = Intent(signChallengeAction(targetPackage)).apply {
        setPackage(targetPackage)
        putExtra(EXTRA_PUBLIC_KEY, publicKey)
        putExtra(EXTRA_NONCE, Base64.encodeToString(nonce, Base64.NO_WRAP))
        putExtra(EXTRA_SHARE_REQUEST_CODE, requestCode)
        putExtra(EXTRA_PROTOCOL_VERSION, PROTOCOL_VERSION.toString())
        if (nonceFormat != null) putExtra(EXTRA_NONCE_FORMAT, nonceFormat)
    }

    // ── Signature verification ────────────────────────────────────────────

    /**
     * Verify a signature produced by the vault's sign-challenge flow.
     *
     * @param publicKeyBase64 Base64-encoded RSA public key (as stored/returned by the vault).
     * @param nonce           The original challenge bytes you sent in [createSignChallengeIntent].
     * @param signatureBytes  Raw signature bytes from [EXTRA_SIGNATURE] in the result intent.
     * @return `true` if the signature is valid; `false` on any mismatch or error.
     */
    fun verifySignature(
        publicKeyBase64: String,
        nonce: ByteArray,
        signatureBytes: ByteArray,
    ): Boolean = try {
        val keyBytes = Base64.decode(publicKeyBase64, Base64.DEFAULT)
        val publicKey = KeyFactory.getInstance("RSA")
            .generatePublic(X509EncodedKeySpec(keyBytes))
        Signature.getInstance(SIGN_ALGORITHM).run {
            initVerify(publicKey)
            update(nonce)
            verify(signatureBytes)
        }
    } catch (_: Exception) {
        false
    }

    // ── Signed statements: the canonical pre-image ────────────────────────
    //
    // A signature is only ever a signature over *bytes*. Everything the migration design rests
    // on — "K_old authorized K_new" — therefore lives or dies on signer and verifier agreeing
    // on those bytes exactly, so the encoding below is defined here once and both sides use it
    // rather than each building "the obvious" concatenation.
    //
    // Two properties, and they are the whole design:
    //
    // 1. **Injective.** Every component is length-prefixed, so no value can spill into the slot
    //    after it: a `statementId` ending exactly where the next component begins produces
    //    different bytes, not the same ones. Two different statements sharing a pre-image would
    //    mean a signature over one is a signature over the other.
    // 2. **Domain-separated.** A fixed prefix marks these bytes as a statement, so a signing
    //    device can refuse to sign them as a challenge — see [isStatementPreImage].
    //
    // Deliberately not built out of Gson, `String.format` or any date formatting. A pre-image
    // whose bytes depend on a JSON library's escaping choices, or on the default `Locale`'s
    // digits, is one that changes under you; timestamps travel as raw milliseconds precisely so
    // that no calendar, timezone or locale ever enters a signature.

    /**
     * The fixed prefix every signed statement's pre-image begins with, whatever its kind.
     *
     * This is the barrier between "prove you hold this key" and "authorize replacing this key":
     * the sign-challenge flow signs arbitrary caller-supplied bytes with the same key a
     * statement is verified against, so without a marker a rotation pre-image can be sent as a
     * login challenge. [isStatementPreImage] is the predicate; a vault calling it before signing
     * is the mechanism.
     */
    const val STATEMENT_DOMAIN_V1 = "lim.statement.v1"

    /** Kind tag naming a [RotationStatement] inside the pre-image, after the domain prefix. */
    const val STATEMENT_ROTATE_V1 = "lim.rotate.v1"

    /**
     * Kind tag naming a [RecoveryAuthorization] inside the pre-image, after the domain prefix.
     *
     * The kind tag is not bookkeeping. A rotation and a recovery authorization carry the same
     * *shapes* of component — two keys, an id, two 64-bit numbers — so without a kind inside the
     * signed bytes a signature over one would be a signature over the other, and the difference
     * between them is "authorized to replace this key today" against "authorized to replace it
     * forever". That is why it is signed rather than carried alongside.
     */
    const val STATEMENT_RECOVER_V1 = "lim.recover.v1"

    /** Kind tag naming a [Revocation] inside the pre-image, after the domain prefix. */
    const val STATEMENT_REVOKE_V1 = "lim.revoke.v1"

    /**
     * Width of the big-endian length that precedes every text component. Four bytes rather than
     * a varint: the encoding has to be reproducible by a peer implementation from a one-line
     * description, and "four-byte big-endian length, then UTF-8 bytes" is that description.
     */
    private const val COMPONENT_LENGTH_BYTES = 4

    /** Width of a raw 64-bit component — a timestamp or a sequence — big-endian, two's complement. */
    private const val STATEMENT_LONG_BYTES = 8

    /** The domain prefix as the bytes it actually occupies, computed once. */
    private val STATEMENT_DOMAIN_BYTES = STATEMENT_DOMAIN_V1.toByteArray(Charsets.UTF_8)

    /** Big-endian, most significant byte first, exactly [width] bytes. */
    private fun ByteArrayOutputStream.writeBigEndian(value: Long, width: Int) {
        for (i in 0 until width) {
            val shift = 8 * (width - 1 - i)
            write(((value ushr shift) and 0xFF).toInt())
        }
    }

    /**
     * A length-prefixed UTF-8 component: four bytes of big-endian *byte* length — not character
     * count, so a multi-byte value still delimits correctly — followed by the bytes themselves.
     *
     * The prefix is what makes the layout injective, and it is also what makes the pre-image
     * readable back rather than merely comparable, which is what carrying one inside a transport
     * envelope depends on.
     */
    private fun ByteArrayOutputStream.writeTextComponent(text: String) {
        val bytes = text.toByteArray(Charsets.UTF_8)
        writeBigEndian(bytes.size.toLong(), COMPONENT_LENGTH_BYTES)
        write(bytes, 0, bytes.size)
    }

    /**
     * A 64-bit component — a timestamp or a sequence number: eight raw big-endian bytes and no
     * length prefix, because a fixed-width field is already self-delimiting, its width *is* its
     * prefix. Negative values encode as two's complement and round-trip like any other.
     *
     * Raw bytes rather than a rendering, for both uses and for the same reason: a number formatted
     * through a locale is a number that changes under you, so no calendar, timezone or locale ever
     * enters a signature.
     */
    private fun ByteArrayOutputStream.writeLongComponent(value: Long) {
        writeBigEndian(value, STATEMENT_LONG_BYTES)
    }

    /**
     * Open a pre-image: the domain prefix, then the kind tag as a length-prefixed component.
     *
     * The prefix is written raw rather than length-prefixed so that [isStatementPreImage] can be
     * a plain byte-prefix comparison; it is a constant shared by every statement, so leaving it
     * unprefixed costs nothing in injectivity. The kind tag is prefixed like any other component
     * — it is what separates "authorized to replace this key today" from other kinds of
     * authorization, so it must be inside the signed bytes and unambiguously delimited.
     */
    private fun openStatement(kindTag: String): ByteArrayOutputStream {
        val out = ByteArrayOutputStream()
        out.write(STATEMENT_DOMAIN_BYTES, 0, STATEMENT_DOMAIN_BYTES.size)
        out.writeTextComponent(kindTag)
        return out
    }

    /**
     * The exact bytes a [RotationStatement] is signed over, and the exact bytes a verifier must
     * reconstruct. Signer and verifier disagreeing by one byte would make the whole mechanism
     * theatre, so there is one encoder and both sides call it.
     *
     * Layout, in order: the [STATEMENT_DOMAIN_V1] prefix; [STATEMENT_ROTATE_V1]; then
     * `oldPublicKey`, `newPublicKey` and `statementId` as length-prefixed UTF-8; then
     * `issuedAtMillis` and `expiresAtMillis` as eight big-endian bytes each. Every component is
     * present, so none can be silently absent from what gets signed — a pre-image that omitted
     * `newPublicKey` would let any key at all be swapped in under a genuine signature.
     *
     * Deterministic: the same statement yields the same bytes on every call, on every machine,
     * under every default [java.util.Locale].
     *
     * **Sign these bytes; do not sign a rendering of them.** And on the other side of the same
     * coin, a device asked to sign bytes it did not construct must check them with
     * [isStatementPreImage] first.
     *
     * One known equivalence, recorded rather than left to be discovered: components are encoded
     * as UTF-8, and no `String` can encode an unpaired surrogate, so a component containing one
     * encodes to the same bytes as one containing `?` in that position. Two such statements are
     * therefore the same statement to a signature. Every component this protocol actually
     * carries is Base64 or an opaque printable id, none of which contains a surrogate at all,
     * and the alternative — refusing to encode, or throwing — would be worse in a function that
     * a verifier calls on input it did not choose.
     */
    fun rotationStatementBytes(statement: RotationStatement): ByteArray {
        val out = openStatement(STATEMENT_ROTATE_V1)
        out.writeTextComponent(statement.oldPublicKey)
        out.writeTextComponent(statement.newPublicKey)
        out.writeTextComponent(statement.statementId)
        out.writeLongComponent(statement.issuedAtMillis)
        out.writeLongComponent(statement.expiresAtMillis)
        return out.toByteArray()
    }

    /**
     * The exact bytes a [RecoveryAuthorization] is signed over, through the same encoder
     * [rotationStatementBytes] uses and with the same guarantees: one domain prefix, a kind tag,
     * every component length-prefixed or fixed-width, no JSON and no formatting.
     *
     * Layout, in order: the [STATEMENT_DOMAIN_V1] prefix; [STATEMENT_RECOVER_V1]; then
     * `subjectPublicKey`, `recoveryPublicKey` and `authorizationId` as length-prefixed UTF-8; then
     * `sequence` and `issuedAtMillis` as eight big-endian bytes each.
     *
     * **The kind tag is what separates this from a rotation**, and it is inside the signed bytes
     * for that reason: the two statements carry the same shapes of component, so a signature over
     * a rotation must not also be a signature over an authorization that never expires. A
     * `RotationStatement` and a `RecoveryAuthorization` whose components are pairwise identical
     * therefore produce different bytes.
     *
     * The same UTF-8 surrogate equivalence [rotationStatementBytes] documents applies here, for
     * the same reason and with the same irrelevance to a protocol whose components are Base64
     * keys and opaque printable ids.
     */
    fun recoveryAuthorizationBytes(authorization: RecoveryAuthorization): ByteArray {
        val out = openStatement(STATEMENT_RECOVER_V1)
        out.writeTextComponent(authorization.subjectPublicKey)
        out.writeTextComponent(authorization.recoveryPublicKey)
        out.writeTextComponent(authorization.authorizationId)
        out.writeLongComponent(authorization.sequence)
        out.writeLongComponent(authorization.issuedAtMillis)
        return out.toByteArray()
    }

    /**
     * The exact bytes a [Revocation] is signed over, through the same encoder as the other two
     * kinds.
     *
     * Layout, in order: the [STATEMENT_DOMAIN_V1] prefix; [STATEMENT_REVOKE_V1]; then
     * `subjectPublicKey` and `revokedAuthorizationId` as length-prefixed UTF-8; then `sequence`
     * and `issuedAtMillis` as eight big-endian bytes each.
     *
     * Four components rather than five, because a revocation names no second key — it cancels an
     * authorization by id, and the id is the whole of what it points at. That is also why
     * [verifyRevocation] can return fewer verdicts than the other two verifiers.
     */
    fun revocationBytes(revocation: Revocation): ByteArray {
        val out = openStatement(STATEMENT_REVOKE_V1)
        out.writeTextComponent(revocation.subjectPublicKey)
        out.writeTextComponent(revocation.revokedAuthorizationId)
        out.writeLongComponent(revocation.sequence)
        out.writeLongComponent(revocation.issuedAtMillis)
        return out.toByteArray()
    }

    /**
     * Report whether [bytes] are a signed-statement pre-image — that is, whether they begin with
     * [STATEMENT_DOMAIN_V1].
     *
     * One predicate covers every kind. The prefix comes before the kind tag, so a
     * [RotationStatement], a [RecoveryAuthorization] and a [Revocation] are all caught by the same
     * comparison, and a kind added later is caught without a second mechanism.
     *
     * **A vault must call this on every nonce before signing, and refuse a match.** That
     * obligation is the entire reason the domain prefix exists, and the signing device is the
     * only place it can be honoured: a verifier cannot distinguish a signature the user
     * authorized as a rotation from one the user was tricked into producing as a login
     * challenge, because in both cases the same key signed the same bytes. See
     * [generateNonce] for the same warning from the challenge side, and [RotationStatement] for
     * the shape of the attack.
     *
     * Total and never throws: `null` is `false`, so is an empty array, so is anything shorter
     * than the prefix. A nonce arrives from another app, which is exactly why this must be safe
     * to call on it unconditionally.
     *
     * A `true` says these bytes are *framed* as a statement, and nothing more — not that they
     * parse, not that they are well-formed, and certainly not that anyone signed them. It is a
     * refusal predicate, not a validator.
     */
    fun isStatementPreImage(bytes: ByteArray?): Boolean {
        if (bytes == null || bytes.size < STATEMENT_DOMAIN_BYTES.size) return false
        for (i in STATEMENT_DOMAIN_BYTES.indices) {
            if (bytes[i] != STATEMENT_DOMAIN_BYTES[i]) return false
        }
        return true
    }

    // ── Signed statements: verification ───────────────────────────────────

    /**
     * Verify a [RotationStatement] against the public key a service already stores for the
     * profile — the integrator-facing half of device migration.
     *
     * **The public key is the account identifier.** That is the rule the whole design rests on
     * and this is the function where a service acts on it: migration means telling every service
     * that stored `K_old` to store `K_new` instead, and the only thing that can say so credibly
     * is a signature by the key the service already holds. A service that keys accounts on a
     * disclosed field such as an email address instead cannot rotate safely — a new key would
     * arrive with nothing to bind it to, and the service has already lost the property this
     * protocol exists for, since that field is now the identifier a breach leaks.
     *
     * **What a [StatementVerdict.VALID] does not say.** It says the holder of [storedPublicKey]
     * signed *these bytes* inside the window the statement declares. It cannot say whether they
     * signed them knowingly as a rotation or were tricked into signing them as a login
     * challenge: the sign-challenge flow signs arbitrary caller-supplied bytes with this very
     * key, and no verifier can tell the two signatures apart afterwards — the bytes are the
     * bytes. That separation is enforced at the signing device, where [isStatementPreImage] lets
     * a vault refuse a nonce that is really a statement. A verifier implying otherwise is
     * overselling what it checked. Consent for the rotation itself is the vault's to obtain.
     *
     * The check order is part of the contract, because which refusal an integrator is shown
     * decides what they tell the user:
     *
     * 1. **The signature**, over [rotationStatementBytes] of [statement], against
     *    [storedPublicKey]. Anything a forger or a tamperer produces stops here as
     *    [StatementVerdict.SIGNATURE_INVALID] and never reaches a verdict that would describe
     *    it as an ordinary, merely-stale statement.
     * 2. **The subject**: [StatementVerdict.WRONG_SUBJECT] unless `statement.oldPublicKey`
     *    equals [storedPublicKey] by exact string equality — no trimming, no normalising. The
     *    protocol looks a profile up by the key *string*, so two spellings of one key are two
     *    different accounts, and a genuine statement for another profile must not be applied
     *    here.
     * 3. **[StatementVerdict.SAME_KEY]**, when the replacement is the key already stored.
     * 4. **[StatementVerdict.NEW_KEY_UNUSABLE]**, when `newPublicKey` is blank, is not standard
     *    Base64, or does not parse as an RSA public key — the same parse [validateEntry]
     *    performs, checked before the swap rather than trusted because it was signed.
     * 5. **The window**, valid when `issuedAtMillis <= now <= expiresAtMillis`. Both ends are
     *    inclusive, the boundary rule [isNonceFresh] already set. A statement whose window is
     *    nonsensical (`expiresAtMillis < issuedAtMillis`) can never be valid, whatever `now` is;
     *    where both window checks would fire at once, [StatementVerdict.NOT_YET_VALID] is the
     *    answer, because such a statement never became valid rather than having gone stale.
     *
     * **The limit of check 4, recorded rather than quietly closed.** It rejects a key it cannot
     * parse; it cannot reject a key that parses but is *spelled* differently from how the service
     * will later look it up. `newPublicKey + "\n"` is accepted, because [Base64.DEFAULT] — what
     * the vault encodes keys with — wraps at 76 characters, so refusing whitespace here would
     * refuse every legitimately wrapped key. A service that stores such a spelling holds a key
     * that authenticates fine and matches no profile, and its next rotation comes back
     * [StatementVerdict.WRONG_SUBJECT] under check 2. That is the identity-matching hazard this
     * protocol has throughout — one key, several spellings, one of which the lookup finds — and
     * narrowing it here would need the vault to agree, so it is a human's decision and not this
     * function's. **Store the exact string you verified**, and encode keys one way.
     *
     * This adds no algorithm. It **delegates to [verifySignature]** rather than re-implementing
     * it, so the security-critical verifier stays byte-identical and there is exactly one place
     * in this library where a signature is checked; `SHA256withRSA` stays hardcoded there, and
     * honouring a peer-supplied [EXTRA_ALGORITHM] remains something a human must decide.
     *
     * Every *value* this can be handed comes back as a verdict: [signature] and [storedPublicKey]
     * arrive from wherever the statement was relayed from, and empty, garbage and blank inputs
     * are all answers rather than exceptions. The parameters are declared non-null, though, so a
     * Java caller passing `null` — `intent.getByteArrayExtra(...)` on an absent extra is the way
     * that happens — gets a [NullPointerException] from Kotlin's parameter check, exactly as
     * [verifySignature] does. Null-check the extra; do not rely on a verdict for it.
     *
     * @param statement       The statement to check. Its five components are exactly what gets
     *                        signed, so every one of them is covered by the signature check.
     * @param signature       The raw signature bytes accompanying the statement.
     * @param storedPublicKey The Base64 RSA public key this service holds for the profile — the
     *                        account identifier, and the key the signature must be by.
     * @param now             Milliseconds since the epoch to measure the window against;
     *                        injected so tests can pin the clock.
     * @return One of [StatementVerdict.VALID], [StatementVerdict.SIGNATURE_INVALID],
     *         [StatementVerdict.WRONG_SUBJECT], [StatementVerdict.SAME_KEY],
     *         [StatementVerdict.NEW_KEY_UNUSABLE], [StatementVerdict.EXPIRED] or
     *         [StatementVerdict.NOT_YET_VALID]. Act only on [StatementVerdict.VALID].
     */
    fun verifyRotationStatement(
        statement: RotationStatement,
        signature: ByteArray,
        storedPublicKey: String,
        now: Long = System.currentTimeMillis(),
    ): StatementVerdict {
        if (!verifySignature(storedPublicKey, rotationStatementBytes(statement), signature)) {
            return StatementVerdict.SIGNATURE_INVALID
        }
        if (statement.oldPublicKey != storedPublicKey) return StatementVerdict.WRONG_SUBJECT
        // Against the stored key rather than against `oldPublicKey`, which the line above has
        // just established is the same string. Stated this way because the fact that matters is
        // "the service would be storing what it already stores", not a property of the statement.
        if (statement.newPublicKey == storedPublicKey) return StatementVerdict.SAME_KEY
        if (!isUsablePublicKey(statement.newPublicKey)) return StatementVerdict.NEW_KEY_UNUSABLE
        if (now < statement.issuedAtMillis) return StatementVerdict.NOT_YET_VALID
        if (now > statement.expiresAtMillis) return StatementVerdict.EXPIRED
        return StatementVerdict.VALID
    }

    /**
     * Verify a [RecoveryAuthorization] against the public key a service already stores for the
     * profile — the standing credential half of the recovery design.
     *
     * Mirrors [verifyRotationStatement] exactly, including the ordering, and for the same reasons:
     *
     * 1. **The signature**, over [recoveryAuthorizationBytes] of [authorization], against
     *    [storedPublicKey]. A forged or tampered authorization stops here as
     *    [StatementVerdict.SIGNATURE_INVALID] and never earns a verdict that describes it as
     *    genuine-but-inapplicable.
     * 2. **[StatementVerdict.WRONG_SUBJECT]** unless `authorization.subjectPublicKey` equals
     *    [storedPublicKey] by exact string equality — no trimming, no normalising, because the
     *    protocol looks a profile up by the key *string*.
     * 3. **[StatementVerdict.SAME_KEY]**, when the recovery key is the key already stored: a
     *    device authorizing itself is not a recovery plan, and honouring it would record a
     *    standing credential that adds nothing and can still be stolen.
     * 4. **[StatementVerdict.NEW_KEY_UNUSABLE]**, when `recoveryPublicKey` is blank, is not
     *    standard Base64, or does not parse as an RSA public key. A blessed device that cannot
     *    sign anything is a recovery plan that will fail at the only moment it is needed.
     *
     * **No window is checked, and there is none to check.** A [RecoveryAuthorization] declares no
     * expiry on purpose — one that expired before the emergency would be worthless, since the
     * emergency is precisely when nothing can refresh it. So this verifier can never return
     * [StatementVerdict.EXPIRED] or [StatementVerdict.NOT_YET_VALID], and an integrator's
     * exhaustive `when` needs no branch that can occur. The consequence to accept explicitly:
     * a [StatementVerdict.VALID] here is valid *forever* unless a [Revocation] arrives, so
     * distributing revocations is load-bearing rather than housekeeping.
     *
     * **A [StatementVerdict.VALID] is not "this device may act now".** It says the holder of
     * [storedPublicKey] signed this authorization. Whether it is still live is a separate
     * question, answered by the revocations the service has been shown, and this function looks
     * at none of them. It also cannot say whether the user signed knowingly: the sign-challenge
     * flow signs arbitrary caller-supplied bytes with this very key, and the separation is
     * enforced at the signing device by [isStatementPreImage] — see [verifyRotationStatement] for
     * the shape of that hazard, which reaches an authorization more sharply than a rotation
     * because an authorization never goes stale.
     *
     * The same delegation and the same limits as [verifyRotationStatement]: one call to
     * [verifySignature], `SHA256withRSA` and no other algorithm, no new dependency, and a key
     * spelled with stray whitespace that decodes to the stored key is accepted here as it is
     * there — **store the exact string you verified**.
     *
     * @param authorization   The authorization to check. All five components are inside the
     *                        signature.
     * @param signature       The raw signature bytes accompanying it.
     * @param storedPublicKey The Base64 RSA public key this service holds for the profile.
     * @return [StatementVerdict.VALID], [StatementVerdict.SIGNATURE_INVALID],
     *         [StatementVerdict.WRONG_SUBJECT], [StatementVerdict.SAME_KEY] or
     *         [StatementVerdict.NEW_KEY_UNUSABLE] — never a window verdict.
     */
    fun verifyRecoveryAuthorization(
        authorization: RecoveryAuthorization,
        signature: ByteArray,
        storedPublicKey: String,
    ): StatementVerdict {
        if (!verifySignature(
                storedPublicKey,
                recoveryAuthorizationBytes(authorization),
                signature,
            )
        ) {
            return StatementVerdict.SIGNATURE_INVALID
        }
        if (authorization.subjectPublicKey != storedPublicKey) return StatementVerdict.WRONG_SUBJECT
        // Against the stored key rather than against `subjectPublicKey`, which the line above has
        // just established is the same string — the fact that matters is "the device being
        // blessed is the one already holding the account", not a property of the statement.
        if (authorization.recoveryPublicKey == storedPublicKey) return StatementVerdict.SAME_KEY
        if (!isUsablePublicKey(authorization.recoveryPublicKey)) {
            return StatementVerdict.NEW_KEY_UNUSABLE
        }
        return StatementVerdict.VALID
    }

    /**
     * Verify a [Revocation] against the public key a service already stores for the profile.
     *
     * Two checks and no more, because a revocation names no second key:
     *
     * 1. **The signature**, over [revocationBytes] of [revocation], against [storedPublicKey].
     * 2. **[StatementVerdict.WRONG_SUBJECT]** unless `revocation.subjectPublicKey` equals
     *    [storedPublicKey] by exact string equality. This is what stops a revocation reaching
     *    across profiles when an `authorizationId` collides between two of them.
     *
     * So the reachable verdicts are exactly [StatementVerdict.VALID],
     * [StatementVerdict.SIGNATURE_INVALID] and [StatementVerdict.WRONG_SUBJECT].
     * [StatementVerdict.SAME_KEY] and [StatementVerdict.NEW_KEY_UNUSABLE] have nothing to be
     * about here, and the window verdicts are impossible by design: **a revocation that could go
     * stale would un-revoke a stolen device**, which is the worst failure this feature has, so a
     * revocation declares no window and none is applied.
     *
     * **A [StatementVerdict.VALID] does not say what this revocation kills.** It says the holder
     * of the stored key signed it, and nothing else; which authorizations it cancels is set
     * arithmetic over the sequence numbers, done by the caller against statements it has already
     * verified with this function and [verifyRecoveryAuthorization].
     *
     * Same delegation to [verifySignature] and the same hostile-input contract as the other two
     * verifiers: every *value* comes back as a verdict, while a `null` passed from Java to a
     * non-null parameter is Kotlin's [NullPointerException] as everywhere else.
     *
     * @param revocation      The revocation to check. All four components are inside the
     *                        signature.
     * @param signature       The raw signature bytes accompanying it.
     * @param storedPublicKey The Base64 RSA public key this service holds for the profile.
     */
    fun verifyRevocation(
        revocation: Revocation,
        signature: ByteArray,
        storedPublicKey: String,
    ): StatementVerdict {
        if (!verifySignature(storedPublicKey, revocationBytes(revocation), signature)) {
            return StatementVerdict.SIGNATURE_INVALID
        }
        if (revocation.subjectPublicKey != storedPublicKey) return StatementVerdict.WRONG_SUBJECT
        return StatementVerdict.VALID
    }

    /**
     * Whether [publicKey] is a key a service could actually store and later verify against:
     * non-blank, standard Base64, and parsing as an X.509 RSA public key.
     *
     * The same two helpers [validateEntry] uses, composed rather than duplicated — but combined
     * into one predicate here on purpose. [validateEntry] must keep the three failures apart
     * because it reports them to a developer; a verifier only has to decide whether to let the
     * swap happen, and a service told *why* the replacement key is unusable can do nothing
     * different about it.
     */
    private fun isUsablePublicKey(publicKey: String): Boolean {
        // Redundant on paper, and kept for the reason `matchesRequestCode`'s blank guard is:
        // `base64Bytes` strips whitespace and then refuses an empty remainder, so removing this
        // line changes no answer *today*. It rests on the behaviour of a different function,
        // though, and "a blank key is not a key" is too load-bearing to leave resting there —
        // storing one would lock the user out permanently.
        if (publicKey.isBlank()) return false
        val keyBytes = base64Bytes(publicKey) ?: return false
        return parsesAsRsaPublicKey(keyBytes)
    }

    // ── Result parsing ────────────────────────────────────────────────────

    /**
     * Read a string extra that another app wrote.
     *
     * Two hostile shapes are handled here rather than at each call site: an extra stored
     * under this key with a non-String type simply reads back as `null`, and unparcelling
     * an extras bundle referencing a class this process does not have throws — a result
     * intent is attacker-influenced input, so neither may take the client app down. Blank
     * is treated as absent so that a caller comparing an echoed token cannot be fooled by
     * `""` matching `""`.
     */
    private fun Intent.presentStringExtra(key: String): String? = try {
        getStringExtra(key)?.takeIf { it.isNotBlank() }
    } catch (_: Exception) {
        null
    }

    /**
     * Read the protocol version the peer declared under [EXTRA_PROTOCOL_VERSION] — the
     * version a vault echoed into a result, or the version a client attached to a request.
     *
     * `null` for everything that is not an unambiguous declaration: an absent or blank
     * extra, one of the wrong type, a value that is not a decimal integer, one that does
     * not fit in an [Int], and zero or below. The extra arrives from another app, so none
     * of that may throw — and none of it may *default*, either: `null` means "the peer
     * did not say", and a peer that did not say must never be presented as a modern one.
     *
     * A version on its own is not an answer. Each parser's empty-envelope or
     * required-extra rule is checked over its flow's own extras before this is read, so an
     * intent carrying nothing but a version still parses to `null`.
     */
    private fun Intent.declaredProtocolVersion(): Int? =
        presentStringExtra(EXTRA_PROTOCOL_VERSION)?.toIntOrNull()?.takeIf { it > 0 }

    /**
     * Base64-decode a signature or nonce, yielding `null` for anything that cannot be one.
     *
     * DEFAULT, not NO_WRAP: signatures arrive DEFAULT-encoded (wrapped at 76 characters)
     * and nonces NO_WRAP-encoded, and DEFAULT decodes both. Android's Base64 skips
     * characters outside the alphabet rather than rejecting them, so junk can decode to
     * zero bytes without throwing: reject that too — an empty signature can never verify,
     * and an empty nonce is a challenge over nothing.
     */
    private fun nonEmptyBase64(encoded: String?): ByteArray? {
        if (encoded == null) return null
        return try {
            Base64.decode(encoded, Base64.DEFAULT).takeIf { it.isNotEmpty() }
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Decode the result intent delivered by the sign-challenge flow.
     *
     * Returns `null` when [intent] is missing or carries no usable signature — including when
     * [EXTRA_SIGNATURE] is absent, blank, not valid Base64 or decodes to no bytes. Without a
     * signature there is nothing that could ever be authenticated, so there is no result worth
     * handing back. A malformed [EXTRA_FIELDS_JSON] payload is *not* fatal by contrast: the
     * signature still stands on its own, so the result comes back with an empty field map.
     *
     * **This function does not authenticate anything, and a non-null return is not a success
     * signal.** It reports what the intent said; [SignChallengeResult.isVerified] is the only
     * thing that reports whether the sender holds the private key.
     */
    fun parseSignChallengeResult(intent: Intent?): SignChallengeResult? {
        if (intent == null) return null
        val signature = nonEmptyBase64(intent.presentStringExtra(EXTRA_SIGNATURE)) ?: return null
        return SignChallengeResult(
            signature = signature,
            algorithm = intent.presentStringExtra(EXTRA_ALGORITHM),
            fields = decodeFields(intent.presentStringExtra(EXTRA_FIELDS_JSON)),
            requestCode = intent.presentStringExtra(EXTRA_SHARE_REQUEST_CODE),
            vaultProtocolVersion = intent.declaredProtocolVersion(),
        )
    }

    /**
     * Decode the result intent delivered in response to [createQueryIntent].
     *
     * Returns `null` when [intent] is missing or carries none of the three extras this flow
     * defines ([EXTRA_QUERY_RESULT_FIELDS], [EXTRA_PUBLIC_KEY], [EXTRA_SHARE_REQUEST_CODE]) —
     * an intent with nothing in it is an empty envelope, not an answer. When any of them is
     * present the result comes back populated with what could be read: a malformed or absent
     * fields payload yields an empty map rather than a `null` result, so that a vault which
     * answers "no fields disclosed" is distinguishable from a vault which did not answer.
     *
     * Note the field payload arrives under [EXTRA_QUERY_RESULT_FIELDS] here, not the
     * [EXTRA_FIELDS_JSON] key the sign-challenge flow uses. The two keys are separate points
     * in the protocol and are deliberately not interchangeable.
     */
    fun parseQueryResult(intent: Intent?): QueryResult? {
        if (intent == null) return null
        val fieldsJson = intent.presentStringExtra(EXTRA_QUERY_RESULT_FIELDS)
        val publicKey = intent.presentStringExtra(EXTRA_PUBLIC_KEY)
        val requestCode = intent.presentStringExtra(EXTRA_SHARE_REQUEST_CODE)
        if (fieldsJson == null && publicKey == null && requestCode == null) return null
        return QueryResult(
            fields = decodeFields(fieldsJson),
            publicKey = publicKey,
            requestCode = requestCode,
            vaultProtocolVersion = intent.declaredProtocolVersion(),
        )
    }

    /**
     * Decode the result intent delivered in response to [createShareIntent] +
     * `startActivityForResult` — the acknowledgement that the vault stored the pushed entry.
     *
     * The vault answers with the public key it stored the profile under
     * ([EXTRA_PUBLIC_KEY]), the stored fields ([EXTRA_FIELDS_JSON], the same key the
     * sign-challenge result uses for its disclosure), and — only when the share was created
     * with the [createShareIntent] overload carrying a request code — the echoed
     * [EXTRA_SHARE_REQUEST_CODE].
     *
     * The semantics mirror [parseQueryResult]: `null` only when [intent] is missing or none
     * of the three extras is present — an intent with nothing in it is an empty envelope,
     * not an answer. Blank extras read as absent, and a malformed fields payload is not
     * fatal: the public key still stands on its own, so the result comes back with an empty
     * field map rather than disappearing.
     *
     * [EXTRA_QUERY_RESULT_FIELDS] is deliberately not read here. The two field payloads sit
     * under different keys at different points in the protocol, and the flows' keys are not
     * interchangeable — the same separation [parseQueryResult] pins from its side.
     */
    fun parseShareResult(intent: Intent?): ShareResult? {
        if (intent == null) return null
        val publicKey = intent.presentStringExtra(EXTRA_PUBLIC_KEY)
        val fieldsJson = intent.presentStringExtra(EXTRA_FIELDS_JSON)
        val requestCode = intent.presentStringExtra(EXTRA_SHARE_REQUEST_CODE)
        if (publicKey == null && fieldsJson == null && requestCode == null) return null
        return ShareResult(
            publicKey = publicKey,
            fields = decodeFields(fieldsJson),
            requestCode = requestCode,
            vaultProtocolVersion = intent.declaredProtocolVersion(),
        )
    }

    // ── Request parsing (the vault's side) ───────────────────────────────
    //
    // The builders above pin what a request looks like leaving a client; these pin what one
    // means arriving at a vault. Until now the request half of the wire format existed in
    // this library only as the builders' output — every vault hand-read the extras back out,
    // so the two ends could drift apart with nothing to fail. A request intent is the most
    // hostile input a vault handles: any app can fire one at it, so every parser here fails
    // closed and never throws.

    /**
     * Decode a share request intent — the vault's half of [createShareIntent].
     *
     * Returns `null` when [intent] is missing, carries no entry payload under
     * [EXTRA_ENTRY_JSON], or carries one that [decodeEntry] refuses — a request whose entry
     * is malformed or has a blank identity is not a share the vault could store, so it is
     * refused whole rather than handed on half-parsed. A blank payload reads as absent, like
     * every extra in this protocol.
     *
     * The share action doubles as the query action; the payload is what tells them apart.
     * An intent carrying an entry payload is a share even if a public key rides alongside —
     * the mirror of [parseQueryRequest]'s rule, so no intent parses as both.
     */
    fun parseShareRequest(intent: Intent?): ShareRequest? {
        if (intent == null) return null
        val entry = decodeEntry(intent.presentStringExtra(EXTRA_ENTRY_JSON)) ?: return null
        return ShareRequest(
            entry = entry,
            requestCode = intent.presentStringExtra(EXTRA_SHARE_REQUEST_CODE),
            protocolVersion = intent.declaredProtocolVersion(),
        )
    }

    /**
     * Decode a query request intent — the vault's half of [createQueryIntent].
     *
     * Returns `null` when [intent] is missing, carries a non-blank [EXTRA_ENTRY_JSON]
     * payload — that intent is a share, and [parseShareRequest] is the parser that accepts
     * it — or carries no usable public key under [EXTRA_PUBLIC_KEY]. The entry-payload rule
     * is how the vault routes today, pinned here so both directions agree: no intent parses
     * as both a share and a query. Blank extras read as absent, so a blank public key is a
     * refusal, not a request naming nobody.
     */
    fun parseQueryRequest(intent: Intent?): QueryRequest? {
        if (intent == null) return null
        if (intent.presentStringExtra(EXTRA_ENTRY_JSON) != null) return null
        val publicKey = intent.presentStringExtra(EXTRA_PUBLIC_KEY) ?: return null
        return QueryRequest(
            publicKey = publicKey,
            requestCode = intent.presentStringExtra(EXTRA_SHARE_REQUEST_CODE),
            protocolVersion = intent.declaredProtocolVersion(),
        )
    }

    /**
     * Decode a sign-challenge request intent — the vault's half of
     * [createSignChallengeIntent], including the Base64 nonce decoding every vault
     * previously did by hand.
     *
     * Returns `null` when [intent] is missing, carries no usable public key under
     * [EXTRA_PUBLIC_KEY], or carries a nonce under [EXTRA_NONCE] that is absent, blank, not
     * decodable Base64, or decodes to no bytes — Android's decoder *skips* characters
     * outside the alphabet rather than rejecting them, so junk can decode to zero bytes
     * without throwing, and a challenge over zero bytes is not a challenge. A parsed
     * request is a claim, not an entitlement: whether to sign is the vault's consent
     * decision, and [SignChallengeRequest.nonceFormat] is only what the client *declared*
     * about its nonce, not something any parser verified.
     */
    fun parseSignChallengeRequest(intent: Intent?): SignChallengeRequest? {
        if (intent == null) return null
        val publicKey = intent.presentStringExtra(EXTRA_PUBLIC_KEY) ?: return null
        val nonce = nonEmptyBase64(intent.presentStringExtra(EXTRA_NONCE)) ?: return null
        return SignChallengeRequest(
            publicKey = publicKey,
            nonce = nonce,
            requestCode = intent.presentStringExtra(EXTRA_SHARE_REQUEST_CODE),
            nonceFormat = intent.presentStringExtra(EXTRA_NONCE_FORMAT),
            protocolVersion = intent.declaredProtocolVersion(),
        )
    }

    /**
     * Report whether [intent] carries the correlation token [expected] under
     * [EXTRA_SHARE_REQUEST_CODE].
     *
     * A client that has several requests in flight gets several result intents back and has to
     * decide which one answers which. Doing that by hand is where the accidents happen, and the
     * accident is not a crash — it is acting on a disclosure meant for a different request.
     *
     * Fails closed on every shape that is not an unambiguous match: a null [intent], an intent
     * with no request-code extra, an extra that is blank or of the wrong type, and an extras
     * bundle that cannot be unparcelled at all. **A blank or empty [expected] never matches
     * anything**, including an intent that carries no request code — "nothing equals nothing"
     * is precisely the mistake a hand-rolled comparison makes, and it is the one that pairs a
     * client's untagged request with the first result that happens to arrive.
     *
     * The comparison is exact. Whitespace is not trimmed from either side, so `"req-1"` and
     * `" req-1"` are different tokens: a request code is an opaque handle the client minted,
     * and quietly normalising it would make two requests it deliberately kept apart collide.
     *
     * This is correlation, not authentication. The token travels in an extra any app can write,
     * so a match says "this is the result I was waiting for", never "this result is genuine" —
     * only [SignChallengeResult.isVerified] says the latter.
     *
     * @param intent   The result intent to test; a null one never matches, so an unchecked
     *                 `onActivityResult` payload can be passed straight in.
     * @param expected Your own request code. Unlike [intent], this is not untrusted input and is
     *                 declared non-null: a Java caller passing `null` gets a
     *                 [NullPointerException] from Kotlin's parameter check rather than `false`.
     *                 If you have no code to compare, you have nothing to correlate — do not
     *                 reach for `""`, which is the case this function refuses by design.
     */
    fun matchesRequestCode(intent: Intent?, expected: String): Boolean {
        // Two independent reasons a blank can never match, and that is deliberate: the guard
        // here refuses a blank the *caller* supplied, while `presentStringExtra` refuses a
        // blank the *sender* supplied. Either alone closes the trap today, which makes this
        // line redundant on paper — but only as long as the helper keeps mapping blank to
        // absent, and the property is too easy to lose to leave resting on that.
        if (intent == null || expected.isBlank()) return false
        return intent.presentStringExtra(EXTRA_SHARE_REQUEST_CODE) == expected
    }

    // ── Advisory entry validation ─────────────────────────────────────────

    /**
     * Standard Base64 with padding only ever as a suffix. Deliberately not the URL-safe
     * alphabet: the vault encodes keys with [Base64.DEFAULT], and `-`/`_` would decode to
     * different bytes than the sender meant.
     */
    private val BASE64_PATTERN = Regex("[A-Za-z0-9+/]*={0,2}")

    /**
     * Report every reason [entry] looks wrong, one human-readable problem per issue, so a
     * client can tell the user what to fix *before* sending it to a vault that will simply
     * refuse. An empty list means nothing here looks wrong.
     *
     * Checked: a missing or blank `id`; a missing or blank `publicKey`; a `publicKey` that
     * is not valid Base64; a `publicKey` whose bytes do not parse as an RSA public key; an
     * empty `fields` map; and any field key that is blank.
     *
     * **This is advisory and changes nothing.** It is not a gate: [createShareIntent] still
     * encodes an [Entry] this reports problems for, and [decodeEntry] still accepts payloads
     * this would flag (an empty `fields` map and a `publicKey` that is not a real key are both
     * decoded happily). Narrowing what the protocol accepts would need the vault to agree, so
     * it is a decision for a human and not something this function makes on the quiet. Treat a
     * non-empty result as advice to show the developer, never as authority to drop the entry.
     *
     * Nor is an empty result a promise that the vault will accept the entry — this checks the
     * shape of what you hold, not what the far side does with it.
     *
     * Like the decoders, this never throws. It defends against the same `Unsafe` hazard
     * [decodeEntry] exists for: an [Entry] built by Gson can have genuinely `null` properties
     * despite their declared types, and one of the places such an object plausibly ends up is
     * a validity check.
     *
     * @param entry The entry you are about to send. Not modified.
     * @return Problems in a stable order — identity first, then the field map — or an empty
     *         list. The strings are for a developer to read; do not match on them.
     */
    @Suppress("SENSELESS_COMPARISON")
    fun validateEntry(entry: Entry): List<String> {
        val problems = mutableListOf<String>()

        val id: String? = entry.id
        if (id == null || id.isBlank()) problems += "id is missing or blank"

        val publicKey: String? = entry.publicKey
        if (publicKey == null || publicKey.isBlank()) {
            // No cascade: an absent key is one problem, not three. Reporting that it is also
            // not valid Base64 and also not an RSA key would bury the one thing to fix.
            problems += "publicKey is missing or blank"
        } else {
            val keyBytes = base64Bytes(publicKey)
            when {
                keyBytes == null -> problems += "publicKey is not valid Base64"
                !parsesAsRsaPublicKey(keyBytes) -> problems += "publicKey is not an RSA public key"
            }
        }

        val fields: Map<String, TypedField>? = entry.fields
        if (fields == null || fields.isEmpty()) {
            problems += "fields is empty"
        } else {
            fields.keys.forEachIndexed { index, key ->
                if (key == null || key.isBlank()) {
                    problems += "fields entry $index has a missing or blank key"
                }
            }
        }

        return problems
    }

    /**
     * Decode [encoded] as standard Base64, or `null` if it is not standard Base64 at all.
     *
     * `Base64.decode` cannot answer this on its own: Android's decoder *skips* characters
     * outside the alphabet instead of rejecting them, so junk comes back as an empty array
     * and half-junk comes back as bytes the sender never encoded. The alphabet is therefore
     * checked here first. Whitespace is stripped before that check rather than counted
     * against it, because [Base64.DEFAULT] — what the vault encodes keys with — wraps at 76
     * characters, so every real key arrives with newlines in it.
     *
     * What is deliberately *not* checked is padding. Encodings without trailing `=` are
     * still Base64 and Android decodes them, so rejecting one here would report a key
     * [verifySignature] can use as invalid — the opposite of advice. Only a length that
     * leaves one character over is impossible, because Base64 has no one-character group.
     *
     * The alphabet check is the other way round on purpose, and this is where the two
     * functions deliberately disagree: a key with a stray character in it — an invisible one
     * pasted in from somewhere else, say — still verifies, because the decoder skips what it
     * does not recognise and recovers the real characters around it. It is still worth
     * reporting, because the protocol identifies a profile by the public-key *string* and the
     * vault looks it up by equality: a key that works only because a decoder was forgiving is
     * one that will match nothing. So "valid here" implies "usable there" for padding and
     * wrapping, and is deliberately stricter about the alphabet.
     */
    private fun base64Bytes(encoded: String): ByteArray? {
        val compact = encoded.filterNot { it.isWhitespace() }
        // The length rule is redundant today — Android's decoder throws on a leftover
        // character and the catch below turns that into the same answer — but it is stated
        // here rather than left resting on the behaviour of a component this library does
        // not own, and the outcome is asserted either way.
        if (compact.isEmpty() || compact.length % 4 == 1) return null
        if (!BASE64_PATTERN.matches(compact)) return null
        return try {
            // No empty-result guard, unlike `nonEmptyBase64`: there it is load-bearing
            // because junk reaches the decoder, whereas the alphabet check above means every
            // character here carries bits, so a non-empty input yields at least one byte.
            Base64.decode(compact, Base64.DEFAULT)
        } catch (_: Exception) {
            // Reachable despite the checks above: the decoder rejects padding that does not
            // land on a group boundary, `"A==="` among others.
            null
        }
    }

    /**
     * Report whether [keyBytes] is an X.509-encoded RSA public key — the same parse
     * [verifySignature] performs, so that "valid here" means "usable there". Anything the
     * JCE refuses, including a well-formed key of another algorithm, is a `false`.
     */
    private fun parsesAsRsaPublicKey(keyBytes: ByteArray): Boolean = try {
        KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(keyBytes)) != null
    } catch (_: Exception) {
        false
    }

    // ── Typed-field (de)serialization ─────────────────────────────────────

    /**
     * Encode a map of [TypedField]s to the canonical JSON form used on the wire.
     *
     * Use this when building the [EXTRA_FIELDS_JSON] payload to send back to a client app.
     */
    fun encodeFields(fields: Map<String, TypedField>): String = Gson().toJson(fields)

    /**
     * Decode the JSON produced by [encodeFields] back into a typed-field map.
     *
     * Returns an empty map on any parse error so callers do not need to handle nulls.
     *
     * This JSON crosses an IPC boundary from another app, so it is untrusted: it may omit
     * `value` or `type`, or contain a null entry, none of which [encodeFields] would ever
     * produce. Such fields are repaired here rather than handed on — see [repaired].
     */
    fun decodeFields(json: String?): Map<String, TypedField> {
        if (json.isNullOrBlank()) return emptyMap()
        return try {
            val parsed: Map<String, TypedField?> =
                Gson().fromJson(json, FIELDS_TYPE) ?: return emptyMap()
            parsed.entries
                .mapNotNull { (key, field) -> field?.let { key to it.repaired() } }
                .toMap(LinkedHashMap())
        } catch (_: Exception) {
            emptyMap()
        }
    }

    // ── Entry (de)serialization ───────────────────────────────────────────

    /**
     * Decode the JSON carried in [EXTRA_ENTRY_JSON] back into an [Entry].
     *
     * This payload crosses an IPC boundary from another app, so it is untrusted. Gson
     * instantiates [Entry] through `Unsafe` without running the Kotlin constructor, so
     * `id`, `publicKey` and `fields` are all genuinely `null` at runtime when their key is
     * absent from the JSON — `{}` decodes to an [Entry] that NPEs on first use. See
     * [repaired] for why the compiler cannot see this.
     *
     * Returns `null` — never a half-built [Entry] — when the payload is missing, is not a
     * JSON object, carries no `id` or no `publicKey` (or only blank ones), or carries a
     * `fields` member of the wrong shape. The first two are the entry's identity: an entry
     * keyed to an empty public key is not a safe default, it is a profile nobody can ever
     * authenticate against, so it is rejected outright rather than handed on.
     *
     * Note that this is deliberately stricter than its sibling [decodeFields], which
     * repairs a malformed field map to an empty one: a field map is a bag of independent
     * values, whereas a malformed `fields` member means this payload was not written by
     * [createShareIntent] and the whole entry is suspect. It is also stricter than
     * [createShareIntent] is on the way out — that will happily encode an [Entry] whose
     * `id` or `publicKey` is blank, and this will refuse to decode it again.
     *
     * A returned [Entry] is fully populated and safe to dereference: its `fields` map
     * contains no null entries and every [TypedField] in it has a non-null `value` and
     * `type`.
     */
    fun decodeEntry(json: String?): Entry? {
        if (json.isNullOrBlank()) return null
        val parsed = try {
            Gson().fromJson(json, Entry::class.java) ?: return null
        } catch (_: Exception) {
            return null
        }
        return parsed.repaired()
    }

    /**
     * Restore the invariants Gson cannot — see [TypedField.repaired].
     *
     * Returns `null` when the payload carries no usable identity, so that a caller cannot
     * mistake a hollow [Entry] for a real profile.
     */
    @Suppress("SENSELESS_COMPARISON", "USELESS_ELVIS")
    private fun Entry.repaired(): Entry? {
        val safeId: String = id ?: return null
        val safePublicKey: String = publicKey ?: return null
        if (safeId.isBlank() || safePublicKey.isBlank()) return null
        val rawFields: Map<String, TypedField?> = fields ?: emptyMap()
        val safeFields = rawFields.entries
            .mapNotNull { (key, field) -> field?.let { key to it.repaired() } }
            .toMap(LinkedHashMap())
        return Entry(id = safeId, fields = safeFields, publicKey = safePublicKey)
    }

    /**
     * Restore the invariants Gson cannot.
     *
     * Gson instantiates [TypedField] through `Unsafe` without running the Kotlin
     * constructor, so a declared-non-null property whose key is absent from the JSON is
     * left as a genuine `null` at runtime — `type` never receives its
     * [FieldType.STRING] default. Kotlin emits no null check when reading its own
     * non-null property, so the null propagates silently until some caller dereferences
     * it and gets an NPE the type system said was impossible.
     *
     * The elvis operators below look useless to the compiler for exactly that reason.
     * They are not.
     */
    @Suppress("SENSELESS_COMPARISON", "USELESS_ELVIS")
    private fun TypedField.repaired(): TypedField {
        val safeValue: String = value ?: ""
        val safeType: String = type ?: FieldType.STRING
        return if (safeValue === value && safeType === type) this
        else TypedField(value = safeValue, type = safeType)
    }
}