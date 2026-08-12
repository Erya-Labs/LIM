package dev.eryalabs.lim

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.util.Base64
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import java.security.KeyFactory
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

object Utils {

    const val DEFAULT_ENDEAVOR_PACKAGE = "com.github.adaydreamaway.endeavor"

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
     * when you need a result (e.g. the vault's confirmation). For fire-and-forget use
     * [shareEntry] instead.
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
    }

    // ── Nonces ───────────────────────────────────────────────────────────

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
        if (nonce.size < NONCE_SIZE) return false
        var timestamp = 0L
        for (i in 0 until NONCE_TIMESTAMP_BYTES) {
            timestamp = (timestamp shl 8) or (nonce[i].toLong() and 0xFF)
        }
        if (timestamp > now) return false
        val age = now - timestamp
        // A hostile timestamp far enough below `now` overflows the subtraction and wraps
        // negative; that must read as "not fresh", not as a small age.
        if (age < 0) return false
        return age <= maxAgeMillis
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
     */
    fun createSignChallengeIntent(
        context: Context,
        publicKey: String,
        nonce: ByteArray,
        requestCode: String,
        targetPackage: String = DEFAULT_ENDEAVOR_PACKAGE,
    ): Intent = Intent(signChallengeAction(targetPackage)).apply {
        setPackage(targetPackage)
        putExtra(EXTRA_PUBLIC_KEY, publicKey)
        putExtra(EXTRA_NONCE, Base64.encodeToString(nonce, Base64.NO_WRAP))
        putExtra(EXTRA_SHARE_REQUEST_CODE, requestCode)
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

    /** Base64-decode a signature, yielding `null` for anything that cannot be one. */
    private fun decodeSignature(encoded: String?): ByteArray? {
        if (encoded == null) return null
        return try {
            // DEFAULT, not NO_WRAP: the vault encodes with DEFAULT, which wraps at 76
            // characters, and a strict decoder would reject every real signature.
            // Android's Base64 skips characters outside the alphabet rather than rejecting
            // them, so junk can decode to zero bytes without throwing: reject that too.
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
        val signature = decodeSignature(intent.presentStringExtra(EXTRA_SIGNATURE)) ?: return null
        return SignChallengeResult(
            signature = signature,
            algorithm = intent.presentStringExtra(EXTRA_ALGORITHM),
            fields = decodeFields(intent.presentStringExtra(EXTRA_FIELDS_JSON)),
            requestCode = intent.presentStringExtra(EXTRA_SHARE_REQUEST_CODE),
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