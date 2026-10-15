package dev.eryalabs.lim

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.util.Base64
import com.google.gson.Gson
import com.google.gson.Strictness
import com.google.gson.reflect.TypeToken
import com.google.gson.stream.JsonReader
import com.google.gson.stream.JsonToken
import com.google.gson.stream.JsonWriter
import java.io.ByteArrayOutputStream
import java.io.StringReader
import java.io.StringWriter
import java.security.KeyFactory
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Collections

/**
 * The client half of the LIM protocol: intent builders, result parsers, nonce and statement
 * helpers, and the verification this library's security rests on.
 *
 * **A non-null parameter met with `null` from Java is a programming error, and it throws.**
 * Every parameter here that is not declared nullable compiles to a `checkNotNullParameter`
 * intrinsic, and Java honours no Kotlin declaration, so
 * `Utils.INSTANCE.isNonceFresh(intent.getByteArrayExtra(EXTRA_NONCE), 60_000L)` — the natural
 * Java spelling, in which an absent extra is `null` — raises a [NullPointerException] rather
 * than returning `false`. Null-check the extra; do not reach for a fail-closed answer that is
 * not there. The entry points that *do* accept `null`, because they exist to be handed an
 * unchecked IPC payload, are exactly these: the `intent` of [parseShareRequest],
 * [parseQueryRequest], [parseSignChallengeRequest], [parseShareResult], [parseQueryResult],
 * [parseSignChallengeResult], [parseFieldRequirements], [parseAppliedOptionalFields],
 * [describeIntent] and [matchesRequestCode]; the `result` of [checkFieldRequirements]; the text of
 * [decodeFields], [decodeEntry] and [parseSignedStatement]; [isStatementPreImage]'s `bytes`;
 * [createSignChallengeIntent]'s `nonceFormat`, whose `null` is the default and attaches no
 * declaration; and, on the same footing, the `requestCode` of all three result builders
 * ([createShareResultIntent], [createQueryResultIntent], [createSignChallengeResultIntent]) —
 * including the requirements-aware share overload, whose `requestCode` has no default but
 * accepts `null` all the same — plus the last one's `algorithm`, each attaching nothing when it
 * is `null`.
 * `NullArgumentTest` measures that split by calling every published parameter
 * position with `null`, so neither a widening nor a narrowing can happen quietly — it turns that
 * file's rows red. This paragraph is prose beside the check rather than the check itself, so it
 * has to be updated alongside it.
 *
 * **Neither fact is a statement about the wire format.** Which parameters are declared nullable
 * is a property of this library's source; what a peer app can put on an intent is a property of
 * the protocol. Every *value* that arrives over IPC is hostile input and comes back as a
 * fail-closed answer rather than an exception — that is what the decoders, the parsers and the
 * verifiers each promise individually. A `null` reference reaching a non-null parameter is a bug
 * in the calling code on this side of the boundary, which is why it is reported as one instead.
 *
 * **Every function here is stateless and safe to call from any thread, concurrently.** That is not
 * a convenience — an Android library is called from a binder thread while the main thread parses a
 * result, which is where the reference vault's handlers sit, and an integrator needs to be told.
 * It holds because each call builds its own `Gson`, `KeyFactory` and `Signature` rather than
 * sharing one: [java.security.Signature] and [java.security.KeyFactory] carry per-operation state
 * and are not thread-safe, so two concurrent verifications sharing one instance would interleave
 * `initVerify`/`update`/`verify` and could return each other's answers. `ThreadSafetyTest` is the
 * check, and it is primarily a *structural* one — it snapshots the non-constant fields of this
 * whole file, the object and its nested classes and the file facade alike, so hoisting a shared
 * instance for speed fails a test by name instead of becoming an intermittent wrong `true`.
 *
 * **The one limit: this library does not copy what a caller hands it.** A `ByteArray` passed to
 * [verifySignature], [isStatementPreImage] or [encodeRotationStatement] is read in place, so a
 * caller mutating one while another thread is inside the call gets exactly what it asked for. The
 * same goes for an [android.content.Intent]: two threads parsing one that has not been read yet
 * race inside `Bundle.unparcel`, which is Android's object and not this library's.
 * Hand over arguments you are finished with, and read a result intent once before sharing it.
 */
object Utils {

    /**
     * Endeavor's package name — the reference vault, and the `targetPackage` default of the
     * *request* builders here. One request builder has no default: the [createShareIntent]
     * overload that takes `optionalFields` makes its caller pass the package, this constant for
     * Endeavor, for the reason its own KDoc gives. No result builder takes a package or writes
     * one: a result is `setResult`'s payload, delivered to whoever started the activity.
     *
     * It is a default rather than a hardcoding: LIM is a protocol, not an app pairing, so any
     * vault that speaks it can be addressed by passing its own package instead. Note what the
     * value is scoped to besides `setPackage`: both action strings are built from it
     * ([shareDataAction], [signChallengeAction]), so a client and a vault that disagree about the
     * package disagree about the action too and no intent resolves.
     *
     * **Reaching it at all is subject to Android 11+ package visibility**, which is the caller's
     * manifest to declare and not this library's — see [shareEntry], whose `false` cannot
     * distinguish "no vault installed" from "not allowed to look".
     */
    const val DEFAULT_ENDEAVOR_PACKAGE = "com.github.adaydreamaway.endeavor"

    /**
     * The protocol generation this library speaks. Version 1 is the implicit legacy
     * protocol: nothing on the wire ever says "1", absence says it instead. Every outgoing
     * request carries this value under [EXTRA_PROTOCOL_VERSION], and a vault that
     * understands it echoes its own version in the result — which lets a client tell a
     * versioned vault from a legacy one that ignored the extra. That is all the echo can say:
     * which vocabulary a vault speaks, never whether it honoured any particular request, for
     * the reason the next paragraph gives.
     *
     * **The number marks vocabulary; a vault *behaviour* gets its own result-only
     * acknowledgement.** Every builder here writes this library's constant, so the echo proves
     * which version a vault was compiled against, not which of its behaviours it implements — a
     * vault rebuilt on a newer library would claim a behaviour it never wired up. So a feature
     * that changes what a vault *does* is acknowledged by an extra of its own that only the
     * vault's answer carries. Required fields are the first: [EXTRA_APPLIED_OPTIONAL_FIELDS], read
     * by [checkFieldRequirements], and this number stayed 2 when they arrived.
     */
    const val PROTOCOL_VERSION = 2

    /**
     * Carries [PROTOCOL_VERSION] as a decimal string, in both directions: attached to every
     * outgoing request intent, and read back out of result intents into the parsers'
     * `vaultProtocolVersion`. A legacy vault ignores the extra and echoes nothing, so its
     * results parse exactly as before with a `null` version — never a default that fakes a
     * modern vault.
     *
     * What the echo is evidence of is the vocabulary a vault speaks, not that it honoured any
     * particular extra — see [PROTOCOL_VERSION] for the rule, and [EXTRA_APPLIED_OPTIONAL_FIELDS]
     * for the first behaviour acknowledged the other way.
     */
    const val EXTRA_PROTOCOL_VERSION = "extra_protocol_version"

    // ── Intent extras ────────────────────────────────────────────────────

    /**
     * The JSON-encoded [Entry] a client pushes on a share, written by [createShareIntent] and
     * read by [parseShareRequest]. Decode it with [decodeEntry] and nothing else: Gson builds an
     * [Entry] through `Unsafe`, so a raw `fromJson` on this payload yields an object whose
     * declared-non-null properties can be `null`.
     *
     * Its *presence* is also how a vault routes: the share and query flows travel under one
     * action, and an intent carrying this extra is a share — which is why [parseQueryRequest]
     * refuses one that does.
     */
    const val EXTRA_ENTRY_JSON          = "extra_entry_json"

    /**
     * The client-chosen correlation token, carried on every request that takes one and echoed
     * back by the vault in every result. Compare it with [matchesRequestCode] rather than by
     * hand — a blank must never match, and "nothing equals nothing" is the mistake that pairs a
     * client with the answer to somebody else's request.
     *
     * Opaque and free-form: nothing here parses it, and it is compared with exact string
     * equality. It is also one of the four values [describeIntent] prints close to verbatim rather
     * than reducing — and the one this protocol defines no vocabulary for at all, which is why
     * printing it is the judgement call that function records — so do not put personal data in it.
     */
    const val EXTRA_SHARE_REQUEST_CODE  = "extra_share_request_code"

    /**
     * JSON-encoded `Map<String, TypedField>` disclosed by the vault on a successful *query*,
     * written by [createQueryResultIntent] and read by [parseQueryResult].
     *
     * **Deliberately not [EXTRA_FIELDS_JSON].** The two field payloads sit at different points in
     * the protocol and are not interchangeable: reading either from either flow would let an
     * unsigned query answer be presented as a disclosure that came with a signature. No parser
     * here reads this key outside the query flow.
     */
    const val EXTRA_QUERY_RESULT_FIELDS = "extra_query_result_fields"

    /**
     * The Base64 X.509 RSA public key a flow is about — **the account identifier the whole design
     * rests on**, carried in four of this protocol's six flows: it names the profile on a query
     * request and on a sign-challenge request, and the vault answers with it on a share result and
     * a query result. (A share request carries no such extra; the key travels inside its [Entry].)
     *
     * **A sign-challenge result deliberately does not carry it**, and that is the one asymmetry to
     * know: [createSignChallengeResultIntent] never writes this key, [parseSignChallengeResult]
     * never reads it, and [SignChallengeResult] has no property for it. The proof in that flow is
     * the signature, checked against the key the client *already stores*
     * ([SignChallengeResult.isVerified]), so a key echoed back by the sender would be the sender
     * choosing both sides of it.
     *
     * Its meaning depends on direction, and that distinction is the one worth keeping. On a
     * request it is the key the *caller* chose to ask about; on a result it is the key the *vault*
     * holds. Keep the one a result carried — never the one you sent — which is why the
     * request-answering overloads of the result builders take a key explicitly instead of echoing
     * the request's.
     */
    const val EXTRA_PUBLIC_KEY          = "extra_public_key"

    /**
     * The challenge bytes a sign-challenge request carries, Base64-encoded. Written by
     * [createSignChallengeIntent] and decoded by [parseSignChallengeRequest]; mint the value with
     * [generateNonce] so [isNonceFresh] can expire it.
     *
     * **A vault must call [isStatementPreImage] on these bytes before signing them and refuse a
     * match.** This extra is arbitrary caller-supplied input signed with a profile's key, so
     * without that check it is a route to obtaining a signed rotation under a consent dialog that
     * said "prove your identity".
     */
    const val EXTRA_NONCE               = "extra_nonce"

    /**
     * The vault's signature over the request's nonce, Base64-encoded, written by
     * [createSignChallengeResultIntent] and read by [parseSignChallengeResult]. An absent, blank
     * or empty value makes the whole result unparseable — there would be nothing that could ever
     * be authenticated. Check it with [SignChallengeResult.isVerified] against the key and nonce
     * *you* kept; parsing it proves nothing.
     */
    const val EXTRA_SIGNATURE           = "extra_signature"

    /**
     * What the vault says it signed with, optional and **informational only**.
     *
     * Nothing in this library honours it: [verifySignature] hardcodes `SHA256withRSA`, so a
     * declaration of `"MD5withRSA"` changes no outcome anywhere, and neither does a correct one.
     * Taking the verification algorithm from the sender is algorithm confusion, and which
     * algorithms to accept is a standing decision for a human — which is also why this library
     * publishes no algorithm constant to put here.
     */
    const val EXTRA_ALGORITHM           = "extra_algorithm"

    /**
     * JSON-encoded `Map<String, TypedField>` returned by the vault app on a successful
     * sign-challenge. Decode with [decodeFields] after verifying the signature to obtain
     * the profile's field values and their declared datatypes.
     */
    const val EXTRA_FIELDS_JSON = "extra_fields_json"

    /**
     * The fields of a share request's [Entry] that the user may leave blank, written by the
     * [createShareIntent] overload taking `optionalFields` and read by [parseFieldRequirements].
     * **Every declared field not named here is required.**
     *
     * The value is one JSON array of JSON strings — `["phone","nickname"]` — each naming a key of
     * the entry's `fields` map by exact string equality. The builder writes the given names that
     * are fields of the entry as it is sent — a key whose [TypedField] is `null` is not encoded,
     * so it is not one — in entry order and without duplicates, and writes `[]` when none
     * survives; a reader accepts any valid JSON spelling and depends on none of that. Absent,
     * blank, wrong-typed, unreadable or malformed all read as "nothing is optional", and so does
     * `[]` — the two differ only on a [describeIntent] line. Malformed means anything but exactly
     * one flat array of strings and nothing after it, read strictly, with nothing salvaged.
     *
     * It can only relax the requirements of the sender's own sign-up: it adds no field, no type and
     * no value, and it never affects routing. No builder here writes it on a result and nothing
     * here reads it from one — but a vault that answers by handing the request back can still
     * carry it on a result, which is why the acknowledgement has a key of its own,
     * [EXTRA_APPLIED_OPTIONAL_FIELDS].
     */
    const val EXTRA_OPTIONAL_FIELDS = "extra_optional_fields"

    /**
     * A vault's acknowledgement that it applied a sign-up's optional fields, carried on a
     * successful share result only — written by the [createShareResultIntent] overload taking a
     * [FieldRequirements], read by [parseAppliedOptionalFields] and [checkFieldRequirements].
     *
     * The value is the same JSON array of strings as [EXTRA_OPTIONAL_FIELDS], holding exactly the
     * optional set the vault applied — `[]` when nothing was optional, which includes every client
     * that sent no declaration. Its presence says that the vault read the declaration (or saw there
     * was none), would not let the user save while a required field was blank, and dropped blank
     * optional fields — and this library's builder writes it only when the payload beside it
     * bears that out.
     *
     * **Deliberately a different key from the request's.** A vault that answers with
     * `setResult(RESULT_OK, incomingIntent)` echoes [EXTRA_OPTIONAL_FIELDS] back, and that can never
     * read as an acknowledgement. Absent, blank, wrong-typed, unreadable or malformed is no
     * acknowledgement at all — which is what every vault built before this key existed sends.
     */
    const val EXTRA_APPLIED_OPTIONAL_FIELDS = "extra_applied_optional_fields"

    private const val SIGN_ALGORITHM = "SHA256withRSA"
    private const val ACTION_SHARE_DATA    = "ACTION_SHARE_DATA"
    private const val ACTION_SIGN_CHALLENGE = "ACTION_SIGN_CHALLENGE"

    private val FIELDS_TYPE = object : TypeToken<Map<String, TypedField>>() {}.type

    // ── Intent action helpers ────────────────────────────────────────────

    /**
     * Returns the share-data action string scoped to [targetPackage].
     *
     * @param targetPackage Package name of the vault app; defaults to [DEFAULT_ENDEAVOR_PACKAGE].
     *                      The action is this value with a fixed suffix, so a client and a vault
     *                      that disagree about the package resolve nothing. Note that the query
     *                      flow travels under this same action — a query and a share are told
     *                      apart by their payload, not by their action.
     */
    @JvmOverloads
    fun shareDataAction(targetPackage: String = DEFAULT_ENDEAVOR_PACKAGE) =
        "$targetPackage.$ACTION_SHARE_DATA"

    /**
     * Returns the sign-challenge action string scoped to [targetPackage].
     *
     * @param targetPackage Package name of the vault app; defaults to [DEFAULT_ENDEAVOR_PACKAGE].
     *                      Unlike [shareDataAction]'s, this action carries one flow only.
     */
    @JvmOverloads
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
     *
     * **On a vault that implements required fields, every field of [entry] is required.** This
     * overload declares nothing optional, so the user cannot save while any of them is blank. To
     * let them leave some empty, name those with the overload taking `optionalFields` — see
     * [FieldRequirements] and [checkFieldRequirements].
     *
     * See `ClientIntegrationExampleTest` for this flow written end to end the way an integrator
     * writes it — sign-up, then query, then login, against one profile, with the refusal case
     * alongside. It is a test rather than a snippet so it cannot go stale.
     *
     * **`docs/INTEGRATION.md` is the same four moves as prose**, and is the place to start if you
     * are reading this library for the first time: every Kotlin block on that page is lifted
     * verbatim out of a region of a test that runs, held there by `GuideSnippetTest`, so it cannot
     * drift from the library either.
     *
     * **Example**, verbatim from `docs/INTEGRATION.md`'s *Sign-up (share)* section:
     *
     * <!-- example: INTEGRATION.md#signup-request -->
     * ```kotlin
     * // The fields your service needs, each with the type you expect. You supply no values —
     * // the user fills those in the vault's own form. `publicKey` is a slot the vault fills,
     * // so send a placeholder: a blank one is encoded here and then refused on arrival.
     * val entry = Entry(
     *     id = "signup-form",
     *     fields = linkedMapOf(
     *         "name" to TypedField(value = "", type = FieldType.STRING),
     *         "email" to TypedField(value = "", type = FieldType.EMAIL),
     *     ),
     *     publicKey = "no-key-yet",
     * )
     * // Pass `requestCode` **by name**. The positional three-argument call resolves to the
     * // `targetPackage` overload instead, addressing the intent at a package named
     * // "signup-1", and nothing ever answers it.
     * val request = Utils.createShareIntent(context, entry, requestCode = SIGN_UP_REQUEST)
     * // startActivityForResult(request, VAULT_RESULT)
     * ```
     *
     * @param context       **Read by nothing in this function today** — the intent is addressed by
     *                      package rather than by component, so no [Context] is needed to build
     *                      one, and none is retained or put on the intent. It stays in the
     *                      signature because removing it would break every app compiled against
     *                      1.0.0. Pass the [android.app.Activity] you will launch from anyway:
     *                      that is what `startActivityForResult` needs, and passing anything else
     *                      is a sign the call site cannot receive the result.
     * @param entry         The profile to push. Encoded to JSON under [EXTRA_ENTRY_JSON] as given,
     *                      with no validation: see [validateEntry] for what looks wrong with one
     *                      before you send it — advice to show a developer rather than a gate, and
     *                      neither necessary nor sufficient for the vault to accept it — and
     *                      [Entry] for which of its three slots are yours to fill. Not modified.
     * @param targetPackage Package name of the vault app; defaults to [DEFAULT_ENDEAVOR_PACKAGE].
     *
     * **Beware the third positional argument.** This overload and the [requestCode][createShareIntent]
     * one differ only in what their third parameter *means*, and a bare string binds here —
     * `createShareIntent(ctx, entry, "req-1")` addresses the intent to a package named `req-1`
     * and reaches no vault at all, in Kotlin and in Java alike. It compiles, it runs, and
     * nothing comes back. That is not a hypothetical: `ClientIntegrationExampleTest` was first
     * written that way and every scene failed, because the action became
     * `req-1.ACTION_SHARE_DATA`. **Pass `requestCode` by name**, and the compiler picks the
     * overload you meant. Renaming either function would break every app compiled against
     * 1.0.0, so the hazard is documented rather than removed, and
     * `JvmOverloadsTest` pins the resolution so this warning cannot go stale.
     */
    @JvmOverloads
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
     *
     * See `ClientIntegrationExampleTest` for the whole sequence as a test: this call, the vault's
     * answer, and the [matchesRequestCode] check that keeps it from being read as the answer to a
     * different request. `docs/INTEGRATION.md` is the prose walkthrough of the same loop.
     *
     * **On a vault that implements required fields, every field of [entry] is required**, as with
     * the sibling overload: nothing is declared optional here. The overload that adds an
     * `optionalFields` set after [requestCode] is the one that lets the user leave fields blank.
     *
     * **Example**, verbatim from `docs/INTEGRATION.md`'s *Sign-up (share)* section — the same
     * block the sibling overload carries, because it is the call that resolves to **this** one:
     *
     * <!-- example: INTEGRATION.md#signup-request -->
     * ```kotlin
     * // The fields your service needs, each with the type you expect. You supply no values —
     * // the user fills those in the vault's own form. `publicKey` is a slot the vault fills,
     * // so send a placeholder: a blank one is encoded here and then refused on arrival.
     * val entry = Entry(
     *     id = "signup-form",
     *     fields = linkedMapOf(
     *         "name" to TypedField(value = "", type = FieldType.STRING),
     *         "email" to TypedField(value = "", type = FieldType.EMAIL),
     *     ),
     *     publicKey = "no-key-yet",
     * )
     * // Pass `requestCode` **by name**. The positional three-argument call resolves to the
     * // `targetPackage` overload instead, addressing the intent at a package named
     * // "signup-1", and nothing ever answers it.
     * val request = Utils.createShareIntent(context, entry, requestCode = SIGN_UP_REQUEST)
     * // startActivityForResult(request, VAULT_RESULT)
     * ```
     *
     * @param context     As the sibling overload: read by nothing here, kept in the signature, and
     *                    still best spelled as the [Activity][android.app.Activity] you will
     *                    launch from. Nothing is retained.
     * @param entry       The profile to push, encoded as given and unvalidated — see
     *                    [validateEntry], which advises rather than gates. Not modified.
     * @param requestCode Correlation token echoed back in the result intent.
     * @param targetPackage Package name of the vault app; defaults to [DEFAULT_ENDEAVOR_PACKAGE].
     *
     * **This overload is not reachable by three positional arguments.** `createShareIntent(ctx,
     * entry, "req-1")` binds to the `targetPackage` overload above, not to this one, so the
     * string becomes a package name and the intent goes nowhere. **Pass `requestCode` by name.**
     *
     * It is also the one defaulted function in this object that cannot carry `@JvmOverloads`,
     * which is why a Java caller must still spell `targetPackage` out here: the generated
     * three-argument overload would be `(Context, Entry, String)`, byte-for-byte the JVM
     * signature the `targetPackage` overload already occupies, so the annotation is a platform
     * declaration clash and will not compile — verified both with and without the sibling
     * annotated. Dropping either function to resolve it would remove published API, so the arity stays and
     * the hazard is documented.
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
     * Create a sign-up intent that names the fields of [entry] the user may leave blank —
     * **every other declared field is required.**
     *
     * The intent is the request-code overload's, byte for byte — action, package, `CLEAR_TOP`,
     * the entry payload, [requestCode] and the protocol version — plus one extra,
     * [EXTRA_OPTIONAL_FIELDS], carrying the names of [optionalFields] that are fields of [entry]
     * as it is encoded, in entry order and without duplicates. Nothing is validated and nothing
     * throws: a name that is not a field of [entry] is simply not sent, so that field stays
     * required, which is the direction that fails closed. A key whose [TypedField] is `null` —
     * reachable from Java or a Gson-built template — is not encoded, so the vault never sees it
     * and it is not named either.
     *
     * On the far side, a vault that implements required fields reads the declaration with
     * [parseFieldRequirements] and acknowledges what it applied; read the answer with
     * [checkFieldRequirements], and gate on [FieldRequirements.committed]. A vault that predates
     * this ignores the extra: it may let the user skip any field, required ones included, or —
     * like the interim Endeavor build — make them fill in every field, optional ones included.
     * The verdict is how you find out. This needs a vault built on 1.1.0 or later.
     *
     * **Five arguments and no defaults, deliberately.** No call with fewer arguments can resolve
     * here, so every call written against 1.0.0 still means what it meant:
     * `createShareIntent(context, entry, "r")` still binds `targetPackage` (see the sibling
     * overloads), and a four-argument call still reaches the request-code overload however its
     * fourth argument is typed — a string, a literal `null`, or a type the compiler has to infer,
     * such as a mocking library's `any()`. A default on [targetPackage] would have given this
     * overload a four-argument form in Kotlin, and made that last call ambiguous there. Java would
     * have met the same ambiguity, over a literal `null` as well as an inferred argument, only once
     * `@JvmOverloads` published that form to it: a default alone gives Java nothing but the
     * five-argument method. [optionalFields] is a `Set`, so a bare string cannot bind it either.
     *
     * **Example**, verbatim from `docs/INTEGRATION.md`'s *Required and optional fields* section:
     *
     * <!-- example: INTEGRATION.md#signup-optional-request -->
     * ```kotlin
     * // Every field you declare is required unless you name it here. Names match exactly, so
     * // a misspelt name is simply not sent and that field stays required. All five arguments
     * // are needed, the vault's package included: with no defaults, no shorter call can
     * // resolve to this overload, so every call written before it still means what it did.
     * val entry = Entry(
     *     id = "signup-form",
     *     fields = linkedMapOf(
     *         "name" to TypedField(value = "", type = FieldType.STRING),
     *         "email" to TypedField(value = "", type = FieldType.EMAIL),
     *         "phone" to TypedField(value = "", type = FieldType.PHONE),
     *     ),
     *     publicKey = "no-key-yet",
     * )
     * val requirements = FieldRequirements(entry.fields.keys, setOf("phone"))
     * val request = Utils.createShareIntent(
     *     context,
     *     entry,
     *     SIGN_UP_REQUEST,
     *     requirements.optionalFields,
     *     Utils.DEFAULT_ENDEAVOR_PACKAGE,
     * )
     * // startActivityForResult(request, VAULT_RESULT)
     * ```
     *
     * @param context        As the sibling overloads: read by nothing here and kept for the
     *                       shape of the family. Pass the [Activity][android.app.Activity] you
     *                       will launch from. Nothing is retained.
     * @param entry          The profile to push, encoded as given and unvalidated. Its field keys
     *                       — those whose value is not `null`, which are the ones encoded — are
     *                       what [optionalFields] is matched against. Not modified.
     * @param requestCode    Correlation token echoed back in the result intent. Required here,
     *                       because a verdict is only worth reading on an answer you can match.
     * @param optionalFields The field names the user may leave blank — usually
     *                       [FieldRequirements.optionalFields]. Matched by exact string equality;
     *                       unknown names and Java `null` elements are dropped. An empty set
     *                       declares that every field is required, which a vault reads exactly as
     *                       it reads no declaration at all. Not modified.
     * @param targetPackage  Package name of the vault app — [DEFAULT_ENDEAVOR_PACKAGE] for
     *                       Endeavor. Required, with no default, for the reason above.
     */
    fun createShareIntent(
        context: Context,
        entry: Entry,
        requestCode: String,
        optionalFields: Set<String>,
        targetPackage: String,
    ): Intent = createShareIntent(context, entry, requestCode, targetPackage).apply {
        val declared = FieldRequirements(entry.encodedFieldNames(), optionalFields).optionalFields
        putExtra(EXTRA_OPTIONAL_FIELDS, encodeNames(declared))
    }

    /**
     * The field names an [Entry] a caller built puts on the wire, in its own order: the keys whose
     * [TypedField] is not `null`, or none at all when `fields` itself is `null`.
     *
     * Neither `null` is excluded by what the compiler can see. Java honours no nullability, and an
     * [Entry] built by Gson can carry a `null` `fields` (see [decodeEntry]); this is reached on the
     * way *out*, where [validateEntry] takes the same precaution for the same reason. Gson does not
     * encode a `null` map value, so a vault never sees that key, and a declaration naming it would
     * name a field that is not on the wire.
     */
    @Suppress("SENSELESS_COMPARISON")
    private fun Entry.encodedFieldNames(): Collection<String> {
        val map: Map<String, TypedField>? = this.fields
        if (map == null) return emptySet()
        val encoded = ArrayList<String>(map.size)
        for ((name, field) in map) {
            val value: TypedField? = field
            if (value != null) encoded += name
        }
        return encoded
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
     * **Example**, verbatim from `docs/INTEGRATION.md`'s *Before you start: is there a vault?*
     * section, which also shows the `<queries>` element the paragraph above is about:
     *
     * <!-- example: INTEGRATION.md#vault-present -->
     * ```kotlin
     * // A device may have no vault on it at all, and that is the first wall an integration
     * // hits. `shareEntry` dispatches the sign-up and its return value is the answer: `false`
     * // means nothing received the intent, so no consent dialog opened and nothing is coming.
     * fun signUpIfAVaultIsInstalled(context: Context, entry: Entry): Boolean {
     *     if (Utils.shareEntry(context, entry)) return true
     *     // Nothing handled it. Offer to install a vault — but declare the vault in your own
     *     // manifest's `<queries>` element first, or on Android 11+ a `false` here also means
     *     // "this app was not allowed to look", and you would be telling the user to install
     *     // an app they already have.
     *     // promptToInstallAVault()
     *     return false
     * }
     * ```
     *
     * @param context       Used twice, which is why it may not be any old [Context]: once for
     *                      `packageManager` to resolve a vault, once for `startActivity`. This
     *                      intent sets `FLAG_ACTIVITY_NEW_TASK`, so an application context does
     *                      work here — unlike [createShareIntent]'s, which must be launched from
     *                      an [android.app.Activity] to get a result back. Nothing is retained.
     * @param entry         The profile to push, encoded as given and unvalidated — see
     *                      [validateEntry]. Not modified.
     * @param targetPackage Package name of the vault app; defaults to [DEFAULT_ENDEAVOR_PACKAGE].
     *                      This is the package whose visibility your manifest has to declare, per
     *                      the paragraph above.
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
    @JvmOverloads
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
     *
     * See `ClientIntegrationExampleTest` for the sequence this call sits in, written as a test —
     * including the refusal, where a declined query and a disclosure of nothing parse to the same
     * [QueryResult] and only the result code tells them apart. `docs/INTEGRATION.md` covers the
     * same ground as prose, including that refusal.
     *
     * **Example**, verbatim from `docs/INTEGRATION.md`'s *Query* section:
     *
     * <!-- example: INTEGRATION.md#query-request -->
     * ```kotlin
     * // A query asks about one profile, by the key you stored at sign-up. The vault decides
     * // what it discloses. The request code is yours: it is what tells answers apart when
     * // more than one request is in flight.
     * val request = Utils.createQueryIntent(context, accountKey, QUERY_REQUEST)
     * // startActivityForResult(request, VAULT_RESULT)
     * ```
     *
     * @param context       Read by nothing here, as in [createShareIntent], and kept in the
     *                      signature for the same reason. Pass the
     *                      [Activity][android.app.Activity] you will launch from: this intent is
     *                      built for `startActivityForResult` and sets no `NEW_TASK` flag.
     *                      Nothing is retained.
     * @param publicKey     The Base64 public key to look up, written to [EXTRA_PUBLIC_KEY]. This
     *                      is the key *you* already store for the profile; the vault answers with
     *                      the key it holds, and that is the one to keep. Not validated here — a
     *                      key naming no profile comes back as a vault that disclosed nothing.
     * @param requestCode   Correlation token echoed back in the result intent; check it with
     *                      [matchesRequestCode].
     * @param targetPackage Package name of the vault app; defaults to [DEFAULT_ENDEAVOR_PACKAGE].
     *                      A query travels under [shareDataAction], not an action of its own.
     */
    @JvmOverloads
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
     * **Example**, verbatim from `docs/INTEGRATION.md`'s *Login (sign-challenge)* section:
     *
     * <!-- example: INTEGRATION.md#login-request -->
     * ```kotlin
     * // Mint the challenge and keep it. It carries its own timestamp, so there is no
     * // server-side state to expire; declaring the format is what lets a vault read that
     * // timestamp and apply a freshness policy of its own.
     * val nonce = Utils.generateNonce()
     * val request = Utils.createSignChallengeIntent(
     *     context,
     *     storedPublicKey,
     *     nonce,
     *     LOGIN_REQUEST,
     *     nonceFormat = Utils.NONCE_FORMAT_TIMESTAMPED,
     * )
     * // startActivityForResult(request, VAULT_RESULT)
     * ```
     *
     * @param random Source of randomness; injected so tests can pin it. Defaults to a fresh
     *               [SecureRandom] — do not pass a plain `Random`.
     * @param now    Milliseconds since the epoch to stamp into the nonce; injected so tests
     *               can pin the clock.
     */
    @JvmOverloads
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
     * A nonce may reach you from a peer app, so every *value* it can carry is hostile input and
     * comes back as an answer rather than an exception. It fails closed on everything it cannot
     * vouch for: a nonce too short to carry the layout above (including an empty one), a
     * negative [maxAgeMillis], and a timestamp in the future — there is no clock-skew grace,
     * because a nonce you issued yourself cannot legitimately be stamped after your own clock.
     * Trailing bytes beyond the 40 the layout defines are ignored rather than rejected.
     *
     * [nonce] is declared non-null, though, and Java honours no such declaration: a Java caller
     * passing `null` — `intent.getByteArrayExtra(EXTRA_NONCE)` on an absent extra is the way that
     * happens — gets a [NullPointerException] from Kotlin's parameter check rather than `false`,
     * exactly as [verifyRotationStatement] and [verifySignature] do. Null-check the extra; do not
     * rely on a `false` for it. The same holds for [nonceTimestamp].
     *
     * This is a freshness check and nothing more. It says the challenge has not expired; it
     * does not say anyone proved possession of a key — only [verifySignature] does that.
     *
     * **Example**, verbatim from `docs/INTEGRATION.md`'s *Login (sign-challenge)* section —
     * freshness is one clause of four, and the other three are the separate questions:
     *
     * <!-- example: INTEGRATION.md#login-result -->
     * ```kotlin
     * // In onActivityResult — and a function, not four lines inline, because this is the one
     * // handler worth running in your own tests against answers it must refuse. Verify
     * // against the key your account table already holds and the challenge you generated,
     * // never against either one read back out of the result, or the sender gets to choose
     * // both sides of the proof.
     * fun loginSucceeded(
     *     resultCode: Int,
     *     data: Intent?,
     *     storedKey: String,
     *     challenge: ByteArray,
     * ): Boolean {
     *     val result = Utils.parseSignChallengeResult(data)
     *     return resultCode == Activity.RESULT_OK &&
     *         Utils.matchesRequestCode(data, LOGIN_REQUEST) &&
     *         Utils.isNonceFresh(challenge, maxAgeMillis = 60_000L) &&
     *         result?.isVerified(storedKey, challenge) == true
     * }
     * ```
     *
     * @param nonce        The challenge bytes to date, in [generateNonce]'s layout — the
     *                     timestamp is read out of the nonce itself, so nothing has to be stored
     *                     alongside it. Anything shorter than the full 40 bytes is `false`,
     *                     including an empty array; trailing bytes beyond 40 are ignored. A nonce
     *                     that was *not* produced by [generateNonce] has no timestamp to find and
     *                     its first eight bytes are read as one anyway, so this question is only
     *                     meaningful for a nonce you minted.
     * @param maxAgeMillis The window, in milliseconds. Inclusive: an age of exactly this is still
     *                     fresh, one millisecond more is not. A negative value can never be
     *                     satisfied, which is the fail-closed direction.
     * @param now          Milliseconds since the epoch to measure against; injected so tests can
     *                     pin the clock.
     */
    @JvmOverloads
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
     * Trailing bytes beyond the layout are ignored. A nonce reaches a peer from another app, so
     * every *value* it can carry is hostile input and comes back as an answer rather than an
     * exception — with the Java-`null` caveat [isNonceFresh] records, which applies here
     * identically.
     *
     * This is the raw header for a *peer* to apply its own policy to; it deliberately
     * decides nothing. [isNonceFresh] assumes the checker issued the nonce — it allows no
     * clock skew, because your own clock cannot legitimately postdate your own nonce — and
     * that assumption is exactly what a peer on a different device's clock does not get to
     * make. Such a peer needs the timestamp itself, plus its own skew grace and its own
     * freshness window. Only trust the value when the sender declared
     * [NONCE_FORMAT_TIMESTAMPED] under [EXTRA_NONCE_FORMAT]: any 40 bytes have a first
     * eight, and an undeclared nonce's header is just random bytes read as a time.
     *
     * @param nonce The challenge bytes to read the header out of. `null` for anything shorter
     *              than the full 40-byte layout, including an empty array; trailing bytes beyond
     *              it are ignored. The value comes back as signed two's complement, so a nonce
     *              whose first byte has its top bit set yields a negative "time" — which is a
     *              possible value rather than an error, and one more reason to require the
     *              sender's declaration before trusting it.
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
     * See `ClientIntegrationExampleTest` for that order played out as a test — mint the nonce,
     * keep it, verify against it and against the key you already store — along with the replay it
     * refuses and the vault-side refusal of a nonce that is really a statement pre-image.
     * `docs/INTEGRATION.md` walks the same login through as prose.
     *
     * **Example**, verbatim from `docs/INTEGRATION.md`'s *Login (sign-challenge)* section:
     *
     * <!-- example: INTEGRATION.md#login-request -->
     * ```kotlin
     * // Mint the challenge and keep it. It carries its own timestamp, so there is no
     * // server-side state to expire; declaring the format is what lets a vault read that
     * // timestamp and apply a freshness policy of its own.
     * val nonce = Utils.generateNonce()
     * val request = Utils.createSignChallengeIntent(
     *     context,
     *     storedPublicKey,
     *     nonce,
     *     LOGIN_REQUEST,
     *     nonceFormat = Utils.NONCE_FORMAT_TIMESTAMPED,
     * )
     * // startActivityForResult(request, VAULT_RESULT)
     * ```
     *
     * @param context     Read by nothing here, as in [createShareIntent], and kept in the
     *                    signature for the same reason. Pass the [Activity][android.app.Activity]
     *                    you will launch from: this intent is built for `startActivityForResult`
     *                    and sets no `NEW_TASK` flag. Nothing is retained.
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
    @JvmOverloads
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
     *
     * @param statement The rotation to encode. All five of its components go into the bytes, so
     *                  all five are covered by whatever signature is made over them; none is
     *                  validated, normalised or defaulted here, because a verifier reconstructing
     *                  these bytes must get exactly what the signer put in. Not modified.
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
     *
     * @param authorization The authorization to encode. All five components go into the bytes and
     *                      none is validated or normalised, exactly as in
     *                      [rotationStatementBytes]. Not modified.
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
     *
     * @param revocation The revocation to encode. All four components go into the bytes —
     *                   including [Revocation.sequence], which is what [isRevoked] compares and
     *                   therefore must be signed rather than carried alongside. Not modified.
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
     *
     * @param bytes The bytes a device has been asked to sign — in practice
     *              [SignChallengeRequest.nonce], straight off an intent another app sent.
     *              Nullable because this is called on unchecked input and must answer rather than
     *              throw: `null`, empty and anything shorter than the prefix are all `false`.
     *              Read in place and not copied.
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
     * **And it says nothing about whether `newPublicKey` is already one of your accounts —
     * check that yourself, before the swap.** This library holds no account table and cannot.
     * The attack it leaves you otherwise is cheap and needs nothing stolen: an attacker signs up
     * with their own key `K_att`, then signs, perfectly genuinely, a rotation from `K_att` onto
     * the *victim's* public key — which this service already stores, which every other service
     * the victim uses also stores, and which a breach hands out. Every check above passes, the
     * verdict is [StatementVerdict.VALID], and a service that swaps blindly has just written the
     * attacker's account over the victim's row. **Refuse a rotation whose `newPublicKey` already
     * names an account**, exactly as you would refuse a sign-up onto a key you already hold.
     * `MigrationEndToEndTest` pins both the attack and the refusal.
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
    @JvmOverloads
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

    // ── Signed statements: revocation ordering ────────────────────────────

    /**
     * Whether [authorization] has been cancelled by any of [revocations].
     *
     * A [RecoveryAuthorization] never expires, so this ordering *is* the safety of the standing
     * credential: a thief holding a stolen recovery device races the revocation to whichever
     * service it reaches first, and every service has to decide which authorizations are still
     * live from statements a relay delivered in whatever order it happened to. The rule is
     * therefore stated over the statements themselves rather than over arrival time — three
     * conditions, all of which must hold for some revocation in the list:
     *
     * 1. the same [Revocation.subjectPublicKey] as [RecoveryAuthorization.subjectPublicKey];
     * 2. a [Revocation.revokedAuthorizationId] equal to
     *    [RecoveryAuthorization.authorizationId];
     * 3. a **strictly greater** [Revocation.sequence].
     *
     * Both string comparisons are exact — no trimming, no case folding — for the reason
     * [matchesRequestCode] and [verifyRotationStatement] both give: these are opaque handles the
     * signer minted, and normalising one merges two things it deliberately kept apart. Condition 1
     * is what stops a revocation reaching across profiles when an id collides between two of them,
     * which is why it is checked even though condition 2 usually implies it.
     *
     * **Strictly greater, not greater-or-equal**, and the asymmetry is the whole mechanism.
     * Greater is what lets a revoked device be deliberately brought back — revoked at 7,
     * re-authorized by a fresh authorization at 8 — and *not* equal-or-lower is what makes a
     * captured old revocation useless against a newer authorization. Relaxing this to `>=` would
     * quietly kill every re-issued device, which is why the test suite pins the equal case
     * separately from the lower one.
     *
     * **This makes no authenticity claim whatsoever**, exactly as [parseSignChallengeResult] makes
     * none. It is set arithmetic over statements the caller must *already* have verified with
     * [verifyRecoveryAuthorization] and [verifyRevocation]; feeding it unverified statements is
     * letting an attacker choose the answer, since anyone can mint a `Revocation` object and a
     * revocation is only meaningful because the subject's own key signed it.
     *
     * Two consequences of the rule, documented rather than papered over, because both are states a
     * signer can mint and neither can be repaired later:
     *
     * - An authorization at [Long.MAX_VALUE] is **permanently unrevocable**: no revocation can
     *   carry a strictly greater sequence. Mint sequences from a small counter, not from a clock
     *   and never from a saturating one.
     * - An authorization whose [RecoveryAuthorization.authorizationId] is blank is likewise
     *   unrevocable, and that is the safer half of a trap worth naming: a blank id must not match
     *   another blank id, or a revocation that names *nobody* would cancel every such
     *   authorization at once. "Nothing equals nothing" is the same bug [matchesRequestCode]
     *   exists to prevent. A blank [RecoveryAuthorization.subjectPublicKey] needs no such guard —
     *   it is the id that names the target, and an authorization with no subject key cannot have
     *   been verified by [verifyRecoveryAuthorization] in the first place.
     *
     * Never throws. A `null` element in [revocations] — reachable from Java through an unchecked
     * cast, the [validateEntry] precedent — revokes nothing rather than taking the caller down.
     *
     * @param authorization The authorization to ask about. Not modified.
     * @param revocations   Every revocation this service has been shown for any profile; order and
     *                      duplicates are irrelevant to the answer.
     * @return `true` when some revocation cancels it. `false` means only "not cancelled by
     *         anything in this list" — not that the list is complete, since a revocation nobody
     *         has relayed here yet cannot be counted.
     */
    @Suppress("SENSELESS_COMPARISON")
    fun isRevoked(authorization: RecoveryAuthorization, revocations: List<Revocation>): Boolean {
        val id: String? = authorization.authorizationId
        // The blank guard sits on the *authorization* rather than on the revocation because that
        // is where it is total: a blank id here can match nothing, whichever way a revocation
        // spells its own. Guarding only the revocation would leave two blanks matching.
        if (id == null || id.isBlank()) return false
        val subject: String? = authorization.subjectPublicKey
        return revocations.any { revocation ->
            revocation != null &&
                revocation.revokedAuthorizationId == id &&
                revocation.subjectPublicKey == subject &&
                revocation.sequence > authorization.sequence
        }
    }

    /**
     * The authorizations from [authorizations] that [revocations] has not cancelled — [isRevoked]
     * applied as a filter, which is the form a service actually wants when it asks "may this
     * device act?".
     *
     * The result is:
     *
     * - **order-independent** in what survives: shuffling either list cannot change *which*
     *   authorizations come back, because the rule compares statement to statement and never
     *   consults position or arrival time;
     * - **stable** in what it returns: survivors come back in the order they were given, and a
     *   duplicated input authorization comes back duplicated, because this filters rather than
     *   deduplicates. A caller wanting a set should make one;
     * - **idempotent**: feeding the result back in with the same revocations returns it unchanged.
     *
     * A `null` element in either list is dropped rather than returned — handing back a `null`
     * inside a `List<RecoveryAuthorization>` would push the problem one frame up, into a caller
     * Kotlin has told there is nothing to check.
     *
     * **Verify first.** Like [isRevoked], this claims nothing about authenticity: it is arithmetic
     * over statements the caller must already have checked with [verifyRecoveryAuthorization] and
     * [verifyRevocation]. An unverified statement fed in here is an attacker choosing the answer —
     * a forged revocation locks a real device out, and a forged authorization lets a stranger's
     * device look live.
     *
     * **A rotation ends the authorizations that named the old key. Discard them; do not re-file
     * them under the new one.** Both lists are keyed by a subject *key* inside the statements
     * themselves, and [verifyRotationStatement] changes which key identifies the account. An
     * authorization carried across still names the old key, so the only revocation that could
     * ever cancel it is one signed by that old key — which after a migration is the key the user
     * no longer has. That makes it a standing credential nobody can withdraw, and it is how a
     * device revoked *before* the migration comes back alive after it, which is precisely what
     * ordering this way exists to prevent. The recovery plan is re-issued under the new key, by
     * the device that now holds the account.
     *
     * **The revocations, though, keep.** They never go stale — that is why neither they nor
     * [verifyRevocation] carry a window — and holding one costs a row. Dropping them is how a
     * captured authorization envelope becomes live again the day that key names an account a
     * second time, which a rotation back onto it makes possible. Discard the authorizations;
     * keep the revocations for ever.
     *
     * **And the vault's half, which is the only durable one: sign a revocation for every
     * authorization a rotation is about to strand, while the old key is still in hand.**
     * Discarding is a service forgetting locally, and forgetting is not a fact about the world:
     * a service that is later shown the same authorization envelope again — off a relay, by
     * anyone who kept a copy — has nothing to weigh it against and will record it. A revocation
     * is the fact, and only the key the authorization names can sign one, so the moment to do it
     * is *during* the migration. Afterwards nobody can, for ever. `MigrationEndToEndTest` pins
     * every half of this, including that limit.
     *
     * @param authorizations The authorizations this service holds, for one profile or many.
     * @param revocations    Every revocation it has been shown.
     * @return The live subset, in input order. Empty when everything is revoked; never `null`.
     */
    @Suppress("SENSELESS_COMPARISON")
    fun liveAuthorizations(
        authorizations: List<RecoveryAuthorization>,
        revocations: List<Revocation>,
    ): List<RecoveryAuthorization> =
        authorizations.filter { it != null && !isRevoked(it, revocations) }

    // ── Signed statements: the transport envelope ─────────────────────────
    //
    // A statement nobody can transmit is not a protocol. Device A's signed statements have to
    // reach device B and then each installed app, so there is one text form defined here and one
    // parser for it; without that every relay invents its own shape and the vault has to guess.
    //
    // The envelope is deliberately channel-agnostic — one line of text, no transport in it — so
    // it rides a file, a QR code or a clipboard equally well. Which channel the vault actually
    // uses is a human's decision and is recorded as such.

    /**
     * The framing marker every LIM statement envelope begins with.
     *
     * Versioned separately from the statement kinds: this names the *framing*, the kind tag names
     * what is inside it, and either can be revised without the other. A peer sending a framing
     * this library does not know is refused whole by [parseSignedStatement] rather than
     * half-understood.
     */
    const val STATEMENT_ENVELOPE_V1 = "lim.env.v1"

    /**
     * Section separator. A colon appears in neither the standard Base64 alphabet nor any kind
     * tag, so the split is unambiguous and needs no escaping — and a value that somehow contained
     * one would change the section count rather than smuggle itself into the next section.
     */
    private const val ENVELOPE_SEPARATOR = ':'

    /** Framing marker, kind tag, pre-image, signature. Exactly four; anything else is damage. */
    private const val ENVELOPE_SECTIONS = 4

    /**
     * Encode a [RotationStatement] and its signature as one line of text a relay can carry.
     *
     * Layout: [STATEMENT_ENVELOPE_V1], the kind tag, the canonical pre-image
     * ([rotationStatementBytes]) and the signature, colon-separated, with the two binary sections
     * Base64-encoded unwrapped. The pre-image travels verbatim rather than as re-listed fields,
     * which is what makes the envelope provably carry the bytes that were signed.
     *
     * The signature must be non-empty: an empty one encodes to an empty section, which
     * [parseSignedStatement] refuses. That asymmetry is deliberate and is the fail-closed
     * direction — an envelope carrying no signature is not something a peer should be able to
     * hand on and have parsed.
     *
     * See `MigrationEndToEndTest` for the whole flow this line exists for, written as an
     * integrator would write it — a test rather than prose, so the example cannot go stale.
     *
     * @param statement The rotation to carry. Its canonical pre-image travels verbatim, so what a
     *                  verifier reconstructs from the parsed statement is what this line carried.
     *                  Not modified.
     * @param signature The raw signature over [rotationStatementBytes] of [statement]. Nothing
     *                  here checks that it is one — this is an encoder, and the only thing that
     *                  settles it is [verifyRotationStatement] against the key the service
     *                  already stores. Must be non-empty: an empty array encodes to an empty
     *                  section, which [parseSignedStatement] refuses. Read in place, not copied.
     */
    fun encodeRotationStatement(statement: RotationStatement, signature: ByteArray): String =
        envelope(STATEMENT_ROTATE_V1, rotationStatementBytes(statement), signature)

    /**
     * Encode a [RecoveryAuthorization] and its signature, same framing as
     * [encodeRotationStatement] and the same guarantees.
     *
     * @param authorization The authorization to carry; its canonical pre-image travels verbatim.
     *                      Not modified.
     * @param signature     The raw signature over [recoveryAuthorizationBytes] of it, unchecked
     *                      here and required to be non-empty — see the sibling.
     */
    fun encodeRecoveryAuthorization(
        authorization: RecoveryAuthorization,
        signature: ByteArray,
    ): String =
        envelope(STATEMENT_RECOVER_V1, recoveryAuthorizationBytes(authorization), signature)

    /**
     * Encode a [Revocation] and its signature, same framing as [encodeRotationStatement].
     *
     * The kind whose delivery matters most: an authorization is live until a service is shown the
     * revocation that cancels it, so a revocation that cannot be transmitted is one that does not
     * exist.
     *
     * @param revocation The revocation to carry; its canonical pre-image travels verbatim. Not
     *                   modified.
     * @param signature  The raw signature over [revocationBytes] of it, unchecked here and
     *                   required to be non-empty — see [encodeRotationStatement].
     */
    fun encodeRevocation(revocation: Revocation, signature: ByteArray): String =
        envelope(STATEMENT_REVOKE_V1, revocationBytes(revocation), signature)

    /** The three encoders, which differ only in the kind tag and the pre-image they pass in. */
    private fun envelope(kindTag: String, preImage: ByteArray, signature: ByteArray): String =
        STATEMENT_ENVELOPE_V1 + ENVELOPE_SEPARATOR +
            kindTag + ENVELOPE_SEPARATOR +
            Base64.encodeToString(preImage, Base64.NO_WRAP) + ENVELOPE_SEPARATOR +
            Base64.encodeToString(signature, Base64.NO_WRAP)

    /**
     * Read an envelope produced by one of the three encoders back into the statement it carries
     * and the signature over it — the one router for all three kinds.
     *
     * **Parsed is not verified.** A non-null return says the text was well-formed, and nothing
     * more: nobody's key has been consulted and no signature has been checked. Route the result
     * to [verifyRotationStatement], [verifyRecoveryAuthorization] or [verifyRevocation] with the
     * public key the service *already stores* for the profile. [SignedStatement] exposes no
     * success signal of its own precisely so that "it parsed" cannot be mistaken for "it is
     * genuine" — the same separation [parseSignChallengeResult] keeps.
     *
     * This is a trust boundary of the same class as the intent parsers: the text arrives from
     * another device across a relay somebody else controls. It **fails closed and never throws**,
     * returning `null` for a null, empty, blank or truncated input, a framing marker or kind tag
     * it does not recognise, the wrong number of sections, a section that is not standard Base64,
     * and a pre-image whose components do not read back exactly.
     *
     * **The envelope text is not canonical, and must never be used as an identity.** Whitespace
     * inside a Base64 section is stripped (a peer that wraps at 76 characters is a peer this has
     * to read), and Base64 itself is not injective in its last quantum — an unpadded tail and
     * several spellings of the final character decode to the same bytes. So unboundedly many
     * distinct strings parse to the identical statement and signature. Nothing is forged by that:
     * the signature covers the pre-image, not the text. But a service deduplicating relayed
     * statements, or keying an audit log, must do it on the *statement* — `statementId`,
     * `authorizationId`, the subject key — and never on the envelope string, which an attacker
     * can respell at will. For the same reason trailing junk after the last section is `null`
     * only when it is junk the Base64 rules reject; junk that is itself well-formed Base64
     * changes the signature and comes back [StatementVerdict.SIGNATURE_INVALID] instead, which is
     * the same refusal one step later.
     *
     * An unrecognised kind tag is `null` rather than a guess, which is what a future
     * `lim.rotate.v2` from a newer peer gets: refused whole, not half-understood, because a peer
     * that revised the format did so for a reason this version cannot know.
     *
     * Two checks worth naming, because both close a route to reading a *different* statement out
     * of the same signed bytes:
     *
     * - The kind tag in the framing must equal the one **inside** the pre-image. Only the inner
     *   one is signed, so an outer tag that disagreed would be an unsigned claim about what the
     *   signature means — exactly what the kind tag exists to prevent.
     * - The parsed statement is re-encoded and must reproduce the transmitted pre-image byte for
     *   byte. That makes the envelope's central promise structural rather than a property of this
     *   reader: whatever a verifier reconstructs from the returned statement is what the relay
     *   carried, so a signature over one is a signature over the other.
     *
     * See `MigrationEndToEndTest` for the whole flow — device A signing, the envelope crossing, a
     * service verifying against the key it stores and swapping — written as an integrator would
     * write it, and as a test rather than prose so the example cannot go stale.
     *
     * @param text One line of text as produced by [encodeRotationStatement],
     *             [encodeRecoveryAuthorization] or [encodeRevocation]. Surrounding whitespace is
     *             ignored, so a line read from a file still parses.
     * @return The statement and its raw signature, or `null` for anything this version cannot
     *         read back exactly.
     */
    fun parseSignedStatement(text: String?): SignedStatement? {
        if (text == null) return null
        val sections = text.trim().split(ENVELOPE_SEPARATOR)
        if (sections.size != ENVELOPE_SECTIONS) return null
        if (sections[0] != STATEMENT_ENVELOPE_V1) return null
        val preImage = base64Bytes(sections[2]) ?: return null
        val signature = base64Bytes(sections[3]) ?: return null

        val parsed = when (val kindTag = sections[1]) {
            STATEMENT_ROTATE_V1 -> statementComponents(preImage, kindTag, texts = 3, longs = 2)
                ?.let { (texts, longs) ->
                    SignedStatement.Rotate(
                        RotationStatement(texts[0], texts[1], texts[2], longs[0], longs[1]),
                        signature,
                    )
                }

            STATEMENT_RECOVER_V1 -> statementComponents(preImage, kindTag, texts = 3, longs = 2)
                ?.let { (texts, longs) ->
                    SignedStatement.Recover(
                        RecoveryAuthorization(texts[0], texts[1], texts[2], longs[0], longs[1]),
                        signature,
                    )
                }

            STATEMENT_REVOKE_V1 -> statementComponents(preImage, kindTag, texts = 2, longs = 2)
                ?.let { (texts, longs) ->
                    SignedStatement.Revoke(
                        Revocation(texts[0], texts[1], longs[0], longs[1]),
                        signature,
                    )
                }

            else -> null
        } ?: return null

        // The signed bytes, reconstructed from what was parsed, must be the bytes that arrived.
        // Cheap, and it closes the gap a reader alone leaves: a pre-image carrying malformed
        // UTF-8, say, decodes to a `String` with replacement characters in it, which would
        // re-encode to different bytes and therefore verify against a signature nobody made.
        //
        // This check is also *stronger* than three of the ones inside `statementComponents`, and
        // recording that is more useful than leaving it to be rediscovered: with this in place,
        // the domain-prefix guard, the kind-tag comparison and the nothing-left-over rule there
        // are all equivalent mutants — remove any of them and the whole suite still passes,
        // because re-encoding a statement read out of the wrong tag, out of bytes with no prefix,
        // or out of bytes with a tail on them cannot reproduce what arrived. They are kept for
        // the reason `isUsablePublicKey`'s blank guard is: `statementComponents` states its own
        // contract, and a contract that holds only because its one caller happens to re-check it
        // is one a second caller would break. Verified by planting each: none is killed.
        val reEncoded = when (parsed) {
            is SignedStatement.Rotate -> rotationStatementBytes(parsed.statement)
            is SignedStatement.Recover -> recoveryAuthorizationBytes(parsed.authorization)
            is SignedStatement.Revoke -> revocationBytes(parsed.revocation)
        }
        return if (reEncoded.contentEquals(preImage)) parsed else null
    }

    /**
     * Read a canonical pre-image back into its components — the inverse of the encoder that
     * [rotationStatementBytes] and its siblings share, and the reason that encoder
     * length-prefixes the layout rather than delimiting it.
     *
     * Total and never throws, because every byte of [preImage] came off a relay: a length prefix
     * claiming more bytes than are present, a truncated fixed-width field, a kind tag that is not
     * the expected one and anything left over after the last component are all `null`.
     *
     * @return the [texts] text components and the [longs] 64-bit components, in order, or `null`
     *         if the bytes are not exactly that.
     */
    private fun statementComponents(
        preImage: ByteArray,
        kindTag: String,
        texts: Int,
        longs: Int,
    ): Pair<List<String>, List<Long>>? {
        if (!isStatementPreImage(preImage)) return null
        var offset = STATEMENT_DOMAIN_BYTES.size

        fun readBigEndian(width: Int): Long? {
            if (preImage.size - offset < width) return null
            var value = 0L
            repeat(width) {
                value = (value shl 8) or (preImage[offset].toLong() and 0xFF)
                offset++
            }
            return value
        }

        fun readText(): String? {
            // Unsigned, so a length whose top bit is set is a length that does not fit rather
            // than a negative one that would index backwards.
            val length = readBigEndian(COMPONENT_LENGTH_BYTES) ?: return null
            if (length > preImage.size - offset) return null
            val text = String(preImage, offset, length.toInt(), Charsets.UTF_8)
            offset += length.toInt()
            return text
        }

        if (readText() != kindTag) return null
        val textValues = ArrayList<String>(texts)
        repeat(texts) { textValues += readText() ?: return null }
        val longValues = ArrayList<Long>(longs)
        repeat(longs) { longValues += readBigEndian(STATEMENT_LONG_BYTES) ?: return null }
        if (offset != preImage.size) return null
        return textValues to longValues
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
     *
     * **Example**, verbatim from `docs/INTEGRATION.md`'s *Rules you must not break* section —
     * the rule being that a parse is not an authentication:
     *
     * <!-- example: INTEGRATION.md#rules-not-authenticated -->
     * ```kotlin
     * // Parsing says the bytes were well formed. It says nothing about who made them:
     * // anything on the device can put a signature-shaped extra in an intent, and it parses
     * // exactly as well as a genuine answer does. `isVerified`, against your own stored key
     * // and your own nonce, is the only success signal this library offers.
     * fun authenticated(data: Intent?, storedKey: String, challenge: ByteArray): Boolean =
     *     Utils.parseSignChallengeResult(data)?.isVerified(storedKey, challenge) == true
     * ```
     *
     * @param intent The result intent from `onActivityResult`, or `null`. Nullable because this
     *               is a trust boundary: the payload arrives unchecked from another app, so an
     *               absent one is an answer rather than a precondition and every *value* on it is
     *               hostile input. Read, never retained. Read it once before sharing it across
     *               threads — see this object's KDoc for why.
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
     *
     * **Example**, verbatim from `docs/INTEGRATION.md`'s *Query* section:
     *
     * <!-- example: INTEGRATION.md#query-result -->
     * ```kotlin
     * // In onActivityResult. Check the correlation first — this answer may belong to a
     * // different request you still have outstanding.
     * val mine = Utils.matchesRequestCode(data, QUERY_REQUEST)
     * val disclosure =
     *     if (mine && resultCode == Activity.RESULT_OK) Utils.parseQueryResult(data) else null
     * val email = disclosure?.fields?.get("email")?.value
     * // A disclosure is not a login. Nothing in a query answer is signed, so this says "the
     * // vault told us this", never "the holder of the key is here".
     * ```
     *
     * @param intent The result intent from `onActivityResult`, or `null` — nullable for the
     *               reason [parseSignChallengeResult]'s is, and with the same contract: an
     *               unchecked IPC payload goes straight in. Read, never retained. A non-null
     *               return says the vault answered; whether it answered *your* query is
     *               [matchesRequestCode]'s question, and nothing in a query result is signed.
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
     *
     * [EXTRA_APPLIED_OPTIONAL_FIELDS] is not read here either, so a result parses to the same
     * [ShareResult] with or without a vault's acknowledgement. If you declared optional fields,
     * read the acknowledgement with [checkFieldRequirements] and keep
     * [FieldRequirements.committed] of the fields rather than the fields as they came.
     *
     * **Example**, verbatim from `docs/INTEGRATION.md`'s *Sign-up (share)* section:
     *
     * <!-- example: INTEGRATION.md#signup-result -->
     * ```kotlin
     * // In onActivityResult, once `resultCode` is RESULT_OK.
     * val result = Utils.parseShareResult(data)
     * // The handle to keep is the key the *result* carried. The vault mints the keypair, so
     * // whatever you put in the slot on the way out was never an identifier.
     * val accountKey = result?.publicKey
     * ```
     *
     * @param intent The result intent from `onActivityResult`, or `null` — nullable for the
     *               reason [parseSignChallengeResult]'s is, and read rather than retained. The
     *               value to keep off a non-null return is [ShareResult.publicKey]: that is the
     *               key the vault minted, and the handle this profile is queried and
     *               authenticated by from now on.
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

    /**
     * Read the optional set a vault says it applied to a sign-up, from
     * [EXTRA_APPLIED_OPTIONAL_FIELDS] — or `null` when the answer carries no acknowledgement.
     *
     * `null` is every vault that predates required fields, every one answering with the builder
     * that writes none, and every one answering with the requirements-aware
     * [createShareResultIntent] over a payload that does not satisfy the requirements it was
     * given — a required field missing or blank, or a blank value left in — which that builder
     * answers with no acknowledgement rather than a false one. So a vault that did read your
     * declaration can still give `null`, and the answer cannot tell you which of the three it was.
     * An absent, blank, wrong-typed, unreadable or malformed extra reads the same way, under the
     * strict reading [EXTRA_OPTIONAL_FIELDS] describes. An empty set is different and means
     * "acknowledged, nothing was optional".
     *
     * Most callers want [checkFieldRequirements], which compares this with what you declared and
     * with what actually arrived. This is the raw reading, for a diagnostic or a test.
     *
     * **Example**, verbatim from `docs/INTEGRATION.md`'s *Testing your integration without a
     * vault* section:
     *
     * <!-- example: INTEGRATION.md#testing-optional-fields -->
     * ```kotlin
     * // A vault that implements required fields reads your declaration off the request, stores
     * // what the user filled in, and acknowledges the declaration only when what it stored
     * // satisfies it. Build that answer and your handler meets the verdict it will really get:
     * // here the user filled in both required fields and left the optional "phone" blank.
     * val declared = Utils.parseFieldRequirements(request)!!
     * val answer = Utils.createShareResultIntent(
     *     FAKE_PUBLIC_KEY,
     *     linkedMapOf(
     *         "name" to TypedField(value = "Ada", type = FieldType.STRING),
     *         "email" to TypedField(value = FAKE_EMAIL, type = FieldType.EMAIL),
     *     ),
     *     SIGN_UP_REQUEST,
     *     declared,
     * )
     * val verdict = Utils.checkFieldRequirements(requirements, answer)
     * // The optional set the vault says it applied. `null` means the answer acknowledges
     * // nothing: a vault older than this release, one answering through the builder that
     * // writes none, or one whose payload did not satisfy your declaration, with a required
     * // field missing or a blank value left in.
     * val applied = Utils.parseAppliedOptionalFields(answer)
     * ```
     *
     * @param intent The result intent from `onActivityResult`, or `null` — nullable for the reason
     *               [parseShareResult]'s is. Read, never retained.
     * @return The names, de-duplicated and in the order they were sent, as a read-only set; or
     *         `null` for no acknowledgement.
     */
    fun parseAppliedOptionalFields(intent: Intent?): Set<String>? {
        if (intent == null) return null
        val names = decodeNames(intent.presentStringExtra(EXTRA_APPLIED_OPTIONAL_FIELDS)) ?: return null
        return Collections.unmodifiableSet(LinkedHashSet(names))
    }

    /**
     * Read a sign-up's answer against the requirements you declared: did the vault honour your
     * optional fields, and did every required field arrive?
     *
     * It reads the result's fields exactly as [parseShareResult] does and computes, with no trust
     * in the vault, whether anything required is missing ([FieldRequirements.missingRequired]);
     * then it reads the acknowledgement ([parseAppliedOptionalFields]):
     *
     * - no acknowledgement — [FieldRequirementsVerdict.NOT_ACKNOWLEDGED] when nothing required is
     *   missing, [FieldRequirementsVerdict.INCOMPLETE] when something is;
     * - an acknowledgement over a missing required field — [FieldRequirementsVerdict.VIOLATED];
     * - an acknowledgement of exactly [FieldRequirements.optionalFields], compared as sets —
     *   [FieldRequirementsVerdict.HONOURED];
     * - any other acknowledged set — [FieldRequirementsVerdict.MISMATCHED].
     *
     * So the verdict splits exactly on whether the data is complete:
     * `requirements.committed(result.fields) != null` holds for `HONOURED`, `MISMATCHED` and
     * `NOT_ACKNOWLEDGED` and for nothing else, and it is the data — never the verdict, and never
     * the protocol version — to gate an account on. A refusal (`RESULT_CANCELED`) carries no
     * fields, so it reads as `INCOMPLETE`, or `NOT_ACKNOWLEDGED` when nothing was required:
     * branch on the result code first, as for every flow.
     *
     * Named "check" and not "verify" on purpose: in this library *verify* means cryptography, and
     * nothing in a share result is signed. The acknowledgement is exactly as trustworthy as the
     * vault you addressed.
     *
     * **Sign-up answers only.** It reads the sign-up fields key, so a *query* answer — whose
     * fields travel under [EXTRA_QUERY_RESULT_FIELDS] — reaches it as an answer carrying no
     * fields: a complete disclosure reads as [FieldRequirementsVerdict.INCOMPLETE] whenever
     * anything is required, and as [FieldRequirementsVerdict.NOT_ACKNOWLEDGED] when nothing is.
     * For a query, call [FieldRequirements.missingRequired] or [FieldRequirements.committed]
     * directly over [QueryResult.fields] instead.
     *
     * Total: no answer a vault can send makes this throw.
     *
     * **Example**, verbatim from `docs/INTEGRATION.md`'s *Required and optional fields* section:
     *
     * <!-- example: INTEGRATION.md#signup-optional-result -->
     * ```kotlin
     * // In onActivityResult, once `resultCode` is RESULT_OK and the request code matches.
     * fun onSignUpAnswer(data: Intent?) {
     *     val result = Utils.parseShareResult(data) ?: return
     *     // Keep the key whatever follows: the profile now exists in the vault, bound to you.
     *     val accountKey = result.publicKey ?: return
     *     // Gate on the data, never on a version number. `committed` is null exactly when a
     *     // required field is missing or blank. It drops a blank optional field too, whether
     *     // the vault left it out or, as an older vault may, sent it as an empty value.
     *     val profile = requirements.committed(result.fields)
     *     when (Utils.checkFieldRequirements(requirements, data)) {
     *         FieldRequirementsVerdict.HONOURED,
     *         FieldRequirementsVerdict.MISMATCHED,
     *         FieldRequirementsVerdict.NOT_ACKNOWLEDGED -> createAccount(accountKey, profile!!)
     *         FieldRequirementsVerdict.INCOMPLETE ->
     *             accountIncomplete(accountKey, requirements.missingRequired(result.fields))
     *         else -> reportVault(accountKey) // VIOLATED, and any verdict a later release adds
     *     }
     * }
     * ```
     *
     * @param requirements What you declared when you sent the sign-up — the same object whose
     *                     [FieldRequirements.optionalFields] you passed to [createShareIntent].
     * @param result       The result intent from `onActivityResult`, or `null`, which reads as an
     *                     answer carrying no fields and no acknowledgement. Read, never retained.
     */
    fun checkFieldRequirements(
        requirements: FieldRequirements,
        result: Intent?,
    ): FieldRequirementsVerdict {
        val fields = decodeFields(result?.presentStringExtra(EXTRA_FIELDS_JSON))
        val missing = requirements.missingRequired(fields)
        val applied = parseAppliedOptionalFields(result)
        return when {
            applied == null ->
                if (missing.isEmpty()) {
                    FieldRequirementsVerdict.NOT_ACKNOWLEDGED
                } else {
                    FieldRequirementsVerdict.INCOMPLETE
                }

            missing.isNotEmpty() -> FieldRequirementsVerdict.VIOLATED
            applied == requirements.optionalFields -> FieldRequirementsVerdict.HONOURED
            else -> FieldRequirementsVerdict.MISMATCHED
        }
    }

    // ── Result intents (the vault's side) ────────────────────────────────
    //
    // The parsers above pin what a result *means* arriving at a client; the four builders here
    // pin what one *looks like* leaving a vault. Until now this library wrote six of the ten
    // extras the protocol defines and only read the other four, so the result half of the wire
    // format existed here as four parsers' expectations and nothing else — every vault
    // hand-assembled its result intents, and the reference vault grew its own builder to do it.
    //
    // No new action and no new constant: every literal below is declared above and frozen by
    // `IntentBuilderTest`. One builder writes a key no 1.0.0 builder did —
    // [EXTRA_APPLIED_OPTIONAL_FIELDS], the requirements-aware share overload's acknowledgement, and
    // the first vault behaviour this protocol acknowledges with an extra of its own rather than
    // with the version number. Three rules are shared, and each is something a hand-written
    // `putExtra` line gets wrong eventually:
    //
    // 1. **No action and no package.** A result is `setResult`'s payload, delivered to whoever
    //    started the activity; both halves of this protocol work off extras alone and no parser
    //    here reads the action (see [describeIntent]), so writing one would be new wire surface
    //    for no reader.
    // 2. **Blank is omitted, not written.** [presentStringExtra] maps blank to absent, so a
    //    builder that wrote `""` would mint an intent its own parser disagrees with. Omitting
    //    means not calling `putExtra` at all — `putExtra(key, null as String?)` stores a null and
    //    leaves `hasExtra` returning `true`, which is a present extra by every other measure.
    // 3. **The version echo is unconditional**, and it is the point of these functions.
    //    [EXTRA_PROTOCOL_VERSION] in a result is what lets a client tell a versioned vault from a
    //    legacy one; a vault that forgets the echo is read as a legacy vault, with nothing
    //    anywhere to fail. A vault that uses these cannot forget it. What the echo names is the
    //    vocabulary, never whether a vault honoured a request — see [PROTOCOL_VERSION] for why a
    //    behaviour gets an acknowledgement of its own.

    /**
     * Write [value] under [key], or nothing at all when it is absent or blank — rule 2 above.
     *
     * Not `putExtra(key, value)` with a nullable argument: that overload resolves to
     * `putExtra(String, String?)` and stores the null, and the extra is then *present* for
     * `hasExtra` while reading `null` for `getStringExtra`. Blank goes the same way as null
     * because every parser in this library already treats the two alike.
     */
    private fun Intent.putPresentExtra(key: String, value: String?) {
        if (!value.isNullOrBlank()) putExtra(key, value)
    }

    /**
     * Build the result intent a vault returns from the share flow — the acknowledgement
     * [parseShareResult] reads.
     *
     * Hand it to `setResult(Activity.RESULT_OK, …)`. It carries no action and no package by
     * design (rule 1 above), and [EXTRA_PROTOCOL_VERSION] always (rule 3).
     *
     * @param publicKey   The key the profile was stored under, written to [EXTRA_PUBLIC_KEY]. A
     *                    blank one is omitted rather than written (rule 2), which leaves a result
     *                    whose only identity is its field payload — build it with a real key.
     * @param fields      The stored fields, encoded with [encodeFields] under
     *                    [EXTRA_FIELDS_JSON] — the share flow's key, *not*
     *                    [EXTRA_QUERY_RESULT_FIELDS]. Always written, even for an empty map:
     *                    `"{}"` reads back as an empty map, and "nothing disclosed" has to stay
     *                    distinguishable from "the vault did not answer", which is the rule
     *                    [parseShareResult] already states from its side.
     * @param requestCode The correlation token the request carried, echoed under
     *                    [EXTRA_SHARE_REQUEST_CODE] so a client can run
     *                    [matchesRequestCode] against it. `null` — the default — and blank both
     *                    attach nothing, which is the legacy shape of an untagged share.
     */
    @JvmOverloads
    fun createShareResultIntent(
        publicKey: String,
        fields: Map<String, TypedField> = emptyMap(),
        requestCode: String? = null,
    ): Intent = Intent().apply {
        putPresentExtra(EXTRA_PUBLIC_KEY, publicKey)
        putExtra(EXTRA_FIELDS_JSON, encodeFields(fields))
        putPresentExtra(EXTRA_SHARE_REQUEST_CODE, requestCode)
        putExtra(EXTRA_PROTOCOL_VERSION, PROTOCOL_VERSION.toString())
    }

    /**
     * Build a sign-up's result the way a vault implementing required fields answers — the
     * three-argument builder's intent, plus the acknowledgement [EXTRA_APPLIED_OPTIONAL_FIELDS]
     * **when, and only when, [fields] satisfies [requirements]**.
     *
     * The four extras of the sibling are written exactly as it writes them, with [fields] as
     * given. The acknowledgement then names [FieldRequirements.optionalFields] — `[]` when
     * nothing was optional — and it is written only if [FieldRequirements.isSatisfiedBy] is true
     * of the payload: every required field non-blank, and no blank value anywhere in it. On a
     * payload that falls short it is **omitted rather than thrown**, so a vault never crashes in
     * front of a waiting client and never claims what its own answer contradicts; the client then
     * reads `NOT_ACKNOWLEDGED` or `INCOMPLETE` instead of a false `HONOURED`.
     *
     * **[requirements] must come from the declared schema, never from the answer.** Use what
     * [parseFieldRequirements] returned for the request, or the vault's own copy of it taken when
     * the form was opened. Rebuilt from the keys about to be sent, the check above would pass by
     * construction and the acknowledgement would mean nothing. Persist
     * [FieldRequirements.committed] of the user's draft and pass that same map here: it drops blank
     * optional fields, which is what the acknowledgement promises.
     *
     * Every parameter is explicit, so this adds no `$default` and no overload a three-argument call
     * could resolve to. A refusal is still `setResult(Activity.RESULT_CANCELED, …)` with no
     * acknowledgement, exactly as before.
     *
     * **Example**, verbatim from `docs/INTEGRATION.md`'s *Testing your integration without a
     * vault* section — a client's test building the answer a vault sends:
     *
     * <!-- example: INTEGRATION.md#testing-optional-fields -->
     * ```kotlin
     * // A vault that implements required fields reads your declaration off the request, stores
     * // what the user filled in, and acknowledges the declaration only when what it stored
     * // satisfies it. Build that answer and your handler meets the verdict it will really get:
     * // here the user filled in both required fields and left the optional "phone" blank.
     * val declared = Utils.parseFieldRequirements(request)!!
     * val answer = Utils.createShareResultIntent(
     *     FAKE_PUBLIC_KEY,
     *     linkedMapOf(
     *         "name" to TypedField(value = "Ada", type = FieldType.STRING),
     *         "email" to TypedField(value = FAKE_EMAIL, type = FieldType.EMAIL),
     *     ),
     *     SIGN_UP_REQUEST,
     *     declared,
     * )
     * val verdict = Utils.checkFieldRequirements(requirements, answer)
     * // The optional set the vault says it applied. `null` means the answer acknowledges
     * // nothing: a vault older than this release, one answering through the builder that
     * // writes none, or one whose payload did not satisfy your declaration, with a required
     * // field missing or a blank value left in.
     * val applied = Utils.parseAppliedOptionalFields(answer)
     * ```
     *
     * @param publicKey    The key the profile was stored under, written to [EXTRA_PUBLIC_KEY]; a
     *                     blank one is omitted (rule 2).
     * @param fields       What the vault stored — [FieldRequirements.committed] of the user's draft
     *                     — encoded with [encodeFields] under [EXTRA_FIELDS_JSON] and always
     *                     written, `"{}"` included: a profile that is a key and nothing else is a
     *                     legitimate answer when every field was optional and left blank.
     * @param requestCode  The correlation token the request carried, echoed under
     *                     [EXTRA_SHARE_REQUEST_CODE]. `null` or blank attaches nothing.
     * @param requirements The requirements the request declared, as [parseFieldRequirements] read
     *                     them. Read, never retained.
     */
    fun createShareResultIntent(
        publicKey: String,
        fields: Map<String, TypedField>,
        requestCode: String?,
        requirements: FieldRequirements,
    ): Intent = createShareResultIntent(publicKey, fields, requestCode).apply {
        if (requirements.isSatisfiedBy(fields)) {
            putExtra(EXTRA_APPLIED_OPTIONAL_FIELDS, encodeNames(requirements.optionalFields))
        }
    }

    /**
     * Build the result intent a vault returns from the query flow — the disclosure
     * [parseQueryResult] reads.
     *
     * Identical to [createShareResultIntent] in every parameter and in every extra **but one**:
     * the field payload goes under [EXTRA_QUERY_RESULT_FIELDS], not [EXTRA_FIELDS_JSON]. The two
     * keys are separate points in the protocol and are deliberately not interchangeable — reading
     * either from either flow would let a query answer be presented as a signed disclosure — and
     * choosing between them by hand is the one mistake this pair of functions exists to remove.
     * `ResultParsingTest` pins the separation on the parser side; `ResultBuilderTest` pins it here.
     *
     * A query is a disclosure and nothing in it is signed. Use [createSignChallengeResultIntent]
     * when the client asked for proof that the holder of the key is present.
     *
     * @param publicKey   The queried profile's key, written to [EXTRA_PUBLIC_KEY]; blank is
     *                    omitted (rule 2).
     * @param fields      The disclosed fields, encoded with [encodeFields] under
     *                    [EXTRA_QUERY_RESULT_FIELDS]. Always written, even for an empty map: a
     *                    vault answering "nothing disclosed" must not be mistaken for one that
     *                    did not answer. A *refusal* is `setResult(Activity.RESULT_CANCELED, …)`
     *                    — the result code, not the payload, is what distinguishes it.
     * @param requestCode Echoed under [EXTRA_SHARE_REQUEST_CODE]; `null` or blank attaches
     *                    nothing.
     */
    @JvmOverloads
    fun createQueryResultIntent(
        publicKey: String,
        fields: Map<String, TypedField> = emptyMap(),
        requestCode: String? = null,
    ): Intent = Intent().apply {
        putPresentExtra(EXTRA_PUBLIC_KEY, publicKey)
        putExtra(EXTRA_QUERY_RESULT_FIELDS, encodeFields(fields))
        putPresentExtra(EXTRA_SHARE_REQUEST_CODE, requestCode)
        putExtra(EXTRA_PROTOCOL_VERSION, PROTOCOL_VERSION.toString())
    }

    /**
     * Build the result intent a vault returns from the sign-challenge flow — the proof
     * [parseSignChallengeResult] reads and [SignChallengeResult.isVerified] authenticates.
     *
     * [signature] must be a real `SHA256withRSA` signature over the nonce the request carried,
     * made with the private key paired to the public key the client already stores. Nothing here
     * checks that: this function writes what the vault says, and only the client's own
     * verification decides whether it is true.
     *
     * **An empty byte array is not a signature.** It Base64-encodes to nothing, reads back as a
     * blank extra, and [parseSignChallengeResult] refuses the whole intent — a signature over
     * zero bytes could never authenticate anything, so there is no result worth handing back.
     * That is the single case in which these builders produce an envelope their own parser
     * rejects, and it is pinned as such rather than papered over.
     *
     * @param signature   Raw signature bytes, written to [EXTRA_SIGNATURE] as `Base64.DEFAULT` —
     *                    which wraps at 76 characters, and is what the parser documents arriving.
     * @param fields      The profile's fields, encoded with [encodeFields] under
     *                    [EXTRA_FIELDS_JSON] — the same key the share result uses, and the
     *                    sign-challenge flow's own. Always written, even for an empty map; a
     *                    garbled payload costs the client the disclosure but not the proof, which
     *                    stands on its own.
     * @param requestCode Echoed under [EXTRA_SHARE_REQUEST_CODE]; `null` or blank attaches
     *                    nothing.
     * @param algorithm   What the vault signed with, written to [EXTRA_ALGORITHM] when non-null
     *                    and non-blank — rule 2 again, since a blank one reads as undeclared.
     *                    **Informational, and never honoured by anything in this library.**
     *                    [verifySignature] hardcodes `SHA256withRSA` and a client that trusted a
     *                    peer-supplied algorithm name would be taking the verification algorithm
     *                    from the sender — an algorithm-confusion surface, and the allow-list
     *                    question is a standing decision for a human rather than something this
     *                    library settles. So a declaration of `"MD5withRSA"` changes no
     *                    verification outcome anywhere, and neither does a correct one: declare it
     *                    for a reader's benefit, not for a verifier's. This library publishes no
     *                    algorithm constant for the same reason.
     */
    @JvmOverloads
    fun createSignChallengeResultIntent(
        signature: ByteArray,
        fields: Map<String, TypedField> = emptyMap(),
        requestCode: String? = null,
        algorithm: String? = null,
    ): Intent = Intent().apply {
        putExtra(EXTRA_SIGNATURE, Base64.encodeToString(signature, Base64.DEFAULT))
        putExtra(EXTRA_FIELDS_JSON, encodeFields(fields))
        putPresentExtra(EXTRA_SHARE_REQUEST_CODE, requestCode)
        putPresentExtra(EXTRA_ALGORITHM, algorithm)
        putExtra(EXTRA_PROTOCOL_VERSION, PROTOCOL_VERSION.toString())
    }

    // ── Answering a parsed request ───────────────────────────────────────
    //
    // The four builders above take a request code as a string, so a vault that parsed a request
    // with [parseShareRequest] and friends still carries the correlation token across to the
    // result by hand — and that token is the one extra which must survive both a refusal and an
    // answer. [matchesRequestCode] already names what a dropped line costs: "the accident is not
    // a crash — it is acting on a disclosure meant for a different request."
    //
    // The requirements-aware share builder has no overload here: a vault answering through it
    // passes [ShareRequest.requestCode] itself, beside the requirements it read off the request.
    //
    // **The request is read, never retained.** The only value these overloads take off a request
    // is the correlation token. Not its public key, not its entry, not its field names — those
    // stay explicit parameters, and the reason is the whole point of the rule rather than an
    // ergonomic preference. A query request's `publicKey` is the key the *caller* chose to ask
    // about; echoing it automatically would let a caller pick the identifier that appears in its
    // own answer, and the key a result must name is the one the *vault* holds. The reference
    // vault reached the same rule independently and wrote it down, which is the strongest
    // argument available that it is the right default to publish.
    //
    // Each delegates to its sibling above, so there is exactly one place that decides which
    // extras a result carries and no second wire format to drift.

    /**
     * Answer a parsed [ShareRequest] — [createShareResultIntent] with the correlation token
     * carried across for you.
     *
     * **[request] is read, never retained: the only value taken off it is the correlation
     * token.** Not its entry, not that entry's public key, and not its field names. What the
     * vault acknowledges is what the vault stored, so [publicKey] and [fields] stay explicit —
     * echoing the request's own contents would let the client decide what its answer says.
     *
     * `ClientIntegrationExampleTest` is the runnable example, and it shows both halves: its
     * fixture vault answers the sign-up scene with this function. `docs/INTEGRATION.md` is the
     * client-side half of the same scene as prose.
     *
     * @param request   The request this result answers, as [parseShareRequest] returned it. Only
     *                  [ShareRequest.requestCode] is read; a `null` or blank one attaches nothing,
     *                  exactly as passing `null` to the sibling does.
     * @param publicKey The key the profile was stored under — the vault's, not the request's.
     * @param fields    The stored fields, under [EXTRA_FIELDS_JSON]; always written, even empty.
     */
    @JvmOverloads
    fun createShareResultIntent(
        request: ShareRequest,
        publicKey: String,
        fields: Map<String, TypedField> = emptyMap(),
    ): Intent = createShareResultIntent(publicKey, fields, request.requestCode)

    /**
     * Answer a parsed [QueryRequest] — [createQueryResultIntent] with the correlation token
     * carried across for you.
     *
     * **[request] is read, never retained: the only value taken off it is the correlation
     * token.** [QueryRequest.publicKey] is deliberately *not* echoed, and this is the flow the
     * rule exists for: that key is the one the caller asked about, so echoing it automatically
     * would let the caller choose the identifier naming its own disclosure. The key a result
     * names must be the one the vault holds, which is why [publicKey] is still required here.
     *
     * `ClientIntegrationExampleTest` is the runnable example, and it shows both halves: its
     * fixture vault answers the query scene with this function. `docs/INTEGRATION.md` is the
     * client-side half of the same scene as prose.
     *
     * @param request   The request this result answers, as [parseQueryRequest] returned it. Only
     *                  [QueryRequest.requestCode] is read.
     * @param publicKey The queried profile's key as the *vault* holds it.
     * @param fields    The disclosed fields, under [EXTRA_QUERY_RESULT_FIELDS]; always written,
     *                  even empty. A refusal is `setResult(Activity.RESULT_CANCELED, …)` — the
     *                  result code, not the payload.
     */
    @JvmOverloads
    fun createQueryResultIntent(
        request: QueryRequest,
        publicKey: String,
        fields: Map<String, TypedField> = emptyMap(),
    ): Intent = createQueryResultIntent(publicKey, fields, request.requestCode)

    /**
     * Answer a parsed [SignChallengeRequest] — [createSignChallengeResultIntent] with the
     * correlation token carried across for you.
     *
     * **[request] is read, never retained: the only value taken off it is the correlation
     * token.** Not its public key, and emphatically not its nonce: [signature] must be made over
     * [SignChallengeRequest.nonce] with the private key the vault holds, and nothing here checks
     * that it was. A convenience that signed the request's nonce for you would be this library
     * holding a private key, which it does not do.
     *
     * `ClientIntegrationExampleTest` is the runnable example, and it shows both halves: its
     * fixture vault answers the login scene with this function, signing the request's nonce
     * itself — and refusing first when [isStatementPreImage] says those bytes are a statement.
     * `docs/INTEGRATION.md` is the client-side half of the same scene as prose.
     *
     * @param request   The request this result answers, as [parseSignChallengeRequest] returned
     *                  it. Only [SignChallengeRequest.requestCode] is read.
     * @param signature Raw signature bytes over the request's nonce, under [EXTRA_SIGNATURE].
     *                  An empty array is not a signature — see the sibling.
     * @param fields    The profile's fields, under [EXTRA_FIELDS_JSON]; always written.
     * @param algorithm Informational only, and never honoured by anything here — see the
     *                  sibling's note on algorithm confusion. `null` attaches nothing.
     */
    @JvmOverloads
    fun createSignChallengeResultIntent(
        request: SignChallengeRequest,
        signature: ByteArray,
        fields: Map<String, TypedField> = emptyMap(),
        algorithm: String? = null,
    ): Intent = createSignChallengeResultIntent(signature, fields, request.requestCode, algorithm)

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
     *
     * @param intent The incoming request intent, or `null`. **The most hostile input a vault
     *               handles** — any app can fire one at an exported activity — so it is nullable
     *               on purpose and every *value* on it comes back as a refusal rather than an
     *               exception. The action is not read: if you route on it, route before calling
     *               this. Read, never retained.
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
     * Read which of a share request's fields the user must fill in — the vault's half of the
     * [createShareIntent] overload taking `optionalFields`.
     *
     * Returns `null` **exactly when [parseShareRequest] does**, because it is answered from that
     * parse: the entry it reads the field names off is the one [parseShareRequest] decoded from
     * the same intent, so a declaration can never be paired with an entry it did not travel with.
     * Otherwise it returns `FieldRequirements(entry.fields.keys, declared)`, where `declared` is
     * [EXTRA_OPTIONAL_FIELDS] read strictly — and empty when that extra is absent, blank,
     * wrong-typed, unreadable, malformed or `[]`. So a missing or broken declaration means **every
     * field is required**, for an old client and a new one alike; names the entry does not declare
     * are dropped, duplicates collapse, the order is the entry's, matching is exact, and a blank
     * field name is kept, as [parseShareRequest] keeps it — refusing one is the vault's policy to
     * set.
     *
     * Nothing here bounds a size: the binder limit bounds the input, the declaration is read as a
     * stream, and only the entry's own names survive it. Product limits belong to the vault.
     * [ShareRequest] is untouched, so the same intent parses to an equal [ShareRequest] with or
     * without a declaration on it; and the declaration never affects routing — a share is still a
     * share by its entry payload alone.
     *
     * Show one form row per [FieldRequirements.fieldNames], gate Save on
     * [FieldRequirements.missingRequired], store [FieldRequirements.committed], and answer with the
     * [createShareResultIntent] overload taking these requirements, which acknowledges them only
     * if what was stored satisfies them. When editing a profile already stored, there is no
     * declaration to read: `FieldRequirements(stored.fields.keys)` keeps every stored field
     * required.
     *
     * **Example**, verbatim from `docs/INTEGRATION.md`'s *Testing your integration without a
     * vault* section, which reads a request the way a vault does:
     *
     * <!-- example: INTEGRATION.md#testing-optional-fields -->
     * ```kotlin
     * // A vault that implements required fields reads your declaration off the request, stores
     * // what the user filled in, and acknowledges the declaration only when what it stored
     * // satisfies it. Build that answer and your handler meets the verdict it will really get:
     * // here the user filled in both required fields and left the optional "phone" blank.
     * val declared = Utils.parseFieldRequirements(request)!!
     * val answer = Utils.createShareResultIntent(
     *     FAKE_PUBLIC_KEY,
     *     linkedMapOf(
     *         "name" to TypedField(value = "Ada", type = FieldType.STRING),
     *         "email" to TypedField(value = FAKE_EMAIL, type = FieldType.EMAIL),
     *     ),
     *     SIGN_UP_REQUEST,
     *     declared,
     * )
     * val verdict = Utils.checkFieldRequirements(requirements, answer)
     * // The optional set the vault says it applied. `null` means the answer acknowledges
     * // nothing: a vault older than this release, one answering through the builder that
     * // writes none, or one whose payload did not satisfy your declaration, with a required
     * // field missing or a blank value left in.
     * val applied = Utils.parseAppliedOptionalFields(answer)
     * ```
     *
     * @param intent The incoming request intent, or `null` — nullable and fail-closed for the
     *               reason [parseShareRequest]'s is, and read rather than retained.
     */
    fun parseFieldRequirements(intent: Intent?): FieldRequirements? {
        if (intent == null) return null
        val request = parseShareRequest(intent) ?: return null
        val declared = decodeNames(intent.presentStringExtra(EXTRA_OPTIONAL_FIELDS)).orEmpty()
        return FieldRequirements(request.entry.fields.keys, declared)
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
     *
     * @param intent The incoming request intent, or `null` — nullable and fail-closed for the
     *               reason [parseShareRequest]'s is, and read rather than retained. A non-null
     *               return is not an entitlement: it says someone asked about a key, and what to
     *               disclose is the vault's consent decision.
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
     *
     * @param intent The incoming request intent, or `null` — nullable and fail-closed for the
     *               reason [parseShareRequest]'s is, and read rather than retained. **Before
     *               signing what comes back, call [isStatementPreImage] on
     *               [SignChallengeRequest.nonce] and refuse a match**: this parser deliberately
     *               does not, because the bytes are legitimate input to look at and the refusal
     *               is the signing device's policy rather than the decoder's.
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
     * **Example**, verbatim from `docs/INTEGRATION.md`'s *When the user says no* section —
     * correlation is the one thing a declining vault still sends:
     *
     * <!-- example: INTEGRATION.md#declined -->
     * ```kotlin
     * // Branch on the result code, never on the parse. A refused query parses into a
     * // perfectly good QueryResult with no fields — exactly what a vault that consented and
     * // disclosed nothing returns — so the parse cannot tell you which of the two happened.
     * val declined = resultCode != Activity.RESULT_OK
     * // Correlation survives a refusal: the echoed request code is the one thing a declining
     * // vault still sends, so you know which request the user said no to.
     * val whichRequest = Utils.matchesRequestCode(data, QUERY_REQUEST)
     * // There is no structured reason to show the user. A refusal is deliberately
     * // uninformative; tell them nothing was sent and let them ask again.
     * ```
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

    // ── Diagnostics ───────────────────────────────────────────────────────
    //
    // Every parser here fails closed and returns `null`, which is right and tells an integrator
    // nothing. "Why did `parseQueryResult` return null" is the support question this API
    // generates — the same argument [verifyRotationStatement] made when it chose a verdict over a
    // `Boolean`, one layer out — and the answer is nearly always a detail of the intent in front
    // of them: an extra that is blank rather than absent, a payload filed under the other flow's
    // key, a request code that became a package name. This renders that detail, redacted.

    /** Rendered for an extra that is not in the bundle at all, under any type. */
    private const val DESCRIBE_ABSENT = "absent"

    /**
     * Present but blank. Named separately from [DESCRIBE_ABSENT] because every parser in this
     * library treats the two alike and nothing else does: an extra that reads `blank` is a sender
     * that *tried* to say something, which is a different bug from one that said nothing.
     */
    private const val DESCRIBE_BLANK = "blank"

    /**
     * Present under this key, but not as a `String`.
     *
     * [presentStringExtra] names this as one of the two hostile shapes it exists for — a peer that
     * writes `putExtra(key, 7)` reads back as `null` and the parser refuses the intent — and it is
     * the one state a diagnostic must not collapse into [DESCRIBE_ABSENT], because "you sent the
     * wrong type" and "you sent nothing" are opposite instructions to the integrator.
     */
    private const val DESCRIBE_NOT_TEXT = "present but not text"

    /**
     * Reading this key threw: an extras bundle referencing a class this process does not have
     * throws on unparcelling, and the sender chooses what goes in the bundle. Rendered for any
     * failure out of the read, since a diagnostic cannot usefully classify one it did not survive.
     */
    private const val DESCRIBE_UNREADABLE = "unreadable"

    /** A payload or Base64 section that is present and non-blank but could not be read back. */
    private const val DESCRIBE_UNDECODABLE = "undecodable"

    /**
     * How much of a short text value [describeIntent] prints verbatim. An action string, a package
     * name, a request code, `lim-ts1` and `SHA256withRSA` all sit well inside it; a peer that sends
     * sixteen kilobytes instead gets truncated, because a diagnostic nobody can log is not a
     * diagnostic.
     *
     * Deliberately **not** [PUBLIC_KEY_PREVIEW_CHARS] and not derived from it, despite both being
     * truncation widths. That one is the published rule for a shared identifier, owned by this
     * repository on behalf of the vault, and a key preview has to stay long enough to be
     * distinguishable; this one is a private detail of one diagnostic line and may be tuned
     * without telling anyone. The two numbers differ today (80 against 64) and are free to drift.
     *
     * Tuning it up is not free, and the reason is worth stating plainly. Redaction here is chosen
     * by *key*, so a value that arrives under the wrong key gets this width rather than its own
     * renderer: a peer that files a public key under [EXTRA_ALGORITHM] has it truncated at 80
     * instead of previewed at 64, which is cosmetic because a public key is deliberately not
     * secret — but a buggy vault that files a fields payload or an `Entry.id` under one of the
     * four verbatim keys would put up to this many characters of personal data on a client's log
     * line, which is not. That is a misdirected sender rather than a leak by this function, and
     * fixing it here would mean sniffing every value's shape instead of trusting its key; the
     * honest mitigation is to keep this number small.
     */
    private const val DESCRIBE_TEXT_CHARS = 80

    /**
     * Every extra this protocol defines, in the order [describeIntent] lists them: the entry
     * payload, then the public key — carried by the query and sign-challenge requests and by the
     * share and query results, though *not* by a sign-challenge result, which proves possession
     * with a signature instead (see [EXTRA_PUBLIC_KEY]) — then the rest of the sign-challenge
     * flow's values, then the two field payloads, then the sign-up's two optional-field lists —
     * the request's declaration and the result's acknowledgement — then the correlation token and
     * the version declaration.
     *
     * All of them are listed on every line, including the absent ones. A diagnostic that only
     * mentioned what was present could not answer the question it exists for, which is almost
     * always about something that is *missing*.
     */
    private val DESCRIBED_EXTRAS = listOf(
        EXTRA_ENTRY_JSON,
        EXTRA_PUBLIC_KEY,
        EXTRA_NONCE,
        EXTRA_NONCE_FORMAT,
        EXTRA_SIGNATURE,
        EXTRA_ALGORITHM,
        EXTRA_FIELDS_JSON,
        EXTRA_QUERY_RESULT_FIELDS,
        EXTRA_OPTIONAL_FIELDS,
        EXTRA_APPLIED_OPTIONAL_FIELDS,
        EXTRA_SHARE_REQUEST_CODE,
        EXTRA_PROTOCOL_VERSION,
    )

    /**
     * One redacted, human-readable line describing [intent] as this library sees it — the action
     * and target package, the state of every extra the protocol defines, the protocol version the
     * peer declared, and **which of LIM's flows this library's own parsers accept it as**.
     *
     * Log it when a parser returned `null` and it is not obvious why. The usual answers are all
     * visible on the line: the extra is `blank` rather than `absent`, the field payload is under
     * [EXTRA_QUERY_RESULT_FIELDS] when the parser you called reads [EXTRA_FIELDS_JSON], the
     * package reads `"req-1"` because a request code was passed positionally to
     * [createShareIntent], or the whole bundle is `unreadable`.
     *
     * **The flow list is a set, not an answer, and it is in a fixed order:** `shareRequest`,
     * `queryRequest`, `signChallengeRequest`, `shareResult`, `queryResult`,
     * `signChallengeResult`. These envelopes genuinely overlap — a share result carrying a public
     * key is also a well-formed query request, because the two differ only in which direction they
     * were travelling and **no parser here reads the action**, which is the only part of an
     * [Intent] that records it — so a diagnostic that picked one would teach a falsehood. An empty
     * list is the common and useful case: it means no parser here would accept this intent as
     * anything.
     *
     * The set is obtained by **calling** [parseShareRequest], [parseQueryRequest],
     * [parseSignChallengeRequest], [parseShareResult], [parseQueryResult] and
     * [parseSignChallengeResult] and reporting which returned non-null. It is not re-derived: a
     * second copy of the share/query disambiguation would be a copy that drifts from the one
     * those parsers pin in both directions, and delegating is the same call
     * [verifyRotationStatement] makes about [verifySignature].
     *
     * **Redaction is [toString]'s policy, not a new one, and it is chosen by *key*.** Every key
     * this protocol defines to carry personal data is reduced: an entry payload renders as
     * `decoded, 3 fields` or `undecodable` and never its contents or its field names, a field
     * payload as a count, a nonce and a signature as byte lengths, and a public key through
     * [previewedPublicKey] rather than a second truncation rule. Anything that would split a line
     * is replaced with `.`, so one call is one line even when the sender chose otherwise.
     *
     * **Choosing by key is also the boundary, and the boundary is narrow but not empty.** Of the
     * extras, the four protocol tokens named below and the public key are where a *sender's* own
     * bytes reach the line, as are the action and the package beside them. A peer that files a
     * profile value, a fields payload or an `Entry.id` under one of those keys therefore puts it
     * on the reader's log line, and nothing here catches it: this function trusts the key rather
     * than sniffing every value's shape, so a value that arrived in the wrong place is a
     * misdirected sender's bug rather than a leak by this line. What is owed in return is a bound
     * on how much such a mistake can print, and every one of those positions carries one — the
     * key is previewed at [PUBLIC_KEY_PREVIEW_CHARS], and the tokens, the action and the package
     * are capped at `DESCRIBE_TEXT_CHARS`, a private width kept small for exactly this reason
     * rather than a cosmetic one. Within the bound a value still prints as it was sent, which is
     * the honest shape of the promise: bounded, not absent.
     *
     * Exactly four values are printed close to verbatim, truncated but not reduced:
     * [EXTRA_NONCE_FORMAT], [EXTRA_ALGORITHM], [EXTRA_PROTOCOL_VERSION] and
     * [EXTRA_SHARE_REQUEST_CODE], alongside the action and package. The first three have
     * vocabularies this protocol defines. The request code is the one judgement call: it is
     * free-form and client-chosen, so it *could* hold anything — but it is the token the reader of
     * this line minted and is trying to correlate, and the hazard the line exists to show (a
     * request code that silently became a package name) is invisible without it. Do not put
     * personal data in a request code; `Entry.id`, which is under the same client control, is
     * reduced to its length for exactly that reason.
     *
     * **The wording is unstable and must never be parsed.** It is prose for a human to read; the
     * spelling of the states, the punctuation and the set of sections may all change in any
     * release, and none of it is wire format. Do not match on it, do not assert on it from another
     * repository, and never route on it — route on the parser that returned the `null`. The one
     * structural commitment, so that a human skimming a wrapped log line knows where to look, is
     * that the bracketed `flows=[…]` section comes **last**.
     *
     * **Advisory only**, the [validateEntry] precedent: this changes what no parser accepts,
     * nothing in this library's main source calls it, and a flow named here is still a flow whose
     * contents are unverified. `IntentDescriptionTest` pins what this repository relies on.
     *
     * `null` is a description rather than an exception, and no value on the line can throw: this
     * is what a client reaches for when something has *already* gone wrong, so it must not add a
     * second failure on top. Note where that guarantee comes from, because it is not local: every
     * extra is read defensively here, but the flow set is the six parsers' own fail-closed
     * behaviour, pinned by `DecoderFuzzTest`'s arms over the shared corpus. A parser that began
     * reading an extra without that discipline would break this promise from a distance.
     *
     * @param intent The intent to describe — a request, a result, or `null`, which describes
     *               itself as `intent=null` rather than throwing. It is read exactly as the
     *               parsers read it, including by *calling* all six of them, so passing one whose
     *               extras have never been unparcelled does that work here. Read, never
     *               retained, and nothing on it is modified.
     */
    fun describeIntent(intent: Intent?): String {
        if (intent == null) return "LIM intent: intent=null, flows=[]"
        val extras = DESCRIBED_EXTRAS.joinToString("; ") { key ->
            "$key=${intent.describedExtra(key)}"
        }
        // `flows=[…]` goes last, and stays last — the one structural promise the KDoc makes. Its
        // vocabulary is fixed, so a reader who needs the set can take the final bracketed section
        // without a sender-chosen value — which can contain anything, including these words —
        // getting in the way first.
        return oneLine(
            "LIM intent: action=${describedToken { intent.action }}, " +
                "package=${describedToken { intent.`package` }}, " +
                "protocolVersion=${intent.declaredProtocolVersion() ?: "undeclared"}, " +
                "extras=[$extras], " +
                "flows=[${acceptedFlows(intent).joinToString(", ")}]",
        )
    }

    /**
     * The action or the package, in the same three states an extra can be in.
     *
     * Read through a lambda with the same catch the extras get. Neither property can throw on an
     * [Intent] that arrived over IPC — unparcelling always yields a plain one — but an in-process
     * caller can pass a subclass, and "this is the call that cannot add a second failure" is a
     * weaker promise if it holds only for the extras.
     */
    private inline fun describedToken(read: () -> String?): String = try {
        val raw = read()
        when {
            raw == null -> DESCRIBE_ABSENT
            raw.isBlank() -> DESCRIBE_BLANK
            else -> describedText(raw)
        }
    } catch (_: Exception) {
        DESCRIBE_UNREADABLE
    }

    /** Which parsers accept [intent], in [describeIntent]'s documented order. */
    private fun acceptedFlows(intent: Intent): List<String> = buildList {
        if (parseShareRequest(intent) != null) add("shareRequest")
        if (parseQueryRequest(intent) != null) add("queryRequest")
        if (parseSignChallengeRequest(intent) != null) add("signChallengeRequest")
        if (parseShareResult(intent) != null) add("shareResult")
        if (parseQueryResult(intent) != null) add("queryResult")
        if (parseSignChallengeResult(intent) != null) add("signChallengeResult")
    }

    /**
     * One extra's state, in five kinds: [DESCRIBE_ABSENT], [DESCRIBE_BLANK], [DESCRIBE_NOT_TEXT],
     * [DESCRIBE_UNREADABLE], or a redacted rendering of what it holds.
     *
     * Read with `getStringExtra` directly rather than through [presentStringExtra], which returns
     * `null` for all four of absent, blank, wrong-typed and unreadable — the whole value of this
     * line is telling them apart. `hasExtra` is what separates the first two of those: a peer that
     * wrote an `Int` under a key the protocol spells as text is a different bug from a peer that
     * wrote nothing, and it is one the parsers cannot report because both read back as `null`.
     */
    private fun Intent.describedExtra(key: String): String = try {
        val raw = getStringExtra(key)
        when {
            raw != null && raw.isBlank() -> DESCRIBE_BLANK
            raw != null -> describedValue(key, raw)
            hasExtra(key) -> DESCRIBE_NOT_TEXT
            else -> DESCRIBE_ABSENT
        }
    } catch (_: Exception) {
        DESCRIBE_UNREADABLE
    }

    /**
     * What a present, non-blank extra is allowed to show about itself.
     *
     * The two field payloads report a count rather than `decoded`/`undecodable`, because
     * [decodeFields] repairs a malformed payload to an empty map instead of refusing it — so
     * `0 fields` genuinely means "empty, absent-ish or malformed", and claiming to know which
     * would be a claim this library cannot make. The entry payload *can* say, because
     * [decodeEntry] fails closed. Neither prints a field *name*: a key is as likely to be
     * `email` as something the vault invented about one user, and a count answers the question.
     *
     * **Every key in [DESCRIBED_EXTRAS] has a deliberate arm here, and the `else` redacts.** The
     * verbatim renderer is opt-in for exactly the four protocol tokens listed in [describeIntent]'s
     * KDoc, so a future extra added to that list prints its length until someone decides what it
     * may show. The alternative ordering — verbatim by default — is how a new extra ends up in a
     * log line with no diff to notice: the drafted per-field query request under "Blocked on human"
     * would carry a list of the field names a service asked about, which is precisely the kind of
     * thing this function must not print by accident. `IntentDescriptionTest` pins that no listed
     * key reaches this fallback.
     *
     * The sign-up's two optional-field lists are that case, met: they *are* lists of field names,
     * so they render as a count of what the strict reader found — `0 names`, `1 name`, `3 names`,
     * duplicates included, as sent — or `undecodable`, and never as a name. `0 names` against
     * `absent` is the one thing the line can tell a vault about a client: a declaration of nothing
     * and no declaration mean the same, but only one of them was sent by a client that knew about
     * required fields.
     */
    private fun describedValue(key: String, raw: String): String = when (key) {
        EXTRA_ENTRY_JSON ->
            decodeEntry(raw)?.let { "decoded, ${fieldCount(it.fields.size)}" }
                ?: DESCRIBE_UNDECODABLE

        EXTRA_PUBLIC_KEY -> previewedPublicKey(raw)

        EXTRA_NONCE, EXTRA_SIGNATURE ->
            nonEmptyBase64(raw)?.let { "${it.size} bytes" } ?: DESCRIBE_UNDECODABLE

        EXTRA_FIELDS_JSON, EXTRA_QUERY_RESULT_FIELDS -> fieldCount(decodeFields(raw).size)

        EXTRA_OPTIONAL_FIELDS, EXTRA_APPLIED_OPTIONAL_FIELDS ->
            decodeNames(raw)?.let { nameCount(it.size) } ?: DESCRIBE_UNDECODABLE

        EXTRA_NONCE_FORMAT, EXTRA_ALGORITHM, EXTRA_PROTOCOL_VERSION, EXTRA_SHARE_REQUEST_CODE ->
            describedText(raw)

        else -> redactedValue(raw)
    }

    /** `1 field`, `3 fields`. Prose, because the line is for a person to read. */
    private fun fieldCount(count: Int): String = if (count == 1) "1 field" else "$count fields"

    /** `0 names`, `1 name`, `3 names` — [fieldCount]'s rule for the two optional-field lists. */
    private fun nameCount(count: Int): String = if (count == 1) "1 name" else "$count names"

    /** A short sender-chosen token, quoted and capped at [DESCRIBE_TEXT_CHARS]. */
    private fun describedText(text: String): String {
        if (text.length <= DESCRIBE_TEXT_CHARS) return "\"$text\""
        // Never cut between a surrogate pair. Half a pair is not a valid string, and a client
        // logging through a strict encoder can get an exception out of it — the second failure
        // this function promises not to add on top of the first.
        val cut =
            if (text[DESCRIBE_TEXT_CHARS - 1].isHighSurrogate()) DESCRIBE_TEXT_CHARS - 1
            else DESCRIBE_TEXT_CHARS
        return "\"${text.take(cut)}\"…(${text.length} chars)"
    }

    /**
     * Make the assembled description one loggable line: replace everything that would split it,
     * and everything that would make it an invalid string, with `.`.
     *
     * Applied to the whole line rather than to each value, because the values come from several
     * renderers and one of them is [previewedPublicKey], whose format this library owns elsewhere
     * and must not fork here.
     *
     * Two classes are replaced, for the same reason — a client must be able to log the result
     * without the attempt failing:
     *
     *  - **Line terminators.** [Char.isISOControl] is not sufficient on its own: it covers `\n`,
     *    `\r` and the C1 range but not U+2028 LINE SEPARATOR or U+2029 PARAGRAPH SEPARATOR, which
     *    Unicode defines as line terminators and which `Scanner` and most log viewers break on.
     *  - **Unpaired surrogates.** A peer can put half a surrogate pair in an extra, and a lone
     *    surrogate is not a valid encodable string: a client logging through a strict UTF-8 or
     *    JSON encoder can get an exception out of it, which is exactly the second failure this
     *    function promises not to add on top of the first. A *well-formed* pair passes through
     *    untouched, so a legitimate astral character — an emoji in a request code — still renders.
     *
     * What deliberately survives: printable non-ASCII, including `…`, which this function's own
     * truncation emits — and including the bidi controls U+202A..U+202E, which can visually
     * reorder a rendered line but neither split it nor make it unencodable. Stripping those is a
     * presentation policy for whatever displays the log rather than a property of this string, and
     * a diagnostic that silently rewrote more of a sender's value than it had to would be lying
     * about what arrived.
     */
    private fun oneLine(text: String): String {
        if (text.none { it.splitsALine() || it.isSurrogate() }) return text
        return buildString(text.length) {
            var index = 0
            while (index < text.length) {
                val char = text[index]
                val paired = char.isHighSurrogate() &&
                    index + 1 < text.length &&
                    text[index + 1].isLowSurrogate()
                when {
                    paired -> {
                        append(char)
                        append(text[index + 1])
                        index++
                    }

                    char.splitsALine() || char.isSurrogate() -> append('.')
                    else -> append(char)
                }
                index++
            }
        }
    }

    /**
     * Whether this character would end the line a description is written on.
     *
     * **The two comparands on the next line are literal U+2028 and U+2029**, not escapes, which is
     * a wart worth naming rather than leaving for a reader to squint at: a line terminator sitting
     * in a source file is one an editor, a diff tool or a copy-paste can silently normalise away,
     * and the predicate would then quietly stop covering the characters it exists for. The nearby
     * tests spell their own control characters numerically for that reason. Rewriting these two as
     * `code == 0x2028 || code == 0x2029` is a safe, behaviour-preserving cleanup for whoever next
     * has an editor that can be trusted to leave them alone.
     */
    private fun Char.splitsALine(): Boolean =
        isISOControl() || this == ' ' || this == ' '

    // ── Typed-field (de)serialization ─────────────────────────────────────

    /**
     * Encode a map of [TypedField]s to the canonical JSON form used on the wire.
     *
     * Use this when building the [EXTRA_FIELDS_JSON] payload to send back to a client app.
     *
     * @param fields The map to encode. Insertion order is preserved, an empty map encodes to
     *               `"{}"` — which reads back as an empty map, and is why the result builders
     *               write the payload even when there is nothing to disclose — and the real
     *               values go on the wire: this is serialisation, not the redaction
     *               [TypedField.toString] performs. Not modified.
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
     *
     * @param json The payload, straight off an intent extra, or `null`. Nullable because an
     *             absent extra is the ordinary case rather than a programming error; `null`,
     *             blank and unparseable all yield an empty map. So an empty map means "nothing
     *             usable was in the payload" and **nothing finer**: "the vault disclosed nothing",
     *             "the extra was absent" and "the JSON was damaged" are one answer here, and
     *             [describeIntent] does not separate them either — it reports `0 fields` for an
     *             empty payload and for a malformed one alike, deliberately, because neither this
     *             function nor that one can tell which it was holding.
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

    // ── Optional-field names (de)serialization ────────────────────────────
    //
    // The two optional-field lists, [EXTRA_OPTIONAL_FIELDS] and [EXTRA_APPLIED_OPTIONAL_FIELDS],
    // share one encoding: a JSON array of JSON strings. Written through Gson's own `JsonWriter`
    // with HTML-safe escaping, which is byte for byte what `Gson().toJson(list)` writes — so a
    // name is escaped exactly as the entry payload escapes it — and read through its streaming
    // `JsonReader`. Neither reflects over a type of this library's, so neither needs a keep rule.

    /** [names] as a JSON array of strings, in the order given. `[]` for none. */
    private fun encodeNames(names: Collection<String>): String {
        val out = StringWriter()
        JsonWriter(out).use { writer ->
            writer.isHtmlSafe = true
            writer.beginArray()
            names.forEach { writer.value(it) }
            writer.endArray()
        }
        return out.toString()
    }

    /**
     * Read [json] as exactly one flat array of strings, or `null` for anything else.
     *
     * **Strict, streaming and all-or-nothing**, because the text arrived from another app. The
     * reader runs at `Strictness.STRICT`, so the lenient spellings — `[a]`, `['a']`, a trailing
     * comma, a comment — are refused rather than repaired. An element that is not a string (a
     * number, a boolean, `null`, an object or a nested array) refuses the whole document and
     * salvages nothing, and so does anything after the closing bracket. It is a loop rather than a
     * recursion: a nested `[[[…` is refused at the first element, so depth costs nothing. Every
     * exception out of the reader is a refusal.
     *
     * Duplicates and order are left to the caller: [parseFieldRequirements] intersects the names
     * with the entry's, [parseAppliedOptionalFields] collapses duplicates, and [describeIntent]
     * counts what was sent.
     */
    private fun decodeNames(json: String?): List<String>? {
        if (json == null) return null
        return try {
            val reader = JsonReader(StringReader(json))
            reader.strictness = Strictness.STRICT
            val names = ArrayList<String>()
            reader.beginArray()
            while (reader.hasNext()) {
                if (reader.peek() != JsonToken.STRING) return null
                names += reader.nextString()
            }
            reader.endArray()
            if (reader.peek() != JsonToken.END_DOCUMENT) return null
            names
        } catch (_: Exception) {
            null
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
     *
     * @param json The [EXTRA_ENTRY_JSON] payload, straight off an intent extra, or `null`.
     *             Nullable because an absent extra is the ordinary case rather than a programming
     *             error, and because this is the trust boundary: `null`, blank, non-JSON, a JSON
     *             array, and an object with a `fields` member of the wrong shape are all `null`
     *             returns and never exceptions. **Do not use `Gson().fromJson` on this string
     *             instead** — that is the hole this function exists to close.
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
     * Restore the invariants Gson cannot — see the [TypedField] overload below.
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