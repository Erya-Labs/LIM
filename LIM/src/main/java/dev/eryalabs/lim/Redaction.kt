package dev.eryalabs.lim

/*
 * Redaction helpers shared by the `toString()` overrides on [Entry] and [TypedField].
 *
 * A Kotlin data class generates a `toString()` that prints every property verbatim, so any
 * client that logs an entry — or any crash reporter, bug-report capture or attached debugger
 * that grabs one — writes the user's name, email and date of birth out in plain text. For a
 * library whose entire purpose is that personal data does not spread, printing the values is
 * the defect. Printing their *shape* is the fix: a redacted rendering still tells you which
 * fields are present, what types they claim and whether a value is empty, which is what
 * debugging an integration actually needs.
 *
 * Both helpers accept a nullable argument even though every caller passes a declared-non-null
 * property. That is not defensive noise: Gson builds [Entry] and [TypedField] through `Unsafe`
 * without running the Kotlin constructor, so those properties are genuinely `null` at runtime
 * for a payload that omitted them (see `Utils.decodeEntry`), and the objects reach `toString()`
 * before anything repairs them. A `toString()` that throws inside a crash handler would be a
 * worse failure than the leak it was added to prevent.
 */

/**
 * Render a personal-data value as its length alone — `<12 chars>` — never the value itself.
 *
 * The length is deliberately kept: "the email field is 0 characters long" is the answer to
 * most integration bugs, and it discloses nothing a log reader could act on.
 */
internal fun redactedValue(value: String?): String =
    if (value == null) "null" else "<${value.length} chars>"

/**
 * How much of a public key to print. 64 characters, not a token 8 or 12, because of what an
 * X.509 RSA key looks like in Base64: the first 44 characters of a 2048-bit key are a fixed
 * DER header (`SubjectPublicKeyInfo` wrapper, algorithm OID, modulus tag — 33 bytes, which is
 * exactly 11 Base64 groups), identical for every user on earth. A shorter preview would print
 * the same string for everybody and identify nothing, which is the one job it has here.
 *
 * `ToStringRedactionTest` pins both halves of that: two real generated keys share the first 44
 * characters, and their previews still differ.
 *
 * **Public, and what that does and does not freeze.** The *name and type* of this constant are
 * published API: neither may be renamed or removed without breaking every compiled consumer. The
 * *value* is not.
 * 64 is a **log** format — no signature is computed over it, nothing on the wire is framed by it
 * and no peer parses a preview back — so the number may still be tuned if a longer or shorter
 * preview turns out to read better. What may not happen is two repositories tuning it
 * separately: see [previewedPublicKey] for who owns the format.
 *
 * One consequence of `const` to know before relying on the number: a consumer's compiler inlines
 * the literal, so a tuned value reaches an app only when that app *recompiles*. An app still
 * built against the old value would print a [previewedPublicKey] preview at the new width and its
 * own `take(PUBLIC_KEY_PREVIEW_CHARS)` at the old one — the same drift, now inside one app. That
 * is a reason to call the function rather than to slice a key by hand, not a reason to copy the
 * number; `const` is kept because dropping it would turn this field into a getter and change the
 * published shape, which is the compatibility promise this comment is about.
 */
public const val PUBLIC_KEY_PREVIEW_CHARS: Int = 64

/**
 * Render a public key truncated but readable.
 *
 * Unlike a field value this is *not* hidden. The public key is the opaque handle the whole LIM
 * design hands out freely — a breached service is meant to leak nothing else — and it is what
 * makes a log line identifiable at all. Truncating it keeps the line short; hiding it would
 * make every entry in a log look the same.
 *
 * **Published for the vault to call, not to copy.** A vault app prints the same keys into the
 * same kind of log line as a client does, and before this function was public the only way for it
 * to match LIM's rendering was to keep its own copy of the truncation rule. Two copies of a format
 * is one copy that drifts, and when it drifts the same key renders two ways in two apps' logs and
 * nobody can line them up. **This repository owns the format**: call this function — and read the
 * boundary off [PUBLIC_KEY_PREVIEW_CHARS] rather than writing 64 — instead of reimplementing it.
 * The name and signature are now frozen like any other published member.
 *
 * Deliberately *not* published alongside it: `redactedValue`. It renders a field *value's*
 * length, which is one app's own data rather than a shared identifier, and nothing outside this
 * library needs to reproduce it character-for-character.
 *
 * @param publicKey The Base64 key to render. Nullable on purpose, and `null` renders as the word
 *                  `"null"` rather than throwing: a key read off an [Entry] Gson built can be
 *                  genuinely `null` despite its declared type, and the call that reaches here is
 *                  usually a log line inside a failure. A key no longer than
 *                  [PUBLIC_KEY_PREVIEW_CHARS] is returned whole, so a short identifier is not
 *                  silently decorated.
 */
public fun previewedPublicKey(publicKey: String?): String = when {
    publicKey == null -> "null"
    publicKey.length <= PUBLIC_KEY_PREVIEW_CHARS -> publicKey
    else -> publicKey.take(PUBLIC_KEY_PREVIEW_CHARS) + "…(${publicKey.length} chars)"
}
