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
 */
internal const val PUBLIC_KEY_PREVIEW_CHARS = 64

/**
 * Render a public key truncated but readable.
 *
 * Unlike a field value this is *not* hidden. The public key is the opaque handle the whole LIM
 * design hands out freely — a breached service is meant to leak nothing else — and it is what
 * makes a log line identifiable at all. Truncating it keeps the line short; hiding it would
 * make every entry in a log look the same.
 */
internal fun previewedPublicKey(publicKey: String?): String = when {
    publicKey == null -> "null"
    publicKey.length <= PUBLIC_KEY_PREVIEW_CHARS -> publicKey
    else -> publicKey.take(PUBLIC_KEY_PREVIEW_CHARS) + "…(${publicKey.length} chars)"
}
