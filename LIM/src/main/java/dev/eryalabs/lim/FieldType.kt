package dev.eryalabs.lim

/**
 * Canonical datatype names for profile fields in the LIM share protocol.
 *
 * Types are transmitted as plain strings (not an enum) so that apps built against an older
 * version of this library can still send field types that Endeavor — or another client —
 * learns to understand later without a library bump on both sides.
 *
 * Note that all profile *values* are stored as strings regardless of the declared type.
 * The type is metadata describing how the value should be interpreted by the receiving
 * app after a successful login — it is not used to validate or coerce the value on
 * Endeavor's side. A field declared `Integer` but typed as "forty-seven" by the user is
 * stored verbatim; it is the receiving app's responsibility to handle that case.
 */
object FieldType {

    /**
     * Free text with no further structure, and the default [TypedField.type] — so it is also what
     * every field whose type nobody declared ends up as, including one repaired by
     * [Utils.decodeFields].
     */
    const val STRING = "String"

    /**
     * A whole number. The value is still a [String] on the wire, so the receiving app parses it —
     * `value.toIntOrNull()`, not `value.toInt()`: nothing on either side checks that an `Integer`
     * field holds digits, and the class doc above spells out why.
     */
    const val INTEGER = "Integer"

    /** A number with a fractional part. Parsed by the receiving app, with the same caveat. */
    const val DECIMAL = "Decimal"

    /**
     * A true/false value. **Which spellings count as true is not defined anywhere in this
     * library** — `"true"`, `"yes"` and `"1"` are all values a vault would store verbatim — so a
     * receiving app has to decide, and two apps may decide differently.
     */
    const val BOOLEAN = "Boolean"

    /**
     * A date, or a date and time.
     *
     * **No format is specified — not here, not in the protocol, and nowhere else in this
     * repository.** Nothing validates, parses or reformats a `Date` field at any point: the value
     * is the string the user typed into the vault, and `"1815-12-10"`, `"10/12/1815"` and
     * `"Dec 1815"` are equally valid as far as every component here is concerned. Naming one
     * format in this comment would be a protocol narrowing written in prose, which the vault would
     * have to agree to; until that decision is made and written down on both sides, a receiving
     * app must parse defensively and be ready to fail.
     */
    const val DATE = "Date"

    /**
     * An email address. Declared, never checked: nothing in this library validates the value
     * against any address grammar, so treat it as text that is *meant* to be an address.
     */
    const val EMAIL = "Email"

    /**
     * A telephone number. As with [EMAIL], the type is a declaration of intent — no format is
     * specified anywhere here, so country codes, spacing and punctuation are whatever the user
     * typed.
     */
    const val PHONE = "Phone"

    /** A URL. Unvalidated and unparsed, like every other type here. */
    const val URL = "Url"

    /** Every type this library ships with a documented meaning. */
    val KNOWN: Set<String> = setOf(STRING, INTEGER, DECIMAL, BOOLEAN, DATE, EMAIL, PHONE, URL)

    /**
     * Fold common aliases into the canonical spelling (`"int"` → `"Integer"`, etc.).
     * Unknown types are returned unchanged so apps can introduce new types without
     * requiring a library update on the other side.
     *
     * @param raw The type as a peer spelled it. Matched case-insensitively after trimming, so
     *            `" INT "` folds to [INTEGER]; an empty or whitespace-only value becomes
     *            [STRING], and anything else unrecognised comes back trimmed but otherwise
     *            unchanged — which is why the result is worth comparing against [KNOWN] when you
     *            need to know whether this library understands it.
     */
    fun normalize(raw: String): String = when (raw.trim().lowercase()) {
        "string", "str", "text" -> STRING
        "integer", "int" -> INTEGER
        "decimal", "double", "float", "number" -> DECIMAL
        "boolean", "bool" -> BOOLEAN
        "date", "datetime", "timestamp" -> DATE
        "email", "e-mail", "mail" -> EMAIL
        "phone", "tel", "telephone" -> PHONE
        "url", "uri", "link" -> URL
        else -> raw.trim().ifEmpty { STRING }
    }
}