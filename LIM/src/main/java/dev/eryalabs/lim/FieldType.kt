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
    const val STRING = "String"
    const val INTEGER = "Integer"
    const val DECIMAL = "Decimal"
    const val BOOLEAN = "Boolean"
    const val DATE = "Date"
    const val EMAIL = "Email"
    const val PHONE = "Phone"
    const val URL = "Url"

    /** Every type this library ships with a documented meaning. */
    val KNOWN: Set<String> = setOf(STRING, INTEGER, DECIMAL, BOOLEAN, DATE, EMAIL, PHONE, URL)

    /**
     * Fold common aliases into the canonical spelling (`"int"` → `"Integer"`, etc.).
     * Unknown types are returned unchanged so apps can introduce new types without
     * requiring a library update on the other side.
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