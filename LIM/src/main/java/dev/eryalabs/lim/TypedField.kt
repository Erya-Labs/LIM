package dev.eryalabs.lim

import android.os.Parcelable
import kotlinx.parcelize.Parcelize

/**
 * A single profile field value with its declared datatype.
 *
 * `value` is always a [String] — profile data is stored as strings even when the declared
 * [type] says otherwise. The receiving app decides how to parse the value after a
 * successful login (e.g. `value.toInt()` when `type == FieldType.INTEGER`).
 *
 * The type is declared by the app that requests profile creation (via the share intent)
 * and is immutable afterwards. Endeavor's form UI shows it as read-only metadata — the
 * user edits the value, not the type.
 */
@Parcelize
data class TypedField(
    val value: String,
    val type: String = FieldType.STRING,
) : Parcelable {

    /**
     * A redacted rendering: the declared [type] and the *length* of [value], never the value.
     *
     * [value] is the user's personal data — their name, their email, their date of birth —
     * and the generated `toString()` a data class would otherwise supply prints it verbatim
     * into every log line, bug report and crash dump that touches it. See [redactedValue].
     *
     * Only this rendering is redacted. Nothing else changes: `equals`, `hashCode`, `copy`,
     * the [Parcelable] encoding and Gson serialisation all still carry the real value, which
     * is what the wire format depends on.
     */
    override fun toString(): String = "TypedField(type=$type, value=${redactedValue(value)})"
}
