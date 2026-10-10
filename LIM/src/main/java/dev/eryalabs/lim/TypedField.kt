package dev.eryalabs.lim

import android.os.Parcelable
import com.google.gson.annotations.SerializedName
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
 *
 * Like [Entry], this is built by Gson through `Unsafe` when it arrives over IPC, so both
 * properties can be genuinely `null` at runtime despite their declared types — [type] never
 * receives its default. [Utils.decodeFields] and [Utils.decodeEntry] repair that; nothing else
 * does.
 *
 * @property value The field's value, always a [String] whatever [type] says, and the user's
 *                 personal data: it is what [toString] redacts and what this library exists to
 *                 keep on the device. Empty is legitimate — a client sends empty values on a
 *                 sign-up and the user fills them in inside the vault.
 * @property type  The declared datatype, as one of [FieldType]'s constants or any other string a
 *                 peer chose. Metadata for the receiving app to interpret the value by, never
 *                 validation: a field declared [FieldType.INTEGER] whose value is `"forty-seven"`
 *                 is stored verbatim. Defaults to [FieldType.STRING]; run a peer-supplied spelling
 *                 through [FieldType.normalize] before comparing it to a constant.
 */
@Parcelize
data class TypedField(
    @SerializedName("value") val value: String,
    @SerializedName("type") val type: String = FieldType.STRING,
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
