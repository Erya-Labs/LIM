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
) : Parcelable
