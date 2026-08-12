package dev.eryalabs.lim

import android.os.Parcel
import android.os.Parcelable
import kotlinx.parcelize.Parceler
import kotlinx.parcelize.Parcelize

@Parcelize
data class Entry(
    val id: String,
    val fields: Map<String, TypedField>,
    val publicKey: String,
) : Parcelable {

    /**
     * A redacted rendering: field keys, declared types and value lengths — never a value.
     *
     * An entry is the user's whole profile. The generated `toString()` a data class would
     * otherwise supply prints all of it verbatim, so a single `Log.d("entry: $entry")` in a
     * client app spills the name, email and date of birth this library exists to keep on the
     * device. That leak is invisible until after it has happened.
     *
     * Two deliberate asymmetries:
     *
     * - [publicKey] is truncated rather than hidden. It is not personal data — it is the
     *   opaque handle the design hands out freely — and it is what makes a log line
     *   identifiable at all. See [previewedPublicKey] for why the preview is as long as it is.
     * - [id] is reduced to its length. It is chosen by the client app, not by this library,
     *   and is as likely to be the user's email address as an opaque token, so it gets the
     *   treatment a value gets rather than the treatment the public key gets.
     *
     * The field values are redacted by [TypedField.toString], which the map interpolated
     * below calls for each entry. That indirection is the trap: an override here that printed
     * `fields` while leaving [TypedField] alone would *look* redacted and still leak every
     * value in the profile.
     *
     * This changes the rendering only. `equals`, `hashCode`, `copy`, the [Parcelable]
     * encoding and Gson serialisation all still carry the real values — the wire format is
     * unaffected.
     */
    override fun toString(): String =
        "Entry(id=${redactedValue(id)}, publicKey=${previewedPublicKey(publicKey)}, fields=$fields)"

    companion object : Parceler<Entry> {
        override fun Entry.write(parcel: Parcel, flags: Int) {
            parcel.writeString(id)
            parcel.writeInt(fields.size)
            fields.forEach { (key, typed) ->
                parcel.writeString(key)
                parcel.writeString(typed.value)
                parcel.writeString(typed.type)
            }
            parcel.writeString(publicKey)
        }

        override fun create(parcel: Parcel): Entry {
            val id = parcel.readString() ?: ""
            val size = parcel.readInt()
            val fields = LinkedHashMap<String, TypedField>(size)
            repeat(size) {
                val key = parcel.readString() ?: ""
                val value = parcel.readString() ?: ""
                val type = parcel.readString() ?: FieldType.STRING
                fields[key] = TypedField(value = value, type = type)
            }
            val publicKey = parcel.readString() ?: ""
            return Entry(id, fields, publicKey)
        }
    }
}