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