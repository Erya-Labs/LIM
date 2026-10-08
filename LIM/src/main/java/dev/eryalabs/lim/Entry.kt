package dev.eryalabs.lim

import android.os.Parcel
import android.os.Parcelable
import kotlinx.parcelize.Parceler
import kotlinx.parcelize.Parcelize

/**
 * One profile as it travels between a client app and the vault: an identity, a map of typed
 * fields, and the public key the profile is keyed by.
 *
 * **This is the first type an integrator constructs** — `createShareIntent(context, Entry(...))`
 * is how a sign-up begins — and the three slots are not symmetric. [id] and [fields] are the
 * client's to fill; [publicKey] is the vault's, and on a first sign-up the client has nothing to
 * put there. See [Utils.createShareIntent] for the flow and `ClientIntegrationExampleTest` for it
 * written as a test, including the `"no-key-yet"` placeholder a sign-up has to send and the rule
 * that goes with it: **the handle to keep is the key the result carries, never the one you sent.**
 *
 * **Nothing is validated on construction.** An [Entry] with a blank [id], a blank [publicKey] or
 * an empty [fields] map builds fine and encodes fine, and [Utils.decodeEntry] on the far side
 * refuses the first two — so a client that sends one is dropped with nothing to show for it. Call
 * [Utils.validateEntry] before sending to be told in words what looks wrong with one. It is
 * advice to show a developer and not a gate: it flags shapes a vault would in fact accept, and an
 * empty verdict is no promise that the vault will accept the entry.
 *
 * **Everything in an [Entry] that arrived over IPC is hostile input, and all three of its
 * properties can be `null` despite their declared types.** Gson instantiates this class through
 * `Unsafe` without running the Kotlin constructor, so every key a payload omits leaves its
 * property genuinely `null` at runtime while the compiler inserts no check — `{}` decodes to an
 * [Entry] that throws on first use, and `{"id":"a","publicKey":"b"}` to one that throws on
 * [fields] alone. [Utils.decodeEntry] is the only safe way to read one back; see its KDoc for the
 * whole hazard.
 *
 * [toString] is overridden to redact, which is the one place this class departs from what a data
 * class would give you. The wire format is unaffected — see below.
 *
 * @property id        The client's own handle for this profile, echoed nowhere in the protocol and
 *                     never used to look one up: the *public key* is the account identifier
 *                     throughout (see [Utils.verifyRotationStatement]). It is chosen by the client
 *                     app, which also means it is as likely to be an email address as an opaque
 *                     token, so it is treated as personal data by [toString] and by
 *                     [Utils.describeIntent] — do not put anything in it you would not want on a
 *                     log line. Must not be blank: [Utils.decodeEntry] refuses a blank one.
 * @property fields    The profile's fields, keyed by the name the client asks for them under, each
 *                     carrying a declared [TypedField.type]. On a sign-up a client sends the keys
 *                     and types it wants with empty values — the user types the values into the
 *                     vault — and the vault echoes back what it stored. A blank key is reported by
 *                     [Utils.validateEntry]; insertion order is preserved through
 *                     [Utils.encodeFields] and [Utils.decodeFields].
 * @property publicKey The Base64 X.509 RSA public key this profile is keyed by — **a slot the
 *                     vault fills, not one the client supplies.** The vault mints the keypair and
 *                     keeps the private half; a first sign-up therefore has no real value to send
 *                     and sends a placeholder, and the key to store afterwards is the one
 *                     [ShareResult.publicKey] carries back. Must not be blank:
 *                     [Utils.decodeEntry] refuses a blank one, since a profile keyed to nothing is
 *                     one nobody could ever authenticate against.
 */
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