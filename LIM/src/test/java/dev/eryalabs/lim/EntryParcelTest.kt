package dev.eryalabs.lim

import android.os.Parcel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * [Entry] hand-writes its [kotlinx.parcelize.Parceler], so reads and writes can drift out of
 * order. When they do, the failure is not an exception — it is a profile whose values and
 * datatypes have been shuffled between fields, delivered to a client app as if correct.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class EntryParcelTest {

    private fun roundTrip(entry: Entry): Entry {
        val parcel = Parcel.obtain()
        return try {
            parcel.writeParcelable(entry, 0)
            parcel.setDataPosition(0)
            parcel.readParcelable(Entry::class.java.classLoader)!!
        } finally {
            parcel.recycle()
        }
    }

    @Test
    fun `a multi-field entry survives the round trip intact`() {
        val original = Entry(
            id = "profile-1",
            fields = linkedMapOf(
                "name" to TypedField("Ada Lovelace", FieldType.STRING),
                "age" to TypedField("36", FieldType.INTEGER),
                "email" to TypedField("ada@example.com", FieldType.EMAIL),
            ),
            publicKey = "PUBLIC-KEY-BASE64",
        )

        val restored = roundTrip(original)

        assertEquals(original.id, restored.id)
        assertEquals(original.publicKey, restored.publicKey)
        assertEquals(original.fields.size, restored.fields.size)
        original.fields.forEach { (key, expected) ->
            assertEquals("value of $key", expected.value, restored.fields[key]?.value)
            assertEquals("type of $key", expected.type, restored.fields[key]?.type)
        }
    }

    /**
     * The specific failure this guards: if `write` and `create` disagree on the order of
     * `value` and `type`, a two-field entry still round-trips the right *number* of entries
     * and only the contents are wrong. Distinct values and types per field make that visible.
     */
    @Test
    fun `values are not transposed with types`() {
        val original = Entry(
            id = "x",
            fields = linkedMapOf(
                "a" to TypedField("value-a", FieldType.EMAIL),
                "b" to TypedField("value-b", FieldType.PHONE),
            ),
            publicKey = "k",
        )

        val restored = roundTrip(original)

        assertEquals("value-a", restored.fields["a"]?.value)
        assertEquals(FieldType.EMAIL, restored.fields["a"]?.type)
        assertEquals("value-b", restored.fields["b"]?.value)
        assertEquals(FieldType.PHONE, restored.fields["b"]?.type)
    }

    @Test
    fun `field order is preserved`() {
        val keys = listOf("first", "second", "third", "fourth")
        val original = Entry(
            id = "ordered",
            fields = keys.associateWithTo(LinkedHashMap()) { TypedField(it, FieldType.STRING) },
            publicKey = "k",
        )

        assertEquals(keys, roundTrip(original).fields.keys.toList())
    }

    @Test
    fun `an entry with no fields survives the round trip`() {
        val restored = roundTrip(Entry(id = "empty", fields = emptyMap(), publicKey = "k"))
        assertEquals("empty", restored.id)
        assertEquals("k", restored.publicKey)
        assertTrue(restored.fields.isEmpty())
    }

    @Test
    fun `unicode and empty strings survive the round trip`() {
        val original = Entry(
            id = "プロフィール",
            fields = linkedMapOf(
                "名前" to TypedField("山田 太郎", FieldType.STRING),
                "blank" to TypedField("", FieldType.STRING),
                "emoji" to TypedField("🔐", "Iban"),
            ),
            publicKey = "",
        )

        val restored = roundTrip(original)

        assertEquals("プロフィール", restored.id)
        assertEquals("山田 太郎", restored.fields["名前"]?.value)
        assertEquals("", restored.fields["blank"]?.value)
        assertEquals("Iban", restored.fields["emoji"]?.type)
        assertEquals("", restored.publicKey)
    }

    /**
     * A realistically sized profile, to catch any fixed-size assumption in the Parceler.
     */
    @Test
    fun `a large entry survives the round trip`() {
        val fields = (1..200).associateTo(LinkedHashMap()) {
            "field_$it" to TypedField("value_$it", if (it % 2 == 0) FieldType.INTEGER else FieldType.STRING)
        }
        val restored = roundTrip(Entry(id = "big", fields = fields, publicKey = "k"))

        assertEquals(200, restored.fields.size)
        assertEquals("value_200", restored.fields["field_200"]?.value)
        assertEquals(FieldType.INTEGER, restored.fields["field_200"]?.type)
        assertEquals(FieldType.STRING, restored.fields["field_199"]?.type)
    }

    /**
     * Negative control: proves the round trip is really serialising, not handing back the
     * same object reference (in which case every assertion above would pass vacuously).
     */
    @Test
    fun `round trip produces a distinct instance`() {
        val original = Entry("id", mapOf("k" to TypedField("v", FieldType.STRING)), "pk")
        val restored = roundTrip(original)

        assertNotNull(restored)
        assertTrue(
            "readParcelable must return a new instance, not the original reference",
            original !== restored,
        )
        assertEquals("...but it must still be equal by value", original, restored)
    }
}
