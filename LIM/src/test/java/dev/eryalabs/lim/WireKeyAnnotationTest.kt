package dev.eryalabs.lim

import com.google.gson.annotations.SerializedName
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.lang.reflect.Field
import java.lang.reflect.Modifier

/**
 * **Every JSON key the two apps exchange is written down, not inferred from a field name.**
 *
 * The five keys — `id`, `fields`, `publicKey` on [Entry] and `value`, `type` on [TypedField] — are
 * protocol. Until the commit that added `@SerializedName` they were *also* the five JVM field
 * names, with nothing but Gson's default reflection between the two, which made every one of them
 * renameable by an edit that reads as a refactor: rename the property and the wire moves with it,
 * in this library and in the consumer's R8 run alike. `LIM/consumer-rules.pro` exists because of
 * the second half of that and says so; this file is the first half.
 *
 * **What the annotation buys and what it does not.** It decouples the key from the field name, so
 * renaming `publicKey` to `key` now changes a Kotlin identifier and leaves the wire alone. It does
 * **not** replace the keep rules: an annotation only helps if it survives into the consumer's
 * release build (`-keepattributes *Annotation*`, which stopped being forward-looking the moment
 * these five arrived), and a field R8 *removed* has no name to serialise under at all. Both
 * mechanisms are needed and `ConsumerRulesTest` is where the second is checked.
 *
 * **Why by reflection rather than by a list of five names.** A list would be a second copy of the
 * protocol, and the failure this file is for is a *sixth* property arriving on one of these two
 * classes with no annotation on it — invisible to any list, and on the wire from the first commit
 * that compiles it. So the field set comes from `declaredFields` and the rule is applied to
 * whatever is in it.
 *
 * **The use-site trap this file is written around.** Gson's `@SerializedName` is a Java annotation
 * targeting `FIELD` and `METHOD`, and Kotlin's rule for an annotation on a constructor `val` with
 * no use-site target is to take the first *applicable* target in the order parameter, property,
 * field. `PARAMETER` is not among its targets and Kotlin properties are not a Java target either,
 * so it should land on the backing field — "should" being exactly why every assertion below reads
 * it back off `Entry::class.java.getDeclaredField(...)` rather than trusting the source text. If
 * one of these ever comes back absent, the repair is `@field:SerializedName(...)`.
 *
 * No Robolectric and no Gson round trip: this is `java.lang.reflect` over two classes. That the
 * annotations *work* — that the keys Gson emits are these strings — is pinned on the encode side
 * by `IntentBuilderTest`'s exact payload literal, on the decode side by `EntryCodecTest`'s
 * literals, and against reflection by `ConsumerRulesTest`'s rule 3.
 */
class WireKeyAnnotationTest {

    /**
     * The fields of [type] that Gson serialises: declared, instance, not compiler-generated.
     *
     * `static` excludes `CREATOR` and `Companion`, neither of which Gson looks at; `synthetic`
     * excludes anything the compiler invented. Deliberately the same filter `ConsumerRulesTest`
     * applies when it decides which fields need a keep rule, because the two files have to be
     * talking about the same five fields for either to mean anything.
     */
    private fun serialisedFieldsOf(type: Class<*>): List<Field> =
        type.declaredFields.filterNot { Modifier.isStatic(it.modifiers) || it.isSynthetic }

    private fun report(type: Class<*>): String =
        "${type.simpleName}: " + serialisedFieldsOf(type).map { field ->
            "${field.name} -> ${field.getAnnotation(SerializedName::class.java)?.value}"
        }

    // ── The annotation is present, and lands where Gson reads it ──────────

    @Test
    fun `every serialised field of the payload classes names its own JSON key`() {
        val classes = listOf(Entry::class.java, TypedField::class.java)
        val fields = classes.flatMap { serialisedFieldsOf(it) }

        println(classes.joinToString("; ") { report(it) })

        // Non-vacuity, first: a scan whose field set came back empty would pass over nothing,
        // and every assertion below is a `forEach` over this list.
        assertTrue(
            "the reflected field set must hold at least the five JSON keys the two apps " +
                "exchange; found ${fields.size}: ${fields.map { "${it.declaringClass.simpleName}.${it.name}" }}",
            fields.size >= 5,
        )

        fields.forEach { field ->
            val where = "${field.declaringClass.simpleName}.${field.name}"
            val annotation = field.getAnnotation(SerializedName::class.java)
            assertNotNull(
                "$where is a field Gson serialises, so its JSON key is protocol and must be " +
                    "written down with `@SerializedName` rather than left as the field's name. " +
                    "If the annotation is on the source line and still absent here, Kotlin put " +
                    "it somewhere other than the backing field — use `@field:SerializedName`",
                annotation,
            )
            assertEquals(
                "$where must serialise under its own name. These five strings are the wire " +
                    "format, spelled as JSON literals in nine test files of this package; an " +
                    "annotation that renamed one would move the payload without moving a single " +
                    "Kotlin identifier",
                field.name,
                annotation!!.value,
            )
            assertTrue(
                "$where must declare no alternate spellings: `alternate` makes a key accepted " +
                    "on decode that is never produced on encode, which is a second wire format " +
                    "nothing in this repository pins",
                annotation.alternate.isEmpty(),
            )
        }
    }

    /**
     * The three keys of [Entry] and the two of [TypedField], named individually.
     *
     * The rule above would pass a class that had lost a property, so this is the other direction:
     * these five fields must exist, under these five names, with these five keys. It is the one
     * place in this file where the protocol is spelled out as literals, and it is spelled against
     * `getDeclaredField` — the call that would throw if a property were renamed or removed, which
     * for a published data class is also a stop-rule-10 break.
     */
    @Test
    fun `the five wire keys are present by name`() {
        val expected = mapOf(
            Entry::class.java to listOf("id", "fields", "publicKey"),
            TypedField::class.java to listOf("value", "type"),
        )
        expected.forEach { (type, names) ->
            names.forEach { name ->
                val field = type.getDeclaredField(name)
                assertEquals(
                    "${type.simpleName}.$name must carry `@SerializedName(\"$name\")`",
                    name,
                    field.getAnnotation(SerializedName::class.java)?.value,
                )
            }
        }
    }
}
