package dev.eryalabs.lim

import android.content.Intent
import com.google.gson.Gson
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.lang.reflect.Modifier

/**
 * **The optional half of "blank is defined once", for every field type** — and the two sentences on
 * that page of the guide that no gate here can reach, given the limit they were missing.
 *
 * `docs/INTEGRATION.md:327-329` tells an integrator that blank means one thing: "**Blank is defined
 * once**, by `FieldRequirements`, and the vault and your handler use the same definition: a field
 * that is absent, or whose value is empty or whitespace only." [FieldRequirements]'s `isBlank`
 * ignores [TypedField.type] entirely, so the promise holds by construction, and the guide's
 * Endeavor bullet (`:330-336`) rests its yes/no and date sentences on exactly that.
 *
 * **The measurement that asked for this class was a grep, and the grep was a false negative.**
 * `grep -c 'FieldType\.DATE'` over [FieldRequirementsTest], [FieldRequirementsVerdictTest] and
 * [RequirementsCompatibilityMatrixTest] is **0, 0, 0**, and `INTEGER`, `DECIMAL` and `URL` are
 * absent from all three — but [FieldRequirementsTest]'s `missingRequired treats every blank shape
 * as missing and nothing else` (`:160-246`) enumerates `FieldType.KNOWN + "Colour"` and asserts all
 * three functions over fourteen type-carrying blank shapes — thirteen whitespace spellings
 * (`:176-190`) and the `null`-valued field Gson's `Unsafe` builds (`:197`) — and seven present ones
 * for every one of them, beside two more shapes that carry no type at all (`:191-194`). Its own
 * KDoc already says "blank never depends on [TypedField.type]" (`:142-144`). The required half of
 * the promise was covered **by enumeration rather than by name**, which is why no grep for a type
 * constant could see it. Recorded here rather than quietly inherited.
 *
 * **What that sweep does not reach, and this one does: the optional half.** Its declaration is
 * `FieldRequirements(listOf("f"))` — one field, required, no optional set — and a blank *optional*
 * field takes a different branch in all three functions: [FieldRequirements.missingRequired] stays
 * empty, [FieldRequirements.isSatisfiedBy] is `false` for the *second* of its two clauses, and
 * [FieldRequirements.committed] returns a map with the field **dropped** rather than `null`. That
 * branch is pinned **one case at a time and never systematically**, and the five cases are:
 *
 *  - `Phone` — `FieldRequirementsVerdictTest`'s `a hand-written acknowledgement beside a blank
 *    optional value is HONOURED, and committed drops it`, which is the whole branch, drop included,
 *    and again end to end in `GuideExamplesTest`'s older-vault answer, whose `phone` takes its type
 *    from the client's declaration (`FixtureVault.store`) and so is a `Phone` too;
 *  - `Boolean` — `FieldRequirementsTest`'s `an unanswered yes-no question is blank whether it
 *    arrives absent or empty`, likewise;
 *  - `String` — `a blank optional value in the payload is not satisfied` and `committed drops blank
 *    optional fields and undeclared keys`, which both write the blank optional as `TypedField("")`,
 *    so it is a `String` and not the `Phone` the declaration calls it;
 *  - `Integer` — `ResultBuilderTest`'s `no acknowledgement is written over a payload that does not
 *    satisfy the requirements`, and for the acknowledgement half only: it asserts no
 *    acknowledgement is written and never asks [FieldRequirements.committed];
 *  - `Email` — `RequirementsCompatibilityMatrixTest`'s `a sign-up with every field optional and
 *    every field left blank is a key-only profile, end to end`, whose V2 vault builds a blank
 *    `Email`-typed draft field and drops it through [FieldRequirements.committed]; the
 *    `missingRequired` and drop halves only, since the builder is handed the already-committed
 *    empty map and [FieldRequirements.isSatisfiedBy] is never asked of the draft.
 *
 * Five of the eight, then. `Date`, `Decimal` and `Url` are pinned nowhere on this side, so the
 * guide's own "an optional date that was never picked is dropped" (`:333-334`) rested on nothing.
 * **A probe says how much the type-independence is worth:** making `isBlank` return `false` for a
 * blank `Date` reddens exactly **two** tests in the whole suite, `FieldRequirementsTest`'s sweep
 * and this one.
 *
 * (This list took three drafts. The first claimed `String` and `Boolean` and no other type; the
 * reviewer found `Phone` and `Integer`, and then `Email` in the very test cited further down this
 * comment. A task written to correct a false-negative grep is exactly where the next one gets
 * written, which is why the list names its tests rather than a count, and why the five and the
 * three are now stated as adding up to eight.)
 *
 * Three arms, and none of them belongs in the files above — all six near neighbours are required to
 * pass unmodified, which is what makes this a new instrument rather than an edit to an old one.
 *
 *  1. **The sweep.** Every type in [FieldType.KNOWN] against five value shapes — absent, `""`,
 *     whitespace, a `null` value and a non-blank value — read under a declaration that requires the
 *     swept field and one that makes it optional, with the required reading as the baseline the
 *     optional one is measured beside, and every cell asserted identical to the `String` cell of
 *     the same shape for [FieldRequirements.missingRequired], [FieldRequirements.isSatisfiedBy] and
 *     [FieldRequirements.committed]. One whitespace spelling, not thirteen: that vocabulary is
 *     pinned at `FieldRequirementsTest:176-190` and is not re-bought here, so this fixture carries
 *     a single representative and asserts the property that makes it one.
 *  2. **The census.** Every `String` [FieldType] publishes — a `const val`'s static field or a
 *     plain `val`'s getter, both read — is in [FieldType.KNOWN]. `FieldTypeTest`'s `KNOWN contains
 *     exactly the documented types` pins `KNOWN` against a hand-written list, which is a different
 *     claim: it cannot see a ninth type that was never added to `KNOWN`, and such a type would
 *     escape arm 1 silently.
 *  3. **The enforceable core of a sentence about vaults in the field.** `:736-740` ends "so the
 *     verdict your test sees is the one a real vault produces", which as written is a promise this
 *     library cannot keep. What it can keep is that **the verdict is a function of the answer's
 *     extras alone**, now the guide's own limit at `:766-773`.
 *
 * **Robolectric, because of arm 3 and only arm 3.** Arms 1 and 2 touch no Android type and would
 * run on the bare JVM; [Utils.checkFieldRequirements] takes an [Intent], so the class is annotated
 * rather than split in two for one annotation.
 *
 * **The limit, in three parts.**
 *
 *  - "Blank is defined once" is true of *field values*, which is what that sentence is about.
 *    `Utils` separately treats a blank **extra** as absent — a request code written as `""` reads
 *    as absent, which the guide states at `:829-830` — and that is a different predicate over a
 *    different thing. Nothing here makes the sentence a tree-wide claim.
 *  - The guide's Endeavor bullet describes a vault built in another repository. The half this
 *    library enforces is blankness, the drop and the verdict — swept here, and already end to end
 *    for the key-only profile at `RequirementsCompatibilityMatrixTest:381`. The half about what a
 *    form shows and when Save unblocks is Endeavor's, and no gate here can hold it to any of it.
 *    `:337-344` now says so on the page.
 *  - Arm 3 pins the verdict against the extras, not against any vault. What a vault in the field
 *    sends is not enforced here, and deleting either new guide paragraph reddens nothing:
 *    `GuideSnippetTest` pins fenced blocks and deliberately not prose.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class BlankAcrossTypesTest {

    // ── Arm 1: the sweep ─────────────────────────────────────────────────

    /**
     * What the three functions answered, as one comparable value.
     *
     * [committedKeys] rather than the map itself: [TypedField] equality includes its `type`, and
     * the type is precisely what varies between a cell and its baseline. Which keys survive is the
     * decision under test; that the surviving [TypedField] is the one handed in — type included,
     * untrimmed and unrewritten — is asserted separately, by identity.
     */
    private data class Reading(
        val missing: List<String>,
        val satisfied: Boolean,
        val committedKeys: List<String>?,
    )

    private fun read(requirements: FieldRequirements, values: Map<String, TypedField>) = Reading(
        requirements.missingRequired(values),
        requirements.isSatisfiedBy(values),
        requirements.committed(values)?.keys?.toList(),
    )

    /**
     * The swept field's value, and `anchor`'s, under one type — or the two-field map with `swept`
     * left out when the shape is *absent*.
     *
     * `anchor` is always a filled required field, so a cell can never read as satisfied for the
     * trivial reason that there was nothing to require.
     */
    private fun valuesOf(shape: (String) -> TypedField?, type: String): Map<String, TypedField> {
        val swept = shape(type) ?: return linkedMapOf("anchor" to ANCHOR)
        return linkedMapOf("swept" to swept, "anchor" to ANCHOR)
    }

    /**
     * **The sweep.** Eight published types against five value shapes, each read under a declaration
     * that requires the swept field and one that makes it optional, and every reading asserted
     * equal to the `String` reading of the same shape.
     *
     * The **second** declaration is the new one, and it is what makes this more than two outcomes:
     * with `swept` optional, a blank value is *kept out of* `committed` while `missingRequired`
     * stays empty, and an absent one satisfies the declaration outright. The first declaration
     * repeats, for three of this sweep's shapes (`empty`, `blank`, `null value`), what
     * `FieldRequirementsTest:160-246` already holds for fourteen; it is kept because it is the
     * baseline the optional reading is read beside, and dropping it would leave the interesting
     * half of each cell with nothing to be interesting *against*.
     *
     * Four distinct readings exist across the whole sweep and the test pins that number, so a
     * `FieldRequirements` that answered a constant could not pass by being uniformly
     * type-independent. **That count is the only assertion here a per-cell comparison cannot
     * make:** every cell is read against the `String` cell of its own shape, so a regression that
     * moves all eight types alike moves the baseline with them and no equality notices. Dropping
     * [FieldRequirements.isSatisfiedBy]'s second clause is such a regression — it collapses the
     * blank-optional reading into the absent-optional one, giving three — and the count is what
     * catches it here. It is not the only detector in the suite: that probe reddens seven tests,
     * this one among them.
     */
    @Test
    fun `blankness ignores the declared type, over every known type and every value shape`() {
        val types = FieldType.KNOWN.toList()
        assertEquals("the sweep must enumerate every published type", 8, types.size)

        // The blank fixture is wider than Java's `String.isBlank`, which is the reason
        // `FieldRequirements.kt:29-31` gives for a vault gating Save on that class rather than on
        // a check of its own. Asserted, not assumed: Kotlin calls it blank, and the no-break space
        // in it is one `Character.isWhitespace` rejects — the line separator is not, which is why
        // this asks for one such character and not for all of them.
        assertTrue("the blank fixture must be blank by Kotlin's measure", BLANK.isBlank())
        assertTrue(
            "the blank fixture must contain a space character Java's whitespace test rejects",
            BLANK.any { !Character.isWhitespace(it) },
        )
        assertTrue(
            "and that character must be the no-break space, which is the one that widens",
            !Character.isWhitespace(Char(0x00A0)) && Char(0x00A0) in BLANK,
        )

        // The null-valued shape is only the Unsafe hazard if Gson really leaves the value null.
        val nullValued = SHAPES.getValue("null value")(FieldType.DATE)!!
        @Suppress("SENSELESS_COMPARISON")
        assertTrue(
            "the null-value shape must carry a null value, or it is just another empty string",
            nullValued.value == null,
        )

        val readings = linkedMapOf<String, Reading>()
        var cells = 0

        for ((shape, raw) in SHAPES) {
            val baseline = DECLARATIONS.mapValues { (_, requirements) ->
                read(requirements, valuesOf(raw, FieldType.STRING))
            }
            for (type in types) {
                val values = valuesOf(raw, type)
                for ((declaration, requirements) in DECLARATIONS) {
                    val reading = read(requirements, values)
                    assertEquals(
                        "shape=$shape type=$type declaration=$declaration",
                        baseline.getValue(declaration),
                        reading,
                    )
                    // The decision ignores the type; the value that survives it still carries one,
                    // and it is the very field that was handed in.
                    if (reading.committedKeys?.contains("swept") == true) {
                        assertSame(
                            "committed hands the field back as it was: shape=$shape type=$type",
                            values["swept"],
                            requirements.committed(values)!!["swept"],
                        )
                    }
                    readings["$shape/$declaration"] = reading
                }
                cells++
            }
        }

        println(
            "Blank-across-types sweep — ${types.size} types by ${SHAPES.size} shapes = $cells " +
                "cells, each read under ${DECLARATIONS.size} declarations.\n" +
                "  The *absent* shape carries no type to vary, so ${types.size} of those cells are " +
                "the same input: ${cells - types.size + 1} distinct inputs, not $cells " +
                "independent ones.\n" +
                readings.entries.joinToString("\n") { (cell, reading) ->
                    "  ${cell.padEnd(26)} missing=${reading.missing} " +
                        "satisfied=${reading.satisfied} committed=${reading.committedKeys}"
                },
        )

        assertEquals(
            "the sweep must discriminate: shape and requiredness decide, and nothing else does",
            4,
            readings.values.toSet().size,
        )
    }

    // ── Arm 2: the census ────────────────────────────────────────────────

    /**
     * **Every `String` [FieldType] publishes is in [FieldType.KNOWN]**, so arm 1's enumeration of
     * `KNOWN` is an enumeration of the published type vocabulary rather than of a list that
     * drifted away from it.
     *
     * **Two reflections, because Kotlin publishes a `String` two ways.** A `const val` is a public
     * static field; a plain `val FOO: String` is a *private* backing field plus a public
     * `getFOO()`, so a field-only census would be blind to exactly the ninth type this exists to
     * catch. Both are read, and the union is compared with `KNOWN`.
     *
     * Fields are filtered by **type**, not by visibility: `INSTANCE` is typed [FieldType] and
     * `KNOWN`'s backing field is a `Set` — `LIM/api/lim.api` spells its published form
     * `getKNOWN()`, a getter and not a field — so neither is a `String` and neither needs an
     * excuse. The type is the reason given because it is the durable one: the census prints the
     * visibility beside it, and `KNOWN`'s backing field happens to be private as well, but a
     * future `val` that was not would still not be a `String`. `getKNOWN()` is excluded from the
     * getter half for the same reason, by its return type.
     *
     * `FieldTypeTest`'s `KNOWN contains exactly the documented types` compares `KNOWN` against a
     * hand-written list and stays green against a ninth constant that was never added to `KNOWN`;
     * this is the assertion that does not.
     *
     * **Both halves probed.** A ninth `const val` outside `KNOWN` reddens this, `ApiBaselineTest`
     * twice and `PublicApiAuditTest` twice — five in all — while `FieldTypeTest` stays green. The
     * same constant declared `private` is reported by none of the five, which is the scope this
     * census means: it is a claim about the *published* vocabulary, and a private constant is not
     * part of it.
     */
    @Test
    fun `every String FieldType publishes is in KNOWN`() {
        val constants = FieldType::class.java.declaredFields.filter {
            Modifier.isStatic(it.modifiers) &&
                Modifier.isPublic(it.modifiers) &&
                it.type == String::class.java
        }
        // A public `val FOO: String` on an object reaches a consumer only through this getter.
        // `toString` is named rather than inferred: it is the one no-arg `String` method that
        // could ever be declared here and would not be a type.
        val getters = FieldType::class.java.declaredMethods.filter {
            Modifier.isPublic(it.modifiers) &&
                it.parameterCount == 0 &&
                it.returnType == String::class.java &&
                !it.isSynthetic &&
                it.name != "toString"
        }

        println(
            "FieldType census — published `String`s, by reflection:\n" +
                FieldType::class.java.declaredFields.joinToString("\n") { field ->
                    val counted = field in constants
                    val why = when {
                        counted -> "counted"
                        field.type != String::class.java -> "skipped: not a String"
                        else -> "skipped: not public"
                    }
                    "  field  ${field.name.padEnd(12)} ${field.type.simpleName.padEnd(10)} " +
                        (if (Modifier.isPublic(field.modifiers)) "public  " else "private ") +
                        why +
                        (if (counted && field.get(null) in FieldType.KNOWN) ", in KNOWN" else "")
                } + "\n" +
                FieldType::class.java.declaredMethods.joinToString("\n") { method ->
                    "  method ${method.name.padEnd(12)} " +
                        "${method.returnType.simpleName.padEnd(10)} ${method.parameterCount} args  " +
                        (if (method in getters) "counted" else "skipped")
                },
        )

        assertTrue(
            "the constant filter must match something, or this census measures nothing",
            constants.isNotEmpty(),
        )
        val spellings = constants.map { it.get(null) as String } +
            getters.map { it.invoke(FieldType) as String }
        assertEquals(
            "no two published types may share a spelling",
            spellings.size,
            spellings.toSet().size,
        )
        assertEquals(
            "every String FieldType publishes is in KNOWN, and KNOWN names nothing else",
            FieldType.KNOWN,
            spellings.toSet(),
        )
    }

    // ── Arm 3: the core of a sentence about vaults in the field ──────────

    /**
     * **The verdict is a function of the answer's extras alone.**
     * [Utils.checkFieldRequirements] reads [Utils.EXTRA_FIELDS_JSON] and
     * [Utils.EXTRA_APPLIED_OPTIONAL_FIELDS] and nothing about who sent them, so an answer from
     * this library's builders and a bare hand-built [Intent] carrying those two extras read the
     * same verdict. That is the enforceable core of the guide's "so the verdict your test sees is
     * the one a real vault produces" (`:736-740`), and the guide now says so at `:766-773`.
     *
     * Not already asserted anywhere, re-measured before building this.
     * `FieldRequirementsVerdictTest`'s sweep (`:258-300`) hand-builds every intent and so never
     * compares a built one against a hand-built one; its other tests mix the two but over
     * different payloads. `ResultBuilderTest`'s `a built result declares the version a
     * hand-written one forgets` (`:429-446`) compares a built answer with a hand-written one to
     * assert a **difference** — the version echo — and reads the parsed result rather than the
     * verdict. The equality below is new.
     *
     * **The stripped intent is given an action and a package rather than left without one**, which
     * is the difference between asserting the sentence and assuming it. `createShareResultIntent`
     * writes neither (`Utils.kt:2245-2248`), so a bare `Intent()` differs from a built answer in
     * neither field, and a `checkFieldRequirements` that branched on one would pass a comparison
     * between the two. Setting both to values this protocol never uses is what makes "not the
     * action, not the package" a measurement. The key and the echoed code need no such treatment:
     * the built answer carries them and the stripped one does not.
     *
     * All five verdicts occur, each produced the way it really arises.
     */
    @Test
    fun `the verdict is a function of the answer's extras alone`() {
        val declared = FieldRequirements(listOf("name", "email", "phone"), setOf("phone"))
        val complete = linkedMapOf(
            "name" to TypedField("Ada", FieldType.STRING),
            "email" to TypedField("ada@example.com", FieldType.EMAIL),
        )
        val incomplete = linkedMapOf("name" to TypedField("Ada", FieldType.STRING))

        val cases = linkedMapOf(
            // The acknowledging vault, through the requirements-aware builder.
            FieldRequirementsVerdict.HONOURED to
                Utils.createShareResultIntent(KEY, complete, CODE, declared),
            // A vault on the 1.0.0 API: complete data, no acknowledgement.
            FieldRequirementsVerdict.NOT_ACKNOWLEDGED to
                Utils.createShareResultIntent(KEY, complete, CODE),
            // The same vault, having let the user skip a required field.
            FieldRequirementsVerdict.INCOMPLETE to
                Utils.createShareResultIntent(KEY, incomplete, CODE),
            // A vault that acknowledges a set this client never named.
            FieldRequirementsVerdict.MISMATCHED to
                Utils.createShareResultIntent(KEY, complete, CODE)
                    .putExtra(Utils.EXTRA_APPLIED_OPTIONAL_FIELDS, "[]"),
            // A vault vouching for an answer that falls short — hand-written, as it must be.
            FieldRequirementsVerdict.VIOLATED to
                Utils.createShareResultIntent(KEY, incomplete, CODE)
                    .putExtra(Utils.EXTRA_APPLIED_OPTIONAL_FIELDS, """["phone"]"""),
        )

        for ((expected, answer) in cases) {
            assertEquals(
                "the fixture for $expected must produce it, or the equality below measures nothing",
                expected,
                Utils.checkFieldRequirements(declared, answer),
            )
            assertEquals(
                "$expected: the same two extras, with nothing else at all, read the same verdict",
                expected,
                Utils.checkFieldRequirements(declared, extrasOnly(answer)),
            )
        }

        assertEquals(
            "every verdict must occur, or the equality was checked over a subset",
            FieldRequirementsVerdict.values().toSet(),
            cases.keys,
        )

        // Control: the stripped intent really is stripped and really is differently addressed, so
        // the equality above is not the trivial one of an intent with itself.
        val honoured = cases.getValue(FieldRequirementsVerdict.HONOURED)
        val bare = extrasOnly(honoured)
        assertTrue("the built answer names the vault's key", honoured.hasExtra(Utils.EXTRA_PUBLIC_KEY))
        assertTrue("and echoes the version", honoured.hasExtra(Utils.EXTRA_PROTOCOL_VERSION))
        assertFalse("the stripped intent carries no key", bare.hasExtra(Utils.EXTRA_PUBLIC_KEY))
        assertFalse("and no version echo", bare.hasExtra(Utils.EXTRA_PROTOCOL_VERSION))
        assertFalse("and no request code", bare.hasExtra(Utils.EXTRA_SHARE_REQUEST_CODE))
        assertEquals("a built result carries no action at all", null, honoured.action)
        assertEquals("a built result carries no package either", null, honoured.`package`)
        assertEquals("so the stripped one is given both, and they differ", STRANGER_ACTION, bare.action)
        assertEquals(STRANGER_PACKAGE, bare.`package`)
    }

    /**
     * [answer]'s two requirements extras and nothing else — the whole input the verdict reads —
     * addressed with an action and a package this protocol never uses.
     *
     * Those two are *added* rather than omitted on purpose: a result built by this library has
     * neither (`Utils.kt:2245-2248`), so an intent without them differs from a built answer in no
     * field at all and would prove nothing about either. See the test's KDoc.
     */
    private fun extrasOnly(answer: Intent): Intent {
        val bare = Intent(STRANGER_ACTION).setPackage(STRANGER_PACKAGE)
        answer.getStringExtra(Utils.EXTRA_FIELDS_JSON)
            ?.let { bare.putExtra(Utils.EXTRA_FIELDS_JSON, it) }
        answer.getStringExtra(Utils.EXTRA_APPLIED_OPTIONAL_FIELDS)
            ?.let { bare.putExtra(Utils.EXTRA_APPLIED_OPTIONAL_FIELDS, it) }
        return bare
    }

    private companion object {

        private const val KEY = "a-fake-public-key-from-a-test"
        private const val CODE = "signup-1"

        /** An action and a package no part of this protocol uses — see [extrasOnly]. */
        private const val STRANGER_ACTION = "com.example.not.a.lim.ACTION"
        private const val STRANGER_PACKAGE = "com.example.not.a.vault"

        /** A filled required field in every cell, so "satisfied" is never satisfied by emptiness. */
        private val ANCHOR = TypedField("anchor", FieldType.STRING)

        /**
         * Whitespace only: a space, a tab, a no-break space and a line separator.
         *
         * Built from code points rather than written as literal characters, so the non-ASCII two
         * are legible in the source and cannot be mistaken for ordinary spaces by a reader or
         * normalised away by an editor.
         *
         * **`U+00A0` is the one that widens, and `U+2028` is not.** Kotlin's `isBlank` accepts
         * every Unicode space separator, so it counts the no-break space that Java's
         * `Character.isWhitespace` — and therefore `String.isBlank` — rejects; that is the
         * difference `FieldRequirements.kt:29-31` names, and `FieldRequirementsTest:212-217` pins
         * the codepoints it holds for (`U+00A0`, `U+2007`, `U+202F`, and pointedly not `U+2028`).
         * The line separator is here only as a second non-ASCII character both measures accept.
         * The sweep asserts the widening rather than assuming it.
         */
        private val BLANK: String = String(charArrayOf(' ', '\t', Char(0x00A0), Char(0x2028)))

        /**
         * The value shapes; `null` is the field being absent from the map entirely.
         *
         * The last is the `Unsafe` hazard [Utils.decodeEntry] documents — a [TypedField] whose
         * `value` is `null` although Kotlin declares it non-null — which is a shape that really
         * arrives over IPC. `FieldRequirementsTest:197` sweeps it across types on the required
         * side; this is the optional side of the same shape.
         */
        private val SHAPES: Map<String, (String) -> TypedField?> = linkedMapOf(
            "absent" to { _ -> null },
            "empty" to { type -> TypedField("", type) },
            "blank" to { type -> TypedField(BLANK, type) },
            "filled" to { type -> TypedField("x", type) },
            "null value" to { type -> Gson().fromJson("""{"type":"$type"}""", TypedField::class.java) },
        )

        /** The swept field required, then optional — the two sides of the one definition. */
        private val DECLARATIONS: Map<String, FieldRequirements> = linkedMapOf(
            "swept-required" to FieldRequirements(listOf("swept", "anchor")),
            "swept-optional" to FieldRequirements(listOf("swept", "anchor"), setOf("swept")),
        )
    }
}
