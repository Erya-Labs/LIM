package dev.eryalabs.lim

import com.google.gson.Gson
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.lang.reflect.Field
import java.lang.reflect.Modifier

/**
 * **`LIM/consumer-rules.pro`, the file this library ships into every consumer's R8 run.**
 *
 * `LIM/build.gradle.kts` names this file in its `consumerProguardFiles` call, so AGP packages it
 * into the AAR and every consumer who sets `isMinifyEnabled = true` applies it to their own release
 * build. Until the commit that added this test the file was the 0-byte Android Studio
 * template — along with the artifact AGP had already built from it,
 * `LIM/build/intermediates/merged_consumer_proguard_file/release/.../proguard.txt`, also 0 bytes.
 * The published AAR therefore told every minifying consumer's R8 to keep nothing in this library.
 *
 * **Why that is a wire-format defect and not a packaging nicety.** Gson serialises the fields of
 * [Entry] (`id`, `fields`, `publicKey`) and [TypedField] (`value`, `type`), and those five keys
 * **are** the payload the two apps exchange. A minifying consumer sends `{"a":…,"b":…,"c":…}`; the
 * vault reads `id` and `publicKey` as absent, [Utils.decodeEntry] answers `null`, the sign-up is
 * dropped, no consent dialog opens, and neither app logs a reason.
 *
 * **What names those keys, and why these rules survived it.** When this file was written the keys
 * *were* the JVM field names, with nothing between them. They are now named by `@SerializedName`,
 * one per property, each spelling the field's own name — `WireKeyAnnotationTest` is the file that
 * holds that true and explains the decoupling. The keep rules are still required, and for a reason
 * the annotation cannot cover: an annotation only helps if it *survives* a consumer's R8
 * (`-keepattributes *Annotation*`, which stopped being forward-looking when those five arrived),
 * and a field R8 *removed* has no key at all however it is annotated — which is why rule 3 below
 * refuses `-keepclassmembernames` as insufficient.
 *
 * **What is measured here and what is reasoning, labelled rather than left to a reader.** No gate in
 * this repository runs R8 over these classes: `isMinifyEnabled = false` in `LIM/build.gradle.kts`,
 * which is correct for a library, because R8 runs in the *consumer's* build. So "R8 would rename
 * these fields" is **configuration reasoning, not a measurement**, and the rules file says so in its
 * own header too. What *is* measured is the half that can be — rule 3's first assertion compares
 * `Entry::class.java.declaredFields` against the keys `Gson().toJson` actually emits, so the claim
 * "every field these rules keep is a field on the wire, under its own name" is reflection rather
 * than belief. A `@SerializedName` renaming a key, or a field-naming policy arriving, reddens it.
 *
 * **Nine rules.**
 *
 *  1. Every non-blank, non-comment line belongs to a directive whose keyword is on a named
 *     allow-list. This is a **vocabulary check, not R8's parser**: it says every directive's
 *     keyword is one of the five this project has written reasons for — five *keywords*, not five
 *     directives — and says nothing about whether R8 would accept the rest of the line.
 *  2. Every directive carries a comment on the line immediately above it, so a rule with no stated
 *     reason fails. Immediately above, with no blank line between, so the pairing of a reason to its
 *     directive is unambiguous — and so that the file's header block cannot stand in as the reason
 *     for the first directive.
 *  3. Every non-static, non-synthetic declared field of every class in [COVERED_CLASSES] has a
 *     covering rule of a **sufficient form**. The field set comes from reflection and never from a
 *     list of names, which is what makes a field added to [Entry] tomorrow red today.
 *  4. Dead-rule hygiene, in three directions: a rule naming a class that does not exist, a rule
 *     naming a field its class does not declare, and a rule naming a real field with the wrong
 *     type. The third matters because a member spec whose type is wrong matches *nothing* — R8
 *     accepts it in silence and removes the field anyway.
 *  5. The `Gson()` call sites in the main sources are exactly the four these rules were written
 *     against, matched **by content rather than by line number**, so a fifth serialised type cannot
 *     arrive without this file being looked at.
 *  6. Floors, printed: at least [MINIMUM_COVERED_CLASSES] covered classes,
 *     [MINIMUM_COVERED_FIELDS] covered fields and [MINIMUM_DIRECTIVES] directives. The directive
 *     floor sits **below** the count on disk on purpose, so a control that deletes one directive
 *     reports the rule it was aimed at instead of burying it under a floor failure.
 *  7. **Every directive rule 3's field census cannot reach is required by name** — see
 *     [REQUIRED_DIRECTIVES]. Three of them are not about members at all (`-keepattributes
 *     Signature`, `-keepattributes *Annotation*`, the `TypeToken` keep) and two are member specs
 *     over a *static* `CREATOR`, which rule 3 excludes because Gson never serialises a static
 *     field. Rules 1–4 are field- and vocabulary-shaped and rule 6's floor sits below the count, so
 *     without rule 7 deleting `-keepattributes Signature` — the line `decodeFields` depends on —
 *     would leave the directive count above its floor with every field still covered, and nothing
 *     red. That was computed before the rule existed; the `CREATOR` pair was added to it after a
 *     review deleted both of those directives and watched all fifteen tests stay green. Rule 9 now
 *     catches a line deleted from *this file alone*, because the guide would still print it — but
 *     not one deleted from both sides, which is the case rule 7 is still the only answer to.
 *  8. Every member spec is balanced: every `{` closed, nothing left open. Two lines, and the one
 *     check here that is **parser-shaped rather than vocabulary-shaped** — unlike rule 1, this is
 *     about something R8 would actually reject. It covers the failure mode that is both unverifiable
 *     from this repository and expensive where it lands: the file is parsed on a *consumer's*
 *     machine, by their R8, so a stray brace breaks their release build rather than anything of
 *     ours.
 *  9. **The copy of these rules printed in `docs/INTEGRATION.md` holds this file's own directive
 *     lines — set-equal both ways, and in the same sequence.** AGP packages this file into the AAR,
 *     but the guide's only working install path is vendoring the AAR into `libs/`, and whether a
 *     *file* dependency's packaged `proguard.txt` reaches R8 is not answerable from here — so the
 *     guide tells the integrator to copy the rules, and the copy is part of what this library ships.
 *
 * **What the rules deliberately do not pin.** Any *particular* directive order: reorder this file
 * **and the guide's copy of it together** and nothing reddens, because order is not meaningful to R8
 * and an assertion over it would be a false pin. Reordering one of the two documents alone *does*
 * redden, on rule 9's sequence check — the two claims are different, and the second is what stops a
 * member spec migrating between two `-keep class` blocks in one document and not the other. The
 * wording of any comment, because the file is
 * prose plus directives and only the directives are pinned. And the member specs of any class
 * outside [COVERED_CLASSES] — the signed-statement classes hand-encode their pre-images field by
 * field, never travel through Gson (`RotationStatement.kt:33`) and are not `Parcelable`, so they
 * are given no rules and the rules file says why in a comment.
 *
 * **The limit of rule 5, stated rather than implied.** It reads a main source as *text*, so it
 * inherits the hole the standing "Blocked on human" cache item describes: the test task fingerprints
 * the main sources as compiled output, so a comment-only edit that adds a `Gson()` mention to a main
 * source can leave `:LIM:testDebugUnitTest` UP-TO-DATE and this rule unexecuted. This class is the
 * **third** verifier behind that item, after `KDocCoverageTest` and `ChangelogTest`; the fix is a
 * decision about the Gradle cache that is already logged for the human, and is not closed here. The
 * rules file itself is a declared input of the test task (`LIM/build.gradle.kts`, held honest by
 * `BuildInputsTest`), so an edit to *it* does re-run this class.
 *
 * **One more limit, conservative in the safe direction.** Rule 3 credits a field as covered only
 * when a directive's class spec is the exact fully-qualified name. A legitimate
 * `-keep class dev.eryalabs.lim.** { *; }` would therefore be reported as covering nothing — a
 * false red rather than a false green, and the repair is to spell the class out, which is what this
 * project's "every rule names its reason and its call site" habit wants anyway.
 *
 * Regex over one text file and the main sources, plus reflection over two classes: no Robolectric,
 * no Gradle, and — the point of the whole file — no R8.
 */
class ConsumerRulesTest {

    // ── What the rules file contains ──────────────────────────────────────

    /**
     * One member spec inside a directive's braces, as the three parts ProGuard spells: access
     * modifiers, a type and a name.
     *
     * All three are read, and each of the first two is a way a rules file can fail **green**. R8
     * does not report a member spec that matches nothing — it keeps nothing and removes the field —
     * so a rule 3 that compared only names would certify a field as kept while the shipped rule set
     * let R8 delete it.
     *
     *  * **The type.** Spelled wrong, the spec matches no member. The wildcards are not
     *    interchangeable either, which a first draft of this class got wrong and a review caught:
     *    `***` matches any type, `**` any *reference* type, `%` only a **primitive**, and a bare
     *    `*` only a class name with **no package separator**. So `% id;` and `* id;` both match
     *    nothing on a `java.lang.String` field, and accepting them as "any type" was a hole wide
     *    enough to keep all five wire keys unprotected while every assertion here stayed green —
     *    measured, not reasoned about: a file spelling all five fields `%` passed 13 of 13.
     *  * **The modifiers.** Kotlin compiles a `val` to a **private** backing field, so
     *    `public java.lang.String id;` matches nothing. Each modifier is therefore checked against
     *    the field's real modifiers rather than skipped over on the way to the type.
     *
     * A token in the modifier position that is not a modifier this class knows how to judge makes
     * the spec match nothing and is reported by rule 4, which is the fail-closed direction.
     */
    private class MemberSpec(
        val modifiers: List<String>,
        val type: String?,
        val name: String,
    ) {
        /** How a failure should name it. */
        val described: String =
            (modifiers + listOf(type ?: "<no type>", name)).joinToString(" ")

        fun matches(field: Field): Boolean =
            name == field.name &&
                typeMatches(field) &&
                modifiers.all { modifierHolds(it, field) }

        private fun typeMatches(field: Field): Boolean = when (type) {
            null -> false
            ANY_TYPE -> true
            ANY_REFERENCE_TYPE -> !field.type.isPrimitive
            ANY_PRIMITIVE_TYPE -> field.type.isPrimitive
            // `name` spells an array `[Ljava.lang.String;` where ProGuard spells it
            // `java.lang.String[]`, so the canonical spelling is accepted — but **only** for an
            // array. The two names also differ for a *nested* class, `android.os.Parcelable$Creator`
            // against `android.os.Parcelable.Creator`, and there ProGuard's grammar requires the
            // `$`: accepting the dotted form would wave through a spec that resolves to a class
            // called `android/os/Parcelable/Creator` and matches nothing. An unguarded
            // `canonicalName` did exactly that — the first draft of this arm accepted a dotted
            // `CREATOR` spec with all fifteen tests green, which a review measured.
            else -> type == field.type.name ||
                (field.type.isArray && type == field.type.canonicalName)
        }

        /**
         * Whether [modifier] — possibly `!`-negated, as ProGuard allows — holds of [field].
         *
         * An unrecognised token answers `false` either way, so a spec this class cannot judge is
         * treated as covering nothing rather than as covering everything.
         */
        private fun modifierHolds(modifier: String, field: Field): Boolean {
            val negated = modifier.startsWith("!")
            val present = when (modifier.removePrefix("!")) {
                "public" -> Modifier.isPublic(field.modifiers)
                "private" -> Modifier.isPrivate(field.modifiers)
                "protected" -> Modifier.isProtected(field.modifiers)
                "static" -> Modifier.isStatic(field.modifiers)
                "final" -> Modifier.isFinal(field.modifiers)
                "transient" -> Modifier.isTransient(field.modifiers)
                "volatile" -> Modifier.isVolatile(field.modifiers)
                "synthetic" -> field.isSynthetic
                else -> return false
            }
            return present != negated
        }
    }

    /** One logical directive: possibly several lines, if it has a member spec. */
    private class Directive(
        /** The first token, e.g. `-keep`. Rule 1's subject. */
        val keyword: String,
        /** The whole directive with its whitespace collapsed. Rule 7's subject. */
        val normalised: String,
        /** The 1-based line its first line sits on, so every failure can cite it. */
        val line: Int,
        /** The class spec, or `null` when it is a wildcard rather than a name. */
        val classSpec: String?,
        /** Every concrete class name the directive mentions: the spec and any supertype. */
        val classNames: List<String>,
        val members: List<MemberSpec>,
        /** `<fields>;` or `*;` — every field of the class, however many there are. */
        val allFields: Boolean,
    )

    /** Every complaint the rules file produces, so the real tests and the controls share one loop. */
    private class Report(
        val directives: List<Directive>,
        /** (1) Lines that are neither blank, comment nor directive, and disallowed keywords. */
        val vocabulary: List<String>,
        /** (2) Directives with no comment immediately above them. */
        val uncommented: List<String>,
        /** (3) Serialised fields with no covering rule at all. */
        val uncovered: List<String>,
        /** (3) Serialised fields named only by a form that permits removal. */
        val insufficient: List<String>,
        /** (4) Rules naming a class, a field or a field type that does not exist. */
        val dead: List<String>,
        /** (8) Directives whose member spec was never closed. */
        val unbalanced: List<String>,
        /** (6) Classes every one of whose fields is covered. */
        val coveredClasses: List<String>,
        /** (6) How many serialised fields are covered by a sufficient form. */
        val coveredFields: Int,
    )

    /**
     * [rules] parsed into directives and judged against [COVERED_CLASSES].
     *
     * A directive begins at a line whose first character is `-` and runs until its braces balance,
     * which is what makes a multi-line member spec one directive rather than four stray lines.
     *
     * **Comments are stripped per line before anything is counted**, because `#` runs to the end of
     * its line *anywhere* in a ProGuard file — including inside a member spec, which is exactly
     * where this file's "every rule states its reason" habit invites one. A first draft counted the
     * raw line, so a comment between two member specs swallowed the spec below it and reported a
     * correctly-kept field as uncovered; a `}` inside such a comment ended the directive early. A
     * review caught both.
     *
     * **A directive whose braces never balance is reported and then abandoned**, with parsing
     * resumed on the line after it. Running to the end of the file instead would make one stray `{`
     * near the top report every directive below it as missing, so rule 7 would drown rule 8's
     * finding in noise about rules that are present.
     */
    private fun parse(rules: String): Report {
        val lines = rules.lines()
        val code = lines.map { it.substringBefore(COMMENT_MARKER) }
        val directives = mutableListOf<Directive>()
        val vocabulary = mutableListOf<String>()
        val uncommented = mutableListOf<String>()
        val unbalanced = mutableListOf<String>()

        // Lines an abandoned member spec would have held. Suppressed from rule 1 so that rule 8's
        // finding is not buried under a stray-line complaint for every member below the stray `{`.
        val swallowed = mutableSetOf<Int>()

        var commented = false
        var index = 0
        while (index < lines.size) {
            val trimmed = code[index].trim()
            if (trimmed.isEmpty()) {
                // A whole-line comment pairs with the directive below it; a blank line breaks that
                // pairing on purpose. See rule 2.
                commented = lines[index].trim().startsWith(COMMENT_MARKER)
                index++
                continue
            }
            if (!trimmed.startsWith(DIRECTIVE_MARKER)) {
                if (index !in swallowed) {
                    vocabulary += "${index + 1}: `$trimmed` is neither a comment nor a directive"
                }
                commented = false
                index++
                continue
            }

            val first = index
            val body = StringBuilder()
            var depth = 0
            var closed = false
            while (index < lines.size) {
                if (body.isNotEmpty()) body.append('\n')
                body.append(code[index])
                depth += code[index].count { it == '{' } - code[index].count { it == '}' }
                index++
                if (depth <= 0) {
                    closed = true
                    break
                }
            }
            if (!closed) {
                unbalanced += "${first + 1}: `$trimmed` leaves $depth `{` unclosed at end of file"
                // Abandon it and carry on below its first line rather than consuming the rest, so
                // a directive further down is still found and rule 7 does not report it missing.
                swallowed += (first + 1) until index
                index = first + 1
            }
            if (!commented) uncommented += "${first + 1}: `$trimmed`"
            commented = false
            directives += directiveOf(body.toString(), first + 1)
        }

        val opens = code.sumOf { line -> line.count { it == '{' } }
        val closes = code.sumOf { line -> line.count { it == '}' } }
        if (opens != closes) {
            unbalanced += "the file holds $opens `{` and $closes `}`; R8 parses this on a " +
                "consumer's machine, so the imbalance breaks their release build"
        }

        vocabulary += directives
            .filterNot { it.keyword in ALLOWED_DIRECTIVES }
            .map { "${it.line}: `${it.keyword}` is not one of $ALLOWED_DIRECTIVES" }

        val uncovered = mutableListOf<String>()
        val insufficient = mutableListOf<String>()
        val coveredClasses = mutableListOf<String>()
        var coveredFields = 0
        for (className in COVERED_CLASSES) {
            val fields = serialisedFieldsOf(className)
            var whole = true
            for (field in fields) {
                val naming = directives.filter {
                    it.classSpec == className &&
                        (it.allFields || it.members.any { member -> member.matches(field) })
                }
                when {
                    naming.any { it.keyword in SUFFICIENT_FORMS } -> coveredFields++
                    naming.isNotEmpty() -> {
                        whole = false
                        insufficient += "$className.${field.name} is named only by " +
                            naming.map { it.keyword }.distinct().sorted().joinToString(", ") +
                            ", which forbids renaming but still permits removal"
                    }
                    else -> {
                        whole = false
                        uncovered += "$className.${field.name}"
                    }
                }
            }
            if (whole) coveredClasses += className
        }

        return Report(
            directives = directives,
            vocabulary = vocabulary.sorted(),
            uncommented = uncommented,
            uncovered = uncovered.sorted(),
            insufficient = insufficient.sorted(),
            dead = deadRulesIn(directives),
            unbalanced = unbalanced,
            coveredClasses = coveredClasses,
            coveredFields = coveredFields,
        )
    }

    /** One directive's text, as the class, members and supertypes it names. */
    private fun directiveOf(text: String, line: Int): Directive {
        val spec = CLASS_SPEC.find(text)?.groupValues?.get(1)
        val supertypes = SUPERTYPE_SPEC.findAll(text).map { it.groupValues[1] }.toList()

        val members = mutableListOf<MemberSpec>()
        var allFields = false
        val braced = text.substringAfter('{', "").substringBeforeLast('}', "")
        for (member in braced.split(MEMBER_SEPARATOR)) {
            val spelled = member.trim()
            if (spelled.isEmpty() || spelled.startsWith(COMMENT_MARKER)) continue
            if ('(' in spelled) continue // a method or a constructor, not a field
            if (spelled in ALL_MEMBERS) {
                allFields = true
                continue
            }
            // `[@annotation] [modifier]* type name` — the name is last, the type is the token
            // before it, and everything earlier is a modifier that has to hold of the field rather
            // than be stepped over on the way to the type. See [MemberSpec].
            val tokens = spelled.split(WHITESPACE)
            members += MemberSpec(
                modifiers = tokens.dropLast(2),
                type = tokens.dropLast(1).lastOrNull(),
                name = tokens.last(),
            )
        }

        val firstLine = text.lines().first().trim()
        return Directive(
            keyword = firstLine.substringBefore(' ').substringBefore('{').trim(),
            normalised = text.replace(WHITESPACE, " ").trim(),
            line = line,
            classSpec = spec?.takeIf { it.isAName() },
            classNames = (listOfNotNull(spec) + supertypes).filter { it.isAName() },
            members = members,
            allFields = allFields,
        )
    }

    /** Rule 4, in its three directions. */
    private fun deadRulesIn(directives: List<Directive>): List<String> {
        val complaints = mutableListOf<String>()
        for (directive in directives) {
            for (className in directive.classNames) {
                if (loadClass(className) == null) {
                    complaints += "${directive.line}: no class `$className` exists, so this rule " +
                        "matches nothing"
                }
            }
            val type = directive.classSpec?.let { loadClass(it) } ?: continue
            for (member in directive.members) {
                val named = type.declaredFields.filter { it.name == member.name }
                when {
                    named.isEmpty() ->
                        complaints += "${directive.line}: `${directive.classSpec}` declares no " +
                            "field `${member.name}`, so this rule matches nothing"
                    named.none { member.matches(it) } ->
                        complaints += "${directive.line}: `${directive.classSpec}.${member.name}` " +
                            "is declared `${declarationOf(named.first())}`, which the spec " +
                            "`${member.described}` does not match; a member spec whose type or " +
                            "access modifier is wrong matches nothing, and R8 says so to nobody. " +
                            "Note that Kotlin compiles a `val` to a *private* field"
                }
            }
        }
        return complaints
    }

    // ── Rule 1: the vocabulary ────────────────────────────────────────────

    /**
     * (1) Nothing in the file but comments and directives from the allow-list.
     *
     * A **vocabulary** check and not R8's parser: it says every directive's *keyword* is one of the
     * five this project has written reasons for, and says nothing about whether R8 would accept the
     * rest of any line. (Five *keywords*, not five directives — the file holds more directives than
     * that, and rule 6 prints how many.) Rule 8 is the parser-shaped one.
     */
    @Test
    fun `every line is a comment or a directive from the allow-list`() {
        assertEquals(
            "${RULES_PATH} may only contain comments and directives whose keyword is one of " +
                "$ALLOWED_DIRECTIVES. This is a vocabulary check: each of those five keywords has " +
                "a stated reason in the file, and a directive outside the list is a decision " +
                "nobody wrote down. " +
                "`-dontobfuscate` in particular is refused rather than merely absent — whether to " +
                "obfuscate is the consumer's decision about the consumer's app, and a library that " +
                "disables it from inside an AAR has overridden a choice that was never its own",
            emptyList<String>(),
            onDisk().vocabulary,
        )
    }

    // ── Rule 2: every directive states its reason ─────────────────────────

    /** (2) A rule with no comment immediately above it is a rule nobody can review. */
    @Test
    fun `every directive is preceded by a comment giving its reason`() {
        assertEquals(
            "every directive in $RULES_PATH must carry a comment on the line immediately above " +
                "it, naming why the rule exists and the call site that needs it. Immediately " +
                "above, with no blank line between, so the pairing is unambiguous and the file's " +
                "header block cannot stand in as the reason for the first directive",
            emptyList<String>(),
            onDisk().uncommented,
        )
    }

    // ── Rule 3: every serialised field is kept, in a form that keeps it ───

    /**
     * (3) The fields Gson reflects over, from reflection, each covered by a sufficient form.
     *
     * The first assertion is the **measurement** the rest of this file rests on: the keys Gson
     * emits are exactly the field names this file's directives keep. That was once true because
     * nothing stood between the two; it is now true because each of the five `@SerializedName`
     * annotations spells its own field's name, and this assertion is what would notice either of
     * those arrangements breaking. The second
     * and third are the rule — and the third is why rule 3 is about semantics rather than spelling:
     * `-keepclassmembernames` forbids renaming but still permits *removal*, and a field only ever
     * written reflectively looks unused to R8, so a names-only spelling is reported as insufficient
     * rather than accepted.
     */
    @Test
    fun `every serialised field has a covering rule of a sufficient form`() {
        val entry = Entry(
            id = "entry-1",
            fields = mapOf("email" to TypedField(value = "a@b.test", type = FieldType.EMAIL)),
            publicKey = "MIIB-not-a-real-key",
        )
        assertEquals(
            "the keys `Gson().toJson` emits for an Entry must be exactly its declared field " +
                "names. This is the measurement the whole rules file rests on: the directives " +
                "below name fields, so a key that is no longer its field's name is a key no " +
                "keep rule protects. Each of these is named by a `@SerializedName` spelling the " +
                "field's own name; change one of those strings, or add a field-naming policy, " +
                "and these keep rules stop being about the wire format",
            serialisedFieldsOf(ENTRY).map { it.name }.sorted(),
            Gson().toJsonTree(entry).asJsonObject.keySet().sorted(),
        )
        assertEquals(
            "…and the same for TypedField, the other half of the payload",
            serialisedFieldsOf(TYPED_FIELD).map { it.name }.sorted(),
            Gson().toJsonTree(entry.fields.values.first()).asJsonObject.keySet().sorted(),
        )

        assertEquals(
            "every field Gson reflects over must have a keep rule in $RULES_PATH naming it, or a " +
                "consumer's R8 *removes* it and there is no field left to carry a key at all — " +
                "which is the live hazard now that `@SerializedName` pins each key to a string, " +
                "and the reason the next assertion refuses a names-only form. The field set here " +
                "comes from reflection, never from a list of names, so a field added to one of " +
                "these classes is red on the run that compiles it",
            emptyList<String>(),
            onDisk().uncovered,
        )
        assertEquals(
            "a field may not be covered by `$NAMES_ONLY_FORM` alone. That form prevents renaming " +
                "but still allows R8 to *remove* the member, and a field that is only ever written " +
                "reflectively looks unused — so the rule has to be `-keep` or " +
                "`-keepclassmembers`, which refuse both",
            emptyList<String>(),
            onDisk().insufficient,
        )
    }

    // ── Rule 4: no rule that matches nothing ──────────────────────────────

    /** (4) Dead rules in all three directions: class, field name, field type. */
    @Test
    fun `no rule names a class, a field or a type that does not exist`() {
        assertEquals(
            "a rule in $RULES_PATH names something that does not exist, so it matches nothing. " +
                "R8 does not report that — it keeps nothing and removes the member anyway — which " +
                "makes a dead rule indistinguishable from a kept field until a user's install " +
                "fails",
            emptyList<String>(),
            onDisk().dead,
        )
    }

    // ── Rule 5: the call sites these rules were written against ───────────

    /**
     * (5) Exactly four `Gson()` call sites in the main sources, matched by content.
     *
     * By content rather than by line number, so ordinary edits above them are not a false alarm
     * while a *fifth* serialised type cannot arrive without this file being looked at. Comments are
     * masked first: `Utils.kt`'s KDoc warns "do not use `Gson().fromJson` on this string", and
     * counting prose as a call site would let a doc comment satisfy a call-site rule — the repair to
     * refuse rather than the one to take.
     *
     * See this class's header for the limit: this rule reads a main source as text, and a
     * comment-only edit to a main source can leave the test task UP-TO-DATE and this rule
     * unexecuted.
     */
    @Test
    fun `the Gson call sites in the main sources are exactly the four these rules cover`() {
        val sites = gsonSites()
        assertEquals(
            "the keep rules in $RULES_PATH were written against these four call sites and no " +
                "others. A fifth means a type is being serialised that nothing here has covered — " +
                "add its rules and its reason, then extend this list. Found: " +
                sites.map { it.where },
            GSON_CALL_SITES.sorted(),
            sites.map { it.code }.sorted(),
        )
        assertTrue(
            "the comment mask must leave the prose mention of `Gson().fromJson` in Utils.kt's " +
                "KDoc out of the count; finding five here means the mask stopped working and a " +
                "doc comment is being counted as a call site. Found: " + sites.map { it.where },
            sites.size == GSON_CALL_SITES.size,
        )
    }

    // ── Rule 6: floors, printed ───────────────────────────────────────────

    /**
     * (6) Floors against an empty scan, each printed — on a green run as well as a red one, so the
     * measurement is in the record and not only in a failure nobody saw.
     *
     * [MINIMUM_DIRECTIVES] sits **below** the count on disk deliberately: a control that deletes
     * one directive should report the rule it was aimed at — rule 3 or rule 7 — rather than burying
     * it under a floor failure. The 0-byte file this test was written against reddens the floor
     * anyway.
     */
    @Test
    fun `the covered set and the rule count are above the floors measured when this file was written`() {
        val report = onDisk()
        println(
            "$RULES_PATH: ${report.coveredClasses.size} covered classes " +
                "(floor $MINIMUM_COVERED_CLASSES), ${report.coveredFields} covered fields " +
                "(floor $MINIMUM_COVERED_FIELDS), ${report.directives.size} directives " +
                "(floor $MINIMUM_DIRECTIVES)",
        )
        assertTrue(
            "$RULES_PATH must cover at least $MINIMUM_COVERED_CLASSES classes wholly. Covered: " +
                "${report.coveredClasses} of $COVERED_CLASSES",
            report.coveredClasses.size >= MINIMUM_COVERED_CLASSES,
        )
        assertTrue(
            "…and at least $MINIMUM_COVERED_FIELDS fields, which is the number of JSON keys the " +
                "two apps exchange. Covered: ${report.coveredFields}",
            report.coveredFields >= MINIMUM_COVERED_FIELDS,
        )
        assertTrue(
            "…and hold at least $MINIMUM_DIRECTIVES directives, a floor set below the count on " +
                "disk so that deleting one reports the rule it was aimed at instead of this. " +
                "Found ${report.directives.size}: ${report.directives.map { it.keyword }}",
            report.directives.size >= MINIMUM_DIRECTIVES,
        )
    }

    // ── Rule 7: the directives rule 3 cannot reach, by name ───────────────

    /**
     * (7) Every directive rule 3's field census cannot reach, each required by name.
     *
     * Rule 3 enumerates the **non-static** fields Gson serialises, so three kinds of directive sit
     * outside it: the two `-keepattributes` lines, the `TypeToken` keep, and the two `CREATOR`
     * specs — `CREATOR` being static, and Gson not serialising static fields.
     *
     * Each one was shown to be invisible to every other rule before being listed here. Deleting
     * `-keepattributes Signature` leaves the directive count above rule 6's floor with every field
     * still covered; deleting both `CREATOR` directives did the same, and a review demonstrated it
     * by watching all fifteen tests stay green. Computed and measured, not assumed.
     *
     * Rule 9 has since narrowed the gap without closing it: a line taken out of this file alone now
     * reddens the guide equality too, because `docs/INTEGRATION.md` still prints it. A line taken
     * out of *both* is seen by this rule and nothing else.
     */
    @Test
    fun `the directives rule 3 cannot reach are each present by name`() {
        val spelled = onDisk().directives.map { it.normalised }
        assertEquals(
            "each of these directives must appear in $RULES_PATH verbatim. None of them is " +
                "something rules 1-4 can see — three are not about members at all, and the two " +
                "`CREATOR` specs name a *static* field, which rule 3 excludes because Gson does " +
                "not serialise one — while rule 6's floor sits below the directive count. Rule 9 " +
                "would catch a deletion from this file alone, since the guide would still print " +
                "the line, but not one taken out of both; without this rule that case is green. " +
                "`Signature` carries the " +
                "`Map<String, TypedField>` type argument of the anonymous TypeToken; " +
                "`*Annotation*` is what makes the five `@SerializedName` keys survive; the " +
                "TypeToken " +
                "keep is what stops R8's full mode stripping that subclass and taking the " +
                "signature with it; and the two `CREATOR` rules keep the field the platform looks " +
                "up reflectively to unparcel a published `Parcelable`. Found: $spelled",
            emptyList<String>(),
            REQUIRED_DIRECTIVES.filterNot { it in spelled },
        )
    }

    // ── Rule 8: the braces R8 would reject ────────────────────────────────

    /**
     * (8) Every member spec closed.
     *
     * The one **parser-shaped** check in this file — unlike rule 1's vocabulary, this is about
     * something R8 would actually refuse. It is here because the file is parsed on a *consumer's*
     * machine: a stray brace breaks their release build, and nothing in this repository would ever
     * see it.
     */
    @Test
    fun `every member spec is balanced`() {
        assertEquals(
            "a member spec in $RULES_PATH is left open. R8 parses this file in a consumer's " +
                "build, so an unbalanced brace is a broken release build in somebody else's " +
                "project and a green suite in this one",
            emptyList<String>(),
            onDisk().unbalanced,
        )
    }

    // ── Rule 9: the guide prints these rules, because one install path may not carry them ─

    /**
     * (9) `docs/INTEGRATION.md`'s one ` ```proguard ` block holds these directive lines, both ways.
     *
     * **Why the guide has to print them at all.** AGP packages this file into the AAR, so a consumer
     * who resolves the library as a *dependency* gets these rules whether they read a word of the
     * guide. No release has been cut, so that is not the install path anybody is on: the guide's
     * only working one is vendoring the AAR into `libs/` (`docs/INTEGRATION.md`, "Until then: build
     * from source"). Whether AGP hands a **file** dependency's packaged `proguard.txt` to R8 is not
     * answerable from this repository — nothing here builds a consumer project — so the guide tells
     * the integrator to copy the rules into their own file rather than asserting either answer. That
     * makes the printed copy part of the shipped rule set, and a printed copy that drifts is worse
     * than none: it is the integrator's only sight of what has to survive their R8.
     *
     * **Set equality, in both directions, printed in one failure.** A line in the file and not in
     * the guide is a rule an integrator on the vendoring path will not have; a line in the guide and
     * not in the file is a rule this library does not actually ship, which sends somebody to debug
     * the wrong thing. Neither direction subsumes the other, and the two are collected into **one**
     * list of labelled complaints rather than asserted one after the other on purpose: a
     * one-character drift is a miss in *both* directions at once, and two assertions would print the
     * first and stop, naming the line that went missing while withholding the line that replaced
     * it — which is the actionable half.
     *
     * **And the sequence, because a set is not enough.** Two sets can be equal while the *order* is
     * not, and order is what attaches a member spec to a class: move `java.util.Map fields;` out of
     * the `Entry` block and into the `TypedField` one in the guide alone and the set is unchanged to
     * the byte, while the block an integrator copies leaves `Entry.fields` free for R8 to remove and
     * names a `fields` member on `TypedField` that matches nothing — the exact silent failure the
     * section tells its reader to watch for, printed by the guide and blessed by the test. A review
     * found that hole in the set-only first draft. So the lines are compared **as a sequence** too,
     * which also pins the duplicate lines a set collapses: the three `}` and the two identical
     * `CREATOR` specs. The set differences are asserted *first*, because they are what names the
     * line and the direction; the sequence is what the reordering case falls to.
     *
     * **What this does and does not pin.** Comments are stripped per line — by
     * [directiveLinesIn], the same `#`-to-end-of-line rule [parse] applies — so the block's prose
     * and this file's are independent, and the guide is **not** claimed to be byte-equal to the
     * file. Blank lines go too, so the paragraph breaks between groups of directives are each
     * document's own. Leading whitespace is trimmed, so a member spec's indentation is not pinned
     * across a Markdown fence. Nothing here says the guide's copy would *work*: no gate in this
     * repository runs R8, which is this whole file's standing caveat.
     *
     * **The locator fails loudly.** Exactly one ` ```proguard ` block is required, because a locator
     * that found none would leave the comparison running against nothing and reporting every line of
     * this file as missing from the guide — technically red, but red for the wrong reason, naming
     * fourteen lines when the finding is "there is no block". The floor below is what stops the
     * mirror case from going quiet. `GuideSnippetTest` excuses that fence by name and cites this
     * test, so the two halves cannot be separated without one of them reddening.
     */
    @Test
    fun `the integration guide prints the rules this file ships`() {
        val guide = locate(GUIDE_PATH)
        val blocks = fencedBlocks(guide.readLines(), RULES_FENCE_LANGUAGE)
        assertEquals(
            "$GUIDE_PATH must hold exactly one ```$RULES_FENCE_LANGUAGE block — the keep rules an " +
                "integrator copies when they vendor the AAR. Finding none would make the equality " +
                "below compare the file against nothing, and finding two would leave one of them " +
                "unchecked. Found ${blocks.size}",
            1,
            blocks.size,
        )
        val printed = directiveLinesIn(blocks.single())
        val shipped = directiveLinesIn(locate(RULES_PATH).readLines())
        println(
            "$RULES_PATH: ${shipped.size} directive lines, ${shipped.toSet().size} distinct " +
                "(floor $MINIMUM_PRINTED_LINES); ${printed.size} printed in $GUIDE_PATH",
        )
        assertTrue(
            "$RULES_PATH must hold at least $MINIMUM_PRINTED_LINES distinct non-comment lines for " +
                "the comparisons below to mean anything; a comment-stripper that blanked the file " +
                "would otherwise make two empty sequences equal. Found ${shipped.toSet().size}",
            shipped.toSet().size >= MINIMUM_PRINTED_LINES,
        )
        assertEquals(
            "the keep rules $GUIDE_PATH prints have drifted from the ones $RULES_PATH ships. A " +
                "line only in the file is a rule an integrator who vendored the AAR and copied the " +
                "block will not have; a line only in the guide is a rule this library does not " +
                "ship, which sends somebody to keep a class on its account that it never asked " +
                "for. The file is the source of truth: copy it across rather than editing it to " +
                "match the guide",
            emptyList<String>(),
            (shipped.toSet() - printed.toSet()).sorted().map { "only in $RULES_PATH: `$it`" } +
                (printed.toSet() - shipped.toSet()).sorted().map { "only in $GUIDE_PATH: `$it`" },
        )
        assertEquals(
            "the two sides hold the same *set* of directive lines but not the same sequence of " +
                "them, so the difference above had nothing to report. Two causes reach this, and " +
                "the lists below say which: either a member spec has moved between two `-keep " +
                "class` blocks and is attached to the wrong class in one document — a spec that " +
                "matches nothing in R8, leaving the field it was meant to keep free to be removed " +
                "— or a line a set collapses is missing from one side or duplicated on it, which " +
                "for a `}` means the block an integrator pastes is unbalanced and their R8 refuses " +
                "the file outright. Rule 8 cannot see that second one: it reads $RULES_PATH and " +
                "never the guide. $RULES_PATH is the source of truth either way",
            shipped,
            printed,
        )
    }

    // ── Controls ──────────────────────────────────────────────────────────

    /**
     * The defect this file was written against, kept as a control.
     *
     * The 0-byte template reddens **three** rules, not one: rule 3 naming all five fields, rule 7
     * naming all three directives, and rule 6's floor at zero. Rules 1, 2, 4 and 8 stay silent,
     * which is the point — an empty file violates no vocabulary and leaves no brace open.
     */
    @Test
    fun `control - the empty file this replaced reddens rules 3, 6 and 7 and no others`() {
        val report = parse("")

        // Derived from reflection rather than written out, and that is not cosmetic: a hard-coded
        // list of the five field names would make a *legitimate* sixth field redden this control
        // alongside rule 3, and a control that fires on the thing it is not about is noise. The
        // count is floored by rule 6; the claim here is "all of them", not "these five".
        assertEquals(
            "the empty file must report every serialised field as uncovered, which is what the " +
                "published AAR has been telling every consumer's R8 all along",
            COVERED_CLASSES.flatMap { type ->
                serialisedFieldsOf(type).map { "$type.${it.name}" }
            }.sorted(),
            report.uncovered,
        )
        assertEquals(
            "…and all three non-member directives as missing",
            REQUIRED_DIRECTIVES,
            REQUIRED_DIRECTIVES.filterNot { it in report.directives.map { d -> d.normalised } },
        )
        assertEquals("…and no directives at all, which is rule 6's floor", 0, report.directives.size)
        assertEquals("…and no covered class", emptyList<String>(), report.coveredClasses)

        assertEquals("an empty file violates no vocabulary", emptyList<String>(), report.vocabulary)
        assertEquals("…leaves no directive uncommented", emptyList<String>(), report.uncommented)
        assertEquals("…names nothing dead", emptyList<String>(), report.dead)
        assertEquals("…and leaves no brace open", emptyList<String>(), report.unbalanced)
        assertEquals("…and nothing is merely insufficient", emptyList<String>(), report.insufficient)
    }

    /**
     * Rule 3's semantics, which is the control that makes it more than a spell-check: the same five
     * fields named by `-keepclassmembernames` are reported as *insufficient*, naming the form, and
     * not as uncovered.
     */
    @Test
    fun `control - a names-only member form is reported as insufficient, naming the form`() {
        val report = parse(FIXTURE_NAMES_ONLY.joinToString("\n"))

        assertEquals(
            "a names-only rule must be reported as insufficient rather than accepted: it forbids " +
                "renaming and still permits removal",
            listOf("$ENTRY.fields", "$ENTRY.id", "$ENTRY.publicKey"),
            report.insufficient.map { it.substringBefore(" is named only by") },
        )
        assertTrue(
            "…and the complaint must name the form, so the repair is obvious: " + report.insufficient,
            report.insufficient.all { NAMES_ONLY_FORM in it },
        )
        assertEquals(
            "…and the same fields must not be reported as uncovered, which is a different " +
                "complaint with a different repair",
            emptyList<String>(),
            report.uncovered.filter { it.startsWith(ENTRY) },
        )
        assertEquals(
            "…and the rule is not dead: every name and type in it is real",
            emptyList<String>(),
            report.dead,
        )
    }

    /** Rule 4 in all three directions, over one fixture. */
    @Test
    fun `control - a missing class, a missing field and a mistyped field are each reported`() {
        val report = parse(FIXTURE_DEAD_RULES.joinToString("\n"))

        assertEquals(
            "three dead rules, three complaints: a class that does not exist, a field the class " +
                "does not declare, and a field whose spec type disagrees with the declared one. " +
                "Found: ${report.dead}",
            3,
            report.dead.size,
        )
        assertTrue("the missing class must be named: ${report.dead}", report.dead.any {
            "dev.eryalabs.lim.Nonexistent" in it && "no class" in it
        })
        assertTrue("the missing field must be named: ${report.dead}", report.dead.any {
            "`notAField`" in it && "declares no field" in it
        })
        assertTrue(
            "the mistyped field must be reported with both types, since a spec whose type is " +
                "wrong matches nothing while looking exactly like a rule that works: ${report.dead}",
            report.dead.any { "$ENTRY.fields" in it && "java.util.Map" in it },
        )
        assertEquals(
            "…and the mistyped spec must not count as covering the field either, or rule 4 would " +
                "be the only thing standing between a wrong type and a deleted field",
            listOf("$ENTRY.fields"),
            report.uncovered.filter { it.startsWith(ENTRY) },
        )
        assertEquals(
            "every directive in this fixture carries its comment, so rule 2 stays out of it and " +
                "the control is about one thing",
            emptyList<String>(),
            report.uncommented,
        )
    }

    /** Rules 1, 2 and 8, each over a fixture that violates exactly it. */
    @Test
    fun `control - a stray directive, a missing comment and an open brace are each reported alone`() {
        val forbidden = parse(FIXTURE_FORBIDDEN_DIRECTIVE.joinToString("\n"))
        assertEquals(
            "a directive outside the allow-list must be reported by rule 1, naming it",
            1,
            forbidden.vocabulary.size,
        )
        assertTrue(
            "…and the complaint must name the directive: ${forbidden.vocabulary}",
            forbidden.vocabulary.single().contains("-dontobfuscate"),
        )
        assertEquals(
            "…and rule 2 must stay out of it: the fixture gives the forbidden directive its own " +
                "comment, so the control is about the vocabulary and nothing else",
            emptyList<String>(),
            forbidden.uncommented,
        )

        val uncommented = parse(FIXTURE_UNCOMMENTED.joinToString("\n"))
        assertEquals(
            "a directive with no comment immediately above it must be reported by rule 2, " +
                "naming its line. A blank line between a reason and its directive counts as no " +
                "reason, which is what makes the pairing unambiguous",
            listOf("4: `-keepattributes Signature`"),
            uncommented.uncommented,
        )

        val open = parse(FIXTURE_OPEN_BRACE.joinToString("\n"))
        assertEquals(
            "an unclosed member spec must be reported twice — once for the directive that never " +
                "closed and once for the file's brace count. Found: ${open.unbalanced}",
            2,
            open.unbalanced.size,
        )
        assertTrue(
            "…and the directive that left it open must be named: ${open.unbalanced}",
            open.unbalanced.any { "unclosed" in it && ENTRY in it },
        )
        assertTrue(
            "…and the directive *below* the stray `{` must still be found, which is what stops " +
                "one open brace near the top reporting every rule under it as missing and burying " +
                "rule 8's finding under rule 7's. Found: ${open.directives.map { it.normalised }}",
            REQUIRED_DIRECTIVES.first() in open.directives.map { it.normalised },
        )
        assertEquals(
            "…and the members the broken spec would have held are not also reported as stray " +
                "lines, or the one finding that matters arrives inside a list of ones that do not",
            emptyList<String>(),
            open.vocabulary,
        )
    }

    /**
     * **The two spellings that passed rule 3 while keeping nothing**, both found by review rather
     * than by this file, and both now refused.
     *
     * Neither is hypothetical: each was installed as the real `consumer-rules.pro` and each took all
     * thirteen tests of this class green while R8 would have renamed all five wire keys. They are
     * the reason [MemberSpec] judges the type wildcard and the access modifiers instead of stepping
     * over them to reach the name.
     */
    @Test
    fun `control - a type wildcard or a modifier that matches nothing does not count as covering`() {
        val wildcards = parse(FIXTURE_WRONG_TYPE_WILDCARDS.joinToString("\n"))
        assertEquals(
            "`%` matches primitives only and a bare `*` matches a class name with no package " +
                "separator, so neither matches `java.lang.String` or `java.util.Map`. Accepting " +
                "them as `any type` left every wire key unprotected with this whole class green",
            COVERED_CLASSES.flatMap { type ->
                serialisedFieldsOf(type).map { "$type.${it.name}" }
            }.sorted(),
            wildcards.uncovered,
        )
        assertEquals(
            "…and each spec must be reported as dead too, naming what the field really is, since " +
                "a rule that matches nothing is the definition of one",
            5,
            wildcards.dead.size,
        )
        assertEquals(
            "…and none of them is merely insufficient: `-keep` is the right *form*, so the " +
                "complaint has to be about the spec and not about the keyword",
            emptyList<String>(),
            wildcards.insufficient,
        )

        val modifier = parse(FIXTURE_WRONG_MODIFIER.joinToString("\n"))
        assertEquals(
            "Kotlin compiles a `val` to a private backing field, so a `public` spec matches " +
                "nothing. The modifiers are checked against the field rather than skipped over on " +
                "the way to the type",
            listOf("$ENTRY.fields", "$ENTRY.id", "$ENTRY.publicKey"),
            modifier.uncovered.filter { it.startsWith(ENTRY) },
        )
        assertTrue(
            "…and the complaint must say what the field actually is, or the repair is a guess: " +
                modifier.dead,
            modifier.dead.any { "private" in it && "$ENTRY.id" in it },
        )

        // …and the converse, or the two assertions above would pass for a check that simply
        // refuses every modifier and every wildcard.
        val accepted = parse(
            listOf(
                "# `***` is the spelling that really does mean any type",
                "-keep class $ENTRY {",
                "    private *** id;",
                "    private *** fields;",
                "    private *** publicKey;",
                "}",
                "# and `**` means any reference type, which these are",
                "-keep class $TYPED_FIELD {",
                "    private final ** value;",
                "    private final ** type;",
                "}",
            ).joinToString("\n"),
        )
        assertEquals(
            "`***`, `**` and a *correct* modifier must all be accepted, or this check has simply " +
                "replaced a false green with a false red",
            emptyList<String>(),
            accepted.uncovered,
        )
        assertEquals("…and nothing is dead in it", emptyList<String>(), accepted.dead)

        // The nested-class spelling, which is the hole the *array* arm of `typeMatches` opened
        // when it was first written as a bare `canonicalName` fallback: a review appended a
        // dotted `CREATOR` spec to the real rules file and all fifteen tests stayed green.
        // ProGuard's grammar separates a nested class from its outer class with `$`, so the
        // dotted form resolves to a class nobody has and matches nothing.
        val dotted = parse(FIXTURE_DOTTED_NESTED_TYPE.joinToString("\n"))
        assertTrue(
            "`android.os.Parcelable.Creator` must be reported: ProGuard wants " +
                "`android.os.Parcelable\$Creator`, and the dotted spelling matches no member. " +
                "`canonicalName` is accepted only for an array, where it is the spelling ProGuard " +
                "actually uses. Found: ${dotted.dead}",
            dotted.dead.any { "CREATOR" in it },
        )
        assertEquals(
            "…and the `$`-separated spelling must still be accepted, or the guard has turned a " +
                "false green into a false red on the two rules this file actually ships",
            emptyList<String>(),
            parse(FIXTURE_NESTED_TYPE.joinToString("\n")).dead,
        )
    }

    /**
     * A `#` comment inside a member spec, which is legal ProGuard and which a first draft of this
     * parser mis-read in both directions: the comment swallowed the member below it, and a `}`
     * inside a comment ended the directive early.
     */
    @Test
    fun `control - a comment inside a member spec hides neither the members nor the brace`() {
        val report = parse(FIXTURE_COMMENTED_MEMBERS.joinToString("\n"))

        assertEquals(
            "every field is still covered: `#` runs to the end of its line, so a per-field reason " +
                "inside the braces is a comment and not a member — and the `}` inside one of them " +
                "is a comment too, so it must not end the directive",
            emptyList<String>(),
            report.uncovered,
        )
        assertEquals(
            "…the comment lines are not stray lines either, which is what rule 1 would otherwise " +
                "call them",
            emptyList<String>(),
            report.vocabulary,
        )
        assertEquals("…nothing is dead", emptyList<String>(), report.dead)
        assertEquals("…and no brace is left open", emptyList<String>(), report.unbalanced)
        assertEquals("…over exactly two directives", 2, report.directives.size)
    }

    /**
     * The parser's two silent-rot directions, which no rule above would notice: a directive whose
     * braces are on their own lines must still be **one** directive, and a `<fields>;` wildcard must
     * cover a field the file never names.
     */
    @Test
    fun `control - a multi-line directive is one directive and a wildcard covers every field`() {
        val report = parse(FIXTURE_WILDCARD.joinToString("\n"))

        assertEquals(
            "two directives, not six: a member spec's lines belong to the directive that opened " +
                "it, or rule 1 would report every `java.lang.String id;` in the real file as a " +
                "stray line. Found: ${report.directives.map { it.normalised }}",
            2,
            report.directives.size,
        )
        assertEquals(
            "a `<fields>;` wildcard must cover every declared field, so a rules file written " +
                "that way is accepted rather than reported as naming none",
            emptyList<String>(),
            report.uncovered,
        )
        assertEquals(
            "…and it names no field, so rule 4 has nothing to call dead",
            emptyList<String>(),
            report.dead,
        )
        assertEquals(
            "…and both classes count as wholly covered",
            COVERED_CLASSES,
            report.coveredClasses,
        )
    }

    // ── Reading the files ─────────────────────────────────────────────────

    /** The rules file, parsed once for the whole class. See [cached]. */
    private fun onDisk(): Report =
        cached ?: parse(locate(RULES_PATH).readText()).also { cached = it }

    /**
     * The non-blank, non-comment lines of [lines], trimmed and **in order** — rule 9's unit of
     * comparison, which reads it both as a set and as a sequence.
     *
     * `#` runs to the end of its line anywhere in a ProGuard file, which is [parse]'s rule too, and
     * applying it to the guide's block as well is what lets the two files carry different prose
     * around the same directives. Trimmed, so the four-space indentation of a member spec is not
     * pinned across a Markdown fence. A `List` rather than a `Set` on purpose: order is what
     * attaches a member spec to the class whose braces it sits in, so collapsing it would wave
     * through a spec that had moved between two `-keep class` blocks.
     */
    private fun directiveLinesIn(lines: List<String>): List<String> =
        lines.map { it.substringBefore(COMMENT_MARKER).trim() }
            .filter { it.isNotEmpty() }

    /**
     * The body of every fenced block in [lines] whose info string is exactly [language].
     *
     * Fences are required at column 0 with a bare language word, which is [FENCE_OPEN] and the same
     * shape `GuideSnippetTest` holds the whole guide to — so a fence this scan cannot see is a
     * failure over there rather than a block silently skipped here. An unclosed fence fails the run
     * rather than swallowing the rest of the document.
     */
    private fun fencedBlocks(lines: List<String>, language: String): List<List<String>> {
        val blocks = mutableListOf<List<String>>()
        var index = 0
        while (index < lines.size) {
            val open = FENCE_OPEN.find(lines[index])
            if (open == null) {
                index++
                continue
            }
            var cursor = index + 1
            while (cursor < lines.size && !FENCE_CLOSE.matches(lines[cursor])) cursor++
            check(cursor < lines.size) {
                "a fenced block opened at line ${index + 1} is never closed, so this scan cannot " +
                    "say what the document contains"
            }
            if (open.groupValues[1] == language) blocks += lines.subList(index + 1, cursor)
            index = cursor + 1
        }
        return blocks
    }

    private class GsonSite(val where: String, val code: String)

    /** Every `Gson()` construction in the main sources, with comments masked. */
    private fun gsonSites(): List<GsonSite> =
        mainSources().entries.sortedBy { it.key }.flatMap { (name, text) ->
            withoutComments(text).lines().mapIndexedNotNull { index, line ->
                if (GSON_CONSTRUCTION in line) {
                    GsonSite("$name:${index + 1}", line.trim())
                } else {
                    null
                }
            }
        }

    /**
     * [source] with its comments blanked **in place**.
     *
     * In place rather than removed, so a block comment does not shift every line below it and rule
     * 5's citations keep naming the line a reader would open.
     */
    private fun withoutComments(source: String): String =
        BLOCK_COMMENT.replace(source) { match -> match.value.replace(NOT_A_NEWLINE, " ") }
            .lines()
            .joinToString("\n") { it.substringBefore(LINE_COMMENT) }

    /** Every Kotlin main source, keyed by file name. */
    private fun mainSources(): Map<String, String> {
        val root = locateDirectory(MAIN_SOURCE_ROOT)
        val sources = root.walkTopDown().filter { it.isFile && it.name.endsWith(".kt") }.toList()
        check(sources.isNotEmpty()) { "no Kotlin main sources under ${root.absolutePath}" }
        return sources.associate { it.name to it.readText() }
    }

    /**
     * [relative], located by walking up from the working directory, or a failure naming every path
     * it tried.
     *
     * `BuildInputsTest`'s walk-up, for its reason: the working directory of a Gradle unit test is
     * the module directory, but that is a Gradle default rather than a promise.
     */
    private fun locate(relative: String): File =
        walkUp(relative) { it.isFile }
            ?: throw AssertionError(
                "cannot find `$relative`, so nothing here can say what this library ships into a " +
                    "consumer's R8 run — and a gate that cannot find the file it guards passes " +
                    "for ever. " + triedPaths(relative),
            )

    /** [locate] for a directory rather than a file. */
    private fun locateDirectory(relative: String): File =
        walkUp(relative) { it.isDirectory }
            ?: throw AssertionError(
                "cannot find `$relative`, so rule 5 has no sources to scan and would pass over " +
                    "an empty list. " + triedPaths(relative),
            )

    private fun walkUp(relative: String, accept: (File) -> Boolean): File? {
        var directory: File? = File(".").absoluteFile.normalize()
        while (directory != null) {
            for (candidate in listOf(File(directory, relative), File(directory, "LIM/$relative"))) {
                if (accept(candidate)) return candidate
            }
            directory = directory.parentFile
        }
        return null
    }

    private fun triedPaths(relative: String): String {
        val working = File(".").absoluteFile.normalize()
        val tried = mutableListOf<File>()
        var directory: File? = working
        while (directory != null) {
            tried += File(directory, relative)
            tried += File(directory, "LIM/$relative")
            directory = directory.parentFile
        }
        return "Working directory: $working. Tried:\n" +
            tried.map { it.absolutePath }.distinct().joinToString("\n")
    }

    private companion object {

        /**
         * The classes whose fields Gson serialises — the two that carry the wire's five JSON keys.
         *
         * Their field names coincide with those keys, but no longer *because* Gson reflects over
         * them: five `@SerializedName` strings say so, and rule 3's first assertion is what holds
         * the coincidence true. See [WireKeyAnnotationTest] for the annotation side of it.
         *
         * The *classes* are listed; their *fields* are never listed, and come from reflection. See
         * [serialisedFieldsOf] and rule 3.
         */
        private const val ENTRY = "dev.eryalabs.lim.Entry"
        private const val TYPED_FIELD = "dev.eryalabs.lim.TypedField"
        private val COVERED_CLASSES = listOf(ENTRY, TYPED_FIELD)

        private const val RULES_PATH = "LIM/consumer-rules.pro"
        private const val MAIN_SOURCE_ROOT = "src/main/java"

        /** The integration guide, which prints these rules for the vendoring path. See rule 9. */
        private const val GUIDE_PATH = "docs/INTEGRATION.md"

        /** The fence the guide's copy of these rules carries, and the key its excuse is spelled with. */
        private const val RULES_FENCE_LANGUAGE = "proguard"

        private const val COMMENT_MARKER = "#"
        private const val DIRECTIVE_MARKER = "-"
        private const val LINE_COMMENT = "//"

        /**
         * The directives this file is allowed to use, each with a reason written into the rules
         * file itself. Rule 1's allow-list.
         */
        private val ALLOWED_DIRECTIVES = setOf(
            "-keep",
            "-keepclassmembers",
            "-keepclassmembernames",
            "-keepattributes",
            "-dontwarn",
        )

        /**
         * The member forms that refuse both renaming **and** removal.
         *
         * `-keepclassmembernames` is deliberately absent: it prevents renaming but still allows R8
         * to drop the member, and a field only ever written reflectively looks unused. See rule 3.
         */
        private val SUFFICIENT_FORMS = setOf("-keep", "-keepclassmembers")
        private const val NAMES_ONLY_FORM = "-keepclassmembernames"

        /** The `CREATOR` member spec, shared by the two directives below so it is written once. */
        private const val CREATOR_SPEC =
            "public static final android.os.Parcelable\$Creator CREATOR;"

        /**
         * Rule 7's list: every directive that rule 3's field census cannot reach, each required
         * verbatim.
         *
         * Three are not about members at all. The last two are member specs that rule 3 excludes on
         * purpose — `CREATOR` is *static*, and Gson does not serialise static fields — so without
         * them here, both `Parcelable` rules could be deleted with every test in this class green.
         * That is not hypothetical: it was measured, by a review that deleted them.
         *
         * Matched against [Directive.normalised], which collapses whitespace, so a multi-line
         * member spec is compared as the one line it means.
         */
        private val REQUIRED_DIRECTIVES = listOf(
            "-keepattributes Signature",
            "-keepattributes *Annotation*",
            "-keep class * extends com.google.gson.reflect.TypeToken",
            "-keepclassmembers class $ENTRY { $CREATOR_SPEC }",
            "-keepclassmembers class $TYPED_FIELD { $CREATOR_SPEC }",
        )

        /** Member specs that mean "every field", so no field name needs naming. */
        private val ALL_MEMBERS = setOf("<fields>", "*", "**")

        /**
         * ProGuard's type wildcards, which are **not** interchangeable. See [MemberSpec].
         *
         * Absent on purpose: a bare `*`, which matches only a class name with no package
         * separator and therefore matches neither `java.lang.String` nor `java.util.Map`. There is
         * no constant for it because there is nothing it could usefully mean here.
         */
        private const val ANY_TYPE = "***"
        private const val ANY_REFERENCE_TYPE = "**"
        private const val ANY_PRIMITIVE_TYPE = "%"

        /**
         * Floors against a failure the rules above cannot see: a parser that found nothing would
         * make every assertion they guard pass over an empty list.
         *
         * Two of the three are **equal** to the measured value rather than below it, and the
         * difference is deliberate in each direction. [MINIMUM_COVERED_CLASSES] and
         * [MINIMUM_COVERED_FIELDS] are equal to today's 2 and 5 because those numbers are not
         * "whatever the file happens to contain" — they are the two Gson-serialised classes and the
         * five JSON keys the protocol exchanges, so a drop in either is a real loss and should be
         * reported rather than absorbed. [MINIMUM_DIRECTIVES] *is* below the count on disk, so that
         * a control which deletes one directive reports the rule it was aimed at — rule 3 or rule 7
         * — instead of burying it under a floor failure. See rule 6.
         */
        private const val MINIMUM_COVERED_CLASSES = 2
        private const val MINIMUM_COVERED_FIELDS = 5
        private const val MINIMUM_DIRECTIVES = 4

        /**
         * Rule 9's floor: distinct non-comment lines in the rules file, 14 when this was written.
         *
         * Below the measured count, for [MINIMUM_DIRECTIVES]'s reason — deleting a line from either
         * side should report the set equality that was aimed at it, naming the line and the
         * direction, rather than burying it under a floor failure.
         */
        private const val MINIMUM_PRINTED_LINES = 10

        /**
         * The four `Gson()` call sites these rules were written against, by content.
         *
         * Content rather than line number, so an edit above them is not a false alarm. All four are
         * in `Utils.kt`: the share encoder, the field-map encoder and decoder, and
         * `Utils.decodeEntry`.
         */
        private val GSON_CALL_SITES = listOf(
            "val json = Gson().toJson(entry)",
            "fun encodeFields(fields: Map<String, TypedField>): String = Gson().toJson(fields)",
            "Gson().fromJson(json, FIELDS_TYPE) ?: return emptyMap()",
            "Gson().fromJson(json, Entry::class.java) ?: return null",
        )

        private const val GSON_CONSTRUCTION = "Gson()"

        /** The class spec of a directive: the token after `class`. */
        private val CLASS_SPEC = Regex("""\bclass\s+([A-Za-z0-9_.*]+)""")

        /** The supertype of an `extends` or `implements` clause. */
        private val SUPERTYPE_SPEC = Regex("""\b(?:extends|implements)\s+([A-Za-z0-9_.*]+)""")

        /** Rule 9's Markdown fences: column 0, backticks, a bare language word. */
        private val FENCE_OPEN = Regex("""^```(\w*)\s*$""")
        private val FENCE_CLOSE = Regex("""^```\s*$""")

        private val MEMBER_SEPARATOR = Regex(";")
        private val WHITESPACE = Regex("""\s+""")
        private val NOT_A_NEWLINE = Regex("""[^\n]""")

        /** A slash-star comment, however many lines it spans. See [withoutComments]. */
        private val BLOCK_COMMENT = Regex("""/\*.*?\*/""", RegexOption.DOT_MATCHES_ALL)

        /** The on-disk measurement, shared across this class's test instances. */
        private var cached: Report? = null

        /**
         * The fields of [className] that Gson reflects over: every declared field that is neither
         * static nor synthetic.
         *
         * Static fields are excluded because Gson does not serialise them, so none of them is a
         * JSON key and rule 3's subject does not reach them.
         *
         * `@Parcelize` generates one: a static `CREATOR`. It is **not** covered by rule 3 and it is
         * not nothing — [Entry] and [TypedField] are published `Parcelable` types, and the
         * `Parcelable` encoding is consumer-visible behaviour (`EntryParcelTest` pins it) — so the
         * rules file keeps it explicitly, with its own reason. The usual answer, that AGP's default
         * `proguard-android-optimize.txt` already keeps every `CREATOR`, holds only while a consumer
         * keeps that default file in their own `proguardFiles`; that is **configuration reasoning
         * about somebody else's build, not a measurement**, which is precisely why the rule is
         * written rather than assumed.
         */
        private fun serialisedFieldsOf(className: String): List<Field> {
            val type = loadClass(className)
                ?: throw AssertionError("`$className` is not on the test classpath")
            val fields = type.declaredFields
                .filter { !Modifier.isStatic(it.modifiers) && !it.isSynthetic }
                .sortedBy { it.name }
            check(fields.isNotEmpty()) {
                "`$className` declares no instance fields, so rule 3 would pass over an empty list"
            }
            return fields
        }

        private fun loadClass(name: String): Class<*>? =
            runCatching { Class.forName(name) }.getOrNull()

        /** [field] as a ProGuard member spec would have to spell it, for rule 4's complaint. */
        private fun declarationOf(field: Field): String =
            "${Modifier.toString(field.modifiers)} ${field.type.name}".trim()

        private fun String.isAName(): Boolean = '*' !in this && '?' !in this && '%' !in this

        // ── The controls' fixtures ────────────────────────────────────────

        private val FIXTURE_NAMES_ONLY = listOf(
            "# names only, which is the form rule 3 has to refuse",
            "$NAMES_ONLY_FORM class $ENTRY {",
            "    java.lang.String id;",
            "    java.util.Map fields;",
            "    java.lang.String publicKey;",
            "}",
        )

        private val FIXTURE_DEAD_RULES = listOf(
            "# a class that does not exist",
            "-keep class dev.eryalabs.lim.Nonexistent { *; }",
            "# a field Entry does not declare, and one whose type is wrong",
            "-keep class $ENTRY {",
            "    java.lang.String id;",
            "    java.lang.String notAField;",
            "    java.lang.String fields;",
            "    java.lang.String publicKey;",
            "}",
            "# the other half of the payload, so only Entry.fields is uncovered",
            "-keep class $TYPED_FIELD { <fields>; }",
        )

        private val FIXTURE_FORBIDDEN_DIRECTIVE = listOf(
            "# the consumer's decision, not this library's",
            "-dontobfuscate",
        )

        private val FIXTURE_UNCOMMENTED = listOf(
            "# a reason, then a blank line, which counts as no reason",
            "",
            "",
            "-keepattributes Signature",
        )

        /**
         * An unclosed member spec **with a directive under it**, which is the half that matters: a
         * fixture that ended at the open brace would never show whether the rest of the file is
         * still parsed.
         */
        private val FIXTURE_OPEN_BRACE = listOf(
            "# a member spec that is never closed",
            "-keep class $ENTRY {",
            "    java.lang.String id;",
            "",
            "# a directive below it, which must still be found",
            "-keepattributes Signature",
        )

        private val FIXTURE_WILDCARD = listOf(
            "# every field, however many there are",
            "-keep class $ENTRY {",
            "    <fields>;",
            "}",
            "# and the other half",
            "-keepclassmembers class $TYPED_FIELD {",
            "    <fields>;",
            "}",
        )

        /**
         * The three type spellings a first draft of [MemberSpec] accepted as "any type" and R8 does
         * not: `%` is primitives only, a bare `*` is a class name with no package separator, and a
         * missing type is not a field spec at all. All five wire keys stayed green through this.
         */
        private val FIXTURE_WRONG_TYPE_WILDCARDS = listOf(
            "# `%` matches primitives only, so it matches no field of either class",
            "-keep class $ENTRY {",
            "    % id;",
            "    % fields;",
            "    % publicKey;",
            "}",
            "# a bare `*` matches a class name with no package separator",
            "-keep class $TYPED_FIELD {",
            "    * value;",
            "    * type;",
            "}",
        )

        /**
         * The two spellings of a nested type, one of which ProGuard refuses.
         *
         * `android.os.Parcelable$Creator` is the form the grammar wants and the form this library's
         * two `CREATOR` rules use; `android.os.Parcelable.Creator` reads the same to a human and
         * resolves to a class nobody has. [FIXTURE_DOTTED_NESTED_TYPE] must be reported and
         * [FIXTURE_NESTED_TYPE] must not, or the array arm of `typeMatches` has either reopened a
         * false green or created a false red on the file as shipped.
         */
        private val FIXTURE_NESTED_TYPE = listOf(
            "# the spelling ProGuard's grammar requires",
            "-keepclassmembers class $ENTRY {",
            "    $CREATOR_SPEC",
            "}",
        )

        private val FIXTURE_DOTTED_NESTED_TYPE = listOf(
            "# the spelling that reads the same and matches nothing",
            "-keepclassmembers class $ENTRY {",
            "    public static final android.os.Parcelable.Creator CREATOR;",
            "}",
        )

        /** `public` on a field Kotlin compiled private: a spec R8 matches to nothing. */
        private val FIXTURE_WRONG_MODIFIER = listOf(
            "# Kotlin compiles a `val` to a private backing field, so `public` matches nothing",
            "-keep class $ENTRY {",
            "    public java.lang.String id;",
            "    public java.util.Map fields;",
            "    public java.lang.String publicKey;",
            "}",
        )

        /**
         * A `#` comment between two member specs, and one carrying a `}`.
         *
         * Legal ProGuard — `#` runs to the end of its line anywhere — and exactly what this file's
         * "every rule states its reason" habit invites inside a member spec. A first draft split
         * members on `;` alone, so the comment swallowed the spec below it and the brace in the
         * second comment ended the directive early.
         */
        private val FIXTURE_COMMENTED_MEMBERS = listOf(
            "# per-field reasons, inside the braces",
            "-keep class $ENTRY {",
            "    # the key the vault looks the profile up by",
            "    java.lang.String id;",
            "    # the field map, whose own keys are the profile's field names",
            "    java.util.Map fields;",
            "    # the handle a service stores; a stray } in this comment must not end the spec",
            "    java.lang.String publicKey;",
            "}",
            "# and the other half",
            "-keep class $TYPED_FIELD { <fields>; }",
        )
    }
}
