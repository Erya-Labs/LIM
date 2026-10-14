package dev.eryalabs.lim

import java.util.Collections

/**
 * Which of a sign-up's declared fields the user must fill in, and which they may leave blank —
 * and **the one definition of "blank" this protocol has**, so that a client's gate and a vault's
 * Save button cannot disagree about it.
 *
 * **Required is the default.** Every name in [fieldNames] is required unless it is also named in
 * the optional list, and a name that is not one of [fieldNames] is dropped rather than added: a
 * misspelt optional name leaves its field required, which is the direction that fails closed. A
 * client builds one from its own [Entry] and sends [optionalFields] with
 * [Utils.createShareIntent]; a vault reads the same thing back with
 * [Utils.parseFieldRequirements]. Matching is exact, case-sensitive string equality — no
 * trimming, no case folding and no [FieldType.normalize] — because a field name is an opaque key
 * the client chose.
 *
 * **Blank, defined once.** A value is blank when its [TypedField] is absent or `null`, when its
 * [TypedField.value] is `null` (the `Unsafe` hazard [Utils.decodeEntry] documents), or when the
 * value is Kotlin-`isBlank` — whitespace only, a no-break space included. A zero-width space is
 * *not* blank, and neither are `"0"` or `"false"`: required means "the user put something here",
 * not "the user put something valid here". This library never trims or rewrites a value; a
 * vault that trims its form's input does so before handing the draft in. A yes/no question the
 * user has not answered is blank on this definition whether the vault sends it as an absent
 * field or as an empty value — which is how a vault that offers "Not answered" makes an
 * unanswered required question block and an unanswered optional one drop.
 *
 * Immutable: every collection handed in is copied, and every collection handed out is a
 * read-only copy. It is not [android.os.Parcelable] and nothing serialises it reflectively, so it
 * adds no keep rule. [toString] prints counts only, never a name — a field name is as likely to
 * be something about one user as it is to be `email`.
 *
 * **A plain class rather than a data class, deliberately.** A data class publishes a `copy`, a
 * `componentN` per property and a constructor whose parameter list is then frozen for ever; this
 * one keeps the freedom to grow without breaking a compiled consumer, and its equality is the one
 * the protocol means — ordered names, optional set — rather than whatever the properties happen
 * to be.
 *
 * **Example**, verbatim from `docs/INTEGRATION.md`'s *Required and optional fields* section:
 *
 * <!-- example: INTEGRATION.md#signup-optional-request -->
 * ```kotlin
 * // Every field you declare is required unless you name it here. Names match exactly, so
 * // a misspelt name is simply not sent and that field stays required. All five arguments
 * // are needed, the vault's package included: with no defaults, no shorter call can
 * // resolve to this overload, so every call written before it still means what it did.
 * val entry = Entry(
 *     id = "signup-form",
 *     fields = linkedMapOf(
 *         "name" to TypedField(value = "", type = FieldType.STRING),
 *         "email" to TypedField(value = "", type = FieldType.EMAIL),
 *         "phone" to TypedField(value = "", type = FieldType.PHONE),
 *     ),
 *     publicKey = "no-key-yet",
 * )
 * val requirements = FieldRequirements(entry.fields.keys, setOf("phone"))
 * val request = Utils.createShareIntent(
 *     context,
 *     entry,
 *     SIGN_UP_REQUEST,
 *     requirements.optionalFields,
 *     Utils.DEFAULT_ENDEAVOR_PACKAGE,
 * )
 * // startActivityForResult(request, VAULT_RESULT)
 * ```
 *
 * @param fieldNames     Every field the sign-up declares, in the order a form should show them —
 *                       for a client, `entry.fields.keys`. Duplicates collapse to their first
 *                       occurrence, and a `null` element (reachable from Java) is skipped. Copied.
 *                       A client whose [Entry] can hold a `null` [TypedField] — Java code, or a
 *                       template Gson built — passes only the keys whose value is not `null`: a
 *                       `null` one is never encoded, so the vault never sees that field, and
 *                       requiring it would make an honest vault's answer read as
 *                       [FieldRequirementsVerdict.VIOLATED].
 * @param optionalFields The names the user may leave blank. Only names that are also in
 *                       [fieldNames] survive; duplicates, unknown names and Java `null` elements
 *                       are dropped. Defaults to none, which makes every field required. Copied,
 *                       and compared by exact string equality whatever kind of collection it is.
 */
class FieldRequirements @JvmOverloads constructor(
    fieldNames: Collection<String>,
    optionalFields: Collection<String> = emptySet(),
) {

    /**
     * Every declared field name, distinct, in the order they were given. Read-only.
     *
     * For a vault this is the form to show: one row per name, in this order.
     */
    val fieldNames: List<String> = Collections.unmodifiableList(ArrayList(distinctNames(fieldNames)))

    /**
     * The declared names the user may leave blank — the given optional names intersected with
     * [fieldNames], in [fieldNames] order. Read-only. Empty when every field is required.
     *
     * This is the set to send with [Utils.createShareIntent], and the set
     * [Utils.checkFieldRequirements] expects a vault to acknowledge.
     */
    val optionalFields: Set<String> = optionalSubset(this.fieldNames, optionalFields)

    /**
     * The declared names the user must fill in — [fieldNames] minus [optionalFields], in
     * [fieldNames] order. Read-only.
     */
    val requiredFields: Set<String> =
        Collections.unmodifiableSet(this.fieldNames.filterTo(LinkedHashSet()) { it !in this.optionalFields })

    /**
     * The required names whose value in [values] is absent or blank, in [fieldNames] order.
     *
     * Empty means every required field arrived with something in it. This is a vault's Save gate
     * and a client's "what is missing" list, and it is the same list on both sides because both
     * call this.
     *
     * @param values The values to check — a vault's draft, or a client's `ShareResult.fields`.
     *               Looked up by exact key; keys this object does not declare are ignored here.
     *               Not modified.
     * @return A read-only list, empty when nothing required is missing.
     */
    fun missingRequired(values: Map<String, TypedField>): List<String> {
        val exact = exactly(values)
        return Collections.unmodifiableList(requiredFields.filter { isBlank(exact[it]) })
    }

    /**
     * Whether [values] is a payload a vault may acknowledge: nothing required is missing, **and no
     * value in it is blank at all**, declared or not.
     *
     * The second half is what "a blank optional field is dropped, never sent as `""`" means as a
     * check. [Utils.createShareResultIntent]'s requirements-aware overload writes its
     * acknowledgement only when this is `true`, so a vault that forgot to drop a blank field
     * answers without one rather than making a claim its payload does not support.
     *
     * @param values The payload about to be sent, exactly as it will be encoded. Not modified.
     */
    fun isSatisfiedBy(values: Map<String, TypedField>): Boolean {
        val exact = exactly(values)
        return requiredFields.none { isBlank(exact[it]) } && exact.values.none { isBlank(it) }
    }

    /**
     * The map to keep: `null` when a required field is missing or blank, otherwise the declared,
     * non-blank entries of [values] in [fieldNames] order — so a blank optional field and any
     * key this object does not declare are both dropped.
     *
     * A vault persists this and answers with it; a client stores it as the account's profile. It
     * is empty, not `null`, when every field is optional and every one was left blank — a profile
     * that is a key and nothing else, which is what a vault offering it answers with.
     *
     * @param values A vault's draft or a client's `ShareResult.fields`. The [TypedField]s are
     *               handed back as they are, never trimmed or rewritten. Not modified.
     * @return A read-only map, or `null` exactly when [missingRequired] is non-empty.
     */
    fun committed(values: Map<String, TypedField>): Map<String, TypedField>? {
        val exact = exactly(values)
        if (requiredFields.any { isBlank(exact[it]) }) return null
        val kept = LinkedHashMap<String, TypedField>()
        for (name in fieldNames) {
            val field = exact[name] ?: continue
            if (!isBlank(field)) kept[name] = field
        }
        return Collections.unmodifiableMap(kept)
    }

    /** Equal when the declared names are the same in the same order and the optional sets match. */
    override fun equals(other: Any?): Boolean =
        other is FieldRequirements &&
            fieldNames == other.fieldNames &&
            optionalFields == other.optionalFields

    override fun hashCode(): Int = 31 * fieldNames.hashCode() + optionalFields.hashCode()

    /** `FieldRequirements(fields=5, optional=2)` — counts only, never a field name. */
    override fun toString(): String =
        "FieldRequirements(fields=${fieldNames.size}, optional=${optionalFields.size})"

    /** [names] without duplicates or the `null`s a Java caller can put in one, in order. */
    private fun distinctNames(names: Collection<String>): Set<String> {
        val distinct = LinkedHashSet<String>()
        for (name: String? in names) if (name != null) distinct += name
        return distinct
    }

    /**
     * [optional] ∩ [declared], in [declared] order.
     *
     * Copied into a `HashSet` first rather than asked `contains`, so the answer is exact string
     * equality whatever collection a caller passed — a `TreeSet` built with a case-insensitive
     * comparator would otherwise make `"Email"` optional when only `"email"` was named.
     */
    private fun optionalSubset(declared: List<String>, optional: Collection<String>): Set<String> {
        val named = HashSet<String>()
        for (name: String? in optional) if (name != null) named += name
        return Collections.unmodifiableSet(declared.filterTo(LinkedHashSet()) { it in named })
    }

    /**
     * [values] re-keyed by exact string equality, with Java `null` keys and values kept as they
     * are. A map with its own idea of key equality — a case-insensitive `TreeMap` — would
     * otherwise answer for a name it was never given.
     */
    @Suppress("UNCHECKED_CAST")
    private fun exactly(values: Map<String, TypedField>): Map<String?, TypedField?> {
        val copy = HashMap<String?, TypedField?>()
        for (entry in (values as Map<String?, TypedField?>).entries) copy[entry.key] = entry.value
        return copy
    }

    /** The one definition of blank; see the class comment. */
    @Suppress("SENSELESS_COMPARISON")
    private fun isBlank(field: TypedField?): Boolean {
        if (field == null) return true
        val value: String? = field.value
        return value == null || value.isBlank()
    }
}
