package dev.eryalabs.lim

/**
 * What a sign-up's answer says about the fields you asked for, as [Utils.checkFieldRequirements]
 * reads it.
 *
 * **Two questions, and the verdicts split exactly on the first.** Is the data complete — did
 * every required field arrive non-blank? That one needs no trust in the vault: it is
 * [FieldRequirements.committed] over the result's own fields, and it holds for [HONOURED],
 * [MISMATCHED] and [NOT_ACKNOWLEDGED] and for nothing else. Did the vault apply *your*
 * declaration? That is the acknowledgement under [Utils.EXTRA_APPLIED_OPTIONAL_FIELDS], which only
 * a vault implementing required fields writes — so silence is never read as compliance.
 *
 * **Not authentication.** The acknowledgement is an unsigned extra, exactly as trustworthy as the
 * vault you addressed: a verdict says what the answer claims and whether its own payload agrees,
 * never who sent it.
 *
 * **Keep an `else` branch.** A later release may add a verdict, and an exhaustive `when` without
 * one would stop compiling against it. The example below sends any verdict it does not know to
 * the branch it sends [VIOLATED] to.
 *
 * **Example**, verbatim from `docs/INTEGRATION.md`'s *Required and optional fields* section:
 *
 * <!-- example: INTEGRATION.md#signup-optional-result -->
 * ```kotlin
 * // In onActivityResult, once `resultCode` is RESULT_OK and the request code matches.
 * fun onSignUpAnswer(data: Intent?) {
 *     val result = Utils.parseShareResult(data) ?: return
 *     // Keep the key whatever follows: the profile now exists in the vault, bound to you.
 *     val accountKey = result.publicKey ?: return
 *     // Gate on the data, never on a version number. `committed` is null exactly when a
 *     // required field is missing or blank. It drops a blank optional field too, whether
 *     // the vault left it out or, as an older vault may, sent it as an empty value.
 *     val profile = requirements.committed(result.fields)
 *     when (Utils.checkFieldRequirements(requirements, data)) {
 *         FieldRequirementsVerdict.HONOURED,
 *         FieldRequirementsVerdict.MISMATCHED,
 *         FieldRequirementsVerdict.NOT_ACKNOWLEDGED -> createAccount(accountKey, profile!!)
 *         FieldRequirementsVerdict.INCOMPLETE ->
 *             accountIncomplete(accountKey, requirements.missingRequired(result.fields))
 *         else -> reportVault(accountKey) // VIOLATED, and any verdict a later release adds
 *     }
 * }
 * ```
 */
enum class FieldRequirementsVerdict {

    /**
     * The vault acknowledged exactly your optional set, and every required field arrived
     * non-blank. The one verdict under which the vault *claims* to have done what you asked — a
     * claim, not a check: the acknowledgement is unsigned and this verdict reads only your
     * required fields, so a vault writing the extra by hand can still send a blank optional or
     * undeclared value beside it. [FieldRequirements.committed] drops both, which is why it, and
     * not the answer's fields as they came, is the profile to keep.
     */
    HONOURED,

    /**
     * The vault acknowledged a *different* optional set, and every required field arrived
     * non-blank — so the data is complete. The usual cause is on the client's side: a marker the
     * vault could not read is treated as "nothing is optional", and the vault then acknowledges
     * the empty set it applied, having asked the user for everything.
     */
    MISMATCHED,

    /**
     * No acknowledgement, and every required field arrived non-blank. The data is complete, but
     * nothing says the vault read your declaration: a vault built before required fields existed,
     * or one answering through the builder that writes no acknowledgement, may have made the user
     * fill in fields you marked optional. A vault whose answer still held a blank value gets here
     * too, because the requirements-aware builder writes no acknowledgement over one.
     */
    NOT_ACKNOWLEDGED,

    /**
     * No acknowledgement, and a required field is absent or blank. Either a vault that predates
     * required fields let the user skip it, or a vault built on this release answered without
     * acknowledging — through the builder that writes no acknowledgement, or through the
     * requirements-aware one over a payload that fell short, which omits it. The answer cannot
     * tell you which: what a vault was built on is not something it shows. The profile exists
     * and is bound to the key the answer carried, so keep that key;
     * [FieldRequirements.missingRequired] names what is missing. There is no protocol path to
     * fill the gap in later.
     */
    INCOMPLETE,

    /**
     * The answer carries an acknowledgement, yet a required field is absent or blank. This
     * library's builder never writes one over an incomplete payload, so this is a vault writing
     * the extra by hand or a broken one — unless the field is one you never sent: a `null`
     * [TypedField] in your [Entry] is not encoded, so build your requirements from the keys whose
     * value is not `null` (see [FieldRequirements]). Otherwise keep the key and treat the vault
     * as faulty.
     */
    VIOLATED,
}
