package dev.eryalabs.lim

import android.os.Parcel
import android.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File
import java.lang.reflect.Modifier
import java.lang.reflect.Type
import java.net.JarURLConnection

/**
 * The audit, made executable.
 *
 * Reading the sources once and declaring "everything is covered" stays true exactly until
 * somebody adds a public member. So the audit is written down here as a manifest — every public
 * member of `dev.eryalabs.lim` paired with the test that covers it — and checked against what
 * reflection actually finds. Add a public function and this fails, naming it, until a test
 * exists and the manifest records which one.
 *
 * It is a guard on the published API too. This library ships to third-party apps via JitPack;
 * removing or renaming a public member breaks them silently at their next build. Here it shows
 * up as a failure carrying the missing name.
 *
 * The manifest names *one* covering test per member, not all of them: the question this audit
 * answers is "is anything untested", and a member with several tests answers it once. The tests
 * further down are the ones the audit itself had to add, for members that turned out to have no
 * home anywhere in the suite.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class PublicApiAuditTest {

    /**
     * The published classes, discovered rather than listed.
     *
     * A hardcoded list would make this audit blind to exactly the change it exists to catch: a
     * *new file* carrying a new public type and no test would leave every assertion below green,
     * because nothing would have asked about it. So the classes are read off the compiled output
     * directory, which is the same set a consumer gets in the AAR.
     */
    private val types: List<Class<*>> = classesInPackage(Utils::class.java)

    /**
     * Every class compiled into `dev.eryalabs.lim` from the same output tree as [anchor].
     *
     * Nested and synthetic classes are folded in via their own entries — `Entry$Companion` is a
     * separate class file and is picked up as one. Anonymous classes (`Utils$FIELDS_TYPE$1`, the
     * Gson `TypeToken`) carry no API and are skipped by name.
     */
    private fun classesInPackage(anchor: Class<*>): List<Class<*>> {
        // Located through the class file itself rather than through the CodeSource: Robolectric
        // loads these classes in its own sandbox, whose protection domain reports no location at
        // all. The resource lookup goes to the underlying classpath and works either way.
        val packageName = anchor.name.substringBeforeLast('.')
        val anchorPath = anchor.name.replace('.', '/') + ".class"
        val loader = checkNotNull(anchor.classLoader) { "no classloader for ${anchor.name}" }
        val url = checkNotNull(loader.getResource(anchorPath)) {
            "cannot locate $anchorPath on the classpath"
        }
        val packagePath = packageName.replace('.', '/')

        // Two shapes, because the two source sets are packaged differently by the Android plugin:
        // the library's own classes arrive as `classes.jar`, the test's as a directory of files.
        val simpleNames = when (url.protocol) {
            "file" -> checkNotNull(File(url.toURI()).parentFile) { "no parent for $url" }
                .listFiles()
                .orEmpty()
                .filter { it.isFile && it.name.endsWith(".class") }
                .map { it.name.removeSuffix(".class") }

            // Via the connection rather than by slicing the URL string: `url.path` is still
            // percent-encoded, so a checkout under a path containing a space would leave `%20`
            // in the filename and throw. The `file:` branch gets that for free from `toURI()`.
            "jar" -> (url.openConnection() as JarURLConnection).let { connection ->
                connection.useCaches = false
                connection.jarFile.use { jar ->
                    jar.entries()
                        .toList()
                        .map { it.name }
                        .filter { it.startsWith("$packagePath/") && it.endsWith(".class") }
                        .map { it.removePrefix("$packagePath/").removeSuffix(".class") }
                        .filterNot { '/' in it }
                }
            }

            else -> error("cannot enumerate classes from $url")
        }
            // Anonymous classes carry no API: `Utils$FIELDS_TYPE$1` is Gson's TypeToken.
            .filterNot { it.substringAfterLast('$').toIntOrNull() != null }
            .sorted()

        check(simpleNames.isNotEmpty()) { "no classes found for $packageName via $url" }
        return simpleNames.map { Class.forName("$packageName.$it", false, loader) }
    }

    /**
     * Every public member of the manifest's classes, paired with a test that exercises it.
     *
     * `INSTANCE` is how Java reaches a Kotlin `object`; every call in the suite goes through it.
     * The `componentN` accessors are what destructuring compiles to — they are public API a
     * consumer can write `val (id, fields, key) = entry` against, so they are covered rather
     * than waved through.
     */
    private val manifest: Map<String, String> = mapOf(
        // ── Utils ────────────────────────────────────────────────────────
        "Utils.INSTANCE" to "every test in this suite — Java's handle on the Kotlin object",
        "Utils.DEFAULT_ENDEAVOR_PACKAGE" to "IntentBuilderTest: the default vault package is Endeavor",
        "Utils.PROTOCOL_VERSION" to "ProtocolVersionTest: the protocol version and its extra key match the wire literals",
        "Utils.EXTRA_PROTOCOL_VERSION" to "ProtocolVersionTest: the protocol version and its extra key match the wire literals",
        "Utils.EXTRA_ENTRY_JSON" to "IntentBuilderTest: extra keys match the literals the vault reads",
        "Utils.EXTRA_SHARE_REQUEST_CODE" to "IntentBuilderTest: extra keys match the literals the vault reads",
        "Utils.EXTRA_QUERY_RESULT_FIELDS" to "IntentBuilderTest: extra keys match the literals the vault reads",
        "Utils.EXTRA_PUBLIC_KEY" to "IntentBuilderTest: extra keys match the literals the vault reads",
        "Utils.EXTRA_NONCE" to "IntentBuilderTest: extra keys match the literals the vault reads",
        "Utils.EXTRA_SIGNATURE" to "IntentBuilderTest: extra keys match the literals the vault reads",
        "Utils.EXTRA_ALGORITHM" to "IntentBuilderTest: extra keys match the literals the vault reads",
        "Utils.EXTRA_FIELDS_JSON" to "IntentBuilderTest: extra keys match the literals the vault reads",
        "Utils.shareDataAction" to "IntentBuilderTest: action strings are scoped to the target package",
        "Utils.signChallengeAction" to "IntentBuilderTest: action strings are scoped to the target package",
        "Utils.createShareIntent" to "IntentBuilderTest: share intent targets the vault and carries the entry as JSON",
        "Utils.shareEntry" to "ShareEntryTest: shareEntry returns true and starts the intent when a vault handles it",
        "Utils.createQueryIntent" to "IntentBuilderTest: query intent reuses the share action and carries the public key",
        "Utils.generateNonce" to "NonceTest: a nonce is a timestamp followed by at least 32 random bytes",
        "Utils.isNonceFresh" to "NonceTest: a nonce exactly maxAgeMillis old is still fresh",
        "Utils.nonceTimestamp" to "NonceTest: nonceTimestamp round-trips the pinned clock of a generated nonce",
        "Utils.EXTRA_NONCE_FORMAT" to "NonceFormatTest: the nonce-format constants match the wire literals",
        "Utils.NONCE_FORMAT_TIMESTAMPED" to "NonceFormatTest: the nonce-format constants match the wire literals",
        "Utils.createSignChallengeIntent" to "IntentBuilderTest: sign challenge intent carries key, nonce and request code",
        "Utils.verifySignature" to "SignatureVerificationTest: a genuine signature over the nonce verifies",
        "Utils.STATEMENT_DOMAIN_V1" to "StatementPreImageTest: the domain prefix and the kind tag match the wire literals",
        "Utils.STATEMENT_ROTATE_V1" to "StatementPreImageTest: the domain prefix and the kind tag match the wire literals",
        "Utils.rotationStatementBytes" to "StatementPreImageTest: the pre-image of a fixed statement is frozen",
        "Utils.STATEMENT_RECOVER_V1" to "RecoveryPreImageTest: the recovery and revocation kind tags match the wire literals",
        "Utils.STATEMENT_REVOKE_V1" to "RecoveryPreImageTest: the recovery and revocation kind tags match the wire literals",
        "Utils.recoveryAuthorizationBytes" to "RecoveryPreImageTest: the pre-image of a fixed recovery authorization is frozen",
        "Utils.revocationBytes" to "RecoveryPreImageTest: the pre-image of a fixed revocation is frozen",
        "Utils.isStatementPreImage" to "StatementPreImageTest: a pre-image arriving as a sign-challenge nonce is recognised",
        "Utils.verifyRotationStatement" to "RotationVerificationTest: a real statement signed by the stored key verifies VALID",
        "Utils.verifyRecoveryAuthorization" to "RecoveryVerificationTest: a real authorization signed by the stored key verifies VALID",
        "Utils.verifyRevocation" to "RecoveryVerificationTest: a real revocation signed by the stored key verifies VALID",
        "Utils.parseSignChallengeResult" to "ResultParsingTest: a full sign-challenge result is decoded",
        "Utils.parseQueryResult" to "ResultParsingTest: a full query result is decoded",
        "Utils.parseShareResult" to "ResultParsingTest: a full share result is decoded",
        "Utils.parseShareRequest" to "RequestParsingTest: a share intent round-trips through parseShareRequest field-for-field",
        "Utils.parseQueryRequest" to "RequestParsingTest: a query intent round-trips through parseQueryRequest field-for-field",
        "Utils.parseSignChallengeRequest" to "RequestParsingTest: a sign-challenge intent round-trips through parseSignChallengeRequest field-for-field",
        "Utils.matchesRequestCode" to "RequestCodeTest: an echoed request code matches the one that was sent",
        "Utils.validateEntry" to "EntryValidationTest: a well-formed entry reports no problems",
        "Utils.encodeFields" to "FieldsCodecTest: round trip preserves every key, value and type",
        "Utils.decodeFields" to "FieldsCodecTest: round trip preserves every key, value and type",
        "Utils.decodeEntry" to "EntryCodecTest: round trip returns a well-formed entry unchanged",

        // ── FieldType ────────────────────────────────────────────────────
        "FieldType.INSTANCE" to "every FieldTypeTest case — Java's handle on the Kotlin object",
        "FieldType.STRING" to "FieldTypeTest: KNOWN contains exactly the documented types",
        "FieldType.INTEGER" to "FieldTypeTest: KNOWN contains exactly the documented types",
        "FieldType.DECIMAL" to "FieldTypeTest: KNOWN contains exactly the documented types",
        "FieldType.BOOLEAN" to "FieldTypeTest: KNOWN contains exactly the documented types",
        "FieldType.DATE" to "FieldTypeTest: KNOWN contains exactly the documented types",
        "FieldType.EMAIL" to "FieldTypeTest: KNOWN contains exactly the documented types",
        "FieldType.PHONE" to "FieldTypeTest: KNOWN contains exactly the documented types",
        "FieldType.URL" to "FieldTypeTest: KNOWN contains exactly the documented types",
        "FieldType.getKNOWN" to "FieldTypeTest: KNOWN contains exactly the documented types",
        "FieldType.normalize" to "FieldTypeTest: canonical spellings normalize to themselves",

        // ── Entry ────────────────────────────────────────────────────────
        "Entry.getId" to "EntryCodecTest: round trip returns a well-formed entry unchanged",
        "Entry.getFields" to "EntryCodecTest: round trip preserves every field key, value and type",
        "Entry.getPublicKey" to "EntryCodecTest: round trip returns a well-formed entry unchanged",
        "Entry.component1" to "PublicApiAuditTest: an entry destructures into its three properties",
        "Entry.component2" to "PublicApiAuditTest: an entry destructures into its three properties",
        "Entry.component3" to "PublicApiAuditTest: an entry destructures into its three properties",
        "Entry.copy" to "ToStringRedactionTest: copy still carries the real values",
        "Entry.equals" to "ToStringRedactionTest: equals and hashCode are unaffected",
        "Entry.hashCode" to "ToStringRedactionTest: equals and hashCode are unaffected",
        "Entry.toString" to "ToStringRedactionTest: entry toString does not print any field value, including through the nested map",
        "Entry.writeToParcel" to "EntryParcelTest: a multi-field entry survives the round trip intact",
        "Entry.describeContents" to "PublicApiAuditTest: describeContents declares no special objects",
        "Entry.CREATOR" to "EntryParcelTest: a multi-field entry survives the round trip intact",
        "Entry.Companion" to "EntryParcelTest: a multi-field entry survives the round trip intact",
        "Entry\$Companion.write" to "EntryParcelTest: values are not transposed with types",
        "Entry\$Companion.create" to "EntryParcelTest: values are not transposed with types",
        "Entry\$Companion.newArray" to "PublicApiAuditTest: the entry Parceler refuses to allocate arrays, loudly",
        "Entry\$Creator.createFromParcel" to "EntryParcelTest: a multi-field entry survives the round trip intact",
        "Entry\$Creator.newArray" to "PublicApiAuditTest: newArray allocates an empty array of the requested size",

        // ── TypedField ───────────────────────────────────────────────────
        "TypedField.getValue" to "FieldsCodecTest: round trip preserves every key, value and type",
        "TypedField.getType" to "FieldsCodecTest: round trip preserves every key, value and type",
        "TypedField.component1" to "PublicApiAuditTest: a typed field destructures into its value and type",
        "TypedField.component2" to "PublicApiAuditTest: a typed field destructures into its value and type",
        "TypedField.copy" to "ToStringRedactionTest: copy still carries the real values",
        "TypedField.equals" to "ToStringRedactionTest: equals and hashCode are unaffected",
        "TypedField.hashCode" to "ToStringRedactionTest: equals and hashCode are unaffected",
        "TypedField.toString" to "ToStringRedactionTest: typed field toString does not print its value",
        "TypedField.writeToParcel" to "EntryParcelTest: a typed field is parcelable in its own right",
        "TypedField.describeContents" to "PublicApiAuditTest: describeContents declares no special objects",
        "TypedField.CREATOR" to "EntryParcelTest: a typed field is parcelable in its own right",
        "TypedField\$Creator.createFromParcel" to "EntryParcelTest: a typed field is parcelable in its own right",
        "TypedField\$Creator.newArray" to "PublicApiAuditTest: newArray allocates an empty array of the requested size",

        // ── RedactionKt ──────────────────────────────────────────────────
        //
        // Declared `internal`, which is *not* private in the published jar: Kotlin compiles
        // top-level internal functions to public JVM methods, so a Java consumer can call
        // `RedactionKt.redactedValue(...)` even though a Kotlin one cannot see it. That makes
        // them part of the shipped surface whether or not they were meant to be, so they are
        // audited like everything else rather than filtered out for looking private in source.
        "RedactionKt.redactedValue" to "ToStringRedactionTest: a value is rendered as its length",
        "RedactionKt.previewedPublicKey" to "ToStringRedactionTest: two real public keys are distinguishable in the preview",
        "RedactionKt.PUBLIC_KEY_PREVIEW_CHARS" to "ToStringRedactionTest: the truncation boundary is inclusive",

        // ── QueryResult ──────────────────────────────────────────────────
        "QueryResult.getFields" to "ResultParsingTest: a full query result is decoded",
        "QueryResult.getPublicKey" to "ResultParsingTest: a full query result is decoded",
        "QueryResult.getRequestCode" to "ResultParsingTest: a full query result is decoded",
        "QueryResult.getVaultProtocolVersion" to "ProtocolVersionTest: a version-2 result reports the vault's protocol version on all three parsers",
        "QueryResult.component1" to "PublicApiAuditTest: a query result destructures into its four properties",
        "QueryResult.component2" to "PublicApiAuditTest: a query result destructures into its four properties",
        "QueryResult.component3" to "PublicApiAuditTest: a query result destructures into its four properties",
        "QueryResult.component4" to "PublicApiAuditTest: a query result destructures into its four properties",
        "QueryResult.copy" to "PublicApiAuditTest: query results carrying the same values are equal",
        "QueryResult.equals" to "PublicApiAuditTest: query results carrying the same values are equal",
        "QueryResult.hashCode" to "PublicApiAuditTest: query results carrying the same values are equal",
        "QueryResult.toString" to "ToStringRedactionTest: query result toString does not print disclosed field values",

        // ── ShareResult ──────────────────────────────────────────────────
        "ShareResult.getPublicKey" to "ResultParsingTest: a full share result is decoded",
        "ShareResult.getFields" to "ResultParsingTest: a full share result is decoded",
        "ShareResult.getRequestCode" to "ResultParsingTest: a full share result is decoded",
        "ShareResult.getVaultProtocolVersion" to "ProtocolVersionTest: a version-2 result reports the vault's protocol version on all three parsers",
        "ShareResult.component1" to "PublicApiAuditTest: a share result destructures into its four properties",
        "ShareResult.component2" to "PublicApiAuditTest: a share result destructures into its four properties",
        "ShareResult.component3" to "PublicApiAuditTest: a share result destructures into its four properties",
        "ShareResult.component4" to "PublicApiAuditTest: a share result destructures into its four properties",
        "ShareResult.copy" to "PublicApiAuditTest: share results carrying the same values are equal",
        "ShareResult.equals" to "PublicApiAuditTest: share results carrying the same values are equal",
        "ShareResult.hashCode" to "PublicApiAuditTest: share results carrying the same values are equal",
        "ShareResult.toString" to "ToStringRedactionTest: share result toString does not print stored field values",

        // ── ShareRequest ─────────────────────────────────────────────────
        "ShareRequest.getEntry" to "RequestParsingTest: a share intent round-trips through parseShareRequest field-for-field",
        "ShareRequest.getRequestCode" to "RequestParsingTest: a tagged share intent carries its request code through",
        "ShareRequest.getProtocolVersion" to "RequestParsingTest: a share intent round-trips through parseShareRequest field-for-field",
        "ShareRequest.component1" to "RequestParsingTest: a share request destructures into its three properties",
        "ShareRequest.component2" to "RequestParsingTest: a share request destructures into its three properties",
        "ShareRequest.component3" to "RequestParsingTest: a share request destructures into its three properties",
        "ShareRequest.copy" to "RequestParsingTest: share requests carrying the same values are equal",
        "ShareRequest.equals" to "RequestParsingTest: share requests carrying the same values are equal",
        "ShareRequest.hashCode" to "RequestParsingTest: share requests carrying the same values are equal",
        "ShareRequest.toString" to "RequestParsingTest: no request toString prints a field value",

        // ── QueryRequest ─────────────────────────────────────────────────
        "QueryRequest.getPublicKey" to "RequestParsingTest: a query intent round-trips through parseQueryRequest field-for-field",
        "QueryRequest.getRequestCode" to "RequestParsingTest: a query intent round-trips through parseQueryRequest field-for-field",
        "QueryRequest.getProtocolVersion" to "RequestParsingTest: an unusable declared protocol version reads as null",
        "QueryRequest.component1" to "RequestParsingTest: a query request destructures into its three properties",
        "QueryRequest.component2" to "RequestParsingTest: a query request destructures into its three properties",
        "QueryRequest.component3" to "RequestParsingTest: a query request destructures into its three properties",
        "QueryRequest.copy" to "RequestParsingTest: query requests carrying the same values are equal",
        "QueryRequest.equals" to "RequestParsingTest: query requests carrying the same values are equal",
        "QueryRequest.hashCode" to "RequestParsingTest: query requests carrying the same values are equal",
        // Nothing on a query request is personal data, so its toString is generated; the fuzz
        // arm is what exercises it over hostile contents.
        "QueryRequest.toString" to "DecoderFuzzTest: no mutated payload makes a request parser throw or yield something unsafe",

        // ── SignChallengeRequest ─────────────────────────────────────────
        "SignChallengeRequest.getPublicKey" to "RequestParsingTest: a sign-challenge intent round-trips through parseSignChallengeRequest field-for-field",
        "SignChallengeRequest.getNonce" to "RequestParsingTest: a sign-challenge intent round-trips through parseSignChallengeRequest field-for-field",
        "SignChallengeRequest.getRequestCode" to "RequestParsingTest: a sign-challenge intent round-trips through parseSignChallengeRequest field-for-field",
        "SignChallengeRequest.getNonceFormat" to "RequestParsingTest: an undeclared nonce format arrives as null and a declared one arrives verbatim",
        "SignChallengeRequest.getProtocolVersion" to "RequestParsingTest: a sign-challenge intent round-trips through parseSignChallengeRequest field-for-field",
        "SignChallengeRequest.component1" to "RequestParsingTest: a sign-challenge request destructures into its five properties",
        "SignChallengeRequest.component2" to "RequestParsingTest: a sign-challenge request destructures into its five properties",
        "SignChallengeRequest.component3" to "RequestParsingTest: a sign-challenge request destructures into its five properties",
        "SignChallengeRequest.component4" to "RequestParsingTest: a sign-challenge request destructures into its five properties",
        "SignChallengeRequest.component5" to "RequestParsingTest: a sign-challenge request destructures into its five properties",
        "SignChallengeRequest.copy" to "RequestParsingTest: sign-challenge requests carrying the same nonce bytes are equal",
        "SignChallengeRequest.equals" to "RequestParsingTest: sign-challenge requests carrying the same nonce bytes are equal",
        "SignChallengeRequest.hashCode" to "RequestParsingTest: sign-challenge requests carrying the same nonce bytes are equal",
        "SignChallengeRequest.toString" to "RequestParsingTest: no request toString prints a field value",

        // ── RotationStatement ────────────────────────────────────────────
        //
        // Not a wire type: it is never decoded from an intent, so there is no `Unsafe` hazard
        // here and no parser to fail closed. What matters about it is that its five components
        // all reach the signature, which is one test apiece rather than one line here.
        "RotationStatement.getOldPublicKey" to "StatementPreImageTest: the pre-image reads back component for component",
        "RotationStatement.getNewPublicKey" to "StatementPreImageTest: the pre-image reads back component for component",
        "RotationStatement.getStatementId" to "StatementPreImageTest: the pre-image reads back component for component",
        "RotationStatement.getIssuedAtMillis" to "StatementPreImageTest: the pre-image reads back component for component",
        "RotationStatement.getExpiresAtMillis" to "StatementPreImageTest: the pre-image reads back component for component",
        "RotationStatement.component1" to "PublicApiAuditTest: a rotation statement destructures into its five properties",
        "RotationStatement.component2" to "PublicApiAuditTest: a rotation statement destructures into its five properties",
        "RotationStatement.component3" to "PublicApiAuditTest: a rotation statement destructures into its five properties",
        "RotationStatement.component4" to "PublicApiAuditTest: a rotation statement destructures into its five properties",
        "RotationStatement.component5" to "PublicApiAuditTest: a rotation statement destructures into its five properties",
        "RotationStatement.copy" to "StatementPreImageTest: changing the new public key changes the bytes",
        "RotationStatement.equals" to "PublicApiAuditTest: rotation statements carrying the same values are equal",
        "RotationStatement.hashCode" to "PublicApiAuditTest: rotation statements carrying the same values are equal",
        "RotationStatement.toString" to "StatementPreImageTest: toString previews both real keys, truncated and distinct",

        // ── RecoveryAuthorization ────────────────────────────────────────
        //
        // Like `RotationStatement`, not a wire type: never decoded from an intent, so no `Unsafe`
        // hazard and no parser to fail closed. What matters is that all five components reach the
        // signature — one test apiece — and that `sequence` in particular does, since the whole
        // safety of revocation is an ordering over it.
        "RecoveryAuthorization.getSubjectPublicKey" to "RecoveryPreImageTest: each pre-image reads back component for component",
        "RecoveryAuthorization.getRecoveryPublicKey" to "RecoveryPreImageTest: each pre-image reads back component for component",
        "RecoveryAuthorization.getAuthorizationId" to "RecoveryPreImageTest: each pre-image reads back component for component",
        "RecoveryAuthorization.getSequence" to "RecoveryPreImageTest: each pre-image reads back component for component",
        "RecoveryAuthorization.getIssuedAtMillis" to "RecoveryPreImageTest: each pre-image reads back component for component",
        "RecoveryAuthorization.component1" to "PublicApiAuditTest: a recovery authorization destructures into its five properties",
        "RecoveryAuthorization.component2" to "PublicApiAuditTest: a recovery authorization destructures into its five properties",
        "RecoveryAuthorization.component3" to "PublicApiAuditTest: a recovery authorization destructures into its five properties",
        "RecoveryAuthorization.component4" to "PublicApiAuditTest: a recovery authorization destructures into its five properties",
        "RecoveryAuthorization.component5" to "PublicApiAuditTest: a recovery authorization destructures into its five properties",
        "RecoveryAuthorization.copy" to "RecoveryPreImageTest: changing the recovery key changes the bytes",
        "RecoveryAuthorization.equals" to "PublicApiAuditTest: recovery authorizations carrying the same values are equal",
        "RecoveryAuthorization.hashCode" to "PublicApiAuditTest: recovery authorizations carrying the same values are equal",
        "RecoveryAuthorization.toString" to "RecoveryPreImageTest: authorization toString previews both real keys, truncated and distinct",

        // ── Revocation ───────────────────────────────────────────────────
        "Revocation.getSubjectPublicKey" to "RecoveryPreImageTest: each pre-image reads back component for component",
        "Revocation.getRevokedAuthorizationId" to "RecoveryPreImageTest: each pre-image reads back component for component",
        "Revocation.getSequence" to "RecoveryPreImageTest: each pre-image reads back component for component",
        "Revocation.getIssuedAtMillis" to "RecoveryPreImageTest: each pre-image reads back component for component",
        "Revocation.component1" to "PublicApiAuditTest: a revocation destructures into its four properties",
        "Revocation.component2" to "PublicApiAuditTest: a revocation destructures into its four properties",
        "Revocation.component3" to "PublicApiAuditTest: a revocation destructures into its four properties",
        "Revocation.component4" to "PublicApiAuditTest: a revocation destructures into its four properties",
        "Revocation.copy" to "RecoveryPreImageTest: changing the revocation sequence changes the bytes",
        "Revocation.equals" to "PublicApiAuditTest: revocations carrying the same values are equal",
        "Revocation.hashCode" to "PublicApiAuditTest: revocations carrying the same values are equal",
        "Revocation.toString" to "RecoveryPreImageTest: revocation toString previews its key and names what it revokes",

        // ── StatementVerdict ─────────────────────────────────────────────
        //
        // An enum's constants are public API in the strongest sense: an integrator writes an
        // exhaustive `when` over them, so removing one breaks compilation and *adding* one breaks
        // it too. Each is therefore claimed by the test that proves a verifier can actually
        // return it — a constant no verifier reaches would be a branch every integrator must
        // write and no input can ever take.
        "StatementVerdict.VALID" to "RotationVerificationTest: a real statement signed by the stored key verifies VALID",
        "StatementVerdict.SIGNATURE_INVALID" to "RotationVerificationTest: a different keypair's signature over the same statement is SIGNATURE_INVALID",
        "StatementVerdict.WRONG_SUBJECT" to "RotationVerificationTest: a genuine statement naming another profile is WRONG_SUBJECT",
        "StatementVerdict.SAME_KEY" to "RotationVerificationTest: a rotation onto the key already stored is SAME_KEY",
        "StatementVerdict.NEW_KEY_UNUSABLE" to "RotationVerificationTest: a blank, non-Base64 or non-key replacement is NEW_KEY_UNUSABLE",
        "StatementVerdict.EXPIRED" to "RotationVerificationTest: exactly the expiry instant is still valid and one millisecond later is not",
        "StatementVerdict.NOT_YET_VALID" to "RotationVerificationTest: exactly the issue instant is valid and one millisecond earlier is not",
        "StatementVerdict.values" to "PublicApiAuditTest: the verdict enum exposes exactly the documented values in order",
        "StatementVerdict.valueOf" to "PublicApiAuditTest: the verdict enum exposes exactly the documented values in order",
        "StatementVerdict.getEntries" to "PublicApiAuditTest: the verdict enum exposes exactly the documented values in order",

        // ── SignChallengeResult ──────────────────────────────────────────
        "SignChallengeResult.getSignature" to "ResultParsingTest: a full sign-challenge result is decoded",
        "SignChallengeResult.getAlgorithm" to "ResultParsingTest: a full sign-challenge result is decoded",
        "SignChallengeResult.getFields" to "ResultParsingTest: a full sign-challenge result is decoded",
        "SignChallengeResult.getRequestCode" to "ResultParsingTest: a full sign-challenge result is decoded",
        "SignChallengeResult.getVaultProtocolVersion" to "ProtocolVersionTest: a version-2 result reports the vault's protocol version on all three parsers",
        "SignChallengeResult.component1" to "PublicApiAuditTest: a sign-challenge result destructures into its five properties",
        "SignChallengeResult.component2" to "PublicApiAuditTest: a sign-challenge result destructures into its five properties",
        "SignChallengeResult.component3" to "PublicApiAuditTest: a sign-challenge result destructures into its five properties",
        "SignChallengeResult.component4" to "PublicApiAuditTest: a sign-challenge result destructures into its five properties",
        "SignChallengeResult.component5" to "PublicApiAuditTest: a sign-challenge result destructures into its five properties",
        "SignChallengeResult.copy" to "PublicApiAuditTest: copying a sign-challenge result keeps it unauthenticated until verified",
        "SignChallengeResult.equals" to "ResultParsingTest: results carrying the same bytes are equal",
        "SignChallengeResult.hashCode" to "ResultParsingTest: results carrying the same bytes are equal",
        "SignChallengeResult.isVerified" to "ResultParsingTest: a genuine signature verifies against the key and nonce that produced it",
        "SignChallengeResult.toString" to "ToStringRedactionTest: sign-challenge result toString does not print disclosed field values",
    )

    /**
     * A generic type as a consumer would write it: `Map<String, TypedField>`, not
     * `java.util.Map<java.lang.String, dev.eryalabs.lim.TypedField>`. Package qualifiers are
     * stripped so the snapshot reads as a diff rather than as a wall. Nested classes keep their
     * `$`, matching how the manifest already spells `Entry$Companion`.
     *
     * The cost of stripping is that package *identity* goes with it — `java.util.Map` and some
     * other `Map` render alike. That is the second blind spot named on the snapshot below, and
     * the only way to exploit it is to swap a public parameter for a same-simple-name class from
     * another package, which is not a change anybody makes by accident.
     */
    private fun render(type: Type): String = PACKAGE_QUALIFIER.replace(type.typeName, "")

    /**
     * Public members as a Java consumer sees them, minus the noise the Kotlin compiler adds for
     * its own use. Synthetic and bridge members are the `$default` overloads carrying
     * default-argument values and the covariant bridges a data class generates; nobody writes
     * against those, and they move with the compiler rather than with this library.
     */
    private fun publicSurface(): Set<String> = types.flatMap { type ->
        val name = type.name.substringAfterLast('.')
        val methods = type.declaredMethods
            .filter { Modifier.isPublic(it.modifiers) && !it.isSynthetic && !it.isBridge }
            .map { "$name.${it.name}" }
        val fields = type.declaredFields
            .filter { Modifier.isPublic(it.modifiers) && !it.isSynthetic }
            .map { "$name.${it.name}" }
        methods + fields
    }.toSet()

    @Test
    fun `every public member is named in the audit`() {
        val uncovered = (publicSurface() - manifest.keys).sorted()
        assertEquals(
            "these public members have no entry in the audit — write a test and record it here, " +
                "do not delete the member",
            emptyList<String>(),
            uncovered,
        )
    }

    /**
     * The other direction, and the one that catches a *removed* member. A manifest entry naming
     * something that no longer exists means either a stale line here or — the case that matters —
     * a public member deleted or renamed out from under the apps that ship against it.
     */
    @Test
    fun `the audit names nothing that no longer exists`() {
        val stale = (manifest.keys - publicSurface()).sorted()
        assertEquals(
            "the audit names members reflection cannot find. For a member of the Kotlin-visible " +
                "API, removing or renaming it breaks apps compiled against 1.0.0 and is stop " +
                "rule 10 — fix the code, not this list. The RedactionKt.* entries are the " +
                "exception: they are `internal`, so they are JVM surface by accident rather " +
                "than API anybody was offered, and renaming one is an ordinary refactor that " +
                "should simply be recorded here",
            emptyList<String>(),
            stale,
        )
    }

    /**
     * The manifest's *values*, machine-checked.
     *
     * "The test that covers this member" is the one claim this whole audit rests on, and the
     * failure mode T9 warns about is a member waved through by a line naming a test that does
     * not do what it says — or does not exist. The second half of that is checkable here: every
     * value must name a real `@Test` in this package, or be one of the handful of members whose
     * coverage is genuinely diffuse rather than a single case.
     */
    @Test
    fun `every manifest entry names a test that exists`() {
        // Keyed by class *and* method. Every test in this suite lives in one package, so
        // matching the method name alone would let "Utils.decodeEntry" be credited to
        // "EntryCodecTest: <a FieldsCodecTest name>" — a citation that resolves to a real test
        // in the wrong file, which is precisely the mis-attribution this audit must not make.
        val realTests: Set<String> = classesInPackage(this::class.java)
            .flatMap { type ->
                type.declaredMethods
                    .filter { it.isAnnotationPresent(Test::class.java) }
                    .map { "${type.name.substringAfterLast('.')}: ${it.name}" }
            }
            .toSet()
        check(realTests.size > 100) { "found only ${realTests.size} tests; the scan is broken" }

        val dangling = manifest.entries
            .filter { (member, _) -> member !in DIFFUSE_COVERAGE }
            .filterNot { (_, coveredBy) -> coveredBy in realTests }
            .map { (member, coveredBy) -> "$member -> $coveredBy" }
            .sorted()

        assertEquals(
            "the audit cites tests that do not exist under the class it names; a renamed or " +
                "moved test must be updated here too, or the member it covered is silently " +
                "unclaimed",
            emptyList<String>(),
            dangling,
        )
    }

    /**
     * The exact shape of every public member, snapshotted.
     *
     * The manifest above is keyed by bare name, which answers "is anything untested" but says
     * nothing about *shape* — and a shape change is the quiet way to break the published API. A
     * parameter retyped, an arity changed, a return type narrowed, or a member removed all leave
     * every other assertion in this file green. So do overloads: `createShareIntent` is one
     * manifest key covering two functions, and a third could be added under it unnoticed.
     *
     * This is a change-detector, not a judgement. A line moving here is a deliberate act, and
     * stop rule 10 decides whether the act is allowed: additions are fine, a removal or a
     * narrowed parameter is the thing to stop and think about.
     *
     * Type arguments are included, because erasing them would leave a hole as wide as the one
     * this closes: `decodeFields` returning `Map<String, String>` instead of
     * `Map<String, TypedField>` breaks every consumer at compile time and does not move a single
     * erased descriptor. They come from the JVM `Signature` attribute kotlinc already emits, via
     * plain `java.lang.reflect` — no new dependency.
     *
     * Two things it still cannot see. The lesser one is package identity, since [render] strips
     * qualifiers — see there. The one worth knowing about:
     *
     * **Kotlin nullability.** `decodeFields(json: String?)` narrowed
     * to `decodeFields(json: String)` breaks every Kotlin caller passing null and does not
     * change the bytecode signature by one byte, so it would slip through here. Kotlin records
     * that in `@Nullable` annotations with CLASS retention and in its own `@Metadata`, neither
     * of which Java reflection can read; catching it would need `kotlin-reflect`, and a new
     * dependency is a human decision under stop rule 5. Recorded rather than papered over.
     */
    @Test
    fun `the published signatures have not changed`() {
        val actual = types.flatMap { type ->
            val name = type.name.substringAfterLast('.')
            val methods = type.declaredMethods
                .filter { Modifier.isPublic(it.modifiers) && !it.isSynthetic && !it.isBridge }
                .map { m ->
                    val params = m.genericParameterTypes.joinToString(", ", transform = ::render)
                    "$name.${m.name}($params): ${render(m.genericReturnType)}"
                }
            val fields = type.declaredFields
                .filter { Modifier.isPublic(it.modifiers) && !it.isSynthetic }
                .map { "$name.${it.name}: ${render(it.genericType)}" }
            methods + fields
        }.sorted()

        assertEquals(
            "the published API's shape changed; adding a member is fine and this list moves " +
                "with it, but a removal or a narrowed parameter breaks apps compiled against " +
                "1.0.0 — see stop rule 10",
            SIGNATURES,
            actual,
        )
    }

    /** Negative control: an audit over an empty surface would pass both tests above. */
    @Test
    fun `the surface is not empty`() {
        val surface = publicSurface()
        assertTrue("reflection found no public members at all; got $surface", surface.size > 50)
        assertTrue("Utils.decodeEntry must be in the surface", "Utils.decodeEntry" in surface)
        assertTrue(
            "the private helpers must NOT be in the surface, or the filter is doing nothing",
            "Utils.base64Bytes" !in surface && "Utils.presentStringExtra" !in surface,
        )

        // The discovery itself, since everything above is scoped by it: a scan that silently
        // found nothing would make this whole file vacuous.
        val discovered = types.map { it.name.substringAfterLast('.') }.toSet()
        assertTrue(
            "class discovery must find every published type; got $discovered",
            discovered.containsAll(
                setOf(
                    "Utils", "FieldType", "Entry", "Entry\$Companion", "TypedField",
                    "QueryResult", "ShareResult", "SignChallengeResult",
                    "ShareRequest", "QueryRequest", "SignChallengeRequest",
                    "RotationStatement", "RecoveryAuthorization", "Revocation",
                    "StatementVerdict",
                ),
            ),
        )
        // Not an oversight, and worth one assertion because it surprises people: `internal` is a
        // Kotlin-only visibility. These compile to public JVM methods and ship in the AAR, so
        // Java callers can reach them and the audit has to account for them.
        assertTrue(
            "Redaction.kt's internal helpers are public in the bytecode and must be audited",
            publicSurface().any { it.startsWith("RedactionKt.") },
        )
    }

    // ── Members the audit found with no test anywhere ─────────────────────

    @Test
    fun `an entry destructures into its three properties`() {
        val entry = Entry("profile-1", mapOf("a" to TypedField("v", FieldType.EMAIL)), "pk")
        val (id, fields, publicKey) = entry
        assertEquals("profile-1", id)
        assertEquals("v", fields["a"]?.value)
        assertEquals("pk", publicKey)
    }

    @Test
    fun `a typed field destructures into its value and type`() {
        val (value, type) = TypedField("ada@example.com", FieldType.EMAIL)
        assertEquals("ada@example.com", value)
        assertEquals(FieldType.EMAIL, type)
    }

    @Test
    fun `a query result destructures into its four properties`() {
        val (fields, publicKey, requestCode, vaultProtocolVersion) =
            QueryResult(mapOf("a" to TypedField("v")), "pk", "req-1", 2)
        assertEquals("v", fields["a"]?.value)
        assertEquals("pk", publicKey)
        assertEquals("req-1", requestCode)
        assertEquals(2, vaultProtocolVersion)
    }

    @Test
    fun `a share result destructures into its four properties`() {
        val (publicKey, fields, requestCode, vaultProtocolVersion) =
            ShareResult("pk", mapOf("a" to TypedField("v")), "req-1", 2)
        assertEquals("pk", publicKey)
        assertEquals("v", fields["a"]?.value)
        assertEquals("req-1", requestCode)
        assertEquals(2, vaultProtocolVersion)
    }

    /**
     * Same claim as its query sibling: only ordinary values here, so the generated `equals`
     * is correct as generated — but that is a claim until it is a test.
     */
    @Test
    fun `share results carrying the same values are equal`() {
        val fields = mapOf("email" to TypedField("ada@example.com", FieldType.EMAIL))
        val a = ShareResult("pk", fields, "req-1")
        val b = ShareResult("pk", fields, "req-1")

        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
        assertNotEquals(a, a.copy(requestCode = "req-2"))
        assertNotEquals(a, a.copy(publicKey = null))
        assertNotEquals(a, a.copy(fields = emptyMap()))
        assertNotEquals(a, a.copy(vaultProtocolVersion = 2))
        assertEquals("copy must carry the values it was not asked to change", "pk", a.copy(requestCode = "z").publicKey)
    }

    @Test
    fun `a sign-challenge result destructures into its five properties`() {
        val (signature, algorithm, fields, requestCode, vaultProtocolVersion) =
            SignChallengeResult(byteArrayOf(1, 2, 3), "SHA256withRSA", mapOf("a" to TypedField("v")), "req-1", 2)
        assertTrue(byteArrayOf(1, 2, 3).contentEquals(signature))
        assertEquals("SHA256withRSA", algorithm)
        assertEquals("v", fields["a"]?.value)
        assertEquals("req-1", requestCode)
        assertEquals(2, vaultProtocolVersion)
    }

    /**
     * [QueryResult] holds only ordinary values, so the generated `equals` is correct as
     * generated — unlike [SignChallengeResult], whose `ByteArray` forced a hand-written one.
     * Pinned anyway: a client that de-duplicates or caches results by value depends on it, and
     * "the generated one is fine" is a claim, not a test.
     */
    @Test
    fun `query results carrying the same values are equal`() {
        val fields = mapOf("email" to TypedField("ada@example.com", FieldType.EMAIL))
        val a = QueryResult(fields, "pk", "req-1")
        val b = QueryResult(fields, "pk", "req-1")

        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
        assertNotEquals(a, a.copy(requestCode = "req-2"))
        assertNotEquals(a, a.copy(publicKey = null))
        assertNotEquals(a, a.copy(fields = emptyMap()))
        assertNotEquals(a, a.copy(vaultProtocolVersion = 2))
        assertEquals("copy must carry the values it was not asked to change", "pk", a.copy(requestCode = "z").publicKey)
    }

    @Test
    fun `a rotation statement destructures into its five properties`() {
        val (oldKey, newKey, statementId, issuedAt, expiresAt) =
            RotationStatement("K-OLD", "K-NEW", "rot-1", 10L, 20L)
        assertEquals("K-OLD", oldKey)
        assertEquals("K-NEW", newKey)
        assertEquals("rot-1", statementId)
        assertEquals(10L, issuedAt)
        assertEquals(20L, expiresAt)
    }

    /**
     * The generated `equals` is correct as generated — five ordinary values, no array — but a
     * statement is compared for a living reason: a service deduplicating rotations it has been
     * shown, or matching one against a record it kept, depends on it. The `copy` assertions are
     * what `StatementPreImageTest`'s one-component-changed controls build on, so they are pinned
     * here rather than assumed there.
     */
    @Test
    fun `rotation statements carrying the same values are equal`() {
        val a = RotationStatement("K-OLD", "K-NEW", "rot-1", 10L, 20L)
        val b = RotationStatement("K-OLD", "K-NEW", "rot-1", 10L, 20L)

        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
        assertNotEquals(a, a.copy(oldPublicKey = "K-OTHER"))
        assertNotEquals(a, a.copy(newPublicKey = "K-OTHER"))
        assertNotEquals(a, a.copy(statementId = "rot-2"))
        assertNotEquals(a, a.copy(issuedAtMillis = 11L))
        assertNotEquals(a, a.copy(expiresAtMillis = 21L))
        assertEquals(
            "copy must carry the values it was not asked to change",
            "K-NEW",
            a.copy(statementId = "rot-2").newPublicKey,
        )
    }

    @Test
    fun `a recovery authorization destructures into its five properties`() {
        val (subject, recovery, id, sequence, issuedAt) =
            RecoveryAuthorization("K-SUBJECT", "K-RECOVERY", "rec-1", 7L, 10L)
        assertEquals("K-SUBJECT", subject)
        assertEquals("K-RECOVERY", recovery)
        assertEquals("rec-1", id)
        assertEquals(7L, sequence)
        assertEquals(10L, issuedAt)
    }

    /**
     * The generated `equals` is correct as generated — five ordinary values, no array — but an
     * authorization is compared for a living reason: T17's revocation arithmetic decides which
     * authorizations are still live by matching them against revocations, and a service holding a
     * set of them de-duplicates by value. The `copy` assertions are what the pre-image's
     * one-component-changed controls build on, so they are pinned here rather than assumed there.
     */
    @Test
    fun `recovery authorizations carrying the same values are equal`() {
        val a = RecoveryAuthorization("K-SUBJECT", "K-RECOVERY", "rec-1", 7L, 10L)
        val b = RecoveryAuthorization("K-SUBJECT", "K-RECOVERY", "rec-1", 7L, 10L)

        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
        assertNotEquals(a, a.copy(subjectPublicKey = "K-OTHER"))
        assertNotEquals(a, a.copy(recoveryPublicKey = "K-OTHER"))
        assertNotEquals(a, a.copy(authorizationId = "rec-2"))
        assertNotEquals(a, a.copy(sequence = 8L))
        assertNotEquals(a, a.copy(issuedAtMillis = 11L))
        assertEquals(
            "copy must carry the values it was not asked to change",
            "K-RECOVERY",
            a.copy(authorizationId = "rec-2").recoveryPublicKey,
        )
    }

    @Test
    fun `a revocation destructures into its four properties`() {
        val (subject, revoked, sequence, issuedAt) = Revocation("K-SUBJECT", "rec-1", 8L, 10L)
        assertEquals("K-SUBJECT", subject)
        assertEquals("rec-1", revoked)
        assertEquals(8L, sequence)
        assertEquals(10L, issuedAt)
    }

    @Test
    fun `revocations carrying the same values are equal`() {
        val a = Revocation("K-SUBJECT", "rec-1", 8L, 10L)
        val b = Revocation("K-SUBJECT", "rec-1", 8L, 10L)

        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
        assertNotEquals(a, a.copy(subjectPublicKey = "K-OTHER"))
        assertNotEquals(a, a.copy(revokedAuthorizationId = "rec-2"))
        assertNotEquals(a, a.copy(sequence = 9L))
        assertNotEquals(a, a.copy(issuedAtMillis = 11L))
        assertEquals(
            "copy must carry the values it was not asked to change",
            "rec-1",
            a.copy(sequence = 9L).revokedAuthorizationId,
        )
    }

    /**
     * The enum's own generated API, and the one property of it that is not generated: the
     * declared order.
     *
     * `values()`, `valueOf` and `entries` have no home in the verifier's own tests — nothing in
     * this library calls them — but they ship, and a Java integrator reaches every one. The
     * ordering matters beyond neatness: an enum's `ordinal` is what anything persisting a verdict
     * by index writes down, so inserting a value in the middle silently reinterprets stored data.
     * Listed rather than counted, so a rename shows up as the name it broke.
     */
    @Test
    fun `the verdict enum exposes exactly the documented values in order`() {
        assertEquals(
            "adding a value is API a consumer's exhaustive `when` must handle; inserting one " +
                "anywhere but the end also renumbers every ordinal after it",
            listOf(
                "VALID", "SIGNATURE_INVALID", "WRONG_SUBJECT", "SAME_KEY", "NEW_KEY_UNUSABLE",
                "EXPIRED", "NOT_YET_VALID",
            ),
            StatementVerdict.values().map { it.name },
        )
        assertEquals(StatementVerdict.SAME_KEY, StatementVerdict.valueOf("SAME_KEY"))
        assertEquals(StatementVerdict.values().toList(), StatementVerdict.entries)
    }

    /**
     * `copy` is the one route by which a caller can build a result the vault never sent, so the
     * property T3 made structural is re-asserted across it: a copied result is still just a
     * claim, and the only thing that can settle it is [SignChallengeResult.isVerified] against
     * the caller's own key and nonce.
     */
    @Test
    fun `copying a sign-challenge result keeps it unauthenticated until verified`() {
        val nonce = Utils.generateNonce(now = 1_770_000_000_000L)
        val keyPair = java.security.KeyPairGenerator.getInstance("RSA")
            .apply { initialize(2048) }
            .generateKeyPair()
        val signature = java.security.Signature.getInstance("SHA256withRSA").run {
            initSign(keyPair.private)
            update(nonce)
            sign()
        }
        val publicKey = Base64.encodeToString(keyPair.public.encoded, Base64.DEFAULT)

        val genuine = SignChallengeResult(signature, "SHA256withRSA", emptyMap(), "req-1")
        assertTrue(genuine.isVerified(publicKey, nonce))

        val retagged = genuine.copy(requestCode = "req-2")
        assertTrue("copying an unrelated property must not disturb the proof", retagged.isVerified(publicKey, nonce))
        assertEquals("req-2", retagged.requestCode)

        val forged = genuine.copy(signature = ByteArray(signature.size) { 7 })
        assertTrue(
            "a copy with substituted bytes must not authenticate",
            !forged.isVerified(publicKey, nonce),
        )
    }

    /**
     * Neither class parcels a file descriptor or anything else needing special handling, and
     * both inherit the answer from `@Parcelize`. Worth a line because a non-zero value here is
     * a contract with the framework, not a detail: it changes how the parcel is transported.
     */
    @Test
    fun `describeContents declares no special objects`() {
        assertEquals(0, Entry("id", emptyMap(), "pk").describeContents())
        assertEquals(0, TypedField("v").describeContents())
    }

    /**
     * The one public member that does not degrade safely, pinned rather than quietly fixed.
     *
     * `Entry` supplies its own [kotlinx.parcelize.Parceler], and the `newArray` that interface
     * ships as a default is a `TODO()`: it throws `NotImplementedError` on every call. Supplying
     * a Parceler therefore *added* a public member to `Entry` that can only ever fail, and
     * `Entry.newArray(2)` is a plausible thing for a consumer to type. Nothing in this library
     * calls it and nothing in the suite went near it, so it sat unexercised.
     *
     * It is left throwing on purpose, and the reasoning belongs next to the assertion:
     *
     * - **Nothing reaches it by accident.** `@Parcelize` does not use it — the `CREATOR` it
     *   generates allocates the array itself, which the next test proves — so every path the
     *   *framework* takes through an `Entry[]` is fine. Only a hand-written direct call lands
     *   here.
     * - **The obvious fix is worse than the defect.** [kotlinx.parcelize.Parceler] declares
     *   `newArray(size): Array<T>` with `T` non-null, so the only implementation that compiles
     *   is `arrayOfNulls(size) as Array<Entry>` — an unchecked cast producing an array of
     *   declared-non-null elements that are all genuinely null. That is the precise hazard this
     *   library exists to shut down everywhere else (`decodeEntry`, `TypedField.repaired`,
     *   `Redaction.kt`), and it would trade a loud failure at the mistaken call for an NPE
     *   somewhere downstream with nothing pointing back here.
     *
     * So: covered, reported, and left alone. Changing it is a judgement call for a human, not
     * something an audit should decide on the quiet.
     */
    @Test
    fun `the entry Parceler refuses to allocate arrays, loudly`() {
        val thrown = try {
            Entry.newArray(3)
            null
        } catch (t: Throwable) {
            t
        }

        assertNotNull("Parceler.newArray is a TODO() and must fail visibly", thrown)
        assertTrue(
            "the failure must be the immediate, diagnosable one, not a null dereference later; " +
                "got ${thrown!!.javaClass.name}",
            thrown is NotImplementedError,
        )
    }

    @Test
    fun `an array of entries survives the round trip`() {
        val entries = arrayOf(
            Entry("profile-1", mapOf("a" to TypedField("one", FieldType.STRING)), "pk-1"),
            Entry("profile-2", mapOf("b" to TypedField("two", FieldType.EMAIL)), "pk-2"),
        )

        val parcel = Parcel.obtain()
        val restored = try {
            parcel.writeParcelableArray(entries, 0)
            parcel.setDataPosition(0)
            parcel.readParcelableArray(Entry::class.java.classLoader)
        } finally {
            parcel.recycle()
        }

        assertNotNull("an Entry[] must survive a parcel", restored)
        assertEquals(2, restored!!.size)
        assertEquals(entries[0], restored[0])
        assertEquals(entries[1], restored[1])
    }

    /**
     * The array `Entry.CREATOR` allocates is sized and empty, not populated or null.
     *
     * Reached by reflection because `@Parcelize` emits `CREATOR` as a Java static field, which
     * Kotlin cannot name on a class whose companion is a [kotlinx.parcelize.Parceler]. A Java
     * consumer — and the framework — has no such trouble, which is the whole point of asserting
     * it: this is API that exists for callers this library's own language cannot reach.
     */
    @Test
    fun `newArray allocates an empty array of the requested size`() {
        fun creatorOf(type: Class<*>): android.os.Parcelable.Creator<*> =
            type.getField("CREATOR").get(null) as android.os.Parcelable.Creator<*>

        listOf(Entry::class.java, TypedField::class.java).forEach { type ->
            val creator = creatorOf(type)
            assertEquals("${type.simpleName}: zero", 0, creator.newArray(0).size)

            val three = creator.newArray(3)
            assertEquals("${type.simpleName}: size", 3, three.size)
            three.forEach { assertNull("${type.simpleName}: a fresh slot must be null", it) }
        }
    }

    companion object {
        /**
         * The members whose manifest entry deliberately does not name a single test. A Kotlin
         * `object`'s `INSTANCE` is how Java reaches it, and every call in the suite goes through
         * it; pointing at one case would be less true rather than more precise.
         *
         * Keyed by *member*, not by the prose that excuses it. Keyed by prose, a future
         * `object Vault` could be waved through by copying an existing string, with no edit
         * here and no test anywhere. Each waiver now has to name what it excuses.
         */
        private val DIFFUSE_COVERAGE = setOf(
            "Utils.INSTANCE",
            "FieldType.INSTANCE",
        )

        /**
         * Strips `java.util.` from `java.util.Map` but leaves `Map` and `TypedField` alone: a
         * run of lowercase-initial dot-separated segments immediately before a capitalised one.
         */
        private val PACKAGE_QUALIFIER = Regex("""\b(?:[a-z][A-Za-z0-9_]*\.)+(?=[A-Z])""")

        /** See `the published signatures have not changed`. Sorted, so a diff here reads. */
        private val SIGNATURES = listOf(
            "Entry\$Companion.create(Parcel): Entry",
            "Entry\$Companion.newArray(int): Entry[]",
            "Entry\$Companion.write(Entry, Parcel, int): void",
            "Entry\$Creator.createFromParcel(Parcel): Entry",
            "Entry\$Creator.newArray(int): Entry[]",
            "Entry.CREATOR: Parcelable\$Creator<Entry>",
            "Entry.Companion: Entry\$Companion",
            "Entry.component1(): String",
            "Entry.component2(): Map<String, TypedField>",
            "Entry.component3(): String",
            "Entry.copy(String, Map<String, TypedField>, String): Entry",
            "Entry.describeContents(): int",
            "Entry.equals(Object): boolean",
            "Entry.getFields(): Map<String, TypedField>",
            "Entry.getId(): String",
            "Entry.getPublicKey(): String",
            "Entry.hashCode(): int",
            "Entry.toString(): String",
            "Entry.writeToParcel(Parcel, int): void",
            "FieldType.BOOLEAN: String",
            "FieldType.DATE: String",
            "FieldType.DECIMAL: String",
            "FieldType.EMAIL: String",
            "FieldType.INSTANCE: FieldType",
            "FieldType.INTEGER: String",
            "FieldType.PHONE: String",
            "FieldType.STRING: String",
            "FieldType.URL: String",
            "FieldType.getKNOWN(): Set<String>",
            "FieldType.normalize(String): String",
            "QueryRequest.component1(): String",
            "QueryRequest.component2(): String",
            "QueryRequest.component3(): Integer",
            "QueryRequest.copy(String, String, Integer): QueryRequest",
            "QueryRequest.equals(Object): boolean",
            "QueryRequest.getProtocolVersion(): Integer",
            "QueryRequest.getPublicKey(): String",
            "QueryRequest.getRequestCode(): String",
            "QueryRequest.hashCode(): int",
            "QueryRequest.toString(): String",
            "QueryResult.component1(): Map<String, TypedField>",
            "QueryResult.component2(): String",
            "QueryResult.component3(): String",
            "QueryResult.component4(): Integer",
            "QueryResult.copy(Map<String, TypedField>, String, String, Integer): QueryResult",
            "QueryResult.equals(Object): boolean",
            "QueryResult.getFields(): Map<String, TypedField>",
            "QueryResult.getPublicKey(): String",
            "QueryResult.getRequestCode(): String",
            "QueryResult.getVaultProtocolVersion(): Integer",
            "QueryResult.hashCode(): int",
            "QueryResult.toString(): String",
            "RecoveryAuthorization.component1(): String",
            "RecoveryAuthorization.component2(): String",
            "RecoveryAuthorization.component3(): String",
            "RecoveryAuthorization.component4(): long",
            "RecoveryAuthorization.component5(): long",
            "RecoveryAuthorization.copy(String, String, String, long, long): RecoveryAuthorization",
            "RecoveryAuthorization.equals(Object): boolean",
            "RecoveryAuthorization.getAuthorizationId(): String",
            "RecoveryAuthorization.getIssuedAtMillis(): long",
            "RecoveryAuthorization.getRecoveryPublicKey(): String",
            "RecoveryAuthorization.getSequence(): long",
            "RecoveryAuthorization.getSubjectPublicKey(): String",
            "RecoveryAuthorization.hashCode(): int",
            "RecoveryAuthorization.toString(): String",
            "RedactionKt.PUBLIC_KEY_PREVIEW_CHARS: int",
            "RedactionKt.previewedPublicKey(String): String",
            "RedactionKt.redactedValue(String): String",
            "Revocation.component1(): String",
            "Revocation.component2(): String",
            "Revocation.component3(): long",
            "Revocation.component4(): long",
            "Revocation.copy(String, String, long, long): Revocation",
            "Revocation.equals(Object): boolean",
            "Revocation.getIssuedAtMillis(): long",
            "Revocation.getRevokedAuthorizationId(): String",
            "Revocation.getSequence(): long",
            "Revocation.getSubjectPublicKey(): String",
            "Revocation.hashCode(): int",
            "Revocation.toString(): String",
            "RotationStatement.component1(): String",
            "RotationStatement.component2(): String",
            "RotationStatement.component3(): String",
            "RotationStatement.component4(): long",
            "RotationStatement.component5(): long",
            "RotationStatement.copy(String, String, String, long, long): RotationStatement",
            "RotationStatement.equals(Object): boolean",
            "RotationStatement.getExpiresAtMillis(): long",
            "RotationStatement.getIssuedAtMillis(): long",
            "RotationStatement.getNewPublicKey(): String",
            "RotationStatement.getOldPublicKey(): String",
            "RotationStatement.getStatementId(): String",
            "RotationStatement.hashCode(): int",
            "RotationStatement.toString(): String",
            "ShareRequest.component1(): Entry",
            "ShareRequest.component2(): String",
            "ShareRequest.component3(): Integer",
            "ShareRequest.copy(Entry, String, Integer): ShareRequest",
            "ShareRequest.equals(Object): boolean",
            "ShareRequest.getEntry(): Entry",
            "ShareRequest.getProtocolVersion(): Integer",
            "ShareRequest.getRequestCode(): String",
            "ShareRequest.hashCode(): int",
            "ShareRequest.toString(): String",
            "ShareResult.component1(): String",
            "ShareResult.component2(): Map<String, TypedField>",
            "ShareResult.component3(): String",
            "ShareResult.component4(): Integer",
            "ShareResult.copy(String, Map<String, TypedField>, String, Integer): ShareResult",
            "ShareResult.equals(Object): boolean",
            "ShareResult.getFields(): Map<String, TypedField>",
            "ShareResult.getPublicKey(): String",
            "ShareResult.getRequestCode(): String",
            "ShareResult.getVaultProtocolVersion(): Integer",
            "ShareResult.hashCode(): int",
            "ShareResult.toString(): String",
            "SignChallengeRequest.component1(): String",
            "SignChallengeRequest.component2(): byte[]",
            "SignChallengeRequest.component3(): String",
            "SignChallengeRequest.component4(): String",
            "SignChallengeRequest.component5(): Integer",
            "SignChallengeRequest.copy(String, byte[], String, String, Integer): SignChallengeRequest",
            "SignChallengeRequest.equals(Object): boolean",
            "SignChallengeRequest.getNonce(): byte[]",
            "SignChallengeRequest.getNonceFormat(): String",
            "SignChallengeRequest.getProtocolVersion(): Integer",
            "SignChallengeRequest.getPublicKey(): String",
            "SignChallengeRequest.getRequestCode(): String",
            "SignChallengeRequest.hashCode(): int",
            "SignChallengeRequest.toString(): String",
            "SignChallengeResult.component1(): byte[]",
            "SignChallengeResult.component2(): String",
            "SignChallengeResult.component3(): Map<String, TypedField>",
            "SignChallengeResult.component4(): String",
            "SignChallengeResult.component5(): Integer",
            "SignChallengeResult.copy(byte[], String, Map<String, TypedField>, String, Integer): SignChallengeResult",
            "SignChallengeResult.equals(Object): boolean",
            "SignChallengeResult.getAlgorithm(): String",
            "SignChallengeResult.getFields(): Map<String, TypedField>",
            "SignChallengeResult.getRequestCode(): String",
            "SignChallengeResult.getSignature(): byte[]",
            "SignChallengeResult.getVaultProtocolVersion(): Integer",
            "SignChallengeResult.hashCode(): int",
            "SignChallengeResult.isVerified(String, byte[]): boolean",
            "SignChallengeResult.toString(): String",
            "StatementVerdict.EXPIRED: StatementVerdict",
            "StatementVerdict.NEW_KEY_UNUSABLE: StatementVerdict",
            "StatementVerdict.NOT_YET_VALID: StatementVerdict",
            "StatementVerdict.SAME_KEY: StatementVerdict",
            "StatementVerdict.SIGNATURE_INVALID: StatementVerdict",
            "StatementVerdict.VALID: StatementVerdict",
            "StatementVerdict.WRONG_SUBJECT: StatementVerdict",
            "StatementVerdict.getEntries(): EnumEntries<StatementVerdict>",
            "StatementVerdict.valueOf(String): StatementVerdict",
            "StatementVerdict.values(): StatementVerdict[]",
            "TypedField\$Creator.createFromParcel(Parcel): TypedField",
            "TypedField\$Creator.newArray(int): TypedField[]",
            "TypedField.CREATOR: Parcelable\$Creator<TypedField>",
            "TypedField.component1(): String",
            "TypedField.component2(): String",
            "TypedField.copy(String, String): TypedField",
            "TypedField.describeContents(): int",
            "TypedField.equals(Object): boolean",
            "TypedField.getType(): String",
            "TypedField.getValue(): String",
            "TypedField.hashCode(): int",
            "TypedField.toString(): String",
            "TypedField.writeToParcel(Parcel, int): void",
            "Utils.DEFAULT_ENDEAVOR_PACKAGE: String",
            "Utils.EXTRA_ALGORITHM: String",
            "Utils.EXTRA_ENTRY_JSON: String",
            "Utils.EXTRA_FIELDS_JSON: String",
            "Utils.EXTRA_NONCE: String",
            "Utils.EXTRA_NONCE_FORMAT: String",
            "Utils.EXTRA_PROTOCOL_VERSION: String",
            "Utils.EXTRA_PUBLIC_KEY: String",
            "Utils.EXTRA_QUERY_RESULT_FIELDS: String",
            "Utils.EXTRA_SHARE_REQUEST_CODE: String",
            "Utils.EXTRA_SIGNATURE: String",
            "Utils.INSTANCE: Utils",
            "Utils.NONCE_FORMAT_TIMESTAMPED: String",
            "Utils.PROTOCOL_VERSION: int",
            "Utils.STATEMENT_DOMAIN_V1: String",
            "Utils.STATEMENT_RECOVER_V1: String",
            "Utils.STATEMENT_REVOKE_V1: String",
            "Utils.STATEMENT_ROTATE_V1: String",
            "Utils.createQueryIntent(Context, String, String, String): Intent",
            // Two overloads, listed separately. A bare-name manifest cannot tell them apart,
            // which is the gap this snapshot exists to cover.
            "Utils.createShareIntent(Context, Entry, String): Intent",
            "Utils.createShareIntent(Context, Entry, String, String): Intent",
            // T12 widened this with a defaulted `nonceFormat: String?` — an addition, which
            // stop rule 10 permits; the pre-T12 arity is gone from the *Kotlin* signature
            // (defaults compile to one method plus a $default bridge, not overloads).
            "Utils.createSignChallengeIntent(Context, String, byte[], String, String, String): Intent",
            "Utils.decodeEntry(String): Entry",
            "Utils.decodeFields(String): Map<String, TypedField>",
            "Utils.encodeFields(Map<String, TypedField>): String",
            "Utils.generateNonce(SecureRandom, long): byte[]",
            "Utils.isNonceFresh(byte[], long, long): boolean",
            "Utils.isStatementPreImage(byte[]): boolean",
            "Utils.matchesRequestCode(Intent, String): boolean",
            "Utils.nonceTimestamp(byte[]): Long",
            "Utils.parseQueryRequest(Intent): QueryRequest",
            "Utils.parseQueryResult(Intent): QueryResult",
            "Utils.parseShareRequest(Intent): ShareRequest",
            "Utils.parseShareResult(Intent): ShareResult",
            "Utils.parseSignChallengeRequest(Intent): SignChallengeRequest",
            "Utils.parseSignChallengeResult(Intent): SignChallengeResult",
            "Utils.recoveryAuthorizationBytes(RecoveryAuthorization): byte[]",
            "Utils.revocationBytes(Revocation): byte[]",
            "Utils.rotationStatementBytes(RotationStatement): byte[]",
            "Utils.shareDataAction(String): String",
            "Utils.shareEntry(Context, Entry, String): boolean",
            "Utils.signChallengeAction(String): String",
            "Utils.validateEntry(Entry): List<String>",
            // Neither takes a clock, and the absence is the design: an authorization declares no
            // expiry, and a revocation that could go stale would un-revoke a stolen device.
            "Utils.verifyRecoveryAuthorization(RecoveryAuthorization, byte[], String): StatementVerdict",
            "Utils.verifyRevocation(Revocation, byte[], String): StatementVerdict",
            "Utils.verifyRotationStatement(RotationStatement, byte[], String, long): StatementVerdict",
            "Utils.verifySignature(String, byte[], byte[]): boolean",
        )
    }
}
