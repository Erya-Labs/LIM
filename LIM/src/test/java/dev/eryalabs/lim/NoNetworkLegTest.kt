package dev.eryalabs.lim

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element
import org.xml.sax.InputSource
import java.io.File
import java.io.StringReader
import java.lang.reflect.Modifier
import java.net.JarURLConnection
import java.net.URL
import javax.xml.parsers.DocumentBuilderFactory

/**
 * **"This library has no network leg of any kind" — the claim two published documents make, and
 * the first evidence for it in this repository.**
 *
 * `docs/INTEGRATION.md`'s Login section states it to an integrator and [Revocation]'s class KDoc
 * calls it "the property the whole design exists for". Until this file, nothing checked it.
 * Measured rather than assumed, at the commit that added this class:
 * `grep -rni 'network' LIM/src/test` returned **two** lines outside this file, and both are prose
 * — `SignatureVerificationTest`'s "no device, no keystore, no network", which asserts nothing, and
 * `GuideSnippetTest`'s excuse text about nothing here reaching the network to resolve a Maven
 * coordinate, which is about a build and not about this. A grep is a grep and not a census, so
 * that is the claim: no line *mentioning the word* was an assertion.
 *
 * Two arms, for the two layers that were unmeasured:
 *
 *  - **Arm A, a bytecode census** over every class compiled into `dev.eryalabs.lim`, looking for
 *    the name of any networking type in the class bytes. This is the only arm that can see inside
 *    a method body; a source grep cannot, and the published API surface cannot.
 *  - **Arm B, the module manifest**, read off disk: no `<uses-permission>` and no `<permission>`
 *    element, so in particular no `INTERNET`.
 *
 * **The third layer is already bought elsewhere and is deliberately not repeated here.**
 * `GuideSnippetTest`'s *the guide prints the coordinate the build file declares* reads this
 * module's `dependencies` block and asserts **exactly one** dependency a consumer inherits,
 * matching `implementation|api|runtimeOnly` anchored with `(?m)^\s*` — an anchor that also defeats
 * the `testImplementation(` trap a word-boundary parser would be written to avoid. What that regex
 * does not name is `compileOnly(`/`compileOnlyApi(`, which reach no consumer's runtime classpath,
 * and the variant-scoped configurations like `releaseImplementation(`, which would; neither kind
 * exists in the build file at all, so nothing is owed and a third arm here would be the same
 * assertion twice.
 *
 * **And the other half of the same sentence, added after this class was first written.** The
 * guide's line is "The private key never leaves the vault **and** this library has no network leg
 * of any kind", and the first half was unmeasured too — four main sources repeat it
 * ([RotationStatement], [RecoveryAuthorization] and [Revocation] each with "Nothing in this class
 * signs anything. The private key lives in the vault's Keystore…", and
 * [Utils.createSignChallengeResultIntent] with "this library holding a private key, which it does
 * not do"). `no class compiled into the library holds or names a private key` measures it, in
 * three arms, **reusing [census] directly rather than from a sibling class**: `ApiBaselineTest`
 * says in so many words why this repository copies an enumeration idiom instead of extracting it,
 * and a second file here would force a choice between a third copy and an extraction that would
 * have to edit the files it enumerates. The class keeps its name, which is about the network half;
 * it now covers the whole sentence.
 *
 * **No Robolectric, and no runner annotation.** No arm touches an Android type: the byte census
 * reads class bytes through the classloader, the manifest arm parses a file with the JDK's own
 * XML parser, and the surface census reflects over classes loaded uninitialised, which resolves
 * the `android.os.Parcel` parameter types off the stub `android.jar` already on the unit-test
 * classpath — exactly as `ApiBaselineTest` does. A sandbox would cost seconds and buy nothing.
 *
 * **This test writes nothing.** `LIM/src/main/AndroidManifest.xml` is opened for reading and never
 * modified, no permission is added anywhere, and the build file is not touched — an arm about
 * permissions is exactly the shape that gets misread, so it is said here plainly.
 *
 * **Two limits, repeated beside each assertion where they bite.** A census over *this library's*
 * classes says LIM contains no network call; it says nothing about Gson, or about anything else a
 * consumer puts on the classpath. And the manifest read here is **this module's**, not the merged
 * manifest of a consumer's app, which this repository cannot build — the same limit
 * `docs/INTEGRATION.md` already states for the consumer keep rules.
 */
class NoNetworkLegTest {

    // ── Arm A: the bytecode census ────────────────────────────────────────

    /**
     * **The claim.** No class compiled into `dev.eryalabs.lim` names a networking type.
     *
     * The census is only as good as what it enumerated, so this test asserts three things about
     * the scan itself before it asserts the absence:
     *
     *  - **Which root was enumerated.** The library's own classes arrive as `classes.jar` and a
     *    test's as a directory of files — a distinction `ApiBaselineTest` records as a comment and
     *    never checks, because it only ever anchors on [Utils]. Here it is checked, because a
     *    layout change that moved the library's classes beside the test classes would silently
     *    poison this census with test classes (which legitimately reference `java.net`), and one
     *    that moved them out of reach would silently shrink it.
     *  - **That no test class is in the set**, which is the same protection stated as a property
     *    rather than as a packaging detail.
     *  - **Three floors**, in `the bytecode census reads a whole library rather than nothing`.
     *
     * **What this absence claim cannot see, written beside it rather than only at the scanner.**
     * A name assembled at run time — `Class.forName("java.net." + "Socket")` — leaves no whole
     * token in the constant pool and goes unreported; and the scan sees only what the unit-test
     * classpath presents, so a variant-specific source set, of which there is none today, would be
     * invisible to it. In the other direction it is deliberately over-sensitive: a token in a
     * string literal is reported too. [census] states both at length.
     *
     * **The limit, written where the assertion is:** this is a census over the classes *this
     * library* compiles. Gson is on a consumer's runtime classpath too and is not scanned.
     */
    @Test
    fun `no class compiled into the library references a networking type`() {
        val census = census(Utils::class.java)

        // Both counts, and the one this arm uses is `classesScanned`: the census keeps the
        // anonymous classes `ApiBaselineTest`'s filter throws away.
        println(
            "NoNetworkLegTest arm A: root=${census.root} (${census.root.protocol}), " +
                "classesScanned=${census.names.size}, " +
                "nonAnonymous=${census.names.count { !it.isAnonymousShaped() }} (not used), " +
                "bytes=${census.bytes}, vocabulary=${FORBIDDEN.size}",
        )

        assertEquals(
            "the library's own classes are expected to arrive as `classes.jar`, so the census " +
                "root should be a `jar:` URL. It is ${census.root}. If AGP's layout changed, " +
                "check that the enumerated set is still this library's classes and not the test " +
                "classpath's before relaxing this line — a census pointed at the wrong root is " +
                "the one failure mode absence assertions cannot show you",
            "jar",
            census.root.protocol,
        )
        assertEquals(
            "a test class turned up in the enumeration, so this census is no longer scanning " +
                "only the library. Test sources reference `java.net` legitimately (see the " +
                "control below), so leaving them in would make the absence claim meaningless",
            emptyList<String>(),
            census.names.filter { it.substringBefore('$').endsWith("Test") },
        )
        assertEquals(
            "a class compiled into `dev.eryalabs.lim` names a networking type. This library " +
                "promises an integrator that it has no network leg of any kind " +
                "(`docs/INTEGRATION.md`, Login) and that the relay gap is the price of it " +
                "(`Revocation`) — so a hit here is either a protocol change a human must decide " +
                "(stop rule 5) or a mistake. Scanned ${census.names.size} classes under " +
                "${census.root}",
            emptyList<String>(),
            census.hits,
        )
    }

    /**
     * **The floors, which are what make an empty scan fail.**
     *
     * The test above is an *absence* claim, and absence claims pass vacuously: a scanner that
     * enumerated nothing, or read zero bytes, or had an empty vocabulary, reports no hit and goes
     * green for ever. Each of the three ways that can happen gets a floor here, and this test —
     * not the one above — is what reddens when one does. The split is deliberate and the two
     * should stay separate: one is a census, this one is a floor.
     *
     * The floors sit below the measured figures on purpose, so that adding a class or a token is
     * not a test edit; they are a tripwire against collapse, not a pin.
     */
    @Test
    fun `the bytecode census reads a whole library rather than nothing`() {
        val census = census(Utils::class.java)

        assertTrue(
            "the census enumerated only ${census.names.size} classes, below the floor of " +
                "$CLASS_FLOOR. At the commit that wrote this test the package held " +
                "$MEASURED_CLASSES class files, of which ${MEASURED_CLASSES - 1} survive the " +
                "`Name\$1` filter `ApiBaselineTest` applies and this census deliberately does " +
                "not — a Kotlin lambda or `object` literal compiles to exactly that shape, so " +
                "dropping them would leave a `Socket()` inside one in a file nothing opened. " +
                "If classes were legitimately removed, lower this floor in the same commit and " +
                "say so; if not, the enumeration is broken. Found: ${census.names}",
            census.names.size >= CLASS_FLOOR,
        )
        assertTrue(
            "the census read ${census.bytes} bytes of class file, below the floor of " +
                "$BYTE_FLOOR. Enumerating files and then reading none of them passes every " +
                "absence assertion above",
            census.bytes >= BYTE_FLOOR,
        )
        assertTrue(
            "the forbidden-token vocabulary is down to ${FORBIDDEN.size} entries, below the " +
                "floor of $VOCABULARY_FLOOR. Deleting a token is the one edit that makes the " +
                "census above weaker without reddening it",
            FORBIDDEN.size >= VOCABULARY_FLOOR,
        )
    }

    /**
     * **Control (a), and the load-bearing one: the same scanner, pointed at classes that *do*
     * reach for the network, reports them.**
     *
     * Without this, arm A could be reporting nothing because it inspects nothing — the failure
     * mode every census-shaped test has. The test sources are the honest counterexample:
     * `ApiBaselineTest` imports and casts to `java.net.JarURLConnection` to walk `classes.jar`, so
     * its class file carries `java/net/JarURLConnection` in its constant pool.
     *
     * It also drives the enumerator's **other** branch: a test class's root is a directory, not a
     * jar, so the `"file"` arm of [classesInPackage] — unexercised by `ApiBaselineTest`, which
     * only ever anchors on [Utils] — is executed here.
     *
     * The assertion names `ApiBaselineTest` specifically rather than merely counting hits, because
     * this very file would otherwise satisfy it on its own: [FORBIDDEN]'s tokens are string
     * constants in `NoNetworkLegTest.class`, so the scanner finds itself.
     */
    @Test
    fun `control - the same scanner over the test classes reports the networking they use`() {
        val census = census(ApiBaselineTest::class.java)

        println(
            "NoNetworkLegTest control (a): root=${census.root} (${census.root.protocol}), " +
                "classes=${census.names.size}, bytes=${census.bytes}, hits=${census.hits.size}",
        )

        assertEquals(
            "the test classes are expected to arrive as a directory, which is the enumerator's " +
                "other branch and the reason this control also covers it",
            "file",
            census.root.protocol,
        )
        assertTrue(
            "the scanner found no networking reference anywhere in the test classes, which " +
                "cannot be true: `ApiBaselineTest` casts to `java.net.JarURLConnection`. Arm A " +
                "is therefore reporting absence because it inspects nothing, not because there " +
                "is nothing there",
            census.hits.any { it.startsWith("ApiBaselineTest ") },
        )
    }

    // ── Arm B: the module manifest ────────────────────────────────────────

    /**
     * **The claim.** `LIM/src/main/AndroidManifest.xml` declares no permission of any kind, so in
     * particular no `INTERNET`.
     *
     * **This arm reads the file and never writes it.** No permission is added, no manifest element
     * is changed, and `git diff -- LIM/src/main/` is empty for the commit that introduced this
     * test.
     *
     * **The manifest is already a declared input of the test task, and that is cited rather than
     * measured.** `LIM/build.gradle.kts`'s `isIncludeAndroidResources = true` makes AGP generate
     * `com/android/tools/test_config.properties` with an `android_merged_manifest` key, so the
     * merged manifest is an input of `:LIM:testDebugUnitTest` already. Measuring that relation
     * would mean editing the manifest to see whether the task re-runs, and stop rule 5 forbids a
     * manifest edit even as a reverted probe — so the measurement was deliberately not taken.
     * Note also that the key names the *merged* manifest while this arm reads the *module* source
     * manifest off disk; the input relation is cited for the file, not claimed to be the same
     * artifact.
     *
     * **One anchor, which is arm A's floors in the shape this arm needs.** The document's root
     * element is asserted to be `<manifest>` before the absence is asserted. Arm B otherwise has
     * the same vacuity hole arm A's floors close: a stub file with a different root, or a path
     * that resolved to some other XML, parses cleanly and declares no permission, and the one
     * assertion anybody reads for this property would stay green over the wrong document.
     *
     * **The limit, written where the assertion is:** this is *this module's* manifest, not the
     * merged manifest of a consumer's app. A consumer may hold `INTERNET` for its own reasons and
     * nothing here can see that, exactly as `docs/INTEGRATION.md` says of the consumer keep rules.
     */
    @Test
    fun `the module manifest declares no permission`() {
        val manifest = locate(MANIFEST_RELATIVE)
        val text = manifest.readText()
        val declarations = permissionElementsIn(text)

        println(
            "NoNetworkLegTest arm B: ${manifest.absolutePath}, root=${rootElementOf(text)}, " +
                "declarations=$declarations",
        )

        assertEquals(
            "${manifest.absolutePath} parsed, but its root element is not `<manifest>`, so this " +
                "arm is reporting the absence of a permission in a document that is not an " +
                "Android manifest. Absence over the wrong file is the one failure this arm " +
                "cannot otherwise show",
            "manifest",
            rootElementOf(text),
        )
        assertEquals(
            "${manifest.absolutePath} declares a permission. This library asks for none — a " +
                "vault holds the data and this library has no network leg — and adding one is a " +
                "security-surface decision a human makes (stop rule 5), not something a test " +
                "should discover after the fact",
            emptyList<String>(),
            declarations,
        )
    }

    /**
     * **Control (c), first two shapes: the reader reports a declaration that is there.**
     *
     * Arm B reads a file with no element in it at all, so on its own it proves nothing about a
     * file with something in it. Two spellings rather than one, because a matcher tuned to the
     * canonical single line would pass straight over a wrapped declaration and the arm would be
     * an absence assertion nothing had ever tripped.
     *
     * **These fixtures carry the first literal `uses-permission` strings anywhere in this
     * repository** — `grep -rn 'uses-permission'` over sources and documents returned nothing
     * before this file. A later permission audit by grep will meet them here: they are fixtures,
     * not declarations, and no manifest in this repository contains either one.
     *
     * The third assertion is arm B's **root anchor**'s own control, and it belongs here rather
     * than in a test of its own: every document [rootElementOf] is otherwise handed in this suite
     * has root `manifest`, so a body of `return "manifest"` would satisfy all six tests. One
     * document with a different root is what makes the anchor a reader rather than a constant.
     */
    @Test
    fun `control - a permission declaration is reported in both of its spellings`() {
        assertEquals(
            "the root anchor arm B asserts must read the document rather than return a " +
                "constant: handed a root that is not `manifest`, it must say so",
            "resources",
            rootElementOf("<resources/>"),
        )
        assertEquals(
            "the canonical one-line spelling must be reported, or arm B is an absence " +
                "assertion over a reader that reports nothing",
            listOf("uses-permission[android.permission.INTERNET]"),
            permissionElementsIn(CANONICAL_PERMISSION_FIXTURE),
        )
        assertEquals(
            "a declaration with `android:name` on its own line must be reported too. A " +
                "substring matcher tuned to the canonical spelling would pass over this one, " +
                "which is why arm B parses the document instead of searching its text",
            listOf("uses-permission[android.permission.INTERNET]"),
            permissionElementsIn(WRAPPED_PERMISSION_FIXTURE),
        )
    }

    /**
     * **Control (c), third shape, and the reason arm B is XML-aware rather than a substring
     * search.**
     *
     * The prediction, written before it was run: a substring reader **reports** a commented-out
     * declaration — a false red — and an XML-aware reader does not, because a comment is not an
     * element. Measured, that is exactly what happens, and this test pins both halves so the
     * reasoning cannot quietly stop being true.
     *
     * The behaviour kept is the XML-aware one. On a file that holds no element at all, a false red
     * is as bad as a miss: it would make the one assertion anybody reads for this property fail
     * for a reason that is not the property, and the usual repair for that is to weaken the
     * assertion. [substringReaderFinds] exists only here, as the strawman this choice is measured
     * against; nothing else calls it.
     */
    @Test
    fun `control - a commented-out declaration is not a declaration, and a substring reader disagrees`() {
        val xmlAware = permissionElementsIn(COMMENTED_PERMISSION_FIXTURE)
        val substring = substringReaderFinds(COMMENTED_PERMISSION_FIXTURE)

        println(
            "NoNetworkLegTest control (c): commented-out fixture — xml-aware=$xmlAware, " +
                "substring=$substring",
        )

        assertEquals(
            "an XML-aware reader must not report a commented-out declaration: a comment is not " +
                "an element, and arm B reads a file with no element in it, where a false red is " +
                "as bad as a miss",
            emptyList<String>(),
            xmlAware,
        )
        assertEquals(
            "the strawman substring reader is supposed to report it — that false red is the " +
                "whole reason arm B parses the document. If this line stops being true the " +
                "comparison the choice rests on has changed and should be re-argued, not deleted",
            listOf("uses-permission"),
            substring,
        )
    }

    // ── The private-key half of the same sentence ─────────────────────────

    /**
     * **The claim.** Nothing this library compiles holds, names or uses a private key.
     *
     * `docs/INTEGRATION.md`'s Login section promises two things in one sentence — "The private key
     * never leaves the vault **and** this library has no network leg of any kind". Everything
     * above measures the second half. This measures the first, and four main sources say it
     * besides the guide: [RotationStatement], [RecoveryAuthorization] and [Revocation] each open a
     * paragraph "Nothing in this class signs anything. The private key lives in the vault's
     * Keystore…", and [Utils.createSignChallengeResultIntent]'s KDoc ends "A convenience that
     * signed the request's nonce for you would be this library holding a private key, which it
     * does not do."
     *
     * **One test rather than three**, because it is one sentence being checked at three depths and
     * the three share an instrument. Everything is measured and printed before anything is
     * asserted, so a red in one arm still leaves the other two's figures in the output — which is
     * the cost a single method would otherwise carry.
     *
     * The **control runs first**, deliberately: an absence claim is worth nothing until the
     * instrument has been shown to report a presence, and asserting that last would mean a broken
     * scanner passed two arms before anything noticed.
     *
     *  - **Control.** The same scanner with the same vocabulary, anchored at the **test** classes,
     *    must report the key material those classes genuinely use — `MigrationEndToEndTest`,
     *    `RotationVerificationTest`, `RecoveryVerificationTest` and others generate real keypairs
     *    and sign with them. This file's own classes are excluded from that check first, because
     *    [KEY_FORBIDDEN]'s entries are string constants compiled into them and the scanner would
     *    otherwise find itself — the trap `control - the same scanner over the test classes
     *    reports the networking they use` names for its own vocabulary.
     *  - **Arm A, the key vocabulary.** No class compiled into `dev.eryalabs.lim` names a private
     *    key type, a keystore, a keypair generator, a `javax.crypto` type, or the member names
     *    `initSign` and `getPrivateKey`. The bare token `sign` is deliberately **not** in that
     *    list: measured at this commit, `grep -la 'sign'` over the library's own class files
     *    reports six of twenty-five — [SignedStatement] and its three subclasses,
     *    [SignChallengeResult], and [Utils], which carries `signChallengeAction`, `signature` and
     *    `signatureBytes` — so an arm asserting `sign` absent would redden on its first run and
     *    assert nothing whatever about signing. `initSign` is the exact member name that would
     *    have to appear, and it is what is asserted.
     *  - **Arm B, the [java.security.Signature] member census.** Of `getInstance`, `initVerify`,
     *    `update`, `verify` and `initSign`, exactly the first four appear as tokens in the
     *    library's classes. The four present are this arm's own control: a scanner that reported
     *    nothing would fail the same assertion. What makes the arm worth having beside arm A is
     *    that an exact set catches a **new** use site — `initSign` creeping in — where arm A's
     *    absence list only catches the one token somebody remembered to forbid.
     *    **Two of the four are discriminating, not four**, and that is worth knowing before
     *    trusting the present half too far: `getInstance` is also `KeyFactory`'s
     *    ([Utils] calls it at `:977` and again at `:2930`) and `verify` is also in
     *    [SignChallengeResult]'s `isVerified`, so deleting `Utils.verifySignature` outright
     *    would still leave those two reported. `initVerify` and `update` are the two that
     *    actually track the verifying call site.
     *  - **Arm C, the published surface.** No public or protected constructor, method or field of
     *    any class compiled into the package declares a parameter, return or field type in
     *    `java.security`, **except [java.security.SecureRandom]**, which is excused by name: it is
     *    injected randomness, which this repository's Definition of done requires of every module
     *    ("Every module takes its dependencies by injection"). Read off the compiled classes the
     *    way `ApiBaselineTest` reads them, not off a list, so a new file carrying a new public
     *    type is in scope. Measured at this commit, `grep -n 'java\.security' LIM/api/lim.api`
     *    names `SecureRandom` on three lines and nothing else — and this census examines 366
     *    members, which is precisely the member count that file pins beneath its 24 class lines.
     *    **This arm carries its own control rather than borrowing one**, for the reason the byte
     *    census carries one: it must be shown to *detect* before its absence means anything. The
     *    member floor cannot do that — it counts members before inspecting a single type, so
     *    deleting the detection filter leaves it green — so the `SecureRandom` detection is
     *    asserted present, by type and by the member that earns it. **Not by count:** three
     *    overloads carry one today and a fourth is a legitimate addition, so pinning the number
     *    would make an overload a test edit. The residual gap that leaves, since there is no
     *    unexcused `java.security` type on this surface to control against: a filter narrowed to
     *    `== "java.security.SecureRandom"` would detect nothing else and still pass. Closing it
     *    would mean parameterising the prefix and scanning for `java.lang.` to prove the filter
     *    is general — contrived enough to record here rather than build.
     *
     * **Three limits, written here because each bounds an assertion below.**
     *
     *  1. **A token scan cannot attribute a member name to an owner class.** Arm B asserts
     *     "`initSign` appears nowhere in these classes, and these four tokens do" — not "`Utils`
     *     calls `initVerify` on a `Signature`". A constant-pool parse would be needed for that and
     *     this scanner does not do one. Over a library with a single `java.security.Signature`
     *     import ([Utils]) used in a single place, that is sufficient; over a library with twenty
     *     it would not be, and this note is what should be re-read if that changes.
     *  2. **This is a claim about *this library*, not about a vault's key.** That the key never
     *     leaves the device is a property of the vault's Keystore, in a repository this loop may
     *     not touch. Nothing here measures it and nothing here should be read as doing so.
     *  3. **Nothing here says *which* algorithm is verified.** `Utils.verifySignature` hardcodes
     *     `SHA256withRSA`, and whether `EXTRA_ALGORITHM` should ever be honoured is a standing
     *     Blocked-on-human decision. Out of scope on purpose.
     */
    @Test
    fun `no class compiled into the library holds or names a private key`() {
        val library = census(Utils::class.java, KEY_FORBIDDEN)
        val control = census(ApiBaselineTest::class.java, KEY_FORBIDDEN)
        // This file's own classes carry every token in `KEY_FORBIDDEN` as a string constant, so
        // the control must be read with them removed or it is satisfied by its own vocabulary.
        val controlHits = control.hits
            .filterNot { it.substringBefore(' ').substringBefore('$') == SELF }
        val controlTokens = controlHits.map { it.tokenOf() }.distinct().sorted()
        val signatureMembers = census(Utils::class.java, SIGNATURE_MEMBERS)
            .hits.map { it.tokenOf() }.distinct().sorted()
        val surface = surfaceCensus(Utils::class.java)
        val unexcused = surface.uses
            .filterNot { it.type in EXCUSED_SECURITY_TYPES }
            .map { it.toString() }

        println(
            "NoNetworkLegTest private-key control: root=${control.root}, " +
                "classes=${control.names.size}, hits=${control.hits.size} " +
                "(${controlHits.size} after dropping $SELF's own), tokens=$controlTokens",
        )
        println(
            "NoNetworkLegTest private-key arm A: root=${library.root}, " +
                "classes=${library.names.size}, bytes=${library.bytes}, " +
                "vocabulary=${KEY_FORBIDDEN.size}, hits=${library.hits}",
        )
        println("NoNetworkLegTest private-key arm B: Signature members present=$signatureMembers")
        println(
            "NoNetworkLegTest private-key arm C: classes=${surface.classesLoaded}, " +
                "members=${surface.membersExamined}, java.security uses=${surface.uses}, " +
                "unexcused=$unexcused",
        )

        // Control, first: the instrument reports key material where key material exists.
        assertEquals(
            "the same scanner over the test classes did not report key material the test " +
                "sources demonstrably use, so arms A and B below are reporting absence because " +
                "they inspect nothing. `$SELF`'s own classes were excluded before this check, " +
                "which is why its vocabulary constants cannot satisfy it. Reported: " +
                controlTokens,
            emptyList<String>(),
            CONTROL_EXPECTED_TOKENS.filterNot { it in controlTokens },
        )
        assertTrue(
            "`SignatureVerificationTest` loads a `java.security.PrivateKey` and calls `initSign` " +
                "on a `Signature`, so the scanner must name it. Naming a class rather than " +
                "counting hits is what stops this control being satisfied by some other file",
            controlHits.containsAll(CONTROL_EXPECTED_HITS),
        )

        // Arm A's own floor. The class-count and byte floors are not repeated: the enumeration
        // and the read-back are the same for either vocabulary, so
        // `the bytecode census reads a whole library rather than nothing` already covers them.
        // What neither covers is *this* list shrinking. Measured, deleting a token reddens the
        // control above for the three in CONTROL_EXPECTED_TOKENS and nothing at all for the other
        // four, so this floor is what stands behind `java/security/KeyStore`,
        // `android/security/keystore/`, `javax/crypto/` and `getPrivateKey`.
        assertTrue(
            "the private-key vocabulary is down to ${KEY_FORBIDDEN.size} entries, below the " +
                "floor of $KEY_VOCABULARY_FLOOR. Deleting a token makes arm A weaker in silence",
            KEY_FORBIDDEN.size >= KEY_VOCABULARY_FLOOR,
        )

        // Arm A.
        assertEquals(
            "a class compiled into `dev.eryalabs.lim` names a private key, a keystore or a " +
                "signing member. This library tells an integrator the private key never leaves " +
                "the vault (`docs/INTEGRATION.md`, Login) and says so again in `RotationStatement`, " +
                "`RecoveryAuthorization`, `Revocation` and `Utils.createSignChallengeResultIntent` " +
                "— so a hit here is either a security-surface change a human must decide (stop " +
                "rule 5) or a mistake. Scanned ${library.names.size} classes under ${library.root}",
            emptyList<String>(),
            library.hits,
        )

        // Arm B. An exact set, so a *new* `Signature` use site moves this line even when the
        // token is one arm A was never told to forbid. Limit 1 above bounds what it means.
        assertEquals(
            "the `java.security.Signature` members named in the library's classes are not the " +
                "four this library verifies with. `initSign` appearing means something here now " +
                "signs; one of the other four disappearing means verification moved or went. " +
                "Note what this does not say: a token scan cannot tell which class owns a member " +
                "name, so this is a statement about the tokens present, not about call sites",
            EXPECTED_SIGNATURE_MEMBERS,
            signatureMembers,
        )

        // Arm C's two floors, then arm C. The arm is an absence claim and has the same two ways
        // of passing vacuously that arm A has, so each gets its own line: a census that *read*
        // nothing, and a census that *detected* nothing. The second is the one a reviewer caught
        // missing — `membersExamined` is incremented before any type is inspected, so the first
        // floor alone stays green with the detection filter deleted outright.
        assertTrue(
            "the surface census examined only ${surface.membersExamined} members across " +
                "${surface.classesLoaded} classes, below the floor of $SURFACE_MEMBER_FLOOR. " +
                "`ApiBaselineTest` pins the same surface in `LIM/api/lim.api`, which held 366 " +
                "member lines beneath its 24 class lines when this floor was set — a census this " +
                "far below that has stopped reading the surface rather than found it clean",
            surface.membersExamined >= SURFACE_MEMBER_FLOOR,
        )
        assertEquals(
            "an excused type is not actually declared anywhere on the published surface. Either " +
                "the detector has stopped detecting — in which case the absence asserted below " +
                "is the instrument reporting nothing, and deleting the `$SECURITY_PACKAGE` " +
                "filter would pass it — or the member that earned the excuse is gone, in which " +
                "case the excuse should go with it rather than sit here covering a type nothing " +
                "declares. Reported: ${surface.uses}",
            emptyList<String>(),
            EXCUSED_SECURITY_TYPES.filterNot { excused -> surface.uses.any { it.type == excused } },
        )
        assertTrue(
            "`$EXCUSED_MEMBER` is what earns `SecureRandom` its excuse — injected randomness the " +
                "Definition of done requires — so the census must name that member for that " +
                "type. Naming the member rather than counting detections is what stops this " +
                "floor being satisfied by some unrelated `java.security` type appearing. " +
                "Reported: ${surface.uses}",
            // `in EXCUSED_SECURITY_TYPES` rather than `== …single()`: a human adding a second
            // legitimate excuse is a decision the constant's KDoc anticipates, and `single()`
            // would meet it by throwing rather than by asserting.
            surface.uses.any {
                it.type in EXCUSED_SECURITY_TYPES && it.member.startsWith(EXCUSED_MEMBER)
            },
        )
        assertEquals(
            "a published member declares a `java.security` type other than the excused " +
                "${EXCUSED_SECURITY_TYPES.joinToString()}. Every key type an integrator could be " +
                "handed, or asked for, would show up here — and this library's whole shape is " +
                "that it never touches one. `SecureRandom` is excused because it is injected " +
                "randomness the Definition of done requires; a second excuse is a decision, not " +
                "a test edit. Examined ${surface.membersExamined} members",
            emptyList<String>(),
            unexcused,
        )
    }

    /** The token half of a `"<class> references <token>"` hit line. */
    private fun String.tokenOf(): String = substringAfter(REFERENCES)

    // ── The scanner ───────────────────────────────────────────────────────

    /** What one scan found, and enough about the scan itself to say whether it found anything. */
    private class Census(
        /** The classpath root the enumeration came from — a `jar:` or a `file:` URL. */
        val root: URL,
        /** Every class simple name under the package, anonymous classes included. */
        val names: List<String>,
        /** Total class-file bytes actually read, which is the floor against an empty scan. */
        val bytes: Long,
        /** One `"<class> references <token>"` line per hit, in enumeration order. */
        val hits: List<String>,
    )

    /**
     * Every class compiled into [anchor]'s package, read back through the same classloader and
     * scanned for [vocabulary], which defaults to [FORBIDDEN].
     *
     * **[vocabulary] is a parameter rather than a constant** so that a second claim about the same
     * classes — `no class compiled into the library holds or names a private key` — can point this
     * scanner at its own token list instead of copying it. Nothing else about the scan changes
     * with it: the enumeration, the read-back and every blind spot below are the same whichever
     * list is handed in, which is why the class-count and byte floors in
     * `the bytecode census reads a whole library rather than nothing` cover both callers.
     *
     * **Through the loader rather than off a `build/` path, deliberately.** The library's classes
     * arrive as `classes.jar` and a test's as a directory of files; the loader handles both, and
     * no arm of this test may depend on an AGP output layout.
     *
     * **A raw ASCII scan of the class bytes is the whole claim, and it is sufficient.** A
     * referenced type's name is a `CONSTANT_Utf8` entry in the constant pool, so it is present as
     * plain bytes; no class-file parser is needed to find it. The scan errs in one direction on
     * purpose and is blind in three others, all four written here because the arm's entire value
     * is an absence claim:
     *
     *  - **Over-sensitive:** a token inside a *string literal* is reported too. For an absence
     *    census that is the safe way to be wrong — it costs a reader one look, where a miss costs
     *    the claim.
     *  - **Blind to a name assembled at run time.** `Class.forName("java.net." + "Socket")` leaves
     *    no whole token in the pool and this scan cannot see it.
     *  - **Blind to what the unit-test classpath does not present.** It sees the classes this
     *    variant compiles; a variant-specific source set, of which there is none today, would be
     *    invisible to it.
     *  - **Blind to shadowing between the two roots.** The *names* come from the enumeration root
     *    and the *bytes* come from the loader, and the two roots — the unit-test classes directory
     *    and `classes.jar` — both sit on that loader's search path in some order this test does
     *    not assert and nothing in this repository distinguishes. The collision that bites is on
     *    a **non-anchor** class: a test source declaring `dev.eryalabs.lim.Entry` would leave
     *    [Utils] resolving to the jar, so the root assertion still passes and the enumeration
     *    still lists `Entry` from the jar, while the read-back of `Entry.class` could come from
     *    the other root. A collision on the anchor itself is already covered — the root would
     *    report `file` and arm A would redden before reading a byte. No such collision exists today,
     *    and the byte total matching the sum of the package's own class files is the evidence of
     *    that; reading through the loader is nonetheless the deliberate choice, because it is what
     *    keeps both packagings readable without depending on an AGP output layout.
     */
    private fun census(anchor: Class<*>, vocabulary: List<String> = FORBIDDEN): Census {
        val packagePath = anchor.name.substringBeforeLast('.').replace('.', '/')
        val loader = checkNotNull(anchor.classLoader) { "no classloader for ${anchor.name}" }
        val enumeration = classesInPackage(anchor)

        var bytes = 0L
        val hits = mutableListOf<String>()
        for (simpleName in enumeration.second) {
            val resource = "$packagePath/$simpleName.class"
            val raw = checkNotNull(loader.getResourceAsStream(resource)) {
                "enumerated $resource but could not read it back through the same classloader, " +
                    "so this census would be silently incomplete"
            }.use { it.readBytes() }
            bytes += raw.size
            // ISO-8859-1 maps every byte to exactly one character, so this is the bytes as text
            // with nothing lost or merged — which UTF-8 decoding would not be.
            val text = String(raw, Charsets.ISO_8859_1)
            vocabulary.filter { it in text }.forEach { hits += "$simpleName$REFERENCES$it" }
        }
        return Census(enumeration.first, enumeration.second, bytes, hits)
    }

    /**
     * The classpath root and every class simple name under [anchor]'s package, **anonymous classes
     * included**.
     *
     * `ApiBaselineTest`'s enumeration idiom, kept as a second copy for the reason that file states
     * about its own copy of it, with one deliberate difference: it drops every `Name$1`-shaped
     * class because "anonymous classes carry no API", which is right for a surface baseline and
     * wrong for an absence census. A Kotlin lambda or `object` literal compiles to exactly that
     * shape, so a networking call inside one would sit in a file the enumeration never opened.
     * One such file exists today — `Utils$FIELDS_TYPE$1`, Gson's `TypeToken`.
     *
     * Located through the class file rather than the `CodeSource`, for the reason
     * `ApiBaselineTest` gives: under a Robolectric sandbox the protection domain reports no
     * location at all, and this test may share a JVM with tests that install one.
     */
    private fun classesInPackage(anchor: Class<*>): Pair<URL, List<String>> {
        val packageName = anchor.name.substringBeforeLast('.')
        val anchorPath = anchor.name.replace('.', '/') + ".class"
        val loader = checkNotNull(anchor.classLoader) { "no classloader for ${anchor.name}" }
        val url = checkNotNull(loader.getResource(anchorPath)) {
            "cannot locate $anchorPath on the classpath"
        }
        val packagePath = packageName.replace('.', '/')

        val simpleNames = when (url.protocol) {
            "file" -> checkNotNull(File(url.toURI()).parentFile) { "no parent for $url" }
                .listFiles()
                .orEmpty()
                .filter { it.isFile && it.name.endsWith(".class") }
                .map { it.name.removeSuffix(".class") }

            // Via the connection rather than by slicing the URL string: `url.path` is still
            // percent-encoded, so a checkout under a path containing a space would leave `%20`
            // in the filename and throw.
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
        }.sorted()

        check(simpleNames.isNotEmpty()) { "no classes found for $packageName via $url" }
        return url to simpleNames
    }

    /** The `Name$1` shape `ApiBaselineTest` filters out and this census keeps. Printed, not used. */
    private fun String.isAnonymousShaped(): Boolean =
        substringAfterLast('$').toIntOrNull() != null

    // ── The surface census (arm C) ────────────────────────────────────────

    /** One published member that declares a `java.security` type, and which type it declares. */
    private class SecurityUse(val member: String, val type: String) {
        override fun toString(): String = "$member declares $type"
    }

    /** What one surface census read, and enough about it to say whether it read anything. */
    private class SurfaceCensus(
        /** Classes loaded back through the anchor's classloader. */
        val classesLoaded: Int,
        /** Public and protected constructors, methods and fields examined — arm C's floor. */
        val membersExamined: Int,
        /** Every `java.security` type a published member declares, excused ones included. */
        val uses: List<SecurityUse>,
    )

    /**
     * Every `java.security` type declared by a public or protected member of a class compiled into
     * [anchor]'s package.
     *
     * **Off the compiled classes, not off a list**, for the reason `ApiBaselineTest` and
     * `PublicApiAuditTest` both give for doing the same: a hardcoded list is blind to a new file
     * carrying a new public type, which is exactly the change this arm exists to catch. The
     * enumeration is [classesInPackage] — this class's own copy, already used by the byte census —
     * so the two arms cannot disagree about which classes are the library's.
     *
     * **Public *and* protected**, which is what a consumer outside the package can link against,
     * and **synthetics included**: Kotlin's `$default` bridges are public, static and synthetic,
     * and `generateNonce$default` carries a `SecureRandom` parameter that a filter on
     * `isSynthetic` would drop. Including them is the conservative direction for an absence claim,
     * and the same direction `ApiBaselineTest`'s baseline takes.
     *
     * **Anonymous classes are examined too.** Their members are not reachable API, so this
     * over-reads rather than under-reads — again the safe direction here, and the reason no
     * `Name$1` filter appears.
     *
     * **Arrays are unwrapped to their component type**, so a hypothetical `PrivateKey[]` return is
     * reported as `java.security.PrivateKey` and not as `java.security.PrivateKey[]`, which a
     * prefix match on the rendered name would have caught anyway but a reader should not have to
     * verify. Generics are not unwrapped: erasure means a `List<PrivateKey>` parameter declares
     * `java.util.List` here and this arm cannot see inside it — the byte census is the arm that
     * can, since the type name is still in the constant pool.
     */
    private fun surfaceCensus(anchor: Class<*>): SurfaceCensus {
        val packageName = anchor.name.substringBeforeLast('.')
        val loader = checkNotNull(anchor.classLoader) { "no classloader for ${anchor.name}" }
        val types = classesInPackage(anchor).second
            .map { Class.forName("$packageName.$it", false, loader) }

        var membersExamined = 0
        val uses = mutableListOf<SecurityUse>()

        fun examine(member: String, declared: List<Class<*>>) {
            membersExamined++
            declared
                .map { generateSequence(it) { type -> type.componentType }.last() }
                .filter { it.name.startsWith(SECURITY_PACKAGE) }
                .forEach { uses += SecurityUse(member, it.name) }
        }

        for (type in types) {
            val parameters = { types: Array<Class<*>> -> types.joinToString(", ") { it.typeName } }
            type.declaredConstructors
                .filter { isVisible(it.modifiers) }
                .forEach {
                    examine("${type.name}.<init>(${parameters(it.parameterTypes)})", it.parameterTypes.toList())
                }
            type.declaredMethods
                .filter { isVisible(it.modifiers) }
                .forEach {
                    examine(
                        "${type.name}.${it.name}(${parameters(it.parameterTypes)})",
                        it.parameterTypes.toList() + it.returnType,
                    )
                }
            type.declaredFields
                .filter { isVisible(it.modifiers) }
                .forEach { examine("${type.name}.${it.name}", listOf(it.type)) }
        }
        return SurfaceCensus(types.size, membersExamined, uses.sortedBy { it.toString() })
    }

    /** A consumer outside this package can link against the public and protected members only. */
    private fun isVisible(bits: Int): Boolean =
        Modifier.isPublic(bits) || Modifier.isProtected(bits)

    // ── The manifest reader ───────────────────────────────────────────────

    /**
     * Every permission-declaring element in an Android manifest document, each rendered with its
     * `android:name` where it has one.
     *
     * Parsed rather than searched: see `control - a commented-out declaration is not a
     * declaration, and a substring reader disagrees`.
     * Namespace-unaware on purpose, so `android:name` is read as the literal attribute name the
     * manifest spells rather than requiring a namespace binding the fixtures would have to repeat.
     */
    private fun permissionElementsIn(xml: String): List<String> {
        val factory = DocumentBuilderFactory.newInstance().apply { isNamespaceAware = false }
        val document = factory.newDocumentBuilder().parse(InputSource(StringReader(xml)))
        val elements = document.getElementsByTagName("*")
        return (0 until elements.length)
            .map { elements.item(it) as Element }
            .filter { it.tagName in PERMISSION_ELEMENTS }
            .map { element ->
                val name = element.getAttribute("android:name")
                if (name.isEmpty()) element.tagName else "${element.tagName}[$name]"
            }
    }

    /**
     * The document's root element name, which is the anchor arm B asserts before its absence.
     *
     * Parsed through the same `DocumentBuilderFactory` as [permissionElementsIn], so the two
     * cannot disagree about what document they read.
     */
    private fun rootElementOf(xml: String): String {
        val factory = DocumentBuilderFactory.newInstance().apply { isNamespaceAware = false }
        return factory.newDocumentBuilder()
            .parse(InputSource(StringReader(xml)))
            .documentElement
            .tagName
    }

    /**
     * The strawman arm B is **not**: a plain substring search for an element's opening tag.
     *
     * Called from one control and nowhere else. It exists so the comparison that chose an
     * XML-aware reader is measured in the suite rather than asserted in a comment.
     */
    private fun substringReaderFinds(xml: String): List<String> =
        PERMISSION_ELEMENTS.filter { "<$it" in xml }

    // ── Locating the manifest ─────────────────────────────────────────────

    /**
     * [relative], located by walking up from the working directory, or a failure naming every path
     * it tried.
     *
     * **A copy of `BuildInputsTest`'s `locate`**, which is the convention `ApiBaselineTest` states
     * for exactly this situation — all eight of the walk-up resolvers this suite already held
     * (across six files, measured) are `private`, so calling one would mean widening it and
     * editing a file this change requires to pass unmodified. This copy is the ninth, and the same
     * reason applies to it. Its reason carries over unchanged: the working directory of a Gradle unit
     * test is the module directory, but that is a default rather than a promise, so every ancestor
     * is tried both as the module root and as the repository root. A resolver that silently found
     * nothing would make an absence assertion pass for ever.
     */
    private fun locate(relative: String): File {
        val workingDirectory = File(".").absoluteFile.normalize()
        val tried = mutableListOf<File>()
        var directory: File? = workingDirectory
        while (directory != null) {
            for (candidate in listOf(File(directory, relative), File(directory, "LIM/$relative"))) {
                tried += candidate
                if (candidate.isFile) return candidate
            }
            directory = directory.parentFile
        }
        throw AssertionError(
            "cannot find `$relative`, so nothing here can say whether this library asks for a " +
                "permission — and a gate that cannot find the file it guards passes for ever. " +
                "Working directory: $workingDirectory. Tried:\n" +
                tried.map { it.absolutePath }.distinct().joinToString("\n"),
        )
    }

    private companion object {

        /**
         * The module manifest, module-relative.
         *
         * Spelled under `src/` and with an `.xml` extension, both of which put it outside
         * `BuildInputsTest`'s rule 3 by design: that rule's path literal matches only
         * `.md|.api|.toml|.kts|.pro`, and it then drops any literal beginning `src/`. Nothing is
         * owed to `VERIFIED_DOCUMENTS`, which stays at eight, and `LIM/build.gradle.kts` is not
         * touched by this test — both that file and `BuildInputsTest` say in so many words that
         * the list is about documents and that nothing under `src/` belongs in it.
         */
        private const val MANIFEST_RELATIVE = "src/main/AndroidManifest.xml"

        /**
         * The names of every networking type a class file would have to mention to reach the
         * network, as they appear in a constant pool: internal form, slashes not dots.
         *
         * Package prefixes where a whole package is out of bounds, bare class names where the
         * package is not (`URLConnection` is `java.net`'s, but `ServerSocket` and
         * `DatagramSocket` are worth naming on their own so a hit reads as what it is).
         * `okhttp3` and `retrofit2` are here despite not being dependencies precisely because
         * they are not: the vocabulary is what a future edit would have to smuggle past.
         *
         * **Necessarily incomplete, and the other half of the guard is elsewhere.** A network leg
         * reached through some *other* client — `io/ktor/`, `com/android/volley/` — would leave no
         * listed token in LIM's own class files, because the `java/net/` references would live in
         * that library's classes rather than in these. Every such route needs a new runtime
         * dependency, which is the layer `GuideSnippetTest` pins at exactly one and stop rule 5
         * reserves for a human; this vocabulary and that assertion are one guard in two halves,
         * not two guards.
         *
         * `URLConnection` rather than a bare `URL`, deliberately: `FieldType.URL` is a published
         * enum constant, so the shorter token would be a permanent false red on `FieldType.class`.
         */
        private val FORBIDDEN = listOf(
            "java/net/",
            "javax/net/",
            "java/nio/channels/",
            "android/net/",
            "android/webkit/",
            "okhttp3/",
            "retrofit2/",
            "java/rmi/",
            "URLConnection",
            "ServerSocket",
            "DatagramSocket",
        )

        /**
         * The names a class file would have to mention to hold or use a **private key**, in the
         * same internal form [FORBIDDEN] uses: slashes, not dots.
         *
         * Package prefixes where a whole package is out of bounds (`javax/crypto/`,
         * `android/security/keystore/`), fully-qualified names where the package is not —
         * `java/security/` itself cannot be forbidden wholesale, since `SecureRandom`,
         * `KeyFactory`, `X509EncodedKeySpec` and `Signature` all live there and all are
         * legitimate here.
         *
         * **Two member names rather than one, and the one that is missing is deliberate.**
         * `initSign` and `getPrivateKey` are the exact member names. The bare token `sign` is
         * **not** in this list: measured at this commit, `grep -la 'sign'` over the library's own
         * class files reports six of twenty-five — [SignedStatement] and its three subclasses,
         * [SignChallengeResult], and [Utils], which carries `signChallengeAction`, `signature`
         * and `signatureBytes` — so forbidding it would redden on the first run and say nothing
         * about signing. The exact-set assertion in arm B is what covers that ground instead.
         *
         * **Necessarily incomplete, the same way [FORBIDDEN] is.** A key held through some type
         * nothing here names would leave no listed token behind. Arm C is the other half of this
         * guard: a key cannot reach a consumer without appearing on the published surface, and
         * arm C reads that surface off the classes rather than off a vocabulary.
         */
        private val KEY_FORBIDDEN = listOf(
            "java/security/PrivateKey",
            "java/security/KeyStore",
            "java/security/KeyPairGenerator",
            "javax/crypto/",
            "android/security/keystore/",
            "initSign",
            "getPrivateKey",
        )

        /** [KEY_FORBIDDEN]'s size at this commit: deleting a token is the edit this catches. */
        private const val KEY_VOCABULARY_FLOOR = 7

        /**
         * The [java.security.Signature] member names arm B takes an exact census of.
         *
         * `sign` is absent for the reason [KEY_FORBIDDEN] gives. What remains is the four members
         * a verifier calls plus the one a signer would.
         */
        private val SIGNATURE_MEMBERS = listOf(
            "getInstance",
            "initVerify",
            "update",
            "verify",
            "initSign",
        )

        /**
         * The four of [SIGNATURE_MEMBERS] present in the library's classes, sorted.
         *
         * `initSign` is the one absent. Measured rather than assumed: at this commit `Utils` holds
         * the only `java.security.Signature` import in `LIM/src/main`, used in exactly one place —
         * `Signature.getInstance(SIGN_ALGORITHM)` — whose `run` block then calls `initVerify`,
         * `update` and `verify`. One use of the class, three members called on it.
         */
        private val EXPECTED_SIGNATURE_MEMBERS = listOf(
            "getInstance",
            "initVerify",
            "update",
            "verify",
        )

        /** Separator in a `"<class> references <token>"` hit line, so parsing it is not a guess. */
        private const val REFERENCES = " references "

        /** This class's own simple name, excluded from its control. See the control's comment. */
        private const val SELF = "NoNetworkLegTest"

        /**
         * Tokens the control must report over the test classes, with [SELF]'s own removed.
         *
         * Three rather than all seven of [KEY_FORBIDDEN]: the test sources generate keypairs and
         * sign with them, so these three are reported by many classes each, while
         * `java/security/KeyStore`, `android/security/keystore/` and `getPrivateKey` are used by
         * no test at all and demanding them would make the control a fiction. `javax/crypto/`
         * **is** reported — by exactly one class, `ThreadSafetyTest` — and is left out anyway: a
         * control that rests on a single unrelated file is one that goes red for a reason which
         * is not the property it guards.
         */
        private val CONTROL_EXPECTED_TOKENS = listOf(
            "java/security/PrivateKey",
            "java/security/KeyPairGenerator",
            "initSign",
        )

        /**
         * The control's named hits, for the reason `control - the same scanner over the test
         * classes reports the networking they use` names `ApiBaselineTest`: a count, or even a
         * token set, could in principle be satisfied by the wrong file. `SignatureVerificationTest`
         * loads a `PrivateKey` and calls `initSign`, measured at this commit.
         *
         * **This is the one line here that a pure test refactor can redden**, and the failure
         * message it prints blames the library. If `SignatureVerificationTest` legitimately stops
         * signing inline — a shared `TestKeys` helper would do it — the repair is to name whichever
         * class now carries the call, not to drop the assertion: [CONTROL_EXPECTED_TOKENS] alone
         * would then be satisfiable by this file's own vocabulary were the [SELF] filter ever to
         * slip, which is exactly what naming a class is for.
         */
        private val CONTROL_EXPECTED_HITS = listOf(
            "SignatureVerificationTest${REFERENCES}java/security/PrivateKey",
            "SignatureVerificationTest${REFERENCES}initSign",
        )

        /** The package arm C census, dotted, as `Class.getName` renders it. */
        private const val SECURITY_PACKAGE = "java.security."

        /**
         * The one `java.security` type the published surface may declare, and why.
         *
         * [java.security.SecureRandom] is injected randomness — `Utils.generateNonce` takes one so
         * a test can pin it, which this repository's Definition of done requires of every module.
         * It carries no key material. Adding a second entry here is a security-surface decision
         * (stop rule 5), not a test edit, which is why the list is a named constant with a reason
         * rather than an inline `filter`.
         */
        private val EXCUSED_SECURITY_TYPES = listOf("java.security.SecureRandom")

        /**
         * The member that earns [EXCUSED_SECURITY_TYPES] its excuse, matched as a prefix so the
         * overload and its `$default` bridge all count.
         *
         * Arm C asserts this is found, which is what keeps the excuse honest in both directions:
         * a detector that stopped detecting reddens here, and so does an excuse left behind after
         * the member that justified it was removed.
         */
        private const val EXCUSED_MEMBER = "dev.eryalabs.lim.Utils.generateNonce"

        /**
         * Below the member count arm C measured, so adding or removing a member is not a test
         * edit — a tripwire against a census that stopped reading, exactly like [CLASS_FLOOR].
         */
        private const val SURFACE_MEMBER_FLOOR = 300

        /** Every element an Android manifest can declare a permission with. */
        private val PERMISSION_ELEMENTS = listOf(
            "uses-permission",
            "uses-permission-sdk-23",
            "permission",
            "permission-group",
            "permission-tree",
        )

        /** Class files in `dev.eryalabs.lim` when this test was written, anonymous included. */
        private const val MEASURED_CLASSES = 25

        /** Below [MEASURED_CLASSES], so adding or removing a class is not a test edit. */
        private const val CLASS_FLOOR = 20

        /** Well below the ~150 KB the package measured, for the same reason. */
        private const val BYTE_FLOOR = 80_000L

        /** [FORBIDDEN]'s size at this commit: deleting a token is the edit this catches. */
        private const val VOCABULARY_FLOOR = 11

        /**
         * The canonical one-line declaration. **A fixture, not a declaration** — see
         * `control - a permission declaration is reported in both of its spellings`.
         */
        private val CANONICAL_PERMISSION_FIXTURE = """
            <?xml version="1.0" encoding="utf-8"?>
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                <uses-permission android:name="android.permission.INTERNET" />
            </manifest>
        """.trimIndent()

        /** The same declaration with `android:name` on its own line. Also a fixture. */
        private val WRAPPED_PERMISSION_FIXTURE = """
            <?xml version="1.0" encoding="utf-8"?>
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                <uses-permission
                    android:name="android.permission.INTERNET" />
            </manifest>
        """.trimIndent()

        /** The same declaration commented out, which is not a declaration. Also a fixture. */
        private val COMMENTED_PERMISSION_FIXTURE = """
            <?xml version="1.0" encoding="utf-8"?>
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                <!-- <uses-permission android:name="android.permission.INTERNET" /> -->
            </manifest>
        """.trimIndent()
    }
}
