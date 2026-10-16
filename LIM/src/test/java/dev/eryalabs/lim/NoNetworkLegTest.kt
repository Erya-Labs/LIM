package dev.eryalabs.lim

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element
import org.xml.sax.InputSource
import java.io.File
import java.io.StringReader
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
 * **No Robolectric, and no runner annotation.** Neither arm touches an Android type: arm A reads
 * class bytes through the classloader and arm B parses a file with the JDK's own XML parser. A
 * sandbox would cost seconds and buy nothing.
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
     * scanned for [FORBIDDEN].
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
    private fun census(anchor: Class<*>): Census {
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
            FORBIDDEN.filter { it in text }.forEach { hits += "$simpleName references $it" }
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
