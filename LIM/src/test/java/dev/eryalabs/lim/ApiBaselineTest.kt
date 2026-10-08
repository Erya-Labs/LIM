package dev.eryalabs.lim

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.lang.reflect.Constructor
import java.lang.reflect.Field
import java.lang.reflect.Method
import java.lang.reflect.Modifier
import java.net.JarURLConnection

/**
 * **The binary surface a consumer links against, checked into git where a diff is reviewable.**
 *
 * `PublicApiAuditTest`'s `SIGNATURES` is the *Kotlin-visible* shape: 277 lines rendered
 * `Name.member(params): return` with package qualifiers stripped and the compiler's own methods
 * filtered out. That is the right snapshot for "did an integrator's source stop compiling", and it
 * is blind to two things that cost an already-compiled consumer a `NoSuchMethodError`:
 *
 *  - **Modifiers.** That file says so itself: it "renders `name(params): return` and never the
 *    modifiers", so an instance method becoming static moves no line in it. Its
 *    `every published method on Utils is an instance method` covers that — for `Utils`'s
 *    *methods* only, not its fields and not one member of any other published class.
 *  - **The `$default` bridges.** `isPublishedApi()` is `isPublic && !isSynthetic && !isBridge`,
 *    and Kotlin's `$default` statics are public, static *and* synthetic — which is why that file
 *    can assert `Utils` publishes zero static methods while a dozen `$default` statics sit on it.
 *    Turn `fun f(a: String, b: String = "x")` into `fun f(a: String, b: String)` and the main
 *    descriptor is byte-identical, no line of `SIGNATURES` moves, and `f$default` — the method
 *    every already-compiled Kotlin caller of the shorter form actually invokes — is gone with
 *    nothing anywhere to notice.
 *
 * So this file pins every JVM-visible **member** instead: every public and protected constructor,
 * method and field of every class compiled into `dev.eryalabs.lim`, synthetics and bridges
 * included, with its modifiers and its erased descriptor, one sorted line each in
 * [BASELINE_PATH].
 *
 * **Members, and nothing above them** — stated here rather than left for whoever trusts this file
 * next. Nothing class-level is rendered, so a published class going `internal`, becoming `final`,
 * or dropping an interface from its supertype list moves no line here (its members keep their own
 * access bits), and every one of those is an `IllegalAccessError` or an `AbstractMethodError` for
 * an already-compiled consumer. `SIGNATURES` cannot see them either. The same goes for a future
 * *subpackage*: [classesInPackage] reads one package directory, exactly as the audit does.
 *
 * **What it is evidence for, and what it does not settle.** Three items under "Blocked on human"
 * turn on a binary-compatibility comparison against the *published* `1.0.0`. That artifact is out
 * of reach here — `~/.m2` is outside this session's allowed directories and the publish is blocked
 * twice over — so this baseline is the surface **as it stands at this commit**, not a diff against
 * what any consumer holds. It makes the next change visible; it resolves none of those decisions.
 *
 * **The two snapshots are deliberately independent**, down to this file keeping its own copy of
 * the class enumeration. A change that moves both is a real API change; a change that moves only
 * this one is exactly what `SIGNATURES` cannot see, which is the whole point of having two.
 *
 * Plain reflection over the compiled output — no Robolectric, no `kotlin-reflect`, no
 * `binary-compatibility-validator` plugin. Adding one would do this for us and is a dependency
 * decision a human makes (stop rule 5).
 */
class ApiBaselineTest {

    // ── One line of the baseline ──────────────────────────────────────────

    /**
     * A rendered member and the key it is classified under.
     *
     * [key] is `<owner>.<name>(<params>)` for a method or constructor and `<owner>.<name>` for a
     * field — deliberately *without* modifiers or return type, so that a member present on both
     * sides with a different modifier set or a different return type is reported **changed**
     * rather than as one addition plus one removal. The distinction is the whole value of the
     * failure message: an addition is fine and a change is stop rule 10.
     *
     * A key is **not unique**. A covariant bridge has the same name and the same erased
     * parameters as the method it forwards to and differs only in return type —
     * `Entry$Creator.createFromParcel(android.os.Parcel)` is two lines — so both sides are
     * compared as multisets of lines per key.
     */
    private class Member(val key: String, val line: String)

    // ── The compiled surface ──────────────────────────────────────────────

    /**
     * Every class compiled into `dev.eryalabs.lim` from the same output tree as [anchor].
     *
     * Read off the compiled output rather than from a list, for the reason `PublicApiAuditTest`
     * gives for doing the same: a hardcoded list makes the baseline blind to a *new file* carrying
     * a new public type, which is one of the two changes it exists to catch.
     *
     * Kept as a second copy rather than extracted into a shared helper on purpose — see this
     * class's own note on independence, and the audit's tests must keep passing unmodified.
     */
    private fun classesInPackage(anchor: Class<*>): List<Class<*>> {
        // Located through the class file rather than the CodeSource: under a Robolectric sandbox
        // the protection domain reports no location at all, and this test may share a JVM with
        // tests that install one.
        val packageName = anchor.name.substringBeforeLast('.')
        val anchorPath = anchor.name.replace('.', '/') + ".class"
        val loader = checkNotNull(anchor.classLoader) { "no classloader for ${anchor.name}" }
        val url = checkNotNull(loader.getResource(anchorPath)) {
            "cannot locate $anchorPath on the classpath"
        }
        val packagePath = packageName.replace('.', '/')

        // Two shapes, because the two source sets are packaged differently by the Android plugin:
        // the library's own classes arrive as `classes.jar`, a test's as a directory of files.
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
        }
            // Anonymous classes carry no API: `Utils$FIELDS_TYPE$1` is Gson's TypeToken.
            .filterNot { it.substringAfterLast('$').toIntOrNull() != null }
            .sorted()

        check(simpleNames.isNotEmpty()) { "no classes found for $packageName via $url" }
        return simpleNames.map { Class.forName("$packageName.$it", false, loader) }
    }

    /**
     * A type as the descriptor denotes it, spelled with dots: `java.lang.String`, `byte[]`,
     * `java.util.Map`.
     *
     * **Erased on purpose.** `Map<String, TypedField>` narrowing to `Map<String, String>` is a
     * source break that changes no descriptor, and `SIGNATURES` already renders type arguments to
     * catch exactly that. This file answers the other question — what a linker resolves — so it
     * renders what the linker sees. Dotted rather than `Ljava/lang/String;` because the line has
     * to be readable in a diff; it *denotes* the descriptor without being spelled like one.
     */
    private fun render(type: Class<*>): String = type.typeName

    /**
     * Modifiers as the JVM records them, plus the flags `Modifier.toString` cannot show.
     *
     * Masked to the member kind's own modifier set, because `ACC_BRIDGE` shares a bit with
     * `ACC_VOLATILE` and `ACC_VARARGS` with `ACC_TRANSIENT`: unmasked, every covariant bridge
     * here would render as a `volatile` *method*, which is not a thing. `synthetic` and `bridge`
     * are then appended as words — they are not in `Modifier`'s vocabulary at all, and on a
     * `$default` line they are the only thing distinguishing a compiler artifact from API
     * somebody chose to publish.
     */
    private fun modifiers(bits: Int, mask: Int, synthetic: Boolean, bridge: Boolean): String {
        val written = Modifier.toString(bits and mask)
        val flags = listOfNotNull(
            "synthetic".takeIf { synthetic },
            "bridge".takeIf { bridge },
        )
        return (listOf(written).filter { it.isNotEmpty() } + flags).joinToString(" ")
    }

    /** A consumer outside this package can link against the public and protected members only. */
    private fun isVisible(bits: Int): Boolean =
        Modifier.isPublic(bits) || Modifier.isProtected(bits)

    private fun memberOf(owner: Class<*>, constructor: Constructor<*>): Member {
        val params = constructor.parameterTypes.joinToString(", ", transform = ::render)
        val key = "${owner.name}.<init>($params)"
        val written = modifiers(
            constructor.modifiers,
            Modifier.constructorModifiers(),
            constructor.isSynthetic,
            bridge = false,
        )
        return Member(key, "$written $key: void")
    }

    private fun memberOf(owner: Class<*>, method: Method): Member {
        val params = method.parameterTypes.joinToString(", ", transform = ::render)
        val key = "${owner.name}.${method.name}($params)"
        val written = modifiers(
            method.modifiers,
            Modifier.methodModifiers(),
            method.isSynthetic,
            method.isBridge,
        )
        return Member(key, "$written $key: ${render(method.returnType)}")
    }

    private fun memberOf(owner: Class<*>, field: Field): Member {
        val key = "${owner.name}.${field.name}"
        val written = modifiers(
            field.modifiers,
            Modifier.fieldModifiers(),
            field.isSynthetic,
            bridge = false,
        )
        return Member(key, "$written $key: ${render(field.type)}")
    }

    /**
     * The whole JVM-visible surface, sorted by [Member.key] and then by line.
     *
     * Sorted by key rather than by the rendered line so that the file groups by owner and a
     * *modifier* change moves a line's content without moving its position — the diff then reads
     * as the one-line change it is, which is also how [classify] reports it.
     */
    private fun surface(): List<Member> = classesInPackage(Utils::class.java)
        .flatMap { type ->
            val constructors = type.declaredConstructors
                .filter { isVisible(it.modifiers) }
                .map { memberOf(type, it) }
            val methods = type.declaredMethods
                .filter { isVisible(it.modifiers) }
                .map { memberOf(type, it) }
            val fields = type.declaredFields
                .filter { isVisible(it.modifiers) }
                .map { memberOf(type, it) }
            constructors + methods + fields
        }
        .sortedWith(compareBy({ it.key }, { it.line }))

    // ── The checked-in baseline ───────────────────────────────────────────

    /**
     * `LIM/api/lim.api` itself, located by walking up from the working directory.
     *
     * The working directory of a Gradle unit test is the module directory, but that is a Gradle
     * default rather than a promise, so every ancestor is tried both as the module root and as the
     * repository root. If none of them holds the file the test fails *naming every absolute path
     * it tried*, and names the regenerated copy it has just written: a baseline test that silently
     * found no baseline would pass for ever.
     */
    private fun baselineFile(): File = locate(BASELINE_RELATIVE) {
        "cannot find $BASELINE_PATH, so there is nothing pinning the binary surface. A " +
            "regenerated copy of what reflection currently finds is at ${regenerated().path} — " +
            "review it and check it in, header included."
    }

    /** `gradle/libs.versions.toml`, for the toolchain versions the baseline's header records. */
    private fun versionsFile(): File = locate("gradle/libs.versions.toml") {
        "cannot find gradle/libs.versions.toml, so the toolchain versions this baseline is " +
            "pinned to cannot be checked against the ones the build actually uses"
    }

    /** `LIM/build.gradle.kts`, for the `jvmTarget` the header records beside those versions. */
    private fun moduleBuildFile(): File = locate("build.gradle.kts") {
        "cannot find the module's build.gradle.kts, so the jvmTarget this baseline is pinned to " +
            "cannot be checked against the one the build actually uses"
    }

    private fun locate(relative: String, complaint: () -> String): File {
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
            complaint() + " Working directory: $workingDirectory. Tried:\n" +
                tried.map { it.absolutePath }.distinct().joinToString("\n"),
        )
    }

    /**
     * The baseline's body: every line that is not a `#` header line and not blank.
     *
     * The header is prose for whoever reads a surprising diff — what the file is, what it is
     * pinned to besides the API, and how to update it — so it cannot be part of the comparison.
     */
    private fun baseline(): List<Member> = baselineFile()
        .readLines()
        .map { it.trim() }
        .filter { it.isNotEmpty() && !it.startsWith("#") }
        .map { parse(it) }

    /**
     * Recovers a line's [Member.key] from its text, which is how the file on disk and the
     * compiled surface are compared under the same key.
     *
     * Modifier words are dropped from the front; the declaration starts at the first token that
     * is not one. A method's key then ends at `)` — the rendering is erased, so no parameter type
     * can contain a parenthesis and the first `)` is the last — and a field's at the `: ` before
     * its type. A line that fits neither shape is a corrupted or hand-edited baseline and must
     * fail loudly rather than be classified as something.
     */
    private fun parse(line: String): Member {
        val declaration = line
            .split(' ')
            .dropWhile { it in MODIFIER_WORDS }
            .joinToString(" ")
        val key = when {
            '(' in declaration -> declaration.substringBefore(')', "") + ")"
            else -> declaration.substringBefore(": ", "")
        }
        if (key.isBlank() || key == ")" || '.' !in key) {
            throw AssertionError(
                "cannot read a member key out of this $BASELINE_PATH line, so it cannot be " +
                    "compared with anything: \"$line\". Every line must read " +
                    "`<modifiers> <owner>.<name>(<types>): <return>` or " +
                    "`<modifiers> <owner>.<name>: <type>`.",
            )
        }
        return Member(key, line)
    }

    /** Where a regenerated surface is written on failure, so updating the file is a copy. */
    private fun regenerated(): File {
        val out = File("build/api/lim.api.actual")
        out.parentFile?.mkdirs()
        out.writeText(surface().joinToString("\n", postfix = "\n") { it.line })
        return out
    }

    // ── Classification ────────────────────────────────────────────────────

    /** What changed, in the three buckets stop rule 10 treats differently. */
    private class Diff(
        val added: List<String>,
        val removed: List<String>,
        val changed: List<String>,
    ) {
        /** One flat list, prefixed, so a failure shows all three at once. */
        val complaints: List<String> =
            removed.map { "removed: $it" } + changed.map { "changed: $it" } +
                added.map { "added: $it" }
    }

    /**
     * Compares the two surfaces **by key**, which is what makes "changed" a bucket of its own.
     *
     * Per key, both sides are multisets of rendered lines: a key on one side only is an addition
     * or a removal, and a key on both sides whose lines differ is a change, reported with both
     * spellings on one entry. Without that, `@JvmStatic` on one function would read as "one
     * member removed, one member added" — two scary lines describing one edit, and
     * indistinguishable from a genuinely removed member next to an unrelated new one.
     */
    private fun classify(baseline: List<Member>, actual: List<Member>): Diff {
        val before = baseline.groupBy { it.key }
        val after = actual.groupBy { it.key }
        val changed = mutableListOf<String>()
        for ((key, mine) in before) {
            val theirs = after[key] ?: continue
            val was = mine.map { it.line }.sorted()
            val now = theirs.map { it.line }.sorted()
            if (was != now) {
                changed += "$key\n    was: ${was.joinToString("\n         ")}" +
                    "\n    now: ${now.joinToString("\n         ")}"
            }
        }
        return Diff(
            added = after.filterKeys { it !in before }.values.flatten().map { it.line }.sorted(),
            removed = before.filterKeys { it !in after }.values.flatten().map { it.line }.sorted(),
            changed = changed.sorted(),
        )
    }

    // ── The baseline itself ───────────────────────────────────────────────

    @Test
    fun `the compiled surface matches the checked-in baseline`() {
        val complaints = classify(baseline(), surface()).complaints

        // Built only when it is about to be shown, because composing it writes the regenerated
        // body to `build/` — a convenience for whoever has to update the file, not something a
        // green run should be doing.
        val message = if (complaints.isEmpty()) "" else {
            "the JVM-visible surface no longer matches $BASELINE_PATH.\n" +
                "  **added** — in the compiled surface, absent from the baseline. Fine under " +
                "stop rule 10, which permits additions: update $BASELINE_PATH in the same " +
                "commit. A line deleted from the baseline by hand lands here too, and that is " +
                "the same fix.\n" +
                "  **removed** — in the baseline, absent from the compiled surface. " +
                "**changed** — in both, rendered differently; a key carrying a covariant bridge " +
                "holds two lines, so losing one of them reads as a change on that key rather " +
                "than as a removal.\n" +
                "  Either way, stop and think. Every already-compiled consumer " +
                "resolves these by name, descriptor *and* modifiers, so a removal or a modifier " +
                "change is a `NoSuchMethodError` at their next run rather than a compile error " +
                "they can see. That is stop rule 10.\n" +
                "  A `$DEFAULT_MARKER` or `synthetic` line moving with no source change usually " +
                "means the Kotlin toolchain moved; the header of $BASELINE_PATH records the " +
                "version it was generated with, and that is the first thing to check.\n" +
                "  The file to edit is ${baselineFile().absolutePath}; a regenerated body is at " +
                "${regenerated().absolutePath} (body only — keep the header)."
        }

        assertEquals(message, emptyList<String>(), complaints)
    }

    @Test
    fun `the baseline covers a whole surface rather than a corner of one`() {
        val actual = surface()
        // `dev.eryalabs.lim.Utils.shareEntry(…)` → `dev.eryalabs.lim.Utils`: drop the parameter
        // list first, or a field's key and a method's key would be cut in different places.
        val owners = actual
            .map { it.key.substringBefore('(').substringBeforeLast('.') }
            .distinct()
        val defaults = actual.filter { DEFAULT_MARKER in it.line }

        println(
            "lim.api: ${actual.size} members over ${owners.size} classes, " +
                "${defaults.size} of them $DEFAULT_MARKER bridges",
        )

        assertTrue(
            "expected at least $MINIMUM_MEMBERS JVM-visible members; found ${actual.size}",
            actual.size >= MINIMUM_MEMBERS,
        )
        assertTrue(
            "expected at least $MINIMUM_CLASSES classes to contribute a member; found " +
                "${owners.size}: ${owners.sorted()}",
            owners.size >= MINIMUM_CLASSES,
        )
        // The number that proves this baseline covers what `SIGNATURES` excludes by
        // construction: every one of these is public, static and synthetic, so the audit's
        // `isPublishedApi` filter drops all of them and this file is the only thing holding them.
        assertTrue(
            "expected at least $MINIMUM_DEFAULTS $DEFAULT_MARKER bridges — they are the half of " +
                "the surface the audit's snapshot cannot see, and a baseline without them is " +
                "just a second copy of SIGNATURES; found ${defaults.size}",
            defaults.size >= MINIMUM_DEFAULTS,
        )
        assertEquals(
            "the baseline on disk must hold one line per member of the compiled surface; a " +
                "different count means it was truncated or a line was dropped by hand",
            actual.size,
            baseline().size,
        )
    }

    @Test
    fun `the rendering is fully qualified, which is the difference from SIGNATURES`() {
        val lines = surface().map { it.line }
        // Neither assertion can be satisfied by the audit's rendering, which strips exactly these
        // qualifiers — so this is the mechanical statement of "these two files are not the same
        // snapshot written twice".
        assertTrue(
            "no line names dev.eryalabs.lim.Entry, so parameter types are not qualified and the " +
                "package identity this file exists to record is being stripped",
            lines.any { "dev.eryalabs.lim.Entry" in it },
        )
        assertTrue(
            "no line names java.lang.String, so JDK types are not qualified either",
            lines.any { "java.lang.String" in it },
        )
        assertTrue(
            "the JVM's slashed spelling must not appear: the line denotes the descriptor, it is " +
                "not written as one",
            lines.none { "Ljava/lang/String;" in it },
        )
    }

    /**
     * The header is prose, and prose rots. Three of its claims are machine-checkable and they are
     * the ones that matter: `$default`, `access$` and bridge members are emitted by the
     * *compiler*, so a routine toolchain bump can move lines in this file with no API change at
     * all, and the header is what tells the next reader of a surprising diff to check that first.
     * A pointer to the wrong toolchain is worse than no pointer.
     *
     * Each is matched **with a boundary after the version**, not as a bare substring: `2.0.2` is a
     * substring of `2.0.21`, so a downgrade to the shorter version would otherwise leave this
     * green while the header named a toolchain nobody was using.
     */
    @Test
    fun `the baseline header records the toolchain the build actually uses`() {
        val versions = versionsFile().readText()
        val recorded = mapOf(
            "Kotlin" to declaration(versions, "kotlin", versionsFile()),
            "AGP" to declaration(versions, "agp", versionsFile()),
            "jvmTarget" to declaration(
                moduleBuildFile().readText(),
                "jvmTarget",
                moduleBuildFile(),
            ),
        )
        val header = baselineFile().readLines().filter { it.startsWith("#") }

        val missing = recorded.filterNot { (label, version) ->
            // The lookahead is the whole point: `Kotlin 2.0.2` must not be satisfied by
            // `Kotlin 2.0.21`, and `jvmTarget 1` must not be satisfied by `jvmTarget 11`.
            val boundaried = Regex(Regex.escape("$label $version") + """(?![\w.\-])""")
            header.any { boundaried.containsMatchIn(it) }
        }

        assertEquals(
            "the header of $BASELINE_PATH must record the toolchain that generated it, exactly " +
                "as the build declares it — $recorded — because a bump to any of the three can " +
                "move $DEFAULT_MARKER, access\$ and bridge lines here with no API change at all",
            emptyMap<String, String>(),
            missing,
        )
    }

    /** `name = "value"` out of a Gradle or TOML declaration; fails loudly if it is not there. */
    private fun declaration(text: String, name: String, source: File): String {
        val found = Regex("""\b${Regex.escape(name)}\s*=\s*"([^"]+)"""").find(text)
        return checkNotNull(found) {
            "no `$name = \"…\"` declaration in ${source.absolutePath}, so the header claim about " +
                "$name cannot be checked against anything"
        }.groupValues[1]
    }

    // ── Controls on the classifier ────────────────────────────────────────

    /**
     * The three buckets, from one fixture, so neither a classifier that reports everything nor one
     * that reports nothing can pass.
     */
    @Test
    fun `addition, removal and change are three different verdicts`() {
        val kept = "public final dev.eryalabs.lim.Utils.kept(java.lang.String): boolean"
        val diff = classify(
            baseline = listOf(
                kept,
                "public final dev.eryalabs.lim.Utils.gone(byte[]): void",
                "public final dev.eryalabs.lim.Utils.moved(byte[]): boolean",
            ).map(::parse),
            actual = listOf(
                kept,
                "public final dev.eryalabs.lim.Utils.fresh(int): int",
                "public static dev.eryalabs.lim.Utils.moved(byte[]): boolean",
            ).map(::parse),
        )

        assertEquals(
            listOf("public final dev.eryalabs.lim.Utils.fresh(int): int"),
            diff.added,
        )
        assertEquals(
            listOf("public final dev.eryalabs.lim.Utils.gone(byte[]): void"),
            diff.removed,
        )
        assertEquals(1, diff.changed.size)
        assertTrue(
            "a changed line must carry both spellings, or the reader cannot tell what moved: " +
                diff.changed.single(),
            diff.changed.single().let { "was: public final" in it && "now: public static" in it },
        )
        // And the change is not double-counted as the add-plus-remove it resembles.
        assertTrue(
            "`moved` must appear in exactly one bucket; it is one edit, not two",
            diff.added.none { "moved" in it } && diff.removed.none { "moved" in it },
        )
    }

    /**
     * The instance-to-static conversion, which is the break `SIGNATURES` cannot see at all: one
     * line, reported **changed**, with no addition and no removal beside it. This is the shape of
     * the `@JvmStatic` decision sitting under "Blocked on human".
     */
    @Test
    fun `an instance method becoming static is one changed line`() {
        val diff = classify(
            baseline = listOf(
                "public final dev.eryalabs.lim.Utils.nonceTimestamp(byte[]): java.lang.Long",
            ).map(::parse),
            actual = listOf(
                "public static final dev.eryalabs.lim.Utils.nonceTimestamp(byte[]): java.lang.Long",
            ).map(::parse),
        )

        assertEquals(emptyList<String>(), diff.added)
        assertEquals(emptyList<String>(), diff.removed)
        assertEquals(1, diff.changed.size)
    }

    /** A return type narrowing on a single-form method: also one line, also **changed**. */
    @Test
    fun `a return type change on a single-form method is one changed line`() {
        val diff = classify(
            baseline = listOf(
                "public final dev.eryalabs.lim.Utils.parseQueryResult(android.content.Intent): " +
                    "dev.eryalabs.lim.QueryResult",
            ).map(::parse),
            actual = listOf(
                "public final dev.eryalabs.lim.Utils.parseQueryResult(android.content.Intent): " +
                    "java.lang.Object",
            ).map(::parse),
        )

        assertEquals(emptyList<String>(), diff.added)
        assertEquals(emptyList<String>(), diff.removed)
        assertEquals(1, diff.changed.size)
    }

    /**
     * A `$default` bridge disappearing is a **removal**, not a change — and it is the removal that
     * matters most here, because losing a default argument leaves the main descriptor untouched
     * and takes away the only method an already-compiled Kotlin caller of the shorter form knows
     * how to call.
     */
    @Test
    fun `a vanished default bridge is reported removed`() {
        val main = "public final dev.eryalabs.lim.Utils.shareEntry(android.content.Context, " +
            "dev.eryalabs.lim.Entry, java.lang.String): boolean"
        val bridge = "public static synthetic dev.eryalabs.lim.Utils.shareEntry\$default(" +
            "dev.eryalabs.lim.Utils, android.content.Context, dev.eryalabs.lim.Entry, " +
            "java.lang.String, int, java.lang.Object): boolean"

        val diff = classify(listOf(main, bridge).map(::parse), listOf(main).map(::parse))

        assertEquals(listOf(bridge), diff.removed)
        assertEquals(emptyList<String>(), diff.added)
        assertEquals(emptyList<String>(), diff.changed)
    }

    /**
     * Two members under one key, which is the case a `Map<String, String>` baseline would have
     * silently dropped half of: a covariant bridge has the same erased parameters as the method
     * it forwards to, so `Entry$Creator.createFromParcel(android.os.Parcel)` is two lines and
     * both have to survive the comparison.
     *
     * **The verdict word for losing one of a pair is "changed", not "removed"**, and that is the
     * one place the three buckets read less literally than their names: the *key* is still on both
     * sides, so what the message reports is one key whose `was` holds two lines and whose `now`
     * holds one. Both words live in the same stop-and-think bucket and the lost line is printed
     * either way; what must not happen is the pair collapsing to one entry and the loss going
     * unnoticed, which is what the second half of this test pins. Ordering must not matter either
     * — both sides are sorted before comparison.
     */
    @Test
    fun `two lines under one key are compared as a pair`() {
        val real = "public final dev.eryalabs.lim.Entry\$Creator.createFromParcel(" +
            "android.os.Parcel): dev.eryalabs.lim.Entry"
        // Verbatim `lim.api`, modifier order included: `modifiers` appends `synthetic` before
        // `bridge`, and a fixture that is not the real rendering is a fixture nobody can check.
        val bridge = "public synthetic bridge dev.eryalabs.lim.Entry\$Creator.createFromParcel(" +
            "android.os.Parcel): java.lang.Object"
        assertEquals(parse(real).key, parse(bridge).key)

        assertEquals(
            "the same pair in either order is the same surface",
            emptyList<String>(),
            classify(listOf(real, bridge).map(::parse), listOf(bridge, real).map(::parse))
                .complaints,
        )

        val lost = classify(listOf(real, bridge).map(::parse), listOf(real).map(::parse))
        assertEquals(emptyList<String>(), lost.added)
        assertEquals(emptyList<String>(), lost.removed)
        assertEquals(1, lost.changed.size)
        assertTrue(
            "the line that disappeared must be printed, or a lost bridge is invisible: " +
                lost.changed.single(),
            bridge in lost.changed.single(),
        )
        assertTrue(
            "and it must be shown on the `was` side only",
            lost.changed.single().substringAfter("now:").let { bridge !in it },
        )
    }

    /**
     * [parse] is the one place the file on disk and the compiled surface could disagree about what
     * a line *means*: the generator builds a key structurally, the reader recovers it from text.
     * Re-reading every generated line and comparing keys is what keeps those two in step —
     * including for the `$default`, `<init>`, array-typed and nested-class spellings, which is why
     * this runs over the real surface rather than a fixture.
     */
    @Test
    fun `every generated line parses back to the key it was generated under`() {
        val mismatched = surface()
            .filterNot { parse(it.line).key == it.key }
            .map { "${it.key} parsed back as ${parse(it.line).key}" }

        assertEquals(
            "the baseline reader and the baseline generator disagree about these lines' keys, so " +
                "the comparison is between two different things",
            emptyList<String>(),
            mismatched,
        )
    }

    /** A line that fits neither shape must fail loudly rather than classify as anything. */
    @Test
    fun `an unreadable line is not silently classified`() {
        for (corrupt in listOf("public final", "nonsense", "", "public static (): void")) {
            val failure = runCatching { parse(corrupt) }.exceptionOrNull()
            assertTrue(
                "\"$corrupt\" must be rejected, not turned into a member key",
                failure is AssertionError,
            )
        }
    }

    private companion object {
        /** Where the baseline lives, as a reader of a failure message should see it spelled. */
        private const val BASELINE_PATH = "LIM/api/lim.api"

        /** The same path relative to the module directory, for the walk-up locator. */
        private const val BASELINE_RELATIVE = "api/lim.api"

        /** Kotlin's default-argument bridge suffix, named once since three tests cite it. */
        private const val DEFAULT_MARKER = "\$default"

        /**
         * Floors, each set below the value measured when this file was written (339 members, 22
         * classes, 30 `$default` bridges) so that ordinary additions do not have to move them.
         * They exist against a different failure: a locator or filter that finds nothing would
         * make every assertion above pass over an empty list.
         */
        private const val MINIMUM_MEMBERS = 300
        private const val MINIMUM_CLASSES = 15
        private const val MINIMUM_DEFAULTS = 25

        /**
         * Every word that can appear before the owner in a rendered line: `Modifier`'s own
         * vocabulary for all three member kinds, plus the two flags [modifiers] appends. Dropping
         * them from the front is how [parse] finds where the declaration starts.
         *
         * **`transient` and `volatile` are in here although nothing in this library publishes a
         * field that can carry either**, and that is the point: `Modifier.fieldModifiers()` can
         * emit both, so the day a published type grows a `@JvmField @Volatile var`, [parse] would
         * otherwise stop at the modifier, key the member as `volatile dev.eryalabs.lim.X.x`, and
         * report a later change to it as one addition plus one removal — the exact outcome keying
         * by member exists to prevent. `every generated line parses back to the key it was
         * generated under` would catch it loudly rather than silently, but two words is cheaper
         * than a red run somebody has to diagnose.
         */
        private val MODIFIER_WORDS = setOf(
            "public", "protected", "private",
            "abstract", "static", "final",
            "synchronized", "native", "strictfp",
            "transient", "volatile",
            "synthetic", "bridge",
        )
    }
}
