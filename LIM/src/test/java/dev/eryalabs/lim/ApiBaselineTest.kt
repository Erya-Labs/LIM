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
 * **And one line per class above them**, keyed `class <fqn>` — the JVM modifiers, the
 * `interface`/`enum`/`annotation` flags that [modifiers]'s mask excludes, and the erased
 * supertype list. Keyed by class rather than by rendered line so that a header change is reported
 * **changed**, the same distinction [classify] draws for members.
 *
 * **Which class-level breaks nothing else could see, and which merely read better here.** The
 * distinction is the only reason to keep two snapshots, so it is spelled out rather than waved at.
 * A class going `final` or `abstract`, and a supertype disappearing when that supertype declares
 * no member — `Revocation` dropping `java.io.Serializable`, `SignedStatement.Rotate` ceasing to
 * extend [SignedStatement] — move **no member line at all**: inherited members are not declared
 * members, so every `declaredMethods` list is unchanged, and `SIGNATURES` is blind to them too.
 * Each is an `IncompatibleClassChangeError` or an `AbstractMethodError` for an already-compiled
 * consumer that nothing in this repository would have noticed before these lines existed.
 *
 * The louder cases are **not** that, and must not be claimed as it. `Entry` dropping
 * `: Parcelable` takes `describeContents`, `writeToParcel` and the whole `Entry$Creator` block
 * with it; [StatementVerdict] ceasing to be an `enum` takes `values`, `valueOf` and `getEntries`.
 * Both redden here *and* in `SIGNATURES` already, as a scatter of removals. What a class line adds
 * there is a diagnosis rather than a detection: one *changed* line naming the supertype or the
 * kind that actually moved, instead of a dozen removals a reader has to reassemble into a cause.
 *
 * **What is still unpinned, said here rather than implied: Kotlin visibility.** An
 * `internal class` compiles to a *public* JVM class — no mangling, no access bit — so a published
 * type going `internal`, which breaks every consumer's source, is invisible to the reflection this
 * file is built on. [modifiers] renders what the JVM records, and the JVM records nothing about
 * it. Closing the gap needs `@Metadata` parsing or `kotlin-reflect`, which is a dependency
 * decision a human makes (stop rule 5), so it is recorded here rather than done. The same goes
 * for a future *subpackage*: [classesInPackage] reads one package directory, exactly as the audit
 * does.
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
     * A rendered member or class header, and the key it is classified under.
     *
     * [key] is `<owner>.<name>(<params>)` for a method or constructor, `<owner>.<name>` for a
     * field and `class <fqn>` for a class header — deliberately *without* modifiers, return type
     * or supertypes, so that a declaration present on both sides with a different modifier set, a
     * different return type or a different supertype list is reported **changed** rather than as
     * one addition plus one removal. The distinction is the whole value of the failure message: an
     * addition is fine and a change is stop rule 10.
     *
     * A key is **not unique**. A covariant bridge has the same name and the same erased
     * parameters as the method it forwards to and differs only in return type —
     * `Entry$Creator.createFromParcel(android.os.Parcel)` is two lines — so both sides are
     * compared as multisets of lines per key.
     */
    private class Member(val key: String, val line: String) {
        /**
         * Whether this line describes a class rather than one of its members, which is how the
         * two floors in `the baseline covers a whole surface rather than a corner of one` stay
         * separate: 22 class lines must not be allowed to count towards 300 members.
         */
        val isClassHeader: Boolean get() = key.startsWith("$CLASS_KEYWORD ")
    }

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
     * Masked to the declaration kind's own modifier set, because `ACC_BRIDGE` shares a bit with
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
     * The class itself: `<modifiers> class <fqn>: <supertypes>`.
     *
     * Three words go in front of the keyword, for the same reason `synthetic` and `bridge` do on a
     * member line: `Modifier.classModifiers()` holds no bit for `ACC_INTERFACE`, `ACC_ENUM` or
     * `ACC_ANNOTATION`, so the mask in [modifiers] strips all three before `Modifier.toString`
     * sees them — it would spell `interface` if asked, and has no word for the other two at all —
     * and a type ceasing to be one of the three would otherwise move nothing. The supertype list is the
     * superclass first — absent only for an interface — and then the directly implemented
     * interfaces **sorted**, because reordering an `implements` clause is not a binary change and
     * a generated file that reshuffles itself over one is a file people learn to regenerate
     * without reading. The superclass keeps its place at the head rather than joining the sort:
     * `Entry: java.lang.Object, android.os.Parcelable` says which of the two it extends.
     *
     * Erased, like everything else here: `Parceler<Entry>` renders as
     * `kotlinx.parcelize.Parceler`. `PublicApiAuditTest`'s snapshot is the one that renders type
     * arguments.
     */
    private fun classHeaderOf(type: Class<*>): Member {
        val key = "$CLASS_KEYWORD ${type.name}"
        val written = modifiers(
            type.modifiers,
            Modifier.classModifiers(),
            type.isSynthetic,
            bridge = false,
        )
        val kinds = listOfNotNull(
            "interface".takeIf { type.isInterface },
            "enum".takeIf { type.isEnum },
            "annotation".takeIf { type.isAnnotation },
        )
        val supertypes = listOfNotNull(type.superclass).map(::render) +
            type.interfaces.map(::render).sorted()
        val head = (listOf(written) + kinds).filter { it.isNotEmpty() }.joinToString(" ")
        // A type with no supertype at all is only reachable for an interface, and this package has
        // none; the colon is still dropped rather than left dangling, and `parse` reads both.
        val tail = if (supertypes.isEmpty()) "" else ": ${supertypes.joinToString(", ")}"
        return Member(key, "$head $key$tail")
    }

    /**
     * The whole JVM-visible surface, in [GENERATED_ORDER].
     */
    private fun surface(): List<Member> = classesInPackage(Utils::class.java)
        .flatMap { type ->
            // The class itself is filtered on its own access bits, exactly as its members are: a
            // package-private class is as unlinkable from outside this package as a private
            // method. Nothing in this package is one today — the filter excludes nothing, and
            // `every member's owner has a class-header line` is what notices if that changes,
            // because the member filter below tests each *member's* modifiers and would keep
            // emitting lines for an owner this one had dropped.
            val header = listOf(classHeaderOf(type)).filter { isVisible(type.modifiers) }
            val constructors = type.declaredConstructors
                .filter { isVisible(it.modifiers) }
                .map { memberOf(type, it) }
            val methods = type.declaredMethods
                .filter { isVisible(it.modifiers) }
                .map { memberOf(type, it) }
            val fields = type.declaredFields
                .filter { isVisible(it.modifiers) }
                .map { memberOf(type, it) }
            header + constructors + methods + fields
        }
        .sortedWith(GENERATED_ORDER)

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
     * is not one. A class's key is then the keyword plus the name up to the supertype list — the
     * keyword is tested first because it is the only one of the three shapes with a token of its
     * own, and `class` is deliberately *not* a modifier word so that dropping stops at it. A
     * method's key ends at `)` — the rendering is erased, so no parameter type can contain a
     * parenthesis and the first `)` is the last — and a field's at the `: ` before its type. A
     * line that fits none of the three is a corrupted or hand-edited baseline and must fail
     * loudly rather than be classified as something.
     *
     * **Loudly, but not omnisciently**, and the boundary is worth knowing before trusting this:
     * the check is that a *key* can be read, not that the line is well-formed. Delete the `class`
     * keyword from a generated header and `public final dev.eryalabs.lim.Entry: java.lang.Object`
     * is a perfectly readable **field** named `Entry` on an owner called `dev.eryalabs.lim` — so
     * it is keyed as one, and reported as a removal beside an addition. That is still red, which
     * is what matters; it is simply not reported as unreadable, and no amount of tightening here
     * could tell that line apart from a real field.
     */
    private fun parse(line: String): Member {
        val declaration = line
            .split(' ')
            .dropWhile { it in MODIFIER_WORDS }
            .joinToString(" ")
        val key = when {
            declaration.startsWith("$CLASS_KEYWORD ") ->
                "$CLASS_KEYWORD " + declaration
                    .removePrefix("$CLASS_KEYWORD ")
                    .substringBefore(':')
                    .trim()

            '(' in declaration -> declaration.substringBefore(')', "") + ")"
            else -> declaration.substringBefore(": ", "")
        }
        if (key.isBlank() || key == ")" || '.' !in key) {
            throw AssertionError(
                "cannot read a key out of this $BASELINE_PATH line, so it cannot be compared " +
                    "with anything: \"$line\". Every line must read " +
                    "`<modifiers> <owner>.<name>(<types>): <return>`, " +
                    "`<modifiers> <owner>.<name>: <type>` or " +
                    "`<modifiers> class <fully.qualified.Name>: <supertypes>` — a name that is " +
                    "not fully qualified is exactly as unreadable as no name at all.",
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
                "  A `$CLASS_KEYWORD` line is the class itself rather than a member: its " +
                "modifiers, its kind and its erased supertypes. A changed one means a published " +
                "type went `final`, changed kind, or gained or lost a supertype — an " +
                "`IncompatibleClassChangeError` for an already-compiled consumer. Read it beside " +
                "the member lines rather than instead of them: losing an interface that declares " +
                "members takes those members with it, so expect removals too, and the class line " +
                "is then what names the cause. Losing one that declares none — a marker " +
                "interface, or a sealed subclass leaving its hierarchy — moves this line alone, " +
                "and that is the case nothing else in this repository can see.\n" +
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
        val headers = actual.filter { it.isClassHeader }
        val members = actual.filterNot { it.isClassHeader }
        // `dev.eryalabs.lim.Utils.shareEntry(…)` → `dev.eryalabs.lim.Utils`: drop the parameter
        // list first, or a field's key and a method's key would be cut in different places. Class
        // headers are excluded before this, or every one of them would contribute an "owner"
        // called `class dev.eryalabs.lim`.
        val owners = members
            .map { it.key.substringBefore('(').substringBeforeLast('.') }
            .distinct()
        val defaults = members.filter { DEFAULT_MARKER in it.line }

        println(
            "lim.api: ${actual.size} lines — ${headers.size} class headers and " +
                "${members.size} members over ${owners.size} classes, " +
                "${defaults.size} of them $DEFAULT_MARKER bridges",
        )

        assertTrue(
            "expected at least $MINIMUM_MEMBERS JVM-visible members; found ${members.size}",
            members.size >= MINIMUM_MEMBERS,
        )
        // Counted separately from the members, and floored separately: a generator that emitted
        // no class header at all would leave the member floor comfortably green, which is how the
        // gap this file closed in the first place went unnoticed for four tasks.
        assertTrue(
            "expected at least $MINIMUM_CLASS_HEADERS class-header lines — they are the half of " +
                "the surface neither snapshot held until they existed; found ${headers.size}: " +
                "${headers.map { it.key }}",
            headers.size >= MINIMUM_CLASS_HEADERS,
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
            "the baseline on disk must hold one line per class and one per member of the " +
                "compiled surface; a different count means it was truncated or a line was " +
                "dropped by hand",
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
     * The file on disk is in the order [surface] generates, not merely holding the same lines.
     *
     * [classify] compares multisets per key and is order-blind on purpose — a diff that moved
     * every line would otherwise be unreadable. The cost of that is that a hand-reordered baseline
     * passes it, and a baseline somebody edits by hand instead of regenerating is the one that
     * drifts: the next real regeneration then arrives as a diff touching hundreds of lines, which
     * nobody reads. So the ordering is asserted separately, which also makes the file mechanically
     * reproducible — `regenerated()` writes exactly these bytes, header aside.
     */
    @Test
    fun `the baseline on disk is in the order the generator emits`() {
        val onDisk = baseline().map { it.line }
        // The generator's own comparator, not a second copy of it: a test that hard-coded the
        // ordering would keep passing against the old order the day `surface()` changed it, while
        // `regenerated()` emitted a different one — silently falsifying this test's own claim.
        val reordered = baseline().sortedWith(GENERATED_ORDER).map { it.line }

        // `regenerated()` is deliberately *not* called to compose this message, and the usual
        // reason — that it writes to `build/` on every green run — is the lesser one here. A hand
        // reorder leaves `the compiled surface matches the checked-in baseline` green, because
        // that comparison is order-blind; so nothing on a run that fails only this test has
        // written `lim.api.actual`, and naming it would send the reader to a file that is absent
        // or stale from some earlier failure. The command that does produce it is named instead.
        assertEquals(
            "$BASELINE_PATH holds the right lines in the wrong order, so it was edited by hand " +
                "rather than regenerated — and the comparison against the compiled surface is " +
                "order-blind by design, so this is the only test that says so. Sorted by key and " +
                "then by line is how the generator emits it: force a regeneration by making the " +
                "bodies differ, or sort the body yourself in that order.",
            reordered,
            onDisk,
        )
    }

    /**
     * The class headers carry something no member line can: a supertype.
     *
     * Non-vacuity, and at the same time the statement of what these lines are *for*. A generator
     * that emitted bare `class <fqn>` lines with the supertypes dropped would satisfy the count
     * floors and pin nothing; this is what says so.
     *
     * **Every assertion reads the supertype *list*, never the line as text**, which is not
     * fussiness: `android.os.Parcelable` is a substring of `android.os.Parcelable$Creator`, so
     * `"android.os.Parcelable" in line` is satisfied by the two `Creator` headers and would stay
     * green with both `Entry` and `TypedField` having dropped the interface outright — the one
     * thing the assertion's own message claims it would catch.
     */
    @Test
    fun `a class header renders supertypes, which no member line can`() {
        val supertypes = surface()
            .filter { it.isClassHeader }
            .associate { it.key to it.line.substringAfter(": ", "").split(", ") }

        assertTrue(
            "Entry's supertype list must name android.os.Parcelable exactly, or its losing the " +
                "interface moves nothing here: $supertypes",
            supertypes["$CLASS_KEYWORD dev.eryalabs.lim.Entry"]
                ?.contains("android.os.Parcelable") == true,
        )
        assertTrue(
            "no class header names dev.eryalabs.lim.SignedStatement as a supertype, so a sealed " +
                "subclass leaving the hierarchy would move nothing: $supertypes",
            // From the list rather than from the line, or the base class's own header would
            // satisfy this by naming itself.
            supertypes.any { (_, list) -> "dev.eryalabs.lim.SignedStatement" in list },
        )
        assertTrue(
            "StatementVerdict's supertype list must name java.lang.Enum, or its ceasing to be " +
                "one is invisible: $supertypes",
            supertypes["$CLASS_KEYWORD dev.eryalabs.lim.StatementVerdict"]
                ?.contains("java.lang.Enum") == true,
        )
        assertTrue(
            "…and its line must say `enum`, which is the flag Modifier.toString has no word for",
            surface().any {
                it.key == "$CLASS_KEYWORD dev.eryalabs.lim.StatementVerdict" &&
                    "enum $CLASS_KEYWORD" in it.line
            },
        )
    }

    /**
     * The one rendering branch no class in this package reaches: a type with no supertype at all,
     * which only an interface can be, rendered without a colon.
     *
     * [classHeaderOf] is otherwise called from [surface] alone, over real classes that all have a
     * superclass, so without this fixture the first thing to execute the branch would be the
     * release baseline on the day somebody publishes an interface. The fixture is a nested
     * interface of this test, which [classesInPackage] cannot see — it enumerates the library's
     * `classes.jar` from [Utils], not the test output — so it adds no line to anything.
     */
    @Test
    fun `a class with no supertype renders without a colon and still parses`() {
        val rendered = classHeaderOf(Supertypeless::class.java)

        assertTrue(
            "a supertype-less type must not be rendered with a dangling colon: ${rendered.line}",
            ':' !in rendered.line,
        )
        assertTrue(
            "…and must still say `interface`, which is its only distinguishing flag: " +
                rendered.line,
            "interface $CLASS_KEYWORD" in rendered.line,
        )
        assertEquals("$CLASS_KEYWORD ${Supertypeless::class.java.name}", rendered.key)
        assertEquals(
            "the colon-less shape must read back as the key it was generated under",
            rendered.key,
            parse(rendered.line).key,
        )
    }

    /** A fixture for [classHeaderOf]'s supertype-less branch; see the test that renders it. */
    private interface Supertypeless

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
     * A supertype disappearing is reported as **one changed line**, not as an addition beside a
     * removal.
     *
     * That is all this fixture can show, and the limit is worth stating: both sides hold class
     * lines only, so nothing here demonstrates that no *member* line moves beside it. That half
     * is a property of the real surface — `Revocation` is a data class and `java.io.Serializable`
     * declares no member, so no descriptor anywhere changes — and what pins it is the compiled
     * comparison in `the compiled surface matches the checked-in baseline`, over which the edit
     * was run out of band: it yields this one line and leaves all 659 other tests green.
     */
    @Test
    fun `a dropped supertype is one changed class line`() {
        val diff = classify(
            baseline = listOf(
                // Verbatim the real rendering, supertype order included — superclass first, then
                // the interfaces sorted — because a fixture that is not what the generator emits
                // is a fixture nobody can check.
                "public final class dev.eryalabs.lim.Revocation: java.lang.Object, " +
                    "java.io.Serializable",
            ).map(::parse),
            actual = listOf(
                "public final class dev.eryalabs.lim.Revocation: java.lang.Object",
            ).map(::parse),
        )

        assertEquals(emptyList<String>(), diff.added)
        assertEquals(emptyList<String>(), diff.removed)
        assertEquals(1, diff.changed.size)
        assertTrue(
            "the lost supertype must be printed on the `was` side, or a dropped interface is " +
                "invisible: " + diff.changed.single(),
            "java.io.Serializable" in diff.changed.single().substringBefore("now:"),
        )
    }

    /**
     * A class header and a member of the same class are different keys, so a type going `final`
     * never reads as though one of its methods had moved.
     *
     * The third fixture is the colon-less shape [classHeaderOf] gives a type with no supertype at
     * all, read here from a hand-written string: this test is about [parse], and the *rendering*
     * of that shape is pinned separately by
     * `a class with no supertype renders without a colon and still parses`.
     */
    @Test
    fun `a class header and its members do not share a key`() {
        val header = parse("public class dev.eryalabs.lim.Entry: java.lang.Object")
        val member = parse("public final dev.eryalabs.lim.Entry.getId(): java.lang.String")
        val supertypeless = parse("public abstract interface class dev.eryalabs.lim.Future")

        assertEquals("$CLASS_KEYWORD dev.eryalabs.lim.Entry", header.key)
        assertEquals("dev.eryalabs.lim.Entry.getId()", member.key)
        assertEquals("$CLASS_KEYWORD dev.eryalabs.lim.Future", supertypeless.key)
        assertTrue("a header with supertypes is a class header", header.isClassHeader)
        assertTrue("…so is one without", supertypeless.isClassHeader)
        assertTrue("…and a member is not", !member.isClassHeader)
    }

    /**
     * Every owner that contributes a member line also has a class-header line.
     *
     * The two filters in [surface] are not the same test — a member is kept on *its own* access
     * bits and a header on the class's — so a package-private class carrying public members would
     * produce member lines under an owner with no header above them, and the baseline would pin
     * members of a class it never named. Nothing in this package is package-private, so this
     * passes today by having nothing to catch; it is here because the day that stops being true
     * is a decision for a human and not a line to quietly regenerate.
     */
    @Test
    fun `every member's owner has a class-header line`() {
        val actual = surface()
        val headers = actual.filter { it.isClassHeader }
            .map { it.key.removePrefix("$CLASS_KEYWORD ") }
            .toSet()
        val orphaned = actual
            .filterNot { it.isClassHeader }
            .map { it.key.substringBefore('(').substringBeforeLast('.') }
            .distinct()
            .filterNot { it in headers }
            .sorted()

        assertEquals(
            "these owners contribute member lines but no class-header line, so the baseline pins " +
                "members of a class it does not name. A class invisible to a consumer whose " +
                "members are visible to one is a shape worth a human's attention rather than a " +
                "regeneration",
            emptyList<String>(),
            orphaned,
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

    /**
     * A line that fits none of the three shapes must fail loudly rather than classify as anything.
     *
     * The class cases are the ones worth naming. A header whose package qualifier was stripped —
     * `public final class Entry : android.os.Parcelable` — is the corruption that a reader would
     * call obviously wrong and a parser scanning for a dotted name would silently key as
     * something; and silently skipping it is how a baseline rots in the one direction nobody
     * watches, because an unpinned class is indistinguishable from a class nobody changed.
     */
    @Test
    fun `an unreadable line is not silently classified`() {
        for (corrupt in listOf(
            "public final",
            "nonsense",
            "",
            "public static (): void",
            "public final class Entry : android.os.Parcelable",
            "public final class : java.lang.Object",
            "class",
        )) {
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
         * How the file is ordered, defined once because two tests depend on it being the same
         * order: [surface] sorts by it and `the baseline on disk is in the order the generator
         * emits` checks the file against it.
         *
         * By key and then by line, rather than by the rendered line, so that the file groups by
         * owner and a *modifier* change moves a line's content without moving its position — the
         * diff then reads as the one-line change it is, which is also how [classify] reports it.
         */
        private val GENERATED_ORDER: Comparator<Member> = compareBy({ it.key }, { it.line })

        /**
         * The token that makes a class-header line a third shape rather than an odd field.
         *
         * Deliberately **not** in [MODIFIER_WORDS]: [parse] finds the start of a declaration by
         * dropping modifier words, so this one has to survive that drop to be recognised.
         */
        private const val CLASS_KEYWORD = "class"

        /**
         * Floors, each set below the value measured when this file was written (22 class headers,
         * 339 members, 22 member owners, 30 `$default` bridges) so that ordinary additions do not
         * have to move them. They exist against a different failure: a locator or filter that
         * finds nothing would make every assertion above pass over an empty list.
         */
        private const val MINIMUM_MEMBERS = 300
        private const val MINIMUM_CLASS_HEADERS = 20
        private const val MINIMUM_CLASSES = 15
        private const val MINIMUM_DEFAULTS = 25

        /**
         * Every word that can appear before the owner in a rendered line: `Modifier`'s own
         * vocabulary for all three member kinds and for a class, plus the two flags [modifiers]
         * appends and the three kind words [classHeaderOf] appends. Dropping them from the front
         * is how [parse] finds where the declaration starts.
         *
         * `interface`, `enum` and `annotation` are safe to drop blindly even though no member line
         * should ever begin with one: a member line's first token after the modifiers is a dotted
         * owner-qualified name, never a bare lowercase word.
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
            "interface", "enum", "annotation",
        )
    }
}
