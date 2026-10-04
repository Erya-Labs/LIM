package dev.eryalabs.lim

import android.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File
import java.security.KeyPairGenerator

/**
 * Which of `Redaction.kt`'s three helpers are *published* Kotlin API, pinned at the source level.
 *
 * T19 made `previewedPublicKey` and `PUBLIC_KEY_PREVIEW_CHARS` `public` so the sibling vault app
 * can call LIM's truncation rule instead of keeping a mirror copy of it, and left `redactedValue`
 * `internal` because it renders a field *value's* length — one app's own data rather than a shared
 * identifier.
 *
 * No test in this module can tell those two cases apart any other way, and that is the whole
 * reason the distinction went unnoticed for so long:
 *
 *  - **Bytecode cannot see it.** `internal` is a Kotlin-only visibility; a top-level `internal`
 *    declaration compiles to a public JVM member, unmangled. All three already sit in
 *    `PublicApiAuditTest`'s signature snapshot, and that snapshot did not move by one line when
 *    T19 landed — which is the mechanical proof the change is invisible to every existing
 *    consumer, and the reason it was safe to do unattended.
 *  - **Calls cannot see it either.** Everything inside a module may call an `internal` member, so
 *    a test that simply calls `redactedValue(...)` compiles whether the modifier is there or not.
 *    A control that cannot fail is not a control.
 *
 * So this reads the source file. One scanner, asked about three declarations, must give two
 * different answers — which is what proves it reads the modifier rather than returning a constant.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class RedactionVisibilityTest {

    // ── The source scanner ───────────────────────────────────────────────

    /** One top-level declaration, with the modifiers written in front of it. */
    private data class Declaration(val name: String, val modifiers: Set<String>)

    /**
     * Every top-level declaration in `Redaction.kt`, in file order.
     *
     * Matching is anchored at column 0, which is what makes "top-level" mean top-level: a member or
     * local declaration would be indented, and so would the `else ->` branch of
     * [previewedPublicKey]'s `when`. KDoc lines start with `*` and never match either.
     *
     * A **list**, not a map keyed by name. A map would be last-wins, so a second line matching an
     * already-seen name — an overload, or prose at column 0 inside a block comment that happens to
     * read like a declaration — would quietly answer *for* the real declaration while leaving the
     * count at three. Here it shows up as an extra element and fails `the scanner finds exactly the
     * three Redaction helpers`. The keyword set is wider than the two kinds this file happens to
     * contain for the same reason: a top-level `class` or `var` added later must be visible to that
     * count rather than slipping past it unpinned.
     */
    private fun declarations(): List<Declaration> {
        val declaration = Regex(
            """^((?:\w+\s+)*)(?:fun|val|var|class|object|interface|typealias)\s+(\w+)""",
        )
        val whitespace = Regex("""\s+""")
        return redactionSource().readLines().mapNotNull { line ->
            declaration.find(line)?.let { match ->
                val (modifiers, name) = match.destructured
                val written = modifiers.trim().split(whitespace).filterNot { it.isEmpty() }
                Declaration(name, written.toSet())
            }
        }
    }

    /** Modifiers on the single declaration named [name]; fails if it is absent or duplicated. */
    private fun modifiersOf(name: String): Set<String> {
        val matching = declarations().filter { it.name == name }
        assertEquals(
            "expected exactly one top-level declaration of `$name` in ${redactionSource()}; " +
                "found ${matching.size}, so the modifier read below would be ambiguous",
            1,
            matching.size,
        )
        return matching.single().modifiers
    }

    /**
     * `Redaction.kt` itself, located by walking up from the working directory.
     *
     * The working directory of a Gradle unit test is the module directory, but that is a Gradle
     * default rather than a promise, so every ancestor is tried both as the module root and as the
     * repository root. If none of them holds the file the test *fails naming every absolute path it
     * tried*: a scanner that silently finds nothing would pass for ever, which is the same vacuity
     * trap the fuzz arms carry an accept-one-genuine floor for.
     */
    private fun redactionSource(): File {
        val relative = "src/main/java/dev/eryalabs/lim/Redaction.kt"
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
            "cannot find Redaction.kt — this test pins a source-level fact and cannot be " +
                "silently skipped. Working directory: $workingDirectory. Tried:\n" +
                tried.map { it.absolutePath }.distinct().joinToString("\n"),
        )
    }

    @Test
    fun `the scanner finds exactly the three Redaction helpers`() {
        assertEquals(
            "the scanner must match every top-level declaration in Redaction.kt, exactly once " +
                "each, and nothing else; a missing, added or duplicated match means the " +
                "assertions below are no longer asking about the whole file",
            listOf("redactedValue", "PUBLIC_KEY_PREVIEW_CHARS", "previewedPublicKey"),
            declarations().map { it.name },
        )
    }

    @Test
    fun `the published preview helpers are not internal`() {
        // Exact modifier sets rather than merely "does not say `internal`": the explicit `public`
        // keyword is redundant to Kotlin but it is what makes this file's intent legible, so
        // dropping it is also a change worth seeing here. Either cause reads the same from the
        // bytecode — which is to say, not at all.
        assertEquals(
            "previewedPublicKey must be declared `public` — it is published API as of T19, the " +
                "member the vault calls instead of mirroring the format. Making it `internal` " +
                "again, or dropping the explicit keyword, moves not a single byte of bytecode, " +
                "so nothing else in this suite would notice",
            setOf("public"),
            modifiersOf("previewedPublicKey"),
        )
        assertEquals(
            "PUBLIC_KEY_PREVIEW_CHARS must be declared `public const` — published alongside it " +
                "so a caller can read the boundary off the constant rather than writing 64, and " +
                "`const` because dropping it would turn the field into a getter and change the " +
                "published shape",
            setOf("public", "const"),
            modifiersOf("PUBLIC_KEY_PREVIEW_CHARS"),
        )
    }

    /**
     * Negative control, and the one that proves the scanner reads the modifier: the same scanner
     * over the same file must still report `redactedValue` as `internal`.
     *
     * It stays internal deliberately. It renders a *field value's* length, which is the vault's own
     * data rather than a shared identifier, and half a reason is not a reason to freeze a second
     * member for ever.
     */
    @Test
    fun `redactedValue is still internal`() {
        assertEquals(
            "redactedValue was deliberately NOT published by T19; if this now reads `public`, " +
                "either it was published without a decision or the two preview assertions above " +
                "are passing against a scanner that reports a constant",
            setOf("internal"),
            modifiersOf("redactedValue"),
        )
    }

    // ── The boundary the published constant names ────────────────────────

    /**
     * Publishing [PUBLIC_KEY_PREVIEW_CHARS] must not have moved the boundary it names.
     *
     * A real 2048-bit key is far longer than the preview and must come back truncated with its
     * length; a short handle is under the boundary and must come back whole.
     * `ToStringRedactionTest` pins the exact boundary arithmetic — this pins that the two sides of
     * it are still different things after the visibility change.
     */
    @Test
    fun `a real key is truncated and a short key is not`() {
        val key = KeyPairGenerator.getInstance("RSA")
            .apply { initialize(2048) }
            .generateKeyPair()
            .public
            .encoded
            .let { Base64.encodeToString(it, Base64.NO_WRAP) }

        assertTrue(
            "a 2048-bit X.509 key must be longer than the preview, or this test proves nothing; " +
                "got ${key.length} chars against a boundary of $PUBLIC_KEY_PREVIEW_CHARS",
            key.length > PUBLIC_KEY_PREVIEW_CHARS,
        )
        val preview = previewedPublicKey(key)
        assertNotEquals("a real key must not be printed whole", key, preview)
        assertTrue(
            "the preview must still start with the key it previews; got $preview",
            preview.startsWith(key.take(PUBLIC_KEY_PREVIEW_CHARS)),
        )

        val short = "0123456789"
        assertTrue(short.length < PUBLIC_KEY_PREVIEW_CHARS)
        assertEquals("a key under the boundary is printed whole", short, previewedPublicKey(short))
    }
}
