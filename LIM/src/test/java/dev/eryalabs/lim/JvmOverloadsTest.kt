package dev.eryalabs.lim

import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * The trap `@JvmOverloads` could not remove, pinned as behaviour so it cannot go stale.
 *
 * `createShareIntent` has two overloads whose third parameter means two different things —
 * `targetPackage` on one, `requestCode` on the other — and a bare third string binds to the
 * `targetPackage` one, in Kotlin and in Java alike. A caller who meant a request code therefore
 * addresses the intent to a package that does not exist, reaches no vault, and gets no error.
 *
 * Two reasons it is pinned here rather than fixed. Renaming or removing either function breaks
 * every app compiled against 1.0.0, which is stop rule 10 in its most literal form. And the
 * `requestCode` overload is the one function in `Utils` that can never carry `@JvmOverloads`:
 * its generated three-argument form would be `(Context, Entry, String)`, byte-for-byte the JVM
 * signature the `targetPackage` overload already occupies, so the annotation is a platform
 * declaration clash and will not compile — with the sibling annotated or without it, since the
 * sibling's three-argument method exists either way. So the answer is a loud warning in both
 * KDocs plus these assertions, which fail if anybody "fixes" the resolution later.
 *
 * This is not a hypothetical. `ClientIntegrationExampleTest` was first written with the
 * positional call and every scene failed, because the vault's routing `when` never matched an
 * action of `signup-1.ACTION_SHARE_DATA`.
 *
 * The generated overloads themselves are not testable from Kotlin at all — Kotlin resolves the
 * full-arity function and fills defaults in at the call site, so the shorter JVM methods are
 * invisible from here. `JavaInteropTest` is where they are exercised, and
 * `PublicApiAuditTest`'s signature snapshot is where their arrival is recorded.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class JvmOverloadsTest {

    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()

    private val entry = Entry(
        id = "profile-1",
        fields = mapOf("name" to TypedField("Ada", FieldType.STRING)),
        publicKey = "PUBLIC-KEY-BASE64",
    )

    @Test
    fun `a bare third string is a target package, not a request code`() {
        val intent = Utils.createShareIntent(context, entry, "req-1")

        assertEquals(
            "a bare third argument binds to targetPackage; if this ever changes, every caller " +
                "who worked around the hazard by passing a package positionally silently " +
                "re-tags their intent instead",
            "req-1",
            intent.getPackage(),
        )
        assertEquals("req-1.ACTION_SHARE_DATA", intent.action)
        assertFalse(
            "the string must NOT arrive as a request code — that is the whole misuse",
            intent.hasExtra(Utils.EXTRA_SHARE_REQUEST_CODE),
        )
        assertNull(intent.getStringExtra(Utils.EXTRA_SHARE_REQUEST_CODE))

        // And the consequence an integrator actually meets: the intent is well-formed, so
        // nothing fails loudly — it is simply addressed to a vault nobody has installed.
        assertNotNull(
            "the misaddressed intent still parses as a share, which is why it fails silently",
            Utils.parseShareRequest(intent),
        )
        assertNull(
            "...and carries no request code to correlate the answer with",
            Utils.parseShareRequest(intent)?.requestCode,
        )
    }

    /**
     * The other half of the pair, so the first assertion cannot pass for the wrong reason: named
     * arguments reach the overload the caller meant, and that intent keeps the default package.
     */
    @Test
    fun `naming the request code reaches the overload the caller meant`() {
        val intent = Utils.createShareIntent(context, entry, requestCode = "req-1")

        assertEquals(Utils.DEFAULT_ENDEAVOR_PACKAGE, intent.getPackage())
        assertEquals("${Utils.DEFAULT_ENDEAVOR_PACKAGE}.ACTION_SHARE_DATA", intent.action)
        assertEquals("req-1", intent.getStringExtra(Utils.EXTRA_SHARE_REQUEST_CODE))
        assertEquals("req-1", Utils.parseShareRequest(intent)?.requestCode)
    }

    /**
     * `matchesRequestCode` is what the misuse defeats, so the cost is stated in the vocabulary a
     * client correlates in: a positionally-tagged intent's answer can never be matched, because
     * the code never left the building.
     */
    @Test
    fun `a positionally tagged share carries nothing to correlate on`() {
        val misused = Utils.createShareIntent(context, entry, "req-1")
        val intended = Utils.createShareIntent(context, entry, requestCode = "req-1")

        assertFalse(
            "a code that never became an extra cannot be matched",
            Utils.matchesRequestCode(misused, "req-1"),
        )
        assertTrue(Utils.matchesRequestCode(intended, "req-1"))
    }

    // ── The required-fields overload ─────────────────────────────────────

    /**
     * A third overload arrived with required fields, and the hazard above must mean exactly what it
     * meant: the bare three-argument call still binds `targetPackage` and declares nothing, and a
     * bare fourth *string* still binds the 1.0.0 request-code overload. Only five arguments with a
     * `Set` in fourth place reach the new one — by position or by name — because it has no
     * defaults at all and no string can bind its `optionalFields`.
     */
    @Test
    fun `the 1_0_0 calls resolve as they did, and only five arguments reach the optional-fields overload`() {
        val bare = Utils.createShareIntent(context, entry, "req-1")
        assertEquals("req-1", bare.getPackage())
        assertFalse(bare.hasExtra(Utils.EXTRA_OPTIONAL_FIELDS))

        val named = Utils.createShareIntent(context, entry, requestCode = "req-1")
        assertEquals("req-1", named.getStringExtra(Utils.EXTRA_SHARE_REQUEST_CODE))
        assertFalse("the named 1.0.0 call declares nothing", named.hasExtra(Utils.EXTRA_OPTIONAL_FIELDS))

        val fourthString = Utils.createShareIntent(context, entry, "req-1", "dev.other.vault")
        assertEquals("dev.other.vault", fourthString.getPackage())
        assertEquals("req-1", fourthString.getStringExtra(Utils.EXTRA_SHARE_REQUEST_CODE))
        assertFalse(fourthString.hasExtra(Utils.EXTRA_OPTIONAL_FIELDS))

        val positional = Utils.createShareIntent(context, entry, "req-1", setOf("name"), "dev.other.vault")
        val byName = Utils.createShareIntent(
            context,
            entry,
            requestCode = "req-1",
            optionalFields = setOf("name"),
            targetPackage = "dev.other.vault",
        )
        for (intent in listOf(positional, byName)) {
            assertEquals("dev.other.vault", intent.getPackage())
            assertEquals("req-1", intent.getStringExtra(Utils.EXTRA_SHARE_REQUEST_CODE))
            assertEquals("""["name"]""", intent.getStringExtra(Utils.EXTRA_OPTIONAL_FIELDS))
        }
    }

    /**
     * A fourth argument whose type the compiler has to infer — the shape of MockK's and
     * mockito-kotlin's `any()`, a generic getter, `TODO()` — still binds the 1.0.0 request-code
     * overload. With a default on the new overload's `targetPackage` it had a four-argument form
     * too, `String` and `Set<String>` were equally good guesses, and every one of these calls was
     * a compile error against a library that promised every 1.0.0 call resolves as it did.
     *
     * So this test is half compile-time: if a four-argument form of the new overload ever comes
     * back, this file stops compiling. The runtime half checks the call landed where it should —
     * the fourth argument became the package, and nothing was declared optional.
     */
    @Test
    fun `a fourth argument of inferred type still binds the 1_0_0 request-code overload`() {
        val generic = Utils.createShareIntent(context, entry, "req-1", inferred("dev.other.vault"))
        val reified = Utils.createShareIntent(context, entry, "req-1", matcherLike("dev.other.vault"))
        val allInferred = Utils.createShareIntent(
            matcherLike(context),
            matcherLike(entry),
            matcherLike("req-1"),
            matcherLike("dev.other.vault"),
        )
        for (intent in listOf(generic, reified, allInferred)) {
            assertEquals("dev.other.vault", intent.getPackage())
            assertEquals("req-1", intent.getStringExtra(Utils.EXTRA_SHARE_REQUEST_CODE))
            assertFalse(intent.hasExtra(Utils.EXTRA_OPTIONAL_FIELDS))
        }

        // `Nothing` is a subtype of both candidates' fourth type, so it is the sharpest probe of
        // all: it compiles only while exactly one four-argument candidate exists.
        val thrown = runCatching { Utils.createShareIntent(context, entry, "req-1", TODO("no package")) }
        assertTrue(thrown.exceptionOrNull() is NotImplementedError)
    }

    /**
     * Measured by reflection, since Kotlin cannot see generated forms: the new overload publishes
     * exactly one JVM method, its full arity, and no `$default` bridge — so no four-parameter
     * `(Context, Entry, String, Set)` exists for `javac` to weigh against the 1.0.0
     * `(Context, Entry, String, String)` either.
     */
    @Test
    fun `the optional-fields overload publishes one JVM method and no shorter form`() {
        val type = Utils::class.java
        val contextType = android.content.Context::class.java
        val entryType = Entry::class.java
        val string = String::class.java
        val set = Set::class.java

        assertNotNull(type.getMethod("createShareIntent", contextType, entryType, string, set, string))
        val withASet = type.declaredMethods
            .filter { it.name.startsWith("createShareIntent") && set in it.parameterTypes }
            .map { method -> method.name + method.parameterTypes.joinToString(", ", "(", ")") { it.simpleName } }
        assertEquals(
            "the five-parameter method and nothing else may take a Set",
            listOf("createShareIntent(Context, Entry, String, Set, String)"),
            withASet,
        )
        assertNotNull(
            "1.0.0's request-code overload is still there",
            type.getMethod("createShareIntent", contextType, entryType, string, string),
        )
        assertNotNull(
            "…and its targetPackage one",
            type.getMethod("createShareIntent", contextType, entryType, string),
        )
    }

    private companion object {
        /** A value whose type is inferred from where it is used: a generic getter's shape. */
        @Suppress("UNCHECKED_CAST")
        fun <T> inferred(value: Any): T = value as T

        /** MockK's and mockito-kotlin's `any()` shape — reified, and inferred all the same. */
        inline fun <reified T : Any> matcherLike(value: Any): T = value as T
    }
}
