package dev.eryalabs.lim

import android.content.Context
import android.content.Intent
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Method
import java.lang.reflect.Modifier
import java.lang.reflect.ParameterizedType
import java.lang.reflect.Type
import java.security.SecureRandom

/**
 * The blind spot `PublicApiAuditTest` names, closed by calling the functions instead of reading
 * them.
 *
 * That snapshot pins the shape of every published member off the JVM `Signature` attribute, and
 * records at `PublicApiAuditTest:568-573` the one thing it cannot see: **Kotlin nullability**.
 * `decodeFields(json: String?)` narrowed to `decodeFields(json: String)` breaks every Kotlin
 * caller passing `null` and does not change the bytecode signature by one byte, because Kotlin
 * records nullability in `@Nullable` annotations with CLASS retention and in its own `@Metadata`,
 * neither of which `java.lang.reflect` can read. Reading it would need `kotlin-reflect`, a new
 * dependency and therefore a human's decision under stop rule 5.
 *
 * There is a way to see it without one: **call the function with `null` and look.** A non-null
 * Kotlin parameter compiles to a `checkNotNullParameter` intrinsic at method entry, so the
 * declaration is observable as behaviour even though it is invisible as a signature — and
 * behaviour is what a Java caller gets either way, since Java honours no Kotlin declaration.
 *
 * **This file pins today's answers; it does not choose them.** Whether the verification and
 * freshness surface *should* widen to nullable and answer fail-closed is drafted under
 * "Blocked on human" in `loop/queue.md` and is deliberately left open: adopting it turns exactly
 * the rows below red, which is the intended signal rather than an obstacle. The split is the
 * finding, not the verdict.
 *
 * **What it covers and what it does not.** Every reference-typed parameter position of every
 * published method on `Utils`, including the arities `@JvmOverloads` generates — each is
 * separately callable from Java, which is the audience this concerns. Three limits, stated rather
 * than discovered later:
 *
 * - Positions are keyed by rendered *type*, because `java.lang.reflect` cannot read parameter
 *   names without `-parameters`. A parameter renamed in place is therefore invisible here, and so
 *   is a swap of two adjacent same-typed parameters; a parameter retyped, removed or reordered
 *   otherwise moves its key and fails the stale-entry assertion. (The intrinsic's *message* does
 *   name the parameter, and the assertion below reads its prefix only — pinning the names would
 *   make every rename a failure in a file whose subject is nullability, which is not a trade
 *   worth making here.)
 * - A tolerant position is checked against the answer its KDoc documents, not against the whole
 *   of its contract. `ResultParsingTest`, `FieldsCodecTest`, `EntryCodecTest`,
 *   `IntentDescriptionTest`, `RequestParsingTest`, `StatementPreImageTest` and `NonceFormatTest`
 *   own those.
 * - Only `Utils` is enumerated. The data classes' constructors and `copy` take non-null
 *   parameters too, but nothing hands a `Revocation` constructor an unchecked IPC payload.
 *
 * The other half of this — the literal Java call, which reflection cannot write because
 * reflection has no compile-time overload resolution and no `null` literal binding to one of
 * several arities — is in `JavaInteropTest`.
 *
 * **And the other half of the hostile surface, which this file deliberately does not cover.**
 * `null` is one way an argument can be hostile; the rest is a non-null reference carrying contents
 * nobody designed — empty, oversized, control-charactered, type-confused, or a `null` *inside* a
 * collection whose declared element type forbids one. `PublishedSurfaceFuzzTest` owns that half
 * over the same enumeration: it draws hostile values by parameter type for every published method
 * on `Utils`, and its own third assertion is that the set it invoked equals the published set. The
 * two files split on the value, not on the member, and neither repeats the other: every argument
 * here is `null` or a well-formed sample, and no *argument* there is ever `null` — only the
 * contents of one.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class NullArgumentTest {

    // ── The declared set ─────────────────────────────────────────────────

    /** A documented answer for `null` at one position, as prose and as a predicate. */
    private class Answer(val described: String, val holds: (Any?) -> Boolean)

    /**
     * Every position declared nullable, paired with the answer its KDoc documents for `null`.
     *
     * This is the *claim*; the loop below measures the real set and compares. A position missing
     * from here is expected to throw, so forgetting one is a failure rather than a silence — and
     * an entry naming a position the enumeration did not produce is a failure too, which is what
     * stops a retyped or removed parameter from leaving a dead expectation behind.
     *
     * The answers are asserted as *values*. "It did not throw" is the weaker claim, and it would
     * be satisfied by a parser that returned a hollow result instead of `null` — exactly the
     * failure `decodeEntry` (T1) exists to prevent.
     */
    private val NULL_TOLERANT: Map<String, Answer> = mapOf(
        // The six intent parsers, the statement parser and the entry decoder: all fail closed,
        // because what reaches them came from another app and "I could not read this" has to be
        // an answer rather than a crash.
        "parseShareRequest(Intent)#0" to Answer("null") { it == null },
        "parseQueryRequest(Intent)#0" to Answer("null") { it == null },
        "parseSignChallengeRequest(Intent)#0" to Answer("null") { it == null },
        "parseShareResult(Intent)#0" to Answer("null") { it == null },
        "parseQueryResult(Intent)#0" to Answer("null") { it == null },
        "parseSignChallengeResult(Intent)#0" to Answer("null") { it == null },
        "parseSignedStatement(String)#0" to Answer("null") { it == null },
        "decodeEntry(String)#0" to Answer("null") { it == null },
        // Not `null`: `decodeFields` documents an empty map precisely so that callers need not
        // handle one, and a `null` here would be the bug that KDoc promises is impossible.
        "decodeFields(String)#0" to Answer("an empty map, never null") {
            it == emptyMap<String, TypedField>()
        },
        "isStatementPreImage(byte[])#0" to Answer("false") { it == false },
        // Only the intent. `expected` is the caller's own request code, not untrusted input, and
        // its KDoc says so — so it is on the throwing side and stays there.
        "matchesRequestCode(Intent, String)#0" to Answer("false") { it == false },
        // Not a fail-closed value but a description: this is what a client reaches for when
        // something has already gone wrong, so it must not add a second failure. The *wording*
        // is explicitly not API and `IntentDescriptionTest` owns it; the structural claim — one
        // line, naming the null, no flow — is what is checked here.
        "describeIntent(Intent)#0" to Answer("a one-line description naming the null") {
            it is String && it.isNotBlank() && it.lines().size == 1 && "null" in it
        },
        // T12's negative control reached from the other side: the default is `null`, and a
        // `null` attaches nothing. A builder whose other arguments are non-null still builds a
        // complete intent, so the absent format is the only difference — hence the nonce check,
        // which stops a broken intent from satisfying "carries no format" trivially.
        "createSignChallengeIntent(Context, String, byte[], String, String, String)#5" to
            Answer("an intent carrying no ${Utils.EXTRA_NONCE_FORMAT}") {
                it is Intent && it.hasExtra(Utils.EXTRA_NONCE) &&
                    !it.hasExtra(Utils.EXTRA_NONCE_FORMAT)
            },
        // T28's result builders, five positions over four generated arities: `requestCode` is
        // position #2 in each of the three full-arity forms *and* in the sign-challenge builder's
        // three-argument one, with `algorithm` at #3. Each answer is a value rather than "it did
        // not throw", and each names the flow's own extras as well as the absent one — a builder
        // that returned a hollow intent would satisfy the weaker claim.
        //
        // `!hasExtra` and never `getStringExtra(…) == null`: `putExtra(key, null as String?)`
        // stores a null and leaves `hasExtra` returning `true`, so the weaker spelling would pass
        // against a builder that wrote the null these functions exist to omit.
        "createShareResultIntent(String, Map<String, TypedField>, String)#2" to
            Answer("an intent carrying its own extras and no ${Utils.EXTRA_SHARE_REQUEST_CODE}") {
                it is Intent && it.hasExtra(Utils.EXTRA_PUBLIC_KEY) &&
                    it.hasExtra(Utils.EXTRA_FIELDS_JSON) &&
                    !it.hasExtra(Utils.EXTRA_SHARE_REQUEST_CODE)
            },
        "createQueryResultIntent(String, Map<String, TypedField>, String)#2" to
            Answer("an intent carrying its own extras and no ${Utils.EXTRA_SHARE_REQUEST_CODE}") {
                it is Intent && it.hasExtra(Utils.EXTRA_PUBLIC_KEY) &&
                    it.hasExtra(Utils.EXTRA_QUERY_RESULT_FIELDS) &&
                    !it.hasExtra(Utils.EXTRA_SHARE_REQUEST_CODE)
            },
        "createSignChallengeResultIntent(byte[], Map<String, TypedField>, String)#2" to
            Answer("an intent carrying its own extras and no ${Utils.EXTRA_SHARE_REQUEST_CODE}") {
                it is Intent && it.hasExtra(Utils.EXTRA_SIGNATURE) &&
                    it.hasExtra(Utils.EXTRA_FIELDS_JSON) &&
                    !it.hasExtra(Utils.EXTRA_SHARE_REQUEST_CODE)
            },
        "createSignChallengeResultIntent(byte[], Map<String, TypedField>, String, String)#2" to
            Answer("an intent carrying its own extras and no ${Utils.EXTRA_SHARE_REQUEST_CODE}") {
                it is Intent && it.hasExtra(Utils.EXTRA_SIGNATURE) &&
                    it.hasExtra(Utils.EXTRA_FIELDS_JSON) &&
                    !it.hasExtra(Utils.EXTRA_SHARE_REQUEST_CODE)
            },
        "createSignChallengeResultIntent(byte[], Map<String, TypedField>, String, String)#3" to
            Answer("an intent carrying its signature and no ${Utils.EXTRA_ALGORITHM}") {
                it is Intent && it.hasExtra(Utils.EXTRA_SIGNATURE) &&
                    it.hasExtra(Utils.EXTRA_SHARE_REQUEST_CODE) &&
                    !it.hasExtra(Utils.EXTRA_ALGORITHM)
            },
        // T29's request overloads add seven published arities and exactly **one** tolerant
        // position: the `algorithm` of the sign-challenge request overload's full arity. The
        // `request` parameters are all on the throwing side and stay there — a vault that lost
        // the request it is answering has nothing to correlate, which is `matchesRequestCode`'s
        // own rule about `""` reached from the builder side. The other six arities declare
        // nothing nullable at all: `publicKey`, `signature` and `fields` are each required.
        //
        // The request carries `"req-1"`, so the echoed token is present here while the algorithm
        // is absent — which is what stops this from being satisfied by a builder that wrote
        // neither.
        "createSignChallengeResultIntent(SignChallengeRequest, byte[], Map<String, TypedField>, String)#3" to
            Answer("an intent carrying its signature and echo, and no ${Utils.EXTRA_ALGORITHM}") {
                it is Intent && it.hasExtra(Utils.EXTRA_SIGNATURE) &&
                    it.hasExtra(Utils.EXTRA_SHARE_REQUEST_CODE) &&
                    !it.hasExtra(Utils.EXTRA_ALGORITHM)
            },
        // Required fields: four tolerant positions and no more. The two readers take an unchecked
        // IPC payload and fail closed to `null`, like the six parsers. The verdict's `result` is
        // the same kind of payload, and a missing one is an answer carrying no fields — so with
        // the sample requirements (`name` required) it is INCOMPLETE, a value and not a throw. And
        // the requirements-aware share result's `requestCode` has no default but accepts `null`
        // like its siblings', attaching nothing — while the acknowledgement, which the sample
        // payload satisfies, is still written: the `null` changes the one extra it is about.
        "parseFieldRequirements(Intent)#0" to Answer("null") { it == null },
        "parseAppliedOptionalFields(Intent)#0" to Answer("null") { it == null },
        "checkFieldRequirements(FieldRequirements, Intent)#1" to
            Answer("${FieldRequirementsVerdict.INCOMPLETE}") { it == FieldRequirementsVerdict.INCOMPLETE },
        "createShareResultIntent(String, Map<String, TypedField>, String, FieldRequirements)#2" to
            Answer(
                "an intent carrying its own extras and the acknowledgement, and no " +
                    Utils.EXTRA_SHARE_REQUEST_CODE,
            ) {
                it is Intent && it.hasExtra(Utils.EXTRA_PUBLIC_KEY) &&
                    it.hasExtra(Utils.EXTRA_FIELDS_JSON) &&
                    it.hasExtra(Utils.EXTRA_APPLIED_OPTIONAL_FIELDS) &&
                    !it.hasExtra(Utils.EXTRA_SHARE_REQUEST_CODE)
            },
    )

    /**
     * The exception type this toolchain actually throws, measured rather than assumed: Kotlin
     * 2.0.21's `Intrinsics.checkNotNullParameter`. Kotlin 1.4 changed this from
     * `IllegalArgumentException` to `NullPointerException`, so it is a toolchain fact and pinned
     * as one — a compiler upgrade that changed it would change what a Java caller catches.
     */
    private val EXPECTED_EXCEPTION = "java.lang.NullPointerException"

    /**
     * And the intrinsic's own message, because the type alone is not enough to say *where* the
     * call failed. A `NullPointerException` raised deeper in a function body would satisfy the
     * type assertion while the parameter check had quietly gone — which would make this file
     * agree with its own thesis for the wrong reason, since the thesis is that a non-null
     * *declaration* is observable at method entry. This prefix is what Kotlin 2.0.21's
     * `checkNotNullParameter` writes, so it is a toolchain string and pinned as one: a compiler
     * that changed it fails here, which is the right place to find that out.
     */
    private val EXPECTED_MESSAGE_PREFIX = "Parameter specified as non-null is null"

    /**
     * Non-vacuity floors. A filter that drifted to the empty set passes every assertion in this
     * file for ever, which is the trap the other suites' fuzz floors exist for. Set below the
     * measured actuals (64 methods, 127 positions — T28's three result builders added ten
     * published arities and 22 reference positions between them, and T29's request overloads
     * seven more arities and 19 more positions) so that adding a member does not fail this,
     * and the actual is printed on every run and recorded in the Progress log.
     */
    private val MINIMUM_METHODS = 45
    private val MINIMUM_POSITIONS = 80

    // ── Fixtures ─────────────────────────────────────────────────────────

    /**
     * Deterministic stand-in for the entropy source, the `NonceTest` idiom: `SecureRandom` with a
     * seed is not reproducible across instances on this toolchain, so the source is pinned
     * explicitly.
     */
    private class SeededRandom(seed: Long) : SecureRandom() {
        private val source = java.util.Random(seed)
        override fun nextBytes(bytes: ByteArray) = source.nextBytes(bytes)
    }

    private val context: Context = ApplicationProvider.getApplicationContext()
    private val clock = 1_770_000_000_000L
    private val nonce = Utils.generateNonce(SeededRandom(7), clock)
    private val fields = mapOf("name" to TypedField("Ada", FieldType.STRING))
    private val entry = Entry("profile-1", fields, "PUBLIC-KEY-BASE64")
    private val intent = Utils.createQueryIntent(context, "PUBLIC-KEY-BASE64", "req-1")
    private val rotation = RotationStatement("K-OLD", "K-NEW", "rot-1", 0L, Long.MAX_VALUE)
    private val authorization = RecoveryAuthorization("K-SUBJECT", "K-RECOVERY", "auth-1", 1L, 0L)
    private val revocation = Revocation("K-SUBJECT", "auth-1", 2L, 0L)

    /**
     * The three parsed-request types T29's result overloads take. Each carries a non-blank
     * `requestCode`, which is what makes the `#2` and `#3` answers below legible: the builders
     * read the token off the request, so a request with none would make "carries no algorithm"
     * and "carries no request code" indistinguishable.
     */
    private val shareRequest = ShareRequest(entry, "req-1", Utils.PROTOCOL_VERSION)
    private val queryRequest = QueryRequest("PUBLIC-KEY-BASE64", "req-1", Utils.PROTOCOL_VERSION)
    private val signChallengeRequest =
        SignChallengeRequest("PUBLIC-KEY-BASE64", nonce, "req-1", Utils.NONCE_FORMAT_TIMESTAMPED)

    /**
     * Required fields' two new parameter types. The requirements declare [fields]' one name
     * required, which is what makes the answers above legible: the sample payload satisfies them,
     * so the requirements-aware builder writes its acknowledgement, and an answer with no fields at
     * all is `INCOMPLETE` rather than `NOT_ACKNOWLEDGED`.
     */
    private val requirements = FieldRequirements(fields.keys)
    private val optionalNames: Set<String> = setOf("name")

    /**
     * One well-formed value per published parameter *type*.
     *
     * "Valid" here means only what this file needs it to mean: the call returns normally. That is
     * not asserted on trust — `the valid argument vector really is valid` invokes every method
     * with the unmodified vector, so a throw observed after substituting `null` is attributable
     * to the `null` and not to a junk vector. It is deliberately not a semantic fixture: the
     * sample `String` is a plausible string and nothing more, so `verifySignature` answers
     * `false` and `parseSignedStatement` answers `null` on it, which is fine here and is pinned
     * properly by the suites that own those functions.
     *
     * An unknown type fails rather than defaulting, so a parameter of a new type cannot be
     * enumerated against a value nobody chose.
     */
    private fun sample(type: Type): Any {
        val raw = when (type) {
            is ParameterizedType -> type.rawType as Class<*>
            is Class<*> -> type
            else -> throw AssertionError("unhandled parameter type shape: ${render(type)}")
        }
        return when (raw) {
            Context::class.java -> context
            Intent::class.java -> intent
            String::class.java -> "PUBLIC-KEY-BASE64"
            ByteArray::class.java -> nonce
            java.lang.Long.TYPE -> clock
            SecureRandom::class.java -> SeededRandom(11)
            Entry::class.java -> entry
            RotationStatement::class.java -> rotation
            RecoveryAuthorization::class.java -> authorization
            Revocation::class.java -> revocation
            ShareRequest::class.java -> shareRequest
            QueryRequest::class.java -> queryRequest
            SignChallengeRequest::class.java -> signChallengeRequest
            FieldRequirements::class.java -> requirements
            Set::class.java -> optionalNames
            Map::class.java -> fields
            List::class.java -> sampleList(type)
            else -> throw AssertionError(
                "no sample value for parameter type ${render(type)} — a new published parameter " +
                    "type needs one here, chosen deliberately, before this file can call it",
            )
        }
    }

    /** A one-element list of whatever the declared element type is, read off the generics. */
    private fun sampleList(type: Type): List<Any> {
        val element = (type as? ParameterizedType)?.actualTypeArguments?.singleOrNull()
        return when (element) {
            Revocation::class.java -> listOf(revocation)
            RecoveryAuthorization::class.java -> listOf(authorization)
            else -> throw AssertionError(
                "no sample element for list parameter ${render(type)}",
            )
        }
    }

    // ── Enumeration ──────────────────────────────────────────────────────

    /**
     * The same three predicates the audit uses — `PublicApiAuditTest:456`, which explains why the
     * `$default` bridges carrying default-argument values must go (nobody writes against them and
     * they move with the compiler) and why the `@JvmOverloads` arities must stay (each is
     * separately callable from Java).
     *
     * Spelled out here rather than shared: it is private to that class, and widening a test's
     * visibility to borrow a one-line predicate buys less than the citation does. The two cannot
     * silently disagree about `Utils` for long — a divergence shows up as a method this file
     * cannot find a sample for, or as the audit's own signature snapshot moving.
     */
    private fun Method.isPublishedApi(): Boolean =
        Modifier.isPublic(modifiers) && !isSynthetic && !isBridge

    /**
     * `isNonceFresh(byte[], long)`, as the audit's snapshot spells it. Arity is part of the key,
     * because `@JvmOverloads` publishes several methods under one name and they do not all take
     * their parameters in the same positions.
     */
    private fun methodKey(method: Method): String =
        "${method.name}(${method.genericParameterTypes.joinToString(", ", transform = ::render)})"

    /** `PublicApiAuditTest:1172`'s renderer, so a key here reads like a line of that snapshot. */
    private fun render(type: Type): String = PACKAGE_QUALIFIER.replace(type.typeName, "")

    private val methods: List<Method> = Utils::class.java.declaredMethods
        .filter { it.isPublishedApi() }
        .sortedBy(::methodKey)

    /** One parameter position, called with `null`, and what came back out. */
    private class Row(
        val key: String,
        val thrown: Throwable?,
        val returned: Any?,
    ) {
        val tolerated: Boolean get() = thrown == null
    }

    private class Measurement(
        /** Method key to whatever the unmodified vector threw, or `null` for "returned". */
        val baseline: List<Pair<String, Throwable?>>,
        val rows: List<Row>,
    )

    /**
     * One loop, every answer. The tolerant and intolerant halves are the same enumeration
     * classified two ways — split into two loops they would be two tests agreeing by
     * construction, and a position dropped by one filter would simply vanish from both reports.
     */
    private val measured: Measurement by lazy {
        val baseline = mutableListOf<Pair<String, Throwable?>>()
        val rows = mutableListOf<Row>()

        for (method in methods) {
            val key = methodKey(method)
            val types = method.genericParameterTypes
            val valid = Array<Any?>(types.size) { sample(types[it]) }

            baseline += key to call(method, valid).second

            types.forEachIndexed { index, type ->
                // A primitive cannot be null, and `Method.invoke` would reject the attempt
                // before the library ever saw it. There is nothing to classify.
                if ((type as? Class<*>)?.isPrimitive == true) return@forEachIndexed
                val args = valid.copyOf()
                args[index] = null
                val (returned, thrown) = call(method, args)
                rows += Row(key = "$key#$index", thrown = thrown, returned = returned)
            }
        }

        check(rows.map { it.key }.distinct().size == rows.size) {
            "two positions render to the same key, so one of them is unassertable"
        }
        Measurement(baseline, rows)
    }

    /**
     * Invoke and report, unwrapping before classifying.
     *
     * `InvocationTargetException` is reflection's wrapper, not the finding: `targetException` is
     * what a direct Java call at this site would actually catch, and pinning the wrapper would
     * pin reflection's behaviour instead of the library's. An `IllegalArgumentException` from
     * `invoke` itself is deliberately *not* caught — that means the sample vector is ill-typed,
     * which is a bug in this file and should be loud.
     */
    private fun call(method: Method, args: Array<Any?>): Pair<Any?, Throwable?> = try {
        method.invoke(Utils, *args) to null
    } catch (e: InvocationTargetException) {
        null to e.targetException
    }

    // ── The control that makes the rest mean anything ────────────────────

    @Test
    fun `the valid argument vector really is valid`() {
        val threw = measured.baseline
            .filter { (_, thrown) -> thrown != null }
            .map { (key, thrown) -> "$key threw $thrown with no null substituted" }
            .sorted()

        assertEquals(
            "every published method must return normally on the unmodified sample vector, or a " +
                "throw seen after substituting null cannot be attributed to the null",
            emptyList<String>(),
            threw,
        )
        assertTrue(
            "only ${methods.size} published methods enumerated, floor $MINIMUM_METHODS — the " +
                "filter has drifted",
            methods.size >= MINIMUM_METHODS,
        )
    }

    // ── The split ────────────────────────────────────────────────────────

    @Test
    fun `exactly the positions declared nullable tolerate a null argument`() {
        val enumerated = measured.rows.map { it.key }.toSet()

        // Direction one: a declared entry naming a position that no longer exists. This is what
        // stops a retyped, removed or reordered parameter from leaving a dead expectation that
        // reads as coverage.
        assertEquals(
            "NULL_TOLERANT names positions the enumeration did not produce; a parameter that " +
                "was retyped or removed moves its key, and the entry must move with it",
            emptyList<String>(),
            (NULL_TOLERANT.keys - enumerated).sorted(),
        )

        // Direction two, out of the same rows: the measured tolerant set against the declared
        // one. A position declared tolerant that threw shows up on one side, a position that
        // quietly started accepting null on the other.
        assertEquals(
            "the measured null-tolerant positions are not the declared ones. A position that " +
                "appears only on the left was widened to nullable without this file being told " +
                "— which may be the blocked nullability decision being adopted, in which case " +
                "move the entry here and give it its fail-closed answer. A position that " +
                "appears only on the right was narrowed, and that is stop rule 10",
            NULL_TOLERANT.keys.sorted(),
            measured.rows.filter { it.tolerated }.map { it.key }.sorted(),
        )
    }

    @Test
    fun `every tolerant position answers what its KDoc documents`() {
        val wrong = measured.rows
            .filter { it.tolerated }
            .mapNotNull { row ->
                val answer = NULL_TOLERANT[row.key] ?: return@mapNotNull null
                if (answer.holds(row.returned)) null
                else "${row.key} must answer ${answer.described}, got ${row.returned}"
            }
            .sorted()

        assertEquals(
            "a position that accepts null must give the documented answer as a value — not " +
                "merely decline to throw, which a hollow result would also do",
            emptyList<String>(),
            wrong,
        )
    }

    @Test
    fun `every other position throws, and all of them throw the same measured type`() {
        val thrown = measured.rows.filterNot { it.tolerated }

        assertEquals(
            "a non-null parameter met with null must raise Kotlin's parameter intrinsic, and the " +
                "type it raises is what a Java caller catches. Measured on Kotlin 2.0.21; a " +
                "second type here means some position fails somewhere other than at method entry",
            setOf(EXPECTED_EXCEPTION),
            thrown.map { it.thrown!!.javaClass.name }.toSet(),
        )

        // The type says a null killed the call; only the message says the *parameter check* did.
        val elsewhere = thrown
            .filterNot { it.thrown!!.message.orEmpty().startsWith(EXPECTED_MESSAGE_PREFIX) }
            .map { "${it.key} threw ${it.thrown!!.message}" }
            .sorted()

        assertEquals(
            "every throw must come from the parameter check at method entry, not from a null " +
                "that survived into the body — the declaration is what this file observes, and " +
                "a later NullPointerException would satisfy the type assertion without it",
            emptyList<String>(),
            elsewhere,
        )
    }

    // ── Non-vacuity ──────────────────────────────────────────────────────

    @Test
    fun `the enumeration is neither empty nor one-sided`() {
        val rows = measured.rows
        val tolerant = rows.count { it.tolerated }
        val threw = rows.size - tolerant

        // Printed on every run, the house habit: the floors below are deliberately slack, so the
        // actuals have to be visible or a drift that stays above them is invisible.
        println(
            "NullArgumentTest: methods=${methods.size} positions=${rows.size} " +
                "tolerant=$tolerant threw=$threw thrownType=$EXPECTED_EXCEPTION",
        )

        assertTrue(
            "only ${rows.size} reference parameter positions enumerated, floor " +
                "$MINIMUM_POSITIONS — the enumeration has drifted and every assertion in this " +
                "file is passing over nothing",
            rows.size >= MINIMUM_POSITIONS,
        )
        assertTrue("no position declared null-tolerant", NULL_TOLERANT.isNotEmpty())
        assertTrue("no position tolerated null, so the tolerant half proved nothing", tolerant > 0)
        assertTrue("no position threw, so the intolerant half proved nothing", threw > 0)
    }

    private companion object {
        /** `PublicApiAuditTest:1172` verbatim: strips `java.util.` and leaves `Map` alone. */
        private val PACKAGE_QUALIFIER = Regex("""\b(?:[a-z][A-Za-z0-9_]*\.)+(?=[A-Z])""")
    }
}
