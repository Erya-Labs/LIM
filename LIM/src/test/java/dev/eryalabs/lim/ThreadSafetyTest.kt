package dev.eryalabs.lim

import android.content.Intent
import android.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.lang.reflect.Field
import java.lang.reflect.Modifier
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.concurrent.Callable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher

/**
 * "`Utils` is stateless, call it from any thread" — made a measured claim rather than a habit.
 *
 * Every function in [Utils] builds its own `Gson`, `KeyFactory` and `Signature` per call, so the
 * object is thread-safe today *by construction* — and that was documented nowhere and checked
 * nowhere. Both halves of that mattered. An Android library is called from a binder thread while
 * the main thread parses a result, which is exactly where the reference vault's handlers sit, and
 * an integrator had nothing to read saying whether it was allowed. And the obvious optimisation —
 * hoisting those per-call instances into fields — is a silent correctness break:
 * [java.security.Signature] and [java.security.KeyFactory] carry per-operation state and are not
 * thread-safe, so two concurrent verifications would interleave `initVerify`/`update`/`verify` and
 * could return each other's answers. A verifier returning the wrong `true` is the worst defect
 * this library can have.
 *
 * Two arms, and the first is the primary one.
 *
 * **(a) Structural.** A snapshot of the declared fields of the whole `Utils.kt` compilation unit —
 * the object, its member classes and the file facade — that are not primitive-or-`String`
 * constants, plus a type assertion over whatever fields exist. This is the guard with teeth: it
 * fails *deterministically* the moment somebody adds mutable per-operation state, in the same way
 * `PublicApiAuditTest`'s signature snapshot makes an API change something a reader has to meet
 * rather than something that slips through. Three holders rather than one because a hoist spelled
 * at file level or inside a nested object lands in a different class file — see [stateHolders].
 *
 * **(b) Behavioural.** Eight threads running 1,600 tasks over fixtures built on the main thread,
 * every answer compared against the single-threaded one. This arm can only ever *observe* a race,
 * never prove its absence — a broken build may pass it by luck. It is here because it exercises
 * the real code paths end to end and because the absence of any multi-threaded test at all in this
 * suite was itself a gap, not because it is the proof. When the two disagree about a change, (a)
 * is the one to believe.
 *
 * **Robolectric off the main thread: measured, not assumed.** No test in this repo had ever used a
 * second thread, so whether the sandbox permits `android.util.Base64` and `Intent` from a pool
 * thread was unknown. It does — all eight workers below call both, and the arm would be reduced to
 * the Android-free operations if that ever stopped being true.
 *
 * **What this file does not claim.** It says nothing about [Utils]'s *callers*. The library does
 * not copy the arguments handed to it, so a caller mutating a `ByteArray` — or handing the same
 * not-yet-unparcelled `Intent` to two threads, where the race is inside `Bundle.unparcel` and not
 * in this library at all — gets exactly what it asked for. That limit is stated in [Utils]'s own
 * KDoc beside the guarantee, since it is a fact an integrator has to act on rather than one this
 * test can check: arm (b)'s baseline calls every operation once on the main thread, which
 * materialises the fixture `Intent`'s `Bundle` before the pool ever starts.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ThreadSafetyTest {

    // ─────────────────────────────────────────────────────────────────────
    // (a) Structural: the field snapshot, which is the primary guard
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Every field the [Utils] *compilation unit* is expected to declare that is not a
     * primitive-or-`String` constant, measured by reflection rather than read off the source.
     * Qualified by declaring class, because "`Utils`'s fields" is not the same set as "the fields
     * a hoist into `Utils.kt` could land in" — see [stateHolders].
     *
     * Constants are filtered out because there are thirty-odd of them — the extra keys, the action
     * strings, the domain tags — and they can never carry per-operation state, so listing them
     * would bury the four that matter under noise that changes every time a protocol constant is
     * added. What is left is the whole of this unit's standing state:
     *
     * - `Utils.INSTANCE` — the Kotlin `object` singleton itself.
     * - `Utils.FIELDS_TYPE` — a Gson `TypeToken.type`, an immutable `java.lang.reflect.Type`.
     * - `Utils.STATEMENT_DOMAIN_BYTES` — the domain prefix, computed once. A `ByteArray`, so it is
     *   the one entry here that is *mutable in principle*; nothing writes to it, and a future
     *   writer would be changing bytes that are inside every signature this library verifies.
     * - `Utils.BASE64_PATTERN` — a `Regex`, documented immutable and safe to share.
     * - `Utils.DESCRIBED_EXTRAS` — a `listOf(...)`, immutable.
     *
     * Adding a field becomes a deliberate act a reader meets here. That is the point: the snapshot
     * rather than the deny-list below is what makes hoisting shared state a decision instead of an
     * optimisation nobody reviewed.
     */
    private val expectedStatefulFields = setOf(
        "Utils.INSTANCE",
        "Utils.FIELDS_TYPE",
        "Utils.STATEMENT_DOMAIN_BYTES",
        "Utils.BASE64_PATTERN",
        "Utils.DESCRIBED_EXTRAS",
    )

    /**
     * Types no field of [Utils] may have, because every one of them carries per-operation state
     * and none is thread-safe. [Signature] and [KeyFactory] are the two this library would
     * actually reach for; [MessageDigest], [Cipher], [SimpleDateFormat] and [Calendar] are the
     * classic rest, listed so that the first time one appears is not also the first time anybody
     * thinks about it.
     *
     * **`Gson` is deliberately absent.** Gson documents its instances as thread-safe, so hoisting
     * one into a field is legitimate and this file must not forbid it. The snapshot above is what
     * makes that hoist deliberate — a reader meets the new field name there and decides — which is
     * exactly why the deny-list is the secondary check and not the mechanism.
     */
    private val forbiddenFieldTypes = listOf(
        Signature::class.java,
        KeyFactory::class.java,
        MessageDigest::class.java,
        Cipher::class.java,
        SimpleDateFormat::class.java,
        Calendar::class.java,
    )

    /**
     * The declared fields of [type] minus its primitive-and-`String` constants.
     *
     * A "constant" is `final` and of primitive or `String` type — the shape every `const val` in
     * [Utils] compiles to. Synthetic fields are dropped as compiler bookkeeping, the same
     * exclusion `PublicApiAuditTest` makes for synthetic methods. Everything else is kept,
     * including a `final` reference field: `final` constrains the *reference*, not the object, so
     * a `private val SHARED_SIGNATURE` is final and is precisely the hazard this looks for.
     */
    private fun statefulFields(type: Class<*>): List<Field> = type.declaredFields
        .filter { !it.isSynthetic }
        .filterNot {
            Modifier.isFinal(it.modifiers) &&
                (it.type.isPrimitive || it.type == String::class.java)
        }

    /**
     * Every class a hoist into `Utils.kt` could put a field in — `Utils` itself is not the whole
     * answer, and assuming it was would leave two easy evasions open.
     *
     * `Class.getDeclaredFields` reports a class's *own* fields and nothing else, so two spellings
     * of the same shared-`Signature` mistake would miss a snapshot taken on `Utils` alone:
     *
     * - a **file-level** `private val SHARED_SIGNATURE = ...`, which Kotlin compiles into the
     *   `UtilsKt` facade class rather than into `Utils` — this library already emits such facades,
     *   `RedactionKt` among them;
     * - a **nested** `private object Shared { val SIG = ... }`, whose field lives on `Utils$Shared`
     *   while the enclosing class gains no field at all for the declaration.
     *
     * Either one would let `verifySignature` share one `Signature` with every structural assertion
     * green, which would make the guarantee in [Utils]'s own KDoc false. So all three are walked:
     * the anchor, its member classes transitively, and the facade if it exists.
     *
     * **The facade name is derived from the anchor class, and Kotlin derives it from the file.**
     * Those coincide only because `object Utils` lives in `Utils.kt` with no `@file:JvmName`. Move
     * it to `LimUtils.kt`, or annotate the file, and the real facade becomes `LimUtilsKt` while
     * this lookup goes on asking for `UtilsKt` and quietly finding nothing. That is the one way
     * this walk can narrow without a test going red, so it is written down rather than discovered:
     * if `Utils.kt` is ever renamed, rename the derivation with it.
     *
     * Also, since every assertion fed by this walk is of the form "found nothing", a lookup that
     * could never find *anything* would absorb the file-level evasion into a green run. There is no
     * `UtilsKt` today — `Utils.kt` declares nothing at file level — so the absence proves nothing
     * either way, and the mechanism is pinned separately against a facade this module really does
     * emit. See `the facade lookup finds a facade that exists`.
     */
    private fun stateHolders(anchor: Class<*>): List<Class<*>> {
        val nested = ArrayList<Class<*>>()
        fun walk(type: Class<*>) {
            nested += type
            // Member classes only: anonymous classes (`Utils$FIELDS_TYPE$1`, the Gson TypeToken)
            // are not reported here, and carry no declaration anybody could hoist into.
            type.declaredClasses.forEach(::walk)
        }
        walk(anchor)
        return nested + listOfNotNull(facadeNamed("${anchor.name}Kt", anchor.classLoader))
    }

    /**
     * The file-facade lookup, as its own function so the control below exercises the same code.
     *
     * `initialize = false` deliberately: this must read a facade's fields without running a static
     * initializer that — in exactly the scenario being hunted — would construct the shared
     * `Signature` the test exists to report. And only [ClassNotFoundException] is caught, which is
     * the narrow "no such facade" answer; a facade that exists but fails to link raises a
     * [LinkageError] and must stay loud rather than be absorbed into a green run.
     */
    private fun facadeNamed(binaryName: String, loader: ClassLoader?): Class<*>? = try {
        Class.forName(binaryName, false, loader)
    } catch (_: ClassNotFoundException) {
        null
    }

    /**
     * The facade branch, proved in both directions against a facade that genuinely exists.
     *
     * `Redaction.kt` is all top-level declarations, so this module really does compile a
     * `RedactionKt` — which makes it the positive control [stateHolders] cannot get from `Utils`
     * itself. Without this, a [facadeNamed] that could never resolve anything under Robolectric's
     * sandbox loader would look identical to "`Utils.kt` has no facade", and the file-level hoist
     * would be undetectable with the suite green.
     */
    @Test
    fun `the facade lookup finds a facade that exists`() {
        val loader = Utils::class.java.classLoader

        assertNotNull(
            "RedactionKt is compiled into this module, so the facade lookup must resolve it. If " +
                "this is null the lookup is broken and the file-level hoist described in " +
                "stateHolders' KDoc would pass every structural assertion",
            facadeNamed("dev.eryalabs.lim.RedactionKt", loader),
        )

        assertNull(
            "and it must answer null — not throw — for a facade that does not exist, which is " +
                "the answer Utils.kt itself produces today",
            facadeNamed("dev.eryalabs.lim.NoSuchFacadeKt", loader),
        )
    }

    /** Fields across every holder, each qualified by the class that declares it. */
    private fun statefulFieldsAcross(anchor: Class<*>): List<Field> =
        stateHolders(anchor).flatMap { statefulFields(it) }

    private fun Field.qualifiedName(): String = "${declaringClass.simpleName}.$name"

    /** The fields whose declared type is one [forbiddenFieldTypes] names, rendered for a message. */
    private fun offendingFields(anchor: Class<*>): List<String> =
        statefulFieldsAcross(anchor)
            .filter { field ->
                forbiddenFieldTypes.any { forbidden -> forbidden.isAssignableFrom(field.type) }
            }
            .map { "${it.qualifiedName()}: ${it.type.name}" }
            .sorted()

    /**
     * The whole structural apparatus, proved to catch what it exists to catch before it is trusted
     * about [Utils] — because every assertion it feeds is of the form "found nothing", and those
     * pass just as happily when the machinery is broken as when the code is clean.
     *
     * Three things are checked at once against contents that are known: the filter keeps a
     * reference field and drops the `String` and `Int` constants; the walk descends into a nested
     * object, which is the evasion [stateHolders] exists for; and the deny-list actually fires,
     * naming both offenders. Without this last part, `no field … carries per-operation state`
     * would still pass with `forbiddenFieldTypes` emptied or with its assignability test written
     * backwards.
     */
    private object FilterProbe {
        val PROBE_SIGNATURE: Signature = Signature.getInstance("SHA256withRSA")
        const val PROBE_NAME = "probe"
        const val PROBE_WIDTH = 4

        object Nested {
            val NESTED_DIGEST: MessageDigest = MessageDigest.getInstance("SHA-256")
        }
    }

    @Test
    fun `the field machinery keeps shared state, descends, and names offenders`() {
        assertEquals(
            "statefulFields must keep the reference fields and the object singletons and drop " +
                "the String and Int constants, and the walk must reach the nested object — " +
                "otherwise every assertion it feeds is vacuous",
            listOf(
                "FilterProbe.INSTANCE",
                "FilterProbe.PROBE_SIGNATURE",
                "Nested.INSTANCE",
                "Nested.NESTED_DIGEST",
            ),
            statefulFieldsAcross(FilterProbe::class.java).map { it.qualifiedName() }.sorted(),
        )

        assertEquals(
            "the deny-list must actually fire — both of these types are on it",
            listOf(
                "FilterProbe.PROBE_SIGNATURE: java.security.Signature",
                "Nested.NESTED_DIGEST: java.security.MessageDigest",
            ),
            offendingFields(FilterProbe::class.java),
        )
    }

    /**
     * The snapshot. A new field anywhere in `Utils.kt` fails here, naming itself.
     *
     * Failing is the intended behaviour, not an inconvenience: the question a reader has to answer
     * is "can two threads be inside a function while this field is in play", and the only way to
     * make them answer it is to put the name in front of them. Update the set *and* its KDoc above
     * once the answer is yes-this-is-safe.
     */
    @Test
    fun `Utils declares no standing state beyond the snapshot`() {
        val actual = statefulFieldsAcross(Utils::class.java).map { it.qualifiedName() }.sorted()

        assertEquals(
            "the non-constant fields of the Utils compilation unit have moved. Utils is " +
                "thread-safe by construction because every call builds its own Gson, KeyFactory " +
                "and Signature; a new field here is either immutable shared data (record it in " +
                "expectedStatefulFields and say why in its KDoc) or per-operation state, which " +
                "is a correctness bug — see this file's class KDoc",
            expectedStatefulFields.sorted(),
            actual,
        )
    }

    /**
     * And the type assertion, over whatever fields exist rather than over the snapshot — so it
     * still applies on the run where somebody has just added a field and not yet reached the
     * assertion above.
     */
    @Test
    fun `no field of Utils has a type that carries per-operation state`() {
        // Non-vacuity: a walk that returned nothing would make the scan below a no-op, and
        // `the field machinery …` proves the scan only against the probe.
        assertTrue(
            "precondition: there are fields to type-check",
            statefulFieldsAcross(Utils::class.java).isNotEmpty(),
        )

        assertEquals(
            "these fields of Utils have a type that is not thread-safe and carries " +
                "per-operation state. Two concurrent calls sharing one of these interleave their " +
                "init/update/verify and can return each other's answers — build it per call " +
                "instead. Gson is NOT on this list and may be hoisted; see forbiddenFieldTypes",
            emptyList<String>(),
            offendingFields(Utils::class.java),
        )
    }

    // ─────────────────────────────────────────────────────────────────────
    // (b) Behavioural: 8 threads, 1,600 tasks, every answer pinned
    // ─────────────────────────────────────────────────────────────────────

    companion object {
        /** Wide enough that the operations genuinely overlap; fixed so a failure reproduces. */
        private const val THREADS = 8

        /** Per worker. 8 × 200 = 1,600 tasks, 200 per operation. */
        private const val TASKS_PER_THREAD = 200

        /** Generous: the whole arm finishes in a couple of seconds. A hang must fail, not wait. */
        private const val TIMEOUT_SECONDS = 120L

        private lateinit var keyPair: KeyPair
        private lateinit var otherKeyPair: KeyPair

        /** 2048-bit RSA generation is slow (~100ms each); do it once for the whole class. */
        @JvmStatic
        @BeforeClass
        fun generateKeys() {
            val gen = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }
            keyPair = gen.generateKeyPair()
            otherKeyPair = gen.generateKeyPair()
        }
    }

    private val publicKeyBase64: String
        get() = Base64.encodeToString(keyPair.public.encoded, Base64.DEFAULT)

    private val otherPublicKeyBase64: String
        get() = Base64.encodeToString(otherKeyPair.public.encoded, Base64.DEFAULT)

    private fun sign(key: PrivateKey, data: ByteArray): ByteArray =
        Signature.getInstance("SHA256withRSA").run {
            initSign(key)
            update(data)
            sign()
        }

    /** Inside the rotation window below, away from either boundary. No clock is read. */
    private val duringWindow = 1_770_000_300_000L

    /**
     * One operation under test: a name for the failure message and a call that must return the
     * same thing on any thread. The call closes over fixtures built on the main thread and
     * mutates nothing, so the only shared state in play is whatever [Utils] itself holds — which
     * is the property being measured.
     */
    private class Operation(val name: String, val call: () -> Any?)

    /**
     * The eight operations, chosen to cover every kind of shared state the library could acquire:
     * the two JCE-backed verifiers, the Gson-backed decoders, the hand-rolled envelope parser and
     * the `Intent` reader. Each gets a positive case or a negative one so that an implementation
     * which answered uniformly could not pass — see the polarity assertions in the test.
     */
    private fun operations(): List<Operation> {
        val storedKey = publicKeyBase64
        val replacementKey = otherPublicKeyBase64

        val nonce = "challenge-nonce-1770000000".toByteArray(Charsets.UTF_8)
        val genuineSignature = sign(keyPair.private, nonce)
        // One flipped bit in the last byte: still a well-formed signature of the right length,
        // which is what makes it a test of the verifier rather than of its length check.
        val tamperedSignature = genuineSignature.copyOf().also {
            it[it.size - 1] = (it[it.size - 1].toInt() xor 0x01).toByte()
        }

        val rotation = RotationStatement(
            oldPublicKey = storedKey,
            newPublicKey = replacementKey,
            statementId = "rot-0001",
            issuedAtMillis = 1_770_000_000_000L,
            expiresAtMillis = 1_770_000_600_000L,
        )
        val rotationSignature = sign(keyPair.private, Utils.rotationStatementBytes(rotation))
        // Signed by a key the service does not store: genuine bytes, wrong signer.
        val wrongKeySignature = sign(otherKeyPair.private, Utils.rotationStatementBytes(rotation))
        val envelope = Utils.encodeRotationStatement(rotation, rotationSignature)

        val fieldsJson = Utils.encodeFields(
            mapOf(
                "email" to TypedField("ada@example.com", FieldType.EMAIL),
                "age" to TypedField("36", FieldType.INTEGER),
            ),
        )
        val entryJson =
            """{"id":"profile-1","publicKey":"$storedKey","fields":""" +
                """{"email":{"value":"ada@example.com","type":"Email"}}}"""

        val intent = Intent(Utils.shareDataAction()).apply {
            putExtra(Utils.EXTRA_PUBLIC_KEY, storedKey)
            putExtra(Utils.EXTRA_NONCE, Base64.encodeToString(nonce, Base64.NO_WRAP))
            putExtra(Utils.EXTRA_SHARE_REQUEST_CODE, "req-1")
        }

        return listOf(
            Operation("verifySignature/genuine") {
                Utils.verifySignature(storedKey, nonce, genuineSignature)
            },
            Operation("verifySignature/tampered") {
                Utils.verifySignature(storedKey, nonce, tamperedSignature)
            },
            Operation("verifyRotationStatement/genuine") {
                Utils.verifyRotationStatement(rotation, rotationSignature, storedKey, duringWindow)
            },
            Operation("verifyRotationStatement/wrongKey") {
                Utils.verifyRotationStatement(rotation, wrongKeySignature, storedKey, duringWindow)
            },
            Operation("parseSignedStatement/genuine") { Utils.parseSignedStatement(envelope) },
            Operation("decodeFields") { Utils.decodeFields(fieldsJson) },
            Operation("decodeEntry") { Utils.decodeEntry(entryJson) },
            Operation("describeIntent") { Utils.describeIntent(intent) },
        )
    }

    /**
     * What one task reports. Carries its thread so the pool's real width can be measured — by
     * name rather than by id, since `Thread.id` is deprecated from JDK 19 and a fixed pool names
     * its workers distinctly (`pool-N-thread-M`) anyway.
     */
    private class Outcome(
        val operation: Int,
        val thread: String,
        val answer: Any?,
        val failure: Throwable?,
    )

    @Test
    fun `every operation returns the single-threaded answer under eight concurrent threads`() {
        val operations = operations()
        assertEquals("the task fixes 8 operations and 200 tasks each", 8, operations.size)
        // Retuning either constant to a non-multiple would break the exact per-operation count
        // further down for a reason that has nothing to do with thread safety. Said here so the
        // failure names the cause.
        assertEquals(
            "TASKS_PER_THREAD must be a multiple of the operation count",
            0,
            TASKS_PER_THREAD % operations.size,
        )

        // ── The baseline, on the main thread, before any pool exists ──
        val expected = operations.map { it.call() }

        // ── Non-vacuity, before anything is asserted about the pool ──
        //
        // Without these, an implementation that refused everything — or one that said `true` to
        // everything — would agree with its own baseline on all 1,600 tasks and pass. The answers
        // are pinned as *values* for that reason, not merely as "the same as the baseline".
        assertEquals("verifySignature must accept the genuine signature", true, expected[0])
        assertEquals("verifySignature must reject the tampered one", false, expected[1])
        assertEquals(StatementVerdict.VALID, expected[2])
        assertEquals(StatementVerdict.SIGNATURE_INVALID, expected[3])
        assertTrue(
            "the envelope must parse to a Rotate: ${expected[4]}",
            expected[4] is SignedStatement.Rotate,
        )
        assertEquals(2, (expected[5] as Map<*, *>).size)
        assertEquals("profile-1", (expected[6] as Entry).id)
        assertTrue("describeIntent must say something", (expected[7] as String).isNotBlank())
        assertTrue(
            "the baseline must contain both a positive and a negative answer",
            expected.contains(true) && expected.contains(false),
        )

        // ── The run ──
        //
        // A start gate rather than a stagger: all eight workers block until the last one is ready,
        // so the first tasks are genuinely simultaneous instead of racing the pool's own ramp-up.
        val ready = CountDownLatch(THREADS)
        val go = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(THREADS)
        val outcomes = try {
            // `submit` rather than `invokeAll`: the latter blocks until every task finishes, so
            // the gate below would never be opened and the whole arm would deadlock.
            val futures = (0 until THREADS).map { worker ->
                pool.submit(
                    Callable {
                        ready.countDown()
                        go.await()
                        (0 until TASKS_PER_THREAD).map { step ->
                            // The operation comes from the task's own global index: no clock, no
                            // randomness, so a failure reproduces. Threads drift apart as the
                            // operations differ in cost, which is what produces both
                            // same-operation and cross-operation overlap.
                            val index = worker * TASKS_PER_THREAD + step
                            val operation = index % operations.size
                            val thread = Thread.currentThread().name
                            try {
                                Outcome(operation, thread, operations[operation].call(), null)
                            } catch (t: Throwable) {
                                Outcome(operation, thread, null, t)
                            }
                        }
                    },
                )
            }
            assertTrue(
                "all $THREADS workers must reach the start gate",
                ready.await(TIMEOUT_SECONDS, TimeUnit.SECONDS),
            )
            go.countDown()
            futures.flatMap { it.get(TIMEOUT_SECONDS, TimeUnit.SECONDS) }
        } finally {
            pool.shutdownNow()
        }

        // ── Non-vacuity of the run itself ──
        assertEquals(
            "all ${THREADS * TASKS_PER_THREAD} tasks must report in — a pool that silently ran " +
                "nothing passes every assertion below",
            THREADS * TASKS_PER_THREAD,
            outcomes.size,
        )
        val perOperation = operations.indices.associateWith { op ->
            outcomes.count { it.operation == op }
        }
        assertEquals(
            "every operation must have run exactly $TASKS_PER_THREAD times",
            operations.indices.associateWith { TASKS_PER_THREAD },
            perOperation,
        )
        val threadsObserved = outcomes.map { it.thread }.distinct().size
        assertTrue(
            "the pool must really be wider than one thread, otherwise this arm measures nothing " +
                "— observed $threadsObserved",
            threadsObserved > 1,
        )

        // ── The claim ──
        val threw = outcomes.filter { it.failure != null }
            .map { "${operations[it.operation].name}: ${it.failure}" }
            .distinct()
            .sorted()
        assertEquals("no task may throw", emptyList<String>(), threw)

        val disagreed = outcomes.filter { it.answer != expected[it.operation] }
            .map { "${operations[it.operation].name}: got ${it.answer}, expected ${expected[it.operation]}" }
            .distinct()
            .sorted()
        assertEquals(
            "a concurrent call returned something other than the single-threaded answer. If one " +
                "of the verifiers is in this list, two operations interleaved inside shared JCE " +
                "state and the library has been answering for the wrong caller",
            emptyList<String>(),
            disagreed,
        )

        println(
            "THREADSAFETY tasks=${outcomes.size} threadsObserved=$threadsObserved " +
                "operations=${operations.size} perOperation=$TASKS_PER_THREAD",
        )
    }

    /**
     * The one property with teeth that a per-call-instance library could still get wrong:
     * [Utils.generateNonce] draws from a `SecureRandom` it creates per call, and 200 of those
     * created in the same instant must still not collide. A nonce reused across two logins is a
     * replayable challenge.
     *
     * The real entropy source and the real clock, deliberately — the injected ones are pinned in
     * `NonceTest`, and what is being measured here is the un-pinned default under contention.
     */
    @Test
    fun `two hundred concurrent nonces are two hundred distinct nonces`() {
        val count = 200
        val go = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(THREADS)
        val nonces = try {
            // Submitted first, released together: 200 tasks over 8 threads means most of them are
            // already queued when the gate opens, so the draws genuinely contend.
            val futures = (0 until count).map {
                pool.submit(
                    Callable {
                        go.await()
                        Utils.generateNonce()
                    },
                )
            }
            go.countDown()
            futures.map { it.get(TIMEOUT_SECONDS, TimeUnit.SECONDS) }
        } finally {
            pool.shutdownNow()
        }

        assertEquals("all $count nonces must be generated", count, nonces.size)
        nonces.forEach { assertNotNull("generateNonce returned null", it) }
        assertEquals(
            "$count concurrent generateNonce() calls must yield $count distinct nonces — a " +
                "collision means two challenges share bytes and one signature answers both",
            count,
            nonces.map { it.joinToString("") { byte -> "%02x".format(byte) } }.toSet().size,
        )
    }
}
