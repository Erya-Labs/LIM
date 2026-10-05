package dev.eryalabs.lim;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import android.app.Application;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Bundle;
import android.util.Base64;

import androidx.test.core.app.ApplicationProvider;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.Shadows;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowPackageManager;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeSet;

/**
 * The library as a Java integrator writes it.
 *
 * LIM ships to Android apps and a large share of them are written in Java, where Kotlin's
 * default arguments simply do not exist: before {@code @JvmOverloads} (T21) every single one of
 * the calls below was a compile error, and a Java caller had to spell out {@code targetPackage},
 * {@code random}, {@code now} and {@code nonceFormat} by hand on every call. So this file is a
 * proof rather than an assertion — <em>that it compiles at all</em> is half of what it checks.
 *
 * It is deliberately Java and deliberately in this package. A Kotlin test cannot see the
 * generated overloads at all: Kotlin resolves the full-arity function and fills the defaults in
 * at the call site, so the shorter JVM methods this file exercises are invisible from there and
 * only {@code PublicApiAuditTest}'s signature snapshot would notice them.
 *
 * The other half is behaviour. Every call asserts what it got back, and the intent builders
 * assert their short form produces <em>the same intent</em> as the explicit full-arity call —
 * which is what proves the generated overload forwards the real default rather than something
 * that merely compiles.
 *
 * {@code Utils.INSTANCE} is how Java reaches a Kotlin {@code object}, and it stays that way on
 * purpose: {@code @JvmStatic} on a named object <em>replaces</em> the instance method with a
 * static one, so every already-compiled consumer's {@code invokevirtual} would become a
 * {@code NoSuchMethodError}. That is recorded under "Blocked on human" and enforced by
 * {@code PublicApiAuditTest}'s "every published method on Utils is an instance method".
 */
@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class JavaInteropTest {

    private static final String REQUEST_CODE = "req-1";
    private static final String OTHER_VAULT = "dev.other.vault";

    private final Context context = ApplicationProvider.getApplicationContext();

    private Entry entry() {
        Map<String, TypedField> fields = new LinkedHashMap<>();
        fields.put("name", new TypedField("Ada", FieldType.STRING));
        fields.put("email", new TypedField("ada@example.com", FieldType.EMAIL));
        return new Entry("profile-1", fields, "PUBLIC-KEY-BASE64");
    }

    /**
     * Every extra on an intent, keyed and ordered, so two intents can be compared as a whole
     * rather than extra by extra — an omitted key is exactly the failure this comparison exists
     * to catch, and naming the keys here would hide it.
     *
     * Read through {@code getString} rather than the untyped {@code Bundle.get}, which is
     * deprecated. Every extra this library puts on an intent is a {@link String}, and the
     * caller asserts that below rather than trusting it: a non-String extra would read as
     * {@code null} here, so an unasserted null would make the whole comparison blind.
     */
    private static Map<String, String> extrasOf(Intent intent) {
        Map<String, String> out = new LinkedHashMap<>();
        Bundle extras = intent.getExtras();
        if (extras == null) {
            return out;
        }
        for (String key : new TreeSet<>(extras.keySet())) {
            out.put(key, extras.getString(key));
        }
        return out;
    }

    private static void assertSameIntent(String what, Intent expected, Intent actual) {
        assertEquals(what + ": action", expected.getAction(), actual.getAction());
        assertEquals(what + ": package", expected.getPackage(), actual.getPackage());
        assertEquals(what + ": flags", expected.getFlags(), actual.getFlags());

        Map<String, String> expectedExtras = extrasOf(expected);
        assertFalse(what + ": the full-arity intent must carry extras at all", expectedExtras.isEmpty());
        assertFalse(
                what + ": an extra read as null, so it was not a String and the comparison is blind",
                expectedExtras.containsValue(null));
        assertEquals(what + ": extras", expectedExtras, extrasOf(actual));
    }

    // ── Action strings ───────────────────────────────────────────────────

    @Test
    public void actionHelpersAreCallableWithNoArguments() {
        assertEquals(
                "com.github.adaydreamaway.endeavor.ACTION_SHARE_DATA",
                Utils.INSTANCE.shareDataAction());
        assertEquals(
                "com.github.adaydreamaway.endeavor.ACTION_SIGN_CHALLENGE",
                Utils.INSTANCE.signChallengeAction());

        // The full arity is still there, which is what makes this additive rather than a
        // replacement — a consumer compiled against 1.0.0 calls exactly this method.
        assertEquals(
                Utils.INSTANCE.shareDataAction(Utils.DEFAULT_ENDEAVOR_PACKAGE),
                Utils.INSTANCE.shareDataAction());
        assertEquals("dev.other.vault.ACTION_SHARE_DATA", Utils.INSTANCE.shareDataAction(OTHER_VAULT));
        assertEquals(
                "dev.other.vault.ACTION_SIGN_CHALLENGE",
                Utils.INSTANCE.signChallengeAction(OTHER_VAULT));
    }

    // ── Intent builders ──────────────────────────────────────────────────

    @Test
    public void shareIntentIsCallableWithoutATargetPackage() {
        Entry entry = entry();
        Intent shortForm = Utils.INSTANCE.createShareIntent(context, entry);
        Intent fullArity =
                Utils.INSTANCE.createShareIntent(context, entry, Utils.DEFAULT_ENDEAVOR_PACKAGE);

        assertSameIntent("createShareIntent", fullArity, shortForm);
        assertEquals(Utils.DEFAULT_ENDEAVOR_PACKAGE, shortForm.getPackage());
        assertTrue(
                "the entry must travel as JSON",
                shortForm.getStringExtra(Utils.EXTRA_ENTRY_JSON).contains("profile-1"));
        assertEquals("2", shortForm.getStringExtra(Utils.EXTRA_PROTOCOL_VERSION));
    }

    /**
     * The one defaulted function in {@code Utils} that cannot carry {@code @JvmOverloads}: its
     * generated three-argument overload would collide with the {@code targetPackage} one's own
     * JVM signature. So a Java caller still spells the package out, and this records that the
     * arity it needs is present and works.
     */
    @Test
    public void theRequestCodeShareOverloadStillNeedsItsTargetPackage() {
        Entry entry = entry();
        Intent tagged = Utils.INSTANCE.createShareIntent(
                context, entry, REQUEST_CODE, Utils.DEFAULT_ENDEAVOR_PACKAGE);

        assertEquals(REQUEST_CODE, tagged.getStringExtra(Utils.EXTRA_SHARE_REQUEST_CODE));
        assertEquals(Utils.DEFAULT_ENDEAVOR_PACKAGE, tagged.getPackage());
        assertTrue(
                "a tagged share is still a share",
                Utils.INSTANCE.parseShareRequest(tagged) != null);
    }

    @Test
    public void queryIntentIsCallableWithoutATargetPackage() {
        Intent shortForm = Utils.INSTANCE.createQueryIntent(context, "K-PUBLIC", REQUEST_CODE);
        Intent fullArity = Utils.INSTANCE.createQueryIntent(
                context, "K-PUBLIC", REQUEST_CODE, Utils.DEFAULT_ENDEAVOR_PACKAGE);

        assertSameIntent("createQueryIntent", fullArity, shortForm);
        QueryRequest parsed = Utils.INSTANCE.parseQueryRequest(shortForm);
        assertEquals("K-PUBLIC", parsed.getPublicKey());
        assertEquals(REQUEST_CODE, parsed.getRequestCode());
        assertEquals(Integer.valueOf(Utils.PROTOCOL_VERSION), parsed.getProtocolVersion());
    }

    @Test
    public void signChallengeIntentIsCallableAtBothShortenedArities() {
        byte[] nonce = Utils.INSTANCE.generateNonce();

        Intent fullArity = Utils.INSTANCE.createSignChallengeIntent(
                context,
                "K-PUBLIC",
                nonce,
                REQUEST_CODE,
                Utils.DEFAULT_ENDEAVOR_PACKAGE,
                null);
        Intent withoutFormat = Utils.INSTANCE.createSignChallengeIntent(
                context, "K-PUBLIC", nonce, REQUEST_CODE, Utils.DEFAULT_ENDEAVOR_PACKAGE);
        Intent shortest =
                Utils.INSTANCE.createSignChallengeIntent(context, "K-PUBLIC", nonce, REQUEST_CODE);

        assertSameIntent("createSignChallengeIntent, 5-arg", fullArity, withoutFormat);
        assertSameIntent("createSignChallengeIntent, 4-arg", fullArity, shortest);

        // The default is `null`, which attaches nothing — the negative control that the shortest
        // form does not quietly declare a format the nonce may not have.
        assertFalse(
                "the shortest form must declare no nonce format",
                shortest.hasExtra(Utils.EXTRA_NONCE_FORMAT));

        // A Java caller that does want to declare it still can, at the full arity.
        Intent declared = Utils.INSTANCE.createSignChallengeIntent(
                context,
                "K-PUBLIC",
                nonce,
                REQUEST_CODE,
                Utils.DEFAULT_ENDEAVOR_PACKAGE,
                Utils.NONCE_FORMAT_TIMESTAMPED);
        assertEquals("lim-ts1", declared.getStringExtra(Utils.EXTRA_NONCE_FORMAT));

        SignChallengeRequest parsed = Utils.INSTANCE.parseSignChallengeRequest(shortest);
        assertEquals("K-PUBLIC", parsed.getPublicKey());
        assertArrayEqualsBytes(nonce, parsed.getNonce());
    }

    /**
     * Both branches, in one test and in this order, because the arity is only half the point.
     * An assertion that the two-argument form returns {@code false} with no vault installed
     * would pass against a {@code shareEntry} hardcoded to {@code false}; registering the vault
     * and watching the same call dispatch is what makes it a behavioural test of the generated
     * overload rather than of nothing.
     */
    @Test
    public void shareEntryIsCallableWithoutATargetPackage() {
        Entry entry = entry();

        // No activity handles the share action yet, so the fire-and-forget path reports the
        // failure T4 added the return value for.
        assertFalse(
                "with no vault reachable, the share went nowhere",
                Utils.INSTANCE.shareEntry(context, entry));
        assertNull("and nothing must have been started", nextStartedActivity());

        installVault();

        assertTrue(
                "the two-argument form must dispatch to the default vault package",
                Utils.INSTANCE.shareEntry(context, entry));
        Intent started = nextStartedActivity();
        assertNotNull("the intent must actually be dispatched", started);
        assertEquals(Utils.INSTANCE.shareDataAction(), started.getAction());
        assertEquals(Utils.DEFAULT_ENDEAVOR_PACKAGE, started.getPackage());
        assertTrue(
                "the entry must travel as JSON",
                started.getStringExtra(Utils.EXTRA_ENTRY_JSON).contains("profile-1"));
    }

    /**
     * Register an activity handling the share action for the default vault package.
     * {@code CATEGORY_DEFAULT} is not decoration: {@code Intent.resolveActivity} matches with
     * {@code MATCH_DEFAULT_ONLY}, so without it the lookup finds nothing — the same filter a
     * real vault's manifest must carry. Mirrors {@code ShareEntryTest.installVault}.
     */
    private void installVault() {
        String vault = Utils.DEFAULT_ENDEAVOR_PACKAGE;
        ComponentName component = new ComponentName(vault, vault + ".ShareActivity");
        ShadowPackageManager packageManager = Shadows.shadowOf(context.getPackageManager());
        packageManager.addActivityIfNotPresent(component);
        IntentFilter filter = new IntentFilter(Utils.INSTANCE.shareDataAction());
        filter.addCategory(Intent.CATEGORY_DEFAULT);
        packageManager.addIntentFilterForActivity(component, filter);
    }

    private Intent nextStartedActivity() {
        return Shadows.shadowOf((Application) ApplicationProvider.getApplicationContext())
                .getNextStartedActivity();
    }

    // ── Nonces ───────────────────────────────────────────────────────────

    @Test
    public void nonceHelpersAreCallableWithoutAClockOrARandom() {
        byte[] nonce = Utils.INSTANCE.generateNonce();
        assertEquals("8 bytes of timestamp plus 32 random", 40, nonce.length);

        byte[] seeded = Utils.INSTANCE.generateNonce(new SecureRandom());
        assertEquals(40, seeded.length);
        assertNotEquals(
                "two nonces must not be the same bytes",
                Base64.encodeToString(nonce, Base64.NO_WRAP),
                Base64.encodeToString(seeded, Base64.NO_WRAP));

        // Two arguments, no clock: the nonce was just minted, so it is fresh within a minute and
        // stale against a window of zero milliseconds only if a millisecond has passed — which is
        // not something to assert on a real clock. A negative window never passes, and that is.
        assertTrue(Utils.INSTANCE.isNonceFresh(nonce, 60_000L));
        assertFalse(
                "a negative window can never be satisfied",
                Utils.INSTANCE.isNonceFresh(nonce, -1L));

        // The full arity is still present and still pins the boundary.
        long pinned = 1_770_000_000_000L;
        byte[] atPinnedClock = Utils.INSTANCE.generateNonce(new SecureRandom(), pinned);
        assertEquals(Long.valueOf(pinned), Utils.INSTANCE.nonceTimestamp(atPinnedClock));
        assertTrue(Utils.INSTANCE.isNonceFresh(atPinnedClock, 1_000L, pinned + 1_000L));
        assertFalse(Utils.INSTANCE.isNonceFresh(atPinnedClock, 1_000L, pinned + 1_001L));
    }

    // ── Statement verification ───────────────────────────────────────────

    @Test
    public void rotationVerificationIsCallableWithoutAClock() throws Exception {
        KeyPair oldKey = rsaKeyPair();
        KeyPair newKey = rsaKeyPair();
        String storedPublicKey = Base64.encodeToString(oldKey.getPublic().getEncoded(), Base64.DEFAULT);
        String replacement = Base64.encodeToString(newKey.getPublic().getEncoded(), Base64.DEFAULT);

        // Open at both ends, because this call takes the real clock: the generated overload's
        // whole content is that it passes System.currentTimeMillis() for `now`, and a window
        // that excluded the present would make a VALID verdict prove nothing about it.
        RotationStatement statement =
                new RotationStatement(storedPublicKey, replacement, "rot-1", 0L, Long.MAX_VALUE);

        byte[] signature = sign(oldKey, statement);

        assertEquals(
                StatementVerdict.VALID,
                Utils.INSTANCE.verifyRotationStatement(statement, signature, storedPublicKey));

        // Negative control: the three-argument form is not a weaker check than the four. A
        // statement that has not opened yet is still refused.
        RotationStatement future = new RotationStatement(
                storedPublicKey, replacement, "rot-2", Long.MAX_VALUE - 1L, Long.MAX_VALUE);
        assertEquals(
                StatementVerdict.NOT_YET_VALID,
                Utils.INSTANCE.verifyRotationStatement(future, sign(oldKey, future), storedPublicKey));

        // And the control that pins the generated overload's *entire content* — that it forwards
        // System.currentTimeMillis() for `now`. The two assertions above hold for any clock at
        // all, including a `now` of 0; this one is EXPIRED only on a clock past 1970.
        RotationStatement longExpired =
                new RotationStatement(storedPublicKey, replacement, "rot-3", 0L, 1_000L);
        assertEquals(
                StatementVerdict.EXPIRED,
                Utils.INSTANCE.verifyRotationStatement(
                        longExpired, sign(oldKey, longExpired), storedPublicKey));
        assertEquals(
                "...and the full arity still takes the caller's clock, which is the difference",
                StatementVerdict.VALID,
                Utils.INSTANCE.verifyRotationStatement(
                        longExpired, sign(oldKey, longExpired), storedPublicKey, 500L));

        // And the full arity is still there, pinning the boundary the generated one cannot.
        assertEquals(
                StatementVerdict.VALID,
                Utils.INSTANCE.verifyRotationStatement(statement, signature, storedPublicKey, 0L));
    }

    /** Signs a statement's canonical pre-image, the way the vault's Keystore would. */
    private static byte[] sign(KeyPair keyPair, RotationStatement statement) throws Exception {
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(keyPair.getPrivate());
        signer.update(Utils.INSTANCE.rotationStatementBytes(statement));
        return signer.sign();
    }

    private static KeyPair rsaKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static void assertArrayEqualsBytes(byte[] expected, byte[] actual) {
        assertEquals(
                Base64.encodeToString(expected, Base64.NO_WRAP),
                Base64.encodeToString(actual, Base64.NO_WRAP));
    }
}
