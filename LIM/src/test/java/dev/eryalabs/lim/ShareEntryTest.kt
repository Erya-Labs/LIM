package dev.eryalabs.lim

import android.content.ComponentName
import android.content.Intent
import androidx.test.core.app.ApplicationProvider
import com.google.gson.Gson
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/**
 * `shareEntry` is the fire-and-forget path, so its only failure mode is silence: when no vault
 * is installed the intent resolves to nothing and the user taps "Sign up with Erya" to no
 * effect. The boolean return is the client's one chance to notice, so both branches are pinned
 * here against a package manager that really does and really does not know the vault.
 *
 * The flags are pinned too. `shareEntry` and [Utils.createShareIntent] deliberately differ —
 * this path needs `NEW_TASK`, the result-bearing path is broken by it — and asserting both
 * flags on both paths is what stops the two being quietly conflated into one.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ShareEntryTest {

    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()
    private val vault = Utils.DEFAULT_ENDEAVOR_PACKAGE

    private val entry = Entry(
        id = "profile-1",
        fields = linkedMapOf(
            "name" to TypedField("Ada", FieldType.STRING),
            "age" to TypedField("36", FieldType.INTEGER),
        ),
        publicKey = "PUBLIC-KEY-BASE64",
    )

    /**
     * Register an activity that handles the share action for [targetPackage].
     *
     * `CATEGORY_DEFAULT` is not decoration: `Intent.resolveActivity` matches with
     * `MATCH_DEFAULT_ONLY`, and a real vault's filter must carry it too or `startActivity`
     * would never reach it either.
     */
    private fun installVault(targetPackage: String = vault) {
        val component = ComponentName(targetPackage, "$targetPackage.ShareActivity")
        shadowOf(context.packageManager).addActivityIfNotPresent(component)
        shadowOf(context.packageManager).addIntentFilterForActivity(
            component,
            android.content.IntentFilter(Utils.shareDataAction(targetPackage)).apply {
                addCategory(Intent.CATEGORY_DEFAULT)
            },
        )
    }

    private fun startedIntent(): Intent? =
        shadowOf(ApplicationProvider.getApplicationContext<android.app.Application>())
            .nextStartedActivity

    // ── With a vault installed ───────────────────────────────────────────

    @Test
    fun `shareEntry returns true and starts the intent when a vault handles it`() {
        installVault()

        assertTrue(Utils.shareEntry(context, entry))

        val started = startedIntent()
        assertNotNull("the intent must actually be dispatched", started)
        assertEquals("com.github.adaydreamaway.endeavor.ACTION_SHARE_DATA", started!!.action)
        assertEquals(vault, started.`package`)

        val decoded = Gson().fromJson(started.getStringExtra("extra_entry_json"), Entry::class.java)
        assertEquals(entry.id, decoded.id)
        assertEquals(entry.publicKey, decoded.publicKey)
        assertEquals("Ada", decoded.fields["name"]?.value)
    }

    /**
     * The fire-and-forget path genuinely needs `NEW_TASK`: there is no result to deliver, and
     * a non-Activity context cannot start an activity without it. `createShareIntent` must
     * *not* set it, and that asymmetry is the whole reason both are asserted.
     */
    @Test
    fun `the dispatched intent sets both NEW_TASK and CLEAR_TOP`() {
        installVault()
        Utils.shareEntry(context, entry)

        val flags = startedIntent()!!.flags
        assertTrue(
            "NEW_TASK must be set — this path has no result to deliver",
            flags and Intent.FLAG_ACTIVITY_NEW_TASK != 0,
        )
        assertTrue(
            "CLEAR_TOP must be set — deliver to an existing vault via onNewIntent",
            flags and Intent.FLAG_ACTIVITY_CLEAR_TOP != 0,
        )
    }

    /** The two paths must not be conflated: NEW_TASK on the result-bearing one breaks it. */
    @Test
    fun `createShareIntent still omits NEW_TASK after shareEntry has added it`() {
        installVault()
        Utils.shareEntry(context, entry)

        val flags = Utils.createShareIntent(context, entry).flags
        assertTrue(flags and Intent.FLAG_ACTIVITY_CLEAR_TOP != 0)
        assertFalse(
            "NEW_TASK must NOT leak back onto the result-bearing path",
            flags and Intent.FLAG_ACTIVITY_NEW_TASK != 0,
        )
    }

    @Test
    fun `shareEntry honours a non-default target package`() {
        val other = "dev.eryalabs.othervault"
        installVault(other)

        assertTrue(Utils.shareEntry(context, entry, targetPackage = other))

        val started = startedIntent()!!
        assertEquals(other, started.`package`)
        assertEquals("$other.ACTION_SHARE_DATA", started.action)
    }

    // ── With no vault installed ──────────────────────────────────────────

    @Test
    fun `shareEntry returns false and starts nothing when no vault handles it`() {
        assertFalse(Utils.shareEntry(context, entry))
        assertNull("nothing may be dispatched when nothing can receive it", startedIntent())
    }

    /**
     * Registering *some other* vault must not make the default one look installed. Without
     * this, a package-manager stub that matches on action alone would let the true branch pass
     * for the wrong reason.
     */
    @Test
    fun `a different vault does not satisfy a share aimed at the default one`() {
        installVault("dev.eryalabs.othervault")

        assertFalse(Utils.shareEntry(context, entry))
        assertNull(startedIntent())
    }

    @Test
    fun `an empty target package resolves to nothing rather than throwing`() {
        installVault()

        assertFalse(Utils.shareEntry(context, entry, targetPackage = ""))
        assertNull(startedIntent())
    }

    // ── When resolve and start disagree ──────────────────────────────────

    /**
     * A context whose `startActivity` fails the way the system can, after a clean resolve.
     * It counts attempts so a test can prove it got past the resolve check rather than
     * returning early — otherwise the false-on-vanish test below would be indistinguishable
     * from the no-vault-installed test and would pass with the `try/catch` deleted.
     */
    private class FailingContext(
        base: android.content.Context,
        private val failure: RuntimeException,
    ) : android.content.ContextWrapper(base) {
        var attempts = 0
            private set

        override fun startActivity(intent: Intent?): Unit {
            attempts++
            throw failure
        }
    }

    /**
     * Resolving and starting are two lookups with a gap between them: the vault can be
     * uninstalled or disabled in that gap. The intent was then never dispatched, which is
     * exactly what `false` means — a client that was promised a boolean must not get a crash
     * from the one path whose entire purpose is reporting failure.
     */
    @Test
    fun `shareEntry returns false when the vault vanishes between resolve and start`() {
        installVault()
        val vanishing = FailingContext(context, android.content.ActivityNotFoundException("gone"))

        assertFalse(Utils.shareEntry(vanishing, entry))
        assertEquals(
            "the start must have been attempted — otherwise this only re-tests the early return",
            1,
            vanishing.attempts,
        )
    }

    /**
     * The opposite call: a vault that matches but refuses the launch (not exported, or behind
     * a permission) is a misconfiguration, not a device without a vault. Reporting it as
     * `false` would have the client tell the user to install an app they already have, so the
     * exception is deliberately left to propagate.
     */
    @Test(expected = SecurityException::class)
    fun `a refused launch propagates rather than masquerading as no vault`() {
        installVault()
        val refusing = FailingContext(context, SecurityException("not exported"))

        Utils.shareEntry(refusing, entry)
    }
}
