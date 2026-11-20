/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall

import android.Manifest
import android.app.admin.DevicePolicyManager
import android.app.admin.DevicePolicyResources
import android.content.ComponentName
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Process
import android.os.ServiceManager
import android.os.UserHandle
import android.platform.uiautomatoraccessibility.PlatformUiAutomatorAccessibilityTestRule
import android.provider.Settings
import android.service.notification.StatusBarNotification
import android.view.KeyEvent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.BySelector
import androidx.test.uiautomator.Condition
import androidx.test.uiautomator.Direction
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.UiObject2
import androidx.test.uiautomator.Until
import com.android.compatibility.common.util.PollingCheck
import com.android.compatibility.common.util.SystemUtil
import com.android.compatibility.common.util.SystemUtil.runShellCommand
import com.android.compatibility.common.util.ThrowingSupplier
import com.google.android.apps.common.testing.accessibility.framework.AccessibilityCheckResultUtils
import com.google.android.apps.common.testing.accessibility.framework.checks.TouchTargetSizeCheck
import com.google.android.apps.common.testing.accessibility.framework.matcher.ElementMatchers
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.function.BooleanSupplier
import java.util.function.Supplier
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeFalse
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.hamcrest.Matchers.allOf
import org.hamcrest.Matchers.`is`

/**
 * Drives the installed firewall app against the real service, with this test app as the app to
 * rule.
 */
@RunWith(AndroidJUnit4::class)
class FirewallAppTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.context
    private val device = UiDevice.getInstance(instrumentation)
    private val firewall =
        IFirewall.Stub.asInterface(checkNotNull(ServiceManager.getService("firewall")))
    private val testPackage = context.packageName
    private val userId = context.userId
    private val appResources = context.packageManager.getResourcesForApplication(APP)

    /** AOSP's accessibility checks, run on every UiAutomator action and after each test. */
    @get:Rule
    val accessibility =
        PlatformUiAutomatorAccessibilityTestRule().configureSuppressions {
            // SystemUI's shade, which a test opens, as AOSP suppresses its other status bar views.
            it.addSuppressingResultMatcher(
                allOf(
                    AccessibilityCheckResultUtils.matchesCheck(TouchTargetSizeCheck::class.java),
                    AccessibilityCheckResultUtils.matchesElements(
                        ElementMatchers.withResourceName(`is`(SYSTEMUI_BATTERY))
                    ),
                )
            )
        }

    @After
    fun tearDown() {
        device.pressHome()
        firewall.setAppRules(testPackage, userId, 0)
    }

    /** The app's own text, in the device's language. */
    private fun text(name: String, vararg args: Any) =
        appResources.getString(appResources.getIdentifier(name, "string", APP), *args)

    /** Opens a page of the app and runs the steps, starting as AOSP Settings' UI tests do. */
    private fun onPage(route: String, steps: () -> Unit) {
        device.wakeUp()
        device.pressKeyCodes(intArrayOf(KeyEvent.KEYCODE_MENU, KeyEvent.KEYCODE_MENU))
        device.pressHome()
        device.wait(Until.hasObject(By.pkg(device.launcherPackageName).depth(0)), TIMEOUT)
        context.startActivity(
            Intent()
                .setComponent(ComponentName(APP, "$APP.MainActivity"))
                .putExtra("spaActivityDestination", route)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
        )
        assertTrue(device.wait(Until.hasObject(By.pkg(APP).depth(0)), TIMEOUT))
        steps()
    }

    private fun find(selector: BySelector, what: String): UiObject2 =
        checkNotNull(device.wait(Until.findObject(selector), TIMEOUT)) { "No $what" }

    private fun find(text: String) = find(By.text(text), "\"$text\"")

    private fun findDescribed(description: String) =
        find(By.desc(description), "\"$description\" button")

    private fun editText() = find(By.clazz(EDIT_TEXT), "text field")

    /**
     * Scrolls the page down until the object shows, as AOSP Settings' UI tests do: Compose sends no
     * scroll events, and only scrollUntil keeps scrolling without them. A page that fits the screen
     * has nothing to scroll, so the wait is for the object or something scrollable.
     */
    private fun scrollTo(selector: BySelector, what: String): UiObject2 {
        val scrollable = By.scrollable(true)
        device.wait(
            Condition<UiDevice, Boolean> { it.hasObject(selector) || it.hasObject(scrollable) },
            TIMEOUT,
        )
        return device.findObject(selector)
            ?: device
                .findObject(scrollable)
                ?.scrollUntil(Direction.DOWN, Until.findObject(selector))
            ?: find(selector, what)
    }

    private fun scrollTo(text: String) = scrollTo(By.text(text), "\"$text\"")

    /** The switch row with this title, which Compose nests the title in. */
    private fun rowOf(title: String): UiObject2 {
        var row: UiObject2? = find(title)
        while (row != null && !row.isCheckable) row = row.parent
        return checkNotNull(row) { "No switch for \"$title\"" }
    }

    private fun isOn(title: String) = rowOf(title).isChecked

    /** Searches the page with the search box in its top bar. */
    private fun search(query: String) {
        findDescribed(text("search_menu_title")).click()
        editText().text = query
    }

    /** Shows the tab of the user's work profile, once the page beside it is gone. */
    private fun openWorkTab() =
        openTab(DevicePolicyResources.Strings.Settings.WORK_CATEGORY_HEADER, "category_work")

    /** Shows a profile's tab by its title, as SPA names it, once the pager settles. */
    private fun openTab(header: String, fallback: String) {
        val title =
            context
                .getSystemService(DevicePolicyManager::class.java)
                .resources
                .getString(header) { text(fallback) } ?: text(fallback)
        find(title).click()
        device.waitForIdle()
    }

    /** Calls the service about another user with shell's permission, as CTS profile tests do. */
    private fun <T> acrossUsers(call: () -> T): T =
        SystemUtil.runWithShellPermissionIdentity(
            ThrowingSupplier { call() },
            Manifest.permission.INTERACT_ACROSS_USERS_FULL,
        )

    @Test
    fun homePageSearchFindsAnAppWithWhatBlocksIt() {
        firewall.setAppRules(testPackage, userId, IFirewall.BLOCK_WIFI)
        onPage("AppList") {
            search(testPackage)
            find(testPackage)
            find(text("rules_blocked_on", text("networks_list_wifi")))
        }
    }

    @Test
    fun systemAppsShowOnlyAfterShowSystem() {
        val pm = context.packageManager
        val home =
            pm.queryIntentActivities(
                    Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME),
                    0,
                )
                .map { it.activityInfo.packageName }
        // As in SPA's lists, updated system apps and those on the launcher count as installed.
        val app =
            pm.getInstalledApplications(0).firstOrNull {
                it.flags and ApplicationInfo.FLAG_SYSTEM != 0 &&
                    it.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP == 0 &&
                    pm.getLaunchIntentForPackage(it.packageName) == null &&
                    it.packageName !in home &&
                    UserHandle.getAppId(it.uid) >= Process.FIRST_APPLICATION_UID &&
                    pm.checkPermission(Manifest.permission.INTERNET, it.packageName) ==
                        PackageManager.PERMISSION_GRANTED &&
                    it.loadLabel(pm).toString() != it.packageName
            }
        assumeTrue("Needs a system app that can use the internet", app != null)
        val label = checkNotNull(app).loadLabel(pm).toString()
        onPage("AppList") {
            search(label)
            find(text("no_applications"))
            findDescribed(text("abc_action_menu_overflow_description")).click()
            find(text("menu_show_system")).click()
            find(By.text(label).clazz(TEXT_VIEW), "\"$label\" in the list")
        }
    }

    /** Runs once the host test of the firewall's warnings stops it, and is skipped otherwise. */
    @Test
    fun homePageWarnsWhileTheFirewallIsNotRunning() {
        assumeFalse("The firewall is running", firewall.isRunning)
        onPage("AppList") { find(text("firewall_not_running")) }
    }

    @Test
    fun networkAccessSwitchBlocksTheAppEverywhere() =
        onPage("AppRules/$testPackage/$userId") {
            find(text("allow_network_access")).click()
            waitUntil { firewall.getAppRules(testPackage, userId) == IFirewall.BLOCK_ALL }
            // The switches for each network have nothing left to block.
            waitUntil { !rowOf(text("network_wifi")).isEnabled }
        }

    @Test
    fun eachNetworkSwitchBlocksItsOwnNetwork() =
        onPage("AppRules/$testPackage/$userId") {
            for ((title, rule) in NETWORK_SWITCHES) {
                scrollTo(text(title)).click()
                waitUntil { firewall.getAppRules(testPackage, userId) == rule }
                find(text(title)).click()
                waitUntil { firewall.getAppRules(testPackage, userId) == 0 }
            }
        }

    @Test
    fun appPageFollowsChangesMadeElsewhere() =
        onPage("AppRules/$testPackage/$userId") {
            assertTrue(isOn(text("network_vpn")))
            firewall.setAppRules(testPackage, userId, IFirewall.BLOCK_VPN)
            waitUntil { !isOn(text("network_vpn")) }
        }

    @Test
    fun dataUsageRowOpensAndroidsDataPage() =
        onPage("AppRules/$testPackage/$userId") {
            scrollTo(text("data_usage")).click()
            assertTrue(device.wait(Until.hasObject(By.pkg(SETTINGS).depth(0)), TIMEOUT))
        }

    @Test
    fun appsWithoutInternetShowTheyCantUseTheNetwork() {
        val saved = firewall.getAppRules(NO_INTERNET, userId)
        try {
            firewall.setAppRules(NO_INTERNET, userId, 0)
            onPage("AppList") {
                search(NO_INTERNET)
                find(NO_INTERNET)
                find(text("rules_no_internet"))
            }
        } finally {
            firewall.setAppRules(NO_INTERNET, userId, saved)
        }
    }

    @Test
    fun appPageNamesTheAppsSharingItsUid() {
        val pm = context.packageManager
        val shared =
            pm.getInstalledPackages(0)
                .map { it.packageName }
                .firstOrNull { name ->
                    val uid = runCatching { pm.getPackageUid(name, 0) }.getOrDefault(-1)
                    uid > Process.SYSTEM_UID && pm.getPackagesForUid(uid).orEmpty().size > 1
                }
        assumeTrue("Needs apps sharing a uid", shared != null)
        val prefix = text("app_rules_footer_shared", "\u0000").substringBefore("\u0000")
        onPage("AppRules/$shared/$userId") {
            scrollTo(By.textContains(prefix), "shared uid footer")
        }
    }

    @Test
    fun settingsShowsTheFirewallUnderNetworkAndInternet() {
        context.startActivity(
            Intent(Settings.ACTION_WIRELESS_SETTINGS)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
        )
        assertTrue(device.wait(Until.hasObject(By.pkg(SETTINGS).depth(0)), TIMEOUT))
        scrollTo(text("app_name")).click()
        assertTrue(device.wait(Until.hasObject(By.pkg(APP).depth(0)), TIMEOUT))
    }

    @Test
    fun workTabAppsGetTheirRulesInTheProfile() = withWorkProfile { profile ->
        runShellCommand("pm install-existing --user $profile $testPackage")
        onPage("AppList") {
            openWorkTab()
            search(testPackage)
            find(testPackage).click()
            find(text("network_wifi")).click()
            waitUntil {
                acrossUsers { firewall.getAppRules(testPackage, profile) } == IFirewall.BLOCK_WIFI
            }
            assertEquals(0, firewall.getAppRules(testPackage, userId))
        }
    }

    /** Runs the steps with a new work profile of this user, removed after. */
    private fun withWorkProfile(steps: (Int) -> Unit) = withProfile("--managed", steps)

    /** Runs the steps with a new profile of this user of the kind [type] names, removed after. */
    private fun withProfile(type: String, steps: (Int) -> Unit) {
        val created = runShellCommand("pm create-user --profileOf $userId $type fwuitest")
        val profile =
            checkNotNull(Regex("created user id (\\d+)").find(created)?.groupValues?.get(1)) {
                    "No profile: $created"
                }
                .toInt()
        try {
            runShellCommand("am start-user -w $profile")
            steps(profile)
        } finally {
            runShellCommand("pm remove-user --wait $profile")
        }
    }

    /** The next notification event about this test app from the firewall app. */
    private fun next(events: LinkedBlockingQueue<StatusBarNotification>): StatusBarNotification {
        while (true) {
            val event = checkNotNull(events.poll(TIMEOUT, TimeUnit.MILLISECONDS)) { "Timed out" }
            if (event.packageName == APP && event.tag == testPackage) return event
        }
    }

    /** Waits for what another process does, which offers this test no callback. */
    private fun <T : Any> waitFor(value: () -> T?): T =
        checkNotNull(PollingCheck.waitFor(TIMEOUT, Supplier { value() }) { it != null })

    private fun waitUntil(condition: () -> Boolean) =
        PollingCheck.waitFor(TIMEOUT, BooleanSupplier { condition() }, "Timed out")

    private companion object {
        const val APP = "org.lineageos.firewall"
        const val SETTINGS = "com.android.settings"
        const val SYSTEMUI_BATTERY = "com.android.systemui:id/battery_meter_composable_view"
        const val NO_INTERNET = "org.lineageos.firewall.hostside.nointernet"
        // Generous: the first launch on a freshly flashed phone runs uncompiled code.
        const val TIMEOUT = 20_000L
        const val ADDRESS = "198.51.100.0/24"
        const val EDIT_TEXT = "android.widget.EditText"
        const val TEXT_VIEW = "android.widget.TextView"
        val NETWORK_SWITCHES =
            listOf(
                "network_wifi" to IFirewall.BLOCK_WIFI,
                "network_mobile" to IFirewall.BLOCK_CELLULAR,
                "network_vpn" to IFirewall.BLOCK_VPN,
                "network_other" to IFirewall.BLOCK_OTHER,
                "network_metered" to IFirewall.BLOCK_METERED,
                "network_roaming" to IFirewall.BLOCK_ROAMING,
            )
    }
}
