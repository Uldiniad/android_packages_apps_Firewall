/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall

import android.Manifest
import android.app.admin.DevicePolicyManager
import android.app.admin.DevicePolicyResources
import android.content.ComponentName
import android.content.ContentValues
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Process
import android.os.ServiceManager
import android.os.UserHandle
import android.os.UserManager
import android.platform.uiautomatoraccessibility.PlatformUiAutomatorAccessibilityTestRule
import android.provider.MediaStore
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
import androidx.test.uiautomator.UiScrollable
import androidx.test.uiautomator.UiSelector
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
import java.util.regex.Pattern
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeFalse
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.hamcrest.Matchers.allOf
import org.hamcrest.Matchers.`is`
import org.hamcrest.Matchers.isOneOf

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
    private val newAppsBlocked = firewall.areNewInstallsBlocked(userId)
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
            // Android's file picker, which the export and import tests open: the 1dp dividers
            // between its groups of places, and its tabs for profiles.
            it.addSuppressingResultMatcher(
                allOf(
                    AccessibilityCheckResultUtils.matchesCheck(TouchTargetSizeCheck::class.java),
                    AccessibilityCheckResultUtils.matchesElements(
                        ElementMatchers.isDescendantOfA(
                            ElementMatchers.withResourceName(
                                isOneOf(DOCUMENTS_UI_PLACES, DOCUMENTS_UI_TABS)
                            )
                        )
                    ),
                )
            )
        }

    @After
    fun tearDown() {
        device.pressHome()
        firewall.setAppRules(testPackage, userId, 0)
        firewall.setPause(testPackage, userId, false, 0)
        firewall.setSchedule(testPackage, userId, 0, 0, 0)
        firewall.getAppRulesForUser(userId).find { it.packageName == testPackage }?.let { rule ->
            val networks =
                rule.allowedNetworks.orEmpty().toList() + rule.blockedNetworks.orEmpty().toList()
            for (network in networks) {
                firewall.setAppNetwork(testPackage, userId, network, IFirewall.NETWORK_DEFAULT)
            }
        }
        firewall.removeRules(
            (firewall.getRules(userId, testPackage) + firewall.getRules(userId, null))
                .filter { it.value in TEST_VALUES || it.port in TEST_VALUES }
                .toTypedArray()
        )
        for (list in firewall.getLists(userId).filter { it.title == LIST_FILE }) {
            firewall.removeList(userId, list.packageName, list.id)
        }
        firewall.setNewInstallsBlocked(userId, newAppsBlocked)
    }

    /** The app's own text, in the device's language. */
    private fun text(name: String, vararg args: Any) =
        appResources.getString(appResources.getIdentifier(name, "string", APP), *args)

    private fun plural(name: String, count: Int) =
        appResources.getQuantityString(
            appResources.getIdentifier(name, "plurals", APP),
            count,
            count,
        )

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

    /** The add page's field for the rules' values, labeled with their kind, among dropdowns. */
    private fun valuesField(kind: String = "kind_domains") =
        find(By.clazz(EDIT_TEXT).hasDescendant(By.text(text(kind))), "field for ${text(kind)}")

    /** Picks an option of the add page's dropdown that shows [shown]. */
    private fun choose(shown: String, option: String) {
        find(text(shown)).click()
        find(text(option)).click()
    }

    /** Checks a network in the add page's list of chosen networks, then closes the list. */
    private fun chooseNetwork(network: String) {
        find(text("networks_chosen")).click()
        find(text(network)).click()
        device.pressBack()
    }

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

    /** Shows a profile's tab by its title, as SPA names it, once the page beside it is gone. */
    private fun openTab(header: String, fallback: String) {
        val title =
            context
                .getSystemService(DevicePolicyManager::class.java)
                .resources
                .getString(header) { text(fallback) } ?: text(fallback)
        find(title).click()
        waitUntil { device.findObjects(By.text(text("new_apps_title"))).size == 1 }
    }

    /** Calls the service about another user with shell's permission, as CTS profile tests do. */
    private fun <T> acrossUsers(call: () -> T): T =
        SystemUtil.runWithShellPermissionIdentity(
            ThrowingSupplier { call() },
            Manifest.permission.INTERACT_ACROSS_USERS_FULL,
        )

    private fun rule(packageName: String?, kind: Int, value: String) =
        FirewallRule().also {
            it.packageName = packageName
            it.userId = userId
            it.kind = kind
            it.value = value
            it.subdomains = true
        }

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
        assumeFalse("The firewall is running or off", firewall.isRunning || !firewall.isEnabled)
        onPage("AppList") { find(text("firewall_not_running")) }
    }

    @Test
    fun mainSwitchTurnsTheFirewallOffAndOn() {
        try {
            onPage("AppList") {
                find(text("main_switch_title")).click()
                waitUntil { !firewall.isEnabled }
                waitUntil { !isOn(text("main_switch_title")) }
                // Off as an admin chose, the firewall isn't failing to run.
                assertFalse(device.hasObject(By.text(text("firewall_not_running"))))
                find(text("main_switch_title")).click()
                waitUntil { firewall.isEnabled }
            }
        } finally {
            firewall.setEnabled(true)
        }
    }

    @Test
    fun rulesStayEditableWhileTheFirewallIsOff() {
        firewall.setEnabled(false)
        try {
            onPage("AppRules/$testPackage/$userId") {
                find(text("allow_network_access")).click()
                waitUntil { firewall.getAppRules(testPackage, userId) == IFirewall.BLOCK_ALL }
            }
        } finally {
            firewall.setEnabled(true)
        }
    }

    /** Runs in a user who isn't an admin, which a host test makes, and is skipped otherwise. */
    @Test
    fun nonAdminsSeeTheMainSwitchGreyed() {
        assumeFalse("An admin user", context.getSystemService(UserManager::class.java).isAdminUser)
        assertThrows(SecurityException::class.java) { firewall.setEnabled(false) }
        onPage("AppList") {
            assertFalse(rowOf(text("main_switch_title")).isEnabled)
            find(text("main_switch_admin_only"))
        }
    }

    @Test
    fun rulesExportedFromOneUserImportIntoAProfile() {
        // A name of its own: the Downloads folder lists each export it saved until its entry goes.
        val name = "firewall-rules-${System.currentTimeMillis()}.xml"
        firewall.setAppRules(testPackage, userId, IFirewall.BLOCK_WIFI)
        withWorkProfile { profile ->
            try {
                runShellCommand("pm install-existing --user $profile $testPackage")
                onPage("ExportImport/$userId") {
                    find(text("export_rules")).click()
                    openDownloadsInPicker()
                    find(By.res("android:id/title").clazz(EDIT_TEXT), "file name").text = name
                    find(By.res("android:id/button1"), "file picker's save button").click()
                    waitUntil {
                        (runShellCommand("stat -c %s $DOWNLOAD_DIR/$name").trim().toIntOrNull()
                            ?: 0) > 0
                    }
                }
                onPage("ExportImport/$profile") {
                    find(text("import_rules")).click()
                    find(text("choose_file")).click()
                    openDownloadsInPicker()
                    pickFile(name)
                    waitUntil {
                        acrossUsers { firewall.getAppRules(testPackage, profile) } ==
                            IFirewall.BLOCK_WIFI
                    }
                }
            } finally {
                // Through the provider, which removes the file with its Downloads entry.
                runShellCommand(
                    "content delete --uri content://downloads/all_downloads --where title='$name'"
                )
                runShellCommand("rm -f $DOWNLOAD_DIR/$name")
            }
        }
    }

    @Test
    fun importRefusesAFileThatIsNotAnExport() {
        val values =
            ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, NOT_AN_EXPORT)
                put(MediaStore.Downloads.MIME_TYPE, "text/xml")
            }
        val file =
            checkNotNull(
                context.contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
            )
        try {
            checkNotNull(context.contentResolver.openOutputStream(file)).use {
                it.write("<notes><note>Not rules</note></notes>".toByteArray())
            }
            firewall.setAppRules(testPackage, userId, IFirewall.BLOCK_WIFI)
            onPage("ExportImport/$userId") {
                find(text("import_rules")).click()
                find(text("choose_file")).click()
                openDownloadsInPicker()
                pickFile(NOT_AN_EXPORT)
                find(text("import_failed_title"))
            }
            assertEquals(IFirewall.BLOCK_WIFI, firewall.getAppRules(testPackage, userId))
        } finally {
            context.contentResolver.delete(file, null, null)
        }
    }

    @Test
    fun aListAddedFromAFileShowsInItsTabAndAsksBeforeItsRemoved() {
        val values =
            ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, LIST_FILE)
                put(MediaStore.Downloads.MIME_TYPE, "text/plain")
            }
        val file =
            checkNotNull(
                context.contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
            )
        try {
            checkNotNull(context.contentResolver.openOutputStream(file)).use {
                it.write("$DOMAIN\n$ADDRESS\n".toByteArray())
            }
            onPage("AllAppsRules/$userId") {
                find(text("kind_lists")).click()
                find(text("no_lists"))
                find(text("add_list")).click()
                scrollTo(text("add_list_file")).click()
                openDownloadsInPicker()
                pickFile(LIST_FILE)
                waitUntil { firewall.getLists(userId).any { it.title == LIST_FILE } }
                val list = firewall.getLists(userId).first { it.title == LIST_FILE }
                assertEquals(1, list.domains)
                assertEquals(1, list.ranges)
                find(text("kind_lists")).click()
                findDescribed(text("remove_list_for", LIST_FILE)).click()
                find(text("remove_list_title", LIST_FILE))
                find(text("remove")).click()
                waitUntil { firewall.getLists(userId).none { it.title == LIST_FILE } }
            }
        } finally {
            context.contentResolver.delete(file, null, null)
        }
    }

    @Test
    fun anAppsRulesSuggestTheEncryptedDnsLists() =
        onPage("AppRules/$testPackage/$userId") {
            scrollTo(text("add_list")).click()
            find(text("list_encrypted_dns"))
            assertFalse(device.hasObject(By.text(text("list_ads"))))
        }

    @Test
    fun anAddressThatIsntHttpsComesBackToFix() =
        onPage("AddList/$userId") {
            scrollTo(By.clazz(EDIT_TEXT), "address field").text = "http://lists.example.test/ads.txt"
            find(text("add")).click()
            scrollTo(text("list_address_invalid"))
            assertTrue(firewall.getLists(userId).none { it.url?.startsWith("http:") == true })
        }

    @Test
    fun homePageSwitchBlocksNewApps() {
        firewall.setNewInstallsBlocked(userId, false)
        onPage("AppList") {
            find(text("new_apps_title")).click()
            waitUntil { firewall.areNewInstallsBlocked(userId) }
        }
    }

    @Test
    fun notificationsRowOpensTheBlockedAppsChannel() =
        onPage("AppList") {
            find(text("notifications_title")).click()
            assertTrue(device.wait(Until.hasObject(By.pkg(SETTINGS).depth(0)), TIMEOUT))
            // The channel's page shows its description; its name is the page's title.
            find(text("channel_blocked_apps_description"))
        }

    @Test
    fun homePageOpensTheRulesForAllApps() =
        onPage("AppList") {
            find(text("all_apps_rules")).click()
            find(text("kind_addresses"))
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
    fun appPageSetsAChoiceForTheWifiItIsOn() {
        val wifi = firewall.getNetworks(userId).find { it.connected && it.key.startsWith("wifi:") }
        assumeTrue("Needs Wi-Fi", wifi != null)
        onPage("AppRules/$testPackage/$userId") {
            scrollTo(text("specific_networks")).click()
            find(checkNotNull(wifi).name).click()
            find(text("choice_blocked")).click()
            waitUntil {
                firewall.getAppRulesForUser(userId)
                    .find { it.packageName == testPackage }
                    ?.blockedNetworks
                    ?.contains(wifi.key) == true
            }
            device.pressBack()
            scrollTo(plural("specific_network_count", 1))
        }
    }

    @Test
    fun specificNetworksPageListsEachKindOrSaysThereIsNone() {
        val networks = firewall.getNetworks(userId)
        onPage("SpecificNetworks/$testPackage/$userId") {
            for ((prefix, heading, none) in SPECIFIC_KINDS) {
                scrollTo(text(heading))
                val first = networks.firstOrNull { it.key.startsWith(prefix) }
                scrollTo(
                    when {
                        first == null -> text(none)
                        first.name == null -> text("removed_sim", first.key.substringAfter(':'))
                        else -> first.name
                    }
                )
            }
        }
    }

    @Test
    fun appPageBlocksTheAppForAWhile() =
        onPage("AppRules/$testPackage/$userId") {
            find(text("pause_block_title")).click()
            find(text("pause_1_hour")).click()
            waitUntil {
                firewall.getAppRulesForUser(userId).any {
                    it.packageName == testPackage && it.pauseBlocks &&
                        it.pauseUntil > System.currentTimeMillis()
                }
            }
        }

    @Test
    fun schedulePageTurnsABedtimeScheduleOn() =
        onPage("Schedule/$testPackage/$userId") {
            find(text("schedule_switch")).click()
            waitUntil {
                firewall.getAppRulesForUser(userId).any {
                    it.packageName == testPackage && it.scheduleDays == 0x7f &&
                        it.scheduleStart == 22 * 60 && it.scheduleEnd == 7 * 60
                }
            }
        }

    @Test
    fun appPageAddsAnAllowRuleForTheApp() =
        onPage("AppRules/$testPackage/$userId") {
            scrollTo(text("add_rule")).click()
            choose("action_block", "action_allow")
            valuesField().text = DOMAIN
            find(text("add")).click()
            waitUntil {
                firewall.getRules(userId, testPackage).any {
                    it.value == DOMAIN && it.allow && it.kind == IFirewall.RULE_DOMAIN
                }
            }
            // The page lists it with the others, removable from there.
            find(DOMAIN)
        }

    @Test
    fun removingARuleAsksFirst() {
        firewall.addRules(arrayOf(rule(testPackage, IFirewall.RULE_DOMAIN, DOMAIN)))
        onPage("AppRules/$testPackage/$userId") {
            val remove = text("remove_rule_for", DOMAIN)
            scrollTo(DOMAIN)
            findDescribed(remove).click()
            find(text("remove_rule_title", DOMAIN))
            find(appResources.getString(android.R.string.cancel)).click()
            assertTrue(firewall.getRules(userId, testPackage).any { it.value == DOMAIN })
            findDescribed(remove).click()
            find(text("remove")).click()
            waitUntil { firewall.getRules(userId, testPackage).none { it.value == DOMAIN } }
        }
    }

    @Test
    fun localNetworkRowOpensAndroidsPermissionPage() =
        onPage("AppRules/$testPackage/$userId") {
            scrollTo(text("local_network")).click()
            val page = Until.hasObject(By.pkg(PERMISSION_CONTROLLER).depth(0))
            assertTrue(device.wait(page, TIMEOUT))
        }

    @Test
    fun dataUsageRowOpensAndroidsDataPage() =
        onPage("AppRules/$testPackage/$userId") {
            scrollTo(text("data_usage")).click()
            assertTrue(device.wait(Until.hasObject(By.pkg(SETTINGS).depth(0)), TIMEOUT))
        }

    @Test
    fun appPageExplainsANewAppsBlock() {
        waitUntil {
            firewall.getAppRulesForUser(userId).any {
                it.packageName == NO_INTERNET && it.isDefault
            }
        }
        onPage("AppRules/$NO_INTERNET/$userId") {
            scrollTo(By.textContains(text("app_rules_footer_new")), "new app footer")
        }
    }

    @Test
    fun appsWithoutInternetShowTheyCantUseTheNetwork() {
        val saved = firewall.getBackupPayload(userId)
        try {
            firewall.setAppRules(NO_INTERNET, userId, 0)
            onPage("AppList") {
                search(NO_INTERNET)
                find(NO_INTERNET)
                find(text("rules_no_internet"))
            }
        } finally {
            firewall.applyRestore(userId, saved)
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
    fun rulesForAllAppsHaveATabPerKind() =
        onPage("AllAppsRules/$userId") {
            for ((tab, add) in RULE_TABS) {
                find(text(tab)).click()
                find(text(add))
            }
        }

    @Test
    fun linesThatAreNotDomainsComeBackToFix() =
        onPage("AllAppsRules/$userId") {
            find(text("kind_domains")).click()
            find(text("add_domains")).click()
            valuesField().text = "$DOMAIN\nnot a domain"
            find(text("add")).click()
            find(text("domains_invalid"))
            assertEquals("not a domain", valuesField().text)
            assertTrue(firewall.getRules(userId, null).any { it.value == DOMAIN && !it.allow })
        }

    @Test
    fun addressPageTakesRangesAndRejectsTheRest() =
        onPage("AllAppsRules/$userId") {
            find(text("kind_addresses")).click()
            find(text("add_addresses")).click()
            valuesField("kind_addresses").text = "$ADDRESS\nnot an address"
            find(text("add")).click()
            find(text("addresses_invalid"))
            assertEquals("not an address", valuesField("kind_addresses").text)
            assertTrue(
                firewall.getRules(userId, null).any {
                    it.value == ADDRESS && it.kind == IFirewall.RULE_ADDRESS
                }
            )
        }

    @Test
    fun portPageLimitsAPortToAProtocol() =
        onPage("AllAppsRules/$userId") {
            find(text("kind_ports")).click()
            find(text("add_ports")).click()
            valuesField("kind_ports").text = PORT
            choose("protocol_both", "protocol_udp")
            find(text("add")).click()
            waitUntil {
                firewall.getRules(userId, null).any {
                    it.value == PORT && it.protocol == IFirewall.PROTOCOL_UDP
                }
            }
            find(text("rule_blocked_udp"))
        }

    @Test
    fun addressRulesTakeAPortOnceItIsOne() =
        onPage("AllAppsRules/$userId") {
            find(text("kind_addresses")).click()
            find(text("add_addresses")).click()
            valuesField("kind_addresses").text = ADDRESS
            valuesField("port_label").text = "70000"
            find(text("add")).click()
            find(text("port_invalid"))
            valuesField("port_label").text = DNS_PORT
            choose("protocol_both", "protocol_udp")
            find(text("add")).click()
            waitUntil {
                firewall.getRules(userId, null).any {
                    it.value == ADDRESS && it.port == DNS_PORT &&
                        it.protocol == IFirewall.PROTOCOL_UDP
                }
            }
            find(text("rule_at_udp_port", text("rule_blocked"), DNS_PORT))
        }

    @Test
    fun domainPageSaysRulesActOnTheDomainsAddresses() =
        onPage("AllAppsRules/$userId") {
            find(text("kind_domains")).click()
            find(text("add_domains")).click()
            scrollTo(text("domain_addresses_footer"))
        }

    @Test
    fun incomingRulesShowInThePortsTabWithWhoConnects() =
        onPage("AllAppsRules/$userId") {
            find(text("kind_ports")).click()
            find(text("add_ports")).click()
            valuesField("kind_ports").text = SERVED_PORT
            choose("direction_outgoing", "direction_incoming")
            choose("sender_anyone", "sender_local_network")
            scrollTo(text("protocol_both")).click()
            find(text("protocol_tcp")).click()
            find(text("add")).click()
            waitUntil {
                firewall.getRules(userId, null).any {
                    it.kind == IFirewall.RULE_INCOMING && it.port == SERVED_PORT &&
                        it.value == IFirewall.INCOMING_FROM_LOCAL_NETWORK &&
                        it.protocol == IFirewall.PROTOCOL_TCP
                }
            }
            find(text("port_title", SERVED_PORT))
            find(text("rule_from_local_network", text("rule_incoming_blocked_tcp")))
        }

    @Test
    fun portRangesShowAsOneRule() {
        firewall.addRules(arrayOf(rule(null, IFirewall.RULE_PORT, PORT_RANGE)))
        onPage("AllAppsRules/$userId") {
            find(text("kind_ports")).click()
            find(text("ports_title", PORT_RANGE))
        }
    }

    @Test
    fun exactDomainRulesLeaveSubdomainsOut() =
        onPage("AllAppsRules/$userId") {
            find(text("kind_domains")).click()
            find(text("add_domains")).click()
            valuesField().text = DOMAIN
            find(text("include_subdomains")).click()
            find(text("add")).click()
            waitUntil {
                firewall.getRules(userId, null).any { it.value == DOMAIN && !it.subdomains }
            }
        }

    @Test
    fun rulesForAllAppsSearchFindsARule() {
        firewall.addRules(
            arrayOf(
                rule(null, IFirewall.RULE_DOMAIN, DOMAIN),
                rule(null, IFirewall.RULE_DOMAIN, OTHER_DOMAIN),
            )
        )
        onPage("AllAppsRules/$userId") {
            search("other.")
            find(OTHER_DOMAIN)
            assertTrue(device.wait(Until.gone(By.text(DOMAIN)), TIMEOUT))
        }
    }

    @Test
    fun aRuleForAllAppsCanBeLimitedToANetwork() =
        onPage("AllAppsRules/$userId") {
            find(text("kind_domains")).click()
            find(text("add_domains")).click()
            valuesField().text = DOMAIN
            choose("networks_all", "networks_only")
            chooseNetwork("network_wifi")
            find(text("add")).click()
            waitUntil {
                firewall.getRules(userId, null).any {
                    it.value == DOMAIN && it.networks.contentEquals(arrayOf("wifi")) &&
                        !it.exceptNetworks
                }
            }
            find(
                text(
                    "rule_only_networks",
                    text("rule_blocked_subdomains"),
                    text("networks_list_wifi"),
                )
            )
        }

    @Test
    fun aRuleForAllAppsCanApplyEverywhereButANetwork() =
        onPage("AllAppsRules/$userId") {
            find(text("kind_domains")).click()
            find(text("add_domains")).click()
            valuesField().text = DOMAIN
            choose("networks_all", "networks_except")
            chooseNetwork("network_vpn")
            find(text("add")).click()
            waitUntil {
                firewall.getRules(userId, null).any {
                    it.value == DOMAIN && it.networks.contentEquals(arrayOf("vpn")) &&
                        it.exceptNetworks
                }
            }
            find(
                text(
                    "rule_except_networks",
                    text("rule_blocked_subdomains"),
                    text("networks_list_vpn"),
                )
            )
        }

    @Test
    fun theAddRulesPageKeepsItsTextWhenTheScreenTurns() =
        onPage("AllAppsRules/$userId") {
            find(text("kind_domains")).click()
            find(text("add_domains")).click()
            valuesField().text = DOMAIN
            try {
                device.setOrientationLeft()
                assertEquals(DOMAIN, valuesField().text)
            } finally {
                device.setOrientationNatural()
                device.unfreezeRotation()
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
    fun aWorkProfileGetsATabWithItsOwnSettings() = withWorkProfile { profile ->
        val blocked = acrossUsers { firewall.areNewInstallsBlocked(profile) }
        onPage("AppList") {
            openWorkTab()
            find(text("new_apps_title")).click()
            waitUntil { acrossUsers { firewall.areNewInstallsBlocked(profile) } != blocked }
            assertEquals(newAppsBlocked, firewall.areNewInstallsBlocked(userId))
            // The profile's notifications are its own copy's, set in its own Settings.
            find(text("notifications_title")).click()
            assertTrue(device.wait(Until.hasObject(By.pkg(SETTINGS).depth(0)), TIMEOUT))
        }
    }

    @Test
    fun privateSpaceGetsATabWithItsOwnSettings() =
        withProfile("--user-type android.os.usertype.profile.PRIVATE") { profile ->
            val blocked = acrossUsers { firewall.areNewInstallsBlocked(profile) }
            onPage("AppList") {
                openTab(
                    DevicePolicyResources.Strings.Settings.PRIVATE_CATEGORY_HEADER,
                    "category_private",
                )
                find(text("new_apps_title")).click()
                waitUntil { acrossUsers { firewall.areNewInstallsBlocked(profile) } != blocked }
                assertEquals(newAppsBlocked, firewall.areNewInstallsBlocked(userId))
            }
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

    @Test
    fun tappingABlockedAppsNotificationOpensItsPage() {
        withNotifications { listener ->
            firewall.setAppRules(testPackage, userId, IFirewall.BLOCK_ALL)
            reportBlocked()
            val posted = next(NotificationListener.posted)
            try {
                // Tapped in the shade as a user would; this test app is named by its package.
                device.openNotification()
                find(text("blocked_app_title", testPackage)).click()
                assertTrue(device.wait(Until.hasObject(By.pkg(APP).depth(0)), TIMEOUT))
                find(text("app_rules_title"))
            } finally {
                listener.cancelNotification(posted.key)
            }
        }
    }

    @Test
    fun allowingFromTheNotificationAllowsTheApp() {
        assertEquals(0, decideFromNotification(IFirewall.BLOCK_ALL, "blocked_app_allow"))
    }

    @Test
    fun keepingBlockedFromTheNotificationBlocksTheApp() {
        assertEquals(IFirewall.BLOCK_ALL, decideFromNotification(0, "blocked_app_keep"))
    }

    /** Has the app report a blocked app, takes the notification's action, returns the rules. */
    private fun decideFromNotification(rules: Int, button: String): Int = withNotifications {
        firewall.setAppRules(testPackage, userId, rules)
        reportBlocked()
        val posted = next(NotificationListener.posted)
        posted.notification.actions
            .first { it.title.toString() == text(button) }
            .actionIntent
            .send()
        next(NotificationListener.removed)
        firewall.getAppRules(testPackage, userId)
    }

    /** Runs the steps with this test's notification listener connected. */
    private fun <T> withNotifications(steps: (NotificationListener) -> T): T {
        val listener = "$testPackage/${NotificationListener::class.java.name}"
        // Events of earlier tests would be taken for this one's.
        NotificationListener.connected.clear()
        NotificationListener.posted.clear()
        NotificationListener.removed.clear()
        runShellCommand("cmd notification allow_listener $listener")
        try {
            return steps(
                checkNotNull(NotificationListener.connected.poll(TIMEOUT, TimeUnit.MILLISECONDS))
            )
        } finally {
            runShellCommand("cmd notification disallow_listener $listener")
        }
    }

    /** Tells the firewall app this test app is blocked until decided, as the service does. */
    private fun reportBlocked() {
        context.sendBroadcast(
            Intent(ACTION_APP_BLOCKED)
                .setPackage(APP)
                .putExtra(Intent.EXTRA_PACKAGE_NAME, testPackage),
            PERMISSION,
        )
    }

    /** Another app's text, in the device's language, as that app shows it. */
    private fun textOf(packageName: String, name: String): String {
        val resources = context.packageManager.getResourcesForApplication(packageName)
        return resources.getString(resources.getIdentifier(name, "string", packageName))
    }

    /** Shows the Downloads folder in Android's file picker, as DocumentsUI's own tests open one. */
    private fun openDownloadsInPicker() {
        find(By.desc(textOf(DOCUMENTS_UI, "drawer_open")), "file picker's places").click()
        clickInList(
            UiSelector()
                .resourceId("$DOCUMENTS_UI:id/container_roots")
                .childSelector(UiSelector().resourceId(DOCUMENTS_UI_PLACES)),
            textOf(DOWNLOAD_PROVIDER, "root_downloads"),
        )
    }

    /** Picks the file in the folder Android's file picker shows. */
    private fun pickFile(name: String) =
        clickInList(
            UiSelector()
                .resourceId("$DOCUMENTS_UI:id/container_directory")
                .childSelector(UiSelector().resourceId("$DOCUMENTS_UI:id/dir_list")),
            name,
        )

    /** Clicks the list's item with the text, found anew on the click, as the lists redraw. */
    private fun clickInList(list: UiSelector, text: String) {
        assertTrue(device.findObject(list.childSelector(UiSelector())).waitForExists(TIMEOUT))
        UiScrollable(list).scrollIntoView(UiSelector().text(text))
        // Unchecked, as in DocumentsUI's tests: a pick closes the picker, which the click can't
        // see, so what the click did is checked after.
        device.findObject(list.childSelector(UiSelector().text(text))).click()
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
        const val DOCUMENTS_UI = "com.android.documentsui"
        const val DOCUMENTS_UI_PLACES = "com.android.documentsui:id/roots_list"
        const val DOCUMENTS_UI_TABS = "com.android.documentsui:id/tabs"
        const val DOWNLOAD_PROVIDER = "com.android.providers.downloads"
        const val DOWNLOAD_DIR = "/sdcard/Download"
        const val NOT_AN_EXPORT = "not-firewall-rules.xml"
        const val LIST_FILE = "firewall-test-list.txt"
        const val SYSTEMUI_BATTERY = "com.android.systemui:id/battery_meter_composable_view"
        const val NO_INTERNET = "org.lineageos.firewall.hostside.nointernet"
        val PERMISSION_CONTROLLER: Pattern = Pattern.compile(".*permissioncontroller")
        // Generous: the first launch on a freshly flashed phone runs uncompiled code.
        const val TIMEOUT = 20_000L
        const val DOMAIN = "example.test"
        const val OTHER_DOMAIN = "other.example.test"
        const val ADDRESS = "198.51.100.0/24"
        const val PORT = "8443"
        const val PORT_RANGE = "6881-6889"
        const val DNS_PORT = "53"
        const val SERVED_PORT = "8080"
        val TEST_VALUES = setOf(DOMAIN, OTHER_DOMAIN, ADDRESS, PORT, PORT_RANGE, SERVED_PORT)
        const val EDIT_TEXT = "android.widget.EditText"
        const val TEXT_VIEW = "android.widget.TextView"
        const val ACTION_APP_BLOCKED = "org.lineageos.firewall.action.APP_BLOCKED"
        const val PERMISSION = "org.lineageos.firewall.permission.MANAGE_FIREWALL"
        val NETWORK_SWITCHES =
            listOf(
                "network_wifi" to IFirewall.BLOCK_WIFI,
                "network_mobile" to IFirewall.BLOCK_CELLULAR,
                "network_vpn" to IFirewall.BLOCK_VPN,
                "network_other" to IFirewall.BLOCK_OTHER,
                "network_metered" to IFirewall.BLOCK_METERED,
                "network_roaming" to IFirewall.BLOCK_ROAMING,
            )
        val SPECIFIC_KINDS =
            listOf(
                Triple("wifi:", "specific_wifi", "no_saved_wifi"),
                Triple("sim:", "specific_sims", "no_sims"),
                Triple("vpn:", "specific_vpns", "no_vpn_apps"),
            )
        val RULE_TABS =
            listOf(
                "kind_domains" to "add_domains",
                "kind_addresses" to "add_addresses",
                "kind_ports" to "add_ports",
                "kind_lists" to "add_list",
            )
    }
}
