/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall

import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Bundle
import android.os.Process
import android.os.UserHandle
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.WifiTethering
import androidx.compose.material3.Icon
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavType
import androidx.navigation.navArgument
import com.android.settingslib.spa.framework.common.SettingsPageProvider
import com.android.settingslib.spa.framework.compose.LocalNavController
import com.android.settingslib.spa.framework.compose.navigator
import com.android.settingslib.spa.framework.theme.SettingsDimension
import com.android.settingslib.spa.widget.dialog.AlertDialogButton
import com.android.settingslib.spa.widget.dialog.rememberAlertDialogPresenter
import com.android.settingslib.spa.widget.preference.Preference
import com.android.settingslib.spa.widget.preference.PreferenceModel
import com.android.settingslib.spa.widget.scaffold.RegularScaffold
import com.android.settingslib.spa.widget.ui.Category
import com.android.settingslib.spa.widget.ui.Footer
import com.android.settingslib.spa.widget.ui.SettingsBody
import com.android.settingslib.spaprivileged.template.app.AppListItemModel
import kotlinx.coroutines.launch

/** The devices on the phone's hotspot and tethering: the rules for all of them, as an app's. */
object HotspotPageProvider : SettingsPageProvider {
    override val name = "Hotspot"

    @Composable fun navigator() = navigator(route = name)

    @Composable
    override fun Page(arguments: Bundle?) {
        val appRules by
            remember { Firewall.appRules(UserHandle.USER_SYSTEM) }.collectAsStateWithLifecycle(null)
        RegularScaffold(title = stringResource(R.string.hotspot_title)) {
            RulesControls(IFirewall.HOTSPOT_PACKAGE, UserHandle.USER_SYSTEM, appRules)
            HotspotDevices(appRules)
            Footer(stringResource(R.string.hotspot_footer))
        }
    }
}

/** One device on the hotspot: its own rules, as an app's, which come before those for all. */
object HotspotDevicePageProvider : SettingsPageProvider {
    private const val MAC = "rt_mac"

    override val name = "HotspotDevice"

    override val parameter = listOf(navArgument(MAC) { type = NavType.StringType })

    @Composable fun navigator(mac: String) = navigator(route = "$name/$mac")

    @Composable
    override fun Page(arguments: Bundle?) {
        HotspotDevicePage(checkNotNull(checkNotNull(arguments).getString(MAC)))
    }
}

fun hotspotDevices() = Firewall.load { getHotspotDevices().toList() }

private fun HotspotDevice.label() = name ?: mac

/** The devices on the hotspot now and those with rules of their own, which open their pages. */
@Composable
private fun HotspotDevices(appRules: Map<String, AppRule>?) {
    val context = LocalContext.current
    val devices by remember { hotspotDevices() }.collectAsStateWithLifecycle(null)
    Category(title = stringResource(R.string.hotspot_devices)) {
        if (devices?.isEmpty() == true) {
            Preference(
                object : PreferenceModel {
                    override val title = stringResource(R.string.no_hotspot_devices)
                }
            )
        }
        for (device in devices.orEmpty().sortedByDescending { it.connected }) {
            key(device.mac) {
                val rule = appRules?.get(IFirewall.DEVICE_PREFIX + device.mac)
                val open = HotspotDevicePageProvider.navigator(device.mac)
                Preference(
                    object : PreferenceModel {
                        override val title = device.label()
                        override val summary = {
                            val rules = context.rulesSummary(rule, usesInternet = true)
                            if (device.connected) {
                                context.getString(R.string.hotspot_device_connected, rules)
                            } else {
                                rules
                            }
                        }
                        override val onClick = open
                    }
                )
            }
        }
    }
}

@Composable
private fun HotspotDevicePage(mac: String) {
    val scope = rememberCoroutineScope()
    val navController = LocalNavController.current
    val appRules by
        remember { Firewall.appRules(UserHandle.USER_SYSTEM) }.collectAsStateWithLifecycle(null)
    val devices by remember { hotspotDevices() }.collectAsStateWithLifecycle(null)
    val device = devices?.find { it.mac == mac }
    if (devices != null && device == null) {
        // Forgotten, here or elsewhere, while it isn't on the hotspot.
        LaunchedEffect(Unit) { navController.navigateBack() }
        return
    }
    val packageName = IFirewall.DEVICE_PREFIX + mac
    val label = device?.label() ?: mac
    val forget =
        rememberAlertDialogPresenter(
            confirmButton =
                AlertDialogButton(stringResource(R.string.forget_hotspot_device)) {
                    scope.launch { Firewall.call { forgetHotspotDevice(mac) } }
                },
            dismissButton = AlertDialogButton(stringResource(android.R.string.cancel)),
            title = stringResource(R.string.forget_hotspot_device_title),
            text = { SettingsBody(stringResource(R.string.forget_hotspot_device_text)) },
        )
    RegularScaffold(title = label) {
        RulesControls(packageName, UserHandle.USER_SYSTEM, appRules)
        Category {
            Preference(
                object : PreferenceModel {
                    override val title = stringResource(R.string.hotspot_device_mac)
                    override val summary = { mac }
                }
            )
            if (appRules?.containsKey(packageName) == true) {
                Preference(
                    object : PreferenceModel {
                        override val title = stringResource(R.string.forget_hotspot_device)
                        override val onClick = forget::open
                    }
                )
            }
        }
        Footer(stringResource(R.string.hotspot_device_footer))
    }
}

/** The devices on the hotspot as a row among the main user's apps, as Settings' data usage has. */
fun Context.hotspotRecords(userId: Int, rules: Map<String, AppRule>): List<FirewallAppRecord> {
    if (userId != UserHandle.USER_SYSTEM) return emptyList()
    val app =
        ApplicationInfo().apply {
            packageName = IFirewall.HOTSPOT_PACKAGE
            uid = Process.DNS_TETHER_UID
            nonLocalizedLabel = getString(R.string.hotspot_title)
        }
    return listOf(FirewallAppRecord(app, rules[IFirewall.HOTSPOT_PACKAGE], usesInternet = true))
}

fun FirewallAppRecord.isHotspot() = app.packageName == IFirewall.HOTSPOT_PACKAGE

/** The hotspot's row, drawn as an app's. */
@Composable
fun AppListItemModel<FirewallAppRecord>.HotspotItem() {
    val open = HotspotPageProvider.navigator()
    Preference(
        object : PreferenceModel {
            override val title = label
            override val summary = this@HotspotItem.summary
            override val icon =
                @Composable {
                    Icon(
                        Icons.Outlined.WifiTethering,
                        contentDescription = null,
                        modifier = Modifier.size(SettingsDimension.appIconItemSize),
                    )
                }
            override val onClick = open
        }
    )
}

/** The rules for all the hotspot's devices, or one device's own. */
fun isHotspotRules(packageName: String) =
    packageName == IFirewall.HOTSPOT_PACKAGE || packageName.startsWith(IFirewall.DEVICE_PREFIX)

/** Tethering never goes out through a VPN, so the hotspot's devices get no VPN switch or choice. */
fun hasVpnChoices(packageName: String) = !isHotspotRules(packageName)

/** The switch's summary on the page, where the hotspot's devices have no Data Saver. */
fun Network.summaryOn(packageName: String) =
    if (this == Network.METERED && isHotspotRules(packageName)) {
        R.string.hotspot_metered_summary
    } else {
        summary
    }
