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
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.android.settingslib.spa.framework.common.SettingsPageProvider
import com.android.settingslib.spa.framework.compose.navigator
import com.android.settingslib.spa.framework.theme.SettingsDimension
import com.android.settingslib.spa.widget.preference.Preference
import com.android.settingslib.spa.widget.preference.PreferenceModel
import com.android.settingslib.spa.widget.scaffold.RegularScaffold
import com.android.settingslib.spa.widget.ui.Footer
import com.android.settingslib.spaprivileged.template.app.AppListItemModel

/** The devices on the phone's hotspot and tethering: their rules, as an app's. */
object HotspotPageProvider : SettingsPageProvider {
    override val name = "Hotspot"

    @Composable fun navigator() = navigator(route = name)

    @Composable
    override fun Page(arguments: Bundle?) {
        val appRules by
            remember { Firewall.appRules(UserHandle.USER_SYSTEM) }.collectAsStateWithLifecycle(null)
        RegularScaffold(title = stringResource(R.string.hotspot_title)) {
            RulesControls(IFirewall.HOTSPOT_PACKAGE, UserHandle.USER_SYSTEM, appRules)
            Footer(stringResource(R.string.hotspot_footer))
        }
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

/** Tethering never goes out through a VPN, so the hotspot's devices get no VPN switch or choice. */
fun hasVpnChoices(packageName: String) = packageName != IFirewall.HOTSPOT_PACKAGE

/** The switch's summary on the page, where the hotspot's devices have no Data Saver. */
fun Network.summaryOn(packageName: String) =
    if (this == Network.METERED && packageName == IFirewall.HOTSPOT_PACKAGE) {
        R.string.hotspot_metered_summary
    } else {
        summary
    }
