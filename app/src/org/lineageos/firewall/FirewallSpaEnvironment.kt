/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall

import android.content.Context
import com.android.settingslib.spa.framework.common.SettingsPageProviderRepository
import com.android.settingslib.spa.framework.common.SpaEnvironment
import com.android.settingslib.spa.framework.common.createSettingsPage
import com.android.settingslib.widget.SettingsThemeHelper

class FirewallSpaEnvironment(context: Context) : SpaEnvironment(context) {
    override val pageProviderRepository = lazy {
        SettingsPageProviderRepository(
            allPageProviders =
                listOf(
                    AppListPageProvider,
                    AppRulesPageProvider,
                    SpecificNetworksPageProvider,
                    SchedulePageProvider,
                    AddAppRulesPageProvider,
                    AllAppsRulesPageProvider,
                    AddRulesPageProvider,
                    ExportImportPageProvider,
                    AddListPageProvider,
                    AddAppListPageProvider,
                    GroupsPageProvider,
                    GroupPageProvider,
                    GroupAppsPageProvider,
                    ActivityPageProvider,
                    ActivityEntryPageProvider,
                    AddEntryRulePageProvider,
                    HotspotPageProvider,
                    HotspotDevicePageProvider,
                ),
            rootPages = listOf(AppListPageProvider.createSettingsPage()),
        )
    }

    override val browseActivityClass = MainActivity::class.java

    // Looks like Settings, which links here.
    override val isSpaExpressiveEnabled by lazy {
        SettingsThemeHelper.isExpressiveTheme(appContext)
    }
}
