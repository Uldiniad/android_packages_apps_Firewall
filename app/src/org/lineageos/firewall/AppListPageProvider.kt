/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall

import android.Manifest
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Bundle
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.android.settingslib.spa.framework.common.SettingsPageProvider
import com.android.settingslib.spa.widget.preference.StatusBannerLevel
import com.android.settingslib.spa.widget.preference.StatusBannerPreference
import com.android.settingslib.spa.widget.preference.StatusBannerPreferenceModel
import com.android.settingslib.spa.widget.ui.Category
import com.android.settingslib.spaprivileged.model.app.AppListModel
import com.android.settingslib.spaprivileged.model.app.AppRecord
import com.android.settingslib.spaprivileged.template.app.AppList
import com.android.settingslib.spaprivileged.template.app.AppListItem
import com.android.settingslib.spaprivileged.template.app.AppListItemModel
import com.android.settingslib.spaprivileged.template.app.AppListPage
import com.android.settingslib.spaprivileged.template.app.isSystemOrRootUid
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.map

/** The home page: each user's apps with their rules, below that user's own settings. */
object AppListPageProvider : SettingsPageProvider {
    override val name = "AppList"

    @Composable
    override fun Page(arguments: Bundle?) {
        val context = LocalContext.current
        AppListPage(
            title = stringResource(R.string.app_name),
            listModel = remember { FirewallAppListModel(context) },
            appList = {
                val userId = config.userIds.first()
                copy(header = { if (state.searchQuery().isEmpty()) UserSettings(userId) }).AppList()
            },
        )
    }
}

data class FirewallAppRecord(
    override val app: ApplicationInfo,
    val rule: AppRule?,
    val usesInternet: Boolean,
) : AppRecord

private class FirewallAppListModel(private val context: Context) : AppListModel<FirewallAppRecord> {
    @OptIn(ExperimentalCoroutinesApi::class)
    override fun transform(userIdFlow: Flow<Int>, appListFlow: Flow<List<ApplicationInfo>>) =
        appListFlow
            .map { apps -> apps.map { it to usesInternet(it) } }
            .combine(userIdFlow.flatMapLatest { Firewall.appRules(it) }) { apps, rules ->
                apps.map { (app, usesInternet) ->
                    FirewallAppRecord(app, rules[app.packageName], usesInternet)
                }
            }

    // As in Datura, system apps that can't use the internet have nothing to block. Root and the
    // system server are never firewalled, so as in Spa's own lists their apps aren't shown.
    override fun filter(
        userIdFlow: Flow<Int>,
        option: Int,
        recordListFlow: Flow<List<FirewallAppRecord>>,
    ) =
        recordListFlow.map { records ->
            records.filter { (it.usesInternet || !it.app.isSystemApp) && !it.isSystemOrRootUid() }
        }

    @Composable
    override fun getSummary(option: Int, record: FirewallAppRecord): () -> CharSequence = {
        context.rulesSummary(record.rule, record.usesInternet)
    }

    @Composable
    override fun AppListItemModel<FirewallAppRecord>.AppItem() {
        AppListItem(onClick = AppRulesPageProvider.navigator(record.app))
    }

    private fun usesInternet(app: ApplicationInfo) =
        context.checkPermission(Manifest.permission.INTERNET, -1, app.uid) ==
            PackageManager.PERMISSION_GRANTED
}

/** The settings of one user, or profile, each feature's entries in turn. */
@Composable
private fun UserSettings(userId: Int) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val running by remember { Firewall.running() }.collectAsStateWithLifecycle(true)
    if (!running) {
        StatusBannerPreference(
            object : StatusBannerPreferenceModel {
                override val title = stringResource(R.string.firewall_not_running)
                override val iconLevel = StatusBannerLevel.HIGH
            }
        )
    }
    Category {
        NewAppsPreferences(userId)
    }
}
