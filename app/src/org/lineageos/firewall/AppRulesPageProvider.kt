/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.os.UserHandle
import android.provider.Settings
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavType
import androidx.navigation.navArgument
import com.android.settingslib.spa.framework.common.SettingsPageProvider
import com.android.settingslib.spa.framework.compose.navigator
import com.android.settingslib.spa.widget.preference.MainSwitchPreference
import com.android.settingslib.spa.widget.preference.Preference
import com.android.settingslib.spa.widget.preference.PreferenceModel
import com.android.settingslib.spa.widget.preference.SwitchPreference
import com.android.settingslib.spa.widget.preference.SwitchPreferenceModel
import com.android.settingslib.spa.widget.ui.Category
import com.android.settingslib.spa.widget.ui.SettingsBody
import com.android.settingslib.spaprivileged.model.app.PackageManagers
import com.android.settingslib.spaprivileged.model.app.userId
import com.android.settingslib.spaprivileged.template.app.AppInfoPage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** One app's rules, for one user. */
object AppRulesPageProvider : SettingsPageProvider {
    private const val PACKAGE_NAME = "rt_packageName"
    private const val USER_ID = "rt_userId"

    override val name = "AppRules"

    override val parameter =
        listOf(
            navArgument(PACKAGE_NAME) { type = NavType.StringType },
            navArgument(USER_ID) { type = NavType.IntType },
        )

    fun route(packageName: String, userId: Int) = "$name/$packageName/$userId"

    @Composable
    fun navigator(app: ApplicationInfo) = navigator(route = route(app.packageName, app.userId))

    @Composable
    override fun Page(arguments: Bundle?) {
        val args = checkNotNull(arguments)
        AppRulesPage(checkNotNull(args.getString(PACKAGE_NAME)), args.getInt(USER_ID))
    }
}

@Composable
private fun AppRulesPage(packageName: String, userId: Int) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val appRules by remember(userId) { Firewall.appRules(userId) }.collectAsStateWithLifecycle(null)
    val rule = appRules?.get(packageName)
    // Null while loading; an app without rules is allowed everywhere.
    val rules = appRules?.let { rule?.rules ?: 0 }
    val change: (Int) -> Unit = { newRules ->
        scope.launch { Firewall.call { setAppRules(packageName, userId, newRules) } }
        BlockedAppNotification.cancel(context, packageName)
    }
    AppInfoPage(
        title = stringResource(R.string.app_rules_title),
        packageName = packageName,
        userId = userId,
        footerContent = { AppRulesFooter(packageName, userId, rule) },
        packageManagers = PackageManagers,
    ) {
        val allowed = rules != null && rules and IFirewall.BLOCK_ALL == 0
        MainSwitchPreference(
            object : SwitchPreferenceModel {
                override val title = stringResource(R.string.allow_network_access)
                override val checked = { rules?.let { it and IFirewall.BLOCK_ALL == 0 } }
                override val onCheckedChange: (Boolean) -> Unit = {
                    change((rules ?: 0).with(IFirewall.BLOCK_ALL, !it))
                }
            }
        )
        ScheduleEntries(packageName, userId, rule)
        Category(title = stringResource(R.string.networks_title)) {
            for (network in Network.entries) {
                SwitchPreference(
                    object : SwitchPreferenceModel {
                        override val title = stringResource(network.title)
                        override val summary = {
                            network.summary?.let { context.getString(it) } ?: ""
                        }
                        override val checked = { rules?.let { it and network.rule == 0 } }
                        override val changeable = { allowed }
                        override val onCheckedChange: (Boolean) -> Unit = {
                            change((rules ?: 0).with(network.rule, !it))
                        }
                    }
                )
            }
            SpecificNetworksEntry(packageName, userId, rule, allowed)
        }
        TargetRules(packageName, userId)
        Category {
            DataUsagePreference(userId)
        }
    }
}

/** Android's own page for the app's background data and Data Saver exemption. */
@Composable
private fun PackageInfo.DataUsagePreference(userId: Int) {
    val context = LocalContext.current
    Preference(
        object : PreferenceModel {
            override val title = stringResource(R.string.data_usage)
            override val onClick = {
                context.startActivityAsUser(
                    Intent(
                        Settings.ACTION_IGNORE_BACKGROUND_DATA_RESTRICTIONS_SETTINGS,
                        Uri.fromParts("package", packageName, null),
                    ),
                    UserHandle.of(userId),
                )
            }
        }
    )
}

@Composable
private fun AppRulesFooter(packageName: String, userId: Int, rule: AppRule?) {
    val context = LocalContext.current
    val shared by
        produceState(emptyList<CharSequence>(), packageName, userId) {
            value = withContext(Dispatchers.IO) { sharedAppLabels(context, packageName, userId) }
        }
    val paragraphs = buildList {
        context.newAppFooter(rule)?.let { add(it) }
        if (shared.isNotEmpty()) {
            add(context.getString(R.string.app_rules_footer_shared, context.formatList(shared)))
        }
        add(context.getString(R.string.app_rules_footer))
        add(context.rulesFooter())
    }
    SettingsBody(paragraphs.joinToString("\n\n"))
}

/** Apps sharing the app's uid, which the firewall gives the same rules. */
private fun sharedAppLabels(
    context: Context,
    packageName: String,
    userId: Int,
): List<CharSequence> {
    val pm = context.createContextAsUser(UserHandle.of(userId), 0).packageManager
    val uid =
        try {
            pm.getPackageUid(packageName, 0)
        } catch (e: PackageManager.NameNotFoundException) {
            return emptyList()
        }
    return pm.getPackagesForUid(uid)
        .orEmpty()
        .filter { it != packageName }
        .mapNotNull {
            try {
                pm.getApplicationInfo(it, 0).loadLabel(pm)
            } catch (e: PackageManager.NameNotFoundException) {
                null
            }
        }
}
