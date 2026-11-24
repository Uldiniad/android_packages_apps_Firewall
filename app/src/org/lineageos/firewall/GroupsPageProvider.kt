/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.content.pm.PackageManager.ApplicationInfoFlags
import android.os.Bundle
import android.os.UserHandle
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Add
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavType
import androidx.navigation.navArgument
import com.android.settingslib.spa.framework.common.SettingsPageProvider
import com.android.settingslib.spa.framework.compose.LocalNavController
import com.android.settingslib.spa.framework.compose.navigator
import com.android.settingslib.spa.widget.dialog.AlertDialogButton
import com.android.settingslib.spa.widget.dialog.rememberAlertDialogPresenter
import com.android.settingslib.spa.widget.preference.Preference
import com.android.settingslib.spa.widget.preference.PreferenceModel
import com.android.settingslib.spa.widget.scaffold.RegularScaffold
import com.android.settingslib.spa.widget.ui.Category
import com.android.settingslib.spa.widget.ui.Footer
import com.android.settingslib.spa.widget.ui.SettingsBody
import com.android.settingslib.spa.widget.ui.SettingsIcon
import com.android.settingslib.spaprivileged.template.app.AppListItem
import com.android.settingslib.spaprivileged.template.app.AppListItemModel
import java.text.Collator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** One user's groups of apps. */
object GroupsPageProvider : SettingsPageProvider {
    private const val USER_ID = "rt_userId"

    override val name = "Groups"

    override val parameter = listOf(navArgument(USER_ID) { type = NavType.IntType })

    @Composable fun navigator(userId: Int) = navigator(route = "$name/$userId")

    @Composable
    override fun Page(arguments: Bundle?) {
        GroupsPage(checkNotNull(arguments).getInt(USER_ID))
    }
}

/** One group: its rules, as an app's, and its apps. */
object GroupPageProvider : SettingsPageProvider {
    private const val GROUP_ID = "rt_groupId"
    private const val USER_ID = "rt_userId"

    override val name = "Group"

    override val parameter =
        listOf(
            navArgument(GROUP_ID) { type = NavType.StringType },
            navArgument(USER_ID) { type = NavType.IntType },
        )

    fun route(id: String, userId: Int) = "$name/$id/$userId"

    @Composable fun navigator(id: String, userId: Int) = navigator(route = route(id, userId))

    @Composable
    override fun Page(arguments: Bundle?) {
        val args = checkNotNull(arguments)
        GroupPage(checkNotNull(args.getString(GROUP_ID)), args.getInt(USER_ID))
    }
}

@Composable
private fun GroupsPage(userId: Int) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val navController = LocalNavController.current
    val groups by remember(userId) { Firewall.groups(userId) }.collectAsStateWithLifecycle(null)
    val appRules by remember(userId) { Firewall.appRules(userId) }.collectAsStateWithLifecycle(null)
    val add =
        rememberGroupNameDialog(R.string.add_group, R.string.add, "") { name ->
            scope.launch {
                val id = Firewall.call { addGroup(userId, name) }
                navController.navigate(GroupPageProvider.route(id, userId))
            }
        }
    RegularScaffold(title = stringResource(R.string.groups_title)) {
        Category {
            Preference(
                object : PreferenceModel {
                    override val title = stringResource(R.string.add_group)
                    override val icon = @Composable { SettingsIcon(Icons.Outlined.Add) }
                    override val onClick = add
                }
            )
            val shown = groups?.sortedWith(compareBy(Collator.getInstance()) { it.name })
            if (shown?.isEmpty() == true) {
                Preference(
                    object : PreferenceModel {
                        override val title = stringResource(R.string.no_groups)
                    }
                )
            }
            for (group in shown.orEmpty()) {
                val count = appRules?.values?.count { it.group == group.id } ?: 0
                key(group.id) {
                    Preference(
                        object : PreferenceModel {
                            override val title = group.name
                            override val summary = { context.groupAppCount(count) }
                            override val onClick = GroupPageProvider.navigator(group.id, userId)
                        }
                    )
                }
            }
        }
        Footer(stringResource(R.string.groups_footer))
    }
}

@Composable
private fun GroupPage(id: String, userId: Int) {
    val scope = rememberCoroutineScope()
    val navController = LocalNavController.current
    val groups by remember(userId) { Firewall.groups(userId) }.collectAsStateWithLifecycle(null)
    val appRules by remember(userId) { Firewall.appRules(userId) }.collectAsStateWithLifecycle(null)
    val group = groups?.find { it.id == id }
    if (groups != null && group == null) {
        // Deleted, here or elsewhere.
        LaunchedEffect(Unit) { navController.navigateBack() }
        return
    }
    val name = group?.name.orEmpty()
    val rename =
        rememberGroupNameDialog(R.string.rename_group_title, R.string.rename_group, name) {
            newName ->
            scope.launch { Firewall.call { renameGroup(userId, id, newName) } }
        }
    val delete =
        rememberAlertDialogPresenter(
            confirmButton =
                AlertDialogButton(stringResource(R.string.delete)) {
                    scope.launch { Firewall.call { removeGroup(userId, id) } }
                },
            dismissButton = AlertDialogButton(stringResource(android.R.string.cancel)),
            title = stringResource(R.string.delete_group_title, name),
            text = { SettingsBody(stringResource(R.string.delete_group_text)) },
        )
    RegularScaffold(title = name) {
        RulesControls(groupPackage(id), userId, appRules)
        GroupApps(id, userId, appRules)
        Category {
            Preference(
                object : PreferenceModel {
                    override val title = stringResource(R.string.rename_group)
                    override val onClick = rename
                }
            )
            Preference(
                object : PreferenceModel {
                    override val title = stringResource(R.string.delete_group)
                    override val onClick = delete::open
                }
            )
        }
        Footer(stringResource(R.string.group_footer))
    }
}

/** The group's apps, which open their own pages, and the way to add more. */
@Composable
private fun GroupApps(id: String, userId: Int, appRules: Map<String, AppRule>?) {
    val context = LocalContext.current
    val members = appRules?.values?.filter { it.group == id }
    val apps by
        produceState<List<Pair<FirewallAppRecord, String>>?>(null, members, userId) {
            value = members?.let { withContext(Dispatchers.IO) { context.labeledApps(userId, it) } }
        }
    Category(title = stringResource(R.string.group_apps)) {
        if (apps?.isEmpty() == true) {
            Preference(
                object : PreferenceModel {
                    override val title = stringResource(R.string.no_group_apps)
                }
            )
        }
        for ((record, label) in apps.orEmpty()) {
            key(record.app.packageName) {
                AppListItemModel(record, label) { "" }
                    .AppListItem(onClick = AppRulesPageProvider.navigator(record.app))
            }
        }
        Preference(
            object : PreferenceModel {
                override val title = stringResource(R.string.add_apps)
                override val icon = @Composable { SettingsIcon(Icons.Outlined.Add) }
                override val onClick = GroupAppsPageProvider.navigator(id, userId)
            }
        )
    }
}

/** The installed apps of the rules, with their labels, in the order of their labels. */
private fun Context.labeledApps(
    userId: Int,
    rules: List<AppRule>,
): List<Pair<FirewallAppRecord, String>> {
    val pm = createContextAsUser(UserHandle.of(userId), 0).packageManager
    return rules
        .mapNotNull { rule ->
            val app: ApplicationInfo =
                try {
                    pm.getApplicationInfo(rule.packageName, ApplicationInfoFlags.of(0))
                } catch (e: PackageManager.NameNotFoundException) {
                    return@mapNotNull null
                }
            FirewallAppRecord(app, rule, usesInternet = true) to app.loadLabel(pm).toString()
        }
        .sortedWith(compareBy(Collator.getInstance()) { it.second })
}
