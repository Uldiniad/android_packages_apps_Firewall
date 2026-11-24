/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall

import android.content.Context
import android.os.Bundle
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavType
import androidx.navigation.navArgument
import com.android.settingslib.spa.framework.common.SettingsPageProvider
import com.android.settingslib.spa.framework.compose.navigator
import com.android.settingslib.spa.widget.dialog.AlertDialogButton
import com.android.settingslib.spa.widget.dialog.rememberAlertDialogPresenter
import com.android.settingslib.spa.widget.scaffold.MoreOptionsAction
import com.android.settingslib.spa.widget.scaffold.SearchScaffold
import com.android.settingslib.spa.widget.ui.SettingsBody
import com.android.settingslib.spaprivileged.R as SpaPrivilegedR
import com.android.settingslib.spaprivileged.template.app.AppList
import com.android.settingslib.spaprivileged.template.app.AppListConfig
import com.android.settingslib.spaprivileged.template.app.AppListInput
import com.android.settingslib.spaprivileged.template.app.AppListItem
import com.android.settingslib.spaprivileged.template.app.AppListItemModel
import com.android.settingslib.spaprivileged.template.app.AppListState
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch

/** The apps of the group's user that aren't in it, which ask before joining it. */
object GroupAppsPageProvider : SettingsPageProvider {
    private const val GROUP_ID = "rt_groupId"
    private const val USER_ID = "rt_userId"

    override val name = "GroupApps"

    override val parameter =
        listOf(
            navArgument(GROUP_ID) { type = NavType.StringType },
            navArgument(USER_ID) { type = NavType.IntType },
        )

    @Composable fun navigator(id: String, userId: Int) = navigator(route = "$name/$id/$userId")

    @Composable
    override fun Page(arguments: Bundle?) {
        val args = checkNotNull(arguments)
        GroupAppsPage(checkNotNull(args.getString(GROUP_ID)), args.getInt(USER_ID))
    }
}

@Composable
private fun GroupAppsPage(id: String, userId: Int) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var showSystem by rememberSaveable { mutableStateOf(false) }
    var chosen by rememberSaveable { mutableStateOf<String?>(null) }
    var chosenLabel by rememberSaveable { mutableStateOf("") }
    var chosenHasRules by rememberSaveable { mutableStateOf(false) }
    val groups by remember(userId) { Firewall.groups(userId) }.collectAsStateWithLifecycle(null)
    val groupName = groups?.find { it.id == id }?.name.orEmpty()
    val ask =
        rememberAlertDialogPresenter(
            confirmButton =
                AlertDialogButton(stringResource(R.string.add)) {
                    val packageName = chosen ?: return@AlertDialogButton
                    scope.launch { Firewall.call { setAppGroup(packageName, userId, id) } }
                    BlockedAppNotification.cancel(context, packageName)
                },
            dismissButton = AlertDialogButton(stringResource(android.R.string.cancel)),
            title = stringResource(R.string.add_to_group_title, chosenLabel, groupName),
            text = {
                SettingsBody(
                    stringResource(
                        if (chosenHasRules) R.string.add_to_group_text_rules
                        else R.string.add_to_group_text,
                        groupName,
                    )
                )
            },
        )
    val listModel =
        remember(id) {
            GroupAppsListModel(context, id) { record, label ->
                chosen = record.app.packageName
                chosenLabel = label
                chosenHasRules = hasOwnRules(record.rule)
                ask.open()
            }
        }
    SearchScaffold(
        title = stringResource(R.string.add_apps),
        actions = {
            MoreOptionsAction {
                MenuItem(
                    stringResource(
                        if (showSystem) SpaPrivilegedR.string.menu_hide_system
                        else SpaPrivilegedR.string.menu_show_system
                    )
                ) {
                    showSystem = !showSystem
                }
            }
        },
    ) { bottomPadding, searchQuery ->
        // Only the group's user, as a group's apps are all of one user or profile.
        AppListInput(
                config = AppListConfig(listOf(userId), false, false),
                listModel = listModel,
                state = AppListState({ showSystem }, searchQuery),
                header = {},
                bottomPadding = bottomPadding,
            )
            .AppList()
    }
}

/** Whether the app has switches or rules of its own, which joining a group deletes. */
private fun hasOwnRules(rule: AppRule?) =
    rule != null &&
        (rule.rules != 0 ||
            rule.ruleCount > 0 ||
            rule.pauseUntil != 0L ||
            rule.scheduleDays != 0 ||
            !rule.allowedNetworks.isNullOrEmpty() ||
            !rule.blockedNetworks.isNullOrEmpty())

private class GroupAppsListModel(
    context: Context,
    private val id: String,
    private val pick: (FirewallAppRecord, String) -> Unit,
) : FirewallAppListModel(context) {
    override fun filter(
        userIdFlow: Flow<Int>,
        option: Int,
        recordListFlow: Flow<List<FirewallAppRecord>>,
    ) =
        super.filter(userIdFlow, option, recordListFlow).map { records ->
            records.filter { it.rule?.group != id }
        }

    @Composable
    override fun AppListItemModel<FirewallAppRecord>.AppItem() {
        AppListItem(onClick = { pick(record, label) })
    }
}
