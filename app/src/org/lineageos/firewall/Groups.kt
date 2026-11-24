/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall

import android.content.Context
import androidx.annotation.StringRes
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.android.settingslib.spa.framework.theme.SettingsDimension
import com.android.settingslib.spa.widget.dialog.AlertDialogButton
import com.android.settingslib.spa.widget.dialog.rememberAlertDialogPresenter
import com.android.settingslib.spa.widget.editor.SettingsOutlinedTextField
import com.android.settingslib.spa.widget.preference.Preference
import com.android.settingslib.spa.widget.preference.PreferenceModel
import com.android.settingslib.spa.widget.ui.Category
import kotlinx.coroutines.launch

/** The user's groups of apps, which follow their group's rules instead of their own. */
fun Firewall.groups(userId: Int) = load { getGroups(userId).toList() }

/** The package name the service knows a group's rules by. */
fun groupPackage(id: String) = IFirewall.GROUP_PREFIX + id

fun Context.groupAppCount(count: Int): String =
    if (count == 0) getString(R.string.no_group_apps)
    else resources.getQuantityString(R.plurals.group_app_count, count, count)

/** The app list's entry for the user's groups. */
@Composable
fun GroupsEntry(userId: Int) {
    val context = LocalContext.current
    val groups by remember(userId) { Firewall.groups(userId) }.collectAsStateWithLifecycle(null)
    Preference(
        object : PreferenceModel {
            override val title = stringResource(R.string.groups_title)
            override val summary = {
                val count = groups?.size ?: 0
                if (count == 0) context.getString(R.string.groups_none)
                else context.resources.getQuantityString(R.plurals.group_count, count, count)
            }
            override val onClick = GroupsPageProvider.navigator(userId)
        }
    )
}

/** Asks for a group's name, starting from [current]; returns what opens the question. */
@Composable
fun rememberGroupNameDialog(
    @StringRes title: Int,
    @StringRes confirm: Int,
    current: String,
    done: (String) -> Unit,
): () -> Unit {
    var name by rememberSaveable { mutableStateOf("") }
    val dialog =
        rememberAlertDialogPresenter(
            confirmButton =
                AlertDialogButton(stringResource(confirm), enabled = name.isNotBlank()) {
                    done(name.trim())
                },
            dismissButton = AlertDialogButton(stringResource(android.R.string.cancel)),
            title = stringResource(title),
            text = {
                val focus = remember { FocusRequester() }
                SettingsOutlinedTextField(
                    value = name,
                    label = stringResource(R.string.group_name),
                    modifier =
                        Modifier.fillMaxWidth()
                            .padding(SettingsDimension.textFieldPadding)
                            .focusRequester(focus),
                ) {
                    name = it
                }
                LaunchedEffect(Unit) { focus.requestFocus() }
            },
        )
    return {
        name = current
        dialog.open()
    }
}

/** What an app in a group has instead of its own switches and rules: its group, and a way out. */
@Composable
fun GroupMembership(packageName: String, userId: Int, rule: AppRule) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    Category {
        Preference(
            object : PreferenceModel {
                override val title = stringResource(R.string.follows_group, rule.groupName.orEmpty())
                override val summary = { context.getString(R.string.follows_group_summary) }
                override val onClick = GroupPageProvider.navigator(checkNotNull(rule.group), userId)
            }
        )
        Preference(
            object : PreferenceModel {
                override val title = stringResource(R.string.leave_group)
                override val summary = { context.getString(R.string.leave_group_summary) }
                override val onClick: () -> Unit = {
                    scope.launch { Firewall.call { setAppGroup(packageName, userId, null) } }
                }
            }
        )
    }
}
