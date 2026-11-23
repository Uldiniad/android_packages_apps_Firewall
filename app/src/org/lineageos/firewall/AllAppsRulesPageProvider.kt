/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall

import android.os.Bundle
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Block
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.Dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavType
import androidx.navigation.navArgument
import com.android.settingslib.spa.framework.common.SettingsPageProvider
import com.android.settingslib.spa.framework.compose.navigator
import com.android.settingslib.spa.widget.preference.Preference
import com.android.settingslib.spa.widget.preference.PreferenceModel
import com.android.settingslib.spa.widget.preference.ZeroStatePreference
import com.android.settingslib.spa.widget.scaffold.SearchScaffold
import com.android.settingslib.spa.widget.scaffold.SettingsPager
import com.android.settingslib.spa.widget.ui.Category
import com.android.settingslib.spa.widget.ui.LazyCategory
import com.android.settingslib.spa.widget.ui.SettingsIcon

/** The rules for all of one user's apps, a tab per kind. */
object AllAppsRulesPageProvider : SettingsPageProvider {
    private const val USER_ID = "rt_userId"

    override val name = "AllAppsRules"

    override val parameter = listOf(navArgument(USER_ID) { type = NavType.IntType })

    fun route(userId: Int) = "$name/$userId"

    @Composable fun navigator(userId: Int) = navigator(route = route(userId))

    @Composable
    override fun Page(arguments: Bundle?) {
        AllAppsRulesPage(checkNotNull(arguments).getInt(USER_ID))
    }
}

@Composable
private fun AllAppsRulesPage(userId: Int) {
    val rules by remember(userId) { Firewall.rules(userId, null) }.collectAsStateWithLifecycle(null)
    SearchScaffold(title = stringResource(R.string.all_apps_rules)) { bottomPadding, searchQuery ->
        val kinds = RuleKind.entries
        val titles = kinds.map { stringResource(it.title) } + stringResource(R.string.kind_lists)
        SettingsPager(titles) { page ->
            if (page < kinds.size) {
                RuleList(rules, kinds[page], userId, bottomPadding, searchQuery)
            } else {
                ListsTab(userId, bottomPadding, searchQuery)
            }
        }
    }
}

@Composable
private fun RuleList(
    rules: List<FirewallRule>?,
    kind: RuleKind,
    userId: Int,
    bottomPadding: Dp,
    searchQuery: () -> String,
) {
    val add = AddRulesPageProvider.navigator(userId, kind)
    val remove = rememberRemoveRuleDialog()
    val names = rememberNetworkNames(userId)
    val shown =
        rules?.filter { rule ->
            kind.covers(rule) &&
                listOfNotNull(rule.value, rule.port).any {
                    it.contains(searchQuery(), ignoreCase = true)
                }
        } ?: return
    LazyCategory(
        count = shown.size,
        key = {
            with(shown[it]) {
                "$kind:$allow:$value:$subdomains:$protocol:$port:$exceptNetworks:" +
                    "${networks?.toList()}"
            }
        },
        bottomPadding = bottomPadding,
        header = {
            Category {
                Preference(
                    object : PreferenceModel {
                        override val title = stringResource(kind.add)
                        override val icon = @Composable { SettingsIcon(Icons.Outlined.Add) }
                        override val onClick = add
                    }
                )
            }
            if (shown.isEmpty())
                ZeroStatePreference(Icons.Outlined.Block, stringResource(kind.empty))
        },
    ) { index ->
        RuleRow(shown[index], names, remove)
    }
}

/** The app list's entry for the rules for all of the user's apps. */
@Composable
fun AllAppsRulesEntry(userId: Int) {
    val context = LocalContext.current
    val rules by remember(userId) { Firewall.rules(userId, null) }.collectAsStateWithLifecycle(null)
    Preference(
        object : PreferenceModel {
            override val title = stringResource(R.string.all_apps_rules)
            override val summary = { context.allAppsRulesSummary(rules.orEmpty()) }
            override val onClick = AllAppsRulesPageProvider.navigator(userId)
        }
    )
}
