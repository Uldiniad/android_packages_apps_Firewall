/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall

import android.os.Bundle
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.navigation.NavType
import androidx.navigation.navArgument
import com.android.settingslib.spa.framework.common.SettingsPageProvider
import com.android.settingslib.spa.framework.compose.LocalNavController
import com.android.settingslib.spa.framework.compose.navigator
import com.android.settingslib.spa.widget.editor.SettingsDropdownBox
import com.android.settingslib.spa.widget.editor.SettingsDropdownCheckBox
import com.android.settingslib.spa.widget.editor.SettingsDropdownCheckOption
import com.android.settingslib.spa.widget.editor.SettingsOutlinedTextField
import com.android.settingslib.spa.widget.preference.SwitchPreference
import com.android.settingslib.spa.widget.preference.SwitchPreferenceModel
import com.android.settingslib.spa.widget.scaffold.RegularScaffold
import kotlinx.coroutines.launch

private const val USER_ID = "rt_userId"
private const val PACKAGE_NAME = "rt_packageName"
private const val KIND = "rt_kind"
private val PROTOCOLS = listOf(0, IFirewall.PROTOCOL_TCP, IFirewall.PROTOCOL_UDP)
private const val ALL_NETWORKS = 0
private const val ALL_EXCEPT = 2

/** Adds rules of one kind for all of a user's apps. */
object AddRulesPageProvider : SettingsPageProvider {
    override val name = "AddRules"

    override val parameter =
        listOf(
            navArgument(USER_ID) { type = NavType.IntType },
            navArgument(KIND) { type = NavType.StringType },
        )

    @Composable
    fun navigator(userId: Int, kind: RuleKind) = navigator(route = "$name/$userId/${kind.name}")

    @Composable
    override fun Page(arguments: Bundle?) {
        val args = checkNotNull(arguments)
        val kind = RuleKind.valueOf(checkNotNull(args.getString(KIND)))
        AddRulesPage(args.getInt(USER_ID), null, kind)
    }
}

/** Adds rules for one app, of a kind chosen on the page. */
object AddAppRulesPageProvider : SettingsPageProvider {
    override val name = "AddAppRules"

    override val parameter =
        listOf(
            navArgument(PACKAGE_NAME) { type = NavType.StringType },
            navArgument(USER_ID) { type = NavType.IntType },
        )

    @Composable
    fun navigator(packageName: String, userId: Int) =
        navigator(route = "$name/$packageName/$userId")

    @Composable
    override fun Page(arguments: Bundle?) {
        val args = checkNotNull(arguments)
        AddRulesPage(args.getInt(USER_ID), checkNotNull(args.getString(PACKAGE_NAME)), null)
    }
}

/**
 * Adds rules, one per line, the way Settings' APN editor adds an APN. Lines the service rejects
 * stay on the page to fix.
 */
@Composable
private fun AddRulesPage(userId: Int, packageName: String?, kind: RuleKind?) {
    val scope = rememberCoroutineScope()
    val navController = LocalNavController.current
    var chosenKind by rememberSaveable { mutableStateOf(RuleKind.DOMAIN) }
    var allow by rememberSaveable { mutableStateOf(false) }
    var subdomains by rememberSaveable { mutableStateOf(true) }
    var protocol by rememberSaveable { mutableIntStateOf(0) }
    var text by rememberSaveable { mutableStateOf("") }
    var invalid by rememberSaveable { mutableStateOf(false) }
    var limit by rememberSaveable { mutableIntStateOf(ALL_NETWORKS) }
    var networks by rememberSaveable { mutableStateOf(listOf<String>()) }
    val shown = kind ?: chosenKind
    RegularScaffold(
        title = stringResource(kind?.add ?: R.string.add_rule),
        actions = {
            Button(
                onClick = {
                    val lines = text.lines().map { it.trim() }.filter { it.isNotEmpty() }
                    val rules =
                        lines.map { value ->
                            FirewallRule().also {
                                it.packageName = packageName
                                it.userId = userId
                                it.allow = allow
                                it.kind = shown.kind
                                it.value = value
                                it.subdomains = subdomains
                                it.protocol = protocol
                                if (limit != ALL_NETWORKS) it.networks = networks.toTypedArray()
                                it.exceptNetworks = limit == ALL_EXCEPT
                            }
                        }
                    scope.launch {
                        val rejected = Firewall.call { addRules(rules.toTypedArray()) }
                        if (rejected.isEmpty()) {
                            navController.navigateBack()
                        } else {
                            text = rejected.joinToString("\n") { lines[it] }
                            invalid = true
                        }
                    }
                },
                enabled = text.isNotBlank() && (limit == ALL_NETWORKS || networks.isNotEmpty()),
            ) {
                Text(stringResource(R.string.add))
            }
        },
    ) {
        SettingsDropdownBox(
            label = stringResource(R.string.action_label),
            options = listOf(R.string.action_block, R.string.action_allow).map { stringResource(it) },
            selectedOptionIndex = if (allow) 1 else 0,
        ) {
            allow = it == 1
        }
        if (kind == null) {
            SettingsDropdownBox(
                label = stringResource(R.string.kind_label),
                options = RuleKind.entries.map { stringResource(it.title) },
                selectedOptionIndex = chosenKind.ordinal,
            ) {
                chosenKind = RuleKind.entries[it]
                invalid = false
            }
        }
        SettingsOutlinedTextField(
            value = text,
            label = stringResource(shown.title),
            errorMessage =
                when {
                    !invalid -> null
                    limit == ALL_NETWORKS -> stringResource(shown.invalid)
                    else -> stringResource(R.string.invalid_or_too_many_networks)
                },
            singleLine = false,
            placeholder = { Text(stringResource(shown.hint)) },
        ) {
            text = it
            invalid = false
        }
        when (shown) {
            RuleKind.DOMAIN ->
                SwitchPreference(
                    object : SwitchPreferenceModel {
                        override val title = stringResource(R.string.include_subdomains)
                        override val checked = { subdomains }
                        override val onCheckedChange: (Boolean) -> Unit = { subdomains = it }
                    }
                )
            RuleKind.PORT ->
                SettingsDropdownBox(
                    label = stringResource(R.string.protocol_label),
                    options =
                        listOf(R.string.protocol_both, R.string.protocol_tcp, R.string.protocol_udp)
                            .map { stringResource(it) },
                    selectedOptionIndex = PROTOCOLS.indexOf(protocol),
                ) {
                    protocol = PROTOCOLS[it]
                }
            RuleKind.ADDRESS -> {}
        }
        SettingsDropdownBox(
            label = stringResource(R.string.networks_label),
            options =
                listOf(R.string.networks_all, R.string.networks_only, R.string.networks_except)
                    .map { stringResource(it) },
            selectedOptionIndex = limit,
        ) {
            limit = it
            invalid = false
        }
        if (limit != ALL_NETWORKS) ChosenNetworks(networks) { networks = it }
    }
}

/** The networks rules are limited to: each kind. */
@Composable
private fun ChosenNetworks(chosen: List<String>, onChange: (List<String>) -> Unit) {
    val context = LocalContext.current
    val options =
        remember {
            val kinds = Network.entries.map { it.key to context.getString(it.title) }
            kinds.map { (key, label) ->
                key to SettingsDropdownCheckOption(label, selected = mutableStateOf(key in chosen))
            }
        }
    SettingsDropdownCheckBox(
        label = stringResource(R.string.networks_chosen),
        options = options.map { it.second },
    ) {
        onChange(options.filter { it.second.selected.value }.map { it.first })
    }
}
