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
import androidx.lifecycle.compose.collectAsStateWithLifecycle
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
import com.android.settingslib.spa.widget.ui.Footer
import kotlinx.coroutines.launch

private const val USER_ID = "rt_userId"
private const val PACKAGE_NAME = "rt_packageName"
private const val KIND = "rt_kind"
private val PROTOCOLS = listOf(0, IFirewall.PROTOCOL_TCP, IFirewall.PROTOCOL_UDP)
private const val ALL_NETWORKS = 0
private const val ALL_EXCEPT = 2
private const val FROM_ANYONE = 0
private const val FROM_LOCAL_NETWORK = 1
private const val FROM_ADDRESS = 2

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
    var port by rememberSaveable { mutableStateOf("") }
    var portInvalid by rememberSaveable { mutableStateOf(false) }
    var text by rememberSaveable { mutableStateOf("") }
    var invalid by rememberSaveable { mutableStateOf(false) }
    var limit by rememberSaveable { mutableIntStateOf(ALL_NETWORKS) }
    var networks by rememberSaveable { mutableStateOf(listOf<String>()) }
    var incoming by rememberSaveable { mutableStateOf(false) }
    var sender by rememberSaveable { mutableIntStateOf(FROM_ANYONE) }
    var senderAddress by rememberSaveable { mutableStateOf("") }
    var senderInvalid by rememberSaveable { mutableStateOf(false) }
    val shown = kind ?: chosenKind
    // Addresses and domains can name a port, and then a protocol.
    val namedPort = if (shown != RuleKind.PORT) port.trim() else ""
    // Incoming rules take the lines as ports on the phone, and who connects from the page.
    val incomingRules = shown == RuleKind.PORT && incoming
    val senderValue =
        when (sender) {
            FROM_ANYONE -> IFirewall.INCOMING_FROM_ANYONE
            FROM_LOCAL_NETWORK -> IFirewall.INCOMING_FROM_LOCAL_NETWORK
            else -> senderAddress.trim()
        }
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
                                it.kind = if (incomingRules) IFirewall.RULE_INCOMING else shown.kind
                                it.value = if (incomingRules) senderValue else value
                                if (incomingRules) it.port = value
                                it.subdomains = subdomains
                                it.protocol = protocol
                                if (namedPort.isNotEmpty()) it.port = namedPort
                                if (limit != ALL_NETWORKS) it.networks = networks.toTypedArray()
                                it.exceptNetworks = limit == ALL_EXCEPT
                            }
                        }
                    if (namedPort.isNotEmpty() && !isPort(namedPort)) {
                        portInvalid = true
                    } else if (incomingRules && sender == FROM_ADDRESS && !isRange(senderValue)) {
                        senderInvalid = true
                    } else {
                        scope.launch {
                            val rejected = Firewall.call { addRules(rules.toTypedArray()) }
                            if (rejected.isEmpty()) {
                                navController.navigateBack()
                            } else {
                                text = rejected.joinToString("\n") { lines[it] }
                                invalid = true
                            }
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
        if (shown == RuleKind.DOMAIN) {
            SwitchPreference(
                object : SwitchPreferenceModel {
                    override val title = stringResource(R.string.include_subdomains)
                    override val checked = { subdomains }
                    override val onCheckedChange: (Boolean) -> Unit = { subdomains = it }
                }
            )
        }
        if (shown != RuleKind.PORT) {
            SettingsOutlinedTextField(
                value = port,
                label = stringResource(R.string.port_label),
                errorMessage = if (portInvalid) stringResource(R.string.port_invalid) else null,
                placeholder = { Text(stringResource(R.string.port_hint)) },
            ) {
                port = it
                portInvalid = false
            }
        }
        if (shown == RuleKind.PORT) {
            SettingsDropdownBox(
                label = stringResource(R.string.direction_label),
                options =
                    listOf(R.string.direction_outgoing, R.string.direction_incoming).map {
                        stringResource(it)
                    },
                selectedOptionIndex = if (incoming) 1 else 0,
            ) {
                incoming = it == 1
            }
        }
        if (incomingRules) {
            SettingsDropdownBox(
                label = stringResource(R.string.sender_label),
                options =
                    listOf(R.string.sender_anyone, R.string.sender_local_network,
                            R.string.sender_address)
                        .map { stringResource(it) },
                selectedOptionIndex = sender,
            ) {
                sender = it
                senderInvalid = false
            }
            if (sender == FROM_ADDRESS) {
                SettingsOutlinedTextField(
                    value = senderAddress,
                    label = stringResource(R.string.sender_address_label),
                    errorMessage =
                        if (senderInvalid) stringResource(R.string.sender_address_invalid)
                        else null,
                    placeholder = { Text(stringResource(R.string.sender_address_hint)) },
                ) {
                    senderAddress = it
                    senderInvalid = false
                }
            }
        }
        if (shown == RuleKind.PORT || namedPort.isNotEmpty()) {
            SettingsDropdownBox(
                label = stringResource(R.string.protocol_label),
                options =
                    listOf(R.string.protocol_both, R.string.protocol_tcp, R.string.protocol_udp)
                        .map { stringResource(it) },
                selectedOptionIndex = PROTOCOLS.indexOf(protocol),
            ) {
                protocol = PROTOCOLS[it]
            }
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
        if (limit != ALL_NETWORKS) ChosenNetworks(userId, networks) { networks = it }
        if (shown == RuleKind.DOMAIN) Footer(stringResource(R.string.domain_addresses_footer))
        if (incomingRules) Footer(stringResource(R.string.incoming_footer))
    }
}

/** Whether [text] is an IP address, or a range of them like 192.0.2.0/24. */
private fun isRange(text: String) =
    try {
        Names.parsePrefix(text)
        true
    } catch (e: IllegalArgumentException) {
        false
    }

/** Whether [text] is a port from 1 to 65535, or a range of them like 6881-6889. */
private fun isPort(text: String): Boolean {
    val ends = text.split('-').map { it.trim().toIntOrNull() ?: return false }
    return ends.size <= 2 && ends.first() in 1..ends.last() && ends.last() <= 65535
}

/** The networks rules are limited to: each kind, then the user's specific networks. */
@Composable
private fun ChosenNetworks(userId: Int, chosen: List<String>, onChange: (List<String>) -> Unit) {
    val context = LocalContext.current
    val known by remember(userId) { Firewall.networks(userId) }.collectAsStateWithLifecycle(null)
    val options =
        remember(known) {
            val kinds = Network.entries.map { it.key to context.getString(it.title) }
            val specific =
                known.orEmpty().mapNotNull { network ->
                    SpecificKind.of(network.key)?.let {
                        network.key to context.getString(it.label, context.networkName(network))
                    }
                }
            (kinds + specific).map { (key, label) ->
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
