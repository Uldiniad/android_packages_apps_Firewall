/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall

import android.content.Context
import android.os.Bundle
import android.widget.Toast
import androidx.annotation.StringRes
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavType
import androidx.navigation.navArgument
import com.android.settingslib.spa.framework.common.SettingsPageProvider
import com.android.settingslib.spa.framework.compose.navigator
import com.android.settingslib.spa.widget.preference.ListPreference
import com.android.settingslib.spa.widget.preference.ListPreferenceModel
import com.android.settingslib.spa.widget.preference.ListPreferenceOption
import com.android.settingslib.spa.widget.preference.Preference
import com.android.settingslib.spa.widget.preference.PreferenceModel
import com.android.settingslib.spa.widget.scaffold.RegularScaffold
import com.android.settingslib.spa.widget.ui.Category
import com.android.settingslib.spa.widget.ui.Footer
import com.android.settingslib.spa.widget.ui.SettingsBody
import com.android.settingslib.spaprivileged.model.app.PackageManagers
import com.android.settingslib.spaprivileged.template.app.AppInfoPage
import kotlinx.coroutines.launch

/** An app's choices for specific networks, which win over its switches for their kinds. */
object SpecificNetworksPageProvider : SettingsPageProvider {
    private const val PACKAGE_NAME = "rt_packageName"
    private const val USER_ID = "rt_userId"

    override val name = "SpecificNetworks"

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
        SpecificNetworksPage(checkNotNull(args.getString(PACKAGE_NAME)), args.getInt(USER_ID))
    }
}

@Composable
private fun SpecificNetworksPage(packageName: String, userId: Int) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val networks by
        remember(userId) { Firewall.networks(userId) }.collectAsStateWithLifecycle(null)
    val appRules by remember(userId) { Firewall.appRules(userId) }.collectAsStateWithLifecycle(null)
    val rule = appRules?.get(packageName)
    val choices = buildMap {
        rule?.allowedNetworks?.forEach { put(it, IFirewall.NETWORK_ALLOW) }
        rule?.blockedNetworks?.forEach { put(it, IFirewall.NETWORK_BLOCK) }
    }
    val content: @Composable () -> Unit = {
        for (kind in SpecificKind.entries) {
            if (kind == SpecificKind.VPN && !hasVpnChoices(packageName)) continue
            Category(title = stringResource(kind.category)) {
                // The networks the device is on come first.
                val shown =
                    networks
                        ?.filter { SpecificKind.of(it.key) == kind }
                        ?.sortedWith(
                            compareByDescending<KnownNetwork> { it.connected }
                                .thenBy { context.networkName(it) }
                        )
                if (shown != null && shown.isEmpty()) {
                    Preference(
                        object : PreferenceModel {
                            override val title = stringResource(kind.empty)
                        }
                    )
                }
                for (network in shown.orEmpty()) {
                    NetworkChoice(
                        network,
                        kind,
                        choices[network.key] ?: IFirewall.NETWORK_DEFAULT,
                    ) { choice ->
                        scope.launch {
                            if (!Firewall.call {
                                    setAppNetwork(packageName, userId, network.key, choice)
                                }
                            ) {
                                Toast.makeText(
                                        context,
                                        R.string.too_many_networks,
                                        Toast.LENGTH_LONG,
                                    )
                                    .show()
                            }
                        }
                    }
                }
            }
        }
    }
    val footer =
        when {
            packageName.startsWith(IFirewall.GROUP_PREFIX) ->
                R.string.specific_networks_footer_group
            packageName == IFirewall.HOTSPOT_PACKAGE -> R.string.specific_networks_footer_hotspot
            packageName.startsWith(IFirewall.DEVICE_PREFIX) ->
                R.string.specific_networks_footer_device
            else -> null
        }
    if (footer != null) {
        // A group or hotspot devices have no app to head the page.
        RegularScaffold(title = stringResource(R.string.specific_networks)) {
            content()
            Footer(stringResource(footer))
        }
    } else {
        AppInfoPage(
            title = stringResource(R.string.specific_networks),
            packageName = packageName,
            userId = userId,
            footerContent = { SettingsBody(stringResource(R.string.specific_networks_footer)) },
            packageManagers = PackageManagers,
        ) {
            content()
        }
    }
}

/** A specific network's row: follow the switch for its kind, or allow or block the app there. */
@Composable
private fun NetworkChoice(
    network: KnownNetwork,
    kind: SpecificKind,
    choice: Int,
    onChoice: (Int) -> Unit,
) {
    val context = LocalContext.current
    val selected = remember(choice) { mutableIntStateOf(choice) }
    ListPreference(
        object : ListPreferenceModel {
            override val title = context.networkName(network)
            override val options =
                listOf(
                    ListPreferenceOption(IFirewall.NETWORK_DEFAULT, context.getString(kind.same)),
                    ListPreferenceOption(
                        IFirewall.NETWORK_ALLOW,
                        context.getString(R.string.choice_allowed),
                    ),
                    ListPreferenceOption(
                        IFirewall.NETWORK_BLOCK,
                        context.getString(R.string.choice_blocked),
                    ),
                )
            override val selectedId = selected
            override val onIdSelected: (Int) -> Unit = {
                selected.intValue = it
                onChoice(it)
            }
        }
    )
}

/** The names of the user's specific networks by key, for rule summaries. */
@Composable
fun rememberNetworkNames(userId: Int): Map<String, String> {
    val context = LocalContext.current
    val networks by
        remember(userId) { Firewall.networks(userId) }.collectAsStateWithLifecycle(null)
    return remember(networks) {
        networks.orEmpty().associate { it.key to context.networkName(it) }
    }
}

/** The user's specific networks, which rules and apps' choices can name. */
fun Firewall.networks(userId: Int) = load { getNetworks(userId).toList() }

/** The app page's entry for its choices for specific networks. */
@Composable
fun SpecificNetworksEntry(packageName: String, userId: Int, rule: AppRule?, allowed: Boolean) {
    val context = LocalContext.current
    val choices = (rule?.allowedNetworks?.size ?: 0) + (rule?.blockedNetworks?.size ?: 0)
    Preference(
        object : PreferenceModel {
            override val title = stringResource(R.string.specific_networks)
            override val summary = {
                if (choices == 0) {
                    context.getString(
                        if (hasVpnChoices(packageName)) R.string.specific_networks_summary
                        else R.string.specific_networks_summary_hotspot
                    )
                } else {
                    context.resources.getQuantityString(
                        R.plurals.specific_network_count,
                        choices,
                        choices,
                    )
                }
            }
            override val enabled = { allowed }
            override val onClick = SpecificNetworksPageProvider.navigator(packageName, userId)
        }
    )
}

/** The kinds of specific networks, by how their keys start, and the switch each follows. */
enum class SpecificKind(
    val prefix: String,
    @StringRes val category: Int,
    @StringRes val empty: Int,
    @StringRes val same: Int,
    @StringRes val label: Int,
) {
    WIFI(
        "wifi:",
        R.string.specific_wifi,
        R.string.no_saved_wifi,
        R.string.choice_same_as_wifi,
        R.string.specific_wifi_label,
    ),
    SIM(
        "sim:",
        R.string.specific_sims,
        R.string.no_sims,
        R.string.choice_same_as_mobile,
        R.string.specific_sim_label,
    ),
    VPN(
        "vpn:",
        R.string.specific_vpns,
        R.string.no_vpn_apps,
        R.string.choice_same_as_vpn,
        R.string.specific_vpn_label,
    );

    companion object {
        fun of(key: String) = entries.find { key.startsWith(it.prefix) }
    }
}

/** What the user knows a specific network as. */
fun Context.networkName(network: KnownNetwork): String =
    network.name ?: getString(R.string.removed_sim, network.key.substringAfter(':'))
