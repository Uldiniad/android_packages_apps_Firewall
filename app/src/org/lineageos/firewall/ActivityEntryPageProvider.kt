/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall

import android.content.Context
import android.content.pm.ApplicationInfo
import android.net.Uri
import android.os.Bundle
import android.os.UserHandle
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavType
import androidx.navigation.navArgument
import com.android.settingslib.spa.framework.common.SettingsPageProvider
import com.android.settingslib.spa.framework.compose.navigator
import com.android.settingslib.spa.widget.preference.Preference
import com.android.settingslib.spa.widget.preference.PreferenceModel
import com.android.settingslib.spa.widget.scaffold.RegularScaffold
import com.android.settingslib.spa.widget.ui.Category
import com.android.settingslib.spaprivileged.model.app.rememberAppRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.withContext

/** One entry of a user's activity log, and for a refused one, what in the rules refused it. */
object ActivityEntryPageProvider : SettingsPageProvider {
    private const val USER_ID = "rt_userId"
    private const val KEY = "rt_key"

    override val name = "ActivityEntry"

    override val parameter =
        listOf(
            navArgument(USER_ID) { type = NavType.IntType },
            navArgument(KEY) { type = NavType.StringType },
        )

    @Composable
    fun navigator(userId: Int, key: String) = navigator(route = "$name/$userId/${Uri.encode(key)}")

    @Composable
    override fun Page(arguments: Bundle?) {
        val bundle = checkNotNull(arguments)
        ActivityEntryPage(bundle.getInt(USER_ID), checkNotNull(bundle.getString(KEY)))
    }
}

@Composable
private fun ActivityEntryPage(userId: Int, key: String) {
    val context = LocalContext.current
    val store = remember { ActivityStore.get(context) }
    val loaded by
        produceState<Pair<ActivityStore.Entry, ApplicationInfo?>?>(null, key) {
            value =
                withContext(Dispatchers.IO) {
                    store.entry(key)?.let { context.withApps(listOf(it)).first() }
                }
        }
    val devices by
        remember(userId) {
                if (userId == UserHandle.USER_SYSTEM) hotspotDevices() else flowOf(emptyList())
            }
            .collectAsStateWithLifecycle(emptyList())
    val (entry, app) = loaded ?: return
    val device = devices.find { it.uid != 0 && it.uid == entry.uid }
    RegularScaffold(title = entry.name ?: entry.address ?: "") {
        ActivityRow(userId, entry, app, device, opensEntry = false)
        if (!entry.allowed) Why(userId, entry, app, device)
        EntryRules(userId, entry, app, device)
    }
}

/** The current rules, lists and switches that account for the refused entry, as Diagnose finds. */
@Composable
private fun Why(
    userId: Int,
    entry: ActivityStore.Entry,
    app: ApplicationInfo?,
    device: HotspotDevice?,
) {
    val context = LocalContext.current
    val repository = rememberAppRepository()
    val appLabel = app?.let { repository.produceLabel(it).value }
    val groups by remember(userId) { Firewall.groups(userId) }.collectAsStateWithLifecycle(null)
    val matches by
        remember(userId, entry) {
                Firewall.load { explainActivity(userId, entry.toParcel()).toList() }
            }
            .collectAsStateWithLifecycle(null)
    Category(title = stringResource(R.string.activity_why)) {
        val shown = matches ?: return@Category
        if (shown.isEmpty()) {
            Preference(
                object : PreferenceModel {
                    override val title = stringResource(R.string.why_nothing)
                }
            )
        }
        for (match in shown) {
            Preference(
                object : PreferenceModel {
                    override val title = context.matchText(match, entry)
                    override val summary = {
                        context.levelText(match.packageName, appLabel, device, groups)
                    }
                }
            )
        }
    }
}

private fun ActivityStore.Entry.toParcel() =
    ActivityEntry().also {
        it.key = key
        it.uid = uid
        it.kind = kind
        it.protocol = protocol
        it.address = address
        it.port = port
        it.name = name
        it.allowed = allowed
        it.reasons = reasons
        it.network = network
        it.firstMillis = firstMillis
        it.lastMillis = lastMillis
        it.count = count
    }

/** What matched, like "List: OISD big" or "Address rule: 192.0.2.7 · TCP 443". */
private fun Context.matchText(match: ActivityMatch, entry: ActivityStore.Entry): String {
    match.list?.let {
        return getString(R.string.why_list, it)
    }
    val rule = match.rule
    if (rule != null) {
        val text =
            when (rule.kind) {
                IFirewall.RULE_DOMAIN ->
                    getString(
                        if (rule.subdomains) R.string.why_domain_rule_subdomains
                        else R.string.why_domain_rule,
                        rule.value,
                    )
                IFirewall.RULE_ADDRESS ->
                    getString(R.string.why_address_rule, shortRange(rule.value))
                IFirewall.RULE_PORT ->
                    return getString(R.string.why_port_rule, portText(rule.protocol, rule.value))
                IFirewall.RULE_INCOMING ->
                    return getString(
                        R.string.why_incoming_rule,
                        portText(rule.protocol, rule.port.orEmpty()),
                        senderText(rule.value),
                    )
                else -> return getString(R.string.why_rule_gone)
            }
        return rule.port?.let {
            getString(R.string.why_with_port, text, portText(rule.protocol, it))
        } ?: text
    }
    return when (match.reason) {
        IFirewall.REASON_DNS,
        IFirewall.REASON_USER_DNS -> getString(R.string.why_dns)
        IFirewall.REASON_LAN -> getString(R.string.why_lan)
        IFirewall.REASON_ALL -> getString(R.string.why_all)
        IFirewall.REASON_NETWORK ->
            Network.entries
                .find { it.rule == entry.network }
                ?.let { getString(R.string.why_network, getString(it.title)) }
                ?: getString(R.string.why_network_unknown)
        IFirewall.REASON_DOMAIN,
        IFirewall.REASON_USER_DOMAIN -> getString(R.string.why_domain_gone)
        else -> getString(R.string.why_rule_gone)
    }
}

private fun Context.portText(protocol: Int, port: String) =
    when (protocol) {
        IFirewall.PROTOCOL_TCP ->
            getString(R.string.why_protocol_port, getString(R.string.protocol_tcp), port)
        IFirewall.PROTOCOL_UDP ->
            getString(R.string.why_protocol_port, getString(R.string.protocol_udp), port)
        else -> getString(R.string.why_any_protocol_port, port)
    }

private fun Context.senderText(sender: String) =
    when (sender) {
        IFirewall.INCOMING_FROM_ANYONE -> getString(R.string.why_from_anyone)
        IFirewall.INCOMING_FROM_LOCAL_NETWORK -> getString(R.string.why_from_local_network)
        else -> shortRange(sender)
    }

/** An address range, or a single address without its /32 or /128. */
private fun shortRange(range: String) =
    if (':' in range) range.removeSuffix("/128") else range.removeSuffix("/32")

/** Whose rules matched: "Rules for Chrome", or the rules for all apps. */
private fun Context.levelText(
    packageName: String?,
    appLabel: CharSequence?,
    device: HotspotDevice?,
    groups: List<FirewallGroup>?,
): String {
    if (packageName == null) return getString(R.string.all_apps_rules)
    val name =
        when {
            packageName == IFirewall.HOTSPOT_PACKAGE -> getString(R.string.hotspot_title)
            packageName.startsWith(IFirewall.DEVICE_PREFIX) ->
                device?.let { it.name ?: it.mac }
                    ?: packageName.removePrefix(IFirewall.DEVICE_PREFIX)
            packageName.startsWith(IFirewall.GROUP_PREFIX) ->
                groups?.find { groupPackage(it.id) == packageName }?.name
                    ?: packageName.removePrefix(IFirewall.GROUP_PREFIX)
            else -> appLabel?.toString() ?: packageName
        }
    return getString(R.string.why_rules_for, name)
}
