/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall

import android.content.Context
import androidx.annotation.PluralsRes
import androidx.annotation.StringRes
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Add
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.android.settingslib.spa.widget.preference.Preference
import com.android.settingslib.spa.widget.preference.PreferenceModel
import com.android.settingslib.spa.widget.ui.Category
import com.android.settingslib.spa.widget.ui.SettingsIcon

/** A network as rule summaries list it: a kind by its list name, a specific one by its name. */
fun Context.networkListName(key: String, names: Map<String, String>): String =
    Network.entries.find { it.key == key }?.let { getString(it.listName) }
        ?: names[key]
        ?: key.substringAfter(':')

/** What a rule can name, in the order the app shows them. */
enum class RuleKind(
    val kind: Int,
    @StringRes val title: Int,
    @StringRes val add: Int,
    @StringRes val empty: Int,
    @StringRes val hint: Int,
    @StringRes val invalid: Int,
    @PluralsRes val count: Int,
) {
    DOMAIN(
        IFirewall.RULE_DOMAIN,
        R.string.kind_domains,
        R.string.add_domains,
        R.string.no_domain_rules,
        R.string.domains_hint,
        R.string.domains_invalid,
        R.plurals.domain_rule_count,
    ),
    ADDRESS(
        IFirewall.RULE_ADDRESS,
        R.string.kind_addresses,
        R.string.add_addresses,
        R.string.no_address_rules,
        R.string.addresses_hint,
        R.string.addresses_invalid,
        R.plurals.address_rule_count,
    ),
    PORT(
        IFirewall.RULE_PORT,
        R.string.kind_ports,
        R.string.add_ports,
        R.string.no_port_rules,
        R.string.ports_hint,
        R.string.ports_invalid,
        R.plurals.port_rule_count,
    ),
}

/** Sums up the rules for all apps by kind, like "3 domains and 2 IP addresses". */
fun Context.allAppsRulesSummary(rules: List<FirewallRule>): String {
    val counts =
        RuleKind.entries.mapNotNull { kind ->
            val count = rules.count { it.kind == kind.kind }
            if (count == 0) null else resources.getQuantityString(kind.count, count, count)
        }
    return if (counts.isEmpty()) getString(R.string.all_apps_rules_none) else formatList(counts)
}

fun Context.ruleTitle(rule: FirewallRule): String =
    when {
        rule.kind != IFirewall.RULE_PORT -> rule.value
        '-' in rule.value -> getString(R.string.ports_title, rule.value)
        else -> getString(R.string.port_title, rule.value)
    }

/** A rule's summary, with its port and the networks it is limited to by the names in [names]. */
fun Context.ruleSummary(rule: FirewallRule, names: Map<String, String>): String {
    val summary = withPort(rule, targetSummary(rule))
    val networks = rule.networks.orEmpty()
    if (networks.isEmpty()) return summary
    return getString(
        if (rule.exceptNetworks) R.string.rule_except_networks else R.string.rule_only_networks,
        summary,
        formatList(networks.map { networkListName(it, names) }),
    )
}

private fun Context.targetSummary(rule: FirewallRule): String =
    getString(
        when {
            rule.kind == IFirewall.RULE_DOMAIN && rule.subdomains ->
                if (rule.allow) R.string.rule_allowed_subdomains
                else R.string.rule_blocked_subdomains
            rule.port == null && rule.protocol == IFirewall.PROTOCOL_TCP ->
                if (rule.allow) R.string.rule_allowed_tcp else R.string.rule_blocked_tcp
            rule.port == null && rule.protocol == IFirewall.PROTOCOL_UDP ->
                if (rule.allow) R.string.rule_allowed_udp else R.string.rule_blocked_udp
            else -> if (rule.allow) R.string.rule_allowed else R.string.rule_blocked
        }
    )

/** The summary with the port an address or domain rule names, like "Blocked · TCP port 443". */
private fun Context.withPort(rule: FirewallRule, summary: String): String {
    val port = rule.port ?: return summary
    val range = '-' in port
    val format =
        when (rule.protocol) {
            IFirewall.PROTOCOL_TCP ->
                if (range) R.string.rule_at_tcp_ports else R.string.rule_at_tcp_port
            IFirewall.PROTOCOL_UDP ->
                if (range) R.string.rule_at_udp_ports else R.string.rule_at_udp_port
            else -> if (range) R.string.rule_at_ports else R.string.rule_at_port
        }
    return getString(format, summary, port)
}

/** The rules of one app, or with a null packageName those for all of the user's apps. */
fun Firewall.rules(userId: Int, packageName: String?) =
    load { getRules(userId, packageName).toList() }

/** The app list's summary of an app with its count of rules, like "Allowed · 2 rules". */
fun Context.withRuleCount(rule: AppRule?, summary: String): String {
    val count = rule?.ruleCount ?: 0
    if (count == 0) return summary
    return getString(
        R.string.summary_with_rules,
        summary,
        resources.getQuantityString(R.plurals.rule_count, count, count),
    )
}

/** What the app page's footer says about rules. */
fun Context.rulesFooter(): String = getString(R.string.rules_footer)

/** The app's rules for domains, addresses and ports, and its lists. */
@Composable
fun TargetRules(packageName: String, userId: Int) {
    val rules by
        remember(packageName, userId) { Firewall.rules(userId, packageName) }
            .collectAsStateWithLifecycle(null)
    val remove = rememberRemoveRuleDialog()
    val names = rememberNetworkNames(userId)
    val lists = rememberAppLists(packageName, userId)
    Category(title = stringResource(R.string.rules_title)) {
        val shown = rules.orEmpty()
        if (rules != null && shown.isEmpty() && lists?.isEmpty() == true) {
            Preference(
                object : PreferenceModel {
                    override val title = stringResource(R.string.no_app_rules)
                }
            )
        }
        for (rule in shown) RuleRow(rule, names, remove)
        AppListRows(lists.orEmpty())
        Preference(
            object : PreferenceModel {
                override val title = stringResource(R.string.add_rule)
                override val icon = @Composable { SettingsIcon(Icons.Outlined.Add) }
                override val onClick = AddAppRulesPageProvider.navigator(packageName, userId)
            }
        )
        AddAppListPreference(packageName, userId)
    }
}
