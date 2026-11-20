/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall

import android.content.Context
import android.icu.text.ListFormatter
import androidx.annotation.StringRes

/** The networks an app can be blocked on, in the order the app shows them. */
enum class Network(
    val rule: Int,
    @StringRes val title: Int,
    @StringRes val summary: Int?,
    @StringRes val listName: Int,
) {
    WIFI(IFirewall.BLOCK_WIFI, R.string.network_wifi, null, R.string.networks_list_wifi),
    MOBILE(IFirewall.BLOCK_CELLULAR, R.string.network_mobile, null, R.string.networks_list_mobile),
    VPN(IFirewall.BLOCK_VPN, R.string.network_vpn, null, R.string.networks_list_vpn),
    OTHER(
        IFirewall.BLOCK_OTHER,
        R.string.network_other,
        R.string.network_other_summary,
        R.string.networks_list_other,
    ),
    METERED(
        IFirewall.BLOCK_METERED,
        R.string.network_metered,
        R.string.network_metered_summary,
        R.string.networks_list_metered,
    ),
    ROAMING(
        IFirewall.BLOCK_ROAMING,
        R.string.network_roaming,
        R.string.network_roaming_summary,
        R.string.networks_list_roaming,
    ),
}

fun Int.with(rule: Int, set: Boolean) = if (set) this or rule else this and rule.inv()

fun Context.formatList(items: List<CharSequence>): String =
    ListFormatter.getInstance(resources.configuration.locales[0]).format(items)

/** How the app list sums up an app's rules. */
fun Context.rulesSummary(rule: AppRule?, usesInternet: Boolean): String =
    networkSummary(rule, usesInternet)

private fun Context.networkSummary(rule: AppRule?, usesInternet: Boolean): String {
    val rules = rule?.rules ?: 0
    scheduleListSummary(rule)?.let { return it }
    if (rules and IFirewall.BLOCK_ALL != 0) {
        return getString(R.string.rules_blocked)
    }
    val blocked = Network.entries.filter { rules and it.rule != 0 }.map { getString(it.listName) }
    if (blocked.isEmpty()) {
        return getString(if (usesInternet) R.string.rules_allowed else R.string.rules_no_internet)
    }
    return getString(R.string.rules_blocked_on, formatList(blocked))
}
