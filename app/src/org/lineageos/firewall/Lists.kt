/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall

import android.content.Context
import android.icu.text.NumberFormat
import android.net.Uri
import android.text.format.DateUtils
import androidx.annotation.StringRes
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Block
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.Dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.android.settingslib.spa.widget.dialog.AlertDialogButton
import com.android.settingslib.spa.widget.dialog.rememberAlertDialogPresenter
import com.android.settingslib.spa.widget.preference.Preference
import com.android.settingslib.spa.widget.preference.PreferenceModel
import com.android.settingslib.spa.widget.preference.TwoTargetButtonPreference
import com.android.settingslib.spa.widget.preference.ZeroStatePreference
import com.android.settingslib.spa.widget.ui.Category
import com.android.settingslib.spa.widget.ui.LazyCategory
import com.android.settingslib.spa.widget.ui.SettingsIcon
import kotlinx.coroutines.launch

/** A list the firewall suggests, for all of a user's apps or for one app. */
enum class SuggestedList(
    val url: String,
    @StringRes val title: Int,
    @StringRes val summary: Int,
    val forAllApps: Boolean,
    val subdomains: Boolean = true,
) {
    ADS("https://big.oisd.nl/domainswild2", R.string.list_ads, R.string.list_ads_summary, true),
    THREATS(
        "$HAGEZI/wildcard/tif.medium-onlydomains.txt",
        R.string.list_threats,
        R.string.list_threats_summary,
        true,
    ),
    ADULT(
        "https://nsfw.oisd.nl/domainswild2",
        R.string.list_adult,
        R.string.list_adult_summary,
        true,
    ),
    ADULT_WIDER(
        "$HAGEZI/wildcard/nsfw-onlydomains.txt",
        R.string.list_adult_wider,
        R.string.list_adult_wider_summary,
        true,
    ),
    HIJACKED_V4(
        "https://www.spamhaus.org/drop/drop_v4.json",
        R.string.list_hijacked_v4,
        R.string.list_hijacked_summary,
        true,
    ),
    HIJACKED_V6(
        "https://www.spamhaus.org/drop/drop_v6.json",
        R.string.list_hijacked_v6,
        R.string.list_hijacked_summary,
        true,
    ),
    BYPASS(
        "$HAGEZI/wildcard/doh-vpn-proxy-bypass-onlydomains.txt",
        R.string.list_bypass,
        R.string.list_bypass_summary,
        true,
    ),
    STALKERWARE(
        "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/hosts",
        R.string.list_stalkerware,
        R.string.list_stalkerware_summary,
        true,
    ),
    ENCRYPTED_DNS(
        "$HAGEZI/wildcard/doh-onlydomains.txt",
        R.string.list_encrypted_dns,
        R.string.list_encrypted_dns_summary,
        false,
    ),
    ENCRYPTED_DNS_ADDRESSES(
        "$HAGEZI/ips/doh.txt",
        R.string.list_encrypted_dns_addresses,
        R.string.list_encrypted_dns_addresses_summary,
        false,
    ),
    ENCRYPTED_DNS_EXACT(
        "https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-domains.txt",
        R.string.list_encrypted_dns_exact,
        R.string.list_encrypted_dns_exact_summary,
        false,
        subdomains = false,
    ),
}

private const val HAGEZI = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main"

/** Every list of the user, for all of their apps and for each app. */
fun Firewall.lists(userId: Int) = load { getLists(userId).toList() }

/** What the app calls a list: the suggestion's name, the list's own, or its address's host. */
fun Context.listTitle(list: FirewallList): String =
    SuggestedList.entries.find { it.url == list.url }?.let { getString(it.title) }
        ?: list.title?.takeIf { it.isNotBlank() }
        ?: list.url?.let { Uri.parse(it).host }
        ?: list.id

/** What a list holds and when it last changed and was checked, or why its last check failed. */
fun Context.listSummary(list: FirewallList): String {
    if (list.changedMillis == 0L && list.error == 0) return getString(R.string.list_not_downloaded)
    val number = NumberFormat.getInstance()
    val counts = buildList {
        if (list.domains > 0 || list.ranges == 0) {
            add(
                resources.getQuantityString(
                    R.plurals.list_domain_count,
                    list.domains,
                    number.format(list.domains),
                )
            )
        }
        if (list.ranges > 0) {
            add(
                resources.getQuantityString(
                    R.plurals.list_address_count,
                    list.ranges,
                    number.format(list.ranges),
                )
            )
        }
    }
    val summary =
        if (list.changedMillis == 0L) getString(R.string.list_not_downloaded)
        else
            getString(
                R.string.list_summary,
                formatList(counts),
                day(list.changedMillis),
                day(list.checkedMillis),
            )
    if (list.error == 0) return summary
    return getString(R.string.list_check_failed, summary, listError(list))
}

private fun Context.day(millis: Long): String =
    DateUtils.formatDateTime(
        this,
        millis,
        DateUtils.FORMAT_SHOW_DATE or DateUtils.FORMAT_ABBREV_MONTH,
    )

private fun Context.listError(list: FirewallList): String =
    when (list.error) {
        IFirewall.LIST_ERROR_NETWORK -> getString(R.string.list_error_network)
        IFirewall.LIST_ERROR_SERVER -> getString(R.string.list_error_server, list.errorDetail)
        IFirewall.LIST_ERROR_COUNT -> getString(R.string.list_error_count)
        IFirewall.LIST_ERROR_STORAGE -> getString(R.string.list_error_storage)
        IFirewall.LIST_ERROR_MEMORY -> getString(R.string.list_error_memory)
        IFirewall.LIST_ERROR_FULL -> getString(R.string.list_error_full)
        else -> getString(R.string.list_error_not_a_list)
    }

/** Asks before removing a list from its app, or from all apps; returns what opens the question. */
@Composable
fun rememberRemoveListDialog(): (FirewallList) -> Unit {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var list by rememberSaveable { mutableStateOf<FirewallList?>(null) }
    val dialog =
        rememberAlertDialogPresenter(
            confirmButton =
                AlertDialogButton(stringResource(R.string.remove)) {
                    val removed = list ?: return@AlertDialogButton
                    scope.launch {
                        Firewall.call { removeList(removed.userId, removed.packageName, removed.id) }
                    }
                },
            dismissButton = AlertDialogButton(stringResource(android.R.string.cancel)),
            title = list?.let { stringResource(R.string.remove_list_title, context.listTitle(it)) },
        )
    return {
        list = it
        dialog.open()
    }
}

/** A list's row, with a button that removes it; in an app's rules, [inRules] names it a list. */
@Composable
fun ListRow(list: FirewallList, remove: (FirewallList) -> Unit, inRules: Boolean = false) {
    val context = LocalContext.current
    val title = context.listTitle(list)
    TwoTargetButtonPreference(
        title = if (inRules) stringResource(R.string.app_list_title, title) else title,
        summary = { context.listSummary(list) },
        buttonIcon = Icons.Outlined.Delete,
        buttonIconDescription = stringResource(R.string.remove_list_for, title),
        onButtonClick = { remove(list) },
    )
}

/** The tab of the lists for all of a user's apps, beside the kinds of rules. */
@Composable
fun ListsTab(userId: Int, bottomPadding: Dp, searchQuery: () -> String) {
    val lists by remember(userId) { Firewall.lists(userId) }.collectAsStateWithLifecycle(null)
    val context = LocalContext.current
    val remove = rememberRemoveListDialog()
    val add = AddListPageProvider.navigator(userId, null)
    val shown =
        lists
            ?.filter { it.packageName == null }
            ?.filter { context.listTitle(it).contains(searchQuery(), ignoreCase = true) }
            ?: return
    LazyCategory(
        count = shown.size,
        key = { shown[it].id },
        bottomPadding = bottomPadding,
        header = {
            Category {
                Preference(
                    object : PreferenceModel {
                        override val title = stringResource(R.string.add_list)
                        override val icon = @Composable { SettingsIcon(Icons.Outlined.Add) }
                        override val onClick = add
                    }
                )
            }
            if (shown.isEmpty()) {
                ZeroStatePreference(Icons.Outlined.Block, stringResource(R.string.no_lists))
            }
        },
    ) { index ->
        ListRow(shown[index], remove)
    }
}

/** The app's own lists, once they've loaded. */
@Composable
fun rememberAppLists(packageName: String, userId: Int): List<FirewallList>? {
    val lists by remember(userId) { Firewall.lists(userId) }.collectAsStateWithLifecycle(null)
    return lists?.filter { it.packageName == packageName }
}

/** The app's own lists, in its rules. */
@Composable
fun AppListRows(lists: List<FirewallList>) {
    val remove = rememberRemoveListDialog()
    for (list in lists) ListRow(list, remove, inRules = true)
}

/** The app's rules' entry for adding a list for the app. */
@Composable
fun AddAppListPreference(packageName: String, userId: Int) {
    Preference(
        object : PreferenceModel {
            override val title = stringResource(R.string.add_list)
            override val icon = @Composable { SettingsIcon(Icons.Outlined.Add) }
            override val onClick = AddListPageProvider.navigator(userId, packageName)
        }
    )
}
