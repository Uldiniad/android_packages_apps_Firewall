/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Bundle
import android.os.UserHandle
import android.system.OsConstants
import android.text.format.DateUtils
import android.text.format.Formatter
import androidx.annotation.StringRes
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.outlined.WifiTethering
import androidx.compose.material3.Icon
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.Dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavType
import androidx.navigation.navArgument
import com.android.settingslib.spa.framework.common.SettingsPageProvider
import com.android.settingslib.spa.framework.compose.navigator
import com.android.settingslib.spa.framework.compose.rememberDrawablePainter
import com.android.settingslib.spa.framework.theme.SettingsDimension
import com.android.settingslib.spa.widget.dialog.AlertDialogButton
import com.android.settingslib.spa.widget.dialog.rememberAlertDialogPresenter
import com.android.settingslib.spa.widget.preference.MainSwitchPreference
import com.android.settingslib.spa.widget.preference.Preference
import com.android.settingslib.spa.widget.preference.PreferenceModel
import com.android.settingslib.spa.widget.preference.SwitchPreferenceModel
import com.android.settingslib.spa.widget.preference.ZeroStatePreference
import com.android.settingslib.spa.widget.scaffold.MoreOptionsAction
import com.android.settingslib.spa.widget.scaffold.SearchScaffold
import com.android.settingslib.spa.widget.scaffold.SettingsPager
import com.android.settingslib.spa.widget.ui.LazyCategory
import com.android.settingslib.spa.widget.ui.SettingsBody
import com.android.settingslib.spaprivileged.model.app.rememberAppRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** One user's activity log, which that user's copy of this app keeps and shows. */
object ActivityPageProvider : SettingsPageProvider {
    private const val USER_ID = "rt_userId"

    override val name = "Activity"

    override val parameter = listOf(navArgument(USER_ID) { type = NavType.IntType })

    fun route(userId: Int) = "$name/$userId"

    @Composable fun navigator(userId: Int) = navigator(route = route(userId))

    @Composable
    override fun Page(arguments: Bundle?) {
        ActivityPage(checkNotNull(arguments).getInt(USER_ID))
    }
}

/** The newest entries the page shows; older ones stay in the log. */
private const val SHOWN = 1000

@Composable
private fun ActivityPage(userId: Int) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val store = remember { ActivityStore.get(context) }
    val on by remember(userId) { Firewall.load { isActivityLogOn(userId) } }
        .collectAsStateWithLifecycle(null)
    val version by store.changes.collectAsStateWithLifecycle()
    // What the service holds goes in at once, as its word may still be on the way.
    LaunchedEffect(Unit) { withContext(Dispatchers.IO) { ActivityStore.takeNew(context) } }
    val clear =
        rememberAlertDialogPresenter(
            confirmButton =
                AlertDialogButton(stringResource(R.string.clear)) {
                    scope.launch(Dispatchers.IO) {
                        Firewall.call { clearActivity(userId) }
                        store.clear()
                    }
                },
            dismissButton = AlertDialogButton(stringResource(android.R.string.cancel)),
            title = stringResource(R.string.clear_activity_title),
            text = { SettingsBody(stringResource(R.string.clear_activity_text)) },
        )
    SearchScaffold(
        title = stringResource(R.string.activity_title),
        actions = {
            MoreOptionsAction {
                MenuItem(stringResource(R.string.clear_activity)) { clear.open() }
            }
        },
    ) { bottomPadding: Dp, searchQuery: () -> String ->
        val titles =
            listOf<Int>(R.string.activity_all, R.string.activity_allowed, R.string.activity_blocked)
                .map { stringResource(it) }
        SettingsPager(titles) { page ->
            ActivityList(userId, on, version, listOf(null, true, false)[page], bottomPadding,
                searchQuery)
        }
    }
}

@Composable
private fun ActivityList(
    userId: Int,
    on: Boolean?,
    version: Long,
    allowed: Boolean?,
    bottomPadding: Dp,
    searchQuery: () -> String,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val store = remember { ActivityStore.get(context) }
    val entries by
        produceState<List<Pair<ActivityStore.Entry, ApplicationInfo?>>?>(null, version, allowed) {
            value = withContext(Dispatchers.IO) { context.withApps(store.entries(allowed, SHOWN)) }
        }
    val size by produceState(0L, version) { value = withContext(Dispatchers.IO) { store.size() } }
    // Hotspot devices with rules of their own make entries in the main user's log, by their uids.
    val devices by
        remember(userId) {
                if (userId == UserHandle.USER_SYSTEM) hotspotDevices() else flowOf(emptyList())
            }
            .collectAsStateWithLifecycle(emptyList())
    val shown =
        entries?.filter { (entry, app) ->
            val query = searchQuery()
            listOfNotNull(entry.name, entry.address, app?.packageName).any {
                it.contains(query, ignoreCase = true)
            }
        } ?: return
    LazyCategory(
        count = shown.size,
        key = { shown[it].first.key },
        bottomPadding = bottomPadding,
        header = {
            MainSwitchPreference(
                object : SwitchPreferenceModel {
                    override val title = stringResource(R.string.record_activity)
                    override val checked = { on }
                    override val onCheckedChange: (Boolean) -> Unit = {
                        scope.launch { Firewall.call { setActivityLog(userId, it) } }
                    }
                }
            )
            Preference(
                object : PreferenceModel {
                    override val title =
                        stringResource(R.string.activity_size, Formatter.formatFileSize(context, size))
                    override val summary = {
                        context.getString(
                            if (store.trimming) R.string.activity_trimming else R.string.activity_kept
                        )
                    }
                }
            )
            if (shown.isEmpty()) {
                ZeroStatePreference(
                    Icons.Outlined.History,
                    stringResource(if (on == false) R.string.no_activity_off else R.string.no_activity),
                )
            }
        },
    ) { index ->
        val (entry, app) = shown[index]
        ActivityRow(userId, entry, app, devices.find { it.uid != 0 && it.uid == entry.uid })
    }
}

/** Each entry with the installed app its uid belongs to, if any. */
internal fun Context.withApps(
    entries: List<ActivityStore.Entry>
): List<Pair<ActivityStore.Entry, ApplicationInfo?>> {
    val apps = HashMap<Int, ApplicationInfo?>()
    return entries.map { entry ->
        entry to
            apps.getOrPut(entry.uid) {
                packageManager.getPackagesForUid(entry.uid)?.firstOrNull()?.let {
                    try {
                        packageManager.getApplicationInfo(it, 0)
                    } catch (e: PackageManager.NameNotFoundException) {
                        null
                    }
                }
            }
    }
}

/** An entry, which opens its page; on that page, whoever it was for, which opens their rules. */
@Composable
internal fun ActivityRow(
    userId: Int,
    entry: ActivityStore.Entry,
    app: ApplicationInfo?,
    device: HotspotDevice?,
    opensEntry: Boolean = true,
) {
    val context = LocalContext.current
    val repository = rememberAppRepository()
    val tethering = device != null || UserHandle.getAppId(entry.uid) == DNS_TETHER_UID
    val label =
        app?.let { repository.produceLabel(it).value }
            ?: device?.let { it.name ?: it.mac }
            ?: if (tethering) stringResource(R.string.activity_tethering) else entry.uid.toString()
    val icon = app?.let { repository.produceIcon(it).value }
    val open =
        if (opensEntry) {
            ActivityEntryPageProvider.navigator(userId, entry.key)
        } else {
            app?.let { AppRulesPageProvider.navigator(it) }
                ?: device?.let { HotspotDevicePageProvider.navigator(it.mac) }
                ?: if (tethering) HotspotPageProvider.navigator() else null
        }
    Preference(
        object : PreferenceModel {
            override val title = if (opensEntry) entry.name ?: entry.address ?: "" else label
            override val summary = { context.activitySummary(entry, label.takeIf { opensEntry }) }
            override val icon =
                @Composable {
                    val size = Modifier.size(SettingsDimension.appIconItemSize)
                    if (tethering) {
                        Icon(Icons.Outlined.WifiTethering, contentDescription = null, modifier = size)
                    } else {
                        Image(
                            painter = rememberDrawablePainter(icon),
                            contentDescription = null,
                            modifier = size,
                        )
                    }
                }
            override val onClick = open
        }
    )
}

/** Like "Chrome · Blocked: domain rule · UDP 53 · Wi-Fi · 12:05 · 3 times", or without the app. */
private fun Context.activitySummary(entry: ActivityStore.Entry, label: String?): String {
    val parts = listOfNotNull(label).toMutableList()
    parts +=
        if (entry.allowed) getString(R.string.activity_allowed)
        else getString(R.string.activity_blocked_by, reasonText(entry))
    parts +=
        when {
            entry.kind == IFirewall.ACTIVITY_LOOKUP -> getString(R.string.activity_lookup)
            entry.protocol == OsConstants.IPPROTO_TCP ->
                getString(R.string.activity_protocol_port, "TCP", entry.port)
            entry.protocol == OsConstants.IPPROTO_UDP ->
                getString(R.string.activity_protocol_port, "UDP", entry.port)
            else -> getString(R.string.activity_protocol, entry.protocol)
        }
    if (entry.kind == IFirewall.ACTIVITY_INCOMING) parts += getString(R.string.activity_incoming)
    if (entry.name != null && entry.address != null) parts += entry.address
    Network.entries.find { it.rule == entry.network }?.let { parts += getString(it.title) }
    parts +=
        DateUtils.formatSameDayTime(
                entry.lastMillis,
                System.currentTimeMillis(),
                java.text.DateFormat.SHORT,
                java.text.DateFormat.SHORT,
            )
            .toString()
    parts +=
        resources.getQuantityString(R.plurals.activity_count, entry.count.toInt(), entry.count)
    return parts.joinToString(getString(R.string.activity_separator))
}

/** dnsmasq's uid, which looks names up for the devices on the phone's hotspot and tethering. */
private const val DNS_TETHER_UID = 1052

/** The most specific rule that refused the entry. */
private fun Context.reasonText(entry: ActivityStore.Entry): String {
    for (reason in REASONS) {
        if (entry.reasons and reason.own != 0) return getString(reason.text)
        if (entry.reasons and reason.forAllApps != 0) {
            return getString(R.string.reason_for_all_apps, getString(reason.text))
        }
    }
    return getString(R.string.reason_all)
}

/** A kind of rule's bits, the app's own and those for all apps, and what it's called. */
private class Reason(val own: Int, val forAllApps: Int, @StringRes val text: Int)

/** The kinds of rules, the most specific first. */
private val REASONS: List<Reason> =
    listOf(
        Reason(IFirewall.REASON_LOCKDOWN, 0, R.string.reason_lockdown),
        Reason(IFirewall.REASON_INCOMING, IFirewall.REASON_USER_INCOMING, R.string.reason_incoming),
        Reason(IFirewall.REASON_DOMAIN, IFirewall.REASON_USER_DOMAIN, R.string.reason_domain),
        Reason(IFirewall.REASON_LIST, IFirewall.REASON_USER_LIST, R.string.reason_list),
        Reason(IFirewall.REASON_ADDRESS, IFirewall.REASON_USER_ADDRESS, R.string.reason_address),
        Reason(IFirewall.REASON_PORT, IFirewall.REASON_USER_PORT, R.string.reason_port),
        Reason(IFirewall.REASON_DNS, IFirewall.REASON_USER_DNS, R.string.reason_dns),
        Reason(IFirewall.REASON_LAN, 0, R.string.reason_lan),
        Reason(IFirewall.REASON_NETWORK, 0, R.string.reason_network),
        Reason(IFirewall.REASON_LOCKED, IFirewall.REASON_USER_LOCKED, R.string.reason_locked),
        Reason(IFirewall.REASON_ALL, 0, R.string.reason_all),
    )

/**
 * The home page's entry for the user's activity log. A profile's log is in the profile's copy of
 * this app, so its page opens there.
 */
@Composable
fun ActivityEntryPreference(userId: Int) {
    val context = LocalContext.current
    val on by remember(userId) { Firewall.load { isActivityLogOn(userId) } }
        .collectAsStateWithLifecycle(null)
    val here = ActivityPageProvider.navigator(userId)
    Preference(
        object : PreferenceModel {
            override val title = stringResource(R.string.activity_title)
            override val summary = {
                context.getString(if (on == true) R.string.activity_on else R.string.activity_off)
            }
            override val onClick: () -> Unit = {
                if (userId == context.userId) {
                    here()
                } else {
                    context.startActivityAsUser(
                        Intent()
                            .setComponent(ComponentName(context, MainActivity::class.java))
                            .putExtra("spaActivityDestination", ActivityPageProvider.route(userId))
                            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                        UserHandle.of(userId),
                    )
                }
            }
        }
    )
}
