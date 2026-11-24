/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.UserHandle
import android.provider.Settings
import androidx.annotation.StringRes
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.android.settingslib.spa.framework.util.appendSpaParams
import com.android.settingslib.spa.widget.preference.Preference
import com.android.settingslib.spa.widget.preference.PreferenceModel
import com.android.settingslib.spa.widget.preference.SwitchPreference
import com.android.settingslib.spa.widget.preference.SwitchPreferenceModel
import kotlinx.coroutines.launch

/** Tells the user about a new app at its first blocked attempt, so they can allow it. */
object BlockedAppNotification {
    private const val CHANNEL_ID = "blocked_apps"
    private const val ACTION_ALLOW = "org.lineageos.firewall.action.ALLOW"
    private const val ACTION_KEEP_BLOCKED = "org.lineageos.firewall.action.KEEP_BLOCKED"
    /** Notifications are tagged with the app's package name. */
    private const val ID = 1

    fun createChannel(context: Context) {
        val channel =
            NotificationChannel(
                CHANNEL_ID,
                context.getString(R.string.channel_blocked_apps),
                NotificationManager.IMPORTANCE_LOW,
            )
        channel.description = context.getString(R.string.channel_blocked_apps_description)
        context.getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    fun settingsIntent(context: Context): Intent =
        Intent(Settings.ACTION_CHANNEL_NOTIFICATION_SETTINGS)
            .putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName)
            .putExtra(Settings.EXTRA_CHANNEL_ID, CHANNEL_ID)

    fun post(context: Context, packageName: String) {
        val pm = context.packageManager
        val label =
            try {
                pm.getApplicationInfo(packageName, 0).loadLabel(pm)
            } catch (e: PackageManager.NameNotFoundException) {
                return
            }
        val data = Uri.fromParts("package", packageName, null)
        fun action(action: String, @StringRes title: Int) =
            Notification.Action.Builder(
                    null,
                    context.getString(title),
                    PendingIntent.getBroadcast(
                        context,
                        0,
                        Intent(action, data, context, BlockedAppActionReceiver::class.java),
                        PendingIntent.FLAG_IMMUTABLE,
                    ),
                )
                .build()
        val open =
            Intent(context, MainActivity::class.java)
                .setData(data)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
                .appendSpaParams(
                    destination = AppRulesPageProvider.route(packageName, context.userId)
                )
        val notification =
            Notification.Builder(context, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_firewall)
                .setContentTitle(context.getString(R.string.blocked_app_title, label))
                .setContentText(context.getString(R.string.blocked_app_text))
                .setContentIntent(
                    PendingIntent.getActivity(context, 0, open, PendingIntent.FLAG_IMMUTABLE)
                )
                .setAutoCancel(true)
                .addAction(action(ACTION_ALLOW, R.string.blocked_app_allow))
                .addAction(action(ACTION_KEEP_BLOCKED, R.string.blocked_app_keep))
                .build()
        context
            .getSystemService(NotificationManager::class.java)
            .notify(packageName, ID, notification)
    }

    fun cancel(context: Context, packageName: String) {
        context.getSystemService(NotificationManager::class.java).cancel(packageName, ID)
    }

    /** Either button records the user's decision, so the app is never reported again. */
    fun onAction(context: Context, intent: Intent) {
        val packageName = intent.data?.schemeSpecificPart ?: return
        val rules = if (intent.action == ACTION_ALLOW) 0 else IFirewall.BLOCK_ALL
        try {
            Firewall.service.setAppRules(packageName, context.userId, rules)
        } catch (e: IllegalArgumentException) {
            // Uninstalled since, its rules gone with it, or in a group, which holds them.
        }
        cancel(context, packageName)
    }
}

/** The firewall service's report of a new app blocked until the user decides. */
class BlockedAppReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val packageName = intent.getStringExtra(Intent.EXTRA_PACKAGE_NAME) ?: return
        BlockedAppNotification.post(context, packageName)
    }
}

class BlockedAppActionReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        BlockedAppNotification.onAction(context, intent)
    }
}

/** Android's report of an app removed with its data, whose rules went with it. */
class PackageReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val packageName = intent.data?.schemeSpecificPart ?: return
        BlockedAppNotification.cancel(context, packageName)
    }
}

fun Firewall.newInstallsBlocked(userId: Int) = load { areNewInstallsBlocked(userId) }

/** The app list's entries for one user: whether new apps start blocked, and their notices. */
@Composable
fun NewAppsPreferences(userId: Int) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val newAppsBlocked by
        remember(userId) { Firewall.newInstallsBlocked(userId) }.collectAsStateWithLifecycle(null)
        SwitchPreference(
            object : SwitchPreferenceModel {
                override val title = stringResource(R.string.new_apps_title)
                override val summary = { context.getString(R.string.new_apps_summary) }
                override val checked = { newAppsBlocked?.not() }
                override val onCheckedChange: (Boolean) -> Unit = { allowed ->
                    scope.launch { Firewall.call { setNewInstallsBlocked(userId, !allowed) } }
                }
            }
        )
        // Each profile's copy of this app posts that profile's notifications.
        Preference(
            object : PreferenceModel {
                override val title = stringResource(R.string.notifications_title)
                override val summary = { context.getString(R.string.notifications_summary) }
                override val onClick = {
                    context.startActivityAsUser(
                        BlockedAppNotification.settingsIntent(context),
                        UserHandle.of(userId),
                    )
                }
            }
        )
}

/** How the app list sums up a blocked app when it is blocked as new, or null. */
fun Context.newAppListSummary(rule: AppRule?): String? =
    if (rule?.isDefault == true) getString(R.string.rules_blocked_new) else null

/** What the app page's footer says about an app blocked as new, or null. */
fun Context.newAppFooter(rule: AppRule?): String? =
    if (rule != null && rule.isDefault && rule.rules and IFirewall.BLOCK_ALL != 0) {
        getString(R.string.app_rules_footer_new)
    } else null
