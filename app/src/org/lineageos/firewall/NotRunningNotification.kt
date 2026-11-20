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
import android.os.ServiceManager

/**
 * Tells a user who set rules that the firewall isn't running after a boot, as Android tells them
 * when Private DNS or an always-on VPN can't work.
 */
object NotRunningNotification {
    private const val CHANNEL_ID = "firewall_status"
    private const val TAG = "not_running"
    private const val ID = 2

    fun createChannel(context: Context) {
        val channel =
            NotificationChannel(
                CHANNEL_ID,
                context.getString(R.string.channel_status),
                NotificationManager.IMPORTANCE_HIGH,
            )
        channel.description = context.getString(R.string.channel_status_description)
        context.getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    fun postIfNotRunning(context: Context) {
        // Without the service there are no rules to read, and none applied either.
        val service =
            ServiceManager.getService("firewall")?.let { IFirewall.Stub.asInterface(it) }
        if (service != null && (service.isRunning() || !hasRules(service, context.userId))) {
            return
        }
        val text = context.getString(R.string.not_running_text)
        val open =
            Intent(context, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
        val notification =
            Notification.Builder(context, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_firewall)
                .setContentTitle(context.getString(R.string.not_running_title))
                .setContentText(text)
                .setStyle(Notification.BigTextStyle().bigText(text))
                .setContentIntent(
                    PendingIntent.getActivity(context, 0, open, PendingIntent.FLAG_IMMUTABLE)
                )
                .setAutoCancel(true)
                .build()
        context.getSystemService(NotificationManager::class.java).notify(TAG, ID, notification)
    }

    /** Whether the user set anything for the firewall to apply. */
    private fun hasRules(service: IFirewall, userId: Int) =
        service.getAppRulesForUser(userId).any { it.rules != 0 }
}

/** Checks once each user unlocks after a boot. */
class BootCompletedReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        NotRunningNotification.postIfNotRunning(context)
    }
}
