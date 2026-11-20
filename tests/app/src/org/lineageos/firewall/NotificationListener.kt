/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall

import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import java.util.concurrent.LinkedBlockingQueue

/** Hands the tests every notification posted or removed while it's connected. */
class NotificationListener : NotificationListenerService() {
    override fun onListenerConnected() {
        connected.offer(this)
    }

    override fun onNotificationPosted(sbn: StatusBarNotification) {
        posted.offer(sbn)
    }

    override fun onNotificationRemoved(sbn: StatusBarNotification) {
        removed.offer(sbn)
    }

    companion object {
        val connected = LinkedBlockingQueue<NotificationListener>()
        val posted = LinkedBlockingQueue<StatusBarNotification>()
        val removed = LinkedBlockingQueue<StatusBarNotification>()
    }
}
