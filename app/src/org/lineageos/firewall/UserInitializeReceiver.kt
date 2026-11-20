/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall

import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.UserManager

/**
 * Hides the launcher icon in work profiles and private space, as Settings does: the personal
 * profile's app shows them in tabs. Their copy stays, for their notifications.
 */
class UserInitializeReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (!context.getSystemService(UserManager::class.java).isProfile) return
        context.packageManager.setComponentEnabledSetting(
            ComponentName(context, "${context.packageName}.LauncherEntry"),
            PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
            PackageManager.DONT_KILL_APP,
        )
    }
}
