/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall

import android.app.Application
import com.android.settingslib.spa.framework.common.SpaEnvironmentFactory

class FirewallApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        SpaEnvironmentFactory.reset(FirewallSpaEnvironment(this))
        BlockedAppNotification.createChannel(this)
        NotRunningNotification.createChannel(this)
        ListUpdates.scheduleDaily(this)
    }
}
