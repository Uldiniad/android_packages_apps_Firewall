/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall

import android.app.backup.BackupAgentHelper
import android.app.backup.BlobBackupHelper

/** Backs up this user's rules, switch and lists, which the firewall service keeps. */
class FirewallBackupAgent : BackupAgentHelper() {
    override fun onCreate() {
        val userId = userId
        addHelper(
            KEY,
            object : BlobBackupHelper(VERSION, KEY) {
                override fun getBackupPayload(key: String): ByteArray =
                    Firewall.service.getBackupPayload(userId)

                override fun applyRestoredPayload(key: String, payload: ByteArray) {
                    Firewall.service.applyRestore(userId, payload)
                    ListUpdates.checkNew(this@FirewallBackupAgent)
                }
            },
        )
    }

    private companion object {
        const val KEY = "firewall"
        const val VERSION = 1
    }
}
