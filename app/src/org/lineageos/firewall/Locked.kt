/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall

import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.android.settingslib.spa.widget.preference.SwitchPreference
import com.android.settingslib.spa.widget.preference.SwitchPreferenceModel
import kotlinx.coroutines.launch

/** Whether all of the user's apps are blocked while it's locked, but those let through. */
fun Firewall.blockedWhileLocked(userId: Int) = load { isBlockedWhileLocked(userId) }

/**
 * An app's switch for while its user is locked: blocking it then, or once all of the user's apps
 * are blocked then, letting it through, as calling and messaging apps need.
 */
@Composable
fun LockedSwitch(userId: Int, rules: Int?, allowed: Boolean, change: (Int) -> Unit) {
    val context = LocalContext.current
    val all by
        remember(userId) { Firewall.blockedWhileLocked(userId) }.collectAsStateWithLifecycle(null)
    // One of the bits at a time, so a switch never hides what the other one does.
    val (bit, other) =
        if (all == true) IFirewall.ALLOW_LOCKED to IFirewall.BLOCK_LOCKED
        else IFirewall.BLOCK_LOCKED to IFirewall.ALLOW_LOCKED
    SwitchPreference(
        object : SwitchPreferenceModel {
            override val title =
                stringResource(
                    if (all == true) R.string.allow_while_locked else R.string.block_while_locked
                )
            override val summary = {
                context.getString(
                    if (all == true) R.string.allow_while_locked_summary
                    else R.string.block_while_locked_summary
                )
            }
            override val checked = { rules?.let { it and bit != 0 && it and other == 0 } }
            override val changeable = { allowed && all != null }
            override val onCheckedChange: (Boolean) -> Unit = {
                change((rules ?: 0).with(bit, it).with(other, false))
            }
        }
    )
}

/** The switch that blocks all of the user's apps while it's locked, but those let through. */
@Composable
fun BlockAllWhileLockedSwitch(userId: Int) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val all by
        remember(userId) { Firewall.blockedWhileLocked(userId) }.collectAsStateWithLifecycle(null)
    SwitchPreference(
        object : SwitchPreferenceModel {
            override val title = stringResource(R.string.block_all_while_locked)
            override val summary = { context.getString(R.string.block_all_while_locked_summary) }
            override val checked = { all }
            override val onCheckedChange: (Boolean) -> Unit = { on ->
                scope.launch { Firewall.call { setBlockedWhileLocked(userId, on) } }
            }
        }
    )
}
