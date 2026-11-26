/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall

import android.os.Process
import android.os.UserHandle
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.android.settingslib.spa.widget.preference.SwitchPreference
import com.android.settingslib.spa.widget.preference.SwitchPreferenceModel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/** Whether the user is in lockdown, which blocks all of its apps but those allowed in it. */
fun Firewall.lockdown(userId: Int) = load { isLockdown(userId) }

/** The home page's switch for the user's lockdown, which the quick settings tile also flips. */
@Composable
fun LockdownPreference(userId: Int) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val on by remember(userId) { Firewall.lockdown(userId) }.collectAsStateWithLifecycle(null)
    SwitchPreference(
        object : SwitchPreferenceModel {
            override val title = stringResource(R.string.lockdown_title)
            override val summary = {
                context.getString(
                    if (userId == UserHandle.USER_SYSTEM) R.string.lockdown_summary_hotspot
                    else R.string.lockdown_summary
                )
            }
            override val checked = { on }
            override val onCheckedChange: (Boolean) -> Unit = { checked ->
                scope.launch { Firewall.call { setLockdown(userId, checked) } }
            }
        }
    )
}

/** An app's switch that lets it through while its user is in lockdown. */
@Composable
fun AllowInLockdownSwitch(rules: Int?, change: (Int) -> Unit) {
    val context = LocalContext.current
    SwitchPreference(
        object : SwitchPreferenceModel {
            override val title = stringResource(R.string.allow_in_lockdown)
            override val summary = { context.getString(R.string.allow_in_lockdown_summary) }
            override val checked = { rules?.let { it and IFirewall.ALLOW_LOCKDOWN != 0 } }
            override val onCheckedChange: (Boolean) -> Unit = {
                change((rules ?: 0).with(IFirewall.ALLOW_LOCKDOWN, it))
            }
        }
    )
}

/**
 * The quick settings tile for the lockdown of the user in front. Turning it on needs nothing more,
 * so it works from the lock screen; turning it off asks to unlock first.
 */
class LockdownTileService : TileService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private var listening: Job? = null
    // Not userId, which Context has already.
    private val user = Process.myUserHandle().identifier

    override fun onStartListening() {
        listening?.cancel()
        listening = scope.launch { Firewall.lockdown(user).collect { show(it) } }
    }

    override fun onStopListening() {
        listening?.cancel()
        listening = null
    }

    override fun onClick() {
        val on = qsTile?.state == Tile.STATE_ACTIVE
        val flip = { scope.launch { Firewall.call { setLockdown(user, !on) } } }
        if (on && isLocked) unlockAndRun { flip() } else flip()
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private fun show(on: Boolean) {
        val tile = qsTile ?: return
        tile.state = if (on) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.updateTile()
    }
}
