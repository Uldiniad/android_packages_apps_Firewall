/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall

import android.os.UserHandle
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

/** Whether the user's apps get the search engines' safe results, and Google's domains so far. */
private data class SafeSearchState(val on: Boolean, val googleChecked: Boolean)

private fun Firewall.safeSearch(userId: Int) = load {
    SafeSearchState(isSafeSearch(userId), (safeSearchDomains?.checkedMillis ?: 0L) != 0L)
}

/**
 * The switch for Safe Search in all of the user's apps. Turning it on downloads Google's list of
 * its search domains, which its other countries' sites wait for.
 */
@Composable
fun SafeSearchSwitch(userId: Int) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val state by remember(userId) { Firewall.safeSearch(userId) }.collectAsStateWithLifecycle(null)
    SwitchPreference(
        object : SwitchPreferenceModel {
            override val title = stringResource(R.string.safe_search_title)
            override val summary = {
                val summary =
                    context.getString(
                        if (userId == UserHandle.USER_SYSTEM) R.string.safe_search_summary_hotspot
                        else R.string.safe_search_summary
                    )
                if (state?.let { it.on && !it.googleChecked } == true) {
                    summary + "\n" + context.getString(R.string.safe_search_not_downloaded)
                } else {
                    summary
                }
            }
            override val checked = { state?.on }
            override val onCheckedChange: (Boolean) -> Unit = { on ->
                scope.launch {
                    Firewall.call { setSafeSearch(userId, on) }
                    if (on) ListUpdates.checkNew(context)
                }
            }
        }
    )
}
