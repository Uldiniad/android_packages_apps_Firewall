/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall

import android.os.UserManager
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.android.settingslib.spa.widget.preference.MainSwitchPreference
import com.android.settingslib.spa.widget.preference.SwitchPreferenceModel
import com.android.settingslib.spa.widget.ui.Footer
import kotlinx.coroutines.launch

fun Firewall.enabled() = load { isEnabled() }

/** The firewall's main switch, for the whole phone, which only an admin user can change. */
@Composable
fun FirewallMainSwitch() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val enabled by remember { Firewall.enabled() }.collectAsStateWithLifecycle(null)
    val admin = remember { context.getSystemService(UserManager::class.java).isAdminUser }
    MainSwitchPreference(
        object : SwitchPreferenceModel {
            override val title = stringResource(R.string.main_switch_title)
            override val checked = { enabled }
            override val changeable = { admin }
            override val onCheckedChange: (Boolean) -> Unit = { on ->
                scope.launch { Firewall.call { setEnabled(on) } }
            }
        }
    )
    OffForAWhilePreference(admin)
    if (!admin) Footer(stringResource(R.string.main_switch_admin_only))
}
