/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall

import android.Manifest
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.UserHandle
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import com.android.settingslib.spa.framework.compose.LifecycleEffect
import com.android.settingslib.spa.widget.preference.Preference
import com.android.settingslib.spa.widget.preference.PreferenceModel
import com.android.settingslib.spaprivileged.model.app.PackageManagers

/** Android's local network permission, which the firewall also enforces through VPNs. */
@Composable
fun PackageInfo.LocalNetworkPreference(userId: Int) {
    val context = LocalContext.current
    val permission = Manifest.permission.ACCESS_LOCAL_NETWORK
    val defined = remember {
        try {
            context.packageManager.getPermissionInfo(permission, 0)
            true
        } catch (e: PackageManager.NameNotFoundException) {
            false
        }
    }
    if (!defined) return
    val app = checkNotNull(applicationInfo)
    // The page's package info comes without permissions; SPA's check reads them.
    val requested = remember { with(PackageManagers) { app.hasRequestPermission(permission) } }
    val uid = app.uid
    fun isGranted() =
        context.checkPermission(permission, -1, uid) == PackageManager.PERMISSION_GRANTED
    // Changed in PermissionController, so read again on return.
    var granted by remember { mutableStateOf(isGranted()) }
    LifecycleEffect(onStart = { granted = isGranted() })
    Preference(
        object : PreferenceModel {
            override val title = stringResource(R.string.local_network)
            override val summary = {
                context.getString(
                    if (granted) R.string.local_network_allowed
                    else R.string.local_network_not_allowed
                )
            }
            override val enabled = { requested }
            override val onClick = {
                context.startActivity(
                    Intent(Intent.ACTION_MANAGE_APP_PERMISSION)
                        .putExtra(Intent.EXTRA_PACKAGE_NAME, packageName)
                        .putExtra(Intent.EXTRA_PERMISSION_NAME, permission)
                        .putExtra(Intent.EXTRA_USER, UserHandle.of(userId))
                )
            }
        }
    )
}
