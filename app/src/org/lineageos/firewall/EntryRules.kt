/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall

import android.content.pm.ApplicationInfo
import android.net.Uri
import android.os.Bundle
import android.os.Process
import android.os.UserHandle
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavType
import androidx.navigation.navArgument
import com.android.settingslib.spa.framework.common.SettingsPageProvider
import com.android.settingslib.spa.framework.compose.navigator
import com.android.settingslib.spa.widget.preference.Preference
import com.android.settingslib.spa.widget.preference.PreferenceModel
import com.android.settingslib.spa.widget.ui.Category
import com.android.settingslib.spaprivileged.model.app.rememberAppRepository

/**
 * Adds a rule from an activity entry, set to block or allow where it went and for whom, as
 * Firewalla's Block on a flow presets the domain and the device; everything can still change.
 */
object AddEntryRulePageProvider : SettingsPageProvider {
    private const val USER_ID = "rt_userId"
    private const val PACKAGE_NAME = "rt_packageName"
    private const val ALLOW = "rt_allow"
    private const val KIND = "rt_kind"
    private const val VALUE = "rt_value"
    /** Stands for the rules for all apps in the route. */
    private const val ALL_APPS = "*"

    override val name = "AddEntryRule"

    override val parameter =
        listOf(
            navArgument(USER_ID) { type = NavType.IntType },
            navArgument(PACKAGE_NAME) { type = NavType.StringType },
            navArgument(ALLOW) { type = NavType.BoolType },
            navArgument(KIND) { type = NavType.StringType },
            navArgument(VALUE) { type = NavType.StringType },
        )

    @Composable
    fun navigator(
        userId: Int,
        packageName: String?,
        allow: Boolean,
        kind: RuleKind,
        value: String,
    ) =
        navigator(
            route =
                "$name/$userId/${Uri.encode(packageName ?: ALL_APPS)}/$allow/${kind.name}/" +
                    Uri.encode(value)
        )

    @Composable
    override fun Page(arguments: Bundle?) {
        val args = checkNotNull(arguments)
        AddRulesPage(
            args.getInt(USER_ID),
            checkNotNull(args.getString(PACKAGE_NAME)).takeIf { it != ALL_APPS },
            null,
            RulePrefill(
                args.getBoolean(ALLOW),
                RuleKind.valueOf(checkNotNull(args.getString(KIND))),
                checkNotNull(args.getString(VALUE)),
            ),
        )
    }
}

/**
 * An entry page's rows that add a rule for where the entry went: allowing it if it was blocked,
 * blocking it if not, for whoever it was for or for all apps.
 */
@Composable
internal fun EntryRules(
    userId: Int,
    entry: ActivityStore.Entry,
    app: ApplicationInfo?,
    device: HotspotDevice?,
) {
    if (entry.kind == IFirewall.ACTIVITY_INCOMING) return
    val value = entry.name ?: entry.address ?: return
    val repository = rememberAppRepository()
    val appLabel = app?.let { repository.produceLabel(it).value }
    val appRules by remember(userId) { Firewall.appRules(userId) }.collectAsStateWithLifecycle(null)
    val group = app?.let { appRules?.get(it.packageName) }?.takeIf { it.group != null }
    // Whose rules a rule for this entry joins: a group member's go to its group.
    val owner =
        when {
            group != null ->
                groupPackage(checkNotNull(group.group)) to (group.groupName ?: group.group)
            app != null -> app.packageName to (appLabel ?: app.packageName)
            device != null -> IFirewall.DEVICE_PREFIX + device.mac to (device.name ?: device.mac)
            UserHandle.getAppId(entry.uid) == Process.DNS_TETHER_UID ->
                IFirewall.HOTSPOT_PACKAGE to stringResource(R.string.hotspot_title)
            else -> null
        }
    val kind = if (entry.name != null) RuleKind.DOMAIN else RuleKind.ADDRESS
    val allow = !entry.allowed
    Category(title = stringResource(R.string.entry_rules)) {
        if (owner != null) {
            val open = AddEntryRulePageProvider.navigator(userId, owner.first, allow, kind, value)
            Preference(
                object : PreferenceModel {
                    override val title =
                        stringResource(
                            if (allow) R.string.allow_for else R.string.block_for,
                            owner.second,
                        )
                    override val onClick = open
                }
            )
        }
        val openForAll = AddEntryRulePageProvider.navigator(userId, null, allow, kind, value)
        Preference(
            object : PreferenceModel {
                override val title =
                    stringResource(
                        if (allow) R.string.allow_for_all_apps else R.string.block_for_all_apps
                    )
                override val onClick = openForAll
            }
        )
    }
}
