/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall

import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.android.settingslib.spa.widget.preference.ListPreference
import com.android.settingslib.spa.widget.preference.ListPreferenceModel
import com.android.settingslib.spa.widget.preference.ListPreferenceOption
import java.time.LocalTime
import java.time.ZonedDateTime
import java.time.temporal.ChronoUnit
import kotlinx.coroutines.launch

fun Firewall.offUntil() = load { getOffUntil() }

/** The option for the time the firewall comes back on, while it's off for a while. */
private const val UNTIL = -1

/** The option that opens a time picker. */
private const val CHOOSE_TIME = -2

/**
 * Turns the firewall off for a while, as Firewalla's Emergency Access does, offered as an app's
 * pause is; it comes back on by itself. For admins only, as the main switch is.
 */
@Composable
fun OffForAWhilePreference(admin: Boolean) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val until by remember { Firewall.offUntil() }.collectAsStateWithLifecycle(0L)
    val active = until > 0
    val selected = remember(until) { mutableIntStateOf(if (active) UNTIL else 0) }
    val options = buildList {
        add(ListPreferenceOption(0, context.getString(R.string.pause_off)))
        if (active) {
            add(
                ListPreferenceOption(
                    UNTIL,
                    context.getString(R.string.pause_until, context.formatTime(until)),
                )
            )
        }
        for ((minutes, text) in PAUSES) add(ListPreferenceOption(minutes, context.getString(text)))
        add(ListPreferenceOption(CHOOSE_TIME, context.getString(R.string.off_choose_time)))
    }
    val turnOffUntil = { end: Long -> scope.launch { Firewall.call { turnOffUntil(end) } } }
    ListPreference(
        object : ListPreferenceModel {
            override val title = stringResource(R.string.off_for_a_while)
            override val options = options
            override val selectedId = selected
            override val enabled = { admin }
            override val onIdSelected: (Int) -> Unit = { id ->
                when {
                    id == 0 -> if (active) scope.launch { Firewall.call { setEnabled(true) } }
                    id == CHOOSE_TIME -> {
                        val inAnHour = LocalTime.now().plusHours(1)
                        pickTime(context, inAnHour.hour * 60 + inAnHour.minute) { minute ->
                            turnOffUntil(nextTimeOfDay(minute))
                        }
                    }
                    id > 0 -> turnOffUntil(System.currentTimeMillis() + id * 60_000L)
                }
            }
        }
    )
}

/** The next time the clock shows the minute of the day: today, or else tomorrow. */
private fun nextTimeOfDay(minute: Int): Long {
    val now = ZonedDateTime.now()
    var at = now.truncatedTo(ChronoUnit.DAYS).plusMinutes(minute.toLong())
    if (!at.isAfter(now)) at = at.plusDays(1)
    return at.toInstant().toEpochMilli()
}
