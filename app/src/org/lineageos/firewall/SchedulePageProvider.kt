/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall

import android.app.TimePickerDialog
import android.content.Context
import android.os.Bundle
import android.text.format.DateFormat
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavType
import androidx.navigation.navArgument
import com.android.settingslib.spa.framework.common.SettingsPageProvider
import com.android.settingslib.spa.framework.compose.navigator
import com.android.settingslib.spa.widget.editor.SettingsDropdownCheckBox
import com.android.settingslib.spa.widget.editor.SettingsDropdownCheckOption
import com.android.settingslib.spa.widget.preference.ListPreference
import com.android.settingslib.spa.widget.preference.ListPreferenceModel
import com.android.settingslib.spa.widget.preference.ListPreferenceOption
import com.android.settingslib.spa.widget.preference.MainSwitchPreference
import com.android.settingslib.spa.widget.preference.Preference
import com.android.settingslib.spa.widget.preference.PreferenceModel
import com.android.settingslib.spa.widget.preference.SwitchPreferenceModel
import com.android.settingslib.spa.widget.scaffold.RegularScaffold
import com.android.settingslib.spa.widget.ui.Footer
import java.time.DayOfWeek
import java.time.format.TextStyle
import java.util.Calendar
import java.util.Date
import kotlinx.coroutines.launch

private const val PACKAGE_NAME = "rt_packageName"
private const val USER_ID = "rt_userId"
private const val ALL_DAYS = 0x7f
// A bedtime, as a first schedule.
private const val FIRST_START = 22 * 60
private const val FIRST_END = 7 * 60

/** An app's weekly schedule, during which it is blocked. */
object SchedulePageProvider : SettingsPageProvider {
    override val name = "Schedule"

    override val parameter =
        listOf(
            navArgument(PACKAGE_NAME) { type = NavType.StringType },
            navArgument(USER_ID) { type = NavType.IntType },
        )

    @Composable
    fun navigator(packageName: String, userId: Int) =
        navigator(route = "$name/$packageName/$userId")

    @Composable
    override fun Page(arguments: Bundle?) {
        val args = checkNotNull(arguments)
        SchedulePage(checkNotNull(args.getString(PACKAGE_NAME)), args.getInt(USER_ID))
    }
}

@Composable
private fun SchedulePage(packageName: String, userId: Int) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val appRules by remember(userId) { Firewall.appRules(userId) }.collectAsStateWithLifecycle(null)
    val rule = appRules?.get(packageName)
    val days = rule?.scheduleDays ?: 0
    val start = if (days != 0) checkNotNull(rule).scheduleStart else FIRST_START
    val end = if (days != 0) checkNotNull(rule).scheduleEnd else FIRST_END
    val set: (Int, Int, Int) -> Unit = { newDays, newStart, newEnd ->
        // A window needs some length; the service refuses one without.
        if (newDays == 0 || newStart != newEnd) {
            scope.launch {
                Firewall.call { setSchedule(packageName, userId, newDays, newStart, newEnd) }
            }
        }
    }
    RegularScaffold(title = stringResource(R.string.schedule_title)) {
        MainSwitchPreference(
            object : SwitchPreferenceModel {
                override val title = stringResource(R.string.schedule_switch)
                override val checked = { appRules?.let { days != 0 } }
                override val onCheckedChange: (Boolean) -> Unit = { on ->
                    if (on) set(ALL_DAYS, start, end) else set(0, 0, 0)
                }
            }
        )
        for ((title, minute) in listOf(R.string.schedule_start to start, R.string.schedule_end to end)) {
            Preference(
                object : PreferenceModel {
                    override val title = stringResource(title)
                    override val summary = { context.formatMinute(minute) }
                    override val enabled = { days != 0 }
                    override val onClick = {
                        pickTime(context, minute) { picked ->
                            if (title == R.string.schedule_start) set(days, picked, end)
                            else set(days, start, picked)
                        }
                    }
                }
            )
        }
        if (days != 0) {
            val options =
                remember(days) {
                    DayOfWeek.entries.map { day ->
                        SettingsDropdownCheckOption(
                            day.getDisplayName(TextStyle.FULL, context.locale()),
                            selected = mutableStateOf(days and day.bit() != 0),
                        )
                    }
                }
            SettingsDropdownCheckBox(label = stringResource(R.string.schedule_days), options) {
                var chosen = 0
                options.forEachIndexed { index, option ->
                    if (option.selected.value) chosen = chosen or (1 shl index)
                }
                set(chosen, start, end)
            }
        }
        Footer(stringResource(R.string.schedule_footer))
    }
}

internal fun pickTime(context: Context, minute: Int, onPicked: (Int) -> Unit) {
    TimePickerDialog(
            context,
            { _, hour, picked -> onPicked(hour * 60 + picked) },
            minute / 60,
            minute % 60,
            DateFormat.is24HourFormat(context),
        )
        .show()
}

private fun DayOfWeek.bit() = 1 shl (value - 1)

private fun Context.locale() = resources.configuration.locales[0]

/** A minute of the day as the device shows times. */
fun Context.formatMinute(minute: Int): String {
    val calendar = Calendar.getInstance()
    calendar.set(Calendar.HOUR_OF_DAY, minute / 60)
    calendar.set(Calendar.MINUTE, minute % 60)
    return DateFormat.getTimeFormat(this).format(calendar.time)
}

/** A time in milliseconds since the epoch, as the device shows times. */
fun Context.formatTime(millis: Long): String = DateFormat.getTimeFormat(this).format(Date(millis))

/** How the app list sums up an app that a pause or its schedule decides on now, or null. */
fun Context.scheduleListSummary(rule: AppRule?): String? {
    if (rule == null) return null
    if (rule.pauseUntil > System.currentTimeMillis()) {
        return getString(
            if (rule.pauseBlocks) R.string.rules_blocked_until else R.string.rules_allowed_until,
            formatTime(rule.pauseUntil),
        )
    }
    if (rule.blockedNow && rule.rules and IFirewall.BLOCK_ALL == 0) {
        return getString(R.string.rules_blocked_schedule)
    }
    return null
}

/** An app's schedule, like "Mon, Tue, 22:00–07:00", or that it has none. */
fun Context.scheduleSummary(rule: AppRule?): String {
    val days = rule?.scheduleDays ?: 0
    if (days == 0) return getString(R.string.schedule_off)
    val names =
        DayOfWeek.entries
            .filter { days and it.bit() != 0 }
            .map { it.getDisplayName(TextStyle.SHORT, locale()) }
    val schedule = checkNotNull(rule)
    return getString(
        R.string.schedule_summary,
        formatList(names),
        formatMinute(schedule.scheduleStart),
        formatMinute(schedule.scheduleEnd),
    )
}

/** The app page's entries: a pause, and the weekly schedule. */
@Composable
fun ScheduleEntries(packageName: String, userId: Int, rule: AppRule?) {
    val context = LocalContext.current
    PausePreference(packageName, userId, rule)
    Preference(
        object : PreferenceModel {
            override val title = stringResource(R.string.schedule_title)
            override val summary = { context.scheduleSummary(rule) }
            override val onClick = SchedulePageProvider.navigator(packageName, userId)
        }
    )
}

/** Blocks the app, or allows it, for a while: the opposite of what it is now. */
@Composable
private fun PausePreference(packageName: String, userId: Int, rule: AppRule?) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val until = rule?.pauseUntil ?: 0
    val active = until > System.currentTimeMillis()
    val blocks = if (active) checkNotNull(rule).pauseBlocks else rule?.blockedNow != true
    val selected = remember(until) { mutableIntStateOf(if (active) -1 else 0) }
    val options = buildList {
        add(ListPreferenceOption(0, context.getString(R.string.pause_off)))
        if (active) {
            add(ListPreferenceOption(-1, context.getString(R.string.pause_until,
                    context.formatTime(until))))
        }
        for ((minutes, text) in PAUSES) add(ListPreferenceOption(minutes, context.getString(text)))
    }
    ListPreference(
        object : ListPreferenceModel {
            override val title =
                stringResource(if (blocks) R.string.pause_block_title else R.string.pause_allow_title)
            override val options = options
            override val selectedId = selected
            override val onIdSelected: (Int) -> Unit = { id ->
                if (id >= 0) {
                    val end = if (id == 0) 0 else System.currentTimeMillis() + id * 60_000L
                    scope.launch { Firewall.call { setPause(packageName, userId, blocks, end) } }
                }
            }
        }
    )
}

/** How long a pause lasts, in minutes, with its name. */
internal val PAUSES =
    listOf(
        15 to R.string.pause_15_minutes,
        60 to R.string.pause_1_hour,
        8 * 60 to R.string.pause_8_hours,
    )
