/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import android.app.AlarmManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.util.Pair;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlSerializer;

import java.io.IOException;
import java.io.PrintWriter;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

/** Pauses, which block or allow an app for a while, and weekly schedules that block it. */
final class Schedules extends Feature {
    private static final List<String> DAYS =
            List.of("mon", "tue", "wed", "thu", "fri", "sat", "sun");

    /** Blocks, or allows, until a time in milliseconds since the epoch. */
    record Pause(boolean block, long until) {}

    /**
     * Blocks on the days, as bits from Monday, from the start to the end minute of the day; an
     * end before the start is the next day's.
     */
    record Schedule(int days, int start, int end) {}

    /** Apps blocked or allowed for a while, over their own switch and schedule. */
    final Map<Pair<String, Integer>, Pause> pauses = new HashMap<>();
    /** When each week apps are blocked. */
    final Map<Pair<String, Integer>, Schedule> schedules = new HashMap<>();
    private final AlarmManager.OnAlarmListener mOnTime = this::onTime;

    Schedules(FirewallService service) {
        super(service);
    }

    @Override
    void clearStore() {
        pauses.clear();
        schedules.clear();
    }

    @Override
    boolean readStoreTag(XmlPullParser parser) {
        switch (parser.getName()) {
            case "pause" -> pauses.put(FirewallStore.appOf(parser), new Pause(
                    "true".equals(parser.getAttributeValue(null, "block")),
                    Long.parseLong(parser.getAttributeValue(null, "until"))));
            case "schedule" -> schedules.put(FirewallStore.appOf(parser), readSchedule(parser));
            default -> {
                return false;
            }
        }
        return true;
    }

    @Override
    void writeStore(XmlSerializer serializer) throws IOException {
        for (Map.Entry<Pair<String, Integer>, Pause> app : pauses.entrySet()) {
            serializer.startTag(null, "pause");
            FirewallStore.writeApp(serializer, app.getKey());
            serializer.attribute(null, "block", Boolean.toString(app.getValue().block()));
            serializer.attribute(null, "until", Long.toString(app.getValue().until()));
            serializer.endTag(null, "pause");
        }
        for (Map.Entry<Pair<String, Integer>, Schedule> app : schedules.entrySet()) {
            serializer.startTag(null, "schedule");
            FirewallStore.writeApp(serializer, app.getKey());
            writeSchedule(serializer, app.getValue());
            serializer.endTag(null, "schedule");
        }
    }

    static Schedule readSchedule(XmlPullParser parser) {
        return new Schedule(Integer.parseInt(parser.getAttributeValue(null, "days")),
                Integer.parseInt(parser.getAttributeValue(null, "start")),
                Integer.parseInt(parser.getAttributeValue(null, "end")));
    }

    static void writeSchedule(XmlSerializer serializer, Schedule schedule) throws IOException {
        serializer.attribute(null, "days", Integer.toString(schedule.days()));
        serializer.attribute(null, "start", Integer.toString(schedule.start()));
        serializer.attribute(null, "end", Integer.toString(schedule.end()));
    }

    @Override
    Object backupAppLocked(Pair<String, Integer> app) {
        return schedules.get(app);
    }

    @Override
    void writeBackupTags(Object part, boolean user, XmlSerializer serializer) throws IOException {
        serializer.startTag(null, "schedule");
        writeSchedule(serializer, (Schedule) part);
        serializer.endTag(null, "schedule");
    }

    @Override
    boolean readBackupTag(XmlPullParser parser, boolean user, FirewallBackup.Parts parts) {
        if (user || !"schedule".equals(parser.getName())) return false;
        try {
            Schedule schedule = readSchedule(parser);
            parts.put(this, valid(schedule) ? schedule : null);
        } catch (NumberFormatException e) {
            parts.put(this, null);
        }
        return true;
    }

    @Override
    void restoreAppLocked(Pair<String, Integer> app, FirewallBackup.App restored) {
        Schedule schedule = (Schedule) restored.parts().get(this);
        if (schedule == null) {
            schedules.remove(app);
        } else {
            mService.store().apps.putIfAbsent(app, 0);
            schedules.put(app, schedule);
        }
    }

    @Override
    void onRestoredLocked(int userId) {
        scheduleNextChangeLocked();
    }

    @Override
    void onBootPhase() {
        IntentFilter time = new IntentFilter(Intent.ACTION_TIME_CHANGED);
        time.addAction(Intent.ACTION_TIMEZONE_CHANGED);
        mService.context().registerReceiver(new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                onTime();
            }
        }, time, null, mService.handler());
        synchronized (mService) {
            scheduleNextChangeLocked();
        }
    }

    @Override
    boolean forgetAppsLocked(Predicate<Pair<String, Integer>> gone) {
        return pauses.keySet().removeIf(gone) | schedules.keySet().removeIf(gone);
    }

    @Override
    boolean forgetUserLocked(int userId) {
        return pauses.keySet().removeIf(app -> app.second == userId)
                | schedules.keySet().removeIf(app -> app.second == userId);
    }

    @Override
    void copyAppLocked(Pair<String, Integer> from, Pair<String, Integer> to) {
        copyEntry(pauses, from, to, pause -> pause);
        copyEntry(schedules, from, to, schedule -> schedule);
    }

    /** The app's rules at the time: a pause's while it lasts, else its own and its schedule's. */
    @Override
    int rulesNowLocked(Pair<String, Integer> app, int rules, long now) {
        Pause pause = pauses.get(app);
        boolean blocked = pause != null && pause.until() > now ? pause.block()
                : (rules & FirewallMaps.BLOCK_ALL) != 0 || inSchedule(schedules.get(app), now);
        return blocked ? rules | FirewallMaps.BLOCK_ALL : rules & ~FirewallMaps.BLOCK_ALL;
    }

    @Override
    void fillAppRuleLocked(Pair<String, Integer> app, AppRule rule) {
        Pause pause = pauses.get(app);
        if (pause != null) {
            rule.pauseBlocks = pause.block();
            rule.pauseUntil = pause.until();
        }
        Schedule schedule = schedules.get(app);
        if (schedule != null) {
            rule.scheduleDays = schedule.days();
            rule.scheduleStart = schedule.start();
            rule.scheduleEnd = schedule.end();
        }
    }

    /** A schedule's window on a day, which ends the next day when its end is before its start. */
    private static ZonedDateTime[] window(Schedule schedule, LocalDate day) {
        ZoneId zone = ZoneId.systemDefault();
        LocalDate endDay = schedule.end() > schedule.start() ? day : day.plusDays(1);
        return new ZonedDateTime[] {
                day.atTime(LocalTime.ofSecondOfDay(schedule.start() * 60L)).atZone(zone),
                endDay.atTime(LocalTime.ofSecondOfDay(schedule.end() * 60L)).atZone(zone)};
    }

    private static boolean onDay(Schedule schedule, LocalDate day) {
        return (schedule.days() & (1 << (day.getDayOfWeek().getValue() - 1))) != 0;
    }

    /** Whether the schedule blocks at the time, in the device's time zone. */
    static boolean inSchedule(Schedule schedule, long now) {
        if (schedule == null) return false;
        Instant time = Instant.ofEpochMilli(now);
        LocalDate today = time.atZone(ZoneId.systemDefault()).toLocalDate();
        // A window past midnight began the day before.
        for (LocalDate day : List.of(today.minusDays(1), today)) {
            if (!onDay(schedule, day)) continue;
            ZonedDateTime[] window = window(schedule, day);
            if (!time.isBefore(window[0].toInstant()) && time.isBefore(window[1].toInstant())) {
                return true;
            }
        }
        return false;
    }

    /** When the schedule next starts or ends after the time; Long.MAX_VALUE for never. */
    static long nextScheduleChange(Schedule schedule, long now) {
        LocalDate today = Instant.ofEpochMilli(now).atZone(ZoneId.systemDefault()).toLocalDate();
        long next = Long.MAX_VALUE;
        for (int day = -1; day <= 7; day++) {
            if (!onDay(schedule, today.plusDays(day))) continue;
            for (ZonedDateTime edge : window(schedule, today.plusDays(day))) {
                long millis = edge.toInstant().toEpochMilli();
                if (millis > now) next = Math.min(next, millis);
            }
        }
        return next;
    }

    /** Sets the alarm for when a pause ends or a schedule starts or ends next. */
    void scheduleNextChangeLocked() {
        AlarmManager alarms = mService.context().getSystemService(AlarmManager.class);
        if (alarms == null) return;
        long now = mService.clock().millis();
        long next = Long.MAX_VALUE;
        for (Pause pause : pauses.values()) {
            if (pause.until() > now) next = Math.min(next, pause.until());
        }
        for (Schedule schedule : schedules.values()) {
            next = Math.min(next, nextScheduleChange(schedule, now));
        }
        alarms.cancel(mOnTime);
        if (next != Long.MAX_VALUE) {
            alarms.setExact(AlarmManager.RTC_WAKEUP, next, FirewallService.TAG, mOnTime,
                    mService.handler());
        }
    }

    /** At a pause's end, a schedule's edge or a change of clock: applies the rules of the time. */
    void onTime() {
        synchronized (mService) {
            long now = mService.clock().millis();
            pauses.values().removeIf(pause -> pause.until() <= now);
            if (mService.mapsReady()) mService.syncAppsLocked();
            scheduleNextChangeLocked();
        }
        // Also tells listeners, as what's blocked changed.
        mService.saveAsync();
    }

    /** Blocks the app, or allows it, until the time in milliseconds since the epoch; 0 ends it. */
    void setPauseInternal(String packageName, int userId, boolean block, long until) {
        synchronized (mService) {
            for (Pair<String, Integer> app : mService.sharingUidLocked(packageName, userId)) {
                if (until <= mService.clock().millis()) {
                    pauses.remove(app);
                } else {
                    mService.store().apps.putIfAbsent(app, 0);
                    pauses.put(app, new Pause(block, until));
                }
            }
            if (mService.mapsReady()) mService.syncAppsLocked();
            scheduleNextChangeLocked();
        }
        mService.saveAsync();
    }

    /**
     * Blocks the app each week on the days, as bits from Monday, from the start to the end
     * minute of the day, which is the next day's when before the start; no days clears it.
     */
    void setScheduleInternal(String packageName, int userId, int days, int start, int end) {
        if (days != 0 && !valid(new Schedule(days, start, end))) {
            throw new IllegalArgumentException("Not a schedule");
        }
        synchronized (mService) {
            for (Pair<String, Integer> app : mService.sharingUidLocked(packageName, userId)) {
                if (days == 0) {
                    schedules.remove(app);
                } else {
                    mService.store().apps.putIfAbsent(app, 0);
                    schedules.put(app, new Schedule(days, start, end));
                }
            }
            if (mService.mapsReady()) mService.syncAppsLocked();
            scheduleNextChangeLocked();
        }
        mService.saveAsync();
    }

    static boolean valid(Schedule schedule) {
        return (schedule.days() & ~0x7f) == 0 && schedule.days() != 0
                && schedule.start() >= 0 && schedule.start() < 24 * 60
                && schedule.end() >= 0 && schedule.end() < 24 * 60
                && schedule.start() != schedule.end();
    }

    private static int parseDays(String text) {
        int days = 0;
        for (String day : text.split(",")) {
            int index = DAYS.indexOf(day);
            if (index < 0) throw new IllegalArgumentException("Unknown day " + day);
            days |= 1 << index;
        }
        return days;
    }

    /** A time of day like 22:30, as its minute of the day. */
    private static int parseMinute(String text) {
        String[] parts = text.split(":");
        if (parts.length != 2) throw new IllegalArgumentException("Not a time: " + text);
        return Integer.parseInt(parts[0]) * 60 + Integer.parseInt(parts[1]);
    }

    @Override
    Integer onShellCommand(String cmd, FirewallShellCommand shell) {
        switch (cmd) {
            case "set-pause" -> {
                String packageName = shell.getNextArgRequired();
                String action = shell.getNextArgRequired();
                if (action.equals("none")) {
                    setPauseInternal(packageName, shell.parseUser(), false, 0);
                    return 0;
                }
                if (!action.equals("block") && !action.equals("allow")) {
                    throw new IllegalArgumentException("Unknown action " + action);
                }
                String time = shell.getNextArgRequired();
                long millis = time.endsWith("s")
                        ? Long.parseLong(time.substring(0, time.length() - 1)) * 1000
                        : Long.parseLong(time) * 60_000;
                setPauseInternal(packageName, shell.parseUser(), action.equals("block"),
                        System.currentTimeMillis() + millis);
            }
            case "set-schedule" -> {
                String packageName = shell.getNextArgRequired();
                String days = shell.getNextArgRequired();
                if (days.equals("none")) {
                    setScheduleInternal(packageName, shell.parseUser(), 0, 0, 0);
                    return 0;
                }
                int start = parseMinute(shell.getNextArgRequired());
                int end = parseMinute(shell.getNextArgRequired());
                setScheduleInternal(packageName, shell.parseUser(), parseDays(days), start, end);
            }
            default -> {
                return null;
            }
        }
        return 0;
    }

    @Override
    void onShellHelp(PrintWriter pw) {
        pw.println("  set-pause PACKAGE block|allow MINUTES | none [--user USER]");
        pw.println("      Blocks the app, or allows it, for a while, over its rules. MINUTES can");
        pw.println("      be seconds instead, with an s, like 30s.");
        pw.println("  set-schedule PACKAGE DAYS START END | none [--user USER]");
        pw.println("      Blocks the app each week on DAYS, a comma list of mon,tue,wed,thu,");
        pw.println("      fri,sat,sun, from START to END, like 22:00 07:00.");
    }
}
