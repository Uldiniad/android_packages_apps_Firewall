/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import static org.junit.Assert.assertEquals;

import android.util.Pair;

import org.junit.Test;

import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/** Pauses and weekly schedules. */
public class SchedulesTest extends ServiceTestBase {
    @Test
    public void pausesBlockOrAllowAnAppUntilTheirTime() {
        FirewallService service = start();
        Schedules schedules = service.feature(Schedules.class);
        long hour = Duration.ofHours(1).toMillis();
        schedules.setPauseInternal(PACKAGE, 0, true, mClock.millis() + hour);
        assertEquals(FirewallMaps.BLOCK_ALL, blockAll());
        mClock.now = mClock.now.plusMillis(hour);
        schedules.onTime();
        assertEquals(0, blockAll());

        service.setAppRulesInternal(PACKAGE, 0, FirewallMaps.BLOCK_ALL);
        schedules.setPauseInternal(PACKAGE, 0, false, mClock.millis() + hour);
        assertEquals(0, blockAll());
        // Ended early, the app's own switch is back.
        schedules.setPauseInternal(PACKAGE, 0, false, 0);
        assertEquals(FirewallMaps.BLOCK_ALL, blockAll());
    }

    @Test
    public void schedulesBlockAnAppInTheirWindowOnTheirDays() {
        FirewallService service = start();
        Schedules schedules = service.feature(Schedules.class);
        int monday = 1;
        schedules.setScheduleInternal(PACKAGE, 0, monday, 9 * 60, 17 * 60);
        assertEquals(FirewallMaps.BLOCK_ALL, blockAll());
        mClock.now = monday(17, 0);
        schedules.onTime();
        assertEquals(0, blockAll());

        // A window ending before it starts goes on into the next day.
        schedules.setScheduleInternal(PACKAGE, 0, monday, 22 * 60, 7 * 60);
        mClock.now = monday(22, 0).plus(Duration.ofHours(8));
        schedules.onTime();
        assertEquals(FirewallMaps.BLOCK_ALL, blockAll());
        mClock.now = monday(22, 0).plus(Duration.ofHours(9));
        schedules.onTime();
        assertEquals(0, blockAll());
    }

    @Test
    public void schedulesGoWithBackups() {
        FirewallService service = start();
        Schedules schedules = service.feature(Schedules.class);
        BackupRestore backups = service.feature(BackupRestore.class);
        schedules.setScheduleInternal(PACKAGE, 0, 0x1f, 22 * 60, 7 * 60);
        byte[] payload = backups.getBackupPayloadInternal(0);
        schedules.setScheduleInternal(PACKAGE, 0, 0, 0, 0);
        backups.applyRestoreInternal(0, payload);
        AppRule rule = Arrays.stream(service.getAppRulesForUserInternal(0))
                .filter(r -> r.packageName.equals(PACKAGE)).findFirst().orElseThrow();
        assertEquals(List.of(0x1f, 22 * 60, 7 * 60),
                List.of(rule.scheduleDays, rule.scheduleStart, rule.scheduleEnd));
    }

    @Test
    public void pausesAndSchedulesSurviveSaveAndLoad() {
        FirewallService service = unstarted();
        Pair<String, Integer> app = Pair.create("org.example.app", 10);
        Schedules schedules = service.feature(Schedules.class);
        schedules.pauses.put(app, new Schedules.Pause(true, 1_800_000_000_000L));
        schedules.schedules.put(app, new Schedules.Schedule(0x60, 9 * 60, 17 * 60));
        service.store().save();

        FirewallService loaded = unstarted();
        loaded.store().load();
        assertEquals(Map.of(app, new Schedules.Pause(true, 1_800_000_000_000L)),
                loaded.feature(Schedules.class).pauses);
        assertEquals(Map.of(app, new Schedules.Schedule(0x60, 9 * 60, 17 * 60)),
                loaded.feature(Schedules.class).schedules);
    }
}
