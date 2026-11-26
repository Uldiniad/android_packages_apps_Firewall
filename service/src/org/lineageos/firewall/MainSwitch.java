/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import android.app.AlarmManager;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlSerializer;

import java.io.IOException;
import java.io.PrintWriter;

/**
 * The firewall's main switch, for the whole phone. While it's off the programs are off and the
 * maps and the OEM deny chain are empty, so no app is firewalled; the rules stay, and can change,
 * for when it's back on. An admin can also turn it off for a while, as Firewalla's Emergency
 * Access, and it comes back on by itself.
 */
final class MainSwitch extends Feature {
    private static final String TAG_MAIN_SWITCH = "main-switch";

    /** Whether an admin turned the firewall off, which lasts across boots. */
    boolean off;
    /** For a while off: the wall-clock time the firewall comes back on, else 0. */
    long offUntil;
    private final AlarmManager.OnAlarmListener mOnTime = this::onTime;

    MainSwitch(FirewallService service) {
        super(service);
    }

    @Override
    void clearStore() {
        off = false;
        offUntil = 0;
    }

    @Override
    boolean readStoreTag(XmlPullParser parser) {
        if (!TAG_MAIN_SWITCH.equals(parser.getName())) return false;
        off = "false".equals(parser.getAttributeValue(null, "on"));
        String until = parser.getAttributeValue(null, "until");
        offUntil = off && until != null ? Long.parseLong(until) : 0;
        return true;
    }

    @Override
    void writeStore(XmlSerializer serializer) throws IOException {
        if (!off) return;
        serializer.startTag(null, TAG_MAIN_SWITCH);
        serializer.attribute(null, "on", "false");
        if (offUntil != 0) serializer.attribute(null, "until", Long.toString(offUntil));
        serializer.endTag(null, TAG_MAIN_SWITCH);
    }

    /** On or off until it's turned back; ends a while off. */
    void setEnabledInternal(boolean enabled) {
        synchronized (mService) {
            boolean timed = offUntil != 0;
            offUntil = 0;
            scheduleLocked();
            if (off != enabled && !timed) return;
            if (off == enabled) {
                off = !enabled;
                if (off) mService.turnOffLocked(); else mService.turnOnLocked();
            }
        }
        mService.saveAsync();
    }

    /** Turns the firewall off until the wall-clock time, when it comes back on. */
    void turnOffUntilInternal(long until) {
        synchronized (mService) {
            offUntil = until;
            if (!off) {
                off = true;
                mService.turnOffLocked();
            }
            scheduleLocked();
        }
        mService.saveAsync();
    }

    /** When the firewall comes back on by itself, or 0 when it won't. */
    long offUntilInternal() {
        synchronized (mService) {
            return off ? offUntil : 0;
        }
    }

    boolean isEnabledInternal() {
        synchronized (mService) {
            return !off;
        }
    }

    @Override
    void onBootPhase() {
        // Comes back on if its time passed while the phone was off, else sets the alarm.
        onTime();
    }

    /** At the end of a while off: back on. */
    void onTime() {
        boolean due;
        synchronized (mService) {
            due = off && offUntil != 0 && offUntil <= mService.clock().millis();
            if (!due) scheduleLocked();
        }
        if (due) setEnabledInternal(true);
    }

    private void scheduleLocked() {
        AlarmManager alarms = mService.context().getSystemService(AlarmManager.class);
        if (alarms == null) return;
        alarms.cancel(mOnTime);
        if (off && offUntil != 0) {
            alarms.setExact(AlarmManager.RTC_WAKEUP, offUntil, FirewallService.TAG, mOnTime,
                    mService.handler());
        }
    }

    @Override
    void dumpLocked(PrintWriter pw) {
        pw.println("Main switch: " + (off ? "off" : "on")
                + (off && offUntil != 0 ? " until " + offUntil : ""));
    }

    @Override
    Integer onShellCommand(String cmd, FirewallShellCommand shell) {
        switch (cmd) {
            case "set-enabled" -> {
                String enabled = shell.getNextArgRequired();
                if (!enabled.equals("true") && !enabled.equals("false")) {
                    throw new IllegalArgumentException("Unknown state " + enabled);
                }
                String option = shell.getNextOption();
                if (option == null) {
                    setEnabledInternal(enabled.equals("true"));
                } else if (option.equals("--for") && enabled.equals("false")) {
                    long minutes = Long.parseLong(shell.getNextArgRequired());
                    turnOffUntilInternal(mService.clock().millis() + minutes * 60_000);
                } else {
                    throw new IllegalArgumentException("Unknown option " + option);
                }
            }
            case "get-enabled" -> shell.getOutPrintWriter().println(isEnabledInternal());
            default -> {
                return null;
            }
        }
        return 0;
    }

    @Override
    void onShellHelp(PrintWriter pw) {
        pw.println("  set-enabled true|false [--for MINUTES]  (off for a while, then back on)");
        pw.println("  get-enabled");
    }
}
