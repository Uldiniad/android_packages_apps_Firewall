/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlSerializer;

import java.io.IOException;
import java.io.PrintWriter;

/**
 * The firewall's main switch, for the whole phone. While it's off the programs are off and the
 * maps and the OEM deny chain are empty, so no app is firewalled; the rules stay, and can change,
 * for when it's back on.
 */
final class MainSwitch extends Feature {
    private static final String TAG_MAIN_SWITCH = "main-switch";

    /** Whether an admin turned the firewall off, which lasts across boots. */
    boolean off;

    MainSwitch(FirewallService service) {
        super(service);
    }

    @Override
    void clearStore() {
        off = false;
    }

    @Override
    boolean readStoreTag(XmlPullParser parser) {
        if (!TAG_MAIN_SWITCH.equals(parser.getName())) return false;
        off = "false".equals(parser.getAttributeValue(null, "on"));
        return true;
    }

    @Override
    void writeStore(XmlSerializer serializer) throws IOException {
        if (!off) return;
        serializer.startTag(null, TAG_MAIN_SWITCH);
        serializer.attribute(null, "on", "false");
        serializer.endTag(null, TAG_MAIN_SWITCH);
    }

    void setEnabledInternal(boolean enabled) {
        synchronized (mService) {
            if (off == !enabled) return;
            off = !enabled;
            if (off) mService.turnOffLocked(); else mService.turnOnLocked();
        }
        mService.saveAsync();
    }

    boolean isEnabledInternal() {
        synchronized (mService) {
            return !off;
        }
    }

    @Override
    void dumpLocked(PrintWriter pw) {
        pw.println("Main switch: " + (off ? "off" : "on"));
    }

    @Override
    Integer onShellCommand(String cmd, FirewallShellCommand shell) {
        switch (cmd) {
            case "set-enabled" -> {
                String enabled = shell.getNextArgRequired();
                if (!enabled.equals("true") && !enabled.equals("false")) {
                    throw new IllegalArgumentException("Unknown state " + enabled);
                }
                setEnabledInternal(enabled.equals("true"));
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
        pw.println("  set-enabled true|false");
        pw.println("  get-enabled");
    }
}
