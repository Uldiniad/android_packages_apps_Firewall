/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import org.lineageos.firewall.AppRule;
import org.lineageos.firewall.IFirewallListener;

interface IFirewall {
    /** Rule bits; each set bit blocks the app somewhere. */
    const int BLOCK_ALL = 1;
    const int BLOCK_WIFI = 2;
    const int BLOCK_CELLULAR = 4;
    const int BLOCK_VPN = 8;
    const int BLOCK_OTHER = 16;
    /** Metered networks and roaming, whatever the transport; also while the app is in use. */
    const int BLOCK_METERED = 65536;
    const int BLOCK_ROAMING = 131072;

    void setAppRules(String packageName, int userId, int rules);
    /** Blocks the app, or allows it, until the time in milliseconds since the epoch; 0 ends it. */
    void setPause(String packageName, int userId, boolean block, long until);
    /**
     * Blocks the app each week on the days, as bits from Monday, from the start to the end minute
     * of the day, which is the next day's when before the start; no days clears it.
     */
    void setSchedule(String packageName, int userId, int days, int start, int end);
    int getAppRules(String packageName, int userId);
    AppRule[] getAppRulesForUser(int userId);

    void registerListener(IFirewallListener listener);
    void unregisterListener(IFirewallListener listener);
    /** Whether the firewall's programs are loaded and on; while not, apps aren't firewalled. */
    boolean isRunning();

    byte[] getBackupPayload(int userId);
    void applyRestore(int userId, in byte[] payload);
}
