/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import org.lineageos.firewall.FirewallRule;

/** A rule, list or switch that accounts for a refused activity entry, as its page shows why. */
parcelable ActivityMatch {
    /** The IFirewall.REASON_* bit it accounts for. */
    int reason;
    /** Whose it is: an app's, a group's or a hotspot device's package, or null for all apps. */
    @nullable String packageName;
    @nullable FirewallRule rule;
    /** The list's title, or its address when it has none. */
    @nullable String list;
}
