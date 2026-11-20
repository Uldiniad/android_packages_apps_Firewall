/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

/** An app's rules for one user, and whether they are a default the user hasn't decided on. */
parcelable AppRule {
    String packageName;
    int rules;
    boolean isDefault;
    boolean notified;
    /** How many FirewallRules the app has. */
    int ruleCount;
    /** The specific networks the app has its own choice for, by KnownNetwork key. */
    String[] allowedNetworks;
    String[] blockedNetworks;
    /** Whether a pause blocks the app or allows it, and until when; 0 for no pause. */
    boolean pauseBlocks;
    long pauseUntil;
    /** The days of the app's weekly schedule, as bits from Monday, and its minutes of the day. */
    int scheduleDays;
    int scheduleStart;
    int scheduleEnd;
    /** Whether the app is blocked now, by its switch, a pause or its schedule. */
    boolean blockedNow;
}
