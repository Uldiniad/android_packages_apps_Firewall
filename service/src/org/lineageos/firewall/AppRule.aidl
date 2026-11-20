/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

/** An app's rules for one user. */
parcelable AppRule {
    String packageName;
    int rules;
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
