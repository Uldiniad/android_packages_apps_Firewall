/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

/** A device on the phone's hotspot or tethering, or one with rules of its own. */
parcelable HotspotDevice {
    /** Its MAC address, as its rules name it after IFirewall.DEVICE_PREFIX. */
    String mac;
    /** The name it gave with its address, if any. */
    String name;
    /** Whether it's on the hotspot now. */
    boolean connected;
    /** The uid its own rules are kept under, which the activity log knows it by; 0 for none. */
    int uid;
}
