/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

/** A network that rules and an app's choices can name. */
parcelable KnownNetwork {
    /**
     * Every network of a kind is "wifi", "mobile", "vpn", "other", "metered" or "roaming". A
     * specific network is "wifi:" with its SSID as Android quotes it, "sim:" with its subscription
     * id, or "vpn:" with the VPN app's package name.
     */
    String key;
    /** What the user knows a specific network as: its SSID, the SIM's name, the VPN app's name. */
    String name;
    /** Whether the device is on the network now. */
    boolean connected;
}
