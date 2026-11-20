/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

/** Told when the firewall's rules, lists or settings change, so screens can reload them. */
oneway interface IFirewallListener {
    void onChanged();
}
