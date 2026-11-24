/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

/**
 * A group of apps, which follow its rules instead of their own. Its rules are set as an app's,
 * with IFirewall.GROUP_PREFIX and its id as the packageName.
 */
parcelable FirewallGroup {
    String id;
    String name;
}
