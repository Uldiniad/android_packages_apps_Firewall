/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

/** A list a user subscribed to, for one app or for all of their apps, and its last check. */
parcelable FirewallList {
    /** Its address, or for one added from a file an id of its own. */
    String id;
    /** The https address it's downloaded from; null for one added from a file. */
    @nullable String url;
    /** Whether plain names in it cover their subdomains too. */
    boolean subdomains;
    /** The app it's for, with the apps sharing its uid; null for all of the user's apps. */
    @nullable String packageName;
    int userId;
    /** As the list names itself, or as the user named a file. */
    @nullable String title;
    @nullable String version;
    int domains;
    int ranges;
    /** When its content last changed, and when it was last checked; 0 for never. */
    long changedMillis;
    long checkedMillis;
    /** An IFirewall.LIST_ERROR_* if the last check failed; for LIST_ERROR_SERVER, the status. */
    int error;
    int errorDetail;
    /** What the last download said of itself, for the next check's conditional request. */
    @nullable String etag;
    @nullable String lastModified;
}
