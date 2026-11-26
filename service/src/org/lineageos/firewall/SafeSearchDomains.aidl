/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

/** Google's search domains for Safe Search, as the firewall app downloads them. */
parcelable SafeSearchDomains {
    /** The domains, such as google.co.uk; null when a check found them unchanged. */
    @nullable String[] names;
    /** The download's ETag and Last-Modified headers, for the next check to ask by. */
    @nullable String etag;
    @nullable String lastModified;
    /** When the domains were last checked, in milliseconds since the epoch; 0 before the first. */
    long checkedMillis;
}
