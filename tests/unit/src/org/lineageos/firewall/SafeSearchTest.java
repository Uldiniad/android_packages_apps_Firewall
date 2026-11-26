/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/** Safe Search for all of a user's apps, with Google's search domains as the app downloads them. */
public class SafeSearchTest extends ServiceTestBase {
    private static final String UK = FakeMaps.scope(FirewallMaps.SAFE_SEARCH_SCOPE) + ":google.co.uk";
    private static final String DE = FakeMaps.scope(FirewallMaps.SAFE_SEARCH_SCOPE) + ":google.de";

    private int userFlags() {
        return mMaps.userFlags.getOrDefault(0, 0);
    }

    private static SafeSearchDomains download(String etag, String... names) {
        SafeSearchDomains domains = new SafeSearchDomains();
        domains.names = names;
        domains.etag = etag;
        return domains;
    }

    @Test
    public void aUsersSafeSearchHoldsItsAppsToAndroidsDnsAndOutlivesARestoreFromABackup() {
        FirewallService service = start();
        SafeSearch safeSearch = service.feature(SafeSearch.class);
        // Nothing to download while no user has it on.
        assertNull(safeSearch.getDomainsInternal());
        safeSearch.setSafeSearchInternal(0, true);
        assertEquals(FirewallMaps.USER_SAFE_SEARCH | FirewallMaps.SCOPE_DOMAINS,
                userFlags() & (FirewallMaps.USER_SAFE_SEARCH | FirewallMaps.SCOPE_DOMAINS));
        assertEquals(0, safeSearch.getDomainsInternal().checkedMillis);
        byte[] payload = service.feature(BackupRestore.class).getBackupPayloadInternal(0);

        safeSearch.setSafeSearchInternal(0, false);
        assertEquals(0, userFlags() & FirewallMaps.USER_SAFE_SEARCH);
        service.feature(BackupRestore.class).applyRestoreInternal(0, payload);
        assertTrue(safeSearch.isSafeSearchInternal(0));
        assertEquals(FirewallMaps.USER_SAFE_SEARCH, userFlags() & FirewallMaps.USER_SAFE_SEARCH);
    }

    @Test
    public void googlesDownloadedDomainsGoToTheDomainMapAndStayThroughARestart() {
        FirewallService service = start();
        SafeSearch safeSearch = service.feature(SafeSearch.class);
        safeSearch.setSafeSearchInternal(0, true);
        safeSearch.setDomainsInternal(download("\"v1\"", "google.com", "google.co.uk"));
        assertTrue(mMaps.domains.containsKey(UK));
        assertEquals("\"v1\"", safeSearch.getDomainsInternal().etag);
        assertEquals(mClock.millis(), safeSearch.getDomainsInternal().checkedMillis);
        // A check that found them unchanged keeps them; a new list replaces them.
        safeSearch.setDomainsInternal(download("\"v1\"", (String[]) null));
        assertTrue(mMaps.domains.containsKey(UK));
        safeSearch.setDomainsInternal(download("\"v2\"", "google.com", "google.de"));
        assertTrue(mMaps.domains.containsKey(DE));
        assertNull(mMaps.domains.get(UK));
        // What isn't Google's form is refused whole, as the download can't be trusted.
        assertThrows(IllegalArgumentException.class,
                () -> safeSearch.setDomainsInternal(download(null, "google.de", "example.com")));
        assertTrue(mMaps.domains.containsKey(DE));
        service.store().save();

        mMaps.domains.clear();
        FirewallService restarted = start();
        assertTrue(mMaps.domains.containsKey(DE));
        assertEquals("\"v2\"", restarted.feature(SafeSearch.class).getDomainsInternal().etag);
    }
}
