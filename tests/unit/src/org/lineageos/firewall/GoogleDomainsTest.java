/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Test;

import java.io.IOException;
import java.io.StringReader;
import java.util.Set;

public class GoogleDomainsTest {
    @Test
    public void takesGooglesListAndRefusesWhatIsntIt() throws IOException {
        assertEquals(Set.of("google.com", "google.co.uk", "google.cat"),
                GoogleDomains.parse(new StringReader(".google.com\n.Google.co.uk\n\n.google.cat\n")));
        // One name of another form, and the download isn't Google's list.
        assertNull(GoogleDomains.parse(new StringReader(".google.com\n.example.com\n")));
        assertNull(GoogleDomains.parse(new StringReader(".google.com\n.google.example.com\n")));
        assertNull(GoogleDomains.parse(new StringReader("<html>\n")));
        assertNull(GoogleDomains.parse(new StringReader("")));
    }
}
