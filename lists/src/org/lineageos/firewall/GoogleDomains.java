/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * Google's search domains, as its list at www.google.com/supported_domains gives them, one per
 * line with a leading dot, such as ".google.co.uk", which Safe Search points to Google's
 * safe-search name. Read as data: only names of Google's own form are taken, so a bad download
 * can't point another site there.
 */
final class GoogleDomains {
    static final String URL = "https://www.google.com/supported_domains";
    /** Far more than Google has; past it the download isn't the list. */
    static final int MAX = 1000;
    private static final int MAX_CHARS = 64 * 1024;
    private static final Pattern DOMAIN = Pattern.compile("google(\\.[a-z]{2,3}){1,2}");

    private GoogleDomains() {}

    /** Whether the name is of the form Google's search domains have, such as google.co.uk. */
    static boolean valid(String name) {
        return name != null && DOMAIN.matcher(name).matches();
    }

    /** The domains, without their leading dots; null when the download isn't Google's list. */
    static Set<String> parse(Reader in) throws IOException {
        Set<String> domains = new TreeSet<>();
        BufferedReader reader = new BufferedReader(in);
        long chars = 0;
        for (String line = reader.readLine(); line != null; line = reader.readLine()) {
            chars += line.length() + 1;
            if (chars > MAX_CHARS) return null;
            String name = line.strip().toLowerCase(Locale.ROOT);
            if (name.isEmpty()) continue;
            if (name.startsWith(".")) name = name.substring(1);
            if (!valid(name)) return null;
            domains.add(name);
        }
        return domains.isEmpty() || domains.size() > MAX ? null : domains;
    }
}
