/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import android.icu.text.IDNA;
import android.net.IpPrefix;

import java.util.regex.Pattern;

/** Domains and address ranges as rules and lists name them, read alike by the service and app. */
final class Names {
    private static final Pattern DOMAIN_NAME = Pattern.compile("[a-z0-9_-]+(\\.[a-z0-9_-]+)*");

    private Names() {}

    static IpPrefix parsePrefix(String cidr) {
        String text = cidr.contains("/") ? cidr : cidr + (cidr.contains(":") ? "/128" : "/32");
        return new IpPrefix(text);
    }

    /** A domain as DNS carries it: ASCII, lowercase, without the root dot or a wildcard. */
    static String normalizeDomain(String domain) {
        String name = domain.trim();
        if (name.startsWith("*.")) name = name.substring(2);
        while (name.endsWith(".")) name = name.substring(0, name.length() - 1);
        IDNA.Info info = new IDNA.Info();
        String ascii = IDNA.getUTS46Instance(IDNA.NONTRANSITIONAL_TO_ASCII)
                .nameToASCII(name, new StringBuilder(), info).toString();
        if (info.hasErrors() || !DOMAIN_NAME.matcher(ascii).matches()) {
            throw new IllegalArgumentException("Not a domain: " + domain);
        }
        return ascii;
    }
}
