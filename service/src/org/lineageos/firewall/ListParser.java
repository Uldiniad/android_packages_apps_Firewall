/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import android.net.InetAddresses;
import android.net.IpPrefix;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.io.Reader;
import java.net.Inet4Address;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reads a downloaded list as data, line by line: hosts files, plain or wildcard domains, adblock
 * domain rules, addresses and ranges, and Spamhaus's JSON lines. A list can only block, so allow
 * rules and anything else it doesn't know are skipped.
 */
final class ListParser {
    /** Where the entries a list blocks go, as they're read. */
    interface Entries {
        void domain(String name, boolean subdomains);

        void prefix(IpPrefix prefix);
    }

    /**
     * What a list held: its data lines, the entries taken from them and those refused, the count
     * and names its header gives, if any, and whether it ran past the limits it was read with.
     */
    record Result(int lines, int taken, int refused, int declared, String title, String version,
            boolean tooBig) {}

    static final int NO_COUNT = -1;
    private static final int MAX_LINE = 4096;
    private static final int MIN_IPV4_PREFIX = 8;
    private static final int MIN_IPV6_PREFIX = 12;
    private static final List<IpPrefix> SPECIAL = List.of(
            new IpPrefix("0.0.0.0/8"), new IpPrefix("10.0.0.0/8"), new IpPrefix("100.64.0.0/10"),
            new IpPrefix("127.0.0.0/8"), new IpPrefix("169.254.0.0/16"),
            new IpPrefix("172.16.0.0/12"), new IpPrefix("192.0.0.0/24"),
            new IpPrefix("192.168.0.0/16"), new IpPrefix("224.0.0.0/4"),
            new IpPrefix("240.0.0.0/4"), new IpPrefix("::/127"),
            new IpPrefix("64:ff9b::/96"), new IpPrefix("64:ff9b:1::/48"),
            new IpPrefix("fc00::/7"), new IpPrefix("fe80::/10"), new IpPrefix("ff00::/8"));
    // What hosts files map to themselves, from the files' own conventions.
    private static final Set<String> HOSTS_BOILERPLATE = Set.of("localhost",
            "localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback",
            "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters", "ip6-allhosts",
            "0.0.0.0");
    private static final Set<String> COUNT_FIELDS =
            Set.of("number of entries", "entries", "number of unique domains");
    private static final Pattern HEADER_FIELD =
            Pattern.compile("[#!]\\s*([A-Za-z][A-Za-z ]*?)\\s*:\\s*(.+)");
    private static final Pattern ADBLOCK_DOMAIN =
            Pattern.compile("\\|\\|([^/^$|*\\s]+)\\^(?:\\$important)?");
    private static final Pattern SPACES = Pattern.compile("\\s+");

    private ListParser() {}

    /**
     * Reads the list, giving plain domains their subdomains too if the list means them so, and
     * stops once it holds more than maxEntries entries or more than maxChars characters.
     */
    static Result parse(Reader in, boolean plainSubdomains, int maxEntries, long maxChars,
            Entries entries) throws IOException {
        Counts counts = new Counts();
        LineReader reader = new LineReader(in, maxChars);
        boolean header = true;
        for (String raw = reader.next(); raw != null; raw = reader.next()) {
            if (reader.tooLong) {
                header = false;
                counts.lines++;
                continue;
            }
            String line = raw.strip();
            if (!line.isEmpty() && line.charAt(0) == '\uFEFF') line = line.substring(1).strip();
            if (line.isEmpty()) continue;
            char first = line.charAt(0);
            if (first == '#' || first == '!' || first == '[') {
                if (header) readHeaderField(line, counts);
                continue;
            }
            header = false;
            if (first == '{') {
                readJson(line, counts, entries);
            } else {
                readLine(line, plainSubdomains, counts, entries);
            }
            if (counts.taken > maxEntries) break;
        }
        return new Result(counts.lines, counts.taken, counts.refused, counts.declared,
                counts.title, counts.version, counts.taken > maxEntries || reader.overBudget);
    }

    private static void readHeaderField(String line, Counts counts) {
        Matcher field = HEADER_FIELD.matcher(line);
        if (!field.matches()) return;
        String key = field.group(1).toLowerCase(Locale.ROOT);
        String value = field.group(2).strip();
        if (key.equals("title")) {
            counts.title = value;
        } else if (key.equals("version")) {
            counts.version = value;
        } else if (COUNT_FIELDS.contains(key)) {
            String digits = value.replaceAll("[,. _]", "");
            if (digits.matches("\\d{1,9}")) counts.declared = Integer.parseInt(digits);
        }
    }

    // Spamhaus's records, and the metadata line that counts them.
    private static void readJson(String line, Counts counts, Entries entries) {
        JSONObject json;
        try {
            json = new JSONObject(line);
        } catch (JSONException e) {
            counts.lines++;
            return;
        }
        if ("metadata".equals(json.optString("type"))) {
            int records = json.optInt("records", NO_COUNT);
            if (records >= 0) counts.declared = records;
            return;
        }
        counts.lines++;
        String cidr = json.optString("cidr", null);
        if (cidr != null) takePrefix(cidr, counts, entries);
    }

    private static void readLine(String line, boolean plainSubdomains, Counts counts,
            Entries entries) {
        if (line.startsWith("@@")) {
            counts.lines++;
            return;
        }
        if (line.startsWith("||")) {
            counts.lines++;
            Matcher rule = ADBLOCK_DOMAIN.matcher(line);
            if (rule.matches()) takeDomain(rule.group(1), true, counts, entries);
            return;
        }
        String[] tokens = SPACES.split(withoutComment(line));
        if (tokens.length >= 2 && InetAddresses.isNumericAddress(tokens[0])) {
            // A hosts file's names, each blocked as itself.
            boolean counted = false;
            for (int i = 1; i < tokens.length; i++) {
                String name = tokens[i].toLowerCase(Locale.ROOT);
                if (HOSTS_BOILERPLATE.contains(name)) continue;
                if (!counted) counts.lines++;
                counted = true;
                takeDomain(name, false, counts, entries);
            }
            return;
        }
        counts.lines++;
        if (tokens.length != 1) return;
        String token = tokens[0];
        if (token.contains("/") || InetAddresses.isNumericAddress(token)) {
            takePrefix(token, counts, entries);
        } else {
            takeDomain(token, plainSubdomains || token.startsWith("*."), counts, entries);
        }
    }

    // Hosts files and plain lists comment after a #, Spamhaus's text lists after a ;.
    private static String withoutComment(String line) {
        for (int i = 1; i < line.length(); i++) {
            char c = line.charAt(i);
            if ((c == '#' || c == ';') && Character.isWhitespace(line.charAt(i - 1))) {
                return line.substring(0, i).strip();
            }
        }
        return line;
    }

    private static void takeDomain(String value, boolean subdomains, Counts counts,
            Entries entries) {
        String name;
        try {
            name = TargetRule.normalizeDomain(value);
        } catch (IllegalArgumentException e) {
            counts.refused++;
            return;
        }
        // A top-level domain alone would block everything under it.
        if (name.indexOf('.') < 0 || InetAddresses.isNumericAddress(name)) {
            counts.refused++;
            return;
        }
        counts.taken++;
        entries.domain(name, subdomains);
    }

    private static void takePrefix(String value, Counts counts, Entries entries) {
        IpPrefix prefix;
        try {
            prefix = TargetRule.parsePrefix(value);
        } catch (IllegalArgumentException e) {
            counts.refused++;
            return;
        }
        if (!blockable(prefix)) {
            counts.refused++;
            return;
        }
        counts.taken++;
        entries.prefix(prefix);
    }

    /**
     * Whether a list may block the range: not one wider than IANA gives a registry, a /8 or an
     * IPv6 /12, and not one that reaches a range the device itself depends on.
     */
    static boolean blockable(IpPrefix prefix) {
        boolean v4 = prefix.getAddress() instanceof Inet4Address;
        if (prefix.getPrefixLength() < (v4 ? MIN_IPV4_PREFIX : MIN_IPV6_PREFIX)) return false;
        for (IpPrefix special : SPECIAL) {
            if (special.contains(prefix.getAddress()) || prefix.contains(special.getAddress())) {
                return false;
            }
        }
        return true;
    }

    private static final class Counts {
        int lines;
        int taken;
        int refused;
        int declared = NO_COUNT;
        String title;
        String version;
    }

    /** Lines of at most MAX_LINE characters, within a budget of characters for the whole list. */
    private static final class LineReader {
        private final Reader mIn;
        private final char[] mBuffer = new char[8192];
        private final StringBuilder mLine = new StringBuilder();
        private final long mBudget;
        private long mRead;
        private int mPos;
        private int mEnd;
        private boolean mEof;
        boolean overBudget;
        /** Whether the line last returned ran past MAX_LINE, and so came back empty. */
        boolean tooLong;

        LineReader(Reader in, long budget) {
            mIn = in;
            mBudget = budget;
        }

        /** The next line, or null at the end or past the budget. */
        String next() throws IOException {
            mLine.setLength(0);
            tooLong = false;
            while (true) {
                if (mPos == mEnd) {
                    if (mEof || overBudget) break;
                    int n = mIn.read(mBuffer);
                    if (n < 0) {
                        mEof = true;
                        break;
                    }
                    mRead += n;
                    if (mRead > mBudget) {
                        overBudget = true;
                        return null;
                    }
                    mPos = 0;
                    mEnd = n;
                }
                char c = mBuffer[mPos++];
                if (c == '\n') return mLine.toString();
                if (tooLong) continue;
                if (mLine.length() == MAX_LINE) {
                    tooLong = true;
                    mLine.setLength(0);
                } else {
                    mLine.append(c);
                }
            }
            return tooLong || mLine.length() > 0 ? mLine.toString() : null;
        }
    }
}
