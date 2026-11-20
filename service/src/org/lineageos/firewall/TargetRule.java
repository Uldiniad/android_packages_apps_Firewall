/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import android.icu.text.IDNA;
import android.net.IpPrefix;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlSerializer;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * A rule blocking or allowing an address range, a domain or a remote port, in its normal form,
 * on every network, only on the networks it names, or on all but those.
 */
record TargetRule(boolean allow, int kind, String value, boolean subdomains, int protocol,
        List<String> networks, boolean exceptNetworks) implements Comparable<TargetRule> {
    static final int ADDRESS = IFirewall.RULE_ADDRESS;
    static final int DOMAIN = IFirewall.RULE_DOMAIN;
    static final int PORT = IFirewall.RULE_PORT;
    /** The kinds of network a rule can name, with the network bits that say a network is one. */
    static final Map<String, Integer> NETWORK_KINDS = Map.of(
            "wifi", FirewallMaps.BLOCK_WIFI, "mobile", FirewallMaps.BLOCK_CELLULAR,
            "vpn", FirewallMaps.BLOCK_VPN, "other", FirewallMaps.BLOCK_OTHER,
            "metered", FirewallMaps.BLOCK_METERED, "roaming", FirewallMaps.BLOCK_ROAMING);
    /** How the keys of specific networks start: an SSID, a subscription id, a package name. */
    static final String WIFI = "wifi:";
    static final String SIM = "sim:";
    static final String VPN = "vpn:";
    private static final String[] KINDS = {"address", "domain", "port"};
    private static final Pattern DOMAIN_NAME = Pattern.compile("[a-z0-9_-]+(\\.[a-z0-9_-]+)*");
    private static final Comparator<List<String>> LISTS = (a, b) -> {
        for (int i = 0; i < Math.min(a.size(), b.size()); i++) {
            int order = a.get(i).compareTo(b.get(i));
            if (order != 0) return order;
        }
        return Integer.compare(a.size(), b.size());
    };
    private static final Comparator<TargetRule> ORDER = Comparator.comparingInt(TargetRule::kind)
            .thenComparing(TargetRule::value).thenComparing(TargetRule::allow)
            .thenComparing(TargetRule::subdomains).thenComparingInt(TargetRule::protocol)
            .thenComparing(TargetRule::networks, LISTS)
            .thenComparing(TargetRule::exceptNetworks);

    /** Checks and normalizes a rule; throws IllegalArgumentException for a bad value. */
    static TargetRule of(boolean allow, int kind, String value, boolean subdomains, int protocol,
            Collection<String> networks, boolean exceptNetworks) {
        if (value == null) throw new IllegalArgumentException("No value");
        TreeSet<String> keys = new TreeSet<>();
        if (networks != null) {
            for (String network : networks) keys.add(normalizeNetwork(network));
        }
        List<String> limits = List.copyOf(keys);
        boolean except = exceptNetworks && !limits.isEmpty();
        return switch (kind) {
            case ADDRESS -> new TargetRule(allow, kind, parsePrefix(value.trim()).toString(),
                    false, 0, limits, except);
            case DOMAIN -> new TargetRule(allow, kind, normalizeDomain(value),
                    subdomains || value.trim().startsWith("*."), 0, limits, except);
            case PORT -> {
                int[] range = portRange(value);
                if (protocol != 0 && protocol != IFirewall.PROTOCOL_TCP
                        && protocol != IFirewall.PROTOCOL_UDP) {
                    throw new IllegalArgumentException("Unknown protocol " + protocol);
                }
                String normal = range[0] == range[1] ? Integer.toString(range[0])
                        : range[0] + "-" + range[1];
                yield new TargetRule(allow, kind, normal, false, protocol, limits, except);
            }
            default -> throw new IllegalArgumentException("Unknown kind " + kind);
        };
    }

    /** A port, or a range of them like 6881-6889, as its first and last port. */
    static int[] portRange(String value) {
        String[] ends = value.trim().split("\\s*-\\s*", -1);
        if (ends.length > 2) throw new IllegalArgumentException("Not a port: " + value);
        int first = Integer.parseInt(ends[0]);
        int last = Integer.parseInt(ends[ends.length - 1]);
        if (first < 1 || last > 65535 || first > last) {
            throw new IllegalArgumentException("Not a port: " + value);
        }
        return new int[] {first, last};
    }

    static TargetRule fromParcel(FirewallRule rule) {
        return of(rule.allow, rule.kind, rule.value, rule.subdomains, rule.protocol,
                rule.networks == null ? List.of() : Arrays.asList(rule.networks),
                rule.exceptNetworks);
    }

    FirewallRule toParcel(String packageName, int userId) {
        FirewallRule rule = new FirewallRule();
        rule.packageName = packageName;
        rule.userId = userId;
        rule.allow = allow;
        rule.kind = kind;
        rule.value = value;
        rule.subdomains = subdomains;
        rule.protocol = protocol;
        rule.networks = networks.toArray(new String[0]);
        rule.exceptNetworks = exceptNetworks;
        return rule;
    }

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

    /** Checks a network's key, as KnownNetwork describes it. */
    static String normalizeNetwork(String key) {
        if (key == null) throw new IllegalArgumentException("No network");
        if (NETWORK_KINDS.containsKey(key)) return key;
        if (key.startsWith(WIFI) && key.length() > WIFI.length()) return key;
        if (key.startsWith(SIM)) {
            int subscription = Integer.parseInt(key.substring(SIM.length()));
            if (subscription >= 0) return SIM + subscription;
        }
        if (key.startsWith(VPN)
                && key.substring(VPN.length()).matches("[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+)*")) {
            return key;
        }
        throw new IllegalArgumentException("Not a network: " + key);
    }

    /** The FirewallMaps.DOMAIN_* bits the rule puts on its domain. */
    int domainBits() {
        if (allow) {
            return FirewallMaps.DOMAIN_ALLOW
                    | (subdomains ? FirewallMaps.DOMAIN_ALLOW_SUBDOMAINS : 0);
        }
        return FirewallMaps.DOMAIN_BLOCK | (subdomains ? FirewallMaps.DOMAIN_BLOCK_SUBDOMAINS : 0);
    }

    /** The FirewallMaps.SCOPE_* flag of the lookups the rule needs. */
    int scopeFlags() {
        return switch (kind) {
            case ADDRESS -> allow ? FirewallMaps.SCOPE_IP_ALLOWS : FirewallMaps.SCOPE_IP_BLOCKS;
            case PORT -> allow ? FirewallMaps.SCOPE_PORT_ALLOWS : FirewallMaps.SCOPE_PORT_BLOCKS;
            default -> FirewallMaps.SCOPE_DOMAINS | (allow ? FirewallMaps.SCOPE_LEARNED : 0);
        };
    }

    void write(XmlSerializer serializer, Integer user, String packageName) throws IOException {
        serializer.startTag(null, "rule");
        if (user != null) serializer.attribute(null, "user", user.toString());
        if (packageName != null) serializer.attribute(null, "package", packageName);
        serializer.attribute(null, "action", allow ? "allow" : "block");
        serializer.attribute(null, "kind", KINDS[kind]);
        serializer.attribute(null, "value", value);
        if (kind == DOMAIN && !subdomains) serializer.attribute(null, "subdomains", "false");
        if (protocol != 0) serializer.attribute(null, "protocol", Integer.toString(protocol));
        if (exceptNetworks) serializer.attribute(null, "except", "true");
        for (String network : networks) {
            serializer.startTag(null, "network");
            serializer.attribute(null, "key", network);
            serializer.endTag(null, "network");
        }
        serializer.endTag(null, "rule");
    }

    /**
     * Reads a rule as written above, with the networks nested in it; throws
     * IllegalArgumentException for a bad one, after reading past it.
     */
    static TargetRule read(XmlPullParser parser) throws IOException, XmlPullParserException {
        boolean allow = "allow".equals(parser.getAttributeValue(null, "action"));
        int kind = Arrays.asList(KINDS).indexOf(parser.getAttributeValue(null, "kind"));
        String value = parser.getAttributeValue(null, "value");
        boolean subdomains = !"false".equals(parser.getAttributeValue(null, "subdomains"));
        String protocol = parser.getAttributeValue(null, "protocol");
        boolean except = "true".equals(parser.getAttributeValue(null, "except"));
        List<String> networks = new ArrayList<>();
        int depth = parser.getDepth();
        int type;
        while ((type = parser.next()) != XmlPullParser.END_DOCUMENT
                && !(type == XmlPullParser.END_TAG && parser.getDepth() == depth)) {
            if (type == XmlPullParser.START_TAG && "network".equals(parser.getName())) {
                networks.add(parser.getAttributeValue(null, "key"));
            }
        }
        return of(allow, kind, value, subdomains, protocol == null ? 0 : Integer.parseInt(protocol),
                networks, except);
    }

    @Override
    public int compareTo(TargetRule other) {
        return ORDER.compare(this, other);
    }

    @Override
    public String toString() {
        String text = (allow ? "allow " : "block ") + KINDS[kind] + " " + value;
        if (kind == DOMAIN && !subdomains) text += " (exact)";
        if (protocol == IFirewall.PROTOCOL_TCP) text += " (tcp)";
        if (protocol == IFirewall.PROTOCOL_UDP) text += " (udp)";
        if (!networks.isEmpty()) {
            text += (exceptNetworks ? " except on " : " only on ") + String.join(", ", networks);
        }
        return text;
    }
}
