/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlSerializer;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Set;
import java.util.TreeSet;

/**
 * Safe Search for all of a user's apps, as Firewalla's: netd's lookup check has the resolver look
 * up the search engines' safe-search names in place of theirs, and the user's apps are held to
 * Android's DNS meanwhile, as under domain rules, so they can't ask elsewhere. The main user's
 * covers the hotspot's devices too. Google's search domains beyond google.com come from its list
 * of them, which the firewall app downloads once a user turns Safe Search on and checks daily;
 * they're domain map entries of their own scope, for netd to find.
 */
final class SafeSearch extends Feature {
    /** Users with Safe Search on. */
    final Set<Integer> users = new TreeSet<>();
    /** Google's search domains, such as google.co.uk, as last downloaded. */
    final Set<String> domains = new TreeSet<>();
    String etag;
    String lastModified;
    long checkedMillis;

    SafeSearch(FirewallService service) {
        super(service);
    }

    @Override
    void clearStore() {
        users.clear();
        domains.clear();
        etag = null;
        lastModified = null;
        checkedMillis = 0;
    }

    @Override
    boolean readStoreTag(XmlPullParser parser) {
        switch (parser.getName()) {
            case "safe-search" ->
                    users.add(Integer.parseInt(parser.getAttributeValue(null, "user")));
            case "safe-search-domain" -> {
                String name = parser.getAttributeValue(null, "name");
                if (GoogleDomains.valid(name)) domains.add(name);
            }
            case "safe-search-check" -> {
                etag = parser.getAttributeValue(null, "etag");
                lastModified = parser.getAttributeValue(null, "lastModified");
                String checked = parser.getAttributeValue(null, "checked");
                checkedMillis = checked != null ? Long.parseLong(checked) : 0;
            }
            default -> {
                return false;
            }
        }
        return true;
    }

    @Override
    void writeStore(XmlSerializer serializer) throws IOException {
        for (int user : users) {
            serializer.startTag(null, "safe-search");
            serializer.attribute(null, "user", Integer.toString(user));
            serializer.endTag(null, "safe-search");
        }
        for (String name : domains) {
            serializer.startTag(null, "safe-search-domain");
            serializer.attribute(null, "name", name);
            serializer.endTag(null, "safe-search-domain");
        }
        if (checkedMillis != 0) {
            serializer.startTag(null, "safe-search-check");
            if (etag != null) serializer.attribute(null, "etag", etag);
            if (lastModified != null) serializer.attribute(null, "lastModified", lastModified);
            serializer.attribute(null, "checked", Long.toString(checkedMillis));
            serializer.endTag(null, "safe-search-check");
        }
    }

    @Override
    void onLoadedLocked(Set<Integer> loaded) {
        users.retainAll(loaded);
    }

    @Override
    boolean forgetUserLocked(int userId) {
        return users.remove(userId);
    }

    @Override
    Object backupUserLocked(int userId) {
        return users.contains(userId) ? Boolean.TRUE : null;
    }

    @Override
    void writeBackupAttributes(Object part, boolean user, XmlSerializer serializer)
            throws IOException {
        if (user) serializer.attribute(null, "safeSearch", "true");
    }

    @Override
    Object readBackupAttributes(XmlPullParser parser, boolean user) {
        return user && "true".equals(parser.getAttributeValue(null, "safeSearch"))
                ? Boolean.TRUE : null;
    }

    @Override
    void restoreUserLocked(int userId, Object part) {
        if (part != null) users.add(userId);
    }

    @Override
    void onMapsClearedLocked() {
        for (String name : domains) writeDomainLocked(name, true);
    }

    /** The rules for all apps write only the flags of users with some. */
    @Override
    void onStartSyncedLocked() {
        TargetRules rules = mService.feature(TargetRules.class);
        if (rules == null) return;
        for (int user : users) rules.writeUserFlagsLocked(user);
    }

    private void writeDomainLocked(String name, boolean listed) {
        mService.maps().setDomain(FirewallMaps.SAFE_SEARCH_SCOPE, name,
                listed ? FirewallMaps.DOMAIN_BLOCK : 0);
    }

    int userFlagsLocked(int userId) {
        return users.contains(userId)
                ? FirewallMaps.USER_SAFE_SEARCH | FirewallMaps.SCOPE_DOMAINS : 0;
    }

    void setSafeSearchInternal(int userId, boolean on) {
        synchronized (mService) {
            if (!(on ? users.add(userId) : users.remove(userId))) return;
            TargetRules rules = mService.feature(TargetRules.class);
            if (rules != null && mService.mapsReady() && !mService.offLocked()) {
                rules.writeUserFlagsLocked(userId);
            }
        }
        mService.saveAsync();
    }

    boolean isSafeSearchInternal(int userId) {
        synchronized (mService) {
            return users.contains(userId);
        }
    }

    SafeSearchDomains getDomainsInternal() {
        synchronized (mService) {
            if (users.isEmpty()) return null;
            SafeSearchDomains parcel = new SafeSearchDomains();
            parcel.names = domains.toArray(new String[0]);
            parcel.etag = etag;
            parcel.lastModified = lastModified;
            parcel.checkedMillis = checkedMillis;
            return parcel;
        }
    }

    /** Takes a check's result: new domains, which must all be Google's form, or none unchanged. */
    void setDomainsInternal(SafeSearchDomains checked) {
        synchronized (mService) {
            if (checked.names != null) {
                Set<String> next = new TreeSet<>();
                for (String name : checked.names) {
                    if (!GoogleDomains.valid(name)) {
                        throw new IllegalArgumentException("Not a Google search domain: " + name);
                    }
                    next.add(name);
                }
                if (next.isEmpty() || next.size() > GoogleDomains.MAX) {
                    throw new IllegalArgumentException(next.size() + " Google search domains");
                }
                if (mService.mapsReady() && !mService.offLocked()) {
                    for (String name : domains) {
                        if (!next.contains(name)) writeDomainLocked(name, false);
                    }
                    for (String name : next) {
                        if (!domains.contains(name)) writeDomainLocked(name, true);
                    }
                }
                domains.clear();
                domains.addAll(next);
                etag = checked.etag;
                lastModified = checked.lastModified;
            }
            checkedMillis = mService.clock().millis();
        }
        mService.saveAsync();
    }

    @Override
    void dumpLocked(PrintWriter pw) {
        pw.println("Safe Search for users: " + users);
        pw.println("  Google search domains: " + domains.size() + ", checked " + checkedMillis);
    }

    @Override
    Integer onShellCommand(String cmd, FirewallShellCommand shell) {
        switch (cmd) {
            case "set-safe-search" -> {
                boolean on = Boolean.parseBoolean(shell.getNextArgRequired());
                setSafeSearchInternal(shell.parseUser(), on);
            }
            case "get-safe-search" ->
                    shell.getOutPrintWriter().println(isSafeSearchInternal(shell.parseUser()));
            default -> {
                return null;
            }
        }
        return 0;
    }

    @Override
    void onShellHelp(PrintWriter pw) {
        pw.println("  set-safe-search true|false [--user USER]");
        pw.println("      Gives the user's apps the search engines' safe results.");
        pw.println("  get-safe-search [--user USER]");
    }
}
