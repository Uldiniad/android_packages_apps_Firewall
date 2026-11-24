/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import android.util.Pair;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlSerializer;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;
import java.util.function.Predicate;

/**
 * Groups of apps that follow one set of rules, as Firewalla's do. A group goes by a package name
 * of IFirewall.GROUP_PREFIX and its id, so its switches, schedule, networks, rules and lists are
 * kept as an app's are, and the service writes them for each app in it. An app is in one group
 * at most and loses its own rules on joining; leaving, or the group's removal, leaves it a copy
 * of the group's.
 */
final class Groups extends Feature {
    /** Each user's groups: their names, by id. */
    final Map<Integer, Map<String, String>> groups = new HashMap<>();
    /** The group each app is in, by id. */
    final Map<Pair<String, Integer>, String> members = new HashMap<>();

    /** A user's groups as backed up. */
    private record Part(Map<String, String> names) {}

    Groups(FirewallService service) {
        super(service);
    }

    private static Pair<String, Integer> groupApp(String id, int userId) {
        return Pair.create(IFirewall.GROUP_PREFIX + id, userId);
    }

    /** The id of the group the app names, if it names one. */
    private static String idOf(Pair<String, Integer> app) {
        return app.first.startsWith(IFirewall.GROUP_PREFIX)
                ? app.first.substring(IFirewall.GROUP_PREFIX.length()) : null;
    }

    private static boolean validId(String id) {
        try {
            return UUID.fromString(id).toString().equals(id);
        } catch (IllegalArgumentException | NullPointerException e) {
            return false;
        }
    }

    /** The name trimmed, or null when there's none. */
    private static String nameOf(String name) {
        String trimmed = name == null ? "" : name.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private boolean existsLocked(String id, int userId) {
        return id != null && groups.getOrDefault(userId, Map.of()).containsKey(id);
    }

    private List<Pair<String, Integer>> membersLocked(String id, int userId) {
        List<Pair<String, Integer>> apps = new ArrayList<>();
        members.forEach((app, group) -> {
            if (group.equals(id) && app.second == userId) apps.add(app);
        });
        return apps;
    }

    @Override
    void clearStore() {
        groups.clear();
        members.clear();
    }

    @Override
    boolean readStoreTag(XmlPullParser parser) {
        switch (parser.getName()) {
            case "group" -> {
                String id = parser.getAttributeValue(null, "id");
                String name = nameOf(parser.getAttributeValue(null, "name"));
                if (validId(id) && name != null) {
                    groups.computeIfAbsent(
                            Integer.parseInt(parser.getAttributeValue(null, "user")),
                            user -> new TreeMap<>()).put(id, name);
                }
            }
            case "member" -> {
                String id = parser.getAttributeValue(null, "group");
                if (id != null) members.put(FirewallStore.appOf(parser), id);
            }
            default -> {
                return false;
            }
        }
        return true;
    }

    @Override
    void writeStore(XmlSerializer serializer) throws IOException {
        for (Map.Entry<Integer, Map<String, String>> user : groups.entrySet()) {
            for (Map.Entry<String, String> group : user.getValue().entrySet()) {
                serializer.startTag(null, "group");
                serializer.attribute(null, "user", Integer.toString(user.getKey()));
                serializer.attribute(null, "id", group.getKey());
                serializer.attribute(null, "name", group.getValue());
                serializer.endTag(null, "group");
            }
        }
        for (Map.Entry<Pair<String, Integer>, String> member : members.entrySet()) {
            serializer.startTag(null, "member");
            FirewallStore.writeApp(serializer, member.getKey());
            serializer.attribute(null, "group", member.getValue());
            serializer.endTag(null, "member");
        }
    }

    @Override
    void onLoadedLocked(Set<Integer> users) {
        groups.keySet().retainAll(users);
        members.entrySet().removeIf(member -> !existsLocked(member.getValue(),
                member.getKey().second) || mService.knownUid(member.getKey()) < 0);
    }

    @Override
    boolean forgetAppsLocked(Predicate<Pair<String, Integer>> gone) {
        return members.keySet().removeIf(gone);
    }

    @Override
    boolean forgetUserLocked(int userId) {
        boolean changed = members.keySet().removeIf(app -> app.second == userId);
        return groups.remove(userId) != null || changed;
    }

    @Override
    void addAppsWithStateLocked(Set<Pair<String, Integer>> apps) {
        apps.addAll(members.keySet());
        groups.forEach((user, ids) -> {
            for (String id : ids.keySet()) apps.add(groupApp(id, user));
        });
    }

    @Override
    int[] memberUidsLocked(Pair<String, Integer> app) {
        String id = idOf(app);
        if (!existsLocked(id, app.second)) return null;
        return membersLocked(id, app.second).stream().mapToInt(mService::knownUid)
                .filter(uid -> uid >= 0).distinct().toArray();
    }

    @Override
    Pair<String, Integer> groupOfLocked(Pair<String, Integer> app) {
        String id = members.get(app);
        return id == null ? null : groupApp(id, app.second);
    }

    @Override
    void fillAppRuleLocked(Pair<String, Integer> app, AppRule rule) {
        rule.group = members.get(app);
        if (rule.group != null) {
            rule.groupName = groups.getOrDefault(app.second, Map.of()).get(rule.group);
        }
    }

    @Override
    Object backupAppLocked(Pair<String, Integer> app) {
        return members.get(app);
    }

    @Override
    Object backupUserLocked(int userId) {
        Map<String, String> names = groups.get(userId);
        return names == null || names.isEmpty() ? null : new Part(new TreeMap<>(names));
    }

    @Override
    void writeBackupAttributes(Object part, boolean user, XmlSerializer serializer)
            throws IOException {
        if (!user) serializer.attribute(null, "group", (String) part);
    }

    @Override
    void writeBackupTags(Object part, boolean user, XmlSerializer serializer) throws IOException {
        if (!user) return;
        for (Map.Entry<String, String> group : ((Part) part).names().entrySet()) {
            serializer.startTag(null, "group");
            serializer.attribute(null, "id", group.getKey());
            serializer.attribute(null, "name", group.getValue());
            serializer.endTag(null, "group");
        }
    }

    @Override
    Object readBackupAttributes(XmlPullParser parser, boolean user) {
        return user ? null : parser.getAttributeValue(null, "group");
    }

    @Override
    boolean readBackupTag(XmlPullParser parser, boolean user, FirewallBackup.Parts parts) {
        if (!user || !"group".equals(parser.getName())) return false;
        String id = parser.getAttributeValue(null, "id");
        String name = nameOf(parser.getAttributeValue(null, "name"));
        if (validId(id) && name != null) {
            Part part = (Part) parts.get(this);
            if (part == null) {
                part = new Part(new TreeMap<>());
                parts.put(this, part);
            }
            part.names().put(id, name);
        }
        return true;
    }

    /** The groups come with the user, before the apps that are in them. */
    @Override
    void restoreUserLocked(int userId, Object part) {
        if (part instanceof Part names) groups.put(userId, new TreeMap<>(names.names()));
    }

    @Override
    void restoreAppLocked(Pair<String, Integer> app, FirewallBackup.App restored) {
        if (restored.parts().get(this) instanceof String id && existsLocked(id, app.second)) {
            members.put(app, id);
        } else {
            members.remove(app);
        }
    }

    @Override
    void dumpLocked(PrintWriter pw) {
        pw.println("Groups:");
        groups.forEach((user, ids) -> ids.forEach((id, name) -> pw.println("  " + id + " user "
                + user + " \"" + name + "\": " + membersLocked(id, user).stream()
                        .map(app -> app.first).toList())));
    }

    /** The user's groups. */
    FirewallGroup[] getGroupsInternal(int userId) {
        synchronized (mService) {
            return groups.getOrDefault(userId, Map.of()).entrySet().stream().map(group -> {
                FirewallGroup parcel = new FirewallGroup();
                parcel.id = group.getKey();
                parcel.name = group.getValue();
                return parcel;
            }).toArray(FirewallGroup[]::new);
        }
    }

    /** Adds a group with no apps and no rules, so it allows everything; its id. */
    String addGroupInternal(int userId, String name) {
        String trimmed = nameOf(name);
        if (trimmed == null) throw new IllegalArgumentException("A group needs a name");
        String id = UUID.randomUUID().toString();
        synchronized (mService) {
            groups.computeIfAbsent(userId, user -> new TreeMap<>()).put(id, trimmed);
            mService.store().apps.put(groupApp(id, userId), 0);
        }
        mService.saveAsync();
        return id;
    }

    void renameGroupInternal(int userId, String id, String name) {
        String trimmed = nameOf(name);
        if (trimmed == null) throw new IllegalArgumentException("A group needs a name");
        synchronized (mService) {
            if (!existsLocked(id, userId)) throw new IllegalArgumentException("No group " + id);
            groups.get(userId).put(id, trimmed);
        }
        mService.saveAsync();
    }

    /** Removes the group; its apps keep a copy of its rules as their own. */
    void removeGroupInternal(int userId, String id) {
        synchronized (mService) {
            if (!existsLocked(id, userId)) return;
            Pair<String, Integer> group = groupApp(id, userId);
            for (Pair<String, Integer> app : membersLocked(id, userId)) {
                mService.copyAppLocked(group, app);
                members.remove(app);
            }
            mService.forgetAppLocked(group);
            Map<String, String> ids = groups.get(userId);
            ids.remove(id);
            if (ids.isEmpty()) groups.remove(userId);
            if (mService.mapsReady()) mService.syncAppsLocked();
        }
        mService.saveAsync();
    }

    /**
     * Puts the app, with those sharing its uid, in the group, whose rules replace their own; with
     * a null id takes them out, leaving them a copy of the group's rules as their own.
     */
    void setAppGroupInternal(String packageName, int userId, String id) {
        synchronized (mService) {
            if (id != null && !existsLocked(id, userId)) {
                throw new IllegalArgumentException("No group " + id);
            }
            for (Pair<String, Integer> app :
                    mService.installedSharingUidLocked(packageName, userId)) {
                String current = members.get(app);
                if (Objects.equals(current, id)) continue;
                if (id == null) {
                    mService.copyAppLocked(groupApp(current, userId), app);
                    members.remove(app);
                } else {
                    if (current == null) mService.forgetAppLocked(app);
                    members.put(app, id);
                }
            }
            if (mService.mapsReady()) mService.syncAppsLocked();
        }
        mService.saveAsync();
    }

    @Override
    Integer onShellCommand(String cmd, FirewallShellCommand shell) {
        PrintWriter pw = shell.getOutPrintWriter();
        switch (cmd) {
            case "list-groups" -> {
                int user = shell.parseUser();
                synchronized (mService) {
                    groups.getOrDefault(user, Map.of()).forEach((id, name) -> {
                        pw.println(id + " " + name);
                        for (Pair<String, Integer> app : membersLocked(id, user)) {
                            pw.println("  " + app.first);
                        }
                    });
                }
            }
            case "add-group" -> {
                String name = shell.getNextArgRequired();
                pw.println(addGroupInternal(shell.parseUser(), name));
            }
            case "rename-group" -> {
                String id = shell.getNextArgRequired();
                String name = shell.getNextArgRequired();
                renameGroupInternal(shell.parseUser(), id, name);
            }
            case "remove-group" -> {
                String id = shell.getNextArgRequired();
                removeGroupInternal(shell.parseUser(), id);
            }
            case "set-group" -> {
                String packageName = shell.getNextArgRequired();
                String id = shell.getNextArgRequired();
                setAppGroupInternal(packageName, shell.parseUser(), id.equals("none") ? null : id);
            }
            default -> {
                return null;
            }
        }
        return 0;
    }

    @Override
    void onShellHelp(PrintWriter pw) {
        pw.println("  list-groups [--user USER]");
        pw.println("  add-group NAME [--user USER]  (writes the group's id)");
        pw.println("  rename-group ID NAME [--user USER]");
        pw.println("  remove-group ID [--user USER]");
        pw.println("  set-group PACKAGE ID|none [--user USER]");
        pw.println("      A group's rules are set as an app's, with package group:ID");
    }
}
