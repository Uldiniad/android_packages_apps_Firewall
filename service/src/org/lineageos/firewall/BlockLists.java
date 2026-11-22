/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import android.net.IpPrefix;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.os.UserHandle;
import android.os.storage.StorageManager;
import android.util.Log;
import android.util.Pair;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlSerializer;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringReader;
import java.net.Inet4Address;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Predicate;

/**
 * Lists of domains and address ranges that block them, for one app or for all of a user's apps,
 * as rules are. The firewall app downloads and reads them; each list holds a slot here, its
 * domains in a file netd's lookup check maps and its ranges in the address lists' tries, and each
 * scope has the bits of its lists' slots. Allow rules win over every list, and lists never cover
 * the firewall's own app, so a bad one can't stop their updates.
 */
final class BlockLists extends Feature {
    /** The kernel's tries hold as many ranges as the rules' ones, per family. */
    private static final int RANGES_SIZE = 262144;

    private final File mDir;
    /** By id: its address, or for one added from a file an id of its own. */
    final Map<String, BlockList> lists = new TreeMap<>();
    /** The lists for all of a user's apps, and for one app, by (package name, user id). */
    final Map<Integer, Set<String>> userLists = new HashMap<>();
    final Map<Pair<String, Integer>, Set<String>> appLists = new HashMap<>();
    /** What the maps hold, so only changes get written. */
    private final Map<Integer, Long> mWrittenScopes = new HashMap<>();
    private Map<IpPrefix, Long> mWrittenRanges = new HashMap<>();

    /** A list and what its last check found. */
    static final class BlockList {
        final String id;
        final String url;
        final boolean subdomains;
        final int slot;
        /**
         * Of its files; 0 before its first content. Random rather than counted, so the next list
         * in a slot is very unlikely to take the generation netd still has mapped from the last.
         */
        int generation;
        String title;
        String version;
        String etag;
        String lastModified;
        String digest;
        int domains;
        long changed;
        long checked;
        int error;
        int errorDetail;
        List<IpPrefix> ranges = List.of();

        BlockList(String id, String url, boolean subdomains, int slot) {
            this.id = id;
            this.url = url;
            this.subdomains = subdomains;
            this.slot = slot;
        }

        long bit() {
            return 1L << slot;
        }
    }

    BlockLists(FirewallService service, File storeDir) {
        super(service);
        mDir = new File(storeDir, "firewall_lists");
    }

    private File namesFile(int slot, int generation) {
        return new File(mDir, slot + "-" + generation + ".names");
    }

    private File rangesFile(int slot, int generation) {
        return new File(mDir, slot + "-" + generation + ".ranges");
    }

    @Override
    void clearStore() {
        lists.clear();
        userLists.clear();
        appLists.clear();
    }

    @Override
    boolean readStoreTag(XmlPullParser parser) throws IOException, XmlPullParserException {
        switch (parser.getName()) {
            case "block-list" -> {
                try {
                    BlockList list = new BlockList(parser.getAttributeValue(null, "id"),
                            parser.getAttributeValue(null, "url"),
                            Boolean.parseBoolean(parser.getAttributeValue(null, "subdomains")),
                            Integer.parseInt(parser.getAttributeValue(null, "slot")));
                    list.generation = intAttribute(parser, "generation");
                    list.title = parser.getAttributeValue(null, "title");
                    list.version = parser.getAttributeValue(null, "version");
                    list.etag = parser.getAttributeValue(null, "etag");
                    list.lastModified = parser.getAttributeValue(null, "modified");
                    list.digest = parser.getAttributeValue(null, "digest");
                    list.domains = intAttribute(parser, "domains");
                    list.changed = longAttribute(parser, "changed");
                    list.checked = longAttribute(parser, "checked");
                    list.error = intAttribute(parser, "error");
                    list.errorDetail = intAttribute(parser, "detail");
                    if (list.id != null && list.slot >= 0 && list.slot < FirewallMaps.LIST_SLOTS) {
                        lists.put(list.id, list);
                    }
                } catch (NumberFormatException e) {
                    Log.w(FirewallService.TAG, "Skipped a malformed list");
                }
            }
            case "list-subscription" -> {
                String id = parser.getAttributeValue(null, "list");
                String packageName = parser.getAttributeValue(null, "package");
                try {
                    int user = Integer.parseInt(parser.getAttributeValue(null, "user"));
                    if (id != null) scopeLists(user, packageName, true).add(id);
                } catch (NumberFormatException e) {
                    Log.w(FirewallService.TAG, "Skipped a malformed list subscription");
                }
            }
            default -> {
                return false;
            }
        }
        return true;
    }

    private static int intAttribute(XmlPullParser parser, String name) {
        String value = parser.getAttributeValue(null, name);
        return value == null ? 0 : Integer.parseInt(value);
    }

    private static long longAttribute(XmlPullParser parser, String name) {
        String value = parser.getAttributeValue(null, name);
        return value == null ? 0 : Long.parseLong(value);
    }

    @Override
    void writeStore(XmlSerializer serializer) throws IOException {
        for (BlockList list : lists.values()) {
            serializer.startTag(null, "block-list");
            serializer.attribute(null, "id", list.id);
            if (list.url != null) serializer.attribute(null, "url", list.url);
            serializer.attribute(null, "subdomains", Boolean.toString(list.subdomains));
            serializer.attribute(null, "slot", Integer.toString(list.slot));
            serializer.attribute(null, "generation", Integer.toString(list.generation));
            optionalAttribute(serializer, "title", list.title);
            optionalAttribute(serializer, "version", list.version);
            optionalAttribute(serializer, "etag", list.etag);
            optionalAttribute(serializer, "modified", list.lastModified);
            optionalAttribute(serializer, "digest", list.digest);
            serializer.attribute(null, "domains", Integer.toString(list.domains));
            serializer.attribute(null, "changed", Long.toString(list.changed));
            serializer.attribute(null, "checked", Long.toString(list.checked));
            serializer.attribute(null, "error", Integer.toString(list.error));
            serializer.attribute(null, "detail", Integer.toString(list.errorDetail));
            serializer.endTag(null, "block-list");
        }
        for (Map.Entry<Integer, Set<String>> user : userLists.entrySet()) {
            for (String id : user.getValue()) {
                writeSubscription(serializer, id, user.getKey(), null);
            }
        }
        for (Map.Entry<Pair<String, Integer>, Set<String>> app : appLists.entrySet()) {
            for (String id : app.getValue()) {
                writeSubscription(serializer, id, app.getKey().second, app.getKey().first);
            }
        }
    }

    private static void optionalAttribute(XmlSerializer serializer, String name, String value)
            throws IOException {
        if (value != null) serializer.attribute(null, name, value);
    }

    private static void writeSubscription(XmlSerializer serializer, String id, int user,
            String packageName) throws IOException {
        serializer.startTag(null, "list-subscription");
        serializer.attribute(null, "list", id);
        serializer.attribute(null, "user", Integer.toString(user));
        if (packageName != null) serializer.attribute(null, "package", packageName);
        serializer.endTag(null, "list-subscription");
    }

    private Set<String> scopeLists(int user, String packageName, boolean create) {
        if (packageName == null) {
            return create ? userLists.computeIfAbsent(user, u -> new TreeSet<>())
                    : userLists.getOrDefault(user, Set.of());
        }
        Pair<String, Integer> app = Pair.create(packageName, user);
        return create ? appLists.computeIfAbsent(app, a -> new TreeSet<>())
                : appLists.getOrDefault(app, Set.of());
    }

    @Override
    void onLoadedLocked(Set<Integer> users) {
        // Made here, so it gets its label before anything else writes to it.
        mDir.mkdirs();
        userLists.keySet().retainAll(users);
        appLists.keySet().removeIf(app ->
                !users.contains(app.second) || mService.knownUid(app) < 0);
        dropUnusedListsLocked();
        for (BlockList list : lists.values()) {
            if (list.generation == 0) continue;
            try {
                list.ranges = readRanges(rangesFile(list.slot, list.generation));
                if (!namesFile(list.slot, list.generation).isFile()) throw new IOException();
            } catch (IOException | IllegalArgumentException e) {
                // Downloaded again at the firewall app's next check.
                Log.w(FirewallService.TAG, "Lost the content of list " + list.slot);
                list.generation = 0;
                list.ranges = List.of();
                list.domains = 0;
                list.digest = null;
                list.etag = null;
                list.lastModified = null;
            }
        }
        deleteStrayFiles();
    }

    private static List<IpPrefix> readRanges(File file) throws IOException {
        List<IpPrefix> ranges = new ArrayList<>();
        for (String line : Files.readAllLines(file.toPath())) {
            if (!line.isEmpty()) ranges.add(new IpPrefix(line));
        }
        return ranges;
    }

    /** Deletes the files of generations no list uses any more. */
    private void deleteStrayFiles() {
        Set<String> used = new HashSet<>();
        for (BlockList list : lists.values()) {
            if (list.generation == 0) continue;
            used.add(namesFile(list.slot, list.generation).getName());
            used.add(rangesFile(list.slot, list.generation).getName());
        }
        File[] files = mDir.listFiles();
        if (files == null) return;
        for (File file : files) {
            if (!used.contains(file.getName())) file.delete();
        }
    }

    /** Drops the lists nobody subscribes to any more, and their files. */
    private boolean dropUnusedListsLocked() {
        userLists.values().forEach(ids -> ids.retainAll(lists.keySet()));
        appLists.values().forEach(ids -> ids.retainAll(lists.keySet()));
        Set<String> used = new HashSet<>();
        userLists.values().forEach(used::addAll);
        appLists.values().forEach(used::addAll);
        userLists.values().removeIf(Set::isEmpty);
        appLists.values().removeIf(Set::isEmpty);
        boolean dropped = false;
        for (BlockList list : List.copyOf(lists.values())) {
            if (used.contains(list.id)) continue;
            lists.remove(list.id);
            dropped = true;
            if (list.generation != 0) {
                namesFile(list.slot, list.generation).delete();
                rangesFile(list.slot, list.generation).delete();
                if (writableLocked()) mService.maps().setListFile(list.slot, 0);
            }
        }
        if (dropped && writableLocked()) writeRangesLocked();
        return dropped;
    }

    private boolean writableLocked() {
        return mService.mapsReady() && !mService.offLocked();
    }

    @Override
    void onMapsClearedLocked() {
        mWrittenScopes.clear();
        mWrittenRanges = new HashMap<>();
        for (BlockList list : lists.values()) {
            if (list.generation != 0) mService.maps().setListFile(list.slot, list.generation);
        }
        writeRangesLocked();
    }

    @Override
    void onStartSyncedLocked() {
        for (int user : List.copyOf(userLists.keySet())) mService.syncUserLocked(user);
    }

    /** Writes the ranges of every address list, each valued with the slots of those holding it. */
    private void writeRangesLocked() {
        Map<IpPrefix, Long> next = rangesOf(lists.values());
        for (IpPrefix range : union(mWrittenRanges.keySet(), next.keySet())) {
            long slots = next.getOrDefault(range, 0L);
            if (slots != mWrittenRanges.getOrDefault(range, 0L)) {
                mService.maps().setListRange(range.getRawAddress(), range.getPrefixLength(), slots);
            }
        }
        mWrittenRanges = next;
    }

    /**
     * The lists' ranges valued with their slots, each also with those of the ranges around it,
     * which a lookup of the longest match passes over.
     */
    private static Map<IpPrefix, Long> rangesOf(Iterable<BlockList> blockLists) {
        Map<IpPrefix, Long> slots = new HashMap<>();
        for (BlockList list : blockLists) {
            for (IpPrefix range : list.ranges) slots.merge(range, list.bit(), (a, b) -> a | b);
        }
        Map<Boolean, TreeMap<Integer, Set<IpPrefix>>> lengths = new HashMap<>();
        for (IpPrefix range : slots.keySet()) {
            boolean v4 = range.getAddress() instanceof Inet4Address;
            lengths.computeIfAbsent(v4, family -> new TreeMap<>())
                    .computeIfAbsent(range.getPrefixLength(), l -> new HashSet<>()).add(range);
        }
        Map<IpPrefix, Long> inherited = new HashMap<>(slots);
        for (TreeMap<Integer, Set<IpPrefix>> family : lengths.values()) {
            for (Map.Entry<Integer, Set<IpPrefix>> length : family.entrySet()) {
                for (IpPrefix range : length.getValue()) {
                    long bits = slots.get(range);
                    for (int wider : family.headMap(length.getKey()).keySet()) {
                        Long outer = slots.get(new IpPrefix(range.getAddress(), wider));
                        if (outer != null) bits |= outer;
                    }
                    inherited.put(range, bits);
                }
            }
        }
        return inherited;
    }

    private static <T> Set<T> union(Set<T> a, Set<T> b) {
        Set<T> all = new HashSet<>(a);
        all.addAll(b);
        return all;
    }

    private long slotsOf(Set<String> ids) {
        long slots = 0;
        for (String id : ids) {
            BlockList list = lists.get(id);
            if (list != null) slots |= list.bit();
        }
        return slots;
    }

    @Override
    void writeAppsLocked(Map<Integer, Integer> wanted) {
        Map<Integer, Long> scopes = new HashMap<>();
        Set<Integer> users = new HashSet<>(userLists.keySet());
        appLists.forEach((app, ids) -> {
            int uid = mService.knownUid(app);
            if (uid < 0) return;
            users.add(app.second);
            for (int each : FirewallService.withSdkSandbox(uid)) {
                scopes.merge(each, slotsOf(ids), (a, b) -> a | b);
            }
        });
        for (int user : users) {
            int uid = mService.knownUid(Pair.create(FirewallService.APP_PACKAGE, user));
            if (uid >= 0) wanted.merge(uid, FirewallMaps.NO_LISTS, (a, b) -> a | b);
        }
        // Entries go in before the flags that enable them, and out after.
        for (int scope : List.copyOf(mWrittenScopes.keySet())) {
            if ((scope & FirewallMaps.USER_SCOPE) == 0 && !scopes.containsKey(scope)) {
                writeScopeLocked(scope, 0);
            }
        }
        scopes.forEach((uid, slots) -> {
            writeScopeLocked(uid, slots);
            wanted.merge(uid, FirewallMaps.SCOPE_LISTS, (a, b) -> a | b);
        });
    }

    @Override
    void writeUserLocked(int userId) {
        writeScopeLocked(FirewallMaps.USER_SCOPE | userId,
                slotsOf(scopeLists(userId, null, false)));
    }

    /** The bits the lists add to the user's flags, which the rules for all apps write. */
    int userFlagsLocked(int userId) {
        return slotsOf(scopeLists(userId, null, false)) != 0 ? FirewallMaps.SCOPE_LISTS : 0;
    }

    private void writeScopeLocked(int scope, long slots) {
        if (slots == mWrittenScopes.getOrDefault(scope, 0L)) return;
        mService.maps().setScopeLists(scope, slots);
        if (slots == 0) {
            mWrittenScopes.remove(scope);
        } else {
            mWrittenScopes.put(scope, slots);
        }
    }

    @Override
    boolean forgetAppsLocked(Predicate<Pair<String, Integer>> gone) {
        boolean changed = appLists.keySet().removeIf(gone);
        return dropUnusedListsLocked() || changed;
    }

    @Override
    boolean forgetUserLocked(int userId) {
        boolean changed = appLists.keySet().removeIf(app -> app.second == userId);
        changed |= userLists.remove(userId) != null;
        return dropUnusedListsLocked() || changed;
    }

    @Override
    void addAppsWithStateLocked(Set<Pair<String, Integer>> apps) {
        apps.addAll(appLists.keySet());
    }

    @Override
    void fillAppRuleLocked(Pair<String, Integer> app, AppRule rule) {
        rule.ruleCount += appLists.getOrDefault(app, Set.of()).size();
    }

    /** An app's or a user's lists as backed up: the addresses of those not added from files. */
    private record Part(Map<String, Boolean> urls) {}

    private Part partOf(Set<String> ids) {
        Map<String, Boolean> urls = new TreeMap<>();
        for (String id : ids) {
            BlockList list = lists.get(id);
            if (list != null && list.url != null) urls.put(list.url, list.subdomains);
        }
        return urls.isEmpty() ? null : new Part(urls);
    }

    @Override
    Object backupAppLocked(Pair<String, Integer> app) {
        return partOf(appLists.getOrDefault(app, Set.of()));
    }

    @Override
    Object backupUserLocked(int userId) {
        return partOf(userLists.getOrDefault(userId, Set.of()));
    }

    @Override
    void writeBackupTags(Object part, boolean user, XmlSerializer serializer) throws IOException {
        for (Map.Entry<String, Boolean> url : ((Part) part).urls().entrySet()) {
            serializer.startTag(null, "list");
            serializer.attribute(null, "url", url.getKey());
            serializer.attribute(null, "subdomains", Boolean.toString(url.getValue()));
            serializer.endTag(null, "list");
        }
    }

    @Override
    boolean readBackupTag(XmlPullParser parser, boolean user, FirewallBackup.Parts parts)
            throws IOException, XmlPullParserException {
        if (!"list".equals(parser.getName())) return false;
        String url = parser.getAttributeValue(null, "url");
        if (validUrl(url)) {
            Part part = (Part) parts.get(this);
            if (part == null) {
                part = new Part(new TreeMap<>());
                parts.put(this, part);
            }
            part.urls().put(url,
                    Boolean.parseBoolean(parser.getAttributeValue(null, "subdomains")));
        }
        return true;
    }

    @Override
    void restoreAppLocked(Pair<String, Integer> app, FirewallBackup.App restored) {
        appLists.remove(app);
        if (restored.parts().get(this) instanceof Part part) {
            subscribeLocked(part.urls(), app.second, app.first);
        }
    }

    @Override
    void restoreUserLocked(int userId, Object part) {
        if (part instanceof Part urls) subscribeLocked(urls.urls(), userId, null);
    }

    @Override
    void onRestoredLocked(int userId) {
        dropUnusedListsLocked();
    }

    private void subscribeLocked(Map<String, Boolean> urls, int user, String packageName) {
        urls.forEach((url, subdomains) -> {
            BlockList list = listForUrlLocked(url, subdomains);
            if (list != null) scopeLists(user, packageName, true).add(list.id);
        });
    }

    static boolean validUrl(String url) {
        if (url == null) return false;
        Uri uri = Uri.parse(url);
        return "https".equals(uri.getScheme()) && uri.getHost() != null
                && !uri.getHost().isEmpty();
    }

    /** The list at the address, made with a free slot if it's new; null if none is free. */
    private BlockList listForUrlLocked(String url, boolean subdomains) {
        BlockList list = lists.get(url);
        if (list != null) return list;
        int slot = freeSlotLocked();
        if (slot < 0) return null;
        list = new BlockList(url, url, subdomains, slot);
        lists.put(url, list);
        return list;
    }

    private int freeSlotLocked() {
        long used = 0;
        for (BlockList list : lists.values()) used |= list.bit();
        for (int slot = 0; slot < FirewallMaps.LIST_SLOTS; slot++) {
            if ((used & (1L << slot)) == 0) return slot;
        }
        return -1;
    }

    @Override
    void dumpLocked(PrintWriter pw) {
        for (BlockList list : lists.values()) {
            pw.println("List " + list.slot + ": " + (list.url != null ? list.url : list.title)
                    + " generation " + list.generation + ", " + list.domains + " domains, "
                    + list.ranges.size() + " ranges, changed " + list.changed + ", checked "
                    + list.checked + (list.error != 0
                            ? ", error " + list.error + "/" + list.errorDetail : ""));
        }
        userLists.forEach((user, ids) -> pw.println("Lists for all apps of user " + user + ": "
                + ids.stream().map(id -> lists.get(id).slot).toList()));
        appLists.forEach((app, ids) -> pw.println("Lists for " + app.first + " user "
                + app.second + ": " + ids.stream().map(id -> lists.get(id).slot).toList()));
    }

    private void syncScopeLocked(int userId, String packageName) {
        if (!mService.mapsReady()) return;
        // The firewall app's exemption is written with the apps.
        mService.syncAppsLocked();
        if (packageName == null) mService.syncUserLocked(userId);
    }

    FirewallList[] getListsInternal(int userId) {
        synchronized (mService) {
            List<FirewallList> out = new ArrayList<>();
            for (String id : userLists.getOrDefault(userId, Set.of())) {
                out.add(toParcel(lists.get(id), null, userId));
            }
            appLists.forEach((app, ids) -> {
                if (app.second != userId) return;
                for (String id : ids) out.add(toParcel(lists.get(id), app.first, userId));
            });
            return out.toArray(new FirewallList[0]);
        }
    }

    private static FirewallList toParcel(BlockList list, String packageName, int userId) {
        FirewallList parcel = new FirewallList();
        parcel.id = list.id;
        parcel.url = list.url;
        parcel.subdomains = list.subdomains;
        parcel.packageName = packageName;
        parcel.userId = userId;
        parcel.title = list.title;
        parcel.version = list.version;
        parcel.domains = list.domains;
        parcel.ranges = list.ranges.size();
        parcel.changedMillis = list.changed;
        parcel.checkedMillis = list.checked;
        parcel.error = list.error;
        parcel.errorDetail = list.errorDetail;
        parcel.etag = list.etag;
        parcel.lastModified = list.lastModified;
        return parcel;
    }

    /** The scope's apps: those sharing the app's uid, or none for all of the user's apps. */
    private List<Pair<String, Integer>> appsOf(int userId, String packageName) {
        return packageName == null ? null : mService.sharingUidLocked(packageName, userId);
    }

    String addListInternal(int userId, String packageName, String url, boolean subdomains) {
        String address = url == null ? null : url.trim();
        if (!validUrl(address)) throw new IllegalArgumentException("Not an https address: " + url);
        String id;
        synchronized (mService) {
            List<Pair<String, Integer>> apps = appsOf(userId, packageName);
            BlockList list = listForUrlLocked(address, subdomains);
            if (list == null) return null;
            id = list.id;
            if (apps == null) {
                scopeLists(userId, null, true).add(id);
            } else {
                for (Pair<String, Integer> app : apps) {
                    scopeLists(app.second, app.first, true).add(id);
                }
            }
            syncScopeLocked(userId, packageName);
        }
        mService.saveAsync();
        return id;
    }

    String addListFromFileInternal(int userId, String packageName, String title,
            ParcelFileDescriptor content) {
        String id = "file:" + UUID.randomUUID();
        synchronized (mService) {
            List<Pair<String, Integer>> apps = appsOf(userId, packageName);
            int slot = freeSlotLocked();
            if (slot < 0) return null;
            BlockList list = new BlockList(id, null, false, slot);
            list.title = title;
            lists.put(id, list);
            if (apps == null) {
                scopeLists(userId, null, true).add(id);
            } else {
                for (Pair<String, Integer> app : apps) {
                    scopeLists(app.second, app.first, true).add(id);
                }
            }
        }
        int error = setListContentInternal(id, content, title, null, null, null);
        synchronized (mService) {
            if (error != 0) {
                userLists.values().forEach(ids -> ids.remove(id));
                appLists.values().forEach(ids -> ids.remove(id));
                dropUnusedListsLocked();
                throw new IllegalArgumentException("Not list content: error " + error);
            }
            syncScopeLocked(userId, packageName);
        }
        mService.saveAsync();
        return id;
    }

    void removeListInternal(int userId, String packageName, String id) {
        synchronized (mService) {
            if (packageName == null) {
                scopeLists(userId, null, false).remove(id);
            } else {
                List<Pair<String, Integer>> shared;
                try {
                    shared = mService.sharingUidLocked(packageName, userId);
                } catch (IllegalArgumentException e) {
                    shared = List.of(Pair.create(packageName, userId));
                }
                for (Pair<String, Integer> app : shared) {
                    scopeLists(app.second, app.first, false).remove(id);
                }
            }
            dropUnusedListsLocked();
            syncScopeLocked(userId, packageName);
        }
        mService.saveAsync();
    }

    void setListCheckedInternal(String id, int error, int errorDetail) {
        synchronized (mService) {
            BlockList list = lists.get(id);
            if (list == null) return;
            list.checked = mService.clock().millis();
            list.error = error;
            list.errorDetail = errorDetail;
        }
        mService.saveAsync();
    }

    /** Content copied to a generation's files, before it replaces the list's. */
    private record Copied(int domains, List<IpPrefix> ranges, String digest) {}

    /** Why content was refused, as an IFirewall.LIST_ERROR_*. */
    private static final class ContentException extends Exception {
        final int error;

        ContentException(int error, Throwable cause) {
            super(cause);
            this.error = error;
        }
    }

    /**
     * Replaces the list's content with the content the firewall app read, in ListContent's form.
     * The copy is made outside the lock; the last good content stays when anything is wrong.
     */
    int setListContentInternal(String id, ParcelFileDescriptor content, String title,
            String version, String etag, String lastModified) {
        int slot;
        int generation;
        int previousGeneration;
        synchronized (mService) {
            BlockList list = lists.get(id);
            if (list == null) return IFirewall.LIST_ERROR_NOT_A_LIST;
            slot = list.slot;
            previousGeneration = list.generation;
            do {
                generation = ThreadLocalRandom.current().nextInt(1, Integer.MAX_VALUE);
            } while (generation == previousGeneration);
        }
        Copied copied;
        try (InputStream in = new ParcelFileDescriptor.AutoCloseInputStream(content)) {
            copied = copyContent(in, slot, generation);
        } catch (ContentException e) {
            deleteGeneration(slot, generation);
            setListCheckedInternal(id, e.error, 0);
            return e.error;
        } catch (IOException e) {
            deleteGeneration(slot, generation);
            setListCheckedInternal(id, IFirewall.LIST_ERROR_NOT_A_LIST, 0);
            return IFirewall.LIST_ERROR_NOT_A_LIST;
        }
        synchronized (mService) {
            BlockList list = lists.get(id);
            if (list == null || list.generation != previousGeneration) {
                deleteGeneration(slot, generation);
                return IFirewall.LIST_ERROR_NOT_A_LIST;
            }
            List<IpPrefix> previous = list.ranges;
            list.ranges = copied.ranges();
            if (!fitsLocked()) {
                list.ranges = previous;
                deleteGeneration(slot, generation);
                list.checked = mService.clock().millis();
                list.error = IFirewall.LIST_ERROR_FULL;
                list.errorDetail = 0;
                mService.saveAsync();
                return IFirewall.LIST_ERROR_FULL;
            }
            int old = list.generation;
            long now = mService.clock().millis();
            list.generation = generation;
            list.domains = copied.domains();
            if (!copied.digest().equals(list.digest)) list.changed = now;
            list.digest = copied.digest();
            list.checked = now;
            list.error = 0;
            list.errorDetail = 0;
            if (title != null) list.title = title;
            list.version = version;
            list.etag = etag;
            list.lastModified = lastModified;
            if (writableLocked()) {
                mService.maps().setListFile(slot, generation);
                writeRangesLocked();
            }
            if (old != 0) deleteGeneration(slot, old);
        }
        mService.saveAsync();
        return 0;
    }

    /** Whether every list's ranges fit the kernel's tries. */
    private boolean fitsLocked() {
        int v4 = 0;
        int v6 = 0;
        for (IpPrefix range : rangesOf(lists.values()).keySet()) {
            if (range.getAddress() instanceof Inet4Address) {
                v4++;
            } else {
                v6++;
            }
        }
        return v4 <= RANGES_SIZE && v6 <= RANGES_SIZE;
    }

    private void deleteGeneration(int slot, int generation) {
        namesFile(slot, generation).delete();
        rangesFile(slot, generation).delete();
    }

    private Copied copyContent(InputStream raw, int slot, int generation)
            throws IOException, ContentException {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
        mDir.mkdirs();
        DataInputStream in = new DataInputStream(
                new DigestInputStream(new BufferedInputStream(raw), digest));
        ListContent.Header header = ListContent.Header.read(in);
        File names = namesFile(slot, generation);
        try (FileOutputStream file = new FileOutputStream(names)) {
            try {
                mService.context().getSystemService(StorageManager.class)
                        .allocateBytes(file.getFD(), ListContent.HEADER_BYTES + 8 * header.names());
            } catch (IOException e) {
                throw new ContentException(IFirewall.LIST_ERROR_STORAGE, e);
            }
            OutputStream out = new BufferedOutputStream(file);
            ListContent.copyNames(in, header.names(), out);
            out.flush();
            file.getFD().sync();
        }
        List<IpPrefix> ranges = new ArrayList<>();
        for (IpPrefix range : ListContent.readRanges(in, header.ranges())) {
            if (ListParser.blockable(range)) ranges.add(range);
        }
        if (in.read() >= 0) throw new IOException("Content past its counts");
        if (header.names() == 0 && ranges.isEmpty()) {
            throw new ContentException(IFirewall.LIST_ERROR_NOT_A_LIST, null);
        }
        StringBuilder text = new StringBuilder();
        for (IpPrefix range : ranges) text.append(range).append('\n');
        File rangesFile = rangesFile(slot, generation);
        try (FileOutputStream file = new FileOutputStream(rangesFile)) {
            file.write(text.toString().getBytes(StandardCharsets.US_ASCII));
            file.getFD().sync();
        }
        if (header.names() > Integer.MAX_VALUE) throw new IOException("Too many names");
        return new Copied((int) header.names(), ranges,
                HexFormat.of().formatHex(digest.digest()));
    }

    /** Reads a list given as text, as the firewall app does a download; for the shell. */
    private static byte[] readListText(InputStream in, boolean subdomains) throws IOException {
        String text = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        ListContent.Builder builder = new ListContent.Builder();
        ListParser.parse(new StringReader(text), subdomains, Integer.MAX_VALUE, Long.MAX_VALUE,
                builder);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        builder.build().write(out);
        return out.toByteArray();
    }

    private static ParcelFileDescriptor pipeOf(byte[] bytes) throws IOException {
        ParcelFileDescriptor[] pipe = ParcelFileDescriptor.createReliablePipe();
        new Thread(() -> {
            try (OutputStream out = new ParcelFileDescriptor.AutoCloseOutputStream(pipe[1])) {
                out.write(bytes);
            } catch (IOException e) {
                Log.w(FirewallService.TAG, "Couldn't hand over list content", e);
            }
        }).start();
        return pipe[0];
    }

    @Override
    Integer onShellCommand(String cmd, FirewallShellCommand shell) throws IOException {
        switch (cmd) {
            case "list-lists" -> {
                int user = userOption(shell);
                for (FirewallList list : getListsInternal(user)) {
                    shell.getOutPrintWriter().println(list.id + " "
                            + (list.packageName != null ? list.packageName : "all apps") + " "
                            + list.domains + " domains " + list.ranges + " ranges"
                            + (list.error != 0 ? " error " + list.error : ""));
                }
            }
            case "add-list" -> {
                String url = shell.getNextArgRequired();
                boolean subdomains = true;
                int user = UserHandle.SYSTEM.getIdentifier();
                String packageName = null;
                String option;
                while ((option = shell.getNextOption()) != null) {
                    switch (option) {
                        case "--user" -> user = Integer.parseInt(shell.getNextArgRequired());
                        case "--package" -> packageName = shell.getNextArgRequired();
                        case "--exact" -> subdomains = false;
                        default -> throw new IllegalArgumentException("Unknown " + option);
                    }
                }
                String id = addListInternal(user, packageName, url, subdomains);
                if (id == null) throw new IllegalStateException("No free list slot");
                shell.getOutPrintWriter().println(id);
            }
            case "add-list-file" -> {
                String title = shell.getNextArgRequired();
                boolean subdomains = true;
                int user = UserHandle.SYSTEM.getIdentifier();
                String packageName = null;
                String option;
                while ((option = shell.getNextOption()) != null) {
                    switch (option) {
                        case "--user" -> user = Integer.parseInt(shell.getNextArgRequired());
                        case "--package" -> packageName = shell.getNextArgRequired();
                        case "--exact" -> subdomains = false;
                        default -> throw new IllegalArgumentException("Unknown " + option);
                    }
                }
                byte[] content = readListText(shell.getRawInputStream(), subdomains);
                String id = addListFromFileInternal(user, packageName, title, pipeOf(content));
                if (id == null) throw new IllegalStateException("No free list slot");
                shell.getOutPrintWriter().println(id);
            }
            case "set-list-content" -> {
                String id = shell.getNextArgRequired();
                BlockList list;
                synchronized (mService) {
                    list = lists.get(id);
                }
                if (list == null) throw new IllegalArgumentException("No list " + id);
                byte[] content = readListText(shell.getRawInputStream(), list.subdomains);
                int error = setListContentInternal(id, pipeOf(content), null, null, null, null);
                if (error != 0) throw new IllegalArgumentException("Refused: error " + error);
            }
            case "remove-list" -> {
                String id = shell.getNextArgRequired();
                int user = UserHandle.SYSTEM.getIdentifier();
                String packageName = null;
                String option;
                while ((option = shell.getNextOption()) != null) {
                    switch (option) {
                        case "--user" -> user = Integer.parseInt(shell.getNextArgRequired());
                        case "--package" -> packageName = shell.getNextArgRequired();
                        default -> throw new IllegalArgumentException("Unknown " + option);
                    }
                }
                removeListInternal(user, packageName, id);
            }
            default -> {
                return null;
            }
        }
        return 0;
    }

    private static int userOption(FirewallShellCommand shell) {
        int user = UserHandle.SYSTEM.getIdentifier();
        String option;
        while ((option = shell.getNextOption()) != null) {
            if (!option.equals("--user")) throw new IllegalArgumentException("Unknown " + option);
            user = Integer.parseInt(shell.getNextArgRequired());
        }
        return user;
    }

    @Override
    void onShellHelp(PrintWriter pw) {
        pw.println("  list-lists [--user USER]");
        pw.println("  add-list URL [--package PACKAGE] [--user USER] [--exact]");
        pw.println("      Subscribes to the list at the https URL; the firewall app downloads it.");
        pw.println("      --exact leaves the subdomains of its plain names out.");
        pw.println("  add-list-file TITLE [--package PACKAGE] [--user USER] [--exact]");
        pw.println("      Adds the list on standard input, as one added from a file.");
        pw.println("  set-list-content ID");
        pw.println("      Replaces the list's content with the list on standard input.");
        pw.println("  remove-list ID [--package PACKAGE] [--user USER]");
    }
}
