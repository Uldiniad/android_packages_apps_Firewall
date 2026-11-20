/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.ApplicationInfoFlags;
import android.content.pm.PackageManager.ResolveInfoFlags;
import android.content.pm.ResolveInfo;
import android.net.NetworkCapabilities;
import android.net.TelephonyNetworkSpecifier;
import android.net.VpnService;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiManager;
import android.os.UserHandle;
import android.telephony.SubscriptionInfo;
import android.telephony.SubscriptionManager;
import android.util.Log;
import android.util.Pair;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlSerializer;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.Predicate;

/**
 * An app's choices for specific networks, a saved Wi-Fi network, a SIM or a VPN app, which win
 * over its switches for the network's kind. Each network that choices or rules name gets one of
 * the SLOTS bits, which the network's bits and the app's entry in uid_networks share.
 */
final class SpecificNetworks extends Feature implements NetworkTracker.BitsSource {
    private static final List<String> CHOICES = List.of("default", "allow", "block");

    /** Apps' choices for specific networks, by KnownNetwork key: true to allow, false to block. */
    final Map<Pair<String, Integer>, Map<String, Boolean>> appNetworks = new HashMap<>();
    /** The slots of the specific networks that rules and choices name, as networks carry them. */
    private final Map<String, Integer> mSlots = new HashMap<>();
    /** The slots as the network tracker reads them, under its own lock. */
    private volatile Map<String, Integer> mTrackerSlots = Map.of();
    /** Specific networks named while every slot was taken. */
    private final Set<String> mUnslotted = new HashSet<>();
    /** The slots of blocked and allowed specific networks, as written per uid. */
    private final Map<Integer, List<Integer>> mNamedWritten = new HashMap<>();

    SpecificNetworks(FirewallService service) {
        super(service);
        service.networks().addBitsSource(this);
    }

    @Override
    void clearStore() {
        appNetworks.clear();
    }

    @Override
    boolean readStoreTag(XmlPullParser parser) {
        if (!"app-network".equals(parser.getName())) return false;
        readNetwork(parser, appNetworks.computeIfAbsent(
                FirewallStore.appOf(parser), app -> new TreeMap<>()));
        return true;
    }

    @Override
    void writeStore(XmlSerializer serializer) throws IOException {
        for (Map.Entry<Pair<String, Integer>, Map<String, Boolean>> app : appNetworks.entrySet()) {
            for (Map.Entry<String, Boolean> choice : app.getValue().entrySet()) {
                serializer.startTag(null, "app-network");
                FirewallStore.writeApp(serializer, app.getKey());
                writeNetworkAttributes(serializer, choice);
                serializer.endTag(null, "app-network");
            }
        }
    }

    static void writeNetworkAttributes(XmlSerializer serializer, Map.Entry<String, Boolean> choice)
            throws IOException {
        serializer.attribute(null, "network", choice.getKey());
        serializer.attribute(null, "action", choice.getValue() ? "allow" : "block");
    }

    /** Reads an app's choice for a specific network into its choices, unless it doesn't parse. */
    static void readNetwork(XmlPullParser parser, Map<String, Boolean> networks) {
        try {
            networks.put(TargetRule.normalizeNetwork(parser.getAttributeValue(null, "network")),
                    "allow".equals(parser.getAttributeValue(null, "action")));
        } catch (IllegalArgumentException e) {
            // Skipped.
        }
    }

    /** An app's choices as backed up. */
    private record Part(Map<String, Boolean> choices) {}

    @Override
    Object backupAppLocked(Pair<String, Integer> app) {
        Map<String, Boolean> choices = appNetworks.get(app);
        return choices == null || choices.isEmpty() ? null : new Part(new TreeMap<>(choices));
    }

    @Override
    void writeBackupTags(Object part, boolean user, XmlSerializer serializer) throws IOException {
        for (Map.Entry<String, Boolean> choice : ((Part) part).choices().entrySet()) {
            serializer.startTag(null, "app-network");
            writeNetworkAttributes(serializer, choice);
            serializer.endTag(null, "app-network");
        }
    }

    @Override
    boolean readBackupTag(XmlPullParser parser, boolean user, FirewallBackup.Parts parts) {
        if (user || !"app-network".equals(parser.getName())) return false;
        Part part = (Part) parts.get(this);
        if (part == null) {
            part = new Part(new TreeMap<>());
            parts.put(this, part);
        }
        readNetwork(parser, part.choices());
        return true;
    }

    @Override
    void restoreAppLocked(Pair<String, Integer> app, FirewallBackup.App restored) {
        Part part = (Part) restored.parts().get(this);
        if (part == null || part.choices().isEmpty()) {
            appNetworks.remove(app);
        } else {
            appNetworks.put(app, new TreeMap<>(part.choices()));
        }
    }

    @Override
    void onLoadedLocked(Set<Integer> users) {
        appNetworks.values().removeIf(Map::isEmpty);
        appNetworks.keySet().removeIf(app ->
                !users.contains(app.second) || mService.knownUid(app) < 0);
    }

    @Override
    void onMapsClearedLocked() {
        mNamedWritten.clear();
    }

    @Override
    boolean forgetAppsLocked(Predicate<Pair<String, Integer>> gone) {
        return appNetworks.keySet().removeIf(gone);
    }

    @Override
    boolean forgetUserLocked(int userId) {
        return appNetworks.keySet().removeIf(app -> app.second == userId);
    }

    @Override
    void addAppsWithStateLocked(Set<Pair<String, Integer>> apps) {
        apps.addAll(appNetworks.keySet());
    }

    /** The specific networks that choices and every feature's rules name, of one user or all. */
    Set<String> namedNetworksLocked(Integer userId) {
        Set<String> named = new TreeSet<>();
        appNetworks.forEach((app, choices) -> {
            if (userId == null || app.second.equals(userId)) named.addAll(choices.keySet());
        });
        for (Feature feature : mService.features()) feature.addNamedNetworksLocked(named, userId);
        return named;
    }

    /** The slot of each specific network that is named and got one. */
    Map<String, Integer> slotsLocked() {
        return mSlots;
    }

    /**
     * Gives each specific network rules and choices name a slot, keeping those it has. True if
     * one named before got its first slot, which entries written before lack.
     */
    @Override
    boolean beforeSyncLocked() {
        Set<String> named = namedNetworksLocked(null);
        mSlots.keySet().retainAll(named);
        Set<Integer> taken = new HashSet<>(mSlots.values());
        boolean gained = false;
        int slot = 0;
        for (String network : named) {
            if (mSlots.containsKey(network)) continue;
            while (taken.contains(slot)) slot++;
            if (slot >= FirewallMaps.SLOTS) break;
            mSlots.put(network, slot);
            taken.add(slot);
            gained |= mUnslotted.contains(network);
        }
        mUnslotted.clear();
        for (String network : named) {
            if (!mSlots.containsKey(network)) mUnslotted.add(network);
        }
        if (!mUnslotted.isEmpty()) Log.w(FirewallService.TAG, "No slots left for " + mUnslotted);
        if (!mTrackerSlots.equals(mSlots)) {
            mTrackerSlots = Map.copyOf(mSlots);
            mService.networks().refreshSourceBits();
        }
        return gained;
    }

    @Override
    void writeAppsLocked(Map<Integer, Integer> wanted) {
        Map<Integer, List<Integer>> named = new HashMap<>();
        for (Map.Entry<Pair<String, Integer>, Map<String, Boolean>> app : appNetworks.entrySet()) {
            int uid = mService.knownUid(app.getKey());
            if (uid < 0) continue;
            int block = 0;
            int allow = 0;
            for (Map.Entry<String, Boolean> choice : app.getValue().entrySet()) {
                Integer slot = mSlots.get(choice.getKey());
                if (slot == null) continue;
                if (choice.getValue()) {
                    allow |= 1 << slot;
                } else {
                    block |= 1 << slot;
                }
            }
            if (block == 0 && allow == 0) continue;
            for (int each : FirewallService.withSdkSandbox(uid)) {
                List<Integer> known = named.getOrDefault(each, List.of(0, 0));
                named.put(each, List.of(known.get(0) | block, known.get(1) | allow));
                wanted.merge(each, FirewallMaps.NAMED_NETWORKS, (a, b) -> a | b);
            }
        }
        for (int uid : mNamedWritten.keySet()) {
            if (!named.containsKey(uid)) mService.maps().setNamedNetworks(uid, 0, 0);
        }
        named.forEach((uid, slots) -> {
            if (!slots.equals(mNamedWritten.get(uid))) {
                mService.maps().setNamedNetworks(uid, slots.get(0), slots.get(1));
            }
        });
        mNamedWritten.clear();
        mNamedWritten.putAll(named);
    }

    @Override
    int[] namedSlotsLocked(int uid) {
        List<Integer> slots = mNamedWritten.get(uid);
        return slots == null ? null : new int[] {slots.get(0), slots.get(1)};
    }

    @Override
    void fillAppRuleLocked(Pair<String, Integer> app, AppRule rule) {
        Map<String, Boolean> choices = appNetworks.getOrDefault(app, Map.of());
        rule.allowedNetworks = choices.keySet().stream().filter(choices::get)
                .toArray(String[]::new);
        rule.blockedNetworks = choices.keySet().stream().filter(key -> !choices.get(key))
                .toArray(String[]::new);
    }

    @Override
    public long bitsOf(NetworkCapabilities nc, int transport) {
        String key = keyOf(nc, transport);
        Integer slot = key != null ? mTrackerSlots.get(key) : null;
        return slot != null ? 1L << (32 + slot) : 0;
    }

    /** The specific network: the VPN's app, the Wi-Fi network's SSID, the SIM's subscription. */
    private String keyOf(NetworkCapabilities nc, int transport) {
        if (transport == FirewallMaps.BLOCK_VPN) {
            int[] owners = nc.getAdministratorUids();
            String packageName = owners.length > 0 ? packageOfUid(owners[0]) : null;
            return packageName != null ? TargetRule.VPN + packageName : null;
        }
        if (transport == FirewallMaps.BLOCK_WIFI) {
            return nc.getSsid() != null ? TargetRule.WIFI + nc.getSsid() : null;
        }
        if (transport == FirewallMaps.BLOCK_CELLULAR
                && nc.getNetworkSpecifier() instanceof TelephonyNetworkSpecifier sim) {
            return TargetRule.SIM + sim.getSubscriptionId();
        }
        return null;
    }

    /** A VPN owner's package, which names the VPN as a specific network. */
    private String packageOfUid(int uid) {
        String[] packages = mService.context().getPackageManager().getPackagesForUid(uid);
        return packages != null && packages.length > 0 ? packages[0] : null;
    }

    /** Sets the app's choice for a specific network; false if it would need a slot none has. */
    boolean setAppNetworkInternal(String packageName, int userId, String network, int choice) {
        String key = TargetRule.normalizeNetwork(network);
        if (TargetRule.NETWORK_KINDS.containsKey(key)) {
            throw new IllegalArgumentException("Not a specific network: " + key);
        }
        if (choice < IFirewall.NETWORK_DEFAULT || choice > IFirewall.NETWORK_BLOCK) {
            throw new IllegalArgumentException("Unknown choice " + choice);
        }
        synchronized (mService) {
            Set<String> named = namedNetworksLocked(null);
            if (choice != IFirewall.NETWORK_DEFAULT && !named.contains(key)
                    && named.size() >= FirewallMaps.SLOTS) {
                return false;
            }
            for (Pair<String, Integer> app : mService.sharingUidLocked(packageName, userId)) {
                Map<String, Boolean> choices = appNetworks.computeIfAbsent(app, a -> new TreeMap<>());
                if (choice == IFirewall.NETWORK_DEFAULT) {
                    choices.remove(key);
                } else {
                    choices.put(key, choice == IFirewall.NETWORK_ALLOW);
                }
                if (choices.isEmpty()) appNetworks.remove(app);
            }
            if (mService.mapsReady()) mService.syncAppsLocked();
        }
        mService.saveAsync();
        return true;
    }

    /**
     * The user's saved Wi-Fi networks, SIMs and VPN apps, with the specific networks their rules
     * and choices name and those the device is on.
     */
    KnownNetwork[] getNetworksInternal(int userId) {
        Map<String, String> names = new TreeMap<>();
        WifiManager wifi = mService.context().getSystemService(WifiManager.class);
        if (wifi != null) {
            for (WifiConfiguration config : wifi.getPrivilegedConfiguredNetworks()) {
                if (config.SSID != null) names.put(TargetRule.WIFI + config.SSID, null);
            }
        }
        SubscriptionManager subscriptions =
                mService.context().getSystemService(SubscriptionManager.class);
        List<SubscriptionInfo> sims =
                subscriptions != null ? subscriptions.getAvailableSubscriptionInfoList() : null;
        for (SubscriptionInfo sim : sims != null ? sims : List.<SubscriptionInfo>of()) {
            names.put(TargetRule.SIM + sim.getSubscriptionId(), sim.getDisplayName() != null
                    ? sim.getDisplayName().toString() : null);
        }
        PackageManager pm = mService.context().createContextAsUser(UserHandle.of(userId), 0)
                .getPackageManager();
        for (ResolveInfo vpn : pm.queryIntentServices(new Intent(VpnService.SERVICE_INTERFACE),
                ResolveInfoFlags.of(FirewallService.PACKAGE_FLAGS))) {
            if (Manifest.permission.BIND_VPN_SERVICE.equals(vpn.serviceInfo.permission)) {
                names.put(TargetRule.VPN + vpn.serviceInfo.packageName, null);
            }
        }
        synchronized (mService) {
            for (String network : namedNetworksLocked(userId)) names.putIfAbsent(network, null);
        }
        Set<String> connected = connectedKeys();
        for (String network : connected) names.putIfAbsent(network, null);
        List<KnownNetwork> networks = new ArrayList<>();
        names.forEach((key, name) -> {
            KnownNetwork network = new KnownNetwork();
            network.key = key;
            network.name = name != null ? name : nameOf(key, pm);
            network.connected = connected.contains(key);
            networks.add(network);
        });
        return networks.toArray(new KnownNetwork[0]);
    }

    /** The keys of the specific networks the device is on. */
    Set<String> connectedKeys() {
        Set<String> connected = new HashSet<>();
        for (NetworkCapabilities nc : mService.networks().connectedCapabilities()) {
            String key = keyOf(nc, NetworkTracker.transportOf(nc));
            if (key != null) connected.add(key);
        }
        return connected;
    }

    /** What the user knows a specific network as, from its key. */
    private static String nameOf(String key, PackageManager pm) {
        if (key.startsWith(TargetRule.WIFI)) {
            String ssid = key.substring(TargetRule.WIFI.length());
            return ssid.length() > 1 && ssid.startsWith("\"") && ssid.endsWith("\"")
                    ? ssid.substring(1, ssid.length() - 1) : ssid;
        }
        if (key.startsWith(TargetRule.VPN)) {
            String packageName = key.substring(TargetRule.VPN.length());
            try {
                return pm.getApplicationInfo(packageName,
                        ApplicationInfoFlags.of(FirewallService.PACKAGE_FLAGS))
                        .loadLabel(pm).toString();
            } catch (PackageManager.NameNotFoundException e) {
                return packageName;
            }
        }
        // A SIM that is gone has no name left.
        return null;
    }

    @Override
    void dumpLocked(PrintWriter pw) {
        appNetworks.forEach((app, choices) -> pw.println("Networks for " + app.first
                + " user " + app.second + ": " + choices));
        pw.println("Specific network slots: " + mSlots);
    }

    @Override
    Integer onShellCommand(String cmd, FirewallShellCommand shell) {
        switch (cmd) {
            case "set-network" -> {
                String packageName = shell.getNextArgRequired();
                String network = shell.getNextArgRequired();
                int choice = CHOICES.indexOf(shell.getNextArgRequired());
                if (choice < 0) throw new IllegalArgumentException("Unknown choice");
                if (!setAppNetworkInternal(packageName, shell.parseUser(), network, choice)) {
                    throw new IllegalArgumentException("Too many specific networks");
                }
            }
            case "list-networks" -> {
                for (KnownNetwork network : getNetworksInternal(shell.parseUser())) {
                    shell.getOutPrintWriter().println(network.key
                            + (network.connected ? " (connected)" : "")
                            + (network.name != null ? ": " + network.name : ""));
                }
            }
            default -> {
                return null;
            }
        }
        return 0;
    }

    @Override
    void onShellHelp(PrintWriter pw) {
        pw.println("  set-network PACKAGE NETWORK default|allow|block [--user USER]");
        pw.println("      Sets the app's choice for a specific network, over its switches.");
        pw.println("  list-networks [--user USER]");
    }
}
