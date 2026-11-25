/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import android.net.MacAddress;
import android.net.Network;
import android.net.TetheredClient;
import android.net.TetheringManager;
import android.os.Process;
import android.os.UserHandle;
import android.util.Log;
import android.util.Pair;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlSerializer;

import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Devices on the phone's hotspot and tethering: what they send out through the phone follows a
 * device's own rules, kept as an app's are under IFirewall.DEVICE_PREFIX and its MAC address, then
 * those for all the devices, under IFirewall.HOTSPOT_PACKAGE, then the rules for all of the main
 * user's apps. The hotspot program is on each tethered interface while the firewall is on, and
 * reads rules limited to networks against Tethering's upstream.
 */
final class Hotspot extends Feature implements TetheringManager.TetheringEventCallback {
    private static final String TAG_DEVICE = "hotspot-device";
    private static final Pair<String, Integer> DEVICES =
            Pair.create(IFirewall.HOTSPOT_PACKAGE, UserHandle.USER_SYSTEM);

    /** The uids the devices' own rules are kept under, by MAC address. */
    final Map<String, Integer> deviceUids = new TreeMap<>();
    /** The names the devices gave with their addresses, by MAC address. */
    final Map<String, String> names = new HashMap<>();
    /** The devices on the hotspot now. */
    private Set<String> mConnected = Set.of();
    /** The devices the hotspot program knows, with their uids. */
    private final Map<String, Integer> mWritten = new HashMap<>();
    /** The tethered interfaces, as Tethering last reported them. */
    private List<String> mTethered = List.of();

    Hotspot(FirewallService service) {
        super(service);
    }

    private static Pair<String, Integer> deviceApp(String mac) {
        return Pair.create(IFirewall.DEVICE_PREFIX + mac, UserHandle.USER_SYSTEM);
    }

    /** The MAC address as Android writes it, or null when it isn't one. */
    private static String canonicalMac(String text) {
        try {
            return text != null ? MacAddress.fromString(text).toString() : null;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** The MAC address of the device the app names, if it names one. */
    private static String macOf(Pair<String, Integer> app) {
        return app.second == UserHandle.USER_SYSTEM && app.first.startsWith(IFirewall.DEVICE_PREFIX)
                ? canonicalMac(app.first.substring(IFirewall.DEVICE_PREFIX.length())) : null;
    }

    static boolean isDeviceUid(int uid) {
        return uid >= FirewallMaps.HOTSPOT_DEVICE_UID_START
                && uid < FirewallMaps.HOTSPOT_DEVICE_UID_START + FirewallMaps.HOTSPOT_DEVICES;
    }

    @Override
    void clearStore() {
        deviceUids.clear();
        names.clear();
    }

    @Override
    boolean readStoreTag(XmlPullParser parser) {
        if (!TAG_DEVICE.equals(parser.getName())) return false;
        String mac = canonicalMac(parser.getAttributeValue(null, "mac"));
        try {
            int uid = Integer.parseInt(parser.getAttributeValue(null, "uid"));
            if (mac != null && isDeviceUid(uid) && !deviceUids.containsValue(uid)) {
                deviceUids.put(mac, uid);
                String name = parser.getAttributeValue(null, "name");
                if (name != null) names.put(mac, name);
            }
        } catch (NumberFormatException e) {
            Log.w(FirewallService.TAG, "Skipped a malformed hotspot device");
        }
        return true;
    }

    @Override
    void writeStore(XmlSerializer serializer) throws IOException {
        for (Map.Entry<String, Integer> device : deviceUids.entrySet()) {
            serializer.startTag(null, TAG_DEVICE);
            serializer.attribute(null, "mac", device.getKey());
            serializer.attribute(null, "uid", Integer.toString(device.getValue()));
            String name = names.get(device.getKey());
            if (name != null) serializer.attribute(null, "name", name);
            serializer.endTag(null, TAG_DEVICE);
        }
    }

    /**
     * dnsmasq's uid stands for all the devices, and a device's own uid for it, in their lookups
     * and in the hotspot program.
     */
    @Override
    int[] memberUidsLocked(Pair<String, Integer> app) {
        if (DEVICES.equals(app)) return new int[] {Process.DNS_TETHER_UID};
        String mac = macOf(app);
        if (mac == null) return null;
        Integer uid = deviceUids.get(mac);
        for (int next = FirewallMaps.HOTSPOT_DEVICE_UID_START;
                uid == null && isDeviceUid(next); next++) {
            if (!deviceUids.containsValue(next)) {
                uid = next;
                deviceUids.put(mac, uid);
            }
        }
        // With every uid taken, the device's rules are kept without applying.
        return uid != null ? new int[] {uid} : new int[0];
    }

    /**
     * dnsmasq keeps answering the devices whatever their rules, which the OEM deny chain stops,
     * and no process has a device's uid.
     */
    @Override
    boolean letsThroughLocked(int uid, int rules) {
        return uid == Process.DNS_TETHER_UID || isDeviceUid(uid);
    }

    @Override
    void onMapsClearedLocked() {
        mWritten.clear();
    }

    /** Devices whose rules are gone give their uids back; the rest are told to the program. */
    @Override
    void writeAppsLocked(Map<Integer, Integer> wanted) {
        Set<Pair<String, Integer>> apps = mService.appsWithStateLocked();
        deviceUids.keySet().removeIf(mac -> !apps.contains(deviceApp(mac)));
        for (String mac : List.copyOf(mWritten.keySet())) {
            if (!mWritten.get(mac).equals(deviceUids.get(mac))) {
                writeDevice(mac, 0);
                mWritten.remove(mac);
            }
        }
        for (Map.Entry<String, Integer> device : deviceUids.entrySet()) {
            if (mWritten.containsKey(device.getKey())) continue;
            writeDevice(device.getKey(), device.getValue());
            mWritten.put(device.getKey(), device.getValue());
        }
    }

    private void writeDevice(String mac, int uid) {
        int error = mService.maps().setHotspotDevice(mac, uid);
        if (error != 0) {
            Log.e(FirewallService.TAG, "Failed to write hotspot device " + mac + ": " + error);
        }
    }

    /** The devices on the hotspot now, and those with rules of their own. */
    HotspotDevice[] getHotspotDevicesInternal() {
        synchronized (mService) {
            Set<String> macs = new TreeSet<>(mConnected);
            for (Pair<String, Integer> app : mService.appsWithStateLocked()) {
                String mac = macOf(app);
                if (mac != null) macs.add(mac);
            }
            return macs.stream().map(mac -> {
                HotspotDevice device = new HotspotDevice();
                device.mac = mac;
                device.name = names.get(mac);
                device.connected = mConnected.contains(mac);
                device.uid = deviceUids.getOrDefault(mac, 0);
                return device;
            }).toArray(HotspotDevice[]::new);
        }
    }

    void forgetHotspotDeviceInternal(String mac) {
        synchronized (mService) {
            String canonical = canonicalMac(mac);
            if (canonical == null) return;
            mService.forgetAppLocked(deviceApp(canonical));
            if (mService.mapsReady()) mService.syncAppsLocked();
        }
        mService.saveAsync();
    }

    @Override
    void onBootPhase() {
        if (!mService.mapsReady()) return;
        mService.context().getSystemService(TetheringManager.class)
                .registerTetheringEventCallback(mService.handler()::post, this);
    }

    @Override
    public void onClientsChanged(Collection<TetheredClient> clients) {
        Set<String> connected = new HashSet<>();
        synchronized (mService) {
            for (TetheredClient client : clients) {
                String mac = client.getMacAddress().toString();
                connected.add(mac);
                for (TetheredClient.AddressInfo address : client.getAddresses()) {
                    if (address.getHostname() != null) names.put(mac, address.getHostname());
                }
            }
            mConnected = connected;
        }
        // Tells the firewall app, and keeps the names of devices with rules.
        mService.saveAsync();
    }

    @Override
    public void onTetheredInterfacesChanged(List<String> interfaces) {
        synchronized (mService) {
            for (String iface : mTethered) {
                if (!interfaces.contains(iface)) setOn(iface, false);
            }
            mTethered = List.copyOf(interfaces);
            applyLocked();
        }
    }

    @Override
    public void onUpstreamChanged(Network network) {
        int error = mService.maps().setHotspotUpstream(network != null ? network.getNetId() : 0);
        if (error != 0) {
            Log.e(FirewallService.TAG, "Failed to write the hotspot's upstream: " + error);
        }
    }

    @Override
    void onTurnedOffLocked() {
        applyLocked();
    }

    @Override
    void onTurnedOnLocked() {
        applyLocked();
    }

    /** Puts the program on the tethered interfaces while the firewall is on, else takes it off. */
    private void applyLocked() {
        for (String iface : mTethered) setOn(iface, !mService.offLocked());
    }

    private void setOn(String iface, boolean on) {
        int error = on ? mService.maps().attachHotspot(iface)
                : mService.maps().detachHotspot(iface);
        if (error != 0) {
            Log.e(FirewallService.TAG, "Failed to " + (on ? "attach" : "detach")
                    + " the hotspot program on " + iface + ": " + error);
        }
    }
}
