/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import android.util.Pair;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlSerializer;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;

/**
 * A part of the firewall with its own rules, which the service consults at each point where it
 * has a say. Every method has a default that does nothing, so a feature implements only its own
 * points, and removing a feature leaves the others as they were. Methods ending in Locked run
 * with the service's lock held.
 */
abstract class Feature {
    protected final FirewallService mService;

    Feature(FirewallService service) {
        mService = service;
    }

    /** Forgets the stored state before the store loads. */
    void clearStore() {}

    /** Reads one of the store's tags; false when the tag isn't this feature's. */
    boolean readStoreTag(XmlPullParser parser) throws IOException, XmlPullParserException {
        return false;
    }

    void writeStore(XmlSerializer serializer) throws IOException {}

    /** After the store loads: drops what belongs to users and apps that are gone. */
    void onLoadedLocked(Set<Integer> users) {}

    /** After loading, with firstStart on the firewall's first start, the upgrade. */
    void onStartLocked(Set<Integer> users, boolean firstStart) {}

    /** At the end of the service's start, without its lock. */
    void onStarted() {}

    /** Writes the maps this feature fills on its own, after the start cleared them. */
    void onMapsClearedLocked() {}

    /** Once the activity manager is ready: registers for what the feature follows. */
    void onBootPhase() {}

    /** An app was installed; true if the store changed. */
    boolean onPackageAddedLocked(Pair<String, Integer> app, int uid) {
        return false;
    }

    /** Drops the state of apps that are gone; true if the store changed. */
    boolean forgetAppsLocked(Predicate<Pair<String, Integer>> gone) {
        return false;
    }

    /** Drops the user's state; true if the store changed. */
    boolean forgetUserLocked(int userId) {
        return false;
    }

    /** Adds the apps this feature has state for, which have rules even without switches. */
    void addAppsWithStateLocked(Set<Pair<String, Integer>> apps) {}

    /**
     * Adds the feature's bits to the uid map's rules, by uid, and writes the feature's own maps
     * for them, before the uid map gets the bits that enable those entries.
     */
    void writeAppsLocked(Map<Integer, Integer> wanted) {}

    /** Fills in what the feature knows of the app for the firewall app. */
    void fillAppRuleLocked(Pair<String, Integer> app, AppRule rule) {}

    /** Writes the feature's part of the dump. */
    void dumpLocked(PrintWriter pw) {}

    /** Runs one of the feature's shell commands; null when the command isn't the feature's. */
    Integer onShellCommand(String cmd, FirewallShellCommand shell) throws IOException {
        return null;
    }

    void onShellHelp(PrintWriter pw) {}
}
