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
import java.util.function.UnaryOperator;

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

    /** Reads the feature's attributes of an app's tag in the store. */
    void readAppAttributes(Pair<String, Integer> app, XmlPullParser parser) {}

    /** Writes the feature's attributes of an app's tag in the store. */
    void writeAppAttributes(Pair<String, Integer> app, XmlSerializer serializer)
            throws IOException {}

    /** Before the store is written, with the service's lock held. */
    void onSaveLocked() {}

    /** The user set the app's switches, which is their decision on it. */
    void onDecisionLocked(Pair<String, Integer> app) {}

    /** Adds what the feature knows of the app to its line in the dump. */
    void describeAppLocked(Pair<String, Integer> app, StringBuilder line) {}

    /** After the store loads: drops what belongs to users and apps that are gone. */
    void onLoadedLocked(Set<Integer> users) {}

    /** After loading, with firstStart on the firewall's first start, the upgrade. */
    void onStartLocked(Set<Integer> users, boolean firstStart) {}

    /** At the end of the service's start, without its lock. */
    void onStarted() {}

    /** Writes the maps this feature fills on its own, after the start cleared them. */
    void onMapsClearedLocked() {}

    /** After the start's first sync of apps and the OEM deny chain. */
    void onStartSyncedLocked() {}

    /** The main switch turned the firewall off, and the maps were emptied. */
    void onTurnedOffLocked() {}

    /** The main switch turned the firewall back on, and everything was written again. */
    void onTurnedOnLocked() {}

    /** Once the activity manager is ready: registers for what the feature follows. */
    void onBootPhase() {}

    /** Before apps are synced again after package or user changes. */
    void onResyncLocked() {}

    /** An app was installed; true if the store changed. */
    boolean onPackageAddedLocked(Pair<String, Integer> app, int uid) {
        return false;
    }

    /** An update of the app finished; true if the store changed. */
    boolean onPackageUpdatedLocked(Pair<String, Integer> app, int uid) {
        return false;
    }

    /** The app is being archived; true if the store changed. */
    boolean onArchivingLocked(Pair<String, Integer> app) {
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

    /** Adds the specific networks the feature's rules name, of the user, or of all if null. */
    void addNamedNetworksLocked(Set<String> named, Integer userId) {}

    /** Adds the apps this feature has state for, which have rules even without switches. */
    void addAppsWithStateLocked(Set<Pair<String, Integer>> apps) {}

    /**
     * When the app is one of this feature's groups, the uids of the apps in it, which get its
     * rules instead of their own; else null.
     */
    int[] memberUidsLocked(Pair<String, Integer> app) {
        return null;
    }

    /** The group whose rules the app follows instead of its own; null when it's in none. */
    Pair<String, Integer> groupOfLocked(Pair<String, Integer> app) {
        return null;
    }

    /** Gives an app or a group a copy of what the feature keeps for another, instead of its own. */
    void copyAppLocked(Pair<String, Integer> from, Pair<String, Integer> to) {}

    /** Copies one app's or group's value in the map to another, or drops the other's for none. */
    static <T> void copyEntry(Map<Pair<String, Integer>, T> map, Pair<String, Integer> from,
            Pair<String, Integer> to, UnaryOperator<T> copy) {
        T value = map.get(from);
        if (value == null) {
            map.remove(to);
        } else {
            map.put(to, copy.apply(value));
        }
    }

    /** The app's switches at the time, as the feature changes them; rules by default. */
    int rulesNowLocked(Pair<String, Integer> app, int rules, long now) {
        return rules;
    }

    /** Called before a sync; true if everything must be written again, not only apps. */
    boolean beforeSyncLocked() {
        return false;
    }

    /**
     * Adds the feature's bits to the uid map's rules, by uid, and writes the feature's own maps
     * for them, before the uid map gets the bits that enable those entries.
     */
    void writeAppsLocked(Map<Integer, Integer> wanted) {}

    /** Writes the user's rules for all of their apps. */
    void writeUserLocked(int userId) {}

    /** Whether the uid's rules let some traffic through even when it has no network left. */
    boolean letsThroughLocked(int uid, int rules) {
        return false;
    }

    /** The slots of specific networks the uid is blocked and allowed on, as {block, allow}. */
    int[] namedSlotsLocked(int uid) {
        return null;
    }

    /** Fills in what the feature knows of the app for the firewall app. */
    void fillAppRuleLocked(Pair<String, Integer> app, AppRule rule) {}

    /** The feature's part of the app's backup; null when it has none. */
    Object backupAppLocked(Pair<String, Integer> app) {
        return null;
    }

    /** The feature's part of the user's backup; null when it has none. */
    Object backupUserLocked(int userId) {
        return null;
    }

    /** Writes the feature's attributes of a backed-up user, or app, from its part. */
    void writeBackupAttributes(Object part, boolean user, XmlSerializer serializer)
            throws IOException {}

    /** Writes the feature's tags inside a backed-up user, or app, from its part. */
    void writeBackupTags(Object part, boolean user, XmlSerializer serializer)
            throws IOException {}

    /** Reads the feature's attributes of a backed-up user, or app: its part, or null. */
    Object readBackupAttributes(XmlPullParser parser, boolean user) {
        return null;
    }

    /**
     * Reads a tag inside a backed-up user, or app, into the feature's part, as payloads are
     * untrusted: what doesn't parse is left out. False if the tag isn't the feature's.
     */
    boolean readBackupTag(XmlPullParser parser, boolean user, FirewallBackup.Parts parts)
            throws IOException, XmlPullParserException {
        return false;
    }

    /** Applies the feature's part of a restored app, after its switches. */
    void restoreAppLocked(Pair<String, Integer> app, FirewallBackup.App restored) {}

    /** Applies the feature's part of a restored user, whose state was forgotten first. */
    void restoreUserLocked(int userId, Object part) {}

    /** After a restore replaced the user's rules and synced them. */
    void onRestoredLocked(int userId) {}

    /** Writes the feature's part of the dump. */
    void dumpLocked(PrintWriter pw) {}

    /** Writes the feature's part of the dump that reads the maps, after the counters. */
    void dumpMaps(PrintWriter pw) {}

    /** Runs one of the feature's shell commands; null when the command isn't the feature's. */
    Integer onShellCommand(String cmd, FirewallShellCommand shell) throws IOException {
        return null;
    }

    void onShellHelp(PrintWriter pw) {}
}
