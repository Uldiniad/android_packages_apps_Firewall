/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import android.util.Xml;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlSerializer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * A user's firewall state as backed up: their apps' switches, and each feature's part of every
 * app and of the user, which the features read and write themselves.
 */
final class FirewallBackup {
    private static final int VERSION = 1;
    /** The rules a user sets; the service works out the other bits. */
    static final int USER_RULES = FirewallMaps.BLOCK_ALL | FirewallMaps.NETWORKS
            | FirewallMaps.BLOCK_DNS | FirewallMaps.BLOCK_LOCKED | FirewallMaps.ALLOW_LOCKED
            | FirewallMaps.ALLOW_LOCKDOWN;

    /** Each feature's part of an app or a user, by feature. */
    static final class Parts {
        private final Map<Feature, Object> mParts = new HashMap<>();

        Object get(Feature feature) {
            return mParts.get(feature);
        }

        void put(Feature feature, Object part) {
            if (part == null) {
                mParts.remove(feature);
            } else {
                mParts.put(feature, part);
            }
        }

        int size() {
            return mParts.size();
        }
    }

    /**
     * An app's switches, -1 if only features' state was set, with the SHA-256 digests of the
     * certificates its APK was signed with.
     */
    record App(String packageName, int rules, Set<String> certs, Parts parts) {}

    final List<App> apps = new ArrayList<>();
    /** The features' parts of the user. */
    final Parts user = new Parts();

    byte[] toBytes(List<Feature> features) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        XmlSerializer serializer = Xml.newSerializer();
        serializer.setOutput(out, StandardCharsets.UTF_8.name());
        serializer.startDocument(null, true);
        serializer.startTag(null, "firewall-backup");
        serializer.attribute(null, "version", Integer.toString(VERSION));
        for (Feature feature : features) {
            Object part = user.get(feature);
            if (part != null) feature.writeBackupAttributes(part, true, serializer);
        }
        for (App app : apps) writeApp(serializer, "app", app, null, features);
        for (Feature feature : features) {
            Object part = user.get(feature);
            if (part != null) feature.writeBackupTags(part, true, serializer);
        }
        serializer.endTag(null, "firewall-backup");
        serializer.endDocument();
        return out.toByteArray();
    }

    /** Parses a payload; throws IllegalArgumentException when it isn't one. */
    static FirewallBackup fromBytes(byte[] payload, List<Feature> features) {
        FirewallBackup backup = new FirewallBackup();
        try {
            XmlPullParser parser = Xml.newPullParser();
            parser.setInput(new ByteArrayInputStream(payload), StandardCharsets.UTF_8.name());
            // Any other document, as a file someone picks can be, isn't an empty backup.
            parser.nextTag();
            parser.require(XmlPullParser.START_TAG, null, "firewall-backup");
            for (Feature feature : features) {
                backup.user.put(feature, feature.readBackupAttributes(parser, true));
            }
            int type;
            while ((type = parser.next()) != XmlPullParser.END_DOCUMENT) {
                if (type != XmlPullParser.START_TAG) continue;
                switch (parser.getName()) {
                    case "app" -> backup.apps.add(readApp(parser, features));
                    default -> {
                        for (Feature feature : features) {
                            if (feature.readBackupTag(parser, true, backup.user)) break;
                        }
                    }
                }
            }
        } catch (IOException | XmlPullParserException | NumberFormatException
                | NullPointerException e) {
            throw new IllegalArgumentException("Not a firewall backup", e);
        }
        return backup;
    }

    static void writeApp(XmlSerializer serializer, String tag, App app, Integer user,
            List<Feature> features) throws IOException {
        serializer.startTag(null, tag);
        if (user != null) serializer.attribute(null, "user", user.toString());
        serializer.attribute(null, "package", app.packageName());
        if (app.rules() >= 0) serializer.attribute(null, "rules", Integer.toString(app.rules()));
        for (Feature feature : features) {
            Object part = app.parts().get(feature);
            if (part != null) feature.writeBackupAttributes(part, false, serializer);
        }
        if (!app.certs().isEmpty()) {
            serializer.attribute(null, "certs", String.join(",", app.certs()));
        }
        for (Feature feature : features) {
            Object part = app.parts().get(feature);
            if (part != null) feature.writeBackupTags(part, false, serializer);
        }
        serializer.endTag(null, tag);
    }

    /** Reads an app as written above, with the features' tags nested in it. */
    static App readApp(XmlPullParser parser, List<Feature> features)
            throws IOException, XmlPullParserException {
        String certs = parser.getAttributeValue(null, "certs");
        String rules = parser.getAttributeValue(null, "rules");
        String packageName = parser.getAttributeValue(null, "package").trim();
        Parts parts = new Parts();
        for (Feature feature : features) {
            parts.put(feature, feature.readBackupAttributes(parser, false));
        }
        int depth = parser.getDepth();
        int type;
        while ((type = parser.next()) != XmlPullParser.END_DOCUMENT
                && !(type == XmlPullParser.END_TAG && parser.getDepth() == depth)) {
            if (type != XmlPullParser.START_TAG) continue;
            for (Feature feature : features) {
                if (feature.readBackupTag(parser, false, parts)) break;
            }
        }
        return new App(packageName, rules == null ? -1 : Integer.parseInt(rules) & USER_RULES,
                certs == null || certs.isEmpty() ? Set.of() : Set.of(certs.split(",")), parts);
    }
}
