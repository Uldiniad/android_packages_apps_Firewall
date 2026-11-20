/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import android.util.AtomicFile;
import android.util.Log;
import android.util.Pair;
import android.util.Xml;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlSerializer;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** The firewall's rules, kept in /data/system so they load before the user unlocks. */
final class FirewallStore {
    private static final String TAG = "Firewall";
    private static final int VERSION = 1;

    /** Rules per (package name, user id); 0 records a decision to allow. */
    final Map<Pair<String, Integer>, Integer> apps = new HashMap<>();

    private final AtomicFile mFile;
    /** The features that keep their own state in the file. */
    private final List<Feature> mFeatures;

    FirewallStore(File dir, List<Feature> features) {
        mFile = new AtomicFile(new File(dir, "firewall.xml"));
        mFeatures = features;
    }

    /** Whether the firewall has saved its rules before; absent on its first start. */
    boolean exists() {
        return mFile.getBaseFile().exists();
    }

    void load() {
        apps.clear();
        for (Feature feature : mFeatures) feature.clearStore();
        try (FileInputStream in = mFile.openRead()) {
            XmlPullParser parser = Xml.newPullParser();
            parser.setInput(in, StandardCharsets.UTF_8.name());
            int type;
            while ((type = parser.next()) != XmlPullParser.END_DOCUMENT) {
                if (type != XmlPullParser.START_TAG) continue;
                switch (parser.getName()) {
                    case "app" -> {
                        Pair<String, Integer> app = Pair.create(
                                parser.getAttributeValue(null, "package"),
                                Integer.parseInt(parser.getAttributeValue(null, "user")));
                        apps.put(app, Integer.parseInt(parser.getAttributeValue(null, "rules")));
                        for (Feature feature : mFeatures) feature.readAppAttributes(app, parser);
                    }
                    default -> {
                        for (Feature feature : mFeatures) {
                            if (feature.readStoreTag(parser)) break;
                        }
                    }
                }
            }
        } catch (FileNotFoundException e) {
            // First boot: no rules yet.
        } catch (IOException | XmlPullParserException | NumberFormatException e) {
            Log.e(TAG, "Failed to read " + mFile.getBaseFile(), e);
        }
    }

    void save() {
        FileOutputStream out = null;
        try {
            out = mFile.startWrite();
            XmlSerializer serializer = Xml.newSerializer();
            serializer.setOutput(out, StandardCharsets.UTF_8.name());
            for (Feature feature : mFeatures) feature.onSaveLocked();
            serializer.startDocument(null, true);
            serializer.startTag(null, "firewall");
            serializer.attribute(null, "version", Integer.toString(VERSION));
            for (Map.Entry<Pair<String, Integer>, Integer> app : apps.entrySet()) {
                serializer.startTag(null, "app");
                serializer.attribute(null, "package", app.getKey().first);
                serializer.attribute(null, "user", Integer.toString(app.getKey().second));
                serializer.attribute(null, "rules", Integer.toString(app.getValue()));
                for (Feature feature : mFeatures) {
                    feature.writeAppAttributes(app.getKey(), serializer);
                }
                serializer.endTag(null, "app");
            }
            for (Feature feature : mFeatures) feature.writeStore(serializer);
            serializer.endTag(null, "firewall");
            serializer.endDocument();
            mFile.finishWrite(out);
        } catch (IOException e) {
            Log.e(TAG, "Failed to write " + mFile.getBaseFile(), e);
            mFile.failWrite(out);
        }
    }

    static Pair<String, Integer> appOf(XmlPullParser parser) {
        return Pair.create(parser.getAttributeValue(null, "package"),
                Integer.parseInt(parser.getAttributeValue(null, "user")));
    }

    static void writeApp(XmlSerializer serializer, Pair<String, Integer> app)
            throws IOException {
        serializer.attribute(null, "package", app.first);
        serializer.attribute(null, "user", Integer.toString(app.second));
    }
}
