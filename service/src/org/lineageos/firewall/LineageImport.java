/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import android.os.FileObserver;
import android.os.UserHandle;
import android.util.Log;
import android.util.Pair;
import android.util.Xml;

import com.android.modules.utils.BinaryXmlPullParser;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Turns the per-app network bits of Lineage's old firewall, which NPMS kept in netpolicy.xml,
 * into firewall rules: on the firewall's first start, which is the upgrade, and as NPMS restores
 * an old backup. Only bits not seen yet this boot count; NPMS drops them when it next reads the
 * file at boot.
 */
final class LineageImport extends Feature {
    private static final byte[] ABX_MAGIC = {'A', 'B', 'X', 0};
    /** Lineage's per-app network policy bits, which this firewall replaced, and their rules. */
    private static final int[][] LINEAGE_POLICIES = {
            {0x40000, FirewallMaps.BLOCK_ALL}, {0x8000, FirewallMaps.BLOCK_WIFI},
            {0x10000, FirewallMaps.BLOCK_CELLULAR}, {0x20000, FirewallMaps.BLOCK_VPN}};

    private final File mNetpolicy;
    /** Catches NPMS writing Lineage's blocks from an old backup, so they apply at once. */
    private final FileObserver mNetpolicyWrites;
    /** Apps whose Lineage bits were already in netpolicy.xml this boot, imported or leftover. */
    private final Set<Pair<String, Integer>> mImportedApps = new HashSet<>();

    LineageImport(FirewallService service, File storeDir) {
        super(service);
        mNetpolicy = new File(storeDir, "netpolicy.xml");
        mNetpolicyWrites = new FileObserver(storeDir,
                FileObserver.CLOSE_WRITE | FileObserver.MOVED_TO) {
            @Override
            public void onEvent(int event, String path) {
                if (mNetpolicy.getName().equals(path)) {
                    mService.handler().post(() -> onNetpolicyWritten());
                }
            }
        };
    }

    /** Bits already there are imported on the first start and are leftovers after it. */
    @Override
    void onStartLocked(Set<Integer> users, boolean firstStart) {
        importLineagePoliciesLocked(firstStart);
    }

    @Override
    void onStarted() {
        mNetpolicyWrites.startWatching();
    }

    @Override
    boolean forgetUserLocked(int userId) {
        mImportedApps.removeIf(app -> app.second == userId);
        return false;
    }

    private boolean importLineagePoliciesLocked(boolean apply) {
        boolean imported = false;
        for (Map.Entry<Integer, Integer> policy : readLineageRules(mNetpolicy).entrySet()) {
            UserHandle user = UserHandle.getUserHandleForUid(policy.getKey());
            String[] packages = mService.context().createContextAsUser(user, 0)
                    .getPackageManager().getPackagesForUid(policy.getKey());
            if (packages == null) continue;
            for (String packageName : packages) {
                Pair<String, Integer> app = Pair.create(packageName, user.getIdentifier());
                if (!mImportedApps.add(app) || !apply) continue;
                mService.store().apps.putIfAbsent(app, policy.getValue());
                imported = true;
            }
        }
        if (imported) Log.i(FirewallService.TAG, "Imported Lineage's app blocks");
        return imported;
    }

    private void onNetpolicyWritten() {
        synchronized (mService) {
            if (!importLineagePoliciesLocked(true)) return;
            if (mService.mapsReady()) mService.syncAppsLocked();
        }
        mService.saveAsync();
    }

    /** Reads the firewall rules that Lineage's bits in NPMS's netpolicy.xml stand for, by UID. */
    static Map<Integer, Integer> readLineageRules(File netpolicy) {
        Map<Integer, Integer> rules = new HashMap<>();
        try (InputStream in = new BufferedInputStream(new FileInputStream(netpolicy))) {
            in.mark(ABX_MAGIC.length);
            boolean binary = Arrays.equals(in.readNBytes(ABX_MAGIC.length), ABX_MAGIC);
            in.reset();
            XmlPullParser parser = binary ? new BinaryXmlPullParser() : Xml.newPullParser();
            parser.setInput(in, binary ? null : StandardCharsets.UTF_8.name());
            int type;
            while ((type = parser.next()) != XmlPullParser.END_DOCUMENT) {
                if (type != XmlPullParser.START_TAG || !"uid-policy".equals(parser.getName())) {
                    continue;
                }
                int policy = Integer.parseInt(parser.getAttributeValue(null, "policy"));
                int rule = 0;
                for (int[] lineage : LINEAGE_POLICIES) {
                    if ((policy & lineage[0]) != 0) rule |= lineage[1];
                }
                if (rule != 0) {
                    rules.put(Integer.parseInt(parser.getAttributeValue(null, "uid")), rule);
                }
            }
        } catch (FileNotFoundException e) {
            // No network policy yet.
        } catch (IOException | XmlPullParserException | NumberFormatException e) {
            Log.e(FirewallService.TAG, "Failed to read " + netpolicy, e);
            rules.clear();
        }
        return rules;
    }
}
