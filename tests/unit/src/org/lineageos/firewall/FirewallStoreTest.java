/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import android.util.Pair;

import androidx.test.platform.app.InstrumentationRegistry;

import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;

public class FirewallStoreTest {
    private File mDir;

    @Before
    public void setUp() throws Exception {
        mDir = Files.createTempDirectory(InstrumentationRegistry.getInstrumentation()
                .getContext().getCacheDir().toPath(), "store").toFile();
    }

    @Test
    public void appSwitchesSurviveSaveAndLoad() {
        FirewallStore store = new FirewallStore(mDir, List.of());
        store.apps.put(Pair.create("org.example.app", 10), FirewallMaps.BLOCK_CELLULAR);
        store.apps.put(Pair.create("org.example.allowed", 10), 0);
        store.save();

        FirewallStore loaded = new FirewallStore(mDir, List.of());
        loaded.load();
        assertEquals(Map.of(Pair.create("org.example.app", 10), FirewallMaps.BLOCK_CELLULAR,
                Pair.create("org.example.allowed", 10), 0), loaded.apps);
    }
    @Test
    public void missingOrCorruptFileLoadsNoRules() throws Exception {
        FirewallStore store = new FirewallStore(mDir, List.of());
        store.load();
        assertTrue(store.apps.isEmpty());

        Files.writeString(new File(mDir, "firewall.xml").toPath(), "<firewall><app package=");
        store.load();
        assertTrue(store.apps.isEmpty());
    }
}
