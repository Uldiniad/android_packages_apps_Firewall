/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;

import android.content.Context;
import android.Manifest;
import android.content.ContextWrapper;
import android.net.ConnectivityManager;
import android.os.Process;
import android.os.SystemClock;

import androidx.test.platform.app.InstrumentationRegistry;

import com.android.compatibility.common.util.AdoptShellPermissionsRule;

import org.junit.Before;
import org.junit.Rule;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;

/** Runs the service against this test app's own package, with fake maps and Connectivity. */
public abstract class ServiceTestBase {
    static final String PACKAGE = "org.lineageos.firewall.tests";
    static final int UID = Process.myUid();

    final ConnectivityManager mConnectivity = mock(ConnectivityManager.class);
    final FakeMaps mMaps = new FakeMaps();
    File mDir;

    int blockAll() {
        return mMaps.uids.get(UID) & FirewallMaps.BLOCK_ALL;
    }

    /** This app's entry among its user's, which also lists other apps the service blocked. */
    static AppRule ownRule(FirewallService service) {
        return Arrays.stream(service.getAppRulesForUserInternal(0))
                .filter(rule -> rule.packageName.equals(PACKAGE)).findFirst().orElseThrow();
    }

    Context context() {
        return new ContextWrapper(InstrumentationRegistry.getInstrumentation().getContext()) {
            @Override
            public Object getSystemService(String name) {
                return Context.CONNECTIVITY_SERVICE.equals(name)
                        ? mConnectivity : super.getSystemService(name);
            }
        };
    }

    FirewallService start() {
        FirewallService service = new FirewallService(context(), mMaps, mDir);
        service.init();
        return service;
    }

    /** A service over the test's directory that isn't started, to set up or read its store. */
    FirewallService unstarted() {
        return new FirewallService(context(), new FakeMaps(), mDir);
    }

    int noLoopback() {
        return mMaps.uids.getOrDefault(UID, 0) & FirewallMaps.NO_LOOPBACK;
    }

    /**
     * Waits until the saved rules pass {@code check}, given a service that loaded them, woken as
     * the service finishes each save. The file is read from a copy: AtomicFile's reader deletes a
     * save still being written.
     */
    void awaitSaved(FirewallService service, Predicate<FirewallService> check)
            throws Exception {
        Semaphore saves = new Semaphore(0);
        IFirewallListener listener = new IFirewallListener.Stub() {
            @Override
            public void onChanged() {
                saves.release();
            }
        };
        service.registerListenerInternal(listener);
        File copy = Files.createTempDirectory(mDir.toPath(), "saved").toFile();
        FirewallService reader = new FirewallService(context(), new FakeMaps(), copy);
        try {
            long deadline = SystemClock.uptimeMillis() + 5000;
            while (true) {
                File saved = new File(mDir, "firewall.xml");
                if (saved.exists()) {
                    Files.copy(saved.toPath(), new File(copy, "firewall.xml").toPath(),
                            StandardCopyOption.REPLACE_EXISTING);
                }
                reader.store().load();
                if (check.test(reader)) return;
                long left = deadline - SystemClock.uptimeMillis();
                assertTrue("rules never saved", saves.tryAcquire(left, TimeUnit.MILLISECONDS));
            }
        } finally {
            service.unregisterListenerInternal(listener);
        }
    }

    // Listing every user's apps needs these.
    @Rule
    public final AdoptShellPermissionsRule mPermissions = new AdoptShellPermissionsRule(
            InstrumentationRegistry.getInstrumentation().getUiAutomation(),
            Manifest.permission.CREATE_USERS, Manifest.permission.INTERACT_ACROSS_USERS,
            Manifest.permission.INTERACT_ACROSS_USERS_FULL);

    @Before
    public void setUpDir() throws Exception {
        mDir = Files.createTempDirectory(InstrumentationRegistry.getInstrumentation()
                .getContext().getCacheDir().toPath(), "service").toFile();
    }
}
