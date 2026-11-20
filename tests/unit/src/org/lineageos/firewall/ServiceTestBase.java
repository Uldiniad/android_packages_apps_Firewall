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
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;

/** Runs the service against this test app's own package, with fake maps and Connectivity. */
public abstract class ServiceTestBase {
    static final String PACKAGE = "org.lineageos.firewall.tests";
    static final String NO_INTERNET_PACKAGE = "org.lineageos.firewall.hostside.nointernet";
    static final int UID = Process.myUid();

    final ConnectivityManager mConnectivity = mock(ConnectivityManager.class);
    final FakeMaps mMaps = new FakeMaps();
    final TestClock mClock = new TestClock(monday(10, 0));
    File mDir;

    static FirewallRule rule(String packageName, boolean allow, int kind, String value) {
        FirewallRule rule = new FirewallRule();
        rule.packageName = packageName;
        rule.allow = allow;
        rule.kind = kind;
        rule.value = value;
        rule.subdomains = true;
        return rule;
    }

    static FirewallRule[] rules(FirewallRule... rules) {
        return rules;
    }

    /** A clock the tests move, as time can't be waited out here. */
    static final class TestClock extends Clock {
        Instant now;

        TestClock(Instant now) {
            this.now = now;
        }

        @Override
        public ZoneId getZone() {
            return ZoneId.systemDefault();
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    /** Monday 16 November 2026 at the time, in the device's time zone. */
    static Instant monday(int hour, int minute) {
        return LocalDate.of(2026, 11, 16).atTime(hour, minute).atZone(ZoneId.systemDefault())
                .toInstant();
    }

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
                // Alarms are the clock's to drive here, through onTime().
                if (Context.ALARM_SERVICE.equals(name)) return null;
                return Context.CONNECTIVITY_SERVICE.equals(name)
                        ? mConnectivity : super.getSystemService(name);
            }
        };
    }

    FirewallService start() {
        FirewallService service = new FirewallService(context(), mMaps, mDir, mClock);
        service.init();
        return service;
    }

    /** A service over the test's directory that isn't started, to set up or read its store. */
    FirewallService unstarted() {
        return new FirewallService(context(), new FakeMaps(), mDir, mClock);
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
        FirewallService reader = new FirewallService(context(), new FakeMaps(), copy, mClock);
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

    // Listing every user's apps needs these; adopting all of shell's would also grant this app
    // ACCESS_LOCAL_NETWORK.
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
