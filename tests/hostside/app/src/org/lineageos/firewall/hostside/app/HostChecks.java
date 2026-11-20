/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall.hostside.app;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import android.os.UserHandle;
import android.os.UserManager;

import androidx.test.platform.app.InstrumentationRegistry;

import com.android.compatibility.common.util.PollingCheck;
import com.android.compatibility.common.util.SystemUtil;

import org.junit.Test;

/** Checks the host runs after changing state it controls, like rebooting or adding a user. */
public class HostChecks {
    @Test
    public void blocked() throws Exception {
        assertTrue("Not reported blocked", Firewall.waitForBlocked(true, 15_000));
        assertFalse(Firewall.tcpConnects("1.1.1.1", 443));
    }

    /**
     * Turns on quiet mode for the profile the "profile" argument names, as pausing work apps or
     * locking private space does.
     */
    @Test
    public void enableQuietMode() throws Exception {
        setQuietMode(true);
    }

    @Test
    public void disableQuietMode() throws Exception {
        setQuietMode(false);
    }

    private static void setQuietMode(boolean enabled) {
        int user = Integer.parseInt(InstrumentationRegistry.getArguments().getString("profile"));
        UserHandle profile = UserHandle.of(user);
        UserManager users = Firewall.context().getSystemService(UserManager.class);
        SystemUtil.runWithShellPermissionIdentity(() -> {
            users.requestQuietModeEnabled(enabled, profile);
            PollingCheck.waitFor(30_000, () -> users.isQuietModeEnabled(profile) == enabled,
                    "Quiet mode never changed");
        }, "android.permission.MODIFY_QUIET_MODE");
    }

    @Test
    public void allowed() throws Exception {
        assertTrue("No usable network", Firewall.waitForUsableNetwork(30_000));
        assertTrue(Firewall.tcpConnects("1.1.1.1", 443));
    }
}
