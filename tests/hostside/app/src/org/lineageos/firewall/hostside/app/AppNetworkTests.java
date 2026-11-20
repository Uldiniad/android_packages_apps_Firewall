/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall.hostside.app;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.app.DownloadManager;
import android.database.Cursor;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.Uri;
import android.os.SystemClock;

import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;

/** What an app sees when the firewall blocks it. */
public class AppNetworkTests {
    @Before
    public void setUp() throws Exception {
        Firewall.setRules("none");
    }

    @After
    public void tearDown() throws Exception {
        Firewall.setRules("none");
    }

    @Test
    public void allowedByDefault() throws Exception {
        assertTrue(Firewall.tcpConnects("1.1.1.1", 443));
        InetAddress.getByName("example.com");
    }

    @Test
    public void blockAllReportsBlockedRefusesAndFailsDnsCleanly() throws Exception {
        Firewall.setRules("all");
        assertTrue("Not reported blocked", Firewall.waitForBlocked(true, 10_000));
        assertFalse(Firewall.tcpConnects("1.1.1.1", 443));
        // Java keeps answers for two seconds, so an earlier test's would come back here.
        SystemClock.sleep(3_000);
        try {
            InetAddress.getByName("example.org");
            fail("DNS answered while blocked");
        } catch (UnknownHostException expected) {
            // A SecurityException instead would crash apps that don't expect it.
        }
    }

    @Test
    public void openSocketIsClosedWhenBlocked() throws Exception {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("1.1.1.1", 443), 5000);
            Firewall.setRules("all");
            socket.setSoTimeout(15_000);
            try {
                int read = socket.getInputStream().read();
                fail("Socket stayed open and read " + read);
            } catch (SocketTimeoutException e) {
                fail("Socket was not closed");
            } catch (IOException expected) {
            }
        }
    }

    @Test
    public void downloadManagerDoesNotDownloadForABlockedApp() throws Exception {
        DownloadManager dm = Firewall.context().getSystemService(DownloadManager.class);
        assertEquals(DownloadManager.STATUS_SUCCESSFUL, download(dm, 30_000));
        Firewall.setRules("all");
        assertNotEquals(DownloadManager.STATUS_SUCCESSFUL, download(dm, 15_000));
    }

    private static int download(DownloadManager dm, long waitMs) {
        return download(dm, "https://1.1.1.1/", waitMs);
    }

    private static int download(DownloadManager dm, String url, long waitMs) {
        long id = dm.enqueue(new DownloadManager.Request(Uri.parse(url))
                .setDestinationInExternalFilesDir(Firewall.context(), null, "probe"));
        int status = 0;
        long deadline = SystemClock.elapsedRealtime() + waitMs;
        while (SystemClock.elapsedRealtime() < deadline) {
            try (Cursor c = dm.query(new DownloadManager.Query().setFilterById(id))) {
                if (c.moveToFirst()) status = c.getInt(c.getColumnIndexOrThrow(
                        DownloadManager.COLUMN_STATUS));
            }
            if (status == DownloadManager.STATUS_SUCCESSFUL
                    || status == DownloadManager.STATUS_FAILED) break;
            SystemClock.sleep(500);
        }
        dm.remove(id);
        return status;
    }

    private interface Check {
        void run() throws Exception;
    }

    @Test
    public void transportRuleBlocksWhenNoAllowedNetworkIsLeft() throws Exception {
        ConnectivityManager cm = Firewall.context().getSystemService(ConnectivityManager.class);
        boolean wifiOnly = true;
        for (Network network : cm.getAllNetworks()) {
            NetworkCapabilities nc = cm.getNetworkCapabilities(network);
            if (nc != null && !nc.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                wifiOnly = false;
            }
        }
        Assume.assumeTrue("Needs Wi-Fi as the only network", wifiOnly);

        Firewall.setRules("wifi");
        assertTrue("Not reported blocked", Firewall.waitForBlocked(true, 10_000));
        assertFalse(Firewall.tcpConnects("1.1.1.1", 443));
        Firewall.setRules("mobile");
        assertTrue("Still reported blocked", Firewall.waitForBlocked(false, 10_000));
        assertTrue(Firewall.tcpConnects("1.1.1.1", 443));
    }
}
