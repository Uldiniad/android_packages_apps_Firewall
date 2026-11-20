/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall.hostside.app;

import static com.android.compatibility.common.util.SystemUtil.runShellCommand;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.app.DownloadManager;
import android.database.Cursor;
import android.net.ConnectivityManager;
import android.net.DnsResolver;
import android.net.InetAddresses;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.Uri;
import android.os.SystemClock;

import com.android.compatibility.common.util.PollingCheck;

import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

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

    @Test
    public void downloadManagerLookupsFollowTheAppsDomainRules() throws Exception {
        DownloadManager dm = Firewall.context().getSystemService(DownloadManager.class);
        String url = "https://example.org/";
        assertEquals(DownloadManager.STATUS_SUCCESSFUL, download(dm, url, 30_000));
        String rule = "block domain example.org --package " + Firewall.PACKAGE + " --user "
                + Firewall.userId();
        runShellCommand("cmd firewall add-rule " + rule);
        try {
            // Java keeps answers for two seconds, in DownloadManager's process too.
            SystemClock.sleep(3_000);
            assertNotEquals(DownloadManager.STATUS_SUCCESSFUL, download(dm, url, 15_000));
        } finally {
            runShellCommand("cmd firewall remove-rule " + rule);
        }
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

    /** Runs the check with strict Private DNS, which encrypts every lookup, then restores it. */
    private static void withPrivateDns(Check check) throws Exception {
        String mode = runShellCommand("settings get global private_dns_mode").trim();
        String host = runShellCommand("settings get global private_dns_specifier").trim();
        try {
            runShellCommand("settings put global private_dns_specifier dns.google");
            runShellCommand("settings put global private_dns_mode hostname");
            // Strict mode never falls back to plain DNS, so an answer means encrypted DNS works.
            Firewall.awaitLookup("example.org", 30_000);
            check.run();
        } finally {
            restoreSetting("private_dns_mode", mode);
            restoreSetting("private_dns_specifier", host);
        }
    }

    /** Runs the check with Private DNS off, so lookups go out as plain DNS, then restores it. */
    private static void withPlainDns(Check check) throws Exception {
        String mode = runShellCommand("settings get global private_dns_mode").trim();
        ConnectivityManager cm = Firewall.context().getSystemService(ConnectivityManager.class);
        try {
            runShellCommand("settings put global private_dns_mode off");
            PollingCheck.waitFor(10_000, () -> {
                LinkProperties lp = cm.getLinkProperties(cm.getActiveNetwork());
                return lp != null && !lp.isPrivateDnsActive();
            }, "Private DNS stayed on");
            check.run();
        } finally {
            restoreSetting("private_dns_mode", mode);
        }
    }

    private interface Check {
        void run() throws Exception;
    }

    @Test
    public void appsWithDomainRulesStillLookNamesUpOverPlainDns() throws Exception {
        String rule = "block domain example.com --package " + Firewall.PACKAGE + " --user "
                + Firewall.userId();
        withPlainDns(() -> {
            runShellCommand("cmd firewall add-rule " + rule);
            try {
                assertTrue(Firewall.looksUp("example.org", 15_000));
            } finally {
                runShellCommand("cmd firewall remove-rule " + rule);
            }
        });
    }

    @Test
    public void blockedAppsLookTheirAllowedDomainsUpOverPlainDns() throws Exception {
        String rule = "allow domain example.com --package " + Firewall.PACKAGE + " --user "
                + Firewall.userId();
        withPlainDns(() -> {
            runShellCommand("cmd firewall add-rule " + rule);
            try {
                Firewall.setRules("all");
                assertTrue(Firewall.looksUp("example.com", 15_000));
                assertFalse(Firewall.looksUp("example.net", 15_000));
            } finally {
                runShellCommand("cmd firewall remove-rule " + rule);
            }
        });
    }

    @Test
    public void blockedDomainsFailLookupsEvenOverPrivateDns() throws Exception {
        String rule = "block domain example.com --user " + Firewall.userId();
        withPrivateDns(() -> {
            runShellCommand("cmd firewall add-rule " + rule);
            try {
                InetAddress.getByName("www.example.com");
                fail("Looked up a blocked domain over Private DNS");
            } catch (UnknownHostException expected) {
            } finally {
                runShellCommand("cmd firewall remove-rule " + rule);
            }
        });
    }

    @Test
    public void knownDohServersAreRefusedWhileDomainRulesApply() throws Exception {
        String rule = "block domain example.com --package " + Firewall.PACKAGE + " --user "
                + Firewall.userId();
        assertTrue(Firewall.tcpConnects("1.1.1.1", 443));
        runShellCommand("cmd firewall add-rule " + rule);
        try {
            assertFalse("DNS over HTTPS", Firewall.tcpConnects("1.1.1.1", 443));
            try {
                InetAddress.getByName("dns.google");
                fail("Looked up a DNS-over-HTTPS server");
            } catch (UnknownHostException expected) {
            }
            Firewall.awaitLookup("example.org", 10_000);
        } finally {
            runShellCommand("cmd firewall remove-rule " + rule);
        }
        assertTrue(Firewall.tcpConnects("1.1.1.1", 443));
    }

    @Test
    public void anAppsOwnDnsIsRefusedWhileDomainRulesApplyToIt() throws Exception {
        InetAddress dns = InetAddresses.parseNumericAddress("9.9.9.9");
        String rule = "block domain example.com --package " + Firewall.PACKAGE + " --user "
                + Firewall.userId();
        assertTrue(Firewall.udpSends(dns, 53));
        assertTrue(Firewall.tcpConnects("9.9.9.9", 853));
        runShellCommand("cmd firewall add-rule " + rule);
        try {
            // Android's resolver checks the rule, so the app looks names up there instead.
            assertFalse(Firewall.udpSends(dns, 53));
            assertFalse("DNS over TLS", Firewall.tcpConnects("9.9.9.9", 853));
            Firewall.awaitLookup("example.org", 10_000);
        } finally {
            runShellCommand("cmd firewall remove-rule " + rule);
        }
        assertTrue(Firewall.udpSends(dns, 53));
    }

    @Test
    public void allowRulesLetABlockedAppReachOnlyTheirDomains() throws Exception {
        String rule = "allow domain example.com --package " + Firewall.PACKAGE + " --user "
                + Firewall.userId();
        withPrivateDns(() -> {
            runShellCommand("cmd firewall add-rule " + rule);
            try {
                Firewall.setRules("all");
                // The firewall saw the decrypted answer before the app did, so even the first
                // connection to it goes through.
                String allowed = null;
                for (InetAddress address : InetAddress.getAllByName("example.com")) {
                    if (address instanceof Inet4Address) allowed = address.getHostAddress();
                }
                assertNotNull("No IPv4 address for example.com", allowed);
                // Android's own lookup API too, which first checks which address families work.
                assertFalse("DnsResolver found no address for example.com",
                        resolverQuery("example.com").isEmpty());
                assertTrue(Firewall.tcpConnects(allowed, 443));
                assertFalse(Firewall.tcpConnects("1.1.1.1", 443));
                try {
                    InetAddress.getByName("example.net");
                    fail("Looked up a domain no rule allows");
                } catch (UnknownHostException expected) {
                }
            } finally {
                runShellCommand("cmd firewall remove-rule " + rule);
            }
        });
    }

    /** Looks the name up for both address families through Android's DnsResolver. */
    private static List<InetAddress> resolverQuery(String name) throws Exception {
        CompletableFuture<List<InetAddress>> answer = new CompletableFuture<>();
        DnsResolver.getInstance().query(null, name, DnsResolver.FLAG_EMPTY, Runnable::run, null,
                new DnsResolver.Callback<List<InetAddress>>() {
                    @Override
                    public void onAnswer(List<InetAddress> addresses, int rcode) {
                        answer.complete(addresses);
                    }

                    @Override
                    public void onError(DnsResolver.DnsException e) {
                        answer.completeExceptionally(e);
                    }
                });
        return answer.get(10, TimeUnit.SECONDS);
    }

    private static void restoreSetting(String name, String value) throws IOException {
        runShellCommand("null".equals(value) ? "settings delete global " + name
                : "settings put global " + name + " " + value);
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
