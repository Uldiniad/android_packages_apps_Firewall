/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall.hostside;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
import com.android.tradefed.testtype.junit4.DeviceTestRunOptions;

import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Runs the helper app's checks, and the ones that need the host: reboots and other users. */
@RunWith(DeviceJUnit4ClassRunner.class)
public class FirewallHostsideTests extends BaseHostJUnit4Test {
    private static final String PACKAGE = "org.lineageos.firewall.hostside.app";
    private static final String NO_INTERNET_PACKAGE = "org.lineageos.firewall.hostside.nointernet";
    private static final String HTTPS_RULE =
            "block port 443 --tcp --package " + PACKAGE + " --user 0";
    private static final String FIREWALL_APP = "org.lineageos.firewall";
    private static final String LOCAL_NETWORK = "android.permission.ACCESS_LOCAL_NETWORK";
    private static final String APP_TESTS = "org.lineageos.firewall.app.tests";
    private static final String NO_INTERNET_APK = "FirewallNoInternetTestApp.apk";
    private static final String NO_INTERNET_UPDATE_APK = "FirewallNoInternetUpdateTestApp.apk";
    private static final String LOCAL_TRANSPORT = "com.android.localtransport/.LocalTransport";
    private static final String WORK_PROFILE = "--managed";
    private static final String CLONE_PROFILE = "--user-type android.os.usertype.profile.CLONE";
    private static final String PRIVATE_PROFILE =
            "--user-type android.os.usertype.profile.PRIVATE";
    private static final String ADOPTABLE_DISKS = "sm list-disks adoptable";

    private String shell(String command) throws Exception {
        return getDevice().executeShellCommand(command);
    }

    private void setRules(String rules, int user) throws Exception {
        shell("cmd firewall set-app " + PACKAGE + " " + rules + " --user " + user);
    }

    private String getRules(int user) throws Exception {
        return getRules(PACKAGE, user);
    }

    private String getRules(String packageName, int user) throws Exception {
        return shell("cmd firewall get-app " + packageName + " --user " + user).trim();
    }

    private boolean run(String className, String method, int user) throws Exception {
        return runDeviceTests(options(className, method, user));
    }

    /** As run, but false rather than a failure when the device test fails, for polling. */
    private boolean passes(String className, String method, int user) throws Exception {
        return runDeviceTests(options(className, method, user).setCheckResults(false));
    }

    private DeviceTestRunOptions options(String className, String method, int user) {
        DeviceTestRunOptions options = new DeviceTestRunOptions(PACKAGE)
                .setTestClassName(PACKAGE + "." + className)
                .setUserId(user);
        if (method != null) options.setTestMethodName(method);
        return options;
    }

    /** Pauses a work profile or locks private space through Android's quiet mode, or undoes it. */
    private boolean setQuietMode(int profile, boolean enabled) throws Exception {
        return runDeviceTests(options("HostChecks", enabled ? "enableQuietMode"
                : "disableQuietMode", 0).addInstrumentationArg("profile",
                Integer.toString(profile)));
    }

    /** Waits for a change with no event to wait for here; fails with the message after the time. */
    private static void waitUntil(String failure, long timeoutMillis, Callable<Boolean> done)
            throws Exception {
        long deadline = System.currentTimeMillis() + timeoutMillis;
        while (!done.call()) {
            assertTrue(failure, System.currentTimeMillis() < deadline);
            Thread.sleep(500);
        }
    }

    /** Restarts Android's framework, running the commands while it's down, as a boot would. */
    private void restartFramework(String... whileStopped) throws Exception {
        shell("stop");
        for (String command : whileStopped) shell(command);
        // Cleared so the wait is for this start.
        shell("setprop sys.boot_completed 0");
        shell("setprop dev.bootcomplete 0");
        shell("start");
        getDevice().waitForDeviceAvailable();
    }

    /** Waits for the service to apply a package change, which reaches it by PackageMonitor. */
    private void awaitRules(String expected, String packageName, int user) throws Exception {
        waitUntil(packageName + " never got " + expected, 30_000,
                () -> expected.equals(getRules(packageName, user)));
    }

    private File testFile(String name) throws Exception {
        return getTestInformation().getDependencyFile(name, true);
    }

    /** Installs one of the test APKs over the one installed, for every user. */
    private void install(String apk, String... options) throws Exception {
        assertNull(getDevice().installPackage(testFile(apk), true, options));
    }

    /** The adopted card's volume, as its id, state and uuid, once it's mounted; else null. */
    private String adoptedVolume() throws Exception {
        for (String line : shell("sm list-volumes private").split("\n")) {
            if (line.startsWith("private:") && line.contains(" mounted ")) return line.trim();
        }
        return null;
    }

    private long connectDenials() throws Exception {
        return Long.parseLong(shell("dumpsys firewall")
                .replaceAll("(?s).*\\bconnect_deny (\\d+).*", "$1"));
    }

    /** Whether the device is on Wi-Fi. */
    private boolean onWifi() throws Exception {
        return shell("cmd wifi status").contains("Wifi is connected to");
    }

    /** The key of the Wi-Fi network the device is on, from the firewall's list; null if none. */
    private String connectedWifi() throws Exception {
        for (String line : shell("cmd firewall list-networks").split("\n")) {
            int connected = line.indexOf(" (connected)");
            if (line.startsWith("wifi:") && connected > 0) return line.substring(0, connected);
        }
        return null;
    }

    /** Adds a profile of the device's first user, like a work profile; returns its id. */
    private int createProfile(String type, String name) throws Exception {
        String created = shell("pm create-user --profileOf 0 " + type + " " + name);
        assertTrue("No profile: " + created, created.matches("(?s).*created user id \\d+.*"));
        return Integer.parseInt(created.replaceAll("(?s).*created user id (\\d+).*", "$1"));
    }

    private int uidOf(String packageName, int user) throws Exception {
        return Integer.parseInt(shell("pm list packages -U --user " + user + " " + packageName)
                .replaceAll("(?s).*uid:([0-9]+).*", "$1"));
    }

    /** The rules the service has written to the BPF maps for the uid, or 0 for none. */
    private int rulesInMap(int uid) throws Exception {
        String map = shell("dumpsys firewall")
                .replaceAll("(?s).*UIDs in map: \\{([^}]*)}.*", "$1");
        for (String entry : map.split(", ")) {
            String[] parts = entry.split("=");
            if (parts[0].equals(Integer.toString(uid))) return Integer.parseInt(parts[1]);
        }
        return 0;
    }

    /** Quotes an argument for the device's shell, as SSIDs can hold anything. */
    private static String quote(String argument) {
        return "'" + argument.replace("'", "'\\''") + "'";
    }

    @After
    public void tearDown() throws Exception {
        setRules("none", 0);
    }

    @Test
    public void aChoiceForTheWifiNetworkWinsOverTheWifiSwitch() throws Exception {
        String wifi = connectedWifi();
        assumeTrue("Needs Wi-Fi", wifi != null);
        String network = "cmd firewall set-network " + PACKAGE + " " + quote(wifi);
        try {
            shell(network + " block");
            assertTrue(run("HostChecks", "blocked", 0));
            setRules("wifi", 0);
            shell(network + " allow");
            assertTrue(run("HostChecks", "allowed", 0));
        } finally {
            shell(network + " default");
        }
    }

    @Test
    public void rulesLimitedToANetworkApplyOnlyThere() throws Exception {
        String wifi = connectedWifi();
        assumeTrue("Needs Wi-Fi", wifi != null);
        String rule = "block address 1.1.1.1 --package " + PACKAGE;
        for (String networks : new String[] {"--on mobile", "--except " + quote(wifi)}) {
            shell("cmd firewall add-rule " + rule + " " + networks);
            try {
                assertTrue(networks, run("HostChecks", "allowed", 0));
            } finally {
                shell("cmd firewall remove-rule " + rule + " " + networks);
            }
        }
        for (String networks : new String[] {"--on wifi", "--on " + quote(wifi)}) {
            shell("cmd firewall add-rule " + rule + " " + networks);
            try {
                assertTrue(networks, run("HostChecks", "refused", 0));
            } finally {
                shell("cmd firewall remove-rule " + rule + " " + networks);
            }
        }
    }

    @Test
    public void refusalsAreListedWithTheAppReasonAndFarEnd() throws Exception {
        // A far end no other test refuses: one far end's refusals are reported once a minute.
        String address = "192.0.2.1";
        String rule = "block address " + address + " --package " + PACKAGE;
        shell("cmd firewall add-rule " + rule);
        try {
            assertTrue(runDeviceTests(options("HostChecks", "refused", 0)
                    .addInstrumentationArg("address", address)));
            Pattern listed = Pattern.compile(
                    Pattern.quote(PACKAGE + " user 0, connect tcp " + address + ":443 refused ")
                            + "(once|\\d+ times): address");
            waitUntil("The refusal was not listed", 10_000,
                    () -> listed.matcher(shell("dumpsys firewall")).find());
        } finally {
            shell("cmd firewall remove-rule " + rule);
        }
    }

    private boolean connects(String check, String address, int port) throws Exception {
        return runDeviceTests(options("HostChecks", check, 0)
                .addInstrumentationArg("address", address)
                .addInstrumentationArg("port", Integer.toString(port)));
    }

    // A rule's port is a limit the service numbers and the BPF programs look up apart, and the
    // answers of a domain blocked on a port are learned for it, so this checks they meet.
    @Test
    public void rulesWithAPortRefuseOnlyAtThatPort() throws Exception {
        // A far end no other test refuses: one far end's refusals are reported once a minute.
        String address = "192.0.2.5";
        String rule = "block address " + address + " --port 443 --tcp --package " + PACKAGE;
        shell("cmd firewall add-rule " + rule);
        try {
            assertTrue(connects("refused", address, 443));
            Pattern listed = Pattern.compile(
                    Pattern.quote(PACKAGE + " user 0, connect tcp " + address + ":443 refused ")
                            + "(once|\\d+ times): address");
            waitUntil("The refusal was not listed", 10_000,
                    () -> listed.matcher(shell("dumpsys firewall")).find());
            assertTrue(connects("refused", address, 80));
            assertFalse(shell("dumpsys firewall").contains(address + ":80 refused"));
        } finally {
            shell("cmd firewall remove-rule " + rule);
        }

        // A domain blocked on a port still resolves, and only that port is refused.
        String domain = "block domain example.org --exact --port 443 --tcp --package " + PACKAGE;
        shell("cmd firewall add-rule " + domain);
        try {
            assertTrue(looksUp("example.org"));
            assertTrue(connects("refused", "example.org", 443));
            assertTrue(connects("allowed", "example.org", 80));
        } finally {
            shell("cmd firewall remove-rule " + domain);
        }
    }

    /** The phone's Wi-Fi IPv4 address, or null without one. */
    private String wifiAddress() throws Exception {
        Matcher inet = Pattern.compile("inet (\\d+\\.\\d+\\.\\d+\\.\\d+)/")
                .matcher(shell("ip -4 -o addr show wlan0"));
        return inet.find() ? inet.group(1) : null;
    }

    /**
     * Runs the app's server at the port while this host keeps connecting to it over Wi-Fi; whether
     * the host reached it, or with reached false didn't, as wanted.
     */
    private boolean served(String phone, int port, boolean reached) throws Exception {
        AtomicBoolean done = new AtomicBoolean();
        Thread client = new Thread(() -> {
            while (!done.get()) {
                try (Socket socket = new Socket()) {
                    socket.connect(new InetSocketAddress(phone, port), 1000);
                    Thread.sleep(200);
                } catch (IOException | InterruptedException e) {
                    // The server isn't up yet, or the firewall drops the handshake.
                }
            }
        });
        client.start();
        try {
            return runDeviceTests(options("HostChecks", reached ? "reached" : "notReached", 0)
                    .addInstrumentationArg("port", Integer.toString(port))
                    .setCheckResults(false));
        } finally {
            done.set(true);
            client.join();
        }
    }

    // The service writes the rules in the app's incoming scope, and the BPF programs check what
    // arrives from this host.
    @Test
    public void incomingRulesDecideWhoReachesTheAppsServer() throws Exception {
        String phone = wifiAddress();
        assumeTrue("Needs Wi-Fi", phone != null);
        int port = 8080;
        // AOSP keeps apps without the permission off the LAN, where this host can be.
        shell("pm grant " + PACKAGE + " " + LOCAL_NETWORK);
        String block = "block incoming any --port " + port + " --tcp --package " + PACKAGE;
        String[] allow = {null};
        try {
            assumeTrue("The host can't reach the phone", served(phone, port, true));
            shell("cmd firewall add-rule " + block);
            assertTrue(served(phone, port, false));
            // The refusals name this host as the phone sees it; an allow rule for it wins.
            Pattern refused = Pattern.compile(Pattern.quote(PACKAGE + " user 0, incoming tcp ")
                    + "([0-9.]+):" + port + " refused");
            waitUntil("The refusal was not listed", 10_000, () -> {
                Matcher host = refused.matcher(shell("dumpsys firewall"));
                if (!host.find()) return false;
                allow[0] = "allow incoming " + host.group(1) + " --port " + port + " --tcp"
                        + " --package " + PACKAGE;
                return true;
            });
            shell("cmd firewall add-rule " + allow[0]);
            assertTrue(served(phone, port, true));
        } finally {
            if (allow[0] != null) shell("cmd firewall remove-rule " + allow[0]);
            shell("cmd firewall remove-rule " + block);
            shell("pm revoke " + PACKAGE + " " + LOCAL_NETWORK);
        }
    }

    private boolean looksUp(String host) throws Exception {
        return runDeviceTests(options("HostChecks", "looksUp", 0)
                .addInstrumentationArg("host", host).setCheckResults(false));
    }

    // The list is read by the service as the firewall app reads a download, and checked by netd and
    // the BPF programs, so this also checks that both find the names as the service keyed them.
    @Test
    public void anAppsListBlocksItsNamesThoseHiddenBehindThemAndItsAddresses() throws Exception {
        String file = "/data/local/tmp/firewall-hostside-list.txt";
        // dyna.wikimedia.org is what www.wikipedia.org points to; the far end is one no other test
        // refuses, as one far end's refusals are reported once a minute.
        shell("printf '%s\\n' example.org dyna.wikimedia.org 192.0.2.3 > " + file);
        String id = shell("cmd firewall add-list-file Hostside --exact --package " + PACKAGE
                + " --user 0 < " + file).trim();
        try {
            assertTrue("Not added: " + id, id.startsWith("file:"));
            assertFalse(looksUp("example.org"));
            assertFalse(looksUp("www.wikipedia.org"));
            assertTrue(looksUp("www.example.org"));
            assertTrue(runDeviceTests(options("HostChecks", "refused", 0)
                    .addInstrumentationArg("address", "192.0.2.3")));
            Pattern listed = Pattern.compile(
                    Pattern.quote(PACKAGE + " user 0, connect tcp 192.0.2.3:443 refused ")
                            + "(once|\\d+ times): list");
            waitUntil("The refusal was not listed", 10_000,
                    () -> listed.matcher(shell("dumpsys firewall")).find());

            // An allow rule wins over every list.
            String allow = "allow domain example.org --package " + PACKAGE;
            shell("cmd firewall add-rule " + allow);
            try {
                assertTrue(looksUp("example.org"));
            } finally {
                shell("cmd firewall remove-rule " + allow);
            }
        } finally {
            shell("cmd firewall remove-list " + id + " --package " + PACKAGE + " --user 0");
            shell("rm -f " + file);
        }
    }

    @Test
    public void appLevelBehavior() throws Exception {
        assertTrue(run("AppNetworkTests", null, 0));
    }

    @Test
    public void vpnBehavior() throws Exception {
        // Tradefed grants the helper app what it requests; the VPN's LAN test needs it without.
        shell("pm revoke " + PACKAGE + " " + LOCAL_NETWORK);
        assertTrue(run("VpnTests", null, 0));
    }

    @Test
    public void testNetworkBehavior() throws Exception {
        assertTrue(run("TestNetworkTests", null, 0));
    }

    @Test
    public void rulesSurviveAReboot() throws Exception {
        setRules("all", 0);
        getDevice().reboot();
        assertTrue(run("HostChecks", "blocked", 0));
        setRules("none", 0);
        assertTrue(run("HostChecks", "allowed", 0));
    }

    @Test
    public void pausesBlockAnAppForAWhile() throws Exception {
        shell("cmd firewall set-pause " + PACKAGE + " block 1");
        try {
            assertTrue(run("HostChecks", "blocked", 0));
            // The service's alarm ends it, once the end is moved closer.
            shell("cmd firewall set-pause " + PACKAGE + " block 5s");
            waitUntil("The pause never ended", 120_000, () -> passes("HostChecks", "allowed", 0));
        } finally {
            shell("cmd firewall set-pause " + PACKAGE + " none");
        }
    }

    @Test
    public void schedulesBlockAnAppInTheirWindow() throws Exception {
        String[] now = shell("date +%H:%M").trim().split(":");
        int minute = Integer.parseInt(now[0]) * 60 + Integer.parseInt(now[1]);
        String window = time(minute + 24 * 60 - 1) + " " + time(minute + 120);
        shell("cmd firewall set-schedule " + PACKAGE + " mon,tue,wed,thu,fri,sat,sun " + window);
        try {
            assertTrue(run("HostChecks", "blocked", 0));
        } finally {
            shell("cmd firewall set-schedule " + PACKAGE + " none");
        }
        assertTrue(run("HostChecks", "allowed", 0));
    }

    private static String time(int minute) {
        return String.format("%02d:%02d", minute / 60 % 24, minute % 60);
    }

    /**
     * Starts the framework as an upgrade from a build with Lineage's old firewall leaves the
     * phone: the uid's bits in NPMS's binary file, which lists uid policies after the
     * policy-list element and before the allowlist, and no firewall file yet.
     */
    private void startAsUpgradedFromLineage(int uid, int policy) throws Exception {
        String policies = "/data/local/tmp/netpolicy.xml";
        try {
            shell("abx2xml /data/system/netpolicy.xml " + policies);
            String text = shell("cat " + policies);
            assertTrue(text.contains("<whitelist"));
            String old = "<uid-policy uid=\"" + uid + "\" policy=\"" + policy + "\" />";
            assertTrue(getDevice().pushString(text.replace("<whitelist", old + "<whitelist"),
                    policies));
            shell("xml2abx " + policies + " " + policies + ".abx");
            restartFramework("cat " + policies + ".abx > /data/system/netpolicy.xml",
                    "rm /data/system/firewall.xml");
        } finally {
            shell("rm -f " + policies + " " + policies + ".abx");
        }
    }

    @Test
    public void lineagesOldAppBlocksBecomeRules() throws Exception {
        String backup = "/data/local/tmp/firewall-upgrade.xml";
        int uid = uidOf(PACKAGE, 0);
        assertTrue(getDevice().pushString(shell("cmd firewall backup --user 0"), backup));
        try {
            startAsUpgradedFromLineage(uid, 0x8000 | 0x10000);
            assertEquals("wifi,mobile", getRules(0));
            // NPMS drops them as it reads the file.
            assertFalse(shell("dumpsys netpolicy").contains("UID=" + uid + " policy="));
        } finally {
            shell("cmd firewall restore --user 0 < " + backup);
            shell("rm -f " + backup);
        }
    }

    @Test
    public void lineagesBlocksOfAppsWithoutInternetActAsNewInstalls() throws Exception {
        String backup = "/data/local/tmp/firewall-upgrade.xml";
        assertTrue(getDevice().pushString(shell("cmd firewall backup --user 0"), backup));
        try {
            // Lineage blocked the app on its own, as it was installed without INTERNET.
            startAsUpgradedFromLineage(uidOf(NO_INTERNET_PACKAGE, 0), 0x40000);
            assertEquals("all", getRules(NO_INTERNET_PACKAGE, 0));
            install(NO_INTERNET_UPDATE_APK);
            shell("am wait-for-broadcast-idle");
            assertEquals("all", getRules(NO_INTERNET_PACKAGE, 0));
            waitUntil("The user was not notified", 10_000,
                    () -> blockedNoticePosted(NO_INTERNET_PACKAGE, 0));
        } finally {
            shell("cmd firewall restore --user 0 < " + backup);
            shell("rm -f " + backup);
            install(NO_INTERNET_APK);
        }
    }

    @Test
    public void theFirewallSaysWhenItIsNotRunning() throws Exception {
        setRules("wifi", 0);
        try {
            // As when the loader skips the firewall's programs, the service starts without them.
            restartFramework("rm /sys/fs/bpf/firewall/map_firewall_uid_rules");
            assertTrue(shell("dumpsys firewall").contains("Maps: missing"));
            // The firewall app's notification, keyed user|package|id|tag|uid.
            String posted = "0|" + FIREWALL_APP + "|2|not_running|";
            waitUntil("The user was not warned", 60_000,
                    () -> shell("dumpsys notification --noredact").contains(posted));
            assertTrue(runDeviceTests(new DeviceTestRunOptions(APP_TESTS)
                    .setTestClassName(FIREWALL_APP + ".FirewallAppTest")
                    .setTestMethodName("homePageWarnsWhileTheFirewallIsNotRunning")));
        } finally {
            // The loader pins the maps again at boot.
            getDevice().reboot();
            setRules("none", 0);
        }
    }

    @Test
    public void rulesArePerUserAndGoWithTheUser() throws Exception {
        int user = getDevice().createUser("fwhosttest");
        try {
            assertTrue(getDevice().startUser(user, true));
            shell("pm install-existing --user " + user + " " + PACKAGE);
            setRules("all", user);
            assertTrue(run("HostChecks", "blocked", user));
            assertTrue(run("HostChecks", "allowed", 0));
        } finally {
            // --wait returns once the removal is done, so the user-removed broadcast is sent.
            shell("pm remove-user --wait " + user);
        }
        // The service drops the user's rules when that broadcast arrives.
        shell("am wait-for-broadcast-idle");
        assertEquals("none", getRules(user));
    }

    @Test
    public void appsInstalledWhileTheirUserIsStoppedAreKeptOffTheLan() throws Exception {
        int user = getDevice().createUser("fwstopped");
        try {
            // Installed while its user is stopped, which Android's package broadcasts skip.
            shell("pm install-existing --user " + user + " " + PACKAGE);
            assertTrue(getDevice().startUser(user, true));
            shell("am wait-for-broadcast-idle");
            int uid = Integer.parseInt(shell("pm list packages -U --user " + user + " " + PACKAGE)
                    .replaceAll("(?s).*uid:([0-9]+).*", "$1"));
            // The helper app doesn't hold ACCESS_LOCAL_NETWORK there, so it gets the NO_LAN bit.
            assertTrue(shell("dumpsys firewall").matches("(?s).*UIDs in map: \\{.*\\b" + uid
                    + "=64\\b.*"));
        } finally {
            shell("pm remove-user --wait " + user);
        }
    }

    @Test
    public void rulesGoWithTheAppOnUninstall() throws Exception {
        // Uninstalling for one user keeps the APK for user 0, so it can come back without one.
        int user = getDevice().createUser("fwuninstall");
        try {
            // The user stays stopped, which Android's package broadcasts skip.
            shell("pm install-existing --user " + user + " " + PACKAGE);
            setRules("all", user);
            assertEquals("all", getRules(user));
            shell("pm uninstall --user " + user + " " + PACKAGE);
            awaitRules("none", PACKAGE, user);
            shell("pm install-existing --user " + user + " " + PACKAGE);
            assertEquals("none", getRules(user));
        } finally {
            shell("pm remove-user --wait " + user);
        }
    }

    @Test
    public void anAppInAGroupFollowsTheGroupsRules() throws Exception {
        setRules("wifi", 0);
        String id = shell("cmd firewall add-group Hostside").trim();
        try {
            shell("cmd firewall set-group " + PACKAGE + " " + id);
            // Its own block went, as a new group allows everything.
            assertTrue(run("HostChecks", "allowed", 0));
            shell("cmd firewall set-app group:" + id + " all");
            assertTrue(run("HostChecks", "blocked", 0));
            shell("cmd firewall set-group " + PACKAGE + " none");
            // It keeps a copy of the group's rules.
            assertEquals("all", getRules(0));
            assertTrue(run("HostChecks", "blocked", 0));
        } finally {
            shell("cmd firewall set-group " + PACKAGE + " none");
            shell("cmd firewall remove-group " + id);
            setRules("none", 0);
        }
    }

    @Test
    public void aGroupLosesAnUninstalledAppAndKeepsItsRules() throws Exception {
        // Uninstalling for one user keeps the APK for user 0, as for the app's own rules.
        int user = getDevice().createUser("fwgroups");
        try {
            shell("pm install-existing --user " + user + " " + PACKAGE);
            String id = shell("cmd firewall add-group Hostside --user " + user).trim();
            shell("cmd firewall set-app group:" + id + " all --user " + user);
            shell("cmd firewall set-group " + PACKAGE + " " + id + " --user " + user);
            assertEquals(1, rulesInMap(uidOf(PACKAGE, user)) & 1);
            shell("pm uninstall --user " + user + " " + PACKAGE);
            waitUntil("The app stayed in its group", 30_000, () -> !shell(
                    "cmd firewall list-groups --user " + user).contains(PACKAGE));
            assertTrue(shell("cmd firewall list-groups --user " + user)
                    .startsWith(id + " Hostside"));
            assertEquals("all", getRules("group:" + id, user));
            shell("pm install-existing --user " + user + " " + PACKAGE);
            assertEquals("none", getRules(user));
        } finally {
            shell("pm remove-user --wait " + user);
        }
    }

    @Test
    public void theActivityLogShowsWhereAnAppWentOnWhichNetworkWithTheNameItLookedUp()
            throws Exception {
        String rule = " block address 9.9.9.9 --package " + PACKAGE;
        shell("cmd firewall set-activity-log on");
        shell("cmd firewall add-rule" + rule);
        try {
            assertTrue(runDeviceTests(options("HostChecks", "looksUp", 0)
                    .addInstrumentationArg("host", "one.one.one.one")));
            assertTrue(run("HostChecks", "allowed", 0));
            assertTrue(runDeviceTests(options("HostChecks", "refused", 0)
                    .addInstrumentationArg("address", "9.9.9.9")));
            String allowed = uidOf(PACKAGE, 0) + " allowed 1 6 1.1.1.1:443 one.one.one.one ";
            // Refused at connect, before a packet went out: its network is its socket's.
            String refused = uidOf(PACKAGE, 0) + " refused 0 6 9.9.9.9:443 null ";
            waitUntil("No entries " + allowed + "and " + refused, 10_000, () -> {
                String list = shell("cmd firewall list-activity");
                return list.contains(allowed) && list.contains(refused);
            });
            String list = shell("cmd firewall list-activity");
            String network = wordAfter(list, allowed);
            assertNotEquals("0", network);
            assertEquals(network, wordAfter(list, refused));
        } finally {
            shell("cmd firewall remove-rule" + rule);
            shell("cmd firewall set-activity-log off");
        }
    }

    /** The word that follows the text in the output. */
    private static String wordAfter(String output, String text) {
        String rest = output.substring(output.indexOf(text) + text.length());
        return rest.split("\\s+", 2)[0];
    }

    @Test
    public void tetheredDevicesLookUpNamesUnderTheRulesForAllApps() throws Exception {
        String rule = "block domain example.org";
        shell("cmd firewall add-rule " + rule);
        try {
            assertTrue(runDeviceTests(options("HostChecks", "tetheredLookups", 0)
                    .addInstrumentationArg("blocked", "www.example.org")
                    .addInstrumentationArg("allowed", "one.one.one.one")));
        } finally {
            shell("cmd firewall remove-rule " + rule);
        }
    }

    @Test
    public void tetheredDevicesTrafficFollowsTheRulesForAllApps() throws Exception {
        String rule = "block address 1.0.0.1";
        shell("cmd firewall add-rule " + rule);
        try {
            assertTrue(runDeviceTests(options("HostChecks", "tetheredTraffic", 0)
                    .addInstrumentationArg("blocked", "1.0.0.1")));
        } finally {
            shell("cmd firewall remove-rule " + rule);
        }
    }

    @Test
    public void theActivityLogShowsTheLookupsTheFirewallRefused() throws Exception {
        String rule = " block domain example.org --package " + PACKAGE;
        shell("cmd firewall set-activity-log on");
        shell("cmd firewall add-rule" + rule);
        try {
            assertFalse(passes("HostChecks", "looksUp", 0));
            String entry = uidOf(PACKAGE, 0) + " refused 4 0 null:0 example.org";
            waitUntil("No entry " + entry, 10_000,
                    () -> shell("cmd firewall list-activity").contains(entry));
        } finally {
            shell("cmd firewall remove-rule" + rule);
            shell("cmd firewall set-activity-log off");
        }
    }

    @Test
    public void activityFromBeforeTheUserUnlocksGoesIntoTheLog() throws Exception {
        String rule = " block address 9.9.9.9 --package " + PACKAGE;
        Pattern waiting = Pattern.compile("user 0: \\d+ entries waiting for the firewall app");
        shell("cmd firewall set-activity-log on");
        shell("cmd firewall add-rule" + rule);
        try {
            // A stopped app gets no broadcasts, so the refusal waits in the service, as activity
            // does until the user unlocks after a boot.
            shell("am force-stop " + FIREWALL_APP);
            assertTrue(runDeviceTests(options("HostChecks", "refused", 0)
                    .addInstrumentationArg("address", "9.9.9.9")));
            waitUntil("Nothing waits for the firewall app", 10_000,
                    () -> waiting.matcher(shell("dumpsys firewall")).find());
            shell("logcat -b crash -c");
            // am returns once the app has finished with the broadcast.
            shell("am broadcast --include-stopped-packages -a android.intent.action.BOOT_COMPLETED"
                    + " -n " + FIREWALL_APP + "/.BootCompletedReceiver");
            assertFalse(waiting.matcher(shell("dumpsys firewall")).find());
            // A crash would come right after the app took the entries.
            Thread.sleep(5_000);
            assertFalse(shell("logcat -b crash -d").contains("Process: " + FIREWALL_APP + ","));
        } finally {
            shell("cmd firewall remove-rule" + rule);
            shell("cmd firewall set-activity-log off");
        }
    }

    @Test
    public void profilesKeepTheirCopyWithoutALauncherIcon() throws Exception {
        String launchers = "cmd package query-activities --brief -a android.intent.action.MAIN"
                + " -c android.intent.category.LAUNCHER --user ";
        assertTrue(shell(launchers + 0).contains(FIREWALL_APP + "/.LauncherEntry"));
        for (String type : new String[] {WORK_PROFILE, CLONE_PROFILE, PRIVATE_PROFILE}) {
            int profile = createProfile(type, "fwprofile");
            try {
                assertTrue(getDevice().startUser(profile, true));
                shell("am wait-for-broadcast-idle");
                // The personal profile's app shows the profile, as Settings does.
                assertFalse(type, shell(launchers + profile).contains(FIREWALL_APP));
                // Its own copy posts its notifications and backs up its rules.
                assertTrue(type, shell("pm list packages --user " + profile + " "
                        + FIREWALL_APP).contains(FIREWALL_APP));
            } finally {
                shell("pm remove-user --wait " + profile);
            }
        }
    }

    @Test
    public void cloneAppsBlockedAsNewNotifyTheUser() throws Exception {
        int clone = createProfile(CLONE_PROFILE, "fwclone");
        try {
            assertTrue(getDevice().startUser(clone, true));
            shell("cmd firewall set-new-installs blocked --user " + clone);
            shell("pm install-existing --user " + clone + " " + PACKAGE);
            awaitRules("all", PACKAGE, clone);
            assertTrue(run("HostChecks", "blocked", clone));
            // The firewall app's notification, keyed user|package|id|tag|uid.
            String posted = clone + "|" + FIREWALL_APP + "|1|" + PACKAGE + "|";
            waitUntil("The user was not notified", 10_000,
                    () -> shell("dumpsys notification --noredact").contains(posted));
        } finally {
            shell("pm remove-user --wait " + clone);
        }
    }

    @Test
    public void guestsFollowTheirOwnRules() throws Exception {
        int guest = getDevice().createUser("fwguest", true, false);
        try {
            assertTrue(getDevice().startUser(guest, true));
            assertTrue("Guests get the firewall app", shell("pm list packages --user " + guest
                    + " " + FIREWALL_APP).contains(FIREWALL_APP));
            shell("pm install-existing --user " + guest + " " + PACKAGE);
            setRules("all", guest);
            assertTrue(run("HostChecks", "blocked", guest));
            assertTrue(run("HostChecks", "allowed", 0));
        } finally {
            shell("pm remove-user --wait " + guest);
        }
        shell("am wait-for-broadcast-idle");
        assertEquals("none", getRules(guest));
    }

    @Test
    public void workProfileAndPrivateSpaceAppsFollowTheirRules() throws Exception {
        for (String type : new String[] {WORK_PROFILE, PRIVATE_PROFILE}) {
            int profile = createProfile(type, "fwprofile");
            try {
                assertTrue(getDevice().startUser(profile, true));
                shell("pm install-existing --user " + profile + " " + PACKAGE);
                setRules("all", profile);
                assertTrue(type, run("HostChecks", "blocked", profile));
                assertTrue(type, run("HostChecks", "allowed", 0));
                // A paused work profile or locked private space keeps its rules for its return.
                assertTrue(type, setQuietMode(profile, true));
                assertEquals(type, "all", getRules(profile));
                assertTrue(type, setQuietMode(profile, false));
                assertTrue(type, run("HostChecks", "blocked", profile));
            } finally {
                shell("pm remove-user --wait " + profile);
            }
        }
    }

    @Test
    public void cloneAppsFollowTheirOwnRules() throws Exception {
        int clone = createProfile(CLONE_PROFILE, "fwclone");
        try {
            assertTrue(getDevice().startUser(clone, true));
            shell("pm install-existing --user " + clone + " " + PACKAGE);
            setRules("all", clone);
            assertTrue(run("HostChecks", "blocked", clone));
            assertTrue(run("HostChecks", "allowed", 0));
        } finally {
            shell("pm remove-user --wait " + clone);
        }
    }

    @Test
    public void rulesHoldBeforeTheUserFirstUnlocks() throws Exception {
        int user = getDevice().createUser("fwlocked");
        try {
            assertTrue(getDevice().startUser(user, true));
            shell("pm install-existing --user " + user + " " + PACKAGE);
            shell("locksettings set-pin --user " + user + " 1234");
            setRules("all", user);
            getDevice().reboot();
            // Started without its PIN, the user's credential-encrypted storage stays locked.
            shell("am start-user " + user);
            waitUntil("The user never started", 60_000,
                    () -> shell("am get-started-user-state " + user).contains("RUNNING_LOCKED"));
            assertEquals(1, rulesInMap(uidOf(PACKAGE, user)) & 1);
        } finally {
            shell("pm remove-user --wait " + user);
        }
    }

    @Test
    public void appsUninstalledWithTheirDataKeptKeepTheirRules() throws Exception {
        int user = getDevice().createUser("fwkeepdata");
        try {
            assertTrue(getDevice().startUser(user, true));
            shell("pm install-existing --user " + user + " " + PACKAGE);
            setRules("all", user);
            // As Android keeps the app's data, the firewall keeps its rules.
            shell("pm uninstall -k --user " + user + " " + PACKAGE);
            shell("am wait-for-broadcast-idle");
            shell("pm install-existing --user " + user + " " + PACKAGE);
            assertEquals("all", getRules(user));
        } finally {
            shell("pm remove-user --wait " + user);
        }
    }

    @Test
    public void archivedAppsKeepTheirRules() throws Exception {
        // As CTS archives: the helper app is an installer that can bring the app back.
        install(NO_INTERNET_APK, "-i", PACKAGE);
        int user = getDevice().createUser("fwarchive");
        try {
            assertTrue(getDevice().startUser(user, true));
            shell("pm install-existing --user " + user + " " + PACKAGE);
            shell("pm install-existing --user " + user + " " + NO_INTERNET_PACKAGE);
            shell("cmd firewall set-app " + NO_INTERNET_PACKAGE + " wifi --user " + user);
            int uid = uidOf(NO_INTERNET_PACKAGE, user);
            assertEquals("Success",
                    shell("pm archive --user " + user + " " + NO_INTERNET_PACKAGE).trim());
            shell("am wait-for-broadcast-idle");
            // As Android keeps an archived app's data, the firewall keeps its rules.
            assertEquals("wifi", getRules(NO_INTERNET_PACKAGE, user));
            assertEquals(2, rulesInMap(uid) & 2);
            shell("pm install-existing --user " + user + " " + NO_INTERNET_PACKAGE);
            shell("am wait-for-broadcast-idle");
            assertEquals("wifi", getRules(NO_INTERNET_PACKAGE, user));
            assertEquals(2, rulesInMap(uid) & 2);
        } finally {
            shell("pm remove-user --wait " + user);
        }
    }

    @Test
    public void archivedAppsDontComeBackAsNewApps() throws Exception {
        // The no-internet app's update has INTERNET, so it starts without rules.
        install(NO_INTERNET_UPDATE_APK, "-i", PACKAGE);
        int user = getDevice().createUser("fwunarchive");
        try {
            assertTrue(getDevice().startUser(user, true));
            shell("pm install-existing --user " + user + " " + PACKAGE);
            shell("pm install-existing --user " + user + " " + NO_INTERNET_PACKAGE);
            shell("am wait-for-broadcast-idle");
            assertEquals("none", getRules(NO_INTERNET_PACKAGE, user));
            shell("cmd firewall set-new-installs blocked --user " + user);
            assertEquals("Success",
                    shell("pm archive --user " + user + " " + NO_INTERNET_PACKAGE).trim());
            shell("am wait-for-broadcast-idle");
            shell("pm install-existing --user " + user + " " + NO_INTERNET_PACKAGE);
            shell("am wait-for-broadcast-idle");
            assertEquals("none", getRules(NO_INTERNET_PACKAGE, user));
        } finally {
            shell("pm remove-user --wait " + user);
            install(NO_INTERNET_APK);
        }
    }

    @Test
    public void restoredRulesWaitForAnAppInstalledArchived() throws Exception {
        String backup = "/data/local/tmp/firewall-archived.xml";
        String metadata = "/data/local/tmp/firewall-archived.metadata";
        String apk = "/data/local/tmp/firewall-archived.apk";
        assertTrue(getDevice().pushFile(testFile(NO_INTERNET_APK), apk));
        int user = getDevice().createUser("fwrestorearchived");
        try {
            assertTrue(getDevice().startUser(user, true));
            shell("pm install-existing --user " + user + " " + PACKAGE);
            shell("cmd firewall set-app " + NO_INTERNET_PACKAGE + " wifi --user 0");
            assertTrue(getDevice().pushString(shell("cmd firewall backup --user 0"), backup));
            shell("pm get-archived-package-metadata --user 0 " + NO_INTERNET_PACKAGE + " > "
                    + metadata);
            // Only an app the device doesn't have can be installed archived.
            shell("pm uninstall " + NO_INTERNET_PACKAGE);
            shell("cmd firewall restore --user " + user + " < " + backup);
            // As a store restoring a phone does: the app comes archived, its APK when opened.
            String installer = " -t -i " + PACKAGE + " --user " + user + " ";
            assertEquals("Success", shell("pm install-archived" + installer + metadata).trim());
            shell("am wait-for-broadcast-idle");
            assertEquals("Success", shell("pm install -r" + installer + apk).trim());
            awaitRules("wifi", NO_INTERNET_PACKAGE, user);
        } finally {
            shell("pm remove-user --wait " + user);
            // Back as the suite installed it, new and so blocked for lacking INTERNET.
            shell("pm uninstall " + NO_INTERNET_PACKAGE);
            shell("pm install -t " + apk);
            shell("rm -f " + backup + " " + metadata + " " + apk);
        }
    }

    @Test
    public void appsOnAnAdoptedCardKeepTheirRulesWhileItsOut() throws Exception {
        assumeTrue("Needs adoptable storage",
                Boolean.parseBoolean(shell("sm has-adoptable").trim()));
        // A virtual card, as CTS's adoptable storage tests use.
        shell("sm set-virtual-disk true");
        String[] volume = null;
        try {
            waitUntil("No card", 30_000, () -> shell(ADOPTABLE_DISKS).startsWith("disk:"));
            shell("sm partition " + shell(ADOPTABLE_DISKS).trim() + " private");
            waitUntil("The card was not adopted", 60_000, () -> adoptedVolume() != null);
            volume = adoptedVolume().split(" ");
            assertTrue(shell("pm move-package " + PACKAGE + " " + volume[2]).contains("Success"));
            setRules("all", 0);
            shell("sm unmount " + volume[0]);
            shell("am wait-for-broadcast-idle");
            // Android keeps the app while its card is out, so the firewall keeps its rules.
            assertEquals("all", getRules(0));
            shell("sm mount " + volume[0]);
            waitUntil("The app did not come back", 60_000,
                    () -> shell("pm list instrumentation").contains(PACKAGE));
            shell("am wait-for-broadcast-idle");
            assertTrue(run("HostChecks", "blocked", 0));
        } finally {
            if (volume != null) {
                shell("sm mount " + volume[0]);
                waitUntil("The app did not come back", 60_000,
                        () -> shell("pm list instrumentation").contains(PACKAGE));
                shell("pm move-package " + PACKAGE + " internal");
            }
            String disk = shell(ADOPTABLE_DISKS).trim();
            if (disk.startsWith("disk:")) shell("sm partition " + disk + " public");
            if (volume != null) shell("sm forget " + volume[2]);
            shell("sm set-virtual-disk false");
        }
    }

    @Test
    public void appsTheUserCantRunKeepTheirRules() throws Exception {
        setRules("all", 0);
        int uid = uidOf(PACKAGE, 0);
        String[][] states = {{"disable-user", "enable"}, {"hide", "unhide"},
                {"suspend", "unsuspend"}};
        for (String[] state : states) {
            shell("pm " + state[0] + " --user 0 " + PACKAGE);
            try {
                shell("am wait-for-broadcast-idle");
                assertEquals(state[0], "all", getRules(0));
                assertEquals(state[0], 1, rulesInMap(uid) & 1);
            } finally {
                shell("pm " + state[1] + " --user 0 " + PACKAGE);
            }
        }
        assertTrue(run("HostChecks", "blocked", 0));
    }

    @Test
    public void backupsKeepNetworkChoicesAndLimits() throws Exception {
        String backup = "/data/local/tmp/firewall-networks.xml";
        String rule = "block domain example.test --package " + PACKAGE + " --on wifi";
        String network = "cmd firewall set-network " + PACKAGE + " vpn:" + PACKAGE;
        shell("cmd firewall add-rule " + rule);
        shell(network + " block");
        int user = getDevice().createUser("fwnetworks");
        try {
            assertTrue(getDevice().pushString(shell("cmd firewall backup --user 0"), backup));
            assertTrue(getDevice().startUser(user, true));
            shell("cmd firewall restore --user " + user + " < " + backup);
            shell("pm install-existing --user " + user + " " + PACKAGE);
            waitUntil("The restored rule never came", 30_000, () -> shell("cmd firewall list-rules"
                    + " --package " + PACKAGE + " --user " + user)
                    .contains("block domain example.test only on wifi"));
            assertTrue(shell("dumpsys firewall").contains("Networks for " + PACKAGE + " user "
                    + user + ": {vpn:" + PACKAGE + "=false}"));
        } finally {
            shell("pm remove-user --wait " + user);
            shell("rm -f " + backup);
            shell("cmd firewall remove-rule " + rule);
            shell(network + " default");
        }
    }

    @Test
    public void webAppFetchesCountAsTheRequestingApp() throws Exception {
        // Web app installs are refused unless this setting is on.
        String enabled = shell("settings get global enable_webapp_minter").trim();
        shell("settings put global enable_webapp_minter 1");
        shell("cmd firewall add-rule " + HTTPS_RULE);
        try {
            long before = connectDenials();
            assertTrue(run("DelegatedTraffic", "requestWebAppInstall", 0));
            assertTrue("The manifest fetch was not refused", connectDenials() > before);
        } finally {
            shell("cmd firewall remove-rule " + HTTPS_RULE);
            shell(enabled.equals("null") ? "settings delete global enable_webapp_minter"
                    : "settings put global enable_webapp_minter " + enabled);
        }
    }

    @Test
    public void pacProxyConnectionsCountAsTheRequestingApp() throws Exception {
        assumeTrue("Needs Wi-Fi", onWifi());
        // An address rule leaves the app its network: with none left, the app loses loopback too,
        // and with it the PAC file it serves and the local proxy.
        String rule = "block address 192.0.2.1 --package " + PACKAGE + " --user 0";
        shell("cmd firewall add-rule " + rule);
        try {
            long before = connectDenials();
            assertTrue(run("DelegatedTraffic", "requestThroughAPacProxy", 0));
            assertTrue("The proxied connection was not refused", connectDenials() > before);
        } finally {
            shell("cmd firewall remove-rule " + rule);
        }
    }

    @Test
    public void appLinkVerificationCountsAsTheApp() throws Exception {
        // A port rule refuses the fetch's connection but not its lookup, which since delegated
        // lookups is made as the app too, so the refusal lands where the counter sees it.
        shell("cmd firewall add-rule " + HTTPS_RULE);
        try {
            long before = connectDenials();
            shell("pm verify-app-links --re-verify " + PACKAGE);
            // Verification runs in the background and reports no event, so wait as CTS does.
            waitUntil("The verification fetch was not refused", 60_000,
                    () -> connectDenials() != before);
        } finally {
            shell("cmd firewall remove-rule " + HTTPS_RULE);
        }
    }

    @Test
    public void newInstallsGetTheirUsersDefaults() throws Exception {
        int user = getDevice().createUser("fwnewinstalls");
        try {
            // The user stays stopped, which Android's package broadcasts skip. The service hears
            // of installs in order, so once the second is in, the first is too.
            shell("pm install-existing --user " + user + " " + PACKAGE);
            shell("pm install-existing --user " + user + " " + NO_INTERNET_PACKAGE);
            // Without INTERNET it starts blocked, so an update adding it doesn't get network.
            awaitRules("all", NO_INTERNET_PACKAGE, user);
            assertEquals("none", getRules(PACKAGE, user));

            shell("pm uninstall --user " + user + " " + PACKAGE);
            shell("cmd firewall set-new-installs blocked --user " + user);
            shell("pm install-existing --user " + user + " " + PACKAGE);
            awaitRules("all", PACKAGE, user);
        } finally {
            shell("pm remove-user --wait " + user);
        }
    }

    @Test
    public void anUpdateAddingInternetLeavesANewAppBlocked() throws Exception {
        int user = getDevice().createUser("fwupdate");
        try {
            assertTrue(getDevice().startUser(user, true));
            shell("pm install-existing --user " + user + " " + NO_INTERNET_PACKAGE);
            awaitRules("all", NO_INTERNET_PACKAGE, user);
            shell("am wait-for-broadcast-idle");
            assertFalse("Notified of an app that can't use the network",
                    blockedNoticePosted(NO_INTERNET_PACKAGE, user));
            install(NO_INTERNET_UPDATE_APK);
            shell("am wait-for-broadcast-idle");
            assertTrue(shell("dumpsys package " + NO_INTERNET_PACKAGE)
                    .contains("android.permission.INTERNET: granted=true"));
            assertEquals("all", getRules(NO_INTERNET_PACKAGE, user));
            assertEquals(1, rulesInMap(uidOf(NO_INTERNET_PACKAGE, user)) & 1);
            waitUntil("The user was not notified", 10_000,
                    () -> blockedNoticePosted(NO_INTERNET_PACKAGE, user));
        } finally {
            shell("pm remove-user --wait " + user);
            install(NO_INTERNET_APK);
        }
    }

    @Test
    public void anUpdateDroppingInternetKeepsTheRulesForItsReturn() throws Exception {
        install(NO_INTERNET_UPDATE_APK);
        int user = getDevice().createUser("fwdropped");
        try {
            assertTrue(getDevice().startUser(user, true));
            shell("pm install-existing --user " + user + " " + NO_INTERNET_PACKAGE);
            shell("cmd firewall set-app " + NO_INTERNET_PACKAGE + " wifi --user " + user);
            int uid = uidOf(NO_INTERNET_PACKAGE, user);
            // Android refuses its sockets meanwhile; the firewall keeps the user's rules.
            install(NO_INTERNET_APK);
            shell("am wait-for-broadcast-idle");
            assertEquals("wifi", getRules(NO_INTERNET_PACKAGE, user));
            install(NO_INTERNET_UPDATE_APK);
            shell("am wait-for-broadcast-idle");
            assertEquals("wifi", getRules(NO_INTERNET_PACKAGE, user));
            assertEquals(2, rulesInMap(uid) & 2);
        } finally {
            shell("pm remove-user --wait " + user);
            install(NO_INTERNET_APK);
        }
    }

    @Test
    public void aNewInstallBlockedByDefaultNotifiesTheUser() throws Exception {
        int user = getDevice().createUser("fwnewapp");
        try {
            assertTrue(getDevice().startUser(user, true));
            shell("cmd firewall set-new-installs blocked --user " + user);
            shell("pm install-existing --user " + user + " " + PACKAGE);
            awaitRules("all", PACKAGE, user);
            String noted = PACKAGE + " user " + user + " rules all (default, notified)";
            waitUntil("The app was not noted", 10_000,
                    () -> shell("dumpsys firewall").contains(noted));
            waitUntil("The user was not notified", 10_000,
                    () -> blockedNoticePosted(PACKAGE, user));
        } finally {
            shell("pm remove-user --wait " + user);
        }
    }

    @Test
    public void theNoticeGoesWithTheAppOnUninstall() throws Exception {
        int user = getDevice().createUser("fwnoticegone");
        try {
            assertTrue(getDevice().startUser(user, true));
            shell("cmd firewall set-new-installs blocked --user " + user);
            shell("pm install-existing --user " + user + " " + PACKAGE);
            waitUntil("The user was not notified", 10_000,
                    () -> blockedNoticePosted(PACKAGE, user));
            shell("pm uninstall --user " + user + " " + PACKAGE);
            waitUntil("The notice stayed", 10_000, () -> !blockedNoticePosted(PACKAGE, user));
        } finally {
            shell("pm remove-user --wait " + user);
        }
    }

    /** Whether the firewall app's notice about the app is up, keyed user|package|id|tag|uid. */
    private boolean blockedNoticePosted(String packageName, int user) throws Exception {
        return shell("dumpsys notification --noredact")
                .contains(user + "|" + FIREWALL_APP + "|1|" + packageName + "|");
    }

    @Test
    public void aNetdRestartKeepsTheFirewallOn() throws Exception {
        setRules("all", 0);
        String netd = shell("pidof netd").trim();
        String server = shell("pidof system_server").trim();
        // netd restarts the zygote too; Connectivity's checks must accept our programs.
        shell("kill " + netd);
        // The boot completed flag stays set, so wait for the new system server's firewall.
        waitUntil("The firewall did not come back", 120_000,
                () -> !server.equals(shell("pidof system_server").trim())
                        && shell("dumpsys firewall").contains("Programs: attached"));
        getDevice().waitForDeviceAvailable();
        assertNotEquals(netd, shell("pidof netd").trim());
        assertTrue(run("HostChecks", "blocked", 0));
    }

    @Test
    public void theFirewallAppBacksUpTheRules() throws Exception {
        String current = shell("bmgr list transports").replaceAll("(?s).*\\* (\\S+).*", "$1");
        boolean enabled = shell("bmgr enabled").contains("currently enabled");
        try {
            shell("bmgr enable true");
            shell("bmgr transport " + LOCAL_TRANSPORT);
            setRules("mobile", 0);
            assertTrue(shell("bmgr backupnow " + FIREWALL_APP).contains("Success"));
            setRules("none", 0);
            String token = shell("bmgr list sets").trim().split("\\s+")[0];
            shell("bmgr restore " + token + " " + FIREWALL_APP);
            assertEquals("mobile", getRules(0));
        } finally {
            shell("bmgr transport " + current);
            if (!enabled) shell("bmgr enable false");
        }
    }

    @Test
    public void restoredRulesWaitForTheAppToBeInstalled() throws Exception {
        String backup = "/data/local/tmp/firewall-backup.xml";
        setRules("mobile", 0);
        assertTrue(getDevice().pushString(shell("cmd firewall backup --user 0"), backup));
        int user = getDevice().createUser("fwrestore");
        try {
            assertTrue(getDevice().startUser(user, true));
            shell("cmd firewall restore --user " + user + " < " + backup);
            assertEquals("none", getRules(user));
            shell("pm install-existing --user " + user + " " + PACKAGE);
            awaitRules("mobile", PACKAGE, user);
        } finally {
            shell("pm remove-user --wait " + user);
            shell("rm -f " + backup);
        }
    }

    @Test
    public void offLetsAppsThroughUntilTheFirewallIsBackOn() throws Exception {
        setRules("all", 0);
        try {
            shell("cmd firewall set-enabled false");
            assertTrue(run("HostChecks", "allowed", 0));
            assertTrue(run("HostChecks", "looksUp", 0));
        } finally {
            shell("cmd firewall set-enabled true");
        }
        assertTrue(run("HostChecks", "blocked", 0));
    }

    @Test
    public void theFirewallStaysOffAfterAReboot() throws Exception {
        setRules("all", 0);
        shell("cmd firewall set-enabled false");
        try {
            getDevice().reboot();
            assertEquals("false", shell("cmd firewall get-enabled").trim());
            assertTrue(run("HostChecks", "allowed", 0));
            // Off as an admin chose, the firewall isn't failing to run.
            shell("am wait-for-broadcast-idle");
            assertFalse(shell("dumpsys notification --noredact")
                    .contains("0|" + FIREWALL_APP + "|2|not_running|"));
        } finally {
            shell("cmd firewall set-enabled true");
        }
    }

    @Test
    public void onlyAnAdminUserCanTurnTheFirewallOff() throws Exception {
        int user = getDevice().createUser("fwnotadmin");
        try {
            assertTrue(getDevice().startUser(user, true));
            shell("pm install-existing --user " + user + " " + APP_TESTS);
            // Only the foreground user's apps show their pages.
            assertTrue(getDevice().switchUser(user));
            assertTrue(runDeviceTests(new DeviceTestRunOptions(APP_TESTS)
                    .setUserId(user)
                    .setTestClassName(FIREWALL_APP + ".FirewallAppTest")
                    .setTestMethodName("nonAdminsSeeTheMainSwitchGreyed")));
        } finally {
            getDevice().switchUser(0);
            shell("pm remove-user --wait " + user);
        }
        assertEquals("true", shell("cmd firewall get-enabled").trim());
    }
}
