/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall.hostside.app;

import static android.system.OsConstants.POLLIN;

import static com.android.compatibility.common.util.SystemUtil.runShellCommand;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.DnsResolver;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Process;
import android.os.SystemClock;
import android.system.ErrnoException;
import android.system.Os;
import android.system.StructPollfd;
import android.util.Log;

import androidx.test.platform.app.InstrumentationRegistry;

import com.android.compatibility.common.util.PollingCheck;
import com.android.testutils.TestableNetworkCallback;
import com.android.testutils.TestableNetworkCallback.Event;

import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/** Drives the firewall for this app through its shell command, and probes the network. */
final class Firewall {
    static final String PACKAGE = "org.lineageos.firewall.hostside.app";
    private static final String TAG = "FirewallHostside";

    private Firewall() {}

    static Context context() {
        return InstrumentationRegistry.getInstrumentation().getContext();
    }

    static int userId() {
        return Process.myUid() / 100000;
    }

    static void setRules(String rules) {
        runShellCommand("cmd firewall set-app " + PACKAGE + " " + rules + " --user " + userId());
    }

    /** Waits until the host resolves, as DNS comes up; nothing reports that to an app. */
    static void awaitLookup(String host, long timeoutMs) {
        PollingCheck.waitFor(timeoutMs, () -> {
            try {
                InetAddress.getByName(host);
                return true;
            } catch (UnknownHostException e) {
                return false;
            }
        }, "No answer for " + host);
    }

    /** Whether Android's resolver answers for the host in time, asking past its cache. */
    static boolean looksUp(String host, long timeoutMs) throws InterruptedException {
        CompletableFuture<Boolean> answered = new CompletableFuture<>();
        DnsResolver.getInstance().query(null, host, DnsResolver.TYPE_A,
                DnsResolver.FLAG_NO_CACHE_LOOKUP, Runnable::run, null,
                new DnsResolver.Callback<List<InetAddress>>() {
                    @Override
                    public void onAnswer(List<InetAddress> answer, int rcode) {
                        answered.complete(!answer.isEmpty());
                    }

                    @Override
                    public void onError(DnsResolver.DnsException error) {
                        answered.complete(false);
                    }
                });
        try {
            return answered.get(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (ExecutionException | TimeoutException e) {
            return false;
        }
    }

    /** Whether Connectivity reports this app's default network as blocked, or not, in time. */
    static boolean waitForBlocked(boolean blocked, long timeoutMs) {
        ConnectivityManager cm = context().getSystemService(ConnectivityManager.class);
        TestableNetworkCallback callback = new TestableNetworkCallback(timeoutMs);
        cm.registerDefaultNetworkCallback(callback);
        try {
            return callback.poll(timeoutMs, event -> event instanceof Event.BlockedStatus
                    && ((Event.BlockedStatus) event).getBlocked() == blocked) != null;
        } finally {
            cm.unregisterNetworkCallback(callback);
        }
    }

    /** Whether a validated default network that isn't blocked for this app comes in time. */
    static boolean waitForUsableNetwork(long timeoutMs) {
        ConnectivityManager cm = context().getSystemService(ConnectivityManager.class);
        TestableNetworkCallback callback = new TestableNetworkCallback(timeoutMs);
        cm.registerDefaultNetworkCallback(callback);
        try {
            boolean[] validated = {false};
            boolean[] blocked = {true};
            return callback.poll(timeoutMs, event -> {
                if (event instanceof Event.CapabilitiesChanged) {
                    validated[0] = ((Event.CapabilitiesChanged) event).getCaps()
                            .hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED);
                } else if (event instanceof Event.BlockedStatus) {
                    blocked[0] = ((Event.BlockedStatus) event).getBlocked();
                }
                return validated[0] && !blocked[0];
            }) != null;
        } finally {
            cm.unregisterNetworkCallback(callback);
        }
    }

    /** The VPN network this app can see, or null for none. */
    static Network vpnNetwork() {
        ConnectivityManager cm = context().getSystemService(ConnectivityManager.class);
        for (Network network : cm.getAllNetworks()) {
            NetworkCapabilities nc = cm.getNetworkCapabilities(network);
            if (nc != null && nc.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return network;
        }
        return null;
    }

    /** Waits until a VPN network is connected or gone. */
    static void awaitVpn(boolean connected) {
        PollingCheck.waitFor(10_000, () -> (vpnNetwork() != null) == connected,
                connected ? "VPN never connected" : "VPN still up");
    }

    /** Waits until the firewall has written the network's interfaces, as its dump prints. */
    static void awaitFirewallSees(Network network) {
        PollingCheck.waitFor(10_000, () -> {
            for (String line : runShellCommand("dumpsys firewall").split("\n")) {
                String[] fields = line.trim().split(" ");
                if (fields.length >= 4 && fields[0].equals("netId")
                        && fields[1].equals(Integer.toString(network.getNetId()))
                        && !line.contains("ifindexes []")) {
                    return true;
                }
            }
            return false;
        }, "The firewall never saw " + network);
    }

    static boolean tcpConnects(String host, int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(InetAddress.getByName(host), port), 5000);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /** Whether a connection comes to a server at the port in time. */
    static boolean accepts(int port, int timeoutMs) throws IOException {
        try (ServerSocket server = new ServerSocket(port)) {
            server.setSoTimeout(timeoutMs);
            try (Socket client = server.accept()) {
                return true;
            } catch (SocketTimeoutException e) {
                return false;
            }
        }
    }

    /** Sends one datagram without connecting; false if the send itself was refused. */
    static boolean udpSends(InetAddress to, int port) {
        return udpSends(null, to, port);
    }

    /** As above, over the network if one is given. */
    static boolean udpSends(Network network, InetAddress to, int port) {
        try (DatagramSocket socket = new DatagramSocket()) {
            if (network != null) network.bindSocket(socket);
            socket.send(new DatagramPacket(new byte[] {1}, 1, to, port));
            return true;
        } catch (IOException e) {
            Log.i(TAG, "Sending to " + to + " over " + network + " failed", e);
            return false;
        }
    }

    /** Whether a UDP packet to the port comes out of the tun within two seconds. */
    static boolean tunSaw(FileDescriptor tun, int port)
            throws ErrnoException, InterruptedIOException {
        StructPollfd poll = new StructPollfd();
        poll.fd = tun;
        poll.events = (short) POLLIN;
        byte[] packet = new byte[2048];
        long deadline = SystemClock.elapsedRealtime() + 2000;
        while (SystemClock.elapsedRealtime() < deadline) {
            if (Os.poll(new StructPollfd[] {poll}, 500) <= 0) continue;
            int length = Os.read(tun, packet, 0, packet.length);
            boolean v6 = (packet[0] >> 4) == 6;
            int l4 = v6 ? 40 : (packet[0] & 0xf) * 4;
            int protocol = v6 ? packet[6] : packet[9];
            if (protocol == 17 && length >= l4 + 4
                    && (((packet[l4 + 2] & 0xff) << 8) | (packet[l4 + 3] & 0xff)) == port) {
                return true;
            }
        }
        return false;
    }
}
