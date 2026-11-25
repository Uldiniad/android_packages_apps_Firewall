/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall.hostside.app;

import static android.Manifest.permission.MANAGE_TEST_NETWORKS;
import static android.Manifest.permission.NETWORK_SETTINGS;
import static android.Manifest.permission.TETHER_PRIVILEGED;
import static android.net.TetheringManager.CONNECTIVITY_SCOPE_GLOBAL;
import static android.net.TetheringManager.TETHERING_VIRTUAL;
import static android.system.OsConstants.POLLIN;

import static org.junit.Assert.assertEquals;

import android.net.InetAddresses;
import android.net.TestNetworkInterface;
import android.net.TestNetworkManager;
import android.net.TetheringManager;
import android.net.TetheringManager.TetheringRequest;
import android.os.SystemClock;
import android.system.ErrnoException;
import android.system.Os;
import android.system.StructPollfd;

import com.android.compatibility.common.util.SystemUtil;

import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;

/**
 * A device on the phone's tethered network, played through a test interface that stands in for
 * the hotspot: it finds the phone by ARP, sends through it, and answers its ARP requests.
 */
final class TetheredDevice implements AutoCloseable {
    private static final byte[] MAC = {0x02, 0, 0, 0, 0, 0x01};
    private static final byte[] BROADCAST = {-1, -1, -1, -1, -1, -1};
    private static final int PORT = 40000;
    private static final short ETHER_IPV4 = 0x0800;
    private static final short ETHER_ARP = 0x0806;
    private static final short ARP_REQUEST = 1;
    private static final short ARP_REPLY = 2;
    private static final byte TCP = 6;
    private static final byte UDP = 17;
    private static final byte SYN = 0x02;
    private static final byte SYN_ACK = 0x12;

    private final TestNetworkInterface mInterface;
    private final FileDescriptor mTap;
    private final byte[] mPhone;
    private final byte[] mAddress;
    private byte[] mPhoneMac;

    private TetheredDevice(TestNetworkInterface tap) throws Exception {
        mInterface = tap;
        mTap = tap.getFileDescriptor().getFileDescriptor();
        mPhone = Firewall.ipv4Of(tap.getInterfaceName(), 10_000).getAddress();
        // The device takes an address next to the phone's on the network.
        mAddress = mPhone.clone();
        mAddress[3] = (byte) (mPhone[3] == 99 ? 98 : 99);
    }

    /** Tethers the phone to a new test interface, with this device behind it. */
    static TetheredDevice start() throws Exception {
        TestNetworkInterface tap = SystemUtil.runWithShellPermissionIdentity(
                () -> Firewall.context().getSystemService(TestNetworkManager.class)
                        .createTapInterface(), MANAGE_TEST_NETWORKS);
        TetheringRequest request = new TetheringRequest.Builder(TETHERING_VIRTUAL)
                .setConnectivityScope(CONNECTIVITY_SCOPE_GLOBAL)
                .setInterfaceName(tap.getInterfaceName())
                .build();
        CompletableFuture<Integer> started = new CompletableFuture<>();
        try {
            // Until it's connected to the tethering service, the manager queues calls for later,
            // so the shell's permissions stay until the answer comes.
            int result = SystemUtil.callWithShellPermissionIdentity(() -> {
                tethering().startTethering(request, Runnable::run,
                        new TetheringManager.StartTetheringCallback() {
                            @Override
                            public void onTetheringStarted() {
                                started.complete(0);
                            }

                            @Override
                            public void onTetheringFailed(int error) {
                                started.complete(error);
                            }
                        });
                return started.get(30, TimeUnit.SECONDS);
            }, TETHER_PRIVILEGED, NETWORK_SETTINGS);
            assertEquals("Tethering failed", 0, result);
            return new TetheredDevice(tap);
        } catch (Throwable e) {
            stop(tap);
            throw e;
        }
    }

    @Override
    public void close() throws IOException {
        stop(mInterface);
    }

    private static void stop(TestNetworkInterface tap) throws IOException {
        SystemUtil.runWithShellPermissionIdentity(
                () -> tethering().stopTethering(TETHERING_VIRTUAL), TETHER_PRIVILEGED);
        tap.getFileDescriptor().close();
    }

    private static TetheringManager tethering() {
        return Firewall.context().getSystemService(TetheringManager.class);
    }

    /** What the phone's DNS server answers this device's lookup of the name's IPv4 addresses. */
    Firewall.DnsAnswer lookUp(String name) throws Exception {
        Firewall.DnsAnswer answer = lookUp(name, mPhone, 10);
        if (answer == null) throw new SocketTimeoutException("The phone's DNS answer never came");
        return answer;
    }

    /** What the DNS server at the address answers this device through the phone, else null. */
    Firewall.DnsAnswer lookUp(String name, String server) throws Exception {
        return lookUp(name, addressOf(server), 3);
    }

    private Firewall.DnsAnswer lookUp(String name, byte[] server, int attempts) throws Exception {
        byte[] query = Firewall.dnsQuery(name);
        // UDP without a checksum, as IPv4 allows.
        byte[] udp = ByteBuffer.allocate(8 + query.length)
                .putShort((short) PORT).putShort((short) 53).putShort((short) (8 + query.length))
                .putShort((short) 0).put(query).array();
        byte[] answer = ask(ipv4(server, UDP, udp), frame -> isFrom(frame, UDP, server, 53),
                attempts);
        if (answer == null) return null;
        int dns = 14 + (answer[14] & 0xf) * 4 + 8;
        return new Firewall.DnsAnswer(answer[dns + 3] & 0xf,
                ByteBuffer.wrap(answer).getShort(dns + 6));
    }

    /** Whether the server at the address and port accepts this device's TCP connection. */
    boolean connects(String address, int port) throws Exception {
        byte[] server = addressOf(address);
        byte[] syn = ByteBuffer.allocate(20)
                .putShort((short) PORT).putShort((short) port).putInt(1).putInt(0)
                .put((byte) 0x50).put(SYN).putShort((short) 65535).putInt(0).array();
        ByteBuffer pseudo = ByteBuffer.allocate(32).put(mAddress).put(server).put((byte) 0)
                .put(TCP).putShort((short) syn.length).put(syn);
        ByteBuffer.wrap(syn).putShort(16, checksum(pseudo.array(), 0, 32));
        byte[] answer = ask(ipv4(server, TCP, syn), frame -> isFrom(frame, TCP, server, port), 3);
        return answer != null && (answer[14 + (answer[14] & 0xf) * 4 + 13] & SYN_ACK) == SYN_ACK;
    }

    private static byte[] addressOf(String address) {
        return InetAddresses.parseNumericAddress(address).getAddress();
    }

    /** An Ethernet frame to the phone with an IPv4 packet from this device to the address. */
    private byte[] ipv4(byte[] to, byte protocol, byte[] payload) throws Exception {
        ByteBuffer frame = ByteBuffer.allocate(34 + payload.length);
        frame.put(phoneMac()).put(MAC).putShort(ETHER_IPV4);
        frame.put((byte) 0x45).put((byte) 0).putShort((short) (20 + payload.length)).putInt(0)
                .put((byte) 64).put(protocol).putShort((short) 0).put(mAddress).put(to);
        frame.putShort(24, checksum(frame.array(), 14, 20));
        return frame.put(payload).array();
    }

    private byte[] phoneMac() throws Exception {
        if (mPhoneMac == null) {
            byte[] request = arp(ARP_REQUEST, BROADCAST, new byte[6], mPhone);
            byte[] reply = ask(request, frame -> isArp(frame, ARP_REPLY, 28, mPhone), 10);
            if (reply == null) throw new SocketTimeoutException("The phone's ARP reply never came");
            mPhoneMac = Arrays.copyOfRange(reply, 22, 28);
        }
        return mPhoneMac;
    }

    /**
     * Sends the frame once a second, as clients retry, until the wanted answer comes, or null
     * after the attempts; the phone's services may start listening only after its address is up.
     * Answers its ARP requests meanwhile.
     */
    private byte[] ask(byte[] question, Predicate<ByteBuffer> wanted, int attempts)
            throws Exception {
        for (int attempt = 0; attempt < attempts; attempt++) {
            write(question);
            byte[] answer = await(wanted, 1000);
            if (answer != null) return answer;
        }
        return null;
    }

    /** Reads frames until a wanted one comes, or null after the time, answering ARP requests. */
    private byte[] await(Predicate<ByteBuffer> wanted, long timeoutMs) throws Exception {
        byte[] in = new byte[2048];
        long deadline = SystemClock.elapsedRealtime() + timeoutMs;
        while (SystemClock.elapsedRealtime() < deadline) {
            StructPollfd poll = new StructPollfd();
            poll.fd = mTap;
            poll.events = (short) POLLIN;
            if (Os.poll(new StructPollfd[] {poll}, 200) <= 0) continue;
            int length = Os.read(mTap, in, 0, in.length);
            if (length < 42) continue;
            ByteBuffer frame = ByteBuffer.wrap(Arrays.copyOf(in, length));
            if (isArp(frame, ARP_REQUEST, 38, mAddress)) {
                write(arp(ARP_REPLY, Arrays.copyOfRange(in, 22, 28),
                        Arrays.copyOfRange(in, 22, 28), Arrays.copyOfRange(in, 28, 32)));
            } else if (wanted.test(frame)) {
                return frame.array();
            }
        }
        return null;
    }

    /** Whether the frame is an ARP packet of the kind with the address at the offset. */
    private static boolean isArp(ByteBuffer frame, short op, int at, byte[] address) {
        return frame.getShort(12) == ETHER_ARP && frame.getShort(20) == op
                && Arrays.equals(Arrays.copyOfRange(frame.array(), at, at + 4), address);
    }

    /** Whether the frame is an IPv4 packet of the protocol from the address and port, to us. */
    private static boolean isFrom(ByteBuffer frame, byte protocol, byte[] address, int port) {
        if (frame.getShort(12) != ETHER_IPV4 || frame.get(23) != protocol
                || !Arrays.equals(Arrays.copyOfRange(frame.array(), 26, 30), address)) {
            return false;
        }
        int l4 = 14 + (frame.get(14) & 0xf) * 4;
        return (frame.getShort(l4) & 0xffff) == port && (frame.getShort(l4 + 2) & 0xffff) == PORT;
    }

    /** An ARP packet from this device. */
    private byte[] arp(short op, byte[] to, byte[] targetMac, byte[] targetAddress) {
        return ByteBuffer.allocate(42)
                .put(to).put(MAC).putShort(ETHER_ARP)
                .putShort((short) 1).putShort(ETHER_IPV4).put((byte) 6).put((byte) 4)
                .putShort(op).put(MAC).put(mAddress).put(targetMac).put(targetAddress)
                .array();
    }

    private void write(byte[] frame) throws ErrnoException, InterruptedIOException {
        Os.write(mTap, frame, 0, frame.length);
    }

    /** The internet checksum of the bytes. */
    private static short checksum(byte[] bytes, int start, int length) {
        int sum = 0;
        for (int i = start; i < start + length; i += 2) {
            sum += ((bytes[i] & 0xff) << 8) | (bytes[i + 1] & 0xff);
        }
        while ((sum >> 16) != 0) sum = (sum & 0xffff) + (sum >> 16);
        return (short) ~sum;
    }
}
