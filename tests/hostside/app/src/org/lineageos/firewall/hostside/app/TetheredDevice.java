/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall.hostside.app;

import static android.system.OsConstants.POLLIN;

import android.os.SystemClock;
import android.system.ErrnoException;
import android.system.Os;
import android.system.StructPollfd;

import java.io.FileDescriptor;
import java.io.InterruptedIOException;
import java.net.Inet4Address;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.function.Predicate;

/**
 * A device on the phone's tethered network, played through the test interface that stands in for
 * the hotspot: it finds the phone by ARP, asks its DNS server, and answers its ARP requests.
 */
final class TetheredDevice {
    private static final byte[] MAC = {0x02, 0, 0, 0, 0, 0x01};
    private static final byte[] BROADCAST = {-1, -1, -1, -1, -1, -1};
    private static final int PORT = 40000;
    private static final short ETHER_IPV4 = 0x0800;
    private static final short ETHER_ARP = 0x0806;
    private static final short ARP_REQUEST = 1;
    private static final short ARP_REPLY = 2;
    private static final byte UDP = 17;

    private final FileDescriptor mTap;
    private final byte[] mPhone;
    private final byte[] mAddress;
    private byte[] mPhoneMac;

    /** The device takes an address next to the phone's on the network. */
    TetheredDevice(FileDescriptor tap, Inet4Address phone) {
        mTap = tap;
        mPhone = phone.getAddress();
        mAddress = mPhone.clone();
        mAddress[3] = (byte) (mPhone[3] == 99 ? 98 : 99);
    }

    /** What the phone's DNS server answers this device's lookup of the name's IPv4 addresses. */
    Firewall.DnsAnswer lookUp(String name) throws Exception {
        if (mPhoneMac == null) {
            byte[] request = arp(ARP_REQUEST, BROADCAST, new byte[6], mPhone);
            byte[] reply = ask(request, frame -> isArp(frame, ARP_REPLY, 28, mPhone), "ARP reply");
            mPhoneMac = Arrays.copyOfRange(reply, 22, 28);
        }
        byte[] query = Firewall.dnsQuery(name);
        // Ethernet, IPv4 with its header checksum, then UDP without one, as IPv4 allows.
        ByteBuffer frame = ByteBuffer.allocate(42 + query.length);
        frame.put(mPhoneMac).put(MAC).putShort(ETHER_IPV4);
        frame.put((byte) 0x45).put((byte) 0).putShort((short) (28 + query.length)).putInt(0)
                .put((byte) 64).put(UDP).putShort((short) 0).put(mAddress).put(mPhone);
        frame.putShort(24, checksum(frame.array(), 14, 20));
        frame.putShort((short) PORT).putShort((short) 53).putShort((short) (8 + query.length))
                .putShort((short) 0).put(query);
        byte[] answer = ask(frame.array(), TetheredDevice::isDnsAnswer, "DNS answer");
        int dns = 14 + (answer[14] & 0xf) * 4 + 8;
        return new Firewall.DnsAnswer(answer[dns + 3] & 0xf, ByteBuffer.wrap(answer).getShort(dns + 6));
    }

    /**
     * Sends the frame once a second, as clients retry, until the wanted answer comes; the phone's
     * services may start listening only after its address is up. Answers its ARP requests meanwhile.
     */
    private byte[] ask(byte[] question, Predicate<ByteBuffer> wanted, String what)
            throws Exception {
        for (int attempt = 0; attempt < 10; attempt++) {
            write(question);
            byte[] answer = await(wanted, 1000);
            if (answer != null) return answer;
        }
        throw new SocketTimeoutException("The phone's " + what + " never came");
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

    private static boolean isDnsAnswer(ByteBuffer frame) {
        if (frame.getShort(12) != ETHER_IPV4 || frame.get(23) != UDP) return false;
        int udp = 14 + (frame.get(14) & 0xf) * 4;
        return frame.getShort(udp) == 53 && (frame.getShort(udp + 2) & 0xffff) == PORT;
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

    /** The IPv4 header checksum of the bytes. */
    private static short checksum(byte[] bytes, int start, int length) {
        int sum = 0;
        for (int i = start; i < start + length; i += 2) {
            sum += ((bytes[i] & 0xff) << 8) | (bytes[i + 1] & 0xff);
        }
        while ((sum >> 16) != 0) sum = (sum & 0xffff) + (sum >> 16);
        return (short) ~sum;
    }
}
