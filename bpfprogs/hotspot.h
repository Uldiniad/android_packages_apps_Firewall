/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

// Devices on the phone's hotspot and tethering. What they send out through the phone follows the
// rules for all of its first user's apps, as dnsmasq's lookups for them do. The service puts the
// program on each tethered interface ahead of Tethering's offload, and the phone's hardware offload
// takes over only flows that start, so a flow refused at its first packet never gets there.

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/pkt_cls.h>

// The netd network id of Tethering's upstream, which rules limited to networks are read against.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} hotspot_upstream SEC(".maps");

// Whether one of the phone's own sockets takes the packet, as dnsmasq takes the devices' lookups.
static __always_inline bool for_the_phone(struct __sk_buff* skb, const struct l4_info* info) {
    if (info->protocol != IPPROTO_TCP && info->protocol != IPPROTO_UDP) return false;
    struct bpf_sock_tuple tuple = {};
    __u32 size;
    if (!info->v6) {
        if (bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, saddr),
                               &tuple.ipv4.saddr, 4)) {
            return false;
        }
        tuple.ipv4.daddr = info->addr[0];
        tuple.ipv4.sport = __builtin_bswap16(info->local_port);
        tuple.ipv4.dport = __builtin_bswap16(info->port);
        size = sizeof(tuple.ipv4);
    } else {
        if (bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct ipv6hdr, saddr),
                               tuple.ipv6.saddr, 16)) {
            return false;
        }
        __builtin_memcpy(tuple.ipv6.daddr, info->addr, 16);
        tuple.ipv6.sport = __builtin_bswap16(info->local_port);
        tuple.ipv6.dport = __builtin_bswap16(info->port);
        size = sizeof(tuple.ipv6);
    }
    struct bpf_sock* sk = info->protocol == IPPROTO_TCP
                                  ? bpf_sk_lookup_tcp(skb, &tuple, size, BPF_F_CURRENT_NETNS, 0)
                                  : bpf_sk_lookup_udp(skb, &tuple, size, BPF_F_CURRENT_NETNS, 0);
    if (!sk) return false;
    bpf_sk_release(sk);
    return true;
}

SEC("tc")
int hotspot(struct __sk_buff* skb) {
    // dnsmasq's uid stands for the devices, as for their lookups: its own rules, then its user's.
    __u32 uid = AID_DNS_TETHER;
    __u32* own = bpf_map_lookup_elem(&uid_rules, &uid);
    __u32 rules = own ? *own : 0;
    __u32 uflags = user_flags_of(uid / AID_USER_OFFSET);
    if (!rules && !(uflags & (FW_SCOPE_ALLOWS | FW_SCOPE_BLOCKS | FW_SCOPE_DOMAINS |
                              FW_SCOPE_LISTS | FW_USER_LOG))) {
        return TC_ACT_UNSPEC;
    }
    // Broadcasts and multicasts stay on the hotspot; only what's sent to the phone goes on.
    if (skb->pkt_type != PACKET_HOST) return TC_ACT_UNSPEC;
    if (skb->protocol != __builtin_bswap16(ETH_P_IP) &&
        skb->protocol != __builtin_bswap16(ETH_P_IPV6)) {
        return TC_ACT_UNSPEC;
    }
    __u32 key = 0;
    __u32* upstream = bpf_map_lookup_elem(&hotspot_upstream, &key);
    // Tethering keeps its traffic off VPNs.
    struct fw_path path = {.mark = (upstream ? *upstream : 0) | FW_MARK_EXPLICIT |
                                   FW_MARK_PROTECTED_FROM_VPN,
                           .owner_uid = uid,
                           .connect = true};
    struct l4_info info = {};
    bool parsed = false;
    __u32 counter;
    __u32 read_flags = FW_FLAGS_UNREAD;
    bool drop = egress_drop(skb, ETH_HLEN, false, uid, rules, &path, &info, &parsed, &counter,
                            &read_flags);
    // What the phone itself takes is no traffic out through it, so it's neither refused nor logged.
    if (parsed && (drop || (uflags & FW_USER_LOG)) && for_the_phone(skb, &info)) {
        return TC_ACT_UNSPEC;
    }
    if (drop) {
        count(counter);
    } else if (!parsed || !(uflags & FW_USER_LOG)) {
        return TC_ACT_UNSPEC;
    }
    note_refusal(uid, rules, FW_REFUSAL_OUT, !drop, &info, parsed, &path);
    return drop ? TC_ACT_SHOT : TC_ACT_UNSPEC;
}
