/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

// Devices on the phone's hotspot and tethering. What they send out through the phone follows a
// device's own rules, by its MAC address, then those for all the devices, kept on dnsmasq's uid as
// for their lookups, then the rules for all of the main user's apps. The service puts the program
// on each tethered interface ahead of Tethering's offload, and the phone's hardware offload takes
// over only flows that start, so a flow refused at its first packet never gets there.

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

// The devices with rules of their own, by MAC address, as the uids their rules are kept under.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u32);
    __uint(max_entries, FW_HOTSPOT_DEVICES);
} hotspot_devices SEC(".maps");

// The addresses those devices send from, which dnsmasq reads to make their lookups as theirs.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct fw_hotspot_address);
    __type(value, __u32);
    __uint(max_entries, FW_HOTSPOT_ADDRESSES);
} hotspot_addresses SEC(".maps");

static __always_inline void learn_address(struct __sk_buff* skb, bool v6, __u32 device) {
    struct fw_hotspot_address key = {};
    if (v6) {
        if (bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct ipv6hdr, saddr), key.addr, 16)) {
            return;
        }
    } else {
        key.addr[10] = 0xff;
        key.addr[11] = 0xff;
        if (bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, saddr), key.addr + 12, 4)) {
            return;
        }
    }
    __u32* known = bpf_map_lookup_elem(&hotspot_addresses, &key);
    if (!known || *known != device) bpf_map_update_elem(&hotspot_addresses, &key, &device, BPF_ANY);
}

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
    __u32 row = AID_DNS_TETHER;
    __u32* own = bpf_map_lookup_elem(&uid_rules, &row);
    __u32 rules = own ? *own : 0;
    __u64 mac = 0;
    if (bpf_skb_load_bytes(skb, ETH_ALEN, &mac, ETH_ALEN)) return TC_ACT_UNSPEC;
    __u32* known = bpf_map_lookup_elem(&hotspot_devices, &mac);
    __u32 device = known ? *known : 0;
    __u32 device_rules = 0;
    if (device) {
        __u32* theirs = bpf_map_lookup_elem(&uid_rules, &device);
        device_rules = theirs ? *theirs : 0;
    }
    // Broadcasts and multicasts stay on the hotspot; only what's sent to the phone goes on.
    if (skb->pkt_type != PACKET_HOST) return TC_ACT_UNSPEC;
    bool v6 = skb->protocol == __builtin_bswap16(ETH_P_IPV6);
    if (!v6 && skb->protocol != __builtin_bswap16(ETH_P_IP)) return TC_ACT_UNSPEC;
    if (device) learn_address(skb, v6, device);
    __u32 uflags = user_flags_of(row / AID_USER_OFFSET);
    if (!device_rules && !rules &&
        !(uflags & (FW_SCOPE_ALLOWS | FW_SCOPE_BLOCKS | FW_SCOPE_DOMAINS | FW_SCOPE_LISTS |
                    FW_USER_LOG))) {
        return TC_ACT_UNSPEC;
    }
    __u32 key = 0;
    __u32* upstream = bpf_map_lookup_elem(&hotspot_upstream, &key);
    // Tethering keeps its traffic off VPNs.
    struct fw_path path = {.mark = (upstream ? *upstream : 0) | FW_MARK_EXPLICIT |
                                   FW_MARK_PROTECTED_FROM_VPN,
                           .owner_uid = row,
                           .connect = true};
    struct l4_info info = {};
    bool parsed = parse_l4_at(skb, ETH_HLEN, &info, true);
    __u32 counter = 0;
    // The device's own rules decide first, then those for all the devices, whose rules give the
    // reasons reported for what they decide; the rules for all apps come after both.
    __u32 scope = device ? device : row;
    __u32 scope_rules = device ? device_rules : rules;
    int verdict = device ? own_verdict(device, device_rules, uflags, false, parsed, &path, &info,
                                       &counter)
                         : -1;
    if (verdict < 0) {
        verdict = own_verdict(row, rules, uflags, false, parsed, &path, &info, &counter);
        if (verdict >= 0) {
            scope = row;
            scope_rules = rules;
        }
    }
    if (verdict < 0 && parsed) {
        bool dns = info.port == 53 || info.port == 853;
        if (user_rules_drop(scope, scope_rules, uflags, dns, false, &info, &path, &counter)) {
            verdict = 1;
        } else if (device && lists_block(row, rules, FW_USER_SCOPE, 0, &info)) {
            counter = FW_C_EGRESS_DROP_LIST;
            scope = row;
            scope_rules = rules;
            verdict = 1;
        }
    }
    bool drop = verdict > 0;
    // What the phone itself takes is no traffic out through it, so it's neither refused nor logged.
    if (parsed && (drop || (uflags & FW_USER_LOG)) && for_the_phone(skb, &info)) {
        return TC_ACT_UNSPEC;
    }
    if (drop) {
        count(counter);
    } else if (!parsed || !(uflags & FW_USER_LOG)) {
        return TC_ACT_UNSPEC;
    }
    note_refusal_as(device ? device : row, scope, scope_rules, FW_REFUSAL_OUT, !drop, &info,
                    parsed, &path);
    return drop ? TC_ACT_SHOT : TC_ACT_UNSPEC;
}
