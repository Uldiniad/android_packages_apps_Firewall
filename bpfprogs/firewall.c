/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include <android_bpf_defs.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
// Bionic's copy of the header names the struct __kernel_udphdr, as Connectivity also works around.
#define __kernel_udphdr udphdr
#include <linux/udp.h>
#include <private/android_filesystem_config.h>
#include <stdbool.h>
#include <stddef.h>

#include "firewall.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, FW_UID_RULES_SIZE);
} uid_rules SEC(".maps");

// Each network's bits, by interface and by network id.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, FW_IFACE_SIZE);
} iface_transport SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, FW_NET_SIZE);
} net_transport SEC(".maps");

// UID ranges routed through a VPN; netd marks those sockets with the underlying network.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct fw_vpn_range);
    __uint(max_entries, FW_VPN_RANGES);
} vpn_ranges SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, FW_COUNTER_MAX);
} counters SEC(".maps");

static __always_inline void count(__u32 index) {
    __u64* value = bpf_map_lookup_elem(&counters, &index);
    if (value) *value += 1;
}

static __always_inline bool is_app_uid(__u32 uid) {
    return uid % AID_USER_OFFSET >= AID_APP_START;
}

// Explicit per-uid rules apply to any uid but root and system, so shell can be a test subject.
static __always_inline __u32 rules_for(__u32 uid, bool* subject) {
    __u32* rules = bpf_map_lookup_elem(&uid_rules, &uid);
    *subject = rules ? (uid != 0 && uid != 1000) : is_app_uid(uid);
    return rules && *subject ? *rules : 0;
}

static __always_inline __u64 iface_network(__u32 ifindex) {
    __u64* net = bpf_map_lookup_elem(&iface_transport, &ifindex);
    return net ? *net : 0;
}

static __always_inline __u32 vpn_net_for_uid(__u32 uid) {
#pragma clang loop unroll(full)
    for (__u32 i = 0; i < FW_VPN_RANGES; i++) {
        __u32 key = i;
        struct fw_vpn_range* range = bpf_map_lookup_elem(&vpn_ranges, &key);
        if (!range || !range->net_id) return 0;
        if (uid >= range->start && uid <= range->end) return range->net_id;
    }
    return 0;
}

// The helpers below are global functions, which the verifier checks once on their own instead of
// at every rule lookup that inlines them.
__u64 fw_socket_network(__u32 mark, __u32 owner_uid);
// The network the socket goes out on, by netd's mark or the VPN the owner is under.
__attribute__((noinline)) __u64 fw_socket_network(__u32 mark, __u32 owner_uid) {
    __u32 net_id = mark & FW_NET_ID_MASK;
    __u32 vpn_net_id = vpn_net_for_uid(owner_uid);
    if (vpn_net_id && !(mark & FW_MARK_PROTECTED_FROM_VPN) &&
        !((mark & FW_MARK_EXPLICIT) && net_id != vpn_net_id)) {
        net_id = vpn_net_id;
    }
    __u64* net = bpf_map_lookup_elem(&net_transport, &net_id);
    return net ? *net : 0;
}

// Where a packet or connection goes. Its network is looked up only where a switch or a rule's
// limits need it, so the verifier doesn't carry it down every path, which it can't afford.
struct fw_path {
    __u32 ifindex;
    __u32 mark;
    __u32 owner_uid;
    bool connect;
};

static __always_inline __u64 path_network(const struct fw_path* path) {
    return path->connect ? fw_socket_network(path->mark, path->owner_uid)
                         : iface_network(path->ifindex);
}

#include "specific_networks.h"

static __always_inline bool network_blocked(__u32 uid, __u32 rules, const struct fw_path* path) {
    if (!(rules & (FW_RULE_NETWORKS | FW_RULE_NAMED_NETWORKS))) return false;
    return fw_network_blocked(rules, named_networks_of(uid, rules), path_network(path));
}

// The far end of a packet or connection: the destination going out, the source coming in.
struct l4_info {
    __u32 l4_offset;
    __u8 protocol;
    __u16 port;
    bool v6;
    __u32 addr[4];
};

static __always_inline bool parse_l4(struct __sk_buff* skb, struct l4_info* info, bool egress) {
    __u8 first;
    if (bpf_skb_load_bytes(skb, 0, &first, 1)) return false;
    __u32 l4_offset;
    if ((first >> 4) == 4) {
        __u8 protocol;
        __u32 addr = egress ? offsetof(struct iphdr, daddr) : offsetof(struct iphdr, saddr);
        if (bpf_skb_load_bytes(skb, offsetof(struct iphdr, protocol), &protocol, 1) ||
            bpf_skb_load_bytes(skb, addr, &info->addr[0], 4)) {
            return false;
        }
        info->protocol = protocol;
        info->v6 = false;
        l4_offset = (first & 0x0f) * 4;
    } else if ((first >> 4) == 6) {
        __u8 next_header;
        __u32 addr = egress ? offsetof(struct ipv6hdr, daddr) : offsetof(struct ipv6hdr, saddr);
        if (bpf_skb_load_bytes(skb, offsetof(struct ipv6hdr, nexthdr), &next_header, 1) ||
            bpf_skb_load_bytes(skb, addr, info->addr, 16)) {
            return false;
        }
        info->protocol = next_header;
        info->v6 = true;
        l4_offset = sizeof(struct ipv6hdr);
    } else {
        return false;
    }
    info->l4_offset = l4_offset;
    info->port = 0;
    if (info->protocol == IPPROTO_TCP || info->protocol == IPPROTO_UDP) {
        // TCP puts its ports where UDP does.
        __be16 port;
        __u32 offset = egress ? offsetof(struct udphdr, dest) : offsetof(struct udphdr, source);
        if (bpf_skb_load_bytes(skb, l4_offset + offset, &port, 2)) return false;
        info->port = __builtin_bswap16(port);
    }
    return true;
}

#include "target_rules.h"
#include "local_network.h"
#include "block_lists.h"
#include "socket_tags.h"

// 127.0.0.0/8 and ::1, with IPv4-mapped addresses taken as IPv4.
static __always_inline bool is_loopback(const struct l4_info* info) {
    if (!info->v6) return (__builtin_bswap32(info->addr[0]) >> 24) == 127;
    return !info->addr[0] && !info->addr[1] && !info->addr[2] &&
           info->addr[3] == __builtin_bswap32(1);
}

// Whether a packet or connection on loopback is refused as on a network: loopback is no network's,
// unless the app is kept off it.
static __always_inline bool cut_off(__u8 direction, __u32 rules, const struct l4_info* info,
                                    const struct fw_path* path) {
    bool loopback = direction == FW_REFUSAL_CONNECT ? is_loopback(info) : path->ifindex == 1;
    return !loopback || (rules & FW_RULE_NO_LOOPBACK);
}

#include "refusal_counts.h"

// Whether a packet out is dropped, and the counter it's dropped under.
static __always_inline bool egress_drop(struct __sk_buff* skb, __u32 uid, __u32 rules,
                                        const struct fw_path* path, struct l4_info* info,
                                        bool* parsed, __u32* counter) {
    bool blocked_all = rules & FW_RULE_BLOCK_ALL;
    // Apps kept off loopback are blocked on it as on a network.
    bool blocked_here = path->ifindex == 1 || network_blocked(uid, rules, path);
    *counter = blocked_all ? FW_C_EGRESS_DROP_ALL : FW_C_EGRESS_DROP_TRANSPORT;
    *parsed = parse_l4(skb, info, true);
    if ((blocked_all || blocked_here) && !(rules & FW_SCOPE_ALLOWS)) return true;
    if (!*parsed) return blocked_all || blocked_here;
    if ((rules & FW_RULE_NO_LAN) && lan_via_vpn(path->ifindex, info)) {
        *counter = FW_C_EGRESS_DROP_LAN;
        return true;
    }
    if ((rules & FW_SCOPE_ALLOWS) && scope_allows(uid, rules, info, path)) {
        count(FW_C_ALLOWED_BY_RULE);
        return false;
    }
    if (blocked_all || blocked_here) return true;

    // An app's own DNS, plain or over TLS or QUIC. With domain rules, the app looks names up
    // through Android's resolver instead, which checks them. Known DNS-over-HTTPS servers count
    // too, looked up only for the apps that rule applies to.
    bool dns = info->port == 53 || info->port == 853;
    if (dns) count(FW_C_DNS_SEEN);
    if ((rules & (FW_RULE_BLOCK_DNS | FW_SCOPE_DOMAINS)) &&
        (dns || listed(&ip4_block, &ip6_block, FW_DOH_SCOPE, 0, info, path))) {
        *counter = (rules & FW_RULE_BLOCK_DNS) ? FW_C_EGRESS_DROP_DNS : FW_C_EGRESS_DROP_DOMAIN;
        return true;
    }
    if ((rules & FW_SCOPE_BLOCKS) && scope_blocks(uid, rules, info, path, counter)) return true;

    __u32 user = uid / AID_USER_OFFSET;
    __u32 user_scope = FW_USER_SCOPE | user;
    __u32 uflags = user_flags_of(user);
    if ((uflags & FW_SCOPE_ALLOWS) && scope_allows(user_scope, uflags, info, path)) {
        count(FW_C_ALLOWED_BY_RULE);
        return false;
    }
    if ((uflags & FW_SCOPE_DOMAINS) &&
        (dns || listed(&ip4_block, &ip6_block, FW_DOH_SCOPE, 0, info, path))) {
        *counter = FW_C_EGRESS_DROP_DOMAIN;
        return true;
    }
    if ((uflags & FW_SCOPE_BLOCKS) && scope_blocks(user_scope, uflags, info, path, counter)) {
        return true;
    }
    if (lists_block(uid, rules, user_scope, uflags, info)) {
        *counter = FW_C_EGRESS_DROP_LIST;
        return true;
    }
    return false;
}

// An app's allow rules win over its blocks, and its rules over its user's. Allow rules for
// domains reach blocked apps through the addresses learned from the lookups they let through.
SEC("cgroup_skb/egress")
int egress(struct __sk_buff* skb) {
    __u32 uid = tagged_uid(bpf_get_socket_cookie(skb), bpf_get_socket_uid(skb));
    bool subject;
    __u32 rules = rules_for(uid, &subject);
    if (!subject) return 1;

    // Read once: the verifier refuses a second read through a pointer the compiler kept.
    __u32 ifindex = skb->ifindex;
    if (ifindex == 1 && !(rules & FW_RULE_NO_LOOPBACK)) return 1;
    struct fw_path path = {.ifindex = ifindex};
    struct l4_info info = {};
    bool parsed = false;
    __u32 counter;
    if (!egress_drop(skb, uid, rules, &path, &info, &parsed, &counter)) return 1;
    count(counter);
    note_refusal(uid, rules, FW_REFUSAL_OUT, &info, parsed, &path);
    return 0;
}

SEC("cgroup_skb/ingress")
int ingress(struct __sk_buff* skb) {
    __u32 ifindex = skb->ifindex;
    if (ifindex == 1) return 1;
    __u32 uid = tagged_uid(bpf_get_socket_cookie(skb), bpf_get_socket_uid(skb));
    bool subject;
    __u32 rules = rules_for(uid, &subject);
    if (!subject || !rules) return 1;
    struct fw_path path = {.ifindex = ifindex};
    if (!(rules & FW_RULE_BLOCK_ALL) && !network_blocked(uid, rules, &path)) return 1;
    struct l4_info info = {};
    bool parsed = parse_l4(skb, &info, false);
    // A blocked app still hears back from what its allow rules let it reach.
    if ((rules & FW_SCOPE_ALLOWS) && parsed && scope_allows(uid, rules, &info, &path)) return 1;
    count(FW_C_INGRESS_DROP);
    note_refusal(uid, rules, FW_REFUSAL_IN, &info, parsed, &path);
    return 0;
}

// IPv4-mapped IPv6 addresses are taken as the IPv4 address.
static __always_inline void connect_info(struct bpf_sock_addr* ctx, bool v6,
                                         struct l4_info* info) {
    info->protocol = ctx->protocol;
    info->port = __builtin_bswap16((__u16)ctx->user_port);
    if (!v6) {
        info->addr[0] = ctx->user_ip4;
    } else if (ctx->user_ip6[0] == 0 && ctx->user_ip6[1] == 0 &&
               ctx->user_ip6[2] == __builtin_bswap32(0xffff)) {
        info->addr[0] = ctx->user_ip6[3];
    } else {
        info->v6 = true;
        info->addr[0] = ctx->user_ip6[0];
        info->addr[1] = ctx->user_ip6[1];
        info->addr[2] = ctx->user_ip6[2];
        info->addr[3] = ctx->user_ip6[3];
    }
}

static __always_inline int connect_verdict(struct bpf_sock_addr* ctx, bool v6) {
    __u32 owner_uid = bpf_get_current_uid_gid();
    __u32 uid = tagged_uid(bpf_get_socket_cookie(ctx), owner_uid);
    bool subject;
    __u32 rules = rules_for(uid, &subject);
    if (!subject) return 1;
    struct l4_info info = {};
    connect_info(ctx, v6, &info);
    // A UDP socket pointed at port 0 only learns its route, as Android's lookups do to see which
    // address families work. What it sends still goes through egress.
    if (info.protocol == IPPROTO_UDP && !info.port) return 1;
    struct fw_path path = {.mark = ctx->sk->mark, .owner_uid = owner_uid, .connect = true};
    if ((rules & FW_SCOPE_ALLOWS) && scope_allows(uid, rules, &info, &path)) return 1;
    // Loopback isn't any network's: only the rules for addresses and ports apply to it, unless
    // the app is kept off it.
    bool off = cut_off(FW_REFUSAL_CONNECT, rules, &info, &path);
    bool blocked =
            (off && ((rules & FW_RULE_BLOCK_ALL) || network_blocked(uid, rules, &path))) ||
            ((rules & FW_SCOPE_BLOCKS) && scope_blocks(uid, rules, &info, &path, NULL));
    if (!blocked) {
        __u32 user = uid / AID_USER_OFFSET;
        __u32 user_scope = FW_USER_SCOPE | user;
        __u32 uflags = user_flags_of(user);
        if ((uflags & FW_SCOPE_ALLOWS) && scope_allows(user_scope, uflags, &info, &path)) {
            return 1;
        }
        blocked =
                (uflags & FW_SCOPE_BLOCKS) && scope_blocks(user_scope, uflags, &info, &path, NULL);
        if (!blocked) blocked = lists_block(uid, rules, user_scope, uflags, &info);
    }
    if (!blocked) return 1;
    count(FW_C_CONNECT_DENY);
    note_refusal(uid, rules, FW_REFUSAL_CONNECT, &info, true, &path);
    return 0;
}

SEC("cgroup/connect4")
int connect4(struct bpf_sock_addr* ctx) {
    return connect_verdict(ctx, false);
}

SEC("cgroup/connect6")
int connect6(struct bpf_sock_addr* ctx) {
    return connect_verdict(ctx, true);
}

LICENSE("Apache 2.0");
