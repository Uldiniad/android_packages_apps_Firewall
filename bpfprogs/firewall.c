/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include <android_bpf_defs.h>
#include <linux/in.h>
// Bionic's copy of the header names the struct __kernel_udphdr, as Connectivity also works around.
#define __kernel_udphdr udphdr
#include <private/android_filesystem_config.h>
#include <stdbool.h>

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
// at every call that inlines them.
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

// Where a packet or connection goes. Its network is looked up only where a switch needs it, so
// the verifier doesn't carry it down every path, which it can't afford.
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

static __always_inline bool network_blocked(__u32 rules, const struct fw_path* path) {
    if (!(rules & FW_RULE_NETWORKS)) return false;
    return fw_network_blocked(rules, path_network(path));
}

// The far end of a packet or connection: the destination going out, the source coming in.
struct l4_info {
    __u32 l4_offset;
    __u8 protocol;
    __u16 port;
    bool v6;
    __u32 addr[4];
};

#include "socket_tags.h"

// 127.0.0.0/8 and ::1, with IPv4-mapped addresses taken as IPv4.
static __always_inline bool is_loopback(const struct l4_info* info) {
    if (!info->v6) return (__builtin_bswap32(info->addr[0]) >> 24) == 127;
    return !info->addr[0] && !info->addr[1] && !info->addr[2] &&
           info->addr[3] == __builtin_bswap32(1);
}

// Whether a packet out is dropped, and the counter it's dropped under.
static __always_inline bool egress_drop(__u32 rules, const struct fw_path* path, __u32* counter) {
    bool blocked_all = rules & FW_RULE_BLOCK_ALL;
    // Apps kept off loopback are blocked on it as on a network.
    bool blocked_here = path->ifindex == 1 || network_blocked(rules, path);
    *counter = blocked_all ? FW_C_EGRESS_DROP_ALL : FW_C_EGRESS_DROP_TRANSPORT;
    return blocked_all || blocked_here;
}

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
    __u32 counter;
    if (!egress_drop(rules, &path, &counter)) return 1;
    count(counter);
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
    if (!(rules & FW_RULE_BLOCK_ALL) && !network_blocked(rules, &path)) return 1;
    count(FW_C_INGRESS_DROP);
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
    // Loopback isn't any network's, so it is refused only to apps kept off it.
    bool off = !is_loopback(&info) || (rules & FW_RULE_NO_LOOPBACK);
    bool blocked = off && ((rules & FW_RULE_BLOCK_ALL) || network_blocked(rules, &path));
    if (!blocked) return 1;
    count(FW_C_CONNECT_DENY);
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
