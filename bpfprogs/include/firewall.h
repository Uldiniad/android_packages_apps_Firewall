/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#define FW_BPF_DIR "/sys/fs/bpf/firewall/"
#define FW_MAP_PATH(name) FW_BPF_DIR "map_firewall_" name
#define FW_PROG_PATH(name) FW_BPF_DIR "prog_firewall_" name

#define FW_UID_RULES_SIZE 20000
#define FW_IFACE_SIZE 1024
#define FW_NET_SIZE 1024
#define FW_NET_ID_MASK 0xffff
#define FW_MARK_EXPLICIT (1u << 16)
#define FW_MARK_PROTECTED_FROM_VPN (1u << 17)
#define FW_VPN_RANGES 32
#define FW_IP_RULES_SIZE 262144
#define FW_PORT_RULES_SIZE 16384
#define FW_USERS_SIZE 256
// Addresses of allowed domains' answers, recently used ones kept when it fills.
#define FW_LEARNED_SIZE 8192
#define FW_DOMAIN_RULES_SIZE 262144
#define FW_REFUSALS_SIZE 65536
#define FW_REFUSAL_STATS_SIZE 8192
#define FW_NS_PER_MINUTE (60ULL * 1000 * 1000 * 1000)
#define FW_FNV_OFFSET 0xcbf29ce484222325ULL
#define FW_FNV_PRIME 0x100000001b3ULL

#define FW_RULE_BLOCK_ALL (1u << 0)
#define FW_RULE_BLOCK_WIFI (1u << 1)
#define FW_RULE_BLOCK_CELLULAR (1u << 2)
#define FW_RULE_BLOCK_VPN (1u << 3)
#define FW_RULE_BLOCK_OTHER (1u << 4)
#define FW_RULE_BLOCK_DNS (1u << 5)
#define FW_RULE_TRANSPORTS \
    (FW_RULE_BLOCK_WIFI | FW_RULE_BLOCK_CELLULAR | FW_RULE_BLOCK_VPN | FW_RULE_BLOCK_OTHER)
// Set for apps with no network left that Connectivity can't keep to themselves on loopback.
#define FW_RULE_NO_LOOPBACK (1u << 18)
#define FW_RULE_BLOCK_METERED (1u << 16)
#define FW_RULE_BLOCK_ROAMING (1u << 17)
#define FW_RULE_NETWORKS (FW_RULE_TRANSPORTS | FW_RULE_BLOCK_METERED | FW_RULE_BLOCK_ROAMING)

// Rules for addresses, domains and ports belong to a scope: an app's uid, or a user with
// FW_USER_SCOPE set. Which kinds a scope has is kept with an app's rules and in user_flags, so
// scopes without them skip the lookups.
#define FW_USER_SCOPE (1u << 31)
#define FW_SCOPE_IP_BLOCKS (1u << 8)
#define FW_SCOPE_IP_ALLOWS (1u << 9)
#define FW_SCOPE_PORT_BLOCKS (1u << 10)
#define FW_SCOPE_PORT_ALLOWS (1u << 11)
#define FW_SCOPE_DOMAINS (1u << 12)
#define FW_SCOPE_LEARNED (1u << 13)
// Some of the scope's rules are limited to networks, by its limits in scope_limits.
#define FW_SCOPE_LIMITS (1u << 14)
#define FW_SCOPE_ALLOWS (FW_SCOPE_IP_ALLOWS | FW_SCOPE_PORT_ALLOWS | FW_SCOPE_LEARNED)
#define FW_SCOPE_BLOCKS (FW_SCOPE_IP_BLOCKS | FW_SCOPE_PORT_BLOCKS)
// The DNS-over-HTTPS servers browsers switch to on their own, by address and by name, which apps
// under domain rules may not reach, as their own DNS.
#define FW_DOH_SCOPE (FW_USER_SCOPE | 0x7fffffffu)

// A domain matches its own bits; a parent domain matches only its subdomain bits.
#define FW_DOMAIN_BLOCK (1u << 0)
#define FW_DOMAIN_BLOCK_SUBDOMAINS (1u << 1)
#define FW_DOMAIN_ALLOW (1u << 2)
#define FW_DOMAIN_ALLOW_SUBDOMAINS (1u << 3)
#define FW_PORT_BLOCK (1u << 0)
#define FW_PORT_ALLOW (1u << 1)

// Limit 0 is every network; any other limit applies on networks with any of its only bits, if it
// has some, and none of its except bits. Rule entries hold bits per limit: one for addresses and
// learned answers, a pair of FW_PORT_* bits for ports and a nibble of FW_DOMAIN_* bits for domains.
#define FW_LIMITS 16
#define FW_LIMITS_SIZE 4096

enum fw_counter {
    FW_C_EGRESS_DROP_ALL,
    FW_C_EGRESS_DROP_TRANSPORT,
    FW_C_EGRESS_DROP_IP,
    FW_C_EGRESS_DROP_DNS,
    FW_C_INGRESS_DROP,
    FW_C_CONNECT_DENY,
    FW_C_DNS_SEEN,
    FW_C_EGRESS_DROP_DOMAIN,
    FW_C_EGRESS_DROP_PORT,
    FW_C_ALLOWED_BY_RULE,
    FW_COUNTER_MAX,
};

// Why the BPF programs refused, as bits: every rule that matched, the app's own apart from those
// for all of its user's apps.
#define FW_REFUSED_ALL (1u << 0)
#define FW_REFUSED_NETWORK (1u << 1)
#define FW_REFUSED_ADDRESS (1u << 2)
#define FW_REFUSED_PORT (1u << 3)
#define FW_REFUSED_DNS (1u << 4)
#define FW_REFUSED_USER_ADDRESS (1u << 5)
#define FW_REFUSED_USER_PORT (1u << 6)
#define FW_REFUSED_USER_DNS (1u << 7)

enum fw_refusal_direction {
    FW_REFUSAL_CONNECT,
    FW_REFUSAL_OUT,
    FW_REFUSAL_IN,
};

// An app's refusals one way to or from one far end. The far end's address and port are as sent,
// an IPv4 address in addr[0].
struct fw_refusal_key {
    __u32 uid;
    __u8 direction;
    __u8 protocol;
    __u8 v6;
    __u8 unused;
    __u16 port;
    __u16 unused2;
    __u32 addr[4];
};

// Every refusal is counted; the reasons are worked out when it's reported. Times are boot times.
struct fw_refusal_stats {
    __u64 count;
    __u64 first_ns;
    __u64 last_ns;
    __u64 reported_ns;
    __u32 reasons;
    __u32 unused;
};

// A report to the service: the first refusal of a key, then at most one a minute.
struct fw_refusal {
    struct fw_refusal_key key;
    __u32 unused;
    struct fw_refusal_stats stats;
};

struct fw_vpn_range {
    __u32 start;
    __u32 end;
    __u32 net_id;
};

// The scope leads the key and counts towards prefixlen.
struct fw_scope_ip4_key {
    __u32 prefixlen;
    __u32 scope;
    __u8 addr[4];
};

struct fw_scope_ip6_key {
    __u32 prefixlen;
    __u32 scope;
    __u8 addr[16];
};

struct fw_scope_domain_key {
    __u32 scope;
    __u32 pad;
    __u64 hash;
};

// A prefix of ports, which ranges of ports are made of: the scope and protocol match whole, then
// prefixlen - FW_PORT_PREFIX_BITS bits of the port, high byte first. protocol is IPPROTO_TCP,
// IPPROTO_UDP, or 0 for both.
struct fw_port_key {
    __u32 prefixlen;
    __u32 scope;
    __u8 protocol;
    __u8 port[2];
    __u8 pad;
};
#define FW_PORT_PREFIX_BITS (32 + 8)

// IPv4 addresses are IPv4-mapped.
struct fw_learned_key {
    __u32 scope;
    __u8 addr[16];
};

struct fw_limits {
    __u64 only[FW_LIMITS];
    __u64 except[FW_LIMITS];
};

// Shared with netd's lookup check, so both decide alike.
#define FW_INLINE static inline __attribute__((always_inline))

// Whether the app's switches block it on the network, whose bits are the rule bits that block it:
// its transport, and whether it is metered or roaming.
FW_INLINE bool fw_network_blocked(__u32 rules, __u64 net) {
    return rules & (__u32)net & FW_RULE_NETWORKS;
}

// 1 if x isn't 0, without a branch; the barrier keeps the compiler from making it one.
FW_INLINE __u64 fw_nonzero(__u64 x) {
    __u64 bits = x | (0 - x);
    asm volatile("" : "+r"(bits));
    return bits >> 63;
}

// The scope's limits that apply on the network, as bits. Branch-free, so the verifier walks one
// path through it whatever the limits are.
FW_INLINE __u32 fw_limits_on(const struct fw_limits* limits, __u64 net) {
    __u32 on = 1;
    if (!limits) return on;
#pragma clang loop unroll(full)
    for (int i = 1; i < FW_LIMITS; i++) {
        __u64 only = limits->only[i];
        __u64 except = limits->except[i];
        __u64 applies = fw_nonzero(only | except) &
                        ((1 - fw_nonzero(only)) | fw_nonzero(net & only)) &
                        (1 - fw_nonzero(net & except));
        on |= (__u32)applies << i;
    }
    return on;
}

// The FW_PORT_* bits a port entry has under the limits on.
FW_INLINE __u32 fw_port_bits_on(__u32 bits, __u32 on) {
    __u32 pairs = on & 0xffff;
    pairs = (pairs | (pairs << 8)) & 0x00ff00ff;
    pairs = (pairs | (pairs << 4)) & 0x0f0f0f0f;
    pairs = (pairs | (pairs << 2)) & 0x33333333;
    pairs = (pairs | (pairs << 1)) & 0x55555555;
    bits &= pairs | (pairs << 1);
    bits |= bits >> 16;
    bits |= bits >> 8;
    bits |= bits >> 4;
    bits |= bits >> 2;
    return bits & (FW_PORT_BLOCK | FW_PORT_ALLOW);
}

// What a domain entry gives a name per limit: the name's own entry its bits, a parent's its
// subdomain bits. Leaves FW_DOMAIN_BLOCK and FW_DOMAIN_ALLOW in each nibble.
FW_INLINE __u64 fw_domain_match(__u64 bits, bool whole_name) {
    return (whole_name ? bits : bits >> 1) & 0x5555555555555555ULL;
}

// The FW_DOMAIN_BLOCK and FW_DOMAIN_ALLOW bits of a match under the limits on.
FW_INLINE __u32 fw_domain_bits_on(__u64 match, __u32 on) {
    __u64 nibbles = on & 0xffff;
    nibbles = (nibbles | (nibbles << 24)) & 0x000000ff000000ffULL;
    nibbles = (nibbles | (nibbles << 12)) & 0x000f000f000f000fULL;
    nibbles = (nibbles | (nibbles << 6)) & 0x0303030303030303ULL;
    nibbles = (nibbles | (nibbles << 3)) & 0x1111111111111111ULL;
    match &= nibbles * 0xf;
    match |= match >> 32;
    match |= match >> 16;
    match |= match >> 8;
    match |= match >> 4;
    return match & (FW_DOMAIN_BLOCK | FW_DOMAIN_ALLOW);
}
