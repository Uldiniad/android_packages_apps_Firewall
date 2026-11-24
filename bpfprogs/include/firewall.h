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
// Every user id Android gives out: an id times AID_USER_OFFSET fits an int.
#define FW_USERS_SIZE (0x7fffffff / AID_USER_OFFSET + 1)
// Addresses of allowed domains' answers, recently used ones kept when it fills.
#define FW_LEARNED_SIZE 8192
#define FW_DOMAIN_RULES_SIZE 262144
#define FW_LAN_SIZE 256
#define FW_REFUSALS_SIZE 65536
#define FW_REFUSAL_STATS_SIZE 8192
#define FW_LIST_SLOTS 64
#define FW_NS_PER_MINUTE (60ULL * 1000 * 1000 * 1000)
#define FW_FNV_OFFSET 0xcbf29ce484222325ULL
#define FW_FNV_PRIME 0x100000001b3ULL

#define FW_RULE_BLOCK_ALL (1u << 0)
#define FW_RULE_BLOCK_WIFI (1u << 1)
#define FW_RULE_BLOCK_CELLULAR (1u << 2)
#define FW_RULE_BLOCK_VPN (1u << 3)
#define FW_RULE_BLOCK_OTHER (1u << 4)
#define FW_RULE_BLOCK_DNS (1u << 5)
#define FW_RULE_NO_LAN (1u << 6)
#define FW_LAN_LOCAL 1
#define FW_LAN_DNS 2
#define FW_RULE_TRANSPORTS \
    (FW_RULE_BLOCK_WIFI | FW_RULE_BLOCK_CELLULAR | FW_RULE_BLOCK_VPN | FW_RULE_BLOCK_OTHER)
// Set for apps with choices for specific networks, kept in uid_networks.
#define FW_RULE_NAMED_NETWORKS (1u << 7)
// Set for apps with no network left that Connectivity can't keep to themselves on loopback.
#define FW_RULE_NO_LOOPBACK (1u << 18)
// Set for the firewall app, which lists never cover, so a bad one can't stop their updates.
#define FW_RULE_NO_LISTS (1u << 19)
#define FW_RULE_BLOCK_METERED (1u << 16)
#define FW_RULE_BLOCK_ROAMING (1u << 17)
#define FW_RULE_NETWORKS (FW_RULE_TRANSPORTS | FW_RULE_BLOCK_METERED | FW_RULE_BLOCK_ROAMING)

// A network's bits are the rule bits that block it: its transport, and whether it is metered or
// roaming. The high word holds the slot of the specific network it is, if rules name it.
#define FW_NET_SLOT_SHIFT 32

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
// The scope subscribes to lists, by the bits of their slots in scope_lists.
#define FW_SCOPE_LISTS (1u << 15)
// The scope blocks domains on a port, whose answers' addresses are learned for that port.
#define FW_SCOPE_LEARNED_BLOCKS (1u << 20)
// The scope has rules for connections others open to its apps, under the scope with
// FW_INCOMING_SCOPE set.
#define FW_SCOPE_INCOMING_BLOCKS (1u << 21)
#define FW_SCOPE_INCOMING_ALLOWS (1u << 22)
#define FW_SCOPE_INCOMING (FW_SCOPE_INCOMING_BLOCKS | FW_SCOPE_INCOMING_ALLOWS)
// In user_flags: the user's activity log is on, so what the programs let through is reported too.
#define FW_USER_LOG (1u << 23)
#define FW_INCOMING_SCOPE (1u << 30)
// A list's domains are in a file netd maps: FW_LISTS_DIR "<slot>-<generation>.names", which holds
// FW_LIST_NAMES_MAGIC, a count, and the sorted keys of fw_domain_hash with the subdomain bit.
#define FW_LISTS_DIR "/data/system/firewall_lists/"
#define FW_LIST_NAMES_MAGIC 0x3153454d414e4c46ULL
#define FW_SCOPE_ALLOWS \
    (FW_SCOPE_IP_ALLOWS | FW_SCOPE_PORT_ALLOWS | FW_SCOPE_LEARNED | FW_SCOPE_INCOMING_ALLOWS)
#define FW_SCOPE_BLOCKS (FW_SCOPE_IP_BLOCKS | FW_SCOPE_PORT_BLOCKS | FW_SCOPE_LEARNED_BLOCKS)
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
// has some, and none of its except bits, and to its port if it names one. Rule entries hold bits
// per limit: one for addresses and learned answers, a pair of FW_PORT_* bits for ports and a
// nibble of FW_DOMAIN_* bits for domains.
#define FW_LIMITS 16
#define FW_LIMITS_SIZE 4096
// The ports of a scope's limits that name one are port_rules entries under the scope with
// FW_LIMIT_PORTS_SCOPE set, valued with the limits whose port they are.
#define FW_LIMIT_PORTS_SCOPE (1u << 29)
// A learned answer's limits for block rules with a port, above those for allow rules.
#define FW_LEARNED_BLOCKS_SHIFT 16
// With a port, that the far end is on the local network, for incoming rules from there.
#define FW_AT_LOCAL_NETWORK (1u << 24)

enum fw_counter {
    FW_C_EGRESS_DROP_ALL,
    FW_C_EGRESS_DROP_TRANSPORT,
    FW_C_EGRESS_DROP_IP,
    FW_C_EGRESS_DROP_DNS,
    FW_C_INGRESS_DROP,
    FW_C_CONNECT_DENY,
    FW_C_DNS_SEEN,
    FW_C_EGRESS_DROP_DOMAIN,
    FW_C_EGRESS_DROP_LAN,
    FW_C_EGRESS_DROP_PORT,
    FW_C_ALLOWED_BY_RULE,
    FW_C_EGRESS_DROP_LIST,
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
#define FW_REFUSED_LAN (1u << 8)
#define FW_REFUSED_LIST (1u << 9)
#define FW_REFUSED_USER_LIST (1u << 10)
#define FW_REFUSED_DOMAIN (1u << 11)
#define FW_REFUSED_USER_DOMAIN (1u << 12)
#define FW_REFUSED_INCOMING (1u << 13)
#define FW_REFUSED_USER_INCOMING (1u << 14)

enum fw_refusal_direction {
    FW_REFUSAL_CONNECT,
    FW_REFUSAL_OUT,
    FW_REFUSAL_IN,
    // A connection others open to the app, whose port is the phone's.
    FW_REFUSAL_INCOMING,
};

// An app's refusals one way to or from one far end, or with its user's log on what was let
// through. The far end's address and port are as sent, an IPv4 address in addr[0].
struct fw_refusal_key {
    __u32 uid;
    __u8 direction;
    __u8 protocol;
    __u8 v6;
    __u8 allowed;
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

// A report to the service: the first refusal of a key, then at most one a minute, with the
// interface of the packet that made it, or for a connect, the network its socket goes out on.
struct fw_refusal {
    struct fw_refusal_key key;
    __u32 ifindex;
    __u32 net_id;
    struct fw_refusal_stats stats;
};

struct fw_vpn_range {
    __u32 start;
    __u32 end;
    __u32 net_id;
};

struct fw_ip4_key {
    __u32 prefixlen;
    __u8 addr[4];
};

struct fw_ip6_key {
    __u32 prefixlen;
    __u8 addr[16];
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

// The slots of the specific networks an app is blocked or allowed on.
struct fw_named_networks {
    __u32 block;
    __u32 allow;
};

struct fw_limits {
    __u64 only[FW_LIMITS];
    __u64 except[FW_LIMITS];
    // The limits that name a port, and those of them for senders on the local network.
    __u32 ported;
    __u32 local_network;
};

// Shared with netd's lookup check, so both decide alike.
#define FW_INLINE static inline __attribute__((always_inline))

// Whether the app's switches block it on the network. A choice for a specific network wins over
// the switches for the network's kind.
FW_INLINE bool fw_network_blocked(__u32 rules, const struct fw_named_networks* named, __u64 net) {
    __u32 slots = net >> FW_NET_SLOT_SHIFT;
    if (named && (named->allow & slots)) return false;
    return (rules & (__u32)net & FW_RULE_NETWORKS) || (named && (named->block & slots));
}

// 1 if x isn't 0, without a branch; the barrier keeps the compiler from making it one.
FW_INLINE __u64 fw_nonzero(__u64 x) {
    __u64 bits = x | (0 - x);
    asm volatile("" : "+r"(bits));
    return bits >> 63;
}

// The scope's limits that apply on the network, as bits. One that names a port also needs its bit
// in ports, the limits whose port is the packet's. Branch-free, so the verifier walks one path
// through it whatever the limits are.
FW_INLINE __u32 fw_limits_on(const struct fw_limits* limits, __u64 net, __u32 ports) {
    __u32 on = 1;
    if (!limits) return on;
    __u32 ported = limits->ported;
#pragma clang loop unroll(full)
    for (int i = 1; i < FW_LIMITS; i++) {
        __u64 only = limits->only[i];
        __u64 except = limits->except[i];
        __u64 applies = fw_nonzero(only | except | ((ported >> i) & 1)) &
                        ((1 - fw_nonzero(only)) | fw_nonzero(net & only)) &
                        (1 - fw_nonzero(net & except));
        on |= (__u32)applies << i;
    }
    return on & (~ported | ports);
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
