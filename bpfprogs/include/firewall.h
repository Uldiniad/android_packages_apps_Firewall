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
#define FW_REFUSALS_SIZE 65536
#define FW_REFUSAL_STATS_SIZE 8192
#define FW_NS_PER_MINUTE (60ULL * 1000 * 1000 * 1000)

#define FW_RULE_BLOCK_ALL (1u << 0)
#define FW_RULE_BLOCK_WIFI (1u << 1)
#define FW_RULE_BLOCK_CELLULAR (1u << 2)
#define FW_RULE_BLOCK_VPN (1u << 3)
#define FW_RULE_BLOCK_OTHER (1u << 4)
#define FW_RULE_TRANSPORTS \
    (FW_RULE_BLOCK_WIFI | FW_RULE_BLOCK_CELLULAR | FW_RULE_BLOCK_VPN | FW_RULE_BLOCK_OTHER)
// Set for apps with no network left that Connectivity can't keep to themselves on loopback.
#define FW_RULE_NO_LOOPBACK (1u << 18)
#define FW_RULE_BLOCK_METERED (1u << 16)
#define FW_RULE_BLOCK_ROAMING (1u << 17)
#define FW_RULE_NETWORKS (FW_RULE_TRANSPORTS | FW_RULE_BLOCK_METERED | FW_RULE_BLOCK_ROAMING)

enum fw_counter {
    FW_C_EGRESS_DROP_ALL,
    FW_C_EGRESS_DROP_TRANSPORT,
    FW_C_INGRESS_DROP,
    FW_C_CONNECT_DENY,
    FW_COUNTER_MAX,
};

// Why the BPF programs refused, as bits: every rule that matched.
#define FW_REFUSED_ALL (1u << 0)
#define FW_REFUSED_NETWORK (1u << 1)

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

// Shared with netd's lookup check, so both decide alike.
#define FW_INLINE static inline __attribute__((always_inline))

// Whether the app's switches block it on the network, whose bits are the rule bits that block it:
// its transport, and whether it is metered or roaming.
FW_INLINE bool fw_network_blocked(__u32 rules, __u64 net) {
    return rules & (__u32)net & FW_RULE_NETWORKS;
}
