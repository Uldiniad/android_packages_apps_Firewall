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
