/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

// Included once, by firewall.c, after the core's maps and helpers.
#pragma once

// Local subnets of the networks under a VPN, valued FW_LAN_LOCAL or FW_LAN_DNS.
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct fw_ip4_key);
    __type(value, __u32);
    __uint(max_entries, FW_LAN_SIZE);
} lan4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct fw_ip6_key);
    __type(value, __u32);
    __uint(max_entries, FW_LAN_SIZE);
} lan6 SEC(".maps");

// AOSP's local network check sees no LAN on a VPN, so a VPN app could reach it for others.
static __always_inline bool lan_via_vpn(__u32 ifindex, const struct l4_info* info) {
    if (((__u32)iface_network(ifindex) & FW_RULE_TRANSPORTS) != FW_RULE_BLOCK_VPN) return false;
    __u32* kind;
    if (info->v6) {
        struct fw_ip6_key key = {.prefixlen = 128};
        __builtin_memcpy(key.addr, info->addr, sizeof(key.addr));
        kind = bpf_map_lookup_elem(&lan6, &key);
    } else {
        struct fw_ip4_key key = {.prefixlen = 32};
        __builtin_memcpy(key.addr, &info->addr[0], sizeof(key.addr));
        kind = bpf_map_lookup_elem(&lan4, &key);
    }
    if (!kind) return false;
    bool dns = info->port == 53 || (info->port == 853 && info->protocol == IPPROTO_TCP);
    return !(*kind == FW_LAN_DNS && dns);
}

