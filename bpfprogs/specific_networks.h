/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

// Included once, by firewall.c, after the core's maps and helpers.
#pragma once

// The slots of the specific networks apps with FW_RULE_NAMED_NETWORKS are blocked or allowed on.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, __u32);
    __type(value, struct fw_named_networks);
    __uint(max_entries, FW_UID_RULES_SIZE);
} uid_networks SEC(".maps");

static __always_inline struct fw_named_networks* named_networks_of(__u32 uid, __u32 rules) {
    return (rules & FW_RULE_NAMED_NETWORKS) ? bpf_map_lookup_elem(&uid_networks, &uid) : NULL;
}
