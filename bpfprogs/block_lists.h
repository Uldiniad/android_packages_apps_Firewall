/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

// Included once, by firewall.c, after the rules for addresses.
#pragma once

// Lists of addresses and domains, for an app or for all of a user's apps, each list in a slot.
// Domains are decided by netd's lookup check from the lists' files; the programs check the
// addresses, after every rule.

// The slots of the lists each scope subscribes to, as bits.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, FW_UID_RULES_SIZE);
} scope_lists SEC(".maps");

// Valued with the slots of the lists that hold the range, or a range around it.
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct fw_ip4_key);
    __type(value, __u64);
    __uint(max_entries, FW_IP_RULES_SIZE);
} list_ip4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct fw_ip6_key);
    __type(value, __u64);
    __uint(max_entries, FW_IP_RULES_SIZE);
} list_ip6 SEC(".maps");

// The generation of each slot's file of domains, for netd's lookup check; 0 is none.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, FW_LIST_SLOTS);
} list_files SEC(".maps");

static __always_inline __u64 list_slots(__u32 scope) {
    __u64* slots = bpf_map_lookup_elem(&scope_lists, &scope);
    return slots ? *slots : 0;
}

// The slots of the address lists that hold the far end.
static __always_inline __u64 lists_holding(const struct l4_info* info) {
    __u64* held;
    if (info->v6) {
        struct fw_ip6_key key = {.prefixlen = 128};
        __builtin_memcpy(key.addr, info->addr, sizeof(key.addr));
        held = bpf_map_lookup_elem(&list_ip6, &key);
    } else {
        struct fw_ip4_key key = {.prefixlen = 32};
        __builtin_memcpy(key.addr, &info->addr[0], sizeof(key.addr));
        held = bpf_map_lookup_elem(&list_ip4, &key);
    }
    return held ? *held : 0;
}

// Whether a list the app or its user subscribes to holds the far end.
static __always_inline bool lists_block(__u32 uid, __u32 rules, __u32 user_scope, __u32 uflags,
                                        const struct l4_info* info) {
    if ((rules & FW_RULE_NO_LISTS) || !((rules | uflags) & FW_SCOPE_LISTS)) return false;
    __u64 slots = 0;
    if (rules & FW_SCOPE_LISTS) slots |= list_slots(uid);
    if (uflags & FW_SCOPE_LISTS) slots |= list_slots(user_scope);
    return slots && (lists_holding(info) & slots);
}

// The FW_REFUSED_* bits of the lists that hold the far end: the app's and its user's.
static __always_inline __u32 list_reasons(__u32 uid, __u32 rules, __u32 user_scope,
                                          __u32 uflags, const struct l4_info* info) {
    if ((rules & FW_RULE_NO_LISTS) || !((rules | uflags) & FW_SCOPE_LISTS)) return 0;
    __u64 held = lists_holding(info);
    __u32 reasons = 0;
    if ((rules & FW_SCOPE_LISTS) && (held & list_slots(uid))) reasons |= FW_REFUSED_LIST;
    if ((uflags & FW_SCOPE_LISTS) && (held & list_slots(user_scope))) {
        reasons |= FW_REFUSED_USER_LIST;
    }
    return reasons;
}
