/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

// Included once, by firewall.c, after the core's maps and helpers.
#pragma once

// Rules for addresses, ports and domains, per app and for all of a user's apps, each limited to
// networks if wanted. Domains are decided by netd's lookup check; the programs see the addresses
// the answers to allowed domains gave, which netd writes to learned.

// The kinds of rules each user's scope has, as an app's are kept with its rules.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, FW_USERS_SIZE);
} user_flags SEC(".maps");

// Valued with the limits under which rules name the range, including those of wider ranges.
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct fw_scope_ip4_key);
    __type(value, __u32);
    __uint(max_entries, FW_IP_RULES_SIZE);
} ip4_block SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct fw_scope_ip6_key);
    __type(value, __u32);
    __uint(max_entries, FW_IP_RULES_SIZE);
} ip6_block SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct fw_scope_ip4_key);
    __type(value, __u32);
    __uint(max_entries, FW_IP_RULES_SIZE);
} ip4_allow SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct fw_scope_ip6_key);
    __type(value, __u32);
    __uint(max_entries, FW_IP_RULES_SIZE);
} ip6_allow SEC(".maps");

// Valued with FW_PORT_* bits per limit. The service splits overlapping ranges into prefixes that
// don't overlap, so a port matches one prefix per scope and protocol.
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct fw_port_key);
    __type(value, __u32);
    __uint(max_entries, FW_PORT_RULES_SIZE);
} port_rules SEC(".maps");

// Answers to lookups of allowed domains, which netd writes before the app gets them, valued with
// the limits under which the domains are allowed.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct fw_learned_key);
    __type(value, __u32);
    __uint(max_entries, FW_LEARNED_SIZE);
} learned SEC(".maps");

// The network limits of scopes with FW_SCOPE_LIMITS.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, __u32);
    __type(value, struct fw_limits);
    __uint(max_entries, FW_LIMITS_SIZE);
} scope_limits SEC(".maps");

// Valued with FW_DOMAIN_* bits per limit, for netd's lookup check: names are decided at the
// resolver, as AOSP and Cilium decide them, and the programs only see the addresses.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct fw_scope_domain_key);
    __type(value, __u64);
    __uint(max_entries, FW_DOMAIN_RULES_SIZE);
} domain_rules SEC(".maps");

static __always_inline __u32 user_flags_of(__u32 user) {
    __u32* flags = bpf_map_lookup_elem(&user_flags, &user);
    return flags ? *flags : 0;
}

__u32 fw_scope_limits(__u32 scope, __u64 net);

__attribute__((noinline)) __u32 fw_scope_limits(__u32 scope, __u64 net) {
    return fw_limits_on(bpf_map_lookup_elem(&scope_limits, &scope), net);
}

static __always_inline __u32 limits_on(__u32 scope, __u32 flags, const struct fw_path* path) {
    if (!(flags & FW_SCOPE_LIMITS)) return 1;
    return fw_scope_limits(scope, path_network(path));
}

// Whether an entry, with a bit per limit, holds on the path's network.
static __always_inline bool holds(__u32 bits, __u32 scope, __u32 flags,
                                  const struct fw_path* path) {
    if (bits & 1) return true;
    return (bits & ~1u) && (bits & limits_on(scope, flags, path));
}

static __always_inline bool listed(void* trie4, void* trie6, __u32 scope, __u32 flags,
                                   const struct l4_info* info, const struct fw_path* path) {
    __u32* limits;
    if (info->v6) {
        struct fw_scope_ip6_key key = {.prefixlen = 32 + 128, .scope = scope};
        __builtin_memcpy(key.addr, info->addr, sizeof(key.addr));
        limits = bpf_map_lookup_elem(trie6, &key);
    } else {
        struct fw_scope_ip4_key key = {.prefixlen = 32 + 32, .scope = scope};
        __builtin_memcpy(key.addr, &info->addr[0], sizeof(key.addr));
        limits = bpf_map_lookup_elem(trie4, &key);
    }
    return limits && holds(*limits, scope, flags, path);
}

static __always_inline __u32 port_bits(__u32 scope, __u32 flags, const struct l4_info* info,
                                       const struct fw_path* path) {
    if (!info->port) return 0;
    struct fw_port_key key = {.prefixlen = FW_PORT_PREFIX_BITS + 16, .scope = scope,
                              .protocol = info->protocol,
                              .port = {info->port >> 8, info->port & 0xff}};
    __u32 bits = 0;
    __u32* value = bpf_map_lookup_elem(&port_rules, &key);
    if (value) bits |= *value;
    key.protocol = 0;
    value = bpf_map_lookup_elem(&port_rules, &key);
    if (value) bits |= *value;
    if (!(bits & ~(FW_PORT_BLOCK | FW_PORT_ALLOW))) return bits;
    return fw_port_bits_on(bits, limits_on(scope, flags, path));
}

static __always_inline bool was_learned(__u32 scope, __u32 flags, const struct l4_info* info,
                                        const struct fw_path* path) {
    struct fw_learned_key key = {.scope = scope};
    if (info->v6) {
        __builtin_memcpy(key.addr, info->addr, sizeof(key.addr));
    } else {
        key.addr[10] = 0xff;
        key.addr[11] = 0xff;
        __builtin_memcpy(&key.addr[12], &info->addr[0], 4);
    }
    __u32* limits = bpf_map_lookup_elem(&learned, &key);
    return limits && holds(*limits, scope, flags, path);
}

// Whether the scope's allow rules cover the far end, by address, port or learned answer.
static __always_inline bool scope_allows(__u32 scope, __u32 flags, const struct l4_info* info,
                                         const struct fw_path* path) {
    if ((flags & FW_SCOPE_IP_ALLOWS) &&
        listed(&ip4_allow, &ip6_allow, scope, flags, info, path)) {
        return true;
    }
    if ((flags & FW_SCOPE_PORT_ALLOWS) &&
        (port_bits(scope, flags, info, path) & FW_PORT_ALLOW)) {
        return true;
    }
    return (flags & FW_SCOPE_LEARNED) && was_learned(scope, flags, info, path);
}

// Whether the scope's block rules cover the far end, and, if asked, the counter of the one that
// does.
static __always_inline bool scope_blocks(__u32 scope, __u32 flags, const struct l4_info* info,
                                         const struct fw_path* path, __u32* counter) {
    if ((flags & FW_SCOPE_IP_BLOCKS) &&
        listed(&ip4_block, &ip6_block, scope, flags, info, path)) {
        if (counter) *counter = FW_C_EGRESS_DROP_IP;
        return true;
    }
    if ((flags & FW_SCOPE_PORT_BLOCKS) &&
        (port_bits(scope, flags, info, path) & FW_PORT_BLOCK)) {
        if (counter) *counter = FW_C_EGRESS_DROP_PORT;
        return true;
    }
    return false;
}

