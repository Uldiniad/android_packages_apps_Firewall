/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

// Included once, by firewall.c, after the core's maps and helpers.
#pragma once

// Refusals for the service to log: every one counted here, and reported at once the first time
// and then at most once a minute, so a refused flood can't swamp the service.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, FW_REFUSALS_SIZE);
} refusals SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct fw_refusal_key);
    __type(value, struct fw_refusal_stats);
    __uint(max_entries, FW_REFUSAL_STATS_SIZE);
} refusal_stats SEC(".maps");

// Every rule that refuses the far end, worked out again only when a refusal is reported.
static __always_inline __u32 refusal_reasons(__u32 rules, __u8 direction,
                                             const struct l4_info* info,
                                             const struct fw_path* path) {
    __u32 reasons = 0;
    if (cut_off(direction, rules, info, path)) {
        if (rules & FW_RULE_BLOCK_ALL) reasons |= FW_REFUSED_ALL;
        // Apps kept off loopback are blocked on it as on a network.
        if ((direction != FW_REFUSAL_CONNECT && path->ifindex == 1) ||
            network_blocked(rules, path)) {
            reasons |= FW_REFUSED_NETWORK;
        }
    }
    return reasons;
}

// Counts a refusal, and reports it the first time and then at most once a minute.
static __always_inline void note_refusal(__u32 uid, __u32 rules, __u8 direction,
                                         const struct l4_info* info,
                                         const struct fw_path* path) {
    struct fw_refusal_key key = {.uid = uid, .direction = direction, .protocol = info->protocol,
                                 .v6 = info->v6, .port = info->port};
    __builtin_memcpy(key.addr, info->addr, sizeof(key.addr));
    __u64 now = bpf_ktime_get_boot_ns();
    struct fw_refusal_stats* stats = bpf_map_lookup_elem(&refusal_stats, &key);
    if (!stats) {
        struct fw_refusal_stats first = {.first_ns = now};
        bpf_map_update_elem(&refusal_stats, &key, &first, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&refusal_stats, &key);
        if (!stats) return;
    }
    __sync_fetch_and_add(&stats->count, 1);
    stats->last_ns = now;
    if (stats->reported_ns && now - stats->reported_ns < FW_NS_PER_MINUTE) return;
    stats->reported_ns = now;
    stats->reasons = refusal_reasons(rules, direction, info, path);
    // If the buffer is full, the count stays here for the service to collect.
    struct fw_refusal* event = bpf_ringbuf_reserve(&refusals, sizeof(*event), 0);
    if (!event) return;
    event->key = key;
    event->unused = 0;
    event->stats = *stats;
    bpf_ringbuf_submit(event, 0);
}

