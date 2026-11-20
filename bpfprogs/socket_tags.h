/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

// Included once, by firewall.c, after the core's maps and helpers.
#pragma once

// Connectivity's socket tags, reused from its pinned map. A tag with another app's uid can only
// be set with UPDATE_DEVICE_STATS, e.g. by DownloadManager for the app it downloads for.
struct uid_tag {
    __u32 uid;
    __u32 tag;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct uid_tag);
    __uint(max_entries, 10000);
} cookie_tag_map SEC(".maps");

static __always_inline __u32 tagged_uid(__u64 cookie, __u32 owner_uid) {
    struct uid_tag* tag = cookie ? bpf_map_lookup_elem(&cookie_tag_map, &cookie) : NULL;
    return tag ? tag->uid : owner_uid;
}

