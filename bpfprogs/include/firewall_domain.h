/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdint.h>

#include <string_view>
#include <vector>

#include "firewall.h"

// The domain list keys of a name and of each parent domain, top-level domain first.
inline std::vector<uint64_t> fw_domain_suffix_hashes(std::string_view domain) {
    std::vector<uint64_t> labels;
    uint64_t hash = FW_FNV_OFFSET;
    bool inLabel = false;
    for (char c : domain) {
        if (c == '.') {
            if (inLabel) labels.push_back(hash);
            hash = FW_FNV_OFFSET;
            inLabel = false;
            continue;
        }
        if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        hash = (hash ^ static_cast<uint8_t>(c)) * FW_FNV_PRIME;
        inLabel = true;
    }
    if (inLabel) labels.push_back(hash);
    std::vector<uint64_t> suffixes;
    uint64_t suffix = FW_FNV_OFFSET;
    for (auto it = labels.rbegin(); it != labels.rend(); ++it) {
        suffix = (suffix ^ *it) * FW_FNV_PRIME;
        suffixes.push_back(suffix);
    }
    return suffixes;
}

// The domain list key of a whole name.
inline uint64_t fw_domain_hash(std::string_view domain) {
    std::vector<uint64_t> suffixes = fw_domain_suffix_hashes(domain);
    return suffixes.empty() ? FW_FNV_OFFSET : suffixes.back();
}
