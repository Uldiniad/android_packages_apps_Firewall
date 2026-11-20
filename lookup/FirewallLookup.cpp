/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#define LOG_TAG "Firewall"

#include "firewall_lookup.h"

#include <string.h>

#include <vector>

#include <bpf/BpfMap.h>
#include <log/log.h>
#include <private/android_filesystem_config.h>

#include "firewall.h"
#include "firewall_domain.h"

namespace android::firewall {

namespace {

using bpf::BpfMap;
using bpf::BpfMapRO;

struct LookupMaps {
    BpfMapRO<uint32_t, uint32_t> uidRules;
    BpfMapRO<uint32_t, fw_named_networks> uidNetworks;
    BpfMapRO<uint32_t, uint32_t> userFlags;
    BpfMapRO<uint32_t, uint64_t> netTransport;
    BpfMapRO<uint32_t, fw_limits> scopeLimits;
    BpfMapRO<fw_scope_domain_key, uint64_t> domainRules;
    BpfMap<fw_learned_key, uint32_t> learned;
    bool ready = false;
};

// Opened once. Many resolver threads look up at once, and BPF maps need no lock.
LookupMaps& lookupMaps() {
    static LookupMaps* const maps = [] {
        auto* m = new LookupMaps();
        m->ready = m->uidRules.init(FW_MAP_PATH("uid_rules")).ok() &&
                   m->uidNetworks.init(FW_MAP_PATH("uid_networks")).ok() &&
                   m->userFlags.init(FW_MAP_PATH("user_flags")).ok() &&
                   m->netTransport.init(FW_MAP_PATH("net_transport")).ok() &&
                   m->scopeLimits.init(FW_MAP_PATH("scope_limits")).ok() &&
                   m->domainRules.init(FW_MAP_PATH("domain_rules")).ok() &&
                   m->learned.init(FW_MAP_PATH("learned")).ok();
        if (!m->ready) ALOGE("lookup maps unavailable");
        return m;
    }();
    return *maps;
}

// The FW_DOMAIN_BLOCK and FW_DOMAIN_ALLOW bits per limit that the scope's domain rules give the
// name, as the BPF program finds them.
uint64_t domainMatch(const LookupMaps& maps, uint32_t scope,
                     const std::vector<uint64_t>& suffixes) {
    uint64_t match = 0;
    fw_scope_domain_key key = {.scope = scope};
    for (size_t i = 0; i < suffixes.size(); i++) {
        key.hash = suffixes[i];
        auto bits = maps.domainRules.readValue(key);
        if (bits.ok()) match |= fw_domain_match(*bits, i + 1 == suffixes.size());
    }
    return match;
}

// A DNS-over-HTTPS server browsers switch to on their own, which apps under domain rules may not
// look up, as they may not use it.
bool dohServer(const LookupMaps& maps, const std::vector<uint64_t>& suffixes) {
    return fw_domain_bits_on(domainMatch(maps, FW_DOH_SCOPE, suffixes), 1) & FW_DOMAIN_BLOCK;
}

uint32_t limitsOn(const LookupMaps& maps, uint32_t scope, uint32_t flags, uint64_t net) {
    if (!(flags & FW_SCOPE_LIMITS)) return 1;
    auto limits = maps.scopeLimits.readValue(scope);
    return fw_limits_on(limits.ok() ? &*limits : nullptr, net);
}

bool networkBlocked(const LookupMaps& maps, uint32_t uid, uint32_t rules, uint64_t net) {
    if (!(rules & FW_RULE_NAMED_NETWORKS)) return fw_network_blocked(rules, nullptr, net);
    auto named = maps.uidNetworks.readValue(uid);
    return fw_network_blocked(rules, named.ok() ? &*named : nullptr, net);
}

bool isAppUid(uid_t uid) {
    return uid % AID_USER_OFFSET >= AID_APP_START;
}

}  // namespace

bool allowsLookup(uid_t uid, unsigned netId, const char* name) {
    const LookupMaps& maps = lookupMaps();
    // As in the BPF programs: root and the system server are never subject.
    if (!maps.ready || uid == AID_ROOT || uid == AID_SYSTEM) return true;
    std::vector<uint64_t> suffixes;
    if (name != nullptr) suffixes = fw_domain_suffix_hashes(name);
    auto netBits = maps.netTransport.readValue(netId & FW_NET_ID_MASK);
    uint64_t net = netBits.ok() ? *netBits : 0;
    auto rules = maps.uidRules.readValue(uid);
    if (rules.ok()) {
        uint32_t app = (*rules & FW_SCOPE_DOMAINS)
                ? fw_domain_bits_on(domainMatch(maps, uid, suffixes),
                                    limitsOn(maps, uid, *rules, net))
                : 0;
        if (app & FW_DOMAIN_ALLOW) return true;
        if (*rules & (FW_RULE_BLOCK_ALL | FW_RULE_BLOCK_DNS)) return false;
        if (networkBlocked(maps, uid, *rules, net)) return false;
        if (app & FW_DOMAIN_BLOCK) return false;
        if ((*rules & FW_SCOPE_DOMAINS) && dohServer(maps, suffixes)) return false;
    } else if (!isAppUid(uid)) {
        // Without rules of their own, only apps follow their user's rules.
        return true;
    }
    uint32_t user = uid / AID_USER_OFFSET;
    auto flags = maps.userFlags.readValue(user);
    if (!flags.ok() || !(*flags & FW_SCOPE_DOMAINS)) return true;
    uint32_t scope = FW_USER_SCOPE | user;
    uint32_t match = fw_domain_bits_on(domainMatch(maps, scope, suffixes),
                                       limitsOn(maps, scope, *flags, net));
    return (match & FW_DOMAIN_ALLOW) || !((match & FW_DOMAIN_BLOCK) || dohServer(maps, suffixes));
}

void learnAnswer(uid_t uid, const char* name, const in6_addr* addresses, size_t count) {
    LookupMaps& maps = lookupMaps();
    if (!maps.ready || name == nullptr || count == 0 || uid == AID_ROOT || uid == AID_SYSTEM) {
        return;
    }
    std::vector<uint32_t> scopes;
    auto rules = maps.uidRules.readValue(uid);
    if (rules.ok() && (*rules & FW_SCOPE_LEARNED)) scopes.push_back(uid);
    if (rules.ok() || isAppUid(uid)) {
        uint32_t user = uid / AID_USER_OFFSET;
        auto flags = maps.userFlags.readValue(user);
        if (flags.ok() && (*flags & FW_SCOPE_LEARNED)) scopes.push_back(FW_USER_SCOPE | user);
    }
    if (scopes.empty()) return;
    std::vector<uint64_t> suffixes = fw_domain_suffix_hashes(name);
    for (uint32_t scope : scopes) {
        // The limits under which the scope's allow rules cover the name, whichever network the
        // lookup went over: the packets the app sends next are checked on their own network.
        uint64_t match = domainMatch(maps, scope, suffixes);
        uint32_t limits = 0;
        for (int i = 0; i < FW_LIMITS; i++) {
            if ((match >> (4 * i)) & FW_DOMAIN_ALLOW) limits |= 1u << i;
        }
        if (!limits) continue;
        for (size_t i = 0; i < count; i++) {
            fw_learned_key key = {.scope = scope};
            memcpy(key.addr, &addresses[i], sizeof(key.addr));
            auto known = maps.learned.readValue(key);
            uint32_t value = limits | (known.ok() ? *known : 0);
            if (auto result = maps.learned.writeValue(key, value, BPF_ANY); !result.ok()) {
                ALOGE("learn: %s", result.error().message().c_str());
            }
        }
    }
}

}  // namespace android::firewall
