/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#define LOG_TAG "Firewall"

#include "firewall_lookup.h"

#include <string.h>

#include <utility>
#include <vector>

#include <bpf/BpfMap.h>
#include <log/log.h>
#include <private/android_filesystem_config.h>

#include "block_lists.h"
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

// The limits that hold for a lookup on the network. It knows no port yet: allow rules with a port
// let it through, and block rules with a port leave it to the connections.
struct LimitsOn {
    uint32_t allows;
    uint32_t blocks;
};

LimitsOn limitsOn(const LookupMaps& maps, uint32_t scope, uint32_t flags, uint64_t net) {
    if (!(flags & FW_SCOPE_LIMITS)) return {1, 1};
    auto limits = maps.scopeLimits.readValue(scope);
    if (!limits.ok()) return {1, 1};
    uint32_t on = fw_limits_on(&*limits, net, ~0u);
    return {on, on & ~limits->ported};
}

bool networkBlocked(const LookupMaps& maps, uint32_t uid, uint32_t rules, uint64_t net) {
    if (!(rules & FW_RULE_NAMED_NETWORKS)) return fw_network_blocked(rules, nullptr, net);
    auto named = maps.uidNetworks.readValue(uid);
    return fw_network_blocked(rules, named.ok() ? &*named : nullptr, net);
}

bool isAppUid(uid_t uid) {
    return uid % AID_USER_OFFSET >= AID_APP_START;
}

uint64_t networkOf(const LookupMaps& maps, unsigned netId) {
    auto bits = maps.netTransport.readValue(netId & FW_NET_ID_MASK);
    return bits.ok() ? *bits : 0;
}

// Which domain rule decides a name for the uid: its own rules come first, then its user's.
enum class Decision { kNone, kAppAllows, kAppBlocks, kUserAllows, kUserBlocks, kListBlocks };

// Whether a list the app or its user subscribes to blocks the name.
bool listsBlock(uid_t uid, uint32_t rules, uint32_t user, uint32_t userFlags,
                const std::vector<uint64_t>& suffixes) {
    if (rules & FW_RULE_NO_LISTS) return false;
    uint64_t slots = 0;
    if (rules & FW_SCOPE_LISTS) slots |= listSlots(uid);
    if (userFlags & FW_SCOPE_LISTS) slots |= listSlots(FW_USER_SCOPE | user);
    return slots && listsHold(slots, suffixes);
}

Decision decide(const LookupMaps& maps, uid_t uid, const base::Result<uint32_t>& rules,
                uint64_t net, const std::vector<uint64_t>& suffixes) {
    if (rules.ok() && (*rules & FW_SCOPE_DOMAINS)) {
        uint64_t match = domainMatch(maps, uid, suffixes);
        LimitsOn on = limitsOn(maps, uid, *rules, net);
        if (fw_domain_bits_on(match, on.allows) & FW_DOMAIN_ALLOW) return Decision::kAppAllows;
        if ((fw_domain_bits_on(match, on.blocks) & FW_DOMAIN_BLOCK) || dohServer(maps, suffixes)) {
            return Decision::kAppBlocks;
        }
    } else if (!rules.ok() && !isAppUid(uid)) {
        // Without rules of their own, only apps follow their user's rules.
        return Decision::kNone;
    }
    uint32_t user = uid / AID_USER_OFFSET;
    auto flags = maps.userFlags.readValue(user);
    uint32_t userFlags = flags.ok() ? *flags : 0;
    if (userFlags & FW_SCOPE_DOMAINS) {
        uint32_t scope = FW_USER_SCOPE | user;
        uint64_t match = domainMatch(maps, scope, suffixes);
        LimitsOn on = limitsOn(maps, scope, userFlags, net);
        if (fw_domain_bits_on(match, on.allows) & FW_DOMAIN_ALLOW) return Decision::kUserAllows;
        if ((fw_domain_bits_on(match, on.blocks) & FW_DOMAIN_BLOCK) || dohServer(maps, suffixes)) {
            return Decision::kUserBlocks;
        }
    }
    if (listsBlock(uid, rules.ok() ? *rules : 0, user, userFlags, suffixes)) {
        return Decision::kListBlocks;
    }
    return Decision::kNone;
}

bool allows(Decision decision) {
    return decision == Decision::kAppAllows || decision == Decision::kUserAllows;
}

bool blocks(Decision decision) {
    return decision == Decision::kAppBlocks || decision == Decision::kUserBlocks ||
           decision == Decision::kListBlocks;
}

// Lets the app reach the addresses of an answer one of whose names its allow rules cover, and
// keeps it from them on the ports its block rules name.
void learn(LookupMaps& maps, uid_t uid, const base::Result<uint32_t>& rules,
           const std::vector<std::vector<uint64_t>>& names, const in6_addr* addresses,
           size_t count) {
    if (count == 0) return;
    constexpr uint32_t kLearned = FW_SCOPE_LEARNED | FW_SCOPE_LEARNED_BLOCKS;
    std::vector<std::pair<uint32_t, uint32_t>> scopes;
    if (rules.ok() && (*rules & kLearned)) scopes.emplace_back(uid, *rules);
    if (rules.ok() || isAppUid(uid)) {
        uint32_t user = uid / AID_USER_OFFSET;
        auto flags = maps.userFlags.readValue(user);
        if (flags.ok() && (*flags & kLearned)) scopes.emplace_back(FW_USER_SCOPE | user, *flags);
    }
    for (const auto& [scope, flags] : scopes) {
        // The limits under which the scope's rules cover a name, whichever network the lookup
        // went over: the packets the app sends next are checked on their own network.
        uint32_t portBlocks = 0;
        if (flags & FW_SCOPE_LEARNED_BLOCKS) {
            auto read = maps.scopeLimits.readValue(scope);
            if (read.ok()) portBlocks = read->ported;
        }
        uint32_t limits = 0;
        for (const std::vector<uint64_t>& suffixes : names) {
            uint64_t match = domainMatch(maps, scope, suffixes);
            for (int i = 0; i < FW_LIMITS; i++) {
                uint64_t bits = match >> (4 * i);
                if (bits & FW_DOMAIN_ALLOW) limits |= 1u << i;
                if ((bits & FW_DOMAIN_BLOCK) && (portBlocks & (1u << i))) {
                    limits |= 1u << (FW_LEARNED_BLOCKS_SHIFT + i);
                }
            }
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

}  // namespace

bool allowsLookup(uid_t uid, unsigned netId, const char* name) {
    const LookupMaps& maps = lookupMaps();
    // As in the BPF programs: root and the system server are never subject.
    if (!maps.ready || uid == AID_ROOT || uid == AID_SYSTEM) return true;
    std::vector<uint64_t> suffixes;
    if (name != nullptr) suffixes = fw_domain_suffix_hashes(name);
    uint64_t net = networkOf(maps, netId);
    auto rules = maps.uidRules.readValue(uid);
    Decision decision = decide(maps, uid, rules, net, suffixes);
    if (decision == Decision::kAppAllows) return true;
    if (rules.ok() && ((*rules & (FW_RULE_BLOCK_ALL | FW_RULE_BLOCK_DNS)) ||
                       networkBlocked(maps, uid, *rules, net))) {
        return false;
    }
    return !blocks(decision);
}

bool allowsAnswer(uid_t uid, unsigned netId, const char* name, const char* const* cnames,
                  size_t cnameCount, const in6_addr* addresses, size_t count) {
    LookupMaps& maps = lookupMaps();
    if (!maps.ready || name == nullptr || uid == AID_ROOT || uid == AID_SYSTEM) return true;
    uint64_t net = networkOf(maps, netId);
    auto rules = maps.uidRules.readValue(uid);
    std::vector<std::vector<uint64_t>> names = {fw_domain_suffix_hashes(name)};
    for (size_t i = 0; i < cnameCount; i++) names.push_back(fw_domain_suffix_hashes(cnames[i]));
    bool allowed = false;
    bool blocked = false;
    for (const std::vector<uint64_t>& suffixes : names) {
        Decision decision = decide(maps, uid, rules, net, suffixes);
        allowed |= allows(decision);
        blocked |= blocks(decision);
    }
    if (blocked && !allowed) return false;
    learn(maps, uid, rules, names, addresses, count);
    return true;
}

}  // namespace android::firewall
