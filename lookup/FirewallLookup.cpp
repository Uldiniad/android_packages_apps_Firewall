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
    BpfMapRO<fw_hotspot_address, uint32_t> hotspotAddresses;
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
                   m->learned.init(FW_MAP_PATH("learned")).ok() &&
                   m->hotspotAddresses.init(FW_MAP_PATH("hotspot_addresses")).ok();
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

// Apps follow their user's rules, and so do the devices on the phone's hotspot, whose lookups
// dnsmasq makes.
bool followsUserRules(uid_t uid) {
    return isAppUid(uid) || uid % AID_USER_OFFSET == AID_DNS_TETHER;
}

// A device on the phone's hotspot with rules of its own, whose lookups dnsmasq makes as its.
bool isHotspotDevice(uid_t uid) {
    return uid >= FW_HOTSPOT_DEVICE_UID_START &&
           uid < FW_HOTSPOT_DEVICE_UID_START + FW_HOTSPOT_DEVICES;
}

// A uid whose own rules decide before its user's.
struct Scope {
    uint32_t uid;
    uint32_t rules;
};

// The uid's own rules, and for a hotspot device then those for all the devices, kept on dnsmasq's
// uid, each deciding in turn.
std::vector<Scope> ownScopes(const LookupMaps& maps, uid_t uid) {
    std::vector<Scope> scopes;
    if (auto rules = maps.uidRules.readValue(uid); rules.ok()) scopes.push_back({uid, *rules});
    if (isHotspotDevice(uid)) {
        auto devices = maps.uidRules.readValue(AID_DNS_TETHER);
        if (devices.ok()) scopes.push_back({AID_DNS_TETHER, *devices});
    }
    return scopes;
}

uint64_t networkOf(const LookupMaps& maps, unsigned netId) {
    auto bits = maps.netTransport.readValue(netId & FW_NET_ID_MASK);
    return bits.ok() ? *bits : 0;
}

// Which domain rule decides a name for the uid: its own rules come first, then its user's.
enum class Decision { kNone, kAppAllows, kAppBlocks, kUserAllows, kUserBlocks, kListBlocks };

// Whether a list the app or its user subscribes to blocks the name.
bool listsBlock(const std::vector<Scope>& scopes, uint32_t user, uint32_t userFlags,
                const std::vector<uint64_t>& suffixes) {
    uint64_t slots = 0;
    for (const Scope& scope : scopes) {
        if (scope.rules & FW_RULE_NO_LISTS) return false;
        if (scope.rules & FW_SCOPE_LISTS) slots |= listSlots(scope.uid);
    }
    if (userFlags & FW_SCOPE_LISTS) slots |= listSlots(FW_USER_SCOPE | user);
    return slots && listsHold(slots, suffixes);
}

// What a scope's own domain rules say of the name; kNone leaves it to the next.
Decision ownDecision(const LookupMaps& maps, const Scope& scope, uint64_t net,
                     const std::vector<uint64_t>& suffixes) {
    if (!(scope.rules & FW_SCOPE_DOMAINS)) return Decision::kNone;
    uint64_t match = domainMatch(maps, scope.uid, suffixes);
    LimitsOn on = limitsOn(maps, scope.uid, scope.rules, net);
    if (fw_domain_bits_on(match, on.allows) & FW_DOMAIN_ALLOW) return Decision::kAppAllows;
    if ((fw_domain_bits_on(match, on.blocks) & FW_DOMAIN_BLOCK) || dohServer(maps, suffixes)) {
        return Decision::kAppBlocks;
    }
    return Decision::kNone;
}

uint32_t userFlagsOf(const LookupMaps& maps, uid_t uid) {
    auto flags = maps.userFlags.readValue(uid / AID_USER_OFFSET);
    return flags.ok() ? *flags : 0;
}

// Whether the rules for all of the user's apps block the app as its user is locked. Devices on
// the phone's hotspot follow the rules for all apps, but not the phone's lock.
bool lockedUser(uid_t uid, const std::vector<Scope>& scopes, uint32_t userFlags) {
    if (!isAppUid(uid) || !(userFlags & FW_USER_BLOCK_LOCKED) || !(userFlags & FW_USER_LOCKED)) {
        return false;
    }
    for (const Scope& scope : scopes) {
        if (scope.rules & FW_RULE_ALLOW_LOCKED) return false;
    }
    return true;
}

// Whether the user's lockdown refuses the uid's lookups, before any rule, as the BPF programs refuse
// its traffic: an app's, or the main user's hotspot devices', but those let through at their own
// level or for all the devices.
bool lockedDown(uid_t uid, const std::vector<Scope>& scopes, uint32_t userFlags) {
    if (!(userFlags & FW_USER_LOCKDOWN) || (!followsUserRules(uid) && !isHotspotDevice(uid))) {
        return false;
    }
    for (const Scope& scope : scopes) {
        if (scope.rules & FW_RULE_ALLOW_LOCKDOWN) return false;
    }
    return true;
}

// What the user's domain rules, their block while locked and the lists say of the name, after the
// uid's own rules.
Decision userDecision(const LookupMaps& maps, uid_t uid, const std::vector<Scope>& scopes,
                      uint64_t net, const std::vector<uint64_t>& suffixes) {
    if (scopes.empty() && !followsUserRules(uid)) return Decision::kNone;
    uint32_t user = uid / AID_USER_OFFSET;
    uint32_t userFlags = userFlagsOf(maps, uid);
    bool blocked = false;
    if (userFlags & FW_SCOPE_DOMAINS) {
        uint32_t scope = FW_USER_SCOPE | user;
        uint64_t match = domainMatch(maps, scope, suffixes);
        LimitsOn on = limitsOn(maps, scope, userFlags, net);
        if (fw_domain_bits_on(match, on.allows) & FW_DOMAIN_ALLOW) return Decision::kUserAllows;
        blocked = (fw_domain_bits_on(match, on.blocks) & FW_DOMAIN_BLOCK) ||
                  dohServer(maps, suffixes);
    }
    if (blocked || lockedUser(uid, scopes, userFlags)) return Decision::kUserBlocks;
    if (listsBlock(scopes, user, userFlags, suffixes)) return Decision::kListBlocks;
    return Decision::kNone;
}

Decision decide(const LookupMaps& maps, uid_t uid, const std::vector<Scope>& scopes, uint64_t net,
                const std::vector<uint64_t>& suffixes) {
    for (const Scope& scope : scopes) {
        Decision own = ownDecision(maps, scope, net, suffixes);
        if (own != Decision::kNone) return own;
    }
    return userDecision(maps, uid, scopes, net, suffixes);
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
void learn(LookupMaps& maps, uid_t uid, const std::vector<Scope>& own,
           const std::vector<std::vector<uint64_t>>& names, const in6_addr* addresses,
           size_t count) {
    if (count == 0) return;
    constexpr uint32_t kLearned = FW_SCOPE_LEARNED | FW_SCOPE_LEARNED_BLOCKS;
    std::vector<std::pair<uint32_t, uint32_t>> scopes;
    for (const Scope& scope : own) {
        if (scope.rules & kLearned) scopes.emplace_back(scope.uid, scope.rules);
    }
    if (!own.empty() || followsUserRules(uid)) {
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
    std::vector<Scope> scopes = ownScopes(maps, uid);
    uint32_t userFlags = userFlagsOf(maps, uid);
    if (lockedDown(uid, scopes, userFlags)) return false;
    bool locked = userFlags & FW_USER_LOCKED;
    // Each scope's allow rules come before its switches, and both before the next scope's.
    for (const Scope& scope : scopes) {
        Decision own = ownDecision(maps, scope, net, suffixes);
        if (own == Decision::kAppAllows) return true;
        if ((scope.rules & (FW_RULE_BLOCK_ALL | FW_RULE_BLOCK_DNS)) ||
            (locked && (scope.rules & FW_RULE_BLOCK_LOCKED)) ||
            networkBlocked(maps, scope.uid, scope.rules, net) || own == Decision::kAppBlocks) {
            return false;
        }
    }
    return !blocks(userDecision(maps, uid, scopes, net, suffixes));
}

bool allowsAnswer(uid_t uid, unsigned netId, const char* name, const char* const* cnames,
                  size_t cnameCount, const in6_addr* addresses, size_t count) {
    LookupMaps& maps = lookupMaps();
    if (!maps.ready || name == nullptr || uid == AID_ROOT || uid == AID_SYSTEM) return true;
    uint64_t net = networkOf(maps, netId);
    std::vector<Scope> scopes = ownScopes(maps, uid);
    std::vector<std::vector<uint64_t>> names = {fw_domain_suffix_hashes(name)};
    for (size_t i = 0; i < cnameCount; i++) names.push_back(fw_domain_suffix_hashes(cnames[i]));
    bool allowed = false;
    bool blocked = false;
    for (const std::vector<uint64_t>& suffixes : names) {
        Decision decision = decide(maps, uid, scopes, net, suffixes);
        allowed |= allows(decision);
        blocked |= blocks(decision);
    }
    if (blocked && !allowed) return false;
    learn(maps, uid, scopes, names, addresses, count);
    return true;
}

uid_t tetheringClientUid(const in6_addr* address) {
    const LookupMaps& maps = lookupMaps();
    if (!maps.ready) return static_cast<uid_t>(-1);
    fw_hotspot_address key;
    memcpy(key.addr, address, sizeof(key.addr));
    auto uid = maps.hotspotAddresses.readValue(key);
    return uid.ok() ? *uid : static_cast<uid_t>(-1);
}

}  // namespace android::firewall
