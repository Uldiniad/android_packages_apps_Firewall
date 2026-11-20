/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#define LOG_TAG "Firewall"

#include "firewall_lookup.h"

#include <bpf/BpfMap.h>
#include <log/log.h>
#include <private/android_filesystem_config.h>

#include "firewall.h"

namespace android::firewall {

namespace {

using bpf::BpfMapRO;

struct LookupMaps {
    BpfMapRO<uint32_t, uint32_t> uidRules;
    BpfMapRO<uint32_t, uint64_t> netTransport;
    bool ready = false;
};

// Opened once. Many resolver threads look up at once, and BPF maps need no lock.
LookupMaps& lookupMaps() {
    static LookupMaps* const maps = [] {
        auto* m = new LookupMaps();
        m->ready = m->uidRules.init(FW_MAP_PATH("uid_rules")).ok() &&
                   m->netTransport.init(FW_MAP_PATH("net_transport")).ok();
        if (!m->ready) ALOGE("lookup maps unavailable");
        return m;
    }();
    return *maps;
}

}  // namespace

bool allowsLookup(uid_t uid, unsigned netId, const char* /*name*/) {
    const LookupMaps& maps = lookupMaps();
    // As in the BPF programs: root and the system server are never subject.
    if (!maps.ready || uid == AID_ROOT || uid == AID_SYSTEM) return true;
    auto netBits = maps.netTransport.readValue(netId & FW_NET_ID_MASK);
    uint64_t net = netBits.ok() ? *netBits : 0;
    auto rules = maps.uidRules.readValue(uid);
    if (!rules.ok()) return true;
    return !(*rules & FW_RULE_BLOCK_ALL) && !fw_network_blocked(*rules, net);
}

void learnAnswer(uid_t /*uid*/, const char* /*name*/, const in6_addr* /*addresses*/,
                 size_t /*count*/) {}

}  // namespace android::firewall
