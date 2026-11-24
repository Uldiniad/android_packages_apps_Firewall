/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <string>
#include <vector>

#include <BpfSyscallWrappers.h>
#include <android-base/file.h>
#include <android-base/unique_fd.h>
#include <benchmark/benchmark.h>
#include <cutils/qtaguid.h>

#include "firewall.h"
#include "firewall_domain.h"
#include "firewall_lookup.h"
#include "tun_interface.h"

using android::base::unique_fd;
using android::bpf::bpf;
using android::bpf::deleteMapEntry;
using android::bpf::mapRetrieveRW;
using android::bpf::retrieveProgram;
using android::bpf::writeToMapEntry;

namespace {

// Same test uid as firewall_bpf_test: an app uid in a user that doesn't exist.
constexpr uint32_t kTestUser = 99;
constexpr uint32_t kTestUid = kTestUser * 100000 + 10999;
constexpr uint32_t kUserScope = FW_USER_SCOPE | kTestUser;
constexpr int kEntries = 100000;

struct RunStats {
    uint64_t count = 0;
    uint64_t ns = 0;
};

RunStats runStats(const char* pin) {
    unique_fd prog(retrieveProgram(pin));
    bpf_prog_info info = {};
    bpf_attr attr = {};
    attr.info.bpf_fd = prog.get();
    attr.info.info_len = sizeof(info);
    attr.info.info = reinterpret_cast<uint64_t>(&info);
    if (prog.get() < 0 || bpf(BPF_OBJ_GET_INFO_BY_FD, &attr)) return {};
    return {info.run_cnt, info.run_time_ns};
}

class FirewallBench : public benchmark::Fixture {
  public:
    void SetUp(benchmark::State& state) override {
        mStatsWas = android::base::ReadFileToString(kStats, &mStatsValue) ? mStatsValue : "0";
        android::base::WriteStringToFile("1", kStats);
        mUidRules.reset(mapRetrieveRW(FW_MAP_PATH("uid_rules")));
        mUserFlags.reset(mapRetrieveRW(FW_MAP_PATH("user_flags")));
        mIp6.reset(mapRetrieveRW(FW_MAP_PATH("ip6_block")));
        mIp6Allow.reset(mapRetrieveRW(FW_MAP_PATH("ip6_allow")));
        mDns.reset(mapRetrieveRW(FW_MAP_PATH("domain_rules")));
        mLimits.reset(mapRetrieveRW(FW_MAP_PATH("scope_limits")));
        if (mUidRules.get() < 0 || mUserFlags.get() < 0 || mIp6.get() < 0 ||
            mIp6Allow.get() < 0 || mDns.get() < 0 || mLimits.get() < 0 || mTun.init()) {
            state.SkipWithError("Firewall maps or test interface unavailable");
            return;
        }
        uint32_t rules = 0;
        writeToMapEntry(mUidRules, &kTestUid, &rules, BPF_ANY);
        mSocket.reset(socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0));
        qtaguid_tagSocket(mSocket.get(), 0, kTestUid);
        int ifindex = mTun.ifindex();
        setsockopt(mSocket.get(), IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex, sizeof(ifindex));
        mTo = {.sin6_family = AF_INET6, .sin6_port = htons(9)};
        inet_pton(AF_INET6, "ff02::1", &mTo.sin6_addr);
    }

    void TearDown(benchmark::State&) override {
        for (uint32_t i = 0; i < mIp6Entries; i++) {
            fw_scope_ip6_key key = ip6Key(i);
            deleteMapEntry(mIp6, &key);
        }
        for (uint32_t i = 0; i < mDnsEntries; i++) {
            fw_scope_domain_key key = dnsKey(i);
            deleteMapEntry(mDns, &key);
        }
        fw_scope_ip6_key multicast = multicastKey();
        deleteMapEntry(mIp6Allow, &multicast);
        deleteMapEntry(mLimits, &kUserScope);
        uint32_t none = 0;
        writeToMapEntry(mUserFlags, &kTestUser, &none, BPF_EXIST);
        deleteMapEntry(mUidRules, &kTestUid);
        mSocket.reset();
        mTun.destroy();
        android::base::WriteStringToFile(mStatsWas, kStats);
    }

  protected:
    static constexpr const char* kStats = "/proc/sys/kernel/bpf_stats_enabled";

    static fw_scope_ip6_key ip6Key(uint32_t i) {
        fw_scope_ip6_key key = {.prefixlen = 32 + 128, .scope = kUserScope,
                                .addr = {0x20, 0x01, 0x0d, 0xb8}};
        memcpy(&key.addr[12], &i, sizeof(i));
        return key;
    }

    static fw_scope_ip6_key multicastKey() {
        fw_scope_ip6_key key = {.prefixlen = 32 + 128, .scope = kTestUid};
        inet_pton(AF_INET6, "ff02::1", key.addr);
        return key;
    }

    static fw_scope_domain_key dnsKey(uint32_t i) {
        return {.scope = kUserScope, .hash = fw_domain_hash("d" + std::to_string(i) + ".test")};
    }

    void addUserFlags(uint32_t flags) {
        uint32_t current = 0;
        android::bpf::findMapEntry(mUserFlags, &kTestUser, &current);
        current |= flags;
        writeToMapEntry(mUserFlags, &kTestUser, &current, BPF_ANY);
    }

    void fillIp6() {
        uint32_t value = 1;
        for (; mIp6Entries < kEntries; mIp6Entries++) {
            fw_scope_ip6_key key = ip6Key(mIp6Entries);
            writeToMapEntry(mIp6, &key, &value, BPF_ANY);
        }
        addUserFlags(FW_SCOPE_IP_BLOCKS);
    }

    void fillDns() {
        uint64_t value = FW_DOMAIN_BLOCK | FW_DOMAIN_BLOCK_SUBDOMAINS;
        for (; mDnsEntries < kEntries; mDnsEntries++) {
            fw_scope_domain_key key = dnsKey(mDnsEntries);
            writeToMapEntry(mDns, &key, &value, BPF_ANY);
        }
        addUserFlags(FW_SCOPE_DOMAINS);
    }

    void sendLoop(benchmark::State& state, int port, const std::vector<uint8_t>& payload) {
        mTo.sin6_port = htons(port);
        RunStats fw0 = runStats(FW_PROG_PATH("egress"));
        RunStats cs0 = runStats("/sys/fs/bpf/netd_shared/prog_netd_egress_stats");
        for (auto _ : state) {
            sendto(mSocket.get(), payload.data(), payload.size(), 0,
                   reinterpret_cast<sockaddr*>(&mTo), sizeof(mTo));
        }
        RunStats fw1 = runStats(FW_PROG_PATH("egress"));
        RunStats cs1 = runStats("/sys/fs/bpf/netd_shared/prog_netd_egress_stats");
        // Per-run kernel time of each egress program, including other traffic while it ran.
        if (fw1.count > fw0.count) state.counters["firewall_egress_ns"] =
                double(fw1.ns - fw0.ns) / double(fw1.count - fw0.count);
        if (cs1.count > cs0.count) state.counters["connectivity_egress_ns"] =
                double(cs1.ns - cs0.ns) / double(cs1.count - cs0.count);
    }

    unique_fd mUidRules, mUserFlags, mIp6, mIp6Allow, mDns, mLimits, mSocket;
    android::net::TunInterface mTun;
    sockaddr_in6 mTo = {};
    uint32_t mIp6Entries = 0, mDnsEntries = 0;
    std::string mStatsValue, mStatsWas;
};

BENCHMARK_DEFINE_F(FirewallBench, EgressEmptyLists)(benchmark::State& state) {
    sendLoop(state, 9, {1});
}

BENCHMARK_DEFINE_F(FirewallBench, Egress100kIp6Entries)(benchmark::State& state) {
    fillIp6();
    sendLoop(state, 9, {1});
}

// netd's check of a lookup for the resolver, against 100k domain rules for all apps.
BENCHMARK_DEFINE_F(FirewallBench, Lookup100kDomains)(benchmark::State& state) {
    fillDns();
    for (auto _ : state) {
        benchmark::DoNotOptimize(
                android::firewall::allowsLookup(kTestUid, 0, "www.example.test"));
    }
}

// The same with every network limit in use, half of them on for the lookup's network.
BENCHMARK_DEFINE_F(FirewallBench, Lookup100kDomainsAllLimits)(benchmark::State& state) {
    fillDns();
    fw_limits limits = {};
    for (int i = 1; i < FW_LIMITS; i++) {
        if (i % 2) {
            limits.only[i] = FW_RULE_BLOCK_WIFI;
        } else {
            limits.except[i] = FW_RULE_BLOCK_WIFI;
        }
    }
    writeToMapEntry(mLimits, &kUserScope, &limits, BPF_ANY);
    addUserFlags(FW_SCOPE_LIMITS);
    for (auto _ : state) {
        benchmark::DoNotOptimize(
                android::firewall::allowsLookup(kTestUid, 0, "www.example.test"));
    }
}

// A blocked app reaching the one address its allow rule lets through.
BENCHMARK_DEFINE_F(FirewallBench, EgressThroughAllowRule)(benchmark::State& state) {
    fw_scope_ip6_key key = multicastKey();
    uint32_t value = 1, rules = FW_RULE_BLOCK_ALL | FW_SCOPE_IP_ALLOWS;
    writeToMapEntry(mIp6Allow, &key, &value, BPF_ANY);
    writeToMapEntry(mUidRules, &kTestUid, &rules, BPF_ANY);
    sendLoop(state, 9, {1});
}

BENCHMARK_DEFINE_F(FirewallBench, ConnectThroughHook)(benchmark::State& state) {
    sockaddr_in6 to = {.sin6_family = AF_INET6, .sin6_port = htons(9)};
    inet_pton(AF_INET6, "2001:db8::1", &to.sin6_addr);
    // The raw syscall skips NetdClient's round trip to netd; a UDP socket can connect repeatedly.
    RunStats fw0 = runStats(FW_PROG_PATH("connect6"));
    RunStats cs0 = runStats("/sys/fs/bpf/netd_shared/prog_netd_connect6_inet6_connect");
    for (auto _ : state) {
        syscall(__NR_connect, mSocket.get(), reinterpret_cast<sockaddr*>(&to), sizeof(to));
    }
    RunStats fw1 = runStats(FW_PROG_PATH("connect6"));
    RunStats cs1 = runStats("/sys/fs/bpf/netd_shared/prog_netd_connect6_inet6_connect");
    if (fw1.count > fw0.count) state.counters["firewall_connect6_ns"] =
            double(fw1.ns - fw0.ns) / double(fw1.count - fw0.count);
    if (cs1.count > cs0.count) state.counters["connectivity_connect6_ns"] =
            double(cs1.ns - cs0.ns) / double(cs1.count - cs0.count);
}

BENCHMARK_DEFINE_F(FirewallBench, UidRuleUpdate)(benchmark::State& state) {
    uint32_t rules = 0;
    for (auto _ : state) {
        rules ^= FW_RULE_BLOCK_CELLULAR;
        writeToMapEntry(mUidRules, &kTestUid, &rules, BPF_ANY);
    }
}

BENCHMARK_REGISTER_F(FirewallBench, EgressEmptyLists);
BENCHMARK_REGISTER_F(FirewallBench, Egress100kIp6Entries);
BENCHMARK_REGISTER_F(FirewallBench, Lookup100kDomains);
BENCHMARK_REGISTER_F(FirewallBench, Lookup100kDomainsAllLimits);
BENCHMARK_REGISTER_F(FirewallBench, EgressThroughAllowRule);
BENCHMARK_REGISTER_F(FirewallBench, ConnectThroughHook);
BENCHMARK_REGISTER_F(FirewallBench, UidRuleUpdate);

}  // namespace

BENCHMARK_MAIN();
