/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include <BpfSyscallWrappers.h>
#include <android-base/unique_fd.h>
#include <cutils/qtaguid.h>
#include <gtest/gtest.h>

#include "firewall.h"
#include "firewall_lookup.h"
#include "tun_interface.h"

using android::base::unique_fd;
using android::bpf::bpf;
using android::bpf::deleteMapEntry;
using android::bpf::findMapEntry;
using android::bpf::mapRetrieveRW;
using android::bpf::retrieveProgram;
using android::bpf::writeToMapEntry;
using android::firewall::allowsLookup;
using android::net::TunInterface;

namespace {

// An app uid in a user that doesn't exist, so no real rules are touched. Tagging a root
// socket with it makes the firewall apply its rules.
constexpr uint32_t kTestUser = 99;
constexpr uint32_t kTestUid = kTestUser * 100000 + 10999;
constexpr uint32_t kTestNetId = 64999;
constexpr int kPort = 9;
constexpr const char* kCgroup = "/sys/fs/cgroup";

const std::vector<std::string> kMaps = {
        "uid_rules",
        "iface_transport",
        "net_transport",
        "vpn_ranges",
        "counters",
};
const std::vector<std::pair<std::string, bpf_attach_type>> kProgs = {
        {"egress", BPF_CGROUP_INET_EGRESS}, {"ingress", BPF_CGROUP_INET_INGRESS},
        {"connect4", BPF_CGROUP_INET4_CONNECT}, {"connect6", BPF_CGROUP_INET6_CONNECT}};

std::string mapPath(const std::string& name) { return FW_BPF_DIR "map_firewall_" + name; }
std::string progPath(const std::string& name) { return FW_BPF_DIR "prog_firewall_" + name; }

uint32_t progId(int fd) {
    bpf_prog_info info = {};
    bpf_attr attr = {};
    attr.info.bpf_fd = fd;
    attr.info.info_len = sizeof(info);
    attr.info.info = reinterpret_cast<uint64_t>(&info);
    return bpf(BPF_OBJ_GET_INFO_BY_FD, &attr) ? 0 : info.id;
}

// Unlike queryProgram(), returns every program attached with BPF_F_ALLOW_MULTI.
std::vector<uint32_t> attachedIds(int cgroupFd, bpf_attach_type type) {
    uint32_t ids[16] = {};
    bpf_attr attr = {};
    attr.query.target_fd = cgroupFd;
    attr.query.attach_type = type;
    attr.query.prog_ids = reinterpret_cast<uint64_t>(ids);
    attr.query.prog_cnt = 16;
    if (bpf(BPF_PROG_QUERY, &attr)) return {};
    return std::vector<uint32_t>(ids, ids + attr.query.prog_cnt);
}

class FirewallBpfTest : public ::testing::Test {
  protected:
    void SetUp() override {
        ASSERT_EQ(0u, getuid()) << "This test must run as root.";
        for (const auto& name : {
                     "uid_rules",
                     "iface_transport",
                     "net_transport",
             }) {
            mMaps[name].reset(mapRetrieveRW(mapPath(name).c_str()));
            ASSERT_LE(0, mMaps[name].get()) << name << ": " << strerror(errno);
        }
        ASSERT_EQ(0, mTun.init());
    }

    void TearDown() override {
        for (auto& [map, key] : mWritten) deleteMapEntry(mMaps[map], key.data());
        mTun.destroy();
    }

    template <typename K>
    void forget(const std::string& map, const K& key) {
        const auto* bytes = reinterpret_cast<const uint8_t*>(&key);
        mWritten.emplace_back(map, std::vector<uint8_t>(bytes, bytes + sizeof(key)));
    }

    template <typename K, typename V>
    void put(const std::string& map, const K& key, const V& value) {
        ASSERT_EQ(0, writeToMapEntry(mMaps[map], &key, &value, BPF_ANY)) << map;
        forget(map, key);
    }

    void setRules(uint32_t rules) { put("uid_rules", kTestUid, rules); }
    // The bits of the test interface's network, and of the test network.
    void setIfaceNetwork(uint64_t bits) {
        put("iface_transport", static_cast<uint32_t>(mTun.ifindex()), bits);
    }
    void setNetwork(uint64_t bits) { put("net_transport", kTestNetId, bits); }

    unique_fd testSocket(int family) {
        unique_fd fd(socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0));
        EXPECT_LE(0, fd.get());
        EXPECT_EQ(0, qtaguid_tagSocket(fd.get(), 0, kTestUid));
        return fd;
    }

    // Sends to ff02::1 out of the test interface; returns 0 or the errno of sendto().
    int sendMulticast(int port, const std::vector<uint8_t>& payload = {1}) {
        unique_fd fd = testSocket(AF_INET6);
        int ifindex = mTun.ifindex();
        setsockopt(fd.get(), IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex, sizeof(ifindex));
        sockaddr_in6 to = {.sin6_family = AF_INET6, .sin6_port = htons(port)};
        inet_pton(AF_INET6, "ff02::1", &to.sin6_addr);
        ssize_t sent = sendto(fd.get(), payload.data(), payload.size(), 0,
                              reinterpret_cast<sockaddr*>(&to), sizeof(to));
        return sent < 0 ? errno : 0;
    }

    // Whether a UDP packet to |port| came out of the test interface.
    bool tunSaw(int port) {
        uint8_t packet[1500];
        pollfd p = {.fd = mTun.getFdForTesting(), .events = POLLIN};
        while (poll(&p, 1, 1000) > 0) {
            ssize_t len = read(p.fd, packet, sizeof(packet));
            if (len >= 48 && (packet[0] >> 4) == 6 && packet[6] == IPPROTO_UDP &&
                ((packet[42] << 8) | packet[43]) == port) {
                return true;
            }
        }
        return false;
    }

    // Sends to 127.0.0.1; returns 0 or the errno of sendto().
    int sendLoopback() {
        unique_fd fd = testSocket(AF_INET);
        sockaddr_in lo = {.sin_family = AF_INET, .sin_port = htons(kPort)};
        lo.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ssize_t sent = sendto(fd.get(), "x", 1, 0, reinterpret_cast<sockaddr*>(&lo), sizeof(lo));
        return sent < 0 ? errno : 0;
    }
    // connect() on a socket marked with the test network; returns 0 or its errno.
    int connectOnTestNet(int family, const char* address, int port = kPort) {
        unique_fd fd = testSocket(family);
        uint32_t mark = kTestNetId | FW_MARK_EXPLICIT;
        setsockopt(fd.get(), SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
        sockaddr_storage to = {};
        socklen_t len;
        if (family == AF_INET) {
            auto* in = reinterpret_cast<sockaddr_in*>(&to);
            *in = {.sin_family = AF_INET, .sin_port = htons(port)};
            inet_pton(AF_INET, address, &in->sin_addr);
            len = sizeof(*in);
        } else {
            auto* in6 = reinterpret_cast<sockaddr_in6*>(&to);
            *in6 = {.sin6_family = AF_INET6, .sin6_port = htons(port)};
            inet_pton(AF_INET6, address, &in6->sin6_addr);
            len = sizeof(*in6);
        }
        return connect(fd.get(), reinterpret_cast<sockaddr*>(&to), len) ? errno : 0;
    }
    std::map<std::string, unique_fd> mMaps;
    std::vector<std::pair<std::string, std::vector<uint8_t>>> mWritten;
    TunInterface mTun;
};

TEST_F(FirewallBpfTest, MapsAndProgramsArePinned) {
    for (const auto& name : kMaps) EXPECT_EQ(0, access(mapPath(name).c_str(), F_OK)) << name;
    for (const auto& [name, type] : kProgs) {
        EXPECT_EQ(0, access(progPath(name).c_str(), F_OK)) << name;
    }
}

TEST_F(FirewallBpfTest, ProgramsAreAttachedNextToConnectivity) {
    unique_fd cgroup(open(kCgroup, O_DIRECTORY | O_RDONLY | O_CLOEXEC));
    ASSERT_LE(0, cgroup.get());
    for (const auto& [name, type] : kProgs) {
        unique_fd prog(retrieveProgram(progPath(name).c_str()));
        ASSERT_LE(0, prog.get()) << name;
        std::vector<uint32_t> ids = attachedIds(cgroup.get(), type);
        EXPECT_NE(ids.end(), std::find(ids.begin(), ids.end(), progId(prog.get()))) << name;
        // Connectivity's own program stays attached alongside ours.
        EXPECT_LE(2u, ids.size()) << name;
    }
}

TEST_F(FirewallBpfTest, BlockAllRefusesConnects) {
    setRules(FW_RULE_BLOCK_ALL);
    EXPECT_EQ(EPERM, connectOnTestNet(AF_INET, "198.51.100.1"));
    EXPECT_EQ(EPERM, connectOnTestNet(AF_INET6, "2001:db8::1"));
}

TEST_F(FirewallBpfTest, LoopbackIsBlockedOnlyForAppsKeptOffIt) {
    setNetwork(FW_RULE_BLOCK_CELLULAR);
    for (uint32_t rules : {FW_RULE_BLOCK_ALL, FW_RULE_BLOCK_CELLULAR}) {
        setRules(rules);
        EXPECT_NE(EPERM, connectOnTestNet(AF_INET, "127.0.0.1")) << rules;
        EXPECT_NE(EPERM, connectOnTestNet(AF_INET6, "::1")) << rules;
        EXPECT_EQ(0, sendLoopback()) << rules;
        setRules(rules | FW_RULE_NO_LOOPBACK);
        EXPECT_EQ(EPERM, connectOnTestNet(AF_INET, "127.0.0.1")) << rules;
        EXPECT_EQ(EPERM, connectOnTestNet(AF_INET6, "::1")) << rules;
        EXPECT_EQ(EPERM, sendLoopback()) << rules;
    }
}

TEST_F(FirewallBpfTest, UdpConnectsToPortZeroOnlyLearnTheirRoute) {
    setRules(FW_RULE_BLOCK_ALL);
    EXPECT_NE(EPERM, connectOnTestNet(AF_INET, "198.51.100.1", 0));
    EXPECT_NE(EPERM, connectOnTestNet(AF_INET6, "2001:db8::1", 0));
    EXPECT_EQ(EPERM, connectOnTestNet(AF_INET, "198.51.100.1"));
    // What the socket sends is still blocked.
    unique_fd fd = testSocket(AF_INET6);
    int ifindex = mTun.ifindex();
    setsockopt(fd.get(), IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex, sizeof(ifindex));
    sockaddr_in6 to = {.sin6_family = AF_INET6};
    inet_pton(AF_INET6, "ff02::1", &to.sin6_addr);
    ASSERT_EQ(0, connect(fd.get(), reinterpret_cast<sockaddr*>(&to), sizeof(to)));
    EXPECT_GT(0, send(fd.get(), "x", 1, 0));
    EXPECT_EQ(EPERM, errno);
}

TEST_F(FirewallBpfTest, TransportRuleUsesTheSocketsNetwork) {
    setNetwork(FW_RULE_BLOCK_CELLULAR);
    setRules(0);
    EXPECT_NE(EPERM, connectOnTestNet(AF_INET, "198.51.100.1"));
    setRules(FW_RULE_BLOCK_WIFI);
    EXPECT_NE(EPERM, connectOnTestNet(AF_INET, "198.51.100.1"));
    setRules(FW_RULE_BLOCK_CELLULAR);
    EXPECT_EQ(EPERM, connectOnTestNet(AF_INET, "198.51.100.1"));
    EXPECT_EQ(EPERM, connectOnTestNet(AF_INET6, "2001:db8::1"));
}

TEST_F(FirewallBpfTest, TransportRuleUsesTheEgressInterface) {
    setIfaceNetwork(FW_RULE_BLOCK_CELLULAR);
    setRules(FW_RULE_BLOCK_WIFI);
    EXPECT_EQ(0, sendMulticast(kPort));
    EXPECT_TRUE(tunSaw(kPort));
    setRules(FW_RULE_BLOCK_CELLULAR);
    EXPECT_EQ(EPERM, sendMulticast(kPort));
    EXPECT_FALSE(tunSaw(kPort));
}

TEST_F(FirewallBpfTest, MeteredAndRoamingSwitchesFollowTheNetwork) {
    setIfaceNetwork(FW_RULE_BLOCK_WIFI | FW_RULE_BLOCK_METERED);
    setRules(FW_RULE_BLOCK_ROAMING);
    EXPECT_EQ(0, sendMulticast(kPort));
    setRules(FW_RULE_BLOCK_METERED);
    EXPECT_EQ(EPERM, sendMulticast(kPort));
    setNetwork(FW_RULE_BLOCK_CELLULAR | FW_RULE_BLOCK_ROAMING);
    setRules(FW_RULE_BLOCK_ROAMING);
    EXPECT_EQ(EPERM, connectOnTestNet(AF_INET, "198.51.100.1"));
    EXPECT_FALSE(allowsLookup(kTestUid, kTestNetId, "example.test"));
}

}  // namespace
