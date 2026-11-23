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
#include "firewall_domain.h"
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
using android::firewall::allowsAnswer;
using android::net::TunInterface;

namespace {

// An app uid in a user that doesn't exist, so no real rules are touched. Tagging a root
// socket with it makes the firewall apply its rules.
constexpr uint32_t kTestUser = 99;
constexpr uint32_t kTestUid = kTestUser * 100000 + 10999;
constexpr uint32_t kUserScope = FW_USER_SCOPE | kTestUser;
constexpr uint32_t kOtherUser = 98;
constexpr uint32_t kTestNetId = 64999;
constexpr int kPort = 9;
constexpr const char* kCgroup = "/sys/fs/cgroup";

const std::vector<std::string> kMaps = {
        "uid_rules",
        "iface_transport",
        "net_transport",
        "vpn_ranges",
        "counters",
        "refusals",
        "refusal_stats",
        "user_flags",
        "ip4_block",
        "ip6_block",
        "ip4_allow",
        "ip6_allow",
        "port_rules",
        "learned",
        "scope_limits",
        "domain_rules",
        "uid_networks",
        "lan4",
        "lan6",
        "scope_lists",
        "list_ip4",
        "list_ip6",
        "list_files",
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

std::vector<uint8_t> dnsQuery(const std::string& name) {
    std::vector<uint8_t> q = {0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0};
    size_t start = 0;
    while (start <= name.size()) {
        size_t dot = name.find('.', start);
        if (dot == std::string::npos) dot = name.size();
        q.push_back(dot - start);
        q.insert(q.end(), name.begin() + start, name.begin() + dot);
        start = dot + 1;
    }
    q.insert(q.end(), {0, 0, 1, 0, 1});
    return q;
}

in6_addr ipv4Mapped(const char* address) {
    in6_addr mapped = {};
    mapped.s6_addr[10] = 0xff;
    mapped.s6_addr[11] = 0xff;
    inet_pton(AF_INET, address, &mapped.s6_addr[12]);
    return mapped;
}

class FirewallBpfTest : public ::testing::Test {
  protected:
    void SetUp() override {
        ASSERT_EQ(0u, getuid()) << "This test must run as root.";
        for (const auto& name : {
                     "uid_rules",
                     "iface_transport",
                     "net_transport",
                     "refusal_stats",
                     "user_flags",
                     "ip4_block",
                     "ip6_block",
                     "ip4_allow",
                     "ip6_allow",
                     "port_rules",
                     "domain_rules",
                     "learned",
                     "scope_limits",
                     "uid_networks",
                     "lan6",
                     "scope_lists",
                     "list_ip4",
                     "list_files",
             }) {
            mMaps[name].reset(mapRetrieveRW(mapPath(name).c_str()));
            ASSERT_LE(0, mMaps[name].get()) << name << ": " << strerror(errno);
        }
        ASSERT_EQ(0, mTun.init());
    }

    void TearDown() override {
        TearDownList();
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
    void setUserFlags(uint32_t flags) { put("user_flags", kTestUser, flags); }
    // The bits of the test interface's network, and of the test network.
    void setIfaceNetwork(uint64_t bits) {
        put("iface_transport", static_cast<uint32_t>(mTun.ifindex()), bits);
    }
    void setNetwork(uint64_t bits) { put("net_transport", kTestNetId, bits); }

    void putIp4(const std::string& map, uint32_t scope, const char* address, uint32_t bits,
                uint32_t limits = 1) {
        fw_scope_ip4_key key = {.prefixlen = 32 + bits, .scope = scope};
        inet_pton(AF_INET, address, key.addr);
        put(map, key, limits);
    }

    void putMulticast(const std::string& map, uint32_t scope, uint32_t limits = 1) {
        fw_scope_ip6_key key = {.prefixlen = 32 + 128, .scope = scope};
        inet_pton(AF_INET6, "ff02::1", key.addr);
        put(map, key, limits);
    }

    void putDomain(uint32_t scope, const char* name, uint64_t bits) {
        put("domain_rules", fw_scope_domain_key{.scope = scope, .hash = fw_domain_hash(name)},
            bits);
    }

    void putPort(uint32_t scope, uint16_t port, uint8_t protocol, uint32_t bits) {
        putPorts(scope, port, 16, protocol, bits);
    }

    // The ports that share the port's first prefixLength bits.
    void putPorts(uint32_t scope, uint16_t port, uint32_t prefixLength, uint8_t protocol,
                  uint32_t bits) {
        fw_port_key key = {.prefixlen = FW_PORT_PREFIX_BITS + prefixLength, .scope = scope,
                           .protocol = protocol,
                           .port = {static_cast<uint8_t>(port >> 8), static_cast<uint8_t>(port)}};
        put("port_rules", key, bits);
    }

    // The ports of a scope's limit that names them.
    void putLimitPorts(uint32_t scope, int limit, uint8_t protocol, uint16_t first,
                       uint16_t last) {
        for (uint32_t port = first; port <= last; port++) {
            putPort(scope | FW_LIMIT_PORTS_SCOPE, port, protocol, 1u << limit);
        }
    }

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

    // A UDP refusal's key, cleared so only refusals from now on count. The service drains the
    // reports, so the counts behind them are what's checked.
    fw_refusal_key clearedRefusal(uint8_t direction, int family, const char* address, int port) {
        fw_refusal_key key = {.uid = kTestUid, .direction = direction, .protocol = IPPROTO_UDP,
                              .v6 = family == AF_INET6, .port = static_cast<uint16_t>(port)};
        inet_pton(family, address, key.addr);
        forget("refusal_stats", key);
        deleteMapEntry(mMaps["refusal_stats"], &key);
        return key;
    }
    fw_refusal_stats refusalStats(const fw_refusal_key& key) {
        fw_refusal_stats stats = {};
        findMapEntry(mMaps["refusal_stats"], &key, &stats);
        return stats;
    }
    // A list's file of domains in slot kListSlot, for netd's lookup check, until the test ends.
    void putListFile(const std::vector<std::pair<std::string, bool>>& names) {
        std::vector<int64_t> keys;
        for (const auto& [name, subdomains] : names) {
            keys.push_back(static_cast<int64_t>((fw_domain_hash(name) & ~1ULL) | subdomains));
        }
        std::sort(keys.begin(), keys.end());
        std::vector<uint64_t> file = {FW_LIST_NAMES_MAGIC, keys.size()};
        file.insert(file.end(), keys.begin(), keys.end());
        unique_fd fd(open(kListFile.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644));
        ASSERT_LE(0, fd.get()) << kListFile << ": " << strerror(errno);
        ssize_t bytes = static_cast<ssize_t>(file.size() * 8);
        ASSERT_EQ(bytes, write(fd.get(), file.data(), bytes));
        ASSERT_EQ(0, writeToMapEntry(mMaps["list_files"], &kListSlot, &kListGeneration, BPF_ANY));
        mListFile = true;
    }

    void TearDownList() {
        if (!mListFile) return;
        uint32_t none = 0;
        writeToMapEntry(mMaps["list_files"], &kListSlot, &none, BPF_ANY);
        unlink(kListFile.c_str());
    }

    static constexpr uint32_t kListSlot = FW_LIST_SLOTS - 1;
    static constexpr uint32_t kListGeneration = 0x7fff0001;
    const std::string kListFile = std::string(FW_LISTS_DIR) + std::to_string(kListSlot) + "-" +
                                  std::to_string(kListGeneration) + ".names";
    bool mListFile = false;
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

TEST_F(FirewallBpfTest, AddressRulesForAllOfTheAppsUsersApps) {
    setRules(0);
    setUserFlags(FW_SCOPE_IP_BLOCKS);
    putIp4("ip4_block", kUserScope, "198.51.100.0", 24);
    putIp4("ip4_block", FW_USER_SCOPE | kOtherUser, "203.0.113.0", 24);
    EXPECT_EQ(EPERM, connectOnTestNet(AF_INET, "198.51.100.7"));
    EXPECT_NE(EPERM, connectOnTestNet(AF_INET, "203.0.113.7"));
    // IPv4-mapped IPv6 addresses are checked against the IPv4 rules.
    EXPECT_EQ(EPERM, connectOnTestNet(AF_INET6, "::ffff:198.51.100.7"));

    putMulticast("ip6_block", kUserScope);
    EXPECT_EQ(EPERM, sendMulticast(kPort));
}

TEST_F(FirewallBpfTest, DomainRulesCoverSubdomainsOnlyWhenTheySaySo) {
    setRules(0);
    setUserFlags(FW_SCOPE_DOMAINS);
    putDomain(kUserScope, "blocked.test", FW_DOMAIN_BLOCK);
    putDomain(kUserScope, "ads.test", FW_DOMAIN_BLOCK | FW_DOMAIN_BLOCK_SUBDOMAINS);
    putDomain(kUserScope, "good.ads.test", FW_DOMAIN_ALLOW);
    putDomain(FW_USER_SCOPE | kOtherUser, "other.test",
              FW_DOMAIN_BLOCK | FW_DOMAIN_BLOCK_SUBDOMAINS);
    EXPECT_FALSE(allowsLookup(kTestUid, kTestNetId, "blocked.test"));
    EXPECT_TRUE(allowsLookup(kTestUid, kTestNetId, "www.blocked.test"));
    EXPECT_FALSE(allowsLookup(kTestUid, kTestNetId, "ads.test"));
    EXPECT_FALSE(allowsLookup(kTestUid, kTestNetId, "x.Ads.test"));
    // An allow rule wins over a block rule for the same apps.
    EXPECT_TRUE(allowsLookup(kTestUid, kTestNetId, "good.ads.test"));
    EXPECT_TRUE(allowsLookup(kTestUid, kTestNetId, "other.test"));
}

TEST_F(FirewallBpfTest, AnAppsOwnDnsIsBlockedWhileDomainRulesApply) {
    setRules(0);
    EXPECT_EQ(0, sendMulticast(53, dnsQuery("example.test")));
    setRules(FW_SCOPE_DOMAINS);
    EXPECT_EQ(EPERM, sendMulticast(53, dnsQuery("example.test")));
    // DNS over TLS and over QUIC share their port.
    EXPECT_EQ(EPERM, sendMulticast(853));
    EXPECT_EQ(0, sendMulticast(kPort));
    setRules(0);
    setUserFlags(FW_SCOPE_DOMAINS);
    EXPECT_EQ(EPERM, sendMulticast(53, dnsQuery("example.test")));
    // The app's allow rules still come before its user's rules.
    setRules(FW_SCOPE_IP_ALLOWS);
    putMulticast("ip6_allow", kTestUid);
    EXPECT_EQ(0, sendMulticast(53, dnsQuery("example.test")));
}

TEST_F(FirewallBpfTest, KnownDohServersCountAsTheAppsOwnDnsOnAnyPort) {
    putMulticast("ip6_block", FW_DOH_SCOPE);
    setRules(0);
    EXPECT_EQ(0, sendMulticast(kPort));
    setRules(FW_SCOPE_DOMAINS);
    EXPECT_EQ(EPERM, sendMulticast(kPort));
    setRules(0);
    setUserFlags(FW_SCOPE_DOMAINS);
    EXPECT_EQ(EPERM, sendMulticast(kPort));
}

TEST_F(FirewallBpfTest, AllowRulesLetABlockedAppReachOnlyWhatTheyName) {
    setRules(FW_RULE_BLOCK_ALL | FW_SCOPE_IP_ALLOWS | FW_SCOPE_PORT_ALLOWS | FW_SCOPE_LEARNED);
    putIp4("ip4_allow", kTestUid, "198.51.100.0", 24);
    fw_learned_key learned = {.scope = kTestUid};
    in6_addr address = ipv4Mapped("203.0.113.9");
    memcpy(learned.addr, &address, sizeof(learned.addr));
    put("learned", learned, uint32_t{1});
    putPort(kTestUid, 5353, IPPROTO_UDP, FW_PORT_ALLOW);

    EXPECT_NE(EPERM, connectOnTestNet(AF_INET, "198.51.100.7"));
    EXPECT_NE(EPERM, connectOnTestNet(AF_INET, "203.0.113.9"));
    EXPECT_EQ(EPERM, connectOnTestNet(AF_INET, "203.0.113.10"));
    EXPECT_EQ(0, sendMulticast(5353));
    EXPECT_EQ(EPERM, sendMulticast(kPort));
}

TEST_F(FirewallBpfTest, AnAppsRulesComeBeforeItsUsersRules) {
    setRules(FW_SCOPE_IP_ALLOWS | FW_SCOPE_IP_BLOCKS);
    setUserFlags(FW_SCOPE_IP_ALLOWS | FW_SCOPE_IP_BLOCKS);
    putIp4("ip4_block", kUserScope, "198.51.100.0", 24);
    putIp4("ip4_allow", kTestUid, "198.51.100.7", 32);
    putIp4("ip4_block", kTestUid, "203.0.113.0", 24);
    putIp4("ip4_allow", kUserScope, "203.0.113.7", 32);
    EXPECT_NE(EPERM, connectOnTestNet(AF_INET, "198.51.100.7"));
    EXPECT_EQ(EPERM, connectOnTestNet(AF_INET, "198.51.100.8"));
    EXPECT_EQ(EPERM, connectOnTestNet(AF_INET, "203.0.113.7"));
    // Within the user's rules, the allow rule wins.
    putIp4("ip4_allow", kUserScope, "198.51.100.8", 32);
    EXPECT_NE(EPERM, connectOnTestNet(AF_INET, "198.51.100.8"));
}

TEST_F(FirewallBpfTest, PortRulesMatchTheirProtocol) {
    setRules(FW_SCOPE_PORT_BLOCKS);
    putPort(kTestUid, kPort, IPPROTO_UDP, FW_PORT_BLOCK);
    putPort(kTestUid, 11, IPPROTO_TCP, FW_PORT_BLOCK);
    putPort(kTestUid, 12, 0, FW_PORT_BLOCK);
    EXPECT_EQ(EPERM, sendMulticast(kPort));
    EXPECT_EQ(0, sendMulticast(10));
    EXPECT_EQ(0, sendMulticast(11));
    EXPECT_EQ(EPERM, sendMulticast(12));
}

TEST_F(FirewallBpfTest, PortRangesMatchThroughTheirPrefixes) {
    setRules(FW_SCOPE_PORT_BLOCKS);
    // Ports 8 to 15, one of the prefixes the service splits a range into.
    putPorts(kTestUid, 8, 13, 0, FW_PORT_BLOCK);
    EXPECT_EQ(EPERM, sendMulticast(kPort));
    EXPECT_EQ(0, sendMulticast(16));
}

TEST_F(FirewallBpfTest, RefusalsAreCountedWithEveryReason) {
    // Blocked everywhere and on this network, with its own address rule and a port rule for all
    // apps that match too.
    setNetwork(FW_RULE_BLOCK_CELLULAR);
    setRules(FW_RULE_BLOCK_ALL | FW_RULE_BLOCK_CELLULAR | FW_SCOPE_IP_BLOCKS);
    putIp4("ip4_block", kTestUid, "203.0.113.7", 32);
    setUserFlags(FW_SCOPE_PORT_BLOCKS);
    putPort(kUserScope, 7, IPPROTO_UDP, FW_PORT_BLOCK);
    fw_refusal_key key = clearedRefusal(FW_REFUSAL_CONNECT, AF_INET, "203.0.113.7", 7);
    EXPECT_EQ(EPERM, connectOnTestNet(AF_INET, "203.0.113.7", 7));
    EXPECT_EQ(EPERM, connectOnTestNet(AF_INET, "203.0.113.7", 7));
    fw_refusal_stats stats = refusalStats(key);
    EXPECT_EQ(2u, stats.count);
    EXPECT_EQ(FW_REFUSED_ALL | FW_REFUSED_NETWORK | FW_REFUSED_ADDRESS | FW_REFUSED_USER_PORT,
              stats.reasons);
    EXPECT_LE(stats.first_ns, stats.last_ns);

    // Packets out count too, with the reasons only they have.
    setUserFlags(0);
    setRules(FW_RULE_BLOCK_DNS);
    key = clearedRefusal(FW_REFUSAL_OUT, AF_INET6, "ff02::1", 53);
    EXPECT_EQ(EPERM, sendMulticast(53, dnsQuery("example.test")));
    stats = refusalStats(key);
    EXPECT_EQ(1u, stats.count);
    EXPECT_EQ(FW_REFUSED_DNS, stats.reasons);
}

TEST_F(FirewallBpfTest, DnsRuleBlocksTheAppsOwnDnsOnly) {
    setRules(FW_RULE_BLOCK_DNS);
    EXPECT_EQ(EPERM, sendMulticast(53, dnsQuery("example.test")));
    EXPECT_EQ(EPERM, sendMulticast(853));
    EXPECT_EQ(0, sendMulticast(kPort));
}

TEST_F(FirewallBpfTest, LanThroughVpnHonorsTheDnsException) {
    // Whatever else the VPN is, like metered.
    setIfaceNetwork(FW_RULE_BLOCK_VPN | FW_RULE_BLOCK_METERED);
    fw_ip6_key lan = {.prefixlen = 128};
    inet_pton(AF_INET6, "ff02::1", lan.addr);
    put("lan6", lan, uint32_t{FW_LAN_DNS});
    setRules(0);
    EXPECT_EQ(0, sendMulticast(kPort));
    setRules(FW_RULE_NO_LAN);
    EXPECT_EQ(EPERM, sendMulticast(kPort));
    EXPECT_EQ(0, sendMulticast(53, dnsQuery("example.test")));
}

// netd's checks for the resolver, as the firewall's library makes them.
TEST_F(FirewallBpfTest, LookupsFollowTheAppsRulesThenItsUsers) {
    setRules(0);
    EXPECT_TRUE(allowsLookup(kTestUid, kTestNetId, "example.test"));
    setUserFlags(FW_SCOPE_DOMAINS);
    putDomain(kUserScope, "blocked.test", FW_DOMAIN_BLOCK | FW_DOMAIN_BLOCK_SUBDOMAINS);
    EXPECT_FALSE(allowsLookup(kTestUid, kTestNetId, "www.blocked.test"));

    setRules(FW_SCOPE_DOMAINS | FW_SCOPE_LEARNED);
    putDomain(kTestUid, "www.blocked.test", FW_DOMAIN_ALLOW);
    EXPECT_TRUE(allowsLookup(kTestUid, kTestNetId, "www.blocked.test"));
    EXPECT_FALSE(allowsLookup(kTestUid, kTestNetId, "mail.blocked.test"));

    setRules(FW_RULE_BLOCK_ALL | FW_SCOPE_DOMAINS | FW_SCOPE_LEARNED);
    EXPECT_TRUE(allowsLookup(kTestUid, kTestNetId, "www.blocked.test"));
    EXPECT_FALSE(allowsLookup(kTestUid, kTestNetId, "example.test"));
    setNetwork(FW_RULE_BLOCK_CELLULAR);
    setRules(FW_RULE_BLOCK_CELLULAR);
    EXPECT_FALSE(allowsLookup(kTestUid, kTestNetId, "example.test"));
}

TEST_F(FirewallBpfTest, KnownDohServersCantBeLookedUpUnderDomainRules) {
    putDomain(FW_DOH_SCOPE, "doh.test", FW_DOMAIN_BLOCK);
    setRules(0);
    EXPECT_TRUE(allowsLookup(kTestUid, kTestNetId, "doh.test"));
    setRules(FW_SCOPE_DOMAINS);
    EXPECT_FALSE(allowsLookup(kTestUid, kTestNetId, "doh.test"));
    EXPECT_TRUE(allowsLookup(kTestUid, kTestNetId, "example.test"));
    setRules(0);
    setUserFlags(FW_SCOPE_DOMAINS);
    EXPECT_FALSE(allowsLookup(kTestUid, kTestNetId, "doh.test"));
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

TEST_F(FirewallBpfTest, AChoiceForASpecificNetworkWinsOverItsKind) {
    constexpr uint32_t kSlot = 3;
    setIfaceNetwork(FW_RULE_BLOCK_WIFI | 1ULL << (FW_NET_SLOT_SHIFT + kSlot));
    setNetwork(FW_RULE_BLOCK_WIFI | 1ULL << (FW_NET_SLOT_SHIFT + kSlot));
    setRules(FW_RULE_BLOCK_WIFI | FW_RULE_NAMED_NETWORKS);
    put("uid_networks", kTestUid, fw_named_networks{.allow = 1u << kSlot});
    EXPECT_EQ(0, sendMulticast(kPort));
    EXPECT_NE(EPERM, connectOnTestNet(AF_INET, "198.51.100.1"));
    EXPECT_TRUE(allowsLookup(kTestUid, kTestNetId, "example.test"));

    setRules(FW_RULE_NAMED_NETWORKS);
    put("uid_networks", kTestUid, fw_named_networks{.block = 1u << kSlot});
    EXPECT_EQ(EPERM, sendMulticast(kPort));
    EXPECT_EQ(EPERM, connectOnTestNet(AF_INET, "198.51.100.1"));
    EXPECT_FALSE(allowsLookup(kTestUid, kTestNetId, "example.test"));
}

TEST_F(FirewallBpfTest, RulesLimitedToNetworksApplyOnlyThere) {
    constexpr uint64_t kHome = 1ULL << (FW_NET_SLOT_SHIFT + 5);
    // Limit 1 is mobile data only, limit 2 every network but home.
    fw_limits limits = {};
    limits.only[1] = FW_RULE_BLOCK_CELLULAR;
    limits.except[2] = kHome;
    put("scope_limits", kUserScope, limits);
    setRules(0);
    setUserFlags(FW_SCOPE_IP_BLOCKS | FW_SCOPE_PORT_BLOCKS | FW_SCOPE_DOMAINS | FW_SCOPE_LIMITS);
    putMulticast("ip6_block", kUserScope, 1u << 1);
    putPort(kUserScope, 10, IPPROTO_UDP, FW_PORT_BLOCK << (2 * 2));
    putDomain(kUserScope, "ads.test",
              uint64_t{FW_DOMAIN_BLOCK | FW_DOMAIN_BLOCK_SUBDOMAINS} << (4 * 2));

    setIfaceNetwork(FW_RULE_BLOCK_WIFI | kHome);
    EXPECT_EQ(0, sendMulticast(kPort));
    EXPECT_EQ(0, sendMulticast(10));
    setIfaceNetwork(FW_RULE_BLOCK_WIFI);
    EXPECT_EQ(0, sendMulticast(kPort));
    EXPECT_EQ(EPERM, sendMulticast(10));
    setIfaceNetwork(FW_RULE_BLOCK_CELLULAR);
    EXPECT_EQ(EPERM, sendMulticast(kPort));

    setNetwork(FW_RULE_BLOCK_WIFI | kHome);
    EXPECT_TRUE(allowsLookup(kTestUid, kTestNetId, "www.ads.test"));
    setNetwork(FW_RULE_BLOCK_WIFI);
    EXPECT_FALSE(allowsLookup(kTestUid, kTestNetId, "www.ads.test"));
    setNetwork(FW_RULE_BLOCK_CELLULAR | FW_RULE_BLOCK_METERED);
    EXPECT_FALSE(allowsLookup(kTestUid, kTestNetId, "www.ads.test"));
}

TEST_F(FirewallBpfTest, LearnedAnswersKeepTheLimitsOfTheirAllowRule) {
    fw_limits limits = {};
    limits.only[1] = FW_RULE_BLOCK_WIFI;
    put("scope_limits", kTestUid, limits);
    setRules(FW_RULE_BLOCK_ALL | FW_SCOPE_DOMAINS | FW_SCOPE_LEARNED | FW_SCOPE_LIMITS);
    putDomain(kTestUid, "allowed.test", uint64_t{FW_DOMAIN_ALLOW} << 4);
    in6_addr allowed = ipv4Mapped("203.0.113.9");
    fw_learned_key key = {.scope = kTestUid};
    memcpy(key.addr, &allowed, sizeof(key.addr));
    forget("learned", key);
    EXPECT_TRUE(allowsAnswer(kTestUid, kTestNetId, "allowed.test", nullptr, 0, &allowed, 1));
    uint32_t learned = 0;
    ASSERT_EQ(0, findMapEntry(mMaps["learned"], &key, &learned));
    EXPECT_EQ(1u << 1, learned);

    setNetwork(FW_RULE_BLOCK_CELLULAR);
    EXPECT_EQ(EPERM, connectOnTestNet(AF_INET, "203.0.113.9"));
    setNetwork(FW_RULE_BLOCK_WIFI);
    EXPECT_NE(EPERM, connectOnTestNet(AF_INET, "203.0.113.9"));
}

TEST_F(FirewallBpfTest, AnswersToAllowedNamesAreLearnedBeforeTheAppConnects) {
    setRules(FW_RULE_BLOCK_ALL | FW_SCOPE_DOMAINS | FW_SCOPE_LEARNED);
    putDomain(kTestUid, "allowed.test", FW_DOMAIN_ALLOW | FW_DOMAIN_ALLOW_SUBDOMAINS);
    in6_addr allowed = ipv4Mapped("203.0.113.9"), other = ipv4Mapped("203.0.113.10");
    for (const in6_addr& address : {allowed, other}) {
        fw_learned_key key = {.scope = kTestUid};
        memcpy(key.addr, &address, sizeof(key.addr));
        forget("learned", key);
    }
    EXPECT_EQ(EPERM, connectOnTestNet(AF_INET, "203.0.113.9"));
    EXPECT_TRUE(allowsAnswer(kTestUid, kTestNetId, "www.allowed.test", nullptr, 0, &allowed, 1));
    EXPECT_NE(EPERM, connectOnTestNet(AF_INET, "203.0.113.9"));
    EXPECT_TRUE(allowsAnswer(kTestUid, kTestNetId, "other.test", nullptr, 0, &other, 1));
    EXPECT_EQ(EPERM, connectOnTestNet(AF_INET, "203.0.113.10"));
}

// A tracker hidden behind a site's own name, which its answer points to.
TEST_F(FirewallBpfTest, AnswersPointingToABlockedNameAreRefused) {
    const char* cloaked[] = {"site.tracker.test"};
    const char* clean[] = {"cdn.test"};
    in6_addr address = ipv4Mapped("203.0.113.9");
    setRules(FW_SCOPE_DOMAINS);
    putDomain(kTestUid, "tracker.test", FW_DOMAIN_BLOCK | FW_DOMAIN_BLOCK_SUBDOMAINS);
    EXPECT_FALSE(allowsAnswer(kTestUid, kTestNetId, "metrics.site.test", cloaked, 1, &address, 1));
    EXPECT_TRUE(allowsAnswer(kTestUid, kTestNetId, "www.site.test", clean, 1, &address, 1));
    setRules(0);
    setUserFlags(FW_SCOPE_DOMAINS);
    putDomain(kUserScope, "tracker.test", FW_DOMAIN_BLOCK | FW_DOMAIN_BLOCK_SUBDOMAINS);
    EXPECT_FALSE(allowsAnswer(kTestUid, kTestNetId, "metrics.site.test", cloaked, 1, &address, 1));
    // Known DNS-over-HTTPS servers count as for a name looked up.
    putDomain(FW_DOH_SCOPE, "doh.test", FW_DOMAIN_BLOCK);
    const char* doh[] = {"doh.test"};
    EXPECT_FALSE(allowsAnswer(kTestUid, kTestNetId, "dns.site.test", doh, 1, &address, 1));
}

TEST_F(FirewallBpfTest, AnAllowedNameAnywhereInAnAnswerLetsItThrough) {
    const char* cloaked[] = {"site.tracker.test", "edge.cdn.test"};
    in6_addr address = ipv4Mapped("203.0.113.9");
    setRules(FW_SCOPE_DOMAINS);
    putDomain(kTestUid, "tracker.test", FW_DOMAIN_BLOCK | FW_DOMAIN_BLOCK_SUBDOMAINS);
    putDomain(kTestUid, "metrics.site.test", FW_DOMAIN_ALLOW);
    EXPECT_TRUE(allowsAnswer(kTestUid, kTestNetId, "metrics.site.test", cloaked, 2, &address, 1));
    setUserFlags(FW_SCOPE_DOMAINS);
    putDomain(kUserScope, "cdn.test", FW_DOMAIN_ALLOW | FW_DOMAIN_ALLOW_SUBDOMAINS);
    EXPECT_TRUE(allowsAnswer(kTestUid, kTestNetId, "www.site.test", cloaked, 2, &address, 1));
}

TEST_F(FirewallBpfTest, AnswersAreLearnedForTheAllowedNamesTheyPointTo) {
    setRules(FW_SCOPE_IP_BLOCKS | FW_SCOPE_DOMAINS | FW_SCOPE_LEARNED);
    putIp4("ip4_block", kTestUid, "203.0.113.0", 24);
    putDomain(kTestUid, "cdn.test", FW_DOMAIN_ALLOW | FW_DOMAIN_ALLOW_SUBDOMAINS);
    in6_addr address = ipv4Mapped("203.0.113.9");
    fw_learned_key key = {.scope = kTestUid};
    memcpy(key.addr, &address, sizeof(key.addr));
    forget("learned", key);
    EXPECT_EQ(EPERM, connectOnTestNet(AF_INET, "203.0.113.9"));
    const char* chain[] = {"edge.cdn.test"};
    EXPECT_TRUE(allowsAnswer(kTestUid, kTestNetId, "www.site.test", chain, 1, &address, 1));
    EXPECT_NE(EPERM, connectOnTestNet(AF_INET, "203.0.113.9"));
}

TEST_F(FirewallBpfTest, AddressListsBlockAfterEveryRule) {
    constexpr uint64_t kList = 1ULL << kListSlot;
    fw_ip4_key range = {.prefixlen = 24};
    inet_pton(AF_INET, "203.0.113.0", range.addr);
    put("list_ip4", range, kList);
    put("scope_lists", kTestUid, kList);
    setRules(FW_SCOPE_LISTS);
    fw_refusal_key refusal = clearedRefusal(FW_REFUSAL_CONNECT, AF_INET, "203.0.113.9", kPort);
    EXPECT_EQ(EPERM, connectOnTestNet(AF_INET, "203.0.113.9"));
    EXPECT_EQ(FW_REFUSED_LIST, refusalStats(refusal).reasons & FW_REFUSED_LIST);
    EXPECT_NE(EPERM, connectOnTestNet(AF_INET, "198.51.100.1"));

    // An allow rule wins over every list, and lists never cover the firewall's own app.
    setRules(FW_SCOPE_LISTS | FW_SCOPE_IP_ALLOWS);
    putIp4("ip4_allow", kTestUid, "203.0.113.9", 32);
    EXPECT_NE(EPERM, connectOnTestNet(AF_INET, "203.0.113.9"));
    setRules(FW_SCOPE_LISTS | FW_RULE_NO_LISTS);
    EXPECT_NE(EPERM, connectOnTestNet(AF_INET, "203.0.113.10"));

    setRules(0);
    setUserFlags(FW_SCOPE_LISTS);
    put("scope_lists", kUserScope, kList);
    EXPECT_EQ(EPERM, connectOnTestNet(AF_INET, "203.0.113.10"));
}

TEST_F(FirewallBpfTest, DomainListsAreCheckedFromTheirFiles) {
    putListFile({{"tracker.test", true}, {"exact.test", false}});
    put("scope_lists", kTestUid, 1ULL << kListSlot);
    setRules(FW_SCOPE_LISTS);
    EXPECT_FALSE(allowsLookup(kTestUid, kTestNetId, "tracker.test"));
    EXPECT_FALSE(allowsLookup(kTestUid, kTestNetId, "www.tracker.test"));
    EXPECT_FALSE(allowsLookup(kTestUid, kTestNetId, "exact.test"));
    EXPECT_TRUE(allowsLookup(kTestUid, kTestNetId, "www.exact.test"));
    EXPECT_TRUE(allowsLookup(kTestUid, kTestNetId, "other.test"));
    const char* cloaked[] = {"site.tracker.test"};
    EXPECT_FALSE(allowsAnswer(kTestUid, kTestNetId, "metrics.site.test", cloaked, 1, nullptr, 0));

    // Allow rules win over every list, the app's own and its user's.
    setRules(FW_SCOPE_LISTS | FW_SCOPE_DOMAINS);
    putDomain(kTestUid, "www.tracker.test", FW_DOMAIN_ALLOW);
    EXPECT_TRUE(allowsLookup(kTestUid, kTestNetId, "www.tracker.test"));
    setRules(FW_SCOPE_LISTS);
    setUserFlags(FW_SCOPE_DOMAINS);
    putDomain(kUserScope, "mail.tracker.test", FW_DOMAIN_ALLOW);
    EXPECT_TRUE(allowsLookup(kTestUid, kTestNetId, "mail.tracker.test"));
    setRules(FW_SCOPE_LISTS | FW_RULE_NO_LISTS);
    EXPECT_TRUE(allowsLookup(kTestUid, kTestNetId, "tracker.test"));
}

TEST_F(FirewallBpfTest, AddressRulesWithAPortApplyOnlyAtThatPort) {
    // Limit 1 is UDP port 9, limit 2 TCP ports 10 to 12, and limit 3 ports 13 and 14 over both.
    put("scope_limits", kTestUid, fw_limits{.ported = (1u << 1) | (1u << 2) | (1u << 3)});
    putLimitPorts(kTestUid, 1, IPPROTO_UDP, kPort, kPort);
    putLimitPorts(kTestUid, 2, IPPROTO_TCP, 10, 12);
    putLimitPorts(kTestUid, 3, 0, 13, 14);
    setRules(FW_SCOPE_IP_BLOCKS | FW_SCOPE_LIMITS);
    putMulticast("ip6_block", kTestUid, (1u << 1) | (1u << 2) | (1u << 3));
    putIp4("ip4_block", kTestUid, "198.51.100.7", 32, 1u << 1);
    EXPECT_EQ(EPERM, sendMulticast(kPort));
    EXPECT_EQ(0, sendMulticast(kPort + 100));
    EXPECT_EQ(0, sendMulticast(11));
    EXPECT_EQ(EPERM, sendMulticast(13));
    EXPECT_EQ(0, sendMulticast(15));
    EXPECT_EQ(EPERM, connectOnTestNet(AF_INET, "198.51.100.7"));
    EXPECT_NE(EPERM, connectOnTestNet(AF_INET, "198.51.100.7", kPort + 1));

    // An allow rule with a port lets a blocked app reach the address there only.
    setRules(FW_RULE_BLOCK_ALL | FW_SCOPE_IP_ALLOWS | FW_SCOPE_LIMITS);
    putIp4("ip4_allow", kTestUid, "198.51.100.8", 32, 1u << 1);
    EXPECT_NE(EPERM, connectOnTestNet(AF_INET, "198.51.100.8"));
    EXPECT_EQ(EPERM, connectOnTestNet(AF_INET, "198.51.100.8", kPort + 1));
}

// netd lets lookups of a domain with a port through and learns the answers for that port.
TEST_F(FirewallBpfTest, DomainRulesWithAPortApplyToTheirAnswersAtThatPort) {
    put("scope_limits", kTestUid, fw_limits{.ported = 1u << 1});
    putLimitPorts(kTestUid, 1, IPPROTO_UDP, kPort, kPort);
    in6_addr blocked = ipv4Mapped("203.0.113.9"), allowed = ipv4Mapped("203.0.113.10");
    for (const in6_addr& address : {blocked, allowed}) {
        fw_learned_key key = {.scope = kTestUid};
        memcpy(key.addr, &address, sizeof(key.addr));
        forget("learned", key);
    }
    setRules(FW_SCOPE_DOMAINS | FW_SCOPE_LEARNED_BLOCKS | FW_SCOPE_LIMITS);
    putDomain(kTestUid, "blocked.test", uint64_t{FW_DOMAIN_BLOCK} << 4);
    EXPECT_TRUE(allowsLookup(kTestUid, kTestNetId, "blocked.test"));
    EXPECT_TRUE(allowsAnswer(kTestUid, kTestNetId, "blocked.test", nullptr, 0, &blocked, 1));
    fw_refusal_key refusal = clearedRefusal(FW_REFUSAL_CONNECT, AF_INET, "203.0.113.9", kPort);
    EXPECT_EQ(EPERM, connectOnTestNet(AF_INET, "203.0.113.9"));
    EXPECT_EQ(FW_REFUSED_DOMAIN, refusalStats(refusal).reasons);
    EXPECT_NE(EPERM, connectOnTestNet(AF_INET, "203.0.113.9", kPort + 1));

    // A blocked app's allow rule with a port lets the lookup through, and the app reach the
    // answer there only.
    setRules(FW_RULE_BLOCK_ALL | FW_SCOPE_DOMAINS | FW_SCOPE_LEARNED | FW_SCOPE_LIMITS);
    putDomain(kTestUid, "allowed.test", uint64_t{FW_DOMAIN_ALLOW} << 4);
    EXPECT_TRUE(allowsLookup(kTestUid, kTestNetId, "allowed.test"));
    EXPECT_FALSE(allowsLookup(kTestUid, kTestNetId, "other.test"));
    EXPECT_TRUE(allowsAnswer(kTestUid, kTestNetId, "allowed.test", nullptr, 0, &allowed, 1));
    EXPECT_NE(EPERM, connectOnTestNet(AF_INET, "203.0.113.10"));
    EXPECT_EQ(EPERM, connectOnTestNet(AF_INET, "203.0.113.10", kPort + 1));
}

}  // namespace
