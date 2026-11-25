/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#define LOG_TAG "Firewall"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <stddef.h>
#include <sys/socket.h>

#include "BpfSyscallWrappers.h"
#include "firewall_jni.h"

#define FILTER_NAME "prog_firewall_hotspot:[*fsobj]"

namespace firewall {
namespace {

using android::base::unique_fd;

BpfMap<uint32_t, uint32_t> gUpstream;
BpfMap<uint64_t, uint32_t> gDevices;

// Sends a request to the kernel's traffic control and returns its answer, 0 or an errno.
int request(const void* message, size_t length) {
    unique_fd fd(socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE));
    sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    if (!fd.ok() || connect(fd.get(), reinterpret_cast<sockaddr*>(&kernel), sizeof(kernel)) ||
        send(fd.get(), message, length, 0) != static_cast<ssize_t>(length)) {
        return errno;
    }
    // Only the start of the answer is read, as it holds the error.
    struct {
        nlmsghdr header;
        nlmsgerr error;
    } answer;
    ssize_t received = recv(fd.get(), &answer, sizeof(answer), 0);
    if (received < 0) return errno;
    if (received < static_cast<ssize_t>(sizeof(answer)) ||
        answer.header.nlmsg_type != NLMSG_ERROR) {
        return EBADMSG;
    }
    return -answer.error.error;
}

// The program's filter where packets come in on the interface: first, ahead of Tethering's offload.
tcmsg filterOn(int ifindex) {
    return {.tcm_family = AF_UNSPEC,
            .tcm_ifindex = ifindex,
            .tcm_handle = 1,
            .tcm_parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS),
            .tcm_info = TC_H_MAKE(1u << 16, htons(ETH_P_ALL))};
}

// The qdisc that filters go on, which the interface may already have.
int addClsact(int ifindex) {
    struct {
        nlmsghdr header;
        tcmsg tc;
        nlattr kind;
        char kindName[NLA_ALIGN(sizeof("clsact"))];
    } message = {
            .header = {.nlmsg_len = sizeof(message),
                       .nlmsg_type = RTM_NEWQDISC,
                       .nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE},
            .tc = {.tcm_family = AF_UNSPEC,
                   .tcm_ifindex = ifindex,
                   .tcm_handle = TC_H_MAKE(TC_H_CLSACT, 0),
                   .tcm_parent = TC_H_CLSACT},
            .kind = {.nla_len = NLA_HDRLEN + sizeof("clsact"), .nla_type = TCA_KIND},
            .kindName = "clsact",
    };
    int error = request(&message, sizeof(message));
    return error == EEXIST ? 0 : error;
}

struct FilterRequest {
    nlmsghdr header;
    tcmsg tc;
    nlattr kind;
    char kindName[NLA_ALIGN(sizeof("bpf"))];
    nlattr options;
    nlattr fd;
    uint32_t fdValue;
    nlattr name;
    char nameValue[NLA_ALIGN(sizeof(FILTER_NAME))];
    nlattr flags;
    uint32_t flagsValue;
};

// Puts the program on the interface, or swaps it in for the one a restarted service left there.
jint nativeAttachHotspot(JNIEnv*, jclass, jint ifindex) {
    unique_fd prog(android::bpf::retrieveProgram(FW_PROG_PATH("hotspot")));
    if (!prog.ok()) return errno;
    if (int error = addClsact(ifindex)) return error;
    FilterRequest message = {
            .header = {.nlmsg_len = sizeof(message),
                       .nlmsg_type = RTM_NEWTFILTER,
                       .nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE},
            .tc = filterOn(ifindex),
            .kind = {.nla_len = NLA_HDRLEN + sizeof("bpf"), .nla_type = TCA_KIND},
            .kindName = "bpf",
            .options = {.nla_len = sizeof(FilterRequest) - offsetof(FilterRequest, options),
                        .nla_type = NLA_F_NESTED | TCA_OPTIONS},
            .fd = {.nla_len = NLA_HDRLEN + sizeof(uint32_t), .nla_type = TCA_BPF_FD},
            .fdValue = static_cast<uint32_t>(prog.get()),
            .name = {.nla_len = NLA_HDRLEN + sizeof(FILTER_NAME), .nla_type = TCA_BPF_NAME},
            .nameValue = FILTER_NAME,
            .flags = {.nla_len = NLA_HDRLEN + sizeof(uint32_t), .nla_type = TCA_BPF_FLAGS},
            .flagsValue = TCA_BPF_FLAG_ACT_DIRECT,
    };
    return request(&message, sizeof(message));
}

// Takes the program off the interface; it's off when the interface lost its qdisc, or never had it.
jint nativeDetachHotspot(JNIEnv*, jclass, jint ifindex) {
    struct {
        nlmsghdr header;
        tcmsg tc;
    } message = {
            .header = {.nlmsg_len = sizeof(message),
                       .nlmsg_type = RTM_DELTFILTER,
                       .nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK},
            .tc = filterOn(ifindex),
    };
    int error = request(&message, sizeof(message));
    return error == ENOENT || error == EINVAL ? 0 : error;
}

jint nativeSetHotspotUpstream(JNIEnv*, jclass, jint netId) {
    return set(gUpstream, 0u, static_cast<uint32_t>(netId));
}

// The MAC address takes the key's first bytes, as the program reads it from the frame.
jint nativeSetHotspotDevice(JNIEnv* env, jclass, jbyteArray mac, jint uid) {
    if (env->GetArrayLength(mac) != ETH_ALEN) return EINVAL;
    uint64_t key = 0;
    env->GetByteArrayRegion(mac, 0, ETH_ALEN, reinterpret_cast<jbyte*>(&key));
    return setOrUnset(gDevices, key, static_cast<uint32_t>(uid));
}

const JNINativeMethod kMethods[] = {
        {"nativeAttachHotspot", "(I)I", reinterpret_cast<void*>(nativeAttachHotspot)},
        {"nativeDetachHotspot", "(I)I", reinterpret_cast<void*>(nativeDetachHotspot)},
        {"nativeSetHotspotUpstream", "(I)I", reinterpret_cast<void*>(nativeSetHotspotUpstream)},
        {"nativeSetHotspotDevice", "([BI)I", reinterpret_cast<void*>(nativeSetHotspotDevice)},
};

}  // namespace

bool initHotspot() {
    return init(gUpstream, FW_MAP_PATH("hotspot_upstream")) &&
           init(gDevices, FW_MAP_PATH("hotspot_devices"));
}

void clearHotspot() {
    clear(gDevices);
}

int registerHotspot(JNIEnv* env, jclass cls) {
    return env->RegisterNatives(cls, kMethods, sizeof(kMethods) / sizeof(kMethods[0]));
}

}  // namespace firewall
