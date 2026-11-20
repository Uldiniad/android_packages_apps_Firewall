/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#define LOG_TAG "Firewall"

#include <fcntl.h>
#include <processgroup/processgroup.h>
#include <unistd.h>

#include <string>
#include <vector>

#include "BpfSyscallWrappers.h"
#include "firewall_jni.h"

namespace firewall {
namespace {

using android::base::unique_fd;

struct Maps {
    BpfMap<uint32_t, uint32_t> uidRules;
    BpfMap<uint32_t, uint64_t> ifaceTransport;
    BpfMap<uint32_t, uint64_t> netTransport;
    BpfMap<uint32_t, fw_vpn_range> vpnRanges;
    // Per CPU, which BpfMap doesn't read; see nativeCounters().
    unique_fd counters;
};

Maps gMaps;

jboolean nativeInit(JNIEnv*, jclass) {
    if (!gMaps.counters.ok()) {
        gMaps.counters.reset(android::bpf::mapRetrieveRO(FW_MAP_PATH("counters")));
    }
    if (!init(gMaps.uidRules, FW_MAP_PATH("uid_rules")) ||
        !init(gMaps.ifaceTransport, FW_MAP_PATH("iface_transport")) ||
        !init(gMaps.netTransport, FW_MAP_PATH("net_transport")) ||
        !init(gMaps.vpnRanges, FW_MAP_PATH("vpn_ranges"))) {
        return false;
    }
    if (!initRefusalCounts()) return false;
    if (!initTargetRules()) return false;
    return gMaps.counters.ok();
}

constexpr struct {
    const char* path;
    bpf_attach_type type;
} kPrograms[] = {
        {FW_PROG_PATH("egress"), BPF_CGROUP_INET_EGRESS},
        {FW_PROG_PATH("ingress"), BPF_CGROUP_INET_INGRESS},
        {FW_PROG_PATH("connect4"), BPF_CGROUP_INET4_CONNECT},
        {FW_PROG_PATH("connect6"), BPF_CGROUP_INET6_CONNECT},
};

// Switches the programs on for every app, on the cgroup root alongside Connectivity's. They outlive
// the system server and the kernel refuses a second copy, so they are re-attached as netd does.
jboolean nativeAttach(JNIEnv*, jclass) {
    std::string path;
    if (!CgroupGetControllerPath(CGROUPV2_HIERARCHY_NAME, &path)) {
        ALOGE("no cgroup v2 hierarchy");
        return false;
    }
    unique_fd cgroup(open(path.c_str(), O_DIRECTORY | O_RDONLY | O_CLOEXEC));
    if (!cgroup.ok()) {
        ALOGE("open %s: %s", path.c_str(), strerror(errno));
        return false;
    }
    bool attached = true;
    for (const auto& prog : kPrograms) {
        unique_fd fd(android::bpf::retrieveProgram(prog.path));
        if (fd.ok()) android::bpf::detachSingleProgram(prog.type, fd, cgroup);
        if (!fd.ok() || android::bpf::attachProgram(prog.type, fd, cgroup, BPF_F_ALLOW_MULTI)) {
            ALOGE("attach %s: %s", prog.path, strerror(errno));
            attached = false;
        }
    }
    return attached;
}

void nativeClearRules(JNIEnv*, jclass) {
    clear(gMaps.uidRules);
    clear(gMaps.ifaceTransport);
    clear(gMaps.netTransport);
    clearTargetRules();
}

jint nativeSetUid(JNIEnv*, jclass, jint uid, jint rules) {
    return setOrUnset(gMaps.uidRules, static_cast<uint32_t>(uid), static_cast<uint32_t>(rules));
}

jint nativeSetIface(JNIEnv*, jclass, jint ifindex, jlong net) {
    return setOrUnset(gMaps.ifaceTransport, static_cast<uint32_t>(ifindex),
                      static_cast<uint64_t>(net));
}

jint nativeSetNet(JNIEnv*, jclass, jint netId, jlong net) {
    return setOrUnset(gMaps.netTransport, static_cast<uint32_t>(netId),
                      static_cast<uint64_t>(net));
}

void nativeSetVpnRanges(JNIEnv* env, jclass, jintArray starts, jintArray ends, jintArray netIds) {
    jsize count = env->GetArrayLength(starts);
    std::vector<jint> s(count), e(count), n(count);
    env->GetIntArrayRegion(starts, 0, count, s.data());
    env->GetIntArrayRegion(ends, 0, count, e.data());
    env->GetIntArrayRegion(netIds, 0, count, n.data());
    for (uint32_t i = 0; i < FW_VPN_RANGES; i++) {
        fw_vpn_range range = {};
        if (static_cast<jsize>(i) < count) {
            range = {.start = static_cast<__u32>(s[i]), .end = static_cast<__u32>(e[i]),
                     .net_id = static_cast<__u32>(n[i])};
        }
        set(gMaps.vpnRanges, i, range);
    }
}

jlongArray nativeCounters(JNIEnv* env, jclass) {
    int cpus = sysconf(_SC_NPROCESSORS_CONF);
    std::vector<uint64_t> perCpu(cpus);
    std::vector<jlong> totals(FW_COUNTER_MAX);
    for (uint32_t i = 0; i < FW_COUNTER_MAX; i++) {
        if (android::bpf::findMapEntry(gMaps.counters, &i, perCpu.data())) continue;
        for (uint64_t v : perCpu) totals[i] += v;
    }
    jlongArray result = env->NewLongArray(FW_COUNTER_MAX);
    env->SetLongArrayRegion(result, 0, FW_COUNTER_MAX, totals.data());
    return result;
}

const JNINativeMethod kMethods[] = {
        {"nativeInit", "()Z", reinterpret_cast<void*>(nativeInit)},
        {"nativeAttach", "()Z", reinterpret_cast<void*>(nativeAttach)},
        {"nativeClearRules", "()V", reinterpret_cast<void*>(nativeClearRules)},
        {"nativeSetUid", "(II)I", reinterpret_cast<void*>(nativeSetUid)},
        {"nativeSetIface", "(IJ)I", reinterpret_cast<void*>(nativeSetIface)},
        {"nativeSetNet", "(IJ)I", reinterpret_cast<void*>(nativeSetNet)},
        {"nativeSetVpnRanges", "([I[I[I)V", reinterpret_cast<void*>(nativeSetVpnRanges)},
        {"nativeCounters", "()[J", reinterpret_cast<void*>(nativeCounters)},
};

}  // namespace
}  // namespace firewall

jint JNI_OnLoad(JavaVM* vm, void*) {
    JNIEnv* env;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    jclass cls = env->FindClass("org/lineageos/firewall/FirewallMaps");
    if (!cls || env->RegisterNatives(cls, firewall::kMethods,
                                     sizeof(firewall::kMethods) / sizeof(firewall::kMethods[0]))) {
        return JNI_ERR;
    }
    if (firewall::registerRefusalCounts(env, cls)) return JNI_ERR;
    if (firewall::registerTargetRules(env, cls)) return JNI_ERR;
    return JNI_VERSION_1_6;
}
