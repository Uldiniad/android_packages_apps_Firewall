/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#define LOG_TAG "Firewall"

#include <android/file_descriptor_jni.h>
#include <arpa/inet.h>
#include <bpf/BpfRingbuf.h>

#include <vector>

#include "BpfSyscallWrappers.h"
#include "firewall_jni.h"

namespace firewall {
namespace {

BpfMap<fw_refusal_key, fw_refusal_stats> gRefusalStats;

using RefusalRingbuf = android::bpf::BpfRingbuf<fw_refusal>;

// The ring buffer of refusals, opened once; null when it isn't pinned.
RefusalRingbuf* refusals() {
    static RefusalRingbuf* const ringbuf = [] {
        auto result = RefusalRingbuf::Create(FW_MAP_PATH("refusals"));
        if (!result.ok()) {
            ALOGE("refusals: %s", result.error().message().c_str());
            return static_cast<RefusalRingbuf*>(nullptr);
        }
        return result.value().release();
    }();
    return ringbuf;
}

// A descriptor for the service's looper to watch for new refusals.
jobject nativeRefusalsFd(JNIEnv* env, jclass) {
    if (!refusals()) return nullptr;
    int fd = android::bpf::mapRetrieveRO(FW_MAP_PATH("refusals"));
    if (fd < 0) return nullptr;
    jobject descriptor = AFileDescriptor_create(env);
    AFileDescriptor_setFd(env, descriptor, fd);
    return descriptor;
}

// A refusal as 13 longs: uid, direction, protocol, IPv6 flag, port and the address words in host
// order, then its count, reasons and first and last boot times.
void pack(std::vector<jlong>& values, const fw_refusal_key& key, const fw_refusal_stats& stats) {
    values.insert(values.end(), {key.uid, key.direction, key.protocol, key.v6, key.port,
                                 ntohl(key.addr[0]), ntohl(key.addr[1]), ntohl(key.addr[2]),
                                 ntohl(key.addr[3]), static_cast<jlong>(stats.count),
                                 stats.reasons, static_cast<jlong>(stats.first_ns),
                                 static_cast<jlong>(stats.last_ns)});
}

jlongArray toArray(JNIEnv* env, const std::vector<jlong>& values) {
    jlongArray array = env->NewLongArray(values.size());
    env->SetLongArrayRegion(array, 0, values.size(), values.data());
    return array;
}

jlongArray nativeConsumeRefusals(JNIEnv* env, jclass) {
    std::vector<jlong> values;
    if (refusals()) {
        auto result = refusals()->ConsumeAll(
                [&](const fw_refusal& refusal) { pack(values, refusal.key, refusal.stats); });
        if (!result.ok()) ALOGE("consume refusals: %s", result.error().message().c_str());
    }
    return toArray(env, values);
}

// Every count, including those whose last refusals came after their last report.
jlongArray nativeRefusalStats(JNIEnv* env, jclass) {
    std::vector<jlong> values;
    gRefusalStats.iterate([&](const fw_refusal_key& key, const fw_refusal_stats& stats)
                                       -> android::base::Result<void> {
        pack(values, key, stats);
        return {};
    });
    return toArray(env, values);
}

const JNINativeMethod kMethods[] = {
        {"nativeRefusalsFd", "()Ljava/io/FileDescriptor;",
         reinterpret_cast<void*>(nativeRefusalsFd)},
        {"nativeConsumeRefusals", "()[J", reinterpret_cast<void*>(nativeConsumeRefusals)},
        {"nativeRefusalStats", "()[J", reinterpret_cast<void*>(nativeRefusalStats)},
};

}  // namespace

bool initRefusalCounts() {
    return init(gRefusalStats, FW_MAP_PATH("refusal_stats"));
}

int registerRefusalCounts(JNIEnv* env, jclass cls) {
    return env->RegisterNatives(cls, kMethods, sizeof(kMethods) / sizeof(kMethods[0]));
}

}  // namespace firewall
