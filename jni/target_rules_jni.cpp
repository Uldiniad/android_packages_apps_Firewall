/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#define LOG_TAG "Firewall"

#include <vector>

#include "firewall_domain.h"
#include "firewall_jni.h"

namespace firewall {
namespace {

struct Rules {
    BpfMap<uint32_t, uint32_t> userFlags;
    BpfMap<fw_scope_ip4_key, uint32_t> ip4Block;
    BpfMap<fw_scope_ip6_key, uint32_t> ip6Block;
    BpfMap<fw_scope_ip4_key, uint32_t> ip4Allow;
    BpfMap<fw_scope_ip6_key, uint32_t> ip6Allow;
    BpfMap<fw_port_key, uint32_t> portRules;
    BpfMap<fw_scope_domain_key, uint64_t> domainRules;
    BpfMap<fw_learned_key, uint32_t> learned;
    BpfMap<uint32_t, fw_limits> scopeLimits;
};

Rules gRules;

jint nativeSetUserFlags(JNIEnv*, jclass, jint user, jint flags) {
    return setOrUnset(gRules.userFlags, static_cast<uint32_t>(user), static_cast<uint32_t>(flags));
}

// Limit 0 is every network, so the arrays start at limit 1; empty ones delete the scope's limits.
jint nativeSetLimits(JNIEnv* env, jclass, jint scope, jlongArray only, jlongArray except,
                     jint ported, jint localNetwork) {
    jsize count = env->GetArrayLength(only);
    if (count == 0) return unset(gRules.scopeLimits, static_cast<uint32_t>(scope));
    if (count >= FW_LIMITS || env->GetArrayLength(except) != count) return EINVAL;
    fw_limits limits = {.ported = static_cast<__u32>(ported),
                        .local_network = static_cast<__u32>(localNetwork)};
    env->GetLongArrayRegion(only, 0, count, reinterpret_cast<jlong*>(&limits.only[1]));
    env->GetLongArrayRegion(except, 0, count, reinterpret_cast<jlong*>(&limits.except[1]));
    return set(gRules.scopeLimits, static_cast<uint32_t>(scope), limits);
}

jint nativeSetIp(JNIEnv* env, jclass, jint scope, jbyteArray address, jint prefixLength,
                 jboolean allow, jint limits) {
    __u32 prefix = 32 + prefixLength, owner = scope;
    return setPrefix(env, address, fw_scope_ip4_key{.prefixlen = prefix, .scope = owner},
                     fw_scope_ip6_key{.prefixlen = prefix, .scope = owner},
                     allow ? gRules.ip4Allow : gRules.ip4Block,
                     allow ? gRules.ip6Allow : gRules.ip6Block, static_cast<uint32_t>(limits));
}

jint nativeSetDomain(JNIEnv* env, jclass, jint scope, jstring domain, jlong bits) {
    const char* chars = env->GetStringUTFChars(domain, nullptr);
    fw_scope_domain_key key = {.scope = static_cast<__u32>(scope),
                               .hash = fw_domain_hash(chars)};
    env->ReleaseStringUTFChars(domain, chars);
    return setOrUnset(gRules.domainRules, key, static_cast<uint64_t>(bits));
}

jint nativeSetPort(JNIEnv*, jclass, jint scope, jint protocol, jint port, jint prefixLength,
                   jint bits) {
    fw_port_key key = {.prefixlen = static_cast<__u32>(FW_PORT_PREFIX_BITS + prefixLength),
                       .scope = static_cast<__u32>(scope),
                       .protocol = static_cast<__u8>(protocol),
                       .port = {static_cast<__u8>(port >> 8), static_cast<__u8>(port)}};
    return setOrUnset(gRules.portRules, key, static_cast<uint32_t>(bits));
}

// Drops the addresses learned for a scope, whose domain allow rules or blocks with a port changed.
void nativeForgetLearned(JNIEnv*, jclass, jint scope) {
    std::vector<fw_learned_key> keys;
    gRules.learned.iterate([&](const fw_learned_key& key) -> android::base::Result<void> {
        if (key.scope == static_cast<__u32>(scope)) keys.push_back(key);
        return {};
    });
    for (const auto& key : keys) unset(gRules.learned, key);
}

const JNINativeMethod kMethods[] = {
        {"nativeSetUserFlags", "(II)I", reinterpret_cast<void*>(nativeSetUserFlags)},
        {"nativeSetIp", "(I[BIZI)I", reinterpret_cast<void*>(nativeSetIp)},
        {"nativeSetDomain", "(ILjava/lang/String;J)I", reinterpret_cast<void*>(nativeSetDomain)},
        {"nativeSetLimits", "(I[J[JII)I", reinterpret_cast<void*>(nativeSetLimits)},
        {"nativeSetPort", "(IIIII)I", reinterpret_cast<void*>(nativeSetPort)},
        {"nativeForgetLearned", "(I)V", reinterpret_cast<void*>(nativeForgetLearned)},
};

}  // namespace

bool initTargetRules() {
    return init(gRules.userFlags, FW_MAP_PATH("user_flags")) &&
           init(gRules.ip4Block, FW_MAP_PATH("ip4_block")) &&
           init(gRules.ip6Block, FW_MAP_PATH("ip6_block")) &&
           init(gRules.ip4Allow, FW_MAP_PATH("ip4_allow")) &&
           init(gRules.ip6Allow, FW_MAP_PATH("ip6_allow")) &&
           init(gRules.portRules, FW_MAP_PATH("port_rules")) &&
           init(gRules.domainRules, FW_MAP_PATH("domain_rules")) &&
           init(gRules.learned, FW_MAP_PATH("learned")) &&
           init(gRules.scopeLimits, FW_MAP_PATH("scope_limits"));
}

void clearTargetRules() {
    clear(gRules.userFlags);
    clear(gRules.ip4Block);
    clear(gRules.ip6Block);
    clear(gRules.ip4Allow);
    clear(gRules.ip6Allow);
    clear(gRules.portRules);
    clear(gRules.domainRules);
    clear(gRules.learned);
    clear(gRules.scopeLimits);
}

int registerTargetRules(JNIEnv* env, jclass cls) {
    return env->RegisterNatives(cls, kMethods, sizeof(kMethods) / sizeof(kMethods[0]));
}

}  // namespace firewall
