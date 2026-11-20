/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#define LOG_TAG "Firewall"

#include "firewall_jni.h"

namespace firewall {
namespace {

BpfMap<uint32_t, fw_named_networks> gUidNetworks;

jint nativeSetNamedNetworks(JNIEnv*, jclass, jint uid, jint block, jint allow) {
    if (!block && !allow) return unset(gUidNetworks, static_cast<uint32_t>(uid));
    return set(gUidNetworks, static_cast<uint32_t>(uid),
               fw_named_networks{.block = static_cast<__u32>(block),
                                 .allow = static_cast<__u32>(allow)});
}

const JNINativeMethod kMethods[] = {
        {"nativeSetNamedNetworks", "(III)I", reinterpret_cast<void*>(nativeSetNamedNetworks)},
};

}  // namespace

bool initSpecificNetworks() {
    return init(gUidNetworks, FW_MAP_PATH("uid_networks"));
}

void clearSpecificNetworks() {
    clear(gUidNetworks);
}

int registerSpecificNetworks(JNIEnv* env, jclass cls) {
    return env->RegisterNatives(cls, kMethods, sizeof(kMethods) / sizeof(kMethods[0]));
}

}  // namespace firewall
