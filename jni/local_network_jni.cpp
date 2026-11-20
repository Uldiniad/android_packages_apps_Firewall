/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#define LOG_TAG "Firewall"

#include "firewall_jni.h"

namespace firewall {
namespace {

BpfMap<fw_ip4_key, uint32_t> gLan4;
BpfMap<fw_ip6_key, uint32_t> gLan6;

jint nativeSetLan(JNIEnv* env, jclass, jbyteArray address, jint prefixLength, jint kind) {
    __u32 prefix = prefixLength;
    return setPrefix(env, address, fw_ip4_key{.prefixlen = prefix},
                     fw_ip6_key{.prefixlen = prefix}, gLan4, gLan6, kind);
}

const JNINativeMethod kMethods[] = {
        {"nativeSetLan", "([BII)I", reinterpret_cast<void*>(nativeSetLan)},
};

}  // namespace

bool initLocalNetwork() {
    return init(gLan4, FW_MAP_PATH("lan4")) && init(gLan6, FW_MAP_PATH("lan6"));
}

void clearLocalNetwork() {
    clear(gLan4);
    clear(gLan6);
}

int registerLocalNetwork(JNIEnv* env, jclass cls) {
    return env->RegisterNatives(cls, kMethods, sizeof(kMethods) / sizeof(kMethods[0]));
}

}  // namespace firewall
