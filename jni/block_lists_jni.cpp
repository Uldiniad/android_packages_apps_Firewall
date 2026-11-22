/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#define LOG_TAG "Firewall"

#include "firewall_jni.h"

namespace firewall {
namespace {

struct Lists {
    BpfMap<uint32_t, uint64_t> scopeLists;
    BpfMap<fw_ip4_key, uint64_t> listIp4;
    BpfMap<fw_ip6_key, uint64_t> listIp6;
    BpfMap<uint32_t, uint32_t> listFiles;
};

Lists gLists;

jint nativeSetScopeLists(JNIEnv*, jclass, jint scope, jlong slots) {
    return setOrUnset(gLists.scopeLists, static_cast<uint32_t>(scope),
                      static_cast<uint64_t>(slots));
}

jint nativeSetListRange(JNIEnv* env, jclass, jbyteArray address, jint prefixLength,
                        jlong slots) {
    jsize length = env->GetArrayLength(address);
    if (length == 4) {
        fw_ip4_key key = {.prefixlen = static_cast<__u32>(prefixLength)};
        env->GetByteArrayRegion(address, 0, 4, reinterpret_cast<jbyte*>(key.addr));
        return setOrUnset(gLists.listIp4, key, static_cast<uint64_t>(slots));
    }
    if (length == 16) {
        fw_ip6_key key = {.prefixlen = static_cast<__u32>(prefixLength)};
        env->GetByteArrayRegion(address, 0, 16, reinterpret_cast<jbyte*>(key.addr));
        return setOrUnset(gLists.listIp6, key, static_cast<uint64_t>(slots));
    }
    return EINVAL;
}

jint nativeSetListFile(JNIEnv*, jclass, jint slot, jint generation) {
    if (slot < 0 || slot >= FW_LIST_SLOTS) return EINVAL;
    return set(gLists.listFiles, static_cast<uint32_t>(slot), static_cast<uint32_t>(generation));
}

const JNINativeMethod kMethods[] = {
        {"nativeSetScopeLists", "(IJ)I", reinterpret_cast<void*>(nativeSetScopeLists)},
        {"nativeSetListRange", "([BIJ)I", reinterpret_cast<void*>(nativeSetListRange)},
        {"nativeSetListFile", "(II)I", reinterpret_cast<void*>(nativeSetListFile)},
};

}  // namespace

bool initBlockLists() {
    return init(gLists.scopeLists, FW_MAP_PATH("scope_lists")) &&
           init(gLists.listIp4, FW_MAP_PATH("list_ip4")) &&
           init(gLists.listIp6, FW_MAP_PATH("list_ip6")) &&
           init(gLists.listFiles, FW_MAP_PATH("list_files"));
}

void clearBlockLists() {
    clear(gLists.scopeLists);
    clear(gLists.listIp4);
    clear(gLists.listIp6);
    // An array's entries stay; 0 is none.
    for (uint32_t slot = 0; slot < FW_LIST_SLOTS; slot++) set(gLists.listFiles, slot, 0u);
}

int registerBlockLists(JNIEnv* env, jclass cls) {
    return env->RegisterNatives(cls, kMethods, sizeof(kMethods) / sizeof(kMethods[0]));
}

}  // namespace firewall
