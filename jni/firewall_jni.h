/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

// What the firewall's JNI files share: map helpers, and each feature's hooks into the core.

#pragma once

#include <bpf/BpfMap.h>
#include <errno.h>
#include <jni.h>
#include <log/log.h>

#include "firewall.h"

namespace firewall {

using android::bpf::BpfMap;

template <class Key, class Value>
bool init(BpfMap<Key, Value>& map, const char* path) {
    if (map.isValid()) return true;
    auto result = map.init(path);
    if (!result.ok()) ALOGE("open %s: %s", path, result.error().message().c_str());
    return result.ok();
}

template <class Key, class Value>
jint set(BpfMap<Key, Value>& map, const Key& key, const Value& value) {
    auto result = map.writeValue(key, value, BPF_ANY);
    return result.ok() ? 0 : result.error().code().value();
}

template <class Key, class Value>
jint unset(BpfMap<Key, Value>& map, const Key& key) {
    auto result = map.deleteValue(key);
    if (result.ok()) return 0;
    int error = result.error().code().value();
    return error == ENOENT ? 0 : error;
}

// Writes a nonzero value, or deletes the entry.
template <class Key, class Value>
jint setOrUnset(BpfMap<Key, Value>& map, const Key& key, Value value) {
    return value ? set(map, key, value) : unset(map, key);
}

template <class Key, class Value>
void clear(BpfMap<Key, Value>& map) {
    for (auto key = map.getFirstKey(); key.ok(); key = map.getFirstKey()) {
        if (!map.deleteValue(*key).ok()) return;
    }
}

// Writes value for the address into the IPv4 or IPv6 map by its length; a value of 0 deletes it.
template <typename Key4, typename Key6>
jint setPrefix(JNIEnv* env, jbyteArray address, Key4 key4, Key6 key6,
               BpfMap<Key4, uint32_t>& map4, BpfMap<Key6, uint32_t>& map6, uint32_t value) {
    jsize length = env->GetArrayLength(address);
    if (length == 4) {
        env->GetByteArrayRegion(address, 0, 4, reinterpret_cast<jbyte*>(key4.addr));
        return setOrUnset(map4, key4, value);
    }
    if (length == 16) {
        env->GetByteArrayRegion(address, 0, 16, reinterpret_cast<jbyte*>(key6.addr));
        return setOrUnset(map6, key6, value);
    }
    return EINVAL;
}

// Each feature opens and clears its maps, and registers its natives on FirewallMaps.
bool initRefusalCounts();
int registerRefusalCounts(JNIEnv* env, jclass cls);
bool initTargetRules();
void clearTargetRules();
int registerTargetRules(JNIEnv* env, jclass cls);
bool initSpecificNetworks();
void clearSpecificNetworks();
int registerSpecificNetworks(JNIEnv* env, jclass cls);
bool initLocalNetwork();
void clearLocalNetwork();
int registerLocalNetwork(JNIEnv* env, jclass cls);
bool initBlockLists();
void clearBlockLists();
int registerBlockLists(JNIEnv* env, jclass cls);

}  // namespace firewall
