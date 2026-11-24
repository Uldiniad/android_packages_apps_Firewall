/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#define LOG_TAG "Firewall"

#include <android-base/unique_fd.h>
#include <android/file_descriptor_jni.h>
#include <android/net/IDnsResolver.h>
#include <android/net/metrics/BnNetdEventListener.h>
#include <binder/IServiceManager.h>
#include <log/log.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include <deque>
#include <mutex>
#include <string>
#include <vector>

#include "firewall_jni.h"

namespace firewall {
namespace {

using android::binder::Status;

// A lookup as the resolver reported it, with the app's uid and the resolver's result.
struct Lookup {
    int32_t uid;
    int32_t result;
    std::string name;
    std::vector<std::string> addresses;
};

// Lookups the service hasn't taken yet. Past the limit the oldest go, so a busy service never
// holds up the resolver's reports.
constexpr size_t kMaxLookups = 4096;
std::mutex gLock;
std::deque<Lookup> gLookups;
bool gWanted = false;
android::base::unique_fd gReady(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK));

class Listener : public android::net::metrics::BnNetdEventListener {
  public:
    Status onDnsEvent(int32_t, int32_t, int32_t returnCode, int32_t, const std::string& hostname,
                      const std::vector<std::string>& ipAddresses, int32_t,
                      int32_t uid) override {
        {
            std::lock_guard guard(gLock);
            if (!gWanted) return Status::ok();
            if (gLookups.size() >= kMaxLookups) gLookups.pop_front();
            gLookups.push_back({uid, returnCode, hostname, ipAddresses});
        }
        uint64_t one = 1;
        if (write(gReady.get(), &one, sizeof(one)) < 0) ALOGE("lookups: %s", strerror(errno));
        return Status::ok();
    }
    Status onPrivateDnsValidationEvent(int32_t, const android::String16&,
                                       const android::String16&, bool) override {
        return Status::ok();
    }
    Status onConnectEvent(int32_t, int32_t, int32_t, const android::String16&, int32_t,
                          int32_t) override {
        return Status::ok();
    }
    Status onWakeupEvent(const android::String16&, int32_t, int32_t, int32_t,
                         const std::vector<uint8_t>&, const android::String16&,
                         const android::String16&, int32_t, int32_t, int64_t) override {
        return Status::ok();
    }
    Status onTcpSocketStatsEvent(const std::vector<int32_t>&, const std::vector<int32_t>&,
                                 const std::vector<int32_t>&, const std::vector<int32_t>&,
                                 const std::vector<int32_t>&) override {
        return Status::ok();
    }
    Status onNat64PrefixEvent(int32_t, bool, const std::string&, int32_t) override {
        return Status::ok();
    }
};

// Registers a listener with the resolver, once: it has no way to unregister one, so whether
// lookups are kept is a switch here.
jobject nativeListenForLookups(JNIEnv* env, jclass) {
    static const bool registered = [] {
        android::sp<android::net::IDnsResolver> resolver =
                android::interface_cast<android::net::IDnsResolver>(
                        android::defaultServiceManager()->checkService(
                                android::String16("dnsresolver")));
        if (!resolver) {
            ALOGE("lookups: no resolver");
            return false;
        }
        Status status = resolver->registerEventListener(android::sp<Listener>::make());
        if (!status.isOk()) ALOGE("lookups: %s", status.toString8().c_str());
        return status.isOk();
    }();
    if (!registered || gReady.get() < 0) return nullptr;
    jobject descriptor = AFileDescriptor_create(env);
    AFileDescriptor_setFd(env, descriptor, dup(gReady.get()));
    return descriptor;
}

void nativeSetLookupsWanted(JNIEnv*, jclass, jboolean wanted) {
    std::lock_guard guard(gLock);
    gWanted = wanted;
    if (!wanted) gLookups.clear();
}

// The lookups since the last call, each as its uid, result, name and addresses.
jobjectArray nativeConsumeLookups(JNIEnv* env, jclass) {
    uint64_t count;
    if (read(gReady.get(), &count, sizeof(count)) < 0 && errno != EAGAIN) {
        ALOGE("lookups: %s", strerror(errno));
    }
    std::deque<Lookup> lookups;
    {
        std::lock_guard guard(gLock);
        lookups.swap(gLookups);
    }
    jclass stringClass = env->FindClass("java/lang/String");
    jclass arrayClass = env->FindClass("[Ljava/lang/String;");
    jobjectArray out = env->NewObjectArray(lookups.size(), arrayClass, nullptr);
    for (size_t i = 0; i < lookups.size(); i++) {
        const Lookup& lookup = lookups[i];
        std::vector<std::string> fields = {std::to_string(lookup.uid),
                                           std::to_string(lookup.result), lookup.name};
        fields.insert(fields.end(), lookup.addresses.begin(), lookup.addresses.end());
        jobjectArray row = env->NewObjectArray(fields.size(), stringClass, nullptr);
        for (size_t j = 0; j < fields.size(); j++) {
            jstring field = env->NewStringUTF(fields[j].c_str());
            env->SetObjectArrayElement(row, j, field);
            env->DeleteLocalRef(field);
        }
        env->SetObjectArrayElement(out, i, row);
        env->DeleteLocalRef(row);
    }
    return out;
}

const JNINativeMethod kMethods[] = {
        {"nativeListenForLookups", "()Ljava/io/FileDescriptor;",
         reinterpret_cast<void*>(nativeListenForLookups)},
        {"nativeSetLookupsWanted", "(Z)V", reinterpret_cast<void*>(nativeSetLookupsWanted)},
        {"nativeConsumeLookups", "()[[Ljava/lang/String;",
         reinterpret_cast<void*>(nativeConsumeLookups)},
};

}  // namespace

int registerActivityLog(JNIEnv* env, jclass cls) {
    return env->RegisterNatives(cls, kMethods, sizeof(kMethods) / sizeof(kMethods[0]));
}

}  // namespace firewall
