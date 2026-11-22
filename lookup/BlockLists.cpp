/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#define LOG_TAG "Firewall"

#include "block_lists.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <algorithm>
#include <memory>
#include <mutex>
#include <string>

#include <android-base/unique_fd.h>
#include <bpf/BpfMap.h>
#include <log/log.h>

#include "firewall.h"

namespace android::firewall {

namespace {

using bpf::BpfMapRO;

struct ListMaps {
    BpfMapRO<uint32_t, uint64_t> scopeLists;
    BpfMapRO<uint32_t, uint32_t> listFiles;
    bool ready = false;
};

const ListMaps& listMaps() {
    static const ListMaps* const maps = [] {
        auto* m = new ListMaps();
        m->ready = m->scopeLists.init(FW_MAP_PATH("scope_lists")).ok() &&
                   m->listFiles.init(FW_MAP_PATH("list_files")).ok();
        if (!m->ready) ALOGE("list maps unavailable");
        return m;
    }();
    return *maps;
}

// A slot's file of keys, mapped for as long as lookups use it.
class Keys {
  public:
    Keys(void* base, size_t size) : mBase(base), mSize(size) {}
    ~Keys() { munmap(mBase, mSize); }
    Keys(const Keys&) = delete;
    Keys& operator=(const Keys&) = delete;

    const int64_t* begin() const { return static_cast<const int64_t*>(mBase) + 2; }
    const int64_t* end() const { return static_cast<const int64_t*>(mBase) + mSize / 8; }

  private:
    void* const mBase;
    const size_t mSize;
};

std::shared_ptr<const Keys> mapKeys(uint32_t slot, uint32_t generation) {
    std::string path = FW_LISTS_DIR + std::to_string(slot) + "-" + std::to_string(generation) +
                       ".names";
    base::unique_fd fd(open(path.c_str(), O_RDONLY | O_CLOEXEC));
    struct stat st;
    if (!fd.ok() || fstat(fd.get(), &st) != 0) {
        ALOGE("list %u: %s", slot, strerror(errno));
        return nullptr;
    }
    size_t size = static_cast<size_t>(st.st_size);
    if (size < 16 || size % 8 != 0) {
        ALOGE("list %u: malformed", slot);
        return nullptr;
    }
    void* base = mmap(nullptr, size, PROT_READ, MAP_SHARED, fd.get(), 0);
    if (base == MAP_FAILED) {
        ALOGE("list %u: %s", slot, strerror(errno));
        return nullptr;
    }
    auto keys = std::make_shared<const Keys>(base, size);
    const uint64_t* header = static_cast<const uint64_t*>(base);
    if (header[0] != FW_LIST_NAMES_MAGIC || header[1] != size / 8 - 2) {
        ALOGE("list %u: malformed", slot);
        return nullptr;
    }
    return keys;
}

std::mutex gLock;
// Each slot's mapped generation, mapped again once list_files names a new one.
struct Mapped {
    uint32_t generation = 0;
    std::shared_ptr<const Keys> keys;
};
Mapped gMapped[FW_LIST_SLOTS];

std::shared_ptr<const Keys> keysOf(const ListMaps& maps, uint32_t slot) {
    auto generation = maps.listFiles.readValue(slot);
    if (!generation.ok() || *generation == 0) return nullptr;
    std::lock_guard lock(gLock);
    Mapped& mapped = gMapped[slot];
    if (mapped.generation != *generation) {
        mapped.keys = mapKeys(slot, *generation);
        mapped.generation = *generation;
    }
    return mapped.keys;
}

// A whole name matches its own entry and one for its subdomains, a parent domain only the latter.
bool holds(const Keys& keys, uint64_t hash, bool wholeName) {
    int64_t name = static_cast<int64_t>(hash & ~1ULL);
    const int64_t* it = std::lower_bound(keys.begin(), keys.end(), name);
    if (it != keys.end() && *it == name) {
        if (wholeName) return true;
        ++it;
    }
    return it != keys.end() && *it == name + 1;
}

}  // namespace

uint64_t listSlots(uint32_t scope) {
    const ListMaps& maps = listMaps();
    if (!maps.ready) return 0;
    auto slots = maps.scopeLists.readValue(scope);
    return slots.ok() ? *slots : 0;
}

bool listsHold(uint64_t slots, const std::vector<uint64_t>& suffixes) {
    const ListMaps& maps = listMaps();
    if (!maps.ready) return false;
    for (uint32_t slot = 0; slot < FW_LIST_SLOTS; slot++) {
        if (!((slots >> slot) & 1)) continue;
        std::shared_ptr<const Keys> keys = keysOf(maps, slot);
        if (!keys) continue;
        for (size_t i = 0; i < suffixes.size(); i++) {
            if (holds(*keys, suffixes[i], i + 1 == suffixes.size())) return true;
        }
    }
    return false;
}

}  // namespace android::firewall
