/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdint.h>

#include <vector>

namespace android::firewall {

// The slots of the lists the scope subscribes to, as bits.
uint64_t listSlots(uint32_t scope);

// Whether a list in one of the slots holds the name, given its suffixes' hashes, top-level
// domain first.
bool listsHold(uint64_t slots, const std::vector<uint64_t>& suffixes);

}  // namespace android::firewall
