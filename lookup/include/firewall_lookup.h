/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <netinet/in.h>
#include <stddef.h>
#include <sys/types.h>

namespace android::firewall {

// Whether the app may look up the name on the network. netd asks for the resolver, before
// Private DNS encrypts the lookup.
bool allowsLookup(uid_t uid, unsigned netId, const char* name);

// The addresses of an answer to the app's lookup of the name, which the resolver hands over
// before the app gets them.
void learnAnswer(uid_t uid, const char* name, const in6_addr* addresses, size_t count);

}  // namespace android::firewall
