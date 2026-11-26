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

// Whether the app may have an answer that leads through the cnames to the addresses: not when
// its domain rules block one of those names, unless its allow rules cover a name of the answer.
// Lets the app reach the addresses of an answer its allow rules cover. The resolver hands over
// each answer before the app gets it, so the app's first connection already passes.
bool allowsAnswer(uid_t uid, unsigned netId, const char* name, const char* const* cnames,
                  size_t cnameCount, const in6_addr* addresses, size_t count);

// The uid that a hotspot device's lookups count as, by an address it sent from, IPv4 as
// IPv4-mapped: the device's, when it has rules of its own; -1 when they count as dnsmasq's.
uid_t tetheringClientUid(const in6_addr* address);

// Writes the name the resolver looks up in place of the one the app asked for into the buffer of
// the size, NUL-terminated: a search engine's safe-search name, while the app's user has Safe
// Search on. False when the name is looked up as asked.
bool lookupNameFor(uid_t uid, const char* name, char* buffer, size_t size);

}  // namespace android::firewall
