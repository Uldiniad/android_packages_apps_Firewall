/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <string_view>

namespace android::firewall {

// The name Google's documentation has networks look up in place of its search domains.
inline constexpr std::string_view kGoogleSafeSearch = "forcesafesearch.google.com";

// The safe-search name of a search engine's name, by the names each engine's documentation gives
// networks; empty for other names. The name is lower case, without a final dot.
std::string_view engineSafeName(std::string_view name);

// The Google search domain the name would be, such as google.co.uk for www.google.co.uk, which
// Safe Search covers once Google's list of them holds it; empty when it can't be one.
std::string_view googleSearchDomain(std::string_view name);

}  // namespace android::firewall
