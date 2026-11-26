/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include "safe_search.h"

#include <array>

namespace android::firewall {

namespace {

struct Engine {
    std::string_view name;
    std::string_view safe;
};

// The names each engine's own documentation has networks point to its safe-search name: Google's
// "Lock SafeSearch for devices & networks you manage", YouTube's "Restrict YouTube content on
// your network" (Strict), Bing's "Block adult content with SafeSearch" and DuckDuckGo's Safe
// Search help. Google's other search domains come from its list of them.
constexpr std::array kEngines = {
        Engine{"www.google.com", kGoogleSafeSearch},
        Engine{"google.com", kGoogleSafeSearch},
        Engine{"www.youtube.com", "restrict.youtube.com"},
        Engine{"m.youtube.com", "restrict.youtube.com"},
        Engine{"youtubei.googleapis.com", "restrict.youtube.com"},
        Engine{"youtube.googleapis.com", "restrict.youtube.com"},
        Engine{"www.youtube-nocookie.com", "restrict.youtube.com"},
        Engine{"www.bing.com", "strict.bing.com"},
        Engine{"edgeservices.bing.com", "strict.bing.com"},
        Engine{"duckduckgo.com", "safe.duckduckgo.com"},
        Engine{"www.duckduckgo.com", "safe.duckduckgo.com"},
};

}  // namespace

std::string_view engineSafeName(std::string_view name) {
    for (const Engine& engine : kEngines) {
        if (name == engine.name) return engine.safe;
    }
    return {};
}

std::string_view googleSearchDomain(std::string_view name) {
    if (name.starts_with("www.")) name.remove_prefix(4);
    return name.starts_with("google.") ? name : std::string_view();
}

}  // namespace android::firewall
