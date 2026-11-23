/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

// Included once, by firewall.c, after the rules for addresses and the local network.
#pragma once

// Rules for connections others open to an app, by the port on the phone they arrive at, from
// anyone, the local network or an address. A rule's entries are its senders' ranges in the
// address tries, under the app's or its user's scope with FW_INCOMING_SCOPE set, and a limit with
// the port. Allow rules cover all that comes and goes at their port, so a blocked app can answer;
// block rules cover what opens a connection: a TCP handshake, or anything over UDP.

// Whether the far end is on one of the networks' local subnets.
static __always_inline bool on_local_network(const struct l4_info* info) {
    if (info->v6) {
        struct fw_ip6_key key = {.prefixlen = 128};
        __builtin_memcpy(key.addr, info->addr, sizeof(key.addr));
        return bpf_map_lookup_elem(&lan6, &key) != NULL;
    }
    struct fw_ip4_key key = {.prefixlen = 32};
    __builtin_memcpy(key.addr, &info->addr[0], sizeof(key.addr));
    return bpf_map_lookup_elem(&lan4, &key) != NULL;
}

// The protocol and the port on the phone, and whether the far end is on the local network, which
// the limits of incoming rules check.
static __always_inline __u32 local_at(const struct l4_info* info) {
    return (__u32)info->protocol << 16 | info->local_port |
           (on_local_network(info) ? FW_AT_LOCAL_NETWORK : 0);
}

static __always_inline bool incoming_listed(void* trie4, void* trie6, __u32 scope,
                                            const struct l4_info* info,
                                            const struct fw_path* path, __u32 at) {
    return listed_at(trie4, trie6, scope | FW_INCOMING_SCOPE, FW_SCOPE_LIMITS, info, path, at);
}

// The byte of TCP's flags with SYN and ACK, as Connectivity's netd.c reads it.
#define FW_TCP_FLAG8_OFF 13
#define FW_TCP_FLAG8_SYN 0x02
#define FW_TCP_FLAG8_ACK 0x10

// Whether a packet opens a TCP connection: a TCP segment with SYN and without ACK.
static __always_inline bool tcp_opens(struct __sk_buff* skb, const struct l4_info* info) {
    if (info->protocol != IPPROTO_TCP) return false;
    __u8 flags;
    if (bpf_skb_load_bytes(skb, info->l4_offset + FW_TCP_FLAG8_OFF, &flags, 1)) return false;
    return (flags & (FW_TCP_FLAG8_SYN | FW_TCP_FLAG8_ACK)) == FW_TCP_FLAG8_SYN;
}

// What the app's incoming rules, then its user's, decide for a packet that arrives: 1 lets it in,
// 0 drops it, -1 leaves it to the other rules. A blocked app follows only its own rules.
static __always_inline int incoming_verdict(struct __sk_buff* skb, __u32 uid, __u32 rules,
                                            __u32 uflags, bool blocked,
                                            const struct l4_info* info,
                                            const struct fw_path* path) {
    if (!((rules | uflags) & FW_SCOPE_INCOMING)) return -1;
    if (info->protocol != IPPROTO_TCP && info->protocol != IPPROTO_UDP) return -1;
    __u32 at = local_at(info);
    bool opens = info->protocol == IPPROTO_UDP || tcp_opens(skb, info);
    if ((rules & FW_SCOPE_INCOMING_ALLOWS) &&
        incoming_listed(&ip4_allow, &ip6_allow, uid, info, path, at)) {
        return 1;
    }
    if (opens && (rules & FW_SCOPE_INCOMING_BLOCKS) &&
        incoming_listed(&ip4_block, &ip6_block, uid, info, path, at)) {
        return 0;
    }
    if (blocked) return -1;
    __u32 user_scope = FW_USER_SCOPE | (uid / AID_USER_OFFSET);
    if ((uflags & FW_SCOPE_INCOMING_ALLOWS) &&
        incoming_listed(&ip4_allow, &ip6_allow, user_scope, info, path, at)) {
        return 1;
    }
    if (opens && (uflags & FW_SCOPE_INCOMING_BLOCKS) &&
        incoming_listed(&ip4_block, &ip6_block, user_scope, info, path, at)) {
        return 0;
    }
    return -1;
}

// Whether a packet out answers what the scope's incoming allow rules let in: it leaves from their
// port, for a sender they let in.
static __always_inline bool incoming_replies(__u32 scope, const struct l4_info* info,
                                             const struct fw_path* path) {
    if (info->protocol != IPPROTO_TCP && info->protocol != IPPROTO_UDP) return false;
    return incoming_listed(&ip4_allow, &ip6_allow, scope, info, path, local_at(info));
}

// The FW_REFUSED_* bits of the incoming block rules that cover a refused connection: the app's
// and its user's.
static __always_inline __u32 incoming_reasons(__u32 uid, __u32 rules, __u32 uflags,
                                              const struct l4_info* info,
                                              const struct fw_path* path) {
    __u32 at = local_at(info);
    __u32 reasons = 0;
    if ((rules & FW_SCOPE_INCOMING_BLOCKS) &&
        incoming_listed(&ip4_block, &ip6_block, uid, info, path, at)) {
        reasons |= FW_REFUSED_INCOMING;
    }
    if ((uflags & FW_SCOPE_INCOMING_BLOCKS) &&
        incoming_listed(&ip4_block, &ip6_block, FW_USER_SCOPE | (uid / AID_USER_OFFSET), info,
                        path, at)) {
        reasons |= FW_REFUSED_USER_INCOMING;
    }
    return reasons;
}
