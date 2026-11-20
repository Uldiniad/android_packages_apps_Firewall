/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import android.os.UserHandle;

import com.android.modules.utils.BasicShellCommandHandler;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Implements {@code cmd firewall}. */
final class FirewallShellCommand extends BasicShellCommandHandler {
    private static final Map<String, Integer> RULES = Map.of(
            "all", FirewallMaps.BLOCK_ALL,
            "wifi", FirewallMaps.BLOCK_WIFI,
            "mobile", FirewallMaps.BLOCK_CELLULAR,
            "vpn", FirewallMaps.BLOCK_VPN,
            "other", FirewallMaps.BLOCK_OTHER,
            "metered", FirewallMaps.BLOCK_METERED,
            "roaming", FirewallMaps.BLOCK_ROAMING,
            "dns", FirewallMaps.BLOCK_DNS);

    private final FirewallService mService;

    FirewallShellCommand(FirewallService service) {
        mService = service;
    }

    static String rulesToString(int rules) {
        List<String> names = new ArrayList<>();
        // In bit order: Map.of's own order changes from one boot to the next.
        for (Map.Entry<String, Integer> rule : RULES.entrySet().stream()
                .sorted(Map.Entry.comparingByValue()).toList()) {
            if ((rules & rule.getValue()) != 0) names.add(rule.getKey());
        }
        return names.isEmpty() ? "none" : String.join(",", names);
    }

    private static int parseRules(String text) {
        if (text.equals("none")) return 0;
        int rules = 0;
        for (String name : text.split(",")) {
            Integer bit = RULES.get(name);
            if (bit == null) throw new IllegalArgumentException("Unknown rule " + name);
            rules |= bit;
        }
        return rules;
    }

    int parseUser() {
        int user = UserHandle.SYSTEM.getIdentifier();
        String option;
        while ((option = getNextOption()) != null) {
            if (!option.equals("--user")) throw new IllegalArgumentException("Unknown " + option);
            user = Integer.parseInt(getNextArgRequired());
        }
        return user;
    }

    @Override
    public int onCommand(String cmd) {
        if (cmd == null) return handleDefaultCommands(cmd);
        PrintWriter pw = getOutPrintWriter();
        try {
            switch (cmd) {
                case "set-app" -> {
                    String packageName = getNextArgRequired();
                    int rules = parseRules(getNextArgRequired());
                    mService.setAppRulesInternal(packageName, parseUser(), rules);
                }
                case "get-app" -> {
                    String packageName = getNextArgRequired();
                    pw.println(rulesToString(mService.getAppRulesInternal(packageName,
                            parseUser())));
                }
                default -> {
                    for (Feature feature : mService.features()) {
                        Integer result = feature.onShellCommand(cmd, this);
                        if (result != null) return result;
                    }
                    return handleDefaultCommands(cmd);
                }
            }
            return 0;
        } catch (IllegalArgumentException | IOException e) {
            getErrPrintWriter().println("Error: " + e.getMessage());
            return 1;
        }
    }

    @Override
    public void onHelp() {
        PrintWriter pw = getOutPrintWriter();
        pw.println("Firewall commands:");
        pw.println("  set-app PACKAGE RULES [--user USER]");
        pw.println("      RULES: none, or a comma list of all,wifi,mobile,vpn,other,metered,");
        pw.println("      roaming,dns");
        pw.println("  get-app PACKAGE [--user USER]");
        for (Feature feature : mService.features()) feature.onShellHelp(pw);
    }
}
