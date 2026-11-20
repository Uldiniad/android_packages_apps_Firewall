/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import static org.junit.Assert.assertEquals;

import android.os.Process;
import android.util.AtomicFile;
import android.util.Xml;

import com.android.modules.utils.TypedXmlSerializer;
import android.util.Pair;

import org.junit.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Map;

import java.nio.charset.StandardCharsets;

/** Importing the blocks of Lineage's old firewall. */
public class LineageImportTest extends ServiceTestBase {
    // Lineage's NetworkPolicyManager bits, which the firewall replaced.
    static final int REJECT_WIFI = 0x8000;
    static final int REJECT_CELLULAR = 0x10000;
    static final int REJECT_VPN = 0x20000;
    static final int REJECT_ALL = 0x40000;
    static final int ALLOW_METERED_BACKGROUND = 0x4;

    /** Writes netpolicy.xml the way NPMS does, by UID. */
    static void writeNetpolicy(File dir, boolean binary, Map<Integer, Integer> policies)
            throws IOException {
        AtomicFile file = new AtomicFile(new File(dir, "netpolicy.xml"));
        FileOutputStream out = file.startWrite();
        TypedXmlSerializer xml = binary ? Xml.newBinarySerializer() : Xml.newFastSerializer();
        xml.setOutput(out, StandardCharsets.UTF_8.name());
        xml.startDocument(null, true);
        xml.startTag(null, "policy-list");
        xml.attributeInt(null, "version", 14);
        for (Map.Entry<Integer, Integer> policy : policies.entrySet()) {
            xml.startTag(null, "uid-policy");
            xml.attributeInt(null, "uid", policy.getKey());
            xml.attributeInt(null, "policy", policy.getValue());
            xml.endTag(null, "uid-policy");
        }
        xml.endTag(null, "policy-list");
        xml.endDocument();
        file.finishWrite(out);
    }

    @Test
    public void lineageBlocksAreReadFromEitherNetpolicyFormat() throws Exception {
        for (boolean binary : new boolean[] {true, false}) {
            writeNetpolicy(mDir, binary, Map.of(10123, REJECT_ALL,
                    10124, REJECT_WIFI | REJECT_CELLULAR | ALLOW_METERED_BACKGROUND,
                    1010125, REJECT_VPN, 10126, ALLOW_METERED_BACKGROUND));
            assertEquals(Map.of(10123, FirewallMaps.BLOCK_ALL,
                    10124, FirewallMaps.BLOCK_WIFI | FirewallMaps.BLOCK_CELLULAR,
                    1010125, FirewallMaps.BLOCK_VPN),
                    LineageImport.readLineageRules(new File(mDir, "netpolicy.xml")));
        }
    }


    @Test
    public void lineageBlocksAreImportedOnTheFirstStartOnly() throws Exception {
        writeNetpolicy(mDir, true,
                Map.of(UID, REJECT_WIFI | REJECT_CELLULAR));
        FirewallService service = start();
        int rules = FirewallMaps.BLOCK_WIFI | FirewallMaps.BLOCK_CELLULAR;
        assertEquals(rules, service.getAppRulesInternal(PACKAGE, 0));
        // Saved before NPMS gets to drop the bits.
        FirewallService saved = unstarted();
        saved.store().load();
        assertEquals(rules, (int) saved.store().apps.get(Pair.create(PACKAGE, 0)));

        // Until NPMS drops them, the bits must not undo a later choice.
        service.setAppRulesInternal(PACKAGE, 0, 0);
        awaitSaved(service,
                reader -> Integer.valueOf(0).equals(
                        reader.store().apps.get(Pair.create(PACKAGE, 0))));
        assertEquals(0, start().getAppRulesInternal(PACKAGE, 0));
    }

    @Test
    public void lineageLeftoversNeverImportOnLaterStarts() throws Exception {
        unstarted().store().save();
        writeNetpolicy(mDir, true, Map.of(UID, REJECT_ALL));
        FirewallService service = start();

        // NPMS writes the file again, here restoring another app; only that one is new.
        writeNetpolicy(mDir, true, Map.of(UID, REJECT_ALL,
                Process.SHELL_UID, REJECT_WIFI));
        mMaps.awaitUid(Process.SHELL_UID, FirewallMaps.BLOCK_WIFI);
        assertEquals(0, service.getAppRulesInternal(PACKAGE, 0));
    }

    @Test
    public void lineageBlocksFromAnOldBackupApplyAsNpmsRestoresEachApp() throws Exception {
        FirewallService service = start();
        writeNetpolicy(mDir, true, Map.of(UID, REJECT_ALL));
        mMaps.awaitUid(UID, FirewallMaps.BLOCK_ALL);
        service.setAppRulesInternal(PACKAGE, 0, 0);

        // NPMS writes the file again for the next app it restores; the choice above stays.
        writeNetpolicy(mDir, true, Map.of(UID, REJECT_ALL,
                Process.SHELL_UID, REJECT_WIFI));
        mMaps.awaitUid(Process.SHELL_UID, FirewallMaps.BLOCK_WIFI);
        assertEquals(0, service.getAppRulesInternal(PACKAGE, 0));
    }
}
