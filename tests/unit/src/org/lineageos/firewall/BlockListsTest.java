/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import android.util.Pair;

import org.junit.Test;

import java.io.File;
import java.nio.file.Files;

/** Lists for all of a user's apps and for one app, as the service keeps them in the maps. */
public class BlockListsTest extends ServiceTestBase {
    private static final String ADS = "https://lists.test/ads.txt";
    private static final String DOH = "https://lists.test/doh.txt";

    private static int firewallAppUid(FirewallService service) {
        return service.knownUid(Pair.create(FirewallService.APP_PACKAGE, 0));
    }

    private int slot(FirewallService service, String id) {
        return service.feature(BlockLists.class).lists.get(id).slot;
    }

    private int generation(FirewallService service, String id) {
        return service.feature(BlockLists.class).lists.get(id).generation;
    }

    private File namesFile(FirewallService service, String id) {
        return new File(mDir, "firewall_lists/" + slot(service, id) + "-"
                + generation(service, id) + ".names");
    }

    @Test
    public void listsForAllAppsGoOnTheUserButNeverOnTheFirewallApp() {
        FirewallService service = start();
        String id = service.feature(BlockLists.class).addListInternal(0, null, ADS, true);
        long bit = 1L << slot(service, id);

        assertEquals(Long.valueOf(bit), mMaps.scopeLists.get("u0"));
        assertTrue((mMaps.userFlags.getOrDefault(0, 0) & FirewallMaps.SCOPE_LISTS) != 0);
        assertTrue((mMaps.uids.getOrDefault(firewallAppUid(service), 0)
                & FirewallMaps.NO_LISTS) != 0);
    }

    @Test
    public void anAppsListsGoOnItsUid() {
        FirewallService service = start();
        String id = service.feature(BlockLists.class).addListInternal(0, PACKAGE, DOH, true);

        assertEquals(Long.valueOf(1L << slot(service, id)),
                mMaps.scopeLists.get(Integer.toString(UID)));
        assertTrue((mMaps.uids.getOrDefault(UID, 0) & FirewallMaps.SCOPE_LISTS) != 0);
    }

    @Test
    public void scopesWithTheSameAddressShareItsSlot() {
        FirewallService service = start();
        BlockLists lists = service.feature(BlockLists.class);
        String forAll = lists.addListInternal(0, null, ADS, true);
        String forApp = lists.addListInternal(0, PACKAGE, ADS, true);

        assertEquals(forAll, forApp);
        assertEquals(1, lists.lists.size());
    }

    @Test
    public void contentGoesInANewGenerationAndBadContentKeepsTheLastGood() throws Exception {
        FirewallService service = start();
        BlockLists lists = service.feature(BlockLists.class);
        String id = lists.addListInternal(0, null, ADS, true);
        int slot = slot(service, id);

        assertEquals(0, lists.setListContentInternal(id,
                open(content("ads.example.com", "203.0.113.0/24")), "Ads", "1", "\"a\"", null));
        int generation = generation(service, id);
        assertNotEquals(0, generation);
        assertEquals(Integer.valueOf(generation), mMaps.listFiles.get(slot));
        assertTrue(namesFile(service, id).isFile());
        assertEquals(Long.valueOf(1L << slot), mMaps.listRanges.get("203.0.113.0/24"));

        File garbage = File.createTempFile("garbage", null, mDir);
        Files.writeString(garbage.toPath(), "<html>Not found</html>");
        assertEquals(IFirewall.LIST_ERROR_NOT_A_LIST,
                lists.setListContentInternal(id, open(garbage), null, null, null, null));
        assertEquals(Integer.valueOf(generation), mMaps.listFiles.get(slot));
        FirewallList list = lists.getListsInternal(0)[0];
        assertEquals(IFirewall.LIST_ERROR_NOT_A_LIST, list.error);
        assertEquals(1, list.domains);
        assertEquals("Ads", list.title);
    }

    @Test
    public void rangesCarryTheSlotsOfTheRangesAroundThem() throws Exception {
        FirewallService service = start();
        BlockLists lists = service.feature(BlockLists.class);
        String wide = lists.addListInternal(0, null, ADS, true);
        String narrow = lists.addListInternal(0, null, DOH, true);
        lists.setListContentInternal(wide, open(content("203.0.113.0/24")), null, null, null,
                null);
        lists.setListContentInternal(narrow, open(content("203.0.113.128/25")), null, null, null,
                null);

        long wideBit = 1L << slot(service, wide);
        long narrowBit = 1L << slot(service, narrow);
        assertEquals(Long.valueOf(wideBit), mMaps.listRanges.get("203.0.113.0/24"));
        assertEquals(Long.valueOf(wideBit | narrowBit), mMaps.listRanges.get("203.0.113.128/25"));
    }

    @Test
    public void theLastSubscriptionGoneFreesTheSlotAndFiles() throws Exception {
        FirewallService service = start();
        BlockLists lists = service.feature(BlockLists.class);
        String id = lists.addListInternal(0, null, ADS, true);
        int slot = slot(service, id);
        lists.setListContentInternal(id, open(content("ads.example.com", "203.0.113.0/24")),
                null, null, null, null);
        File names = namesFile(service, id);

        lists.removeListInternal(0, null, id);
        assertTrue(lists.lists.isEmpty());
        assertFalse(mMaps.scopeLists.containsKey("u0"));
        assertFalse(mMaps.listFiles.containsKey(slot));
        assertTrue(mMaps.listRanges.isEmpty());
        assertFalse(names.exists());
        assertEquals(0, mMaps.uids.getOrDefault(firewallAppUid(service), 0)
                & FirewallMaps.NO_LISTS);
    }

    @Test
    public void listsComeBackWithTheirContentAfterARestart() throws Exception {
        FirewallService service = start();
        BlockLists lists = service.feature(BlockLists.class);
        String id = lists.addListInternal(0, null, ADS, true);
        int slot = slot(service, id);
        lists.setListContentInternal(id, open(content("ads.example.com", "203.0.113.0/24")),
                null, null, null, null);
        int generation = generation(service, id);
        awaitSaved(service, reader -> {
            BlockLists.BlockList saved = reader.feature(BlockLists.class).lists.get(id);
            return saved != null && saved.generation == generation;
        });

        FakeMaps maps = new FakeMaps();
        FirewallService restarted = new FirewallService(context(), maps, mDir, mClock);
        restarted.init();
        assertEquals(Integer.valueOf(generation), maps.listFiles.get(slot));
        assertEquals(Long.valueOf(1L << slot), maps.listRanges.get("203.0.113.0/24"));
        assertEquals(Long.valueOf(1L << slot), maps.scopeLists.get("u0"));
    }

    @Test
    public void listsComeBackWhenTheFirewallIsTurnedOnAgain() throws Exception {
        FirewallService service = start();
        BlockLists lists = service.feature(BlockLists.class);
        String id = lists.addListInternal(0, null, ADS, true);
        int slot = slot(service, id);
        lists.setListContentInternal(id, open(content("203.0.113.0/24")), null, null, null, null);

        service.feature(MainSwitch.class).setEnabledInternal(false);
        assertFalse(mMaps.listFiles.containsKey(slot));
        service.feature(MainSwitch.class).setEnabledInternal(true);
        assertEquals(Integer.valueOf(generation(service, id)), mMaps.listFiles.get(slot));
        assertEquals(Long.valueOf(1L << slot), mMaps.scopeLists.get("u0"));
    }

    @Test
    public void backupsCarryTheAddressesNotTheContent() throws Exception {
        FirewallService service = start();
        BlockLists lists = service.feature(BlockLists.class);
        BackupRestore backups = service.feature(BackupRestore.class);
        String id = lists.addListInternal(0, null, ADS, false);
        lists.setListContentInternal(id, open(content("ads.example.com")), null, null, null, null);
        byte[] payload = backups.getBackupPayloadInternal(0);

        lists.removeListInternal(0, null, id);
        backups.applyRestoreInternal(0, payload);
        FirewallList[] restored = lists.getListsInternal(0);
        assertEquals(1, restored.length);
        assertEquals(ADS, restored[0].url);
        assertFalse(restored[0].subdomains);
        assertEquals(0, restored[0].domains);
    }
}
