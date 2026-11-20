/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import android.Manifest;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.PackageInfoFlags;
import android.net.ConnectivityManager;
import android.os.Binder;
import android.os.Environment;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.os.RemoteCallbackList;
import android.os.RemoteException;
import android.os.UserHandle;
import android.os.UserManager;
import android.util.Log;
import android.util.Pair;

import com.android.internal.content.PackageMonitor;
import com.android.server.SystemService;

import java.io.File;
import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.time.Clock;

/**
 * Owns the firewall rules, keeps them in the BPF maps and serves the app and the shell.
 * Started by SystemServer through config_deviceSpecificSystemServices.
 */
public final class FirewallService extends SystemService {
    static final String TAG = "Firewall";
    private static final String SERVICE_NAME = "firewall";
    static final String PERMISSION = "org.lineageos.firewall.permission.MANAGE_FIREWALL";
    static final String APP_PACKAGE = "org.lineageos.firewall";
    // Like NetworkPolicyManagerService: see apps of locked users, and disabled apps.
    static final long PACKAGE_FLAGS = PackageManager.MATCH_DIRECT_BOOT_AWARE
            | PackageManager.MATCH_DIRECT_BOOT_UNAWARE | PackageManager.MATCH_DISABLED_COMPONENTS;

    private final Context mContext;
    private final Handler mHandler;
    private final Maps mMaps;
    private final FirewallStore mStore;
    private final RemoteCallbackList<IFirewallListener> mListeners = new RemoteCallbackList<>();
    private final NetworkTracker mNetworks;
    /** The firewall's features, each consulted at the points where it has a say. */
    private final List<Feature> mFeatures;
    /** Rules as currently written to the uid map. */
    private final Map<Integer, Integer> mUidRules = new HashMap<>();
    /** Apps with no network left, mirrored on Connectivity's OEM deny chain. */
    private final Set<Integer> mOemDenyUids = new HashSet<>();
    /** The apps written with NO_LOOPBACK. */
    private final Set<Integer> mNoLoopback = new HashSet<>();
    private ConnectivityManager mConnectivity;
    private final Clock mClock;
    /** Held here, as PackageManager's callback keeps only a weak reference to it. */
    private PackageMonitor mPackageMonitor;
    private boolean mOemDenyReady;
    private boolean mMapsReady;
    private boolean mKnowsLoopbackReceivers;
    private boolean mAttached;
    /** A save is posted; changes made until it runs go with it. */
    private boolean mSavePending;

    public FirewallService(Context context) {
        this(context, Maps.NATIVE, new File(Environment.getDataDirectory(), "system"),
                Clock.systemUTC());
    }

    FirewallService(Context context, Maps maps, File storeDir, Clock clock) {
        super(context);
        mContext = context;
        mMaps = maps;
        mClock = clock;
        HandlerThread thread = new HandlerThread(TAG);
        thread.start();
        mHandler = new Handler(thread.getLooper());
        mNetworks = new NetworkTracker(maps, mHandler, this::onNetworksChanged);
        mFeatures = List.of(
                new BackupRestore(this),
                new RefusalCounts(this));
        mStore = new FirewallStore(storeDir, mFeatures);
    }

    Context context() {
        return mContext;
    }

    Handler handler() {
        return mHandler;
    }

    Clock clock() {
        return mClock;
    }

    FirewallStore store() {
        return mStore;
    }

    Maps maps() {
        return mMaps;
    }

    NetworkTracker networks() {
        return mNetworks;
    }

    /** The uid and, for an app, its SDK sandbox, which gets the app's rules. */
    static int[] withSdkSandbox(int uid) {
        int appId = UserHandle.getAppId(uid);
        return appId >= Process.FIRST_APPLICATION_UID && appId <= Process.LAST_APPLICATION_UID
                ? new int[] {uid, Process.toSdkSandboxUid(uid)} : new int[] {uid};
    }

    boolean mapsReady() {
        return mMapsReady;
    }

    List<Feature> features() {
        return mFeatures;
    }

    /** The feature of the type, or null when the firewall is built without it. */
    <T extends Feature> T feature(Class<T> type) {
        for (Feature feature : mFeatures) {
            if (type.isInstance(feature)) return type.cast(feature);
        }
        return null;
    }

    @Override
    public void onStart() {
        init();
        publishBinderService(SERVICE_NAME, new BinderService());
    }

    /** Loads the stored rules and writes them to the maps. */
    void init() {
        mMapsReady = mMaps.init();
        mKnowsLoopbackReceivers = mMaps.knowsLoopbackReceivers();
        mAttached = mMapsReady && mMaps.attach();
        mConnectivity = mContext.getSystemService(ConnectivityManager.class);
        synchronized (this) {
            boolean firstStart = !mStore.exists();
            mStore.load();
            Set<Integer> users = new HashSet<>();
            for (UserHandle user : mContext.getSystemService(UserManager.class)
                    .getUserHandles(false)) {
                users.add(user.getIdentifier());
            }
            mStore.apps.keySet().removeIf(app -> !users.contains(app.second) || knownUid(app) < 0);
            for (Feature feature : mFeatures) feature.onLoadedLocked(users);
            for (Feature feature : mFeatures) feature.onStartLocked(users, firstStart);
            if (mMapsReady) {
                mMaps.clearRules();
                for (Feature feature : mFeatures) feature.onMapsClearedLocked();
                syncAppsLocked();
                replaceOemDenyChainLocked();
            }
        }
        Log.i(TAG, "Started: maps " + (mMapsReady ? "ready" : "missing") + ", programs "
                + (mAttached ? "attached" : "not attached") + ", "
                + mStore.apps.size() + " app rules");
        for (Feature feature : mFeatures) feature.onStarted();
    }

    @Override
    public void onUserStarting(TargetUser user) {
        // Broadcasts skip stopped users, so apps back from adopted storage meanwhile catch up here.
        mHandler.post(this::resync);
    }

    private void resync() {
        synchronized (this) {
            if (!mMapsReady) return;
            syncAppsLocked();
        }
    }

    @Override
    public void onBootPhase(int phase) {
        if (phase != PHASE_ACTIVITY_MANAGER_READY) return;
        // Unlike package broadcasts, PackageMonitor's callbacks reach stopped users too.
        mPackageMonitor = new PackageMonitor(false) {
            @Override
            public void onPackageAdded(String packageName, int uid) {
                synchronized (FirewallService.this) {
                    if (onNewInstallLocked(packageName, uid)) saveAsync();
                }
            }

            @Override
            public void onUidRemoved(int uid) {
                // Dropped like NPMS drops the uid's policy; not sent when data is kept.
                int userId = UserHandle.getUserId(uid);
                Predicate<Pair<String, Integer>> gone = app -> {
                    if (app.second != userId) return false;
                    int known = knownUid(app);
                    return known == uid || known < 0;
                };
                synchronized (FirewallService.this) {
                    if (mStore.apps.keySet().removeIf(gone)
                            | forgetAppsLocked(gone)) {
                        saveAsync();
                    }
                }
                resync();
            }

            @Override
            public void onSomePackagesChanged() {
                resync();
            }
        };
        mPackageMonitor.register(mContext, UserHandle.ALL, mHandler);
        BroadcastReceiver resync = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                if (Intent.ACTION_USER_REMOVED.equals(intent.getAction())) {
                    UserHandle user = intent.getParcelableExtra(Intent.EXTRA_USER,
                            UserHandle.class);
                    synchronized (FirewallService.this) {
                        if (user != null && forgetUserLocked(user.getIdentifier())) saveAsync();
                    }
                }
                resync();
            }
        };
        IntentFilter users = new IntentFilter(Intent.ACTION_USER_ADDED);
        users.addAction(Intent.ACTION_USER_REMOVED);
        // Apps on adoptable storage come back without a package broadcast.
        users.addAction(Intent.ACTION_EXTERNAL_APPLICATIONS_AVAILABLE);
        mContext.registerReceiverForAllUsers(resync, users, null, mHandler);
        for (Feature feature : mFeatures) feature.onBootPhase();
        if (!mMapsReady) return;
        mNetworks.start(mContext);
    }

    /** An app was installed: the features have their say, in their order. */
    private boolean onNewInstallLocked(String packageName, int uid) {
        if (uid < 0) return false;
        UserHandle user = UserHandle.getUserHandleForUid(uid);
        // An install made while a user is being removed still reaches it after USER_REMOVED.
        if (!mContext.getSystemService(UserManager.class).getUserHandles(true).contains(user)) {
            return false;
        }
        Pair<String, Integer> app = Pair.create(packageName, user.getIdentifier());
        boolean changed = false;
        for (Feature feature : mFeatures) changed |= feature.onPackageAddedLocked(app, uid);
        if (changed && mMapsReady) syncAppsLocked();
        return changed;
    }

    /** The app's uid on the user, while any user has the app or its data; else -1. */
    int knownUid(Pair<String, Integer> app) {
        return packageUid(app, PackageManager.MATCH_UNINSTALLED_PACKAGES);
    }

    int packageUid(Pair<String, Integer> app, long flags) {
        try {
            return mContext.createContextAsUser(UserHandle.of(app.second), 0).getPackageManager()
                    .getPackageUid(app.first, PackageInfoFlags.of(flags));
        } catch (PackageManager.NameNotFoundException e) {
            return -1;
        }
    }

    boolean forgetUserLocked(int userId) {
        boolean changed = mStore.apps.keySet().removeIf(app -> app.second == userId);
        for (Feature feature : mFeatures) changed |= feature.forgetUserLocked(userId);
        return changed;
    }

    void syncAppsLocked() {
        writeAppsLocked();
    }

    private void writeAppsLocked() {
        Map<Integer, Integer> wanted = new HashMap<>();
        for (Map.Entry<Pair<String, Integer>, Integer> app : mStore.apps.entrySet()) {
            // Also while hidden, archived, or on adoptable storage that is not mounted yet.
            int uid = knownUid(app.getKey());
            if (uid < 0) continue;
            int rules = app.getValue();
            for (int each : withSdkSandbox(uid)) wanted.merge(each, rules, (a, b) -> a | b);
        }
        for (Feature feature : mFeatures) feature.writeAppsLocked(wanted);
        for (int uid : mUidRules.keySet()) {
            if (!wanted.containsKey(uid)) mMaps.setUid(uid, 0);
        }
        mUidRules.clear();
        mUidRules.putAll(wanted);
        mNoLoopback.clear();
        for (int uid : wanted.keySet()) writeUidLocked(uid);
        updateOemDenyLocked();
    }

    private void onNetworksChanged() {
        synchronized (this) {
            if (!mMapsReady) return;
            // Networks coming and going cut apps off and let them back.
            for (int uid : mUidRules.keySet()) {
                if (noLoopbackLocked(uid) != mNoLoopback.contains(uid)) writeUidLocked(uid);
            }
            updateOemDenyLocked();
        }
    }

    /** Whether the app has no network left: it's blocked from all, or on every one there is. */
    private boolean cutOffLocked(int uid) {
        int rules = mUidRules.get(uid);
        return (rules & FirewallMaps.BLOCK_ALL) != 0 || mNetworks.blocksEveryNetwork(uid, rules);
    }

    private Set<Integer> blockedEverywhereLocked() {
        Set<Integer> uids = new HashSet<>();
        for (Map.Entry<Integer, Integer> rule : mUidRules.entrySet()) {
            if (cutOffLocked(rule.getKey())) uids.add(rule.getKey());
        }
        return uids;
    }

    /**
     * Whether the programs keep the app off loopback: an app with no network left that Connectivity
     * can't keep to itself, as the kernel doesn't let Connectivity know whose socket it reaches.
     */
    private boolean noLoopbackLocked(int uid) {
        return cutOffLocked(uid) && !mKnowsLoopbackReceivers;
    }

    private void writeUidLocked(int uid) {
        boolean noLoopback = noLoopbackLocked(uid);
        if (noLoopback) mNoLoopback.add(uid); else mNoLoopback.remove(uid);
        int rules = mUidRules.get(uid);
        mMaps.setUid(uid, noLoopback ? rules | FirewallMaps.NO_LOOPBACK : rules);
    }

    /**
     * Puts apps with no network left on Connectivity's OEM deny chain, so apps, JobScheduler
     * and DownloadManager see BLOCKED_REASON_OEM_DENY and their sockets get closed.
     */
    private void replaceOemDenyChainLocked() {
        Set<Integer> uids = blockedEverywhereLocked();
        final long identity = Binder.clearCallingIdentity();
        try {
            mConnectivity.replaceFirewallChain(ConnectivityManager.FIREWALL_CHAIN_OEM_DENY_1,
                    uids.stream().mapToInt(Integer::intValue).toArray());
            mConnectivity.setFirewallChainEnabled(ConnectivityManager.FIREWALL_CHAIN_OEM_DENY_1,
                    true);
            mOemDenyUids.clear();
            mOemDenyUids.addAll(uids);
            mOemDenyReady = true;
        } catch (RuntimeException e) {
            Log.e(TAG, "Failed to set the OEM deny chain", e);
        } finally {
            Binder.restoreCallingIdentity(identity);
        }
    }

    private void updateOemDenyLocked() {
        if (!mOemDenyReady) return;
        Set<Integer> uids = blockedEverywhereLocked();
        final long identity = Binder.clearCallingIdentity();
        try {
            for (int uid : uids) {
                if (mOemDenyUids.contains(uid)) continue;
                mConnectivity.setUidFirewallRule(ConnectivityManager.FIREWALL_CHAIN_OEM_DENY_1,
                        uid, ConnectivityManager.FIREWALL_RULE_DENY);
            }
            for (int uid : mOemDenyUids) {
                if (uids.contains(uid)) continue;
                mConnectivity.setUidFirewallRule(ConnectivityManager.FIREWALL_CHAIN_OEM_DENY_1,
                        uid, ConnectivityManager.FIREWALL_RULE_DEFAULT);
            }
            mOemDenyUids.clear();
            mOemDenyUids.addAll(uids);
        } catch (RuntimeException e) {
            Log.e(TAG, "Failed to update the OEM deny chain", e);
        } finally {
            Binder.restoreCallingIdentity(identity);
        }
    }

    /** Saves the rules and tells listeners; every change goes through here. */
    void saveAsync() {
        synchronized (this) {
            if (mSavePending) return;
            mSavePending = true;
        }
        mHandler.post(() -> {
            synchronized (this) {
                mSavePending = false;
                mStore.save();
            }
            mListeners.broadcast(listener -> {
                try {
                    listener.onChanged();
                } catch (RemoteException e) {
                    // The listener's process is gone; RemoteCallbackList drops it.
                }
            });
        });
    }

    /** The installed app and those sharing its uid, which the maps give the same rules. */
    List<Pair<String, Integer>> sharingUidLocked(String packageName, int userId) {
        int uid = packageUid(Pair.create(packageName, userId), PACKAGE_FLAGS);
        if (uid < 0) {
            throw new IllegalArgumentException(packageName + " is not installed for user "
                    + userId);
        }
        String[] shared = mContext.createContextAsUser(UserHandle.of(userId), 0)
                .getPackageManager().getPackagesForUid(uid);
        List<Pair<String, Integer>> apps = new ArrayList<>();
        for (String name : shared != null ? shared : new String[] {packageName}) {
            apps.add(Pair.create(name, userId));
        }
        return apps;
    }

    void setAppRulesInternal(String packageName, int userId, int rules) {
        synchronized (this) {
            for (Pair<String, Integer> app : sharingUidLocked(packageName, userId)) {
                mStore.apps.put(app, rules);
            }
            if (mMapsReady) syncAppsLocked();
        }
        saveAsync();
    }

    private boolean forgetAppsLocked(Predicate<Pair<String, Integer>> gone) {
        boolean changed = false;
        for (Feature feature : mFeatures) changed |= feature.forgetAppsLocked(gone);
        return changed;
    }

    Set<Pair<String, Integer>> appsWithStateLocked() {
        Set<Pair<String, Integer>> apps = new HashSet<>(mStore.apps.keySet());
        for (Feature feature : mFeatures) feature.addAppsWithStateLocked(apps);
        return apps;
    }

    synchronized int getAppRulesInternal(String packageName, int userId) {
        return mStore.apps.getOrDefault(Pair.create(packageName, userId), 0);
    }

    synchronized AppRule[] getAppRulesForUserInternal(int userId) {
        List<AppRule> rules = new ArrayList<>();
        for (Pair<String, Integer> app : appsWithStateLocked()) {
            if (app.second != userId) continue;
            AppRule rule = new AppRule();
            rule.packageName = app.first;
            rule.rules = mStore.apps.getOrDefault(app, 0);
            for (Feature feature : mFeatures) feature.fillAppRuleLocked(app, rule);
            rules.add(rule);
        }
        return rules.toArray(new AppRule[0]);
    }

    void registerListenerInternal(IFirewallListener listener) {
        mListeners.register(listener);
    }

    void unregisterListenerInternal(IFirewallListener listener) {
        mListeners.unregister(listener);
    }

    boolean isRunningInternal() {
        return mMapsReady && mAttached;
    }

    private void dumpInternal(PrintWriter pw) {
        synchronized (this) {
            pw.println("Maps: " + (mMapsReady ? "ready" : "missing"));
            pw.println("Programs: " + (mAttached ? "attached" : "not attached"));
            pw.println("App rules:");
            for (Map.Entry<Pair<String, Integer>, Integer> app : mStore.apps.entrySet()) {
                StringBuilder line = new StringBuilder("  " + app.getKey().first + " user "
                        + app.getKey().second + " rules "
                        + FirewallShellCommand.rulesToString(app.getValue()));
                pw.println(line);
            }
            pw.println("UIDs in map: " + mUidRules);
            pw.println("UIDs on OEM deny chain 1: " + mOemDenyUids);
            for (Feature feature : mFeatures) feature.dumpLocked(pw);
        }
        mNetworks.dump(pw);
        if (mMapsReady) {
            long[] counters = mMaps.counters();
            pw.println("Counters:");
            for (int i = 0; i < counters.length && i < FirewallMaps.COUNTERS.length; i++) {
                pw.println("  " + FirewallMaps.COUNTERS[i] + " " + counters[i]);
            }
            for (Feature feature : mFeatures) feature.dumpMaps(pw);
        }
    }

    private final class BinderService extends IFirewall.Stub {
        private void enforcePermission() {
            mContext.enforceCallingOrSelfPermission(PERMISSION, TAG);
        }

        /** Runs work that reaches other services as the system, as NPMS does after its checks. */
        private <T> T callAsSystem(Supplier<T> work) {
            final long identity = Binder.clearCallingIdentity();
            try {
                return work.get();
            } finally {
                Binder.restoreCallingIdentity(identity);
            }
        }

        private void runAsSystem(Runnable work) {
            callAsSystem(() -> {
                work.run();
                return null;
            });
        }

        private void enforceUser(int userId) {
            enforcePermission();
            if (userId != UserHandle.getUserHandleForUid(Binder.getCallingUid()).getIdentifier()) {
                mContext.enforceCallingOrSelfPermission(
                        android.Manifest.permission.INTERACT_ACROSS_USERS_FULL, TAG);
            }
        }

        @Override
        public void setAppRules(String packageName, int userId, int rules) {
            enforceUser(userId);
            runAsSystem(() -> setAppRulesInternal(packageName, userId, rules));
        }

        @Override
        public int getAppRules(String packageName, int userId) {
            enforceUser(userId);
            return getAppRulesInternal(packageName, userId);
        }

        @Override
        public AppRule[] getAppRulesForUser(int userId) {
            enforceUser(userId);
            return getAppRulesForUserInternal(userId);
        }

        @Override
        public void registerListener(IFirewallListener listener) {
            enforcePermission();
            registerListenerInternal(listener);
        }

        @Override
        public void unregisterListener(IFirewallListener listener) {
            enforcePermission();
            unregisterListenerInternal(listener);
        }

        @Override
        public byte[] getBackupPayload(int userId) {
            enforceUser(userId);
            return callAsSystem(() -> feature(BackupRestore.class).getBackupPayloadInternal(
                    userId));
        }

        @Override
        public void applyRestore(int userId, byte[] payload) {
            enforceUser(userId);
            runAsSystem(() -> feature(BackupRestore.class).applyRestoreInternal(userId,
                    payload));
        }

        @Override
        public boolean isRunning() {
            enforcePermission();
            return isRunningInternal();
        }

        @Override
        public int handleShellCommand(ParcelFileDescriptor in, ParcelFileDescriptor out,
                ParcelFileDescriptor err, String[] args) {
            int uid = Binder.getCallingUid();
            if (uid != Process.ROOT_UID && uid != Process.SHELL_UID
                    && uid != Process.SYSTEM_UID) {
                throw new SecurityException("Shell commands need shell or root");
            }
            final long identity = Binder.clearCallingIdentity();
            try {
                return new FirewallShellCommand(FirewallService.this).exec(this,
                        in.getFileDescriptor(), out.getFileDescriptor(),
                        err.getFileDescriptor(), args);
            } finally {
                Binder.restoreCallingIdentity(identity);
            }
        }

        @Override
        protected void dump(FileDescriptor fd, PrintWriter pw, String[] args) {
            if (mContext.checkCallingOrSelfPermission(android.Manifest.permission.DUMP)
                    != PackageManager.PERMISSION_GRANTED) {
                pw.println("Permission Denial: can't dump " + SERVICE_NAME);
                return;
            }
            dumpInternal(pw);
        }
    }
}
