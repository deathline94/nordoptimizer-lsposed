package com.nordoptimizer.lsposed.common;

import android.content.Context;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.SystemClock;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.nordoptimizer.lsposed.core.HookReport;
import com.nordoptimizer.lsposed.core.Observation;
import com.nordoptimizer.lsposed.core.Resolvers;

/**
 * Target-process side of the config channel. Defaults are always available so a hook gate can never block
 * the app on a binder call, and no call is made synchronously while the target is binding its application.
 */
public final class ConfigClient {

    private static final long POLL_INTERVAL_MS = 3000L;
    private static final long PUSH_MIN_INTERVAL_MS = 1000L;

    /** Report-bundle key for whether the last config poll reached the provider. */
    public static final String FIELD_PROVIDER_REACHABLE = "provider_reachable";

    private static final Map<String, Object> SNAPSHOT = new ConcurrentHashMap<>();
    private static volatile Context app;
    private static volatile Handler worker;
    private static volatile long lastGeneration = -1L;
    private static volatile long lastPushMs = 0L;
    private static volatile boolean providerReachable = false;
    private static volatile int lastNonce = -1;
    private static volatile String[] SELF_TEST = null;
    private static final java.util.List<Runnable> PENDING = new java.util.ArrayList<>();

    private ConfigClient() {
    }

    static {
        for (Map.Entry<String, Boolean> e : Contract.boolKeys().entrySet()) {
            SNAPSHOT.put(e.getKey(), e.getValue());
        }
        for (Map.Entry<String, Integer> e : Contract.intKeys().entrySet()) {
            SNAPSHOT.put(e.getKey(), e.getValue());
        }
        for (Map.Entry<String, String> e : Contract.stringKeys().entrySet()) {
            SNAPSHOT.put(e.getKey(), e.getValue());
        }
    }

    /** The attached target Context, for the rare hook that needs storage (native library extraction). */
    public static Context context() {
        return app;
    }

    public static void attach(Context context) {
        if (worker != null || context == null) return;
        app = context.getApplicationContext();
        HandlerThread t = new HandlerThread("nord-optimizer-ipc");
        t.start();
        worker = new Handler(t.getLooper());
        java.util.List<Runnable> waiting;
        synchronized (PENDING) {
            waiting = new java.util.ArrayList<>(PENDING);
            PENDING.clear();
        }
        for (Runnable r : waiting) worker.post(r);
        worker.post(pollTask);
    }

    /**
     * Deferred work for hooks that must not touch the app during package load. Called before a Context exists,
     * these queue and run once the target has bound its application.
     */
    public static void post(Runnable r) {
        Handler h = worker;
        if (h != null) {
            h.post(r);
            return;
        }
        synchronized (PENDING) {
            PENDING.add(r);
        }
    }

    /** Deferred work on the same worker, for checks that have to wait for the app to do something. */
    public static void postDelayed(Runnable r, long delayMs) {
        Handler h = worker;
        if (h != null) {
            h.postDelayed(r, delayMs);
            return;
        }
        post(r);
    }

    public static boolean getBoolean(String key) {
        Object v = SNAPSHOT.get(key);
        return v instanceof Boolean ? (Boolean) v : Contract.defaultBool(key);
    }

    public static int getInt(String key) {
        Object v = SNAPSHOT.get(key);
        return v instanceof Integer ? (Integer) v : Contract.defaultInt(key);
    }

    public static String getString(String key) {
        Object v = SNAPSHOT.get(key);
        return v instanceof String ? (String) v : Contract.defaultString(key);
    }

    public static String[] selfTestLines() {
        String[] v = SELF_TEST;
        return v == null ? new String[0] : v;
    }

    public static boolean isProviderReachable() {
        return providerReachable;
    }

    /** Cheap generation check, full pull only when something changed. */
    private static final Runnable pollTask = new Runnable() {
        @Override
        public void run() {
            Context c = app;
            if (c != null) {
                long generation = readGeneration(c);
                if (generation >= 0 && generation != lastGeneration) pullConfig(c, generation);
                pushReport(c, true);
            }
            Handler h = worker;
            if (h != null) h.postDelayed(pollTask, POLL_INTERVAL_MS);
        }
    };

    private static long readGeneration(Context c) {
        try {
            Bundle out = c.getContentResolver()
                    .call(Contract.CONTENT_URI, Contract.METHOD_VERSION, null, null);
            providerReachable = true;
            return out == null ? -1L : out.getLong(Contract.KEY_GENERATION, -1L);
        } catch (Throwable t) {
            providerReachable = false;
            return -1L;
        }
    }

    private static void pullConfig(Context c, long generation) {
        try {
            Bundle out = c.getContentResolver()
                    .call(Contract.CONTENT_URI, Contract.METHOD_CONFIG, null, null);
            if (out == null) return;
            for (String key : Contract.boolKeys().keySet()) {
                String k = Contract.PREFIX_BOOL + key;
                if (out.containsKey(k)) SNAPSHOT.put(key, out.getBoolean(k));
            }
            for (String key : Contract.intKeys().keySet()) {
                String k = Contract.PREFIX_INT + key;
                if (out.containsKey(k)) SNAPSHOT.put(key, out.getInt(k));
            }
            for (String key : Contract.stringKeys().keySet()) {
                String k = Contract.PREFIX_STRING + key;
                if (out.containsKey(k)) {
                    String v = out.getString(k);
                    SNAPSHOT.put(key, v == null ? "" : v);
                }
            }
            lastGeneration = generation;
            Observation.verbose = getBoolean(Contract.KEY_VERBOSE);
            HostList.invalidate();
            int nonce = getInt(Contract.KEY_SELFTEST_NONCE);
            if (nonce != lastNonce) {
                lastNonce = nonce;
                if (nonce > 0) runSelfTest();
            }
            HookReport.log("CONFIG|loaded|gen=" + generation + "|keys=" + SNAPSHOT.size());
        } catch (Throwable t) {
            HookReport.log("CONFIG|error|" + t);
        }
    }

    /** Re-check every registered target without hooking: answers "did Nord rename it?" on a new build. */
    private static void runSelfTest() {
        try {
            java.util.List<String> lines = Resolvers.runSelfTest(Resolvers.classLoader());
            SELF_TEST = lines.toArray(new String[0]);
            HookReport.log("SELFTEST|ran|targets=" + SELF_TEST.length);
        } catch (Throwable t) {
            SELF_TEST = new String[]{"selftest|ERROR|" + t};
        }
    }

    public static void pushReport(Context c, boolean throttled) {
        long now = SystemClock.elapsedRealtime();
        if (throttled && now - lastPushMs < PUSH_MIN_INTERVAL_MS) return;
        lastPushMs = now;
        Bundle payload = StatusReporter.reportBundle();
        if (payload == null) return;
        try {
            c.getContentResolver().call(Contract.CONTENT_URI, Contract.METHOD_REPORT, null, payload);
        } catch (Throwable ignored) {
            // Reporting is best effort; the target must never fail because the module is not listening.
        }
    }
}
