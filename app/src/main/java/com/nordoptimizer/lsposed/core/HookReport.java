package com.nordoptimizer.lsposed.core;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicInteger;

import com.nordoptimizer.lsposed.common.Contract;
import de.robv.android.xposed.XposedBridge;

/**
 * Install state and fire state are different facts, and neither is proof of effect. Everything the module
 * claims to do is measured here instead of asserted at install time.
 */
public final class HookReport {

    public static final String TAG = "NOPT";
    private static final int MAX_SAMPLES = 40;

    public enum State { NOT_ATTEMPTED, CLASS_MISSING, NO_MATCHING_METHOD, INSTALLED }

    public static final class Feature {
        public final String id;
        public final String label;
        private volatile State state = State.NOT_ATTEMPTED;
        /** Install-time facts, appended so one feature's later failure never erases an earlier success. */
        private volatile String installDetail = "";
        /** The current runtime condition (substituted/error/config-off), overwritten on purpose. */
        private volatile String runtimeDetail = "";
        private volatile boolean partial;
        private final AtomicInteger resolved = new AtomicInteger();
        private final AtomicInteger fired = new AtomicInteger();
        private final AtomicInteger substituted = new AtomicInteger();
        private final AtomicInteger errors = new AtomicInteger();
        private final TreeSet<String> signatures = new TreeSet<>();
        private final Map<String, AtomicInteger> samples =
                new LinkedHashMap<String, AtomicInteger>(16, 0.75f, true) {
                    @Override
                    protected boolean removeEldestEntry(Map.Entry<String, AtomicInteger> eldest) {
                        return size() > MAX_SAMPLES;
                    }
                };

        Feature(String id, String label) {
            this.id = id;
            this.label = label;
        }

        public State state() {
            return state;
        }

        /** Install detail and runtime condition, joined so a row can carry both without losing either. */
        public String detail() {
            String install = installDetail;
            String runtime = runtimeDetail;
            if (install.isEmpty()) return runtime;
            if (runtime.isEmpty()) return install;
            return install + " | " + runtime;
        }

        public int resolved() {
            return resolved.get();
        }

        public int fired() {
            return fired.get();
        }

        public int substituted() {
            return substituted.get();
        }

        public int errors() {
            return errors.get();
        }

        public boolean partial() {
            return partial;
        }

        void sample(String key) {
            AtomicInteger counter;
            synchronized (samples) {
                counter = samples.get(key);
                if (counter == null) {
                    counter = new AtomicInteger();
                    samples.put(key, counter);
                }
            }
            counter.incrementAndGet();
        }

        List<String> sampleLines() {
            synchronized (samples) {
                List<String> out = new ArrayList<>(samples.size());
                for (Map.Entry<String, AtomicInteger> e : samples.entrySet()) {
                    out.add(e.getKey() + " x" + e.getValue().get());
                }
                return out;
            }
        }
    }

    private static final Map<String, Feature> REGISTRY =
            Collections.synchronizedMap(new LinkedHashMap<String, Feature>());

    /** Newest-first observations worth showing the user (tunnel facts, TP counts). Bounded, never a leak. */
    private static final int MAX_FACTS = 24;
    private static final List<String> FACTS = Collections.synchronizedList(new ArrayList<String>());

    private HookReport() {
    }

    public static void fact(String line) {
        if (line == null) return;
        synchronized (FACTS) {
            FACTS.add(0, line);
            while (FACTS.size() > MAX_FACTS) FACTS.remove(FACTS.size() - 1);
        }
    }

    public static List<String> facts() {
        synchronized (FACTS) {
            return new ArrayList<>(FACTS);
        }
    }

    /**
     * Which concrete members a feature has actually seen at runtime, with counts. This is the difference
     * between "moose UI events blocked" and "nordvpnappSendUserInterfaceUiItemsHover x37 was called and
     * dropped" — the second one can be checked.
     */
    public static void sample(Feature f, String key) {
        if (key == null) return;
        f.sample(key);
    }

    public static Feature of(String id, String label) {
        Feature f = REGISTRY.get(id);
        if (f == null) {
            f = new Feature(id, label);
            REGISTRY.put(id, f);
        }
        return f;
    }

    public static void log(String line) {
        XposedBridge.log(TAG + "|" + line);
    }

    public static void classMissing(Feature f, String className) {
        note(f, State.CLASS_MISSING, "class not found: " + className);
    }

    public static void noMatch(Feature f, String detail) {
        note(f, State.NO_MATCHING_METHOD, detail);
    }

    public static void installed(Feature f, int count, String detail) {
        f.resolved.addAndGet(count);
        note(f, State.INSTALLED, detail);
    }

    /**
     * One feature can cover several targets, so a later failure must not erase an earlier success and vice
     * versa: a feature that hooked 2 of 3 methods is installed *and* incomplete, and both facts belong in the
     * row rather than one of them overwriting the other.
     */
    private static void note(Feature f, State state, String detail) {
        synchronized (f) {
            // Several processes report into the same row, and one process can note the same fact twice;
            // repeating it pushes the useful part of the detail out of the UI.
            if (!detail.equals(f.installDetail) && !f.installDetail.endsWith("; " + detail)
                    && !f.installDetail.isEmpty()) {
                f.installDetail = f.installDetail + "; " + detail;
            } else if (f.installDetail.isEmpty()) {
                f.installDetail = detail;
            }
            State before = f.state;
            boolean beforePartial = f.partial;
            if (state == State.INSTALLED) {
                f.state = State.INSTALLED;
            } else if (f.state == State.INSTALLED) {
                f.partial = true;
            } else {
                f.state = state;
            }
            // The first row (the state transition) is the signal; the seven install-detail appends after it
            // (one per method of a 10-method facade) are noise unless verbose is on.
            emit(f, f.state != before || f.partial != beforePartial);
        }
    }

    public static void signature(Feature f, String sig) {
        if (sig != null) f.signatures.add(sig);
    }

    /** The hook body ran. Does not mean anything changed. */
    public static void fired(Feature f) {
        int n = f.fired.incrementAndGet();
        // The first fire is the proof a target is reachable, so it is never suppressed by verbosity.
        emit(f, n == 1);
    }

    /** The hook body actually altered app behaviour. */
    public static void substituted(Feature f, String what) {
        int n = f.substituted.incrementAndGet();
        f.runtimeDetail = what;
        // A substitution is the headline fact of a row: emit the first one unconditionally, the rest when
        // verbose, so "WORKING" is visible in logcat without needing the provider.
        emit(f, n == 1);
    }

    public static void error(Feature f, String where, Throwable t) {
        f.errors.incrementAndGet();
        f.runtimeDetail = where + ": " + t;
        emit(f, true);
    }

    /** A config gate is a runtime condition, not an install failure: the install state must stay visible. */
    public static void disabledByConfig(Feature f, String why) {
        if (why.equals(f.runtimeDetail)) return;
        f.runtimeDetail = why;
        emit(f, true);
    }

    /**
     * A feature can be installed and never called, or called and never have any effect. Both are failures
     * that look like success in a log that only reports installation.
     */
    public static String verdict(Feature f) {
        String base;
        switch (f.state) {
            case CLASS_MISSING: return Contract.VERDICT_CLASS_MISSING;
            case NO_MATCHING_METHOD: return Contract.VERDICT_NO_MATCHING_METHOD;
            case NOT_ATTEMPTED: return Contract.VERDICT_NOT_ATTEMPTED;
            default:
                if (f.fired.get() == 0) base = Contract.VERDICT_NEVER_FIRED;
                else if (f.substituted.get() == 0) base = Contract.VERDICT_NO_EFFECT;
                else base = Contract.VERDICT_WORKING;
                return f.partial ? base + Contract.VERDICT_PARTIAL_SUFFIX : base;
        }
    }

    public static List<Feature> snapshot() {
        synchronized (REGISTRY) {
            return new ArrayList<>(REGISTRY.values());
        }
    }

    public static List<String> samplesOf(Feature f) {
        return f.sampleLines();
    }

    public static String digest() {
        TreeSet<String> all = new TreeSet<>();
        for (Feature f : snapshot()) all.addAll(f.signatures);
        if (all.isEmpty()) return "none";
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            for (String s : all) md.update(s.getBytes("UTF-8"));
            byte[] d = md.digest();
            StringBuilder sb = new StringBuilder(8);
            for (int i = 0; i < 4; i++) sb.append(String.format("%02x", d[i]));
            return sb.toString();
        } catch (Throwable t) {
            return "error";
        }
    }

    private static void emit(Feature f, boolean always) {
        if (!always && !Observation.verbose) return;
        log(f.id + "|" + f.state + "|r=" + f.resolved.get() + "|f=" + f.fired.get()
                + "|s=" + f.substituted.get() + "|e=" + f.errors.get() + "|" + f.detail());
    }
}
