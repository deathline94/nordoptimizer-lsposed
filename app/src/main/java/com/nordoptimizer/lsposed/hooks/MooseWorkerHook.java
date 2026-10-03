package com.nordoptimizer.lsposed.hooks;

import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import com.nordoptimizer.lsposed.common.ConfigClient;
import com.nordoptimizer.lsposed.common.Contract;
import com.nordoptimizer.lsposed.common.StatusReporter;
import com.nordoptimizer.lsposed.core.HookReport;
import com.nordoptimizer.lsposed.core.Observation;
import com.nordoptimizer.lsposed.core.Resolvers;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;

/**
 * Moose is Nord's analytics stack: a Rust worker with a Java callback layer. Every upload leaves the process
 * through {@code MooseHttpClient.post}, which is the single choke point; the {@code Worker} and
 * {@code Nordvpnapp} classes are the switches that decide whether anything is queued at all.
 *
 * <p>Names here are Kotlin-{@code internal} and therefore mangled ({@code setSendEvents-OGnWXxg}), so the
 * matching is by prefix or signature. An exact-name hook silently matches nothing and, if the install is not
 * inspected, reports success anyway.
 */
public final class MooseWorkerHook {

    private static final String HTTP_CLIENT = "com.nordsec.moose.mooseworkerjava.MooseHttpClient";
    private static final String UNIFFI_CLIENT = "com.nordsec.moose.mooseworkerjava.UniFfiHttpClient";
    private static final String WORKER = "com.nordsec.moose.mooseworkerjava.Worker";
    private static final String NORDVPNAPP = "com.nordsec.moose.moosenordvpnappjava.Nordvpnapp";

    /** The interface's only {@code post} shape, reused by the runtime-captured implementation class. */
    private static final Resolvers.Shape POST = m -> {
        if (Resolvers.isSynthetic(m) || !"post".equals(m.getName())) return false;
        Class<?>[] p = m.getParameterTypes();
        return p.length == 3 && p[0] == String.class && Map.class.isAssignableFrom(p[1])
                && p[2] == byte[].class;
    };

    private static final AtomicBoolean UNIFFI_TAKEN = new AtomicBoolean(false);

    private MooseWorkerHook() {
    }

    public static void init(ClassLoader cl) {
        uploadChokePoint(cl, HTTP_CLIENT, "moose-post");
        captureUniFfiClient(cl);
        workerSwitches(cl);
        coreSwitches(cl);
        eventCategories(cl);
    }

    /**
     * {@code UniFfiHttpClient.post} is an abstract interface declaration in both supported builds, so it
     * cannot be hooked and the concrete object the Rust worker uses is the only hookable one. Its class name
     * is per-release obfuscation, so it is never hardcoded: the argument handed to
     * {@code Worker.startWithClient-*} is captured once and its runtime class is hooked there.
     *
     * <p>On 9.14.1 the captured object is a {@code MooseHttpClient}, the class {@link #uploadChokePoint}
     * already hooks, so nothing extra is installed and the upload keeps a single counter per real call. If a
     * future build hands over a different class, that class is hooked into the same {@code moose-post}
     * feature: one upload path, one row, whatever it is implemented by.
     */
    private static void captureUniFfiClient(ClassLoader cl) {
        HookReport.Feature capture = HookReport.of("moose-uniffi-capture", "Moose client capture");
        Class<?> worker = Resolvers.cls(cl, WORKER, capture);
        if (worker == null) return;
        Class<?> iface = XposedHelpers.findClassIfExists(UNIFFI_CLIENT, cl);

        int n = Resolvers.byPrefix(worker, capture, "startWithClient", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) {
                if (UNIFFI_TAKEN.get()) return;
                Object client = clientArg(p.args, iface);
                if (client == null) return;
                if (!UNIFFI_TAKEN.compareAndSet(false, true)) return;
                String name = client.getClass().getName();
                HookReport.Feature post = HookReport.of("moose-post", "Moose upload (MooseHttpClient)");
                if (HTTP_CLIENT.equals(name)) {
                    HookReport.signature(capture, "worker client = " + name + " (already hooked)");
                    HookReport.log("moose-uniffi-capture|CLIENT|" + name + "|hooked=0 (moose-post covers it)");
                    return;
                }
                int h = Resolvers.hookInstance(client, post, POST, "post(String,Map,byte[])", upload(post));
                HookReport.log("moose-uniffi-capture|CLIENT|" + name + "|hooked=" + h);
            }
        });
        if (n == 0) HookReport.noMatch(capture, "Worker.startWithClient-* absent: no route to the client");
    }

    /** The worker's client argument, matched by interface so the obfuscated impl name never has to be known. */
    private static Object clientArg(Object[] args, Class<?> iface) {
        if (args == null || iface == null) return null;
        for (Object a : args) {
            if (a != null && iface.isInstance(a)) return a;
        }
        return null;
    }

    private static void uploadChokePoint(ClassLoader cl, String className, String featureId) {
        HookReport.Feature f = HookReport.of(featureId, "Moose upload (" + simple(className) + ")");
        Class<?> c = Resolvers.cls(cl, className, f);
        if (c == null) return;
        Resolvers.byShape(c, f, POST, "post(String,Map,byte[])", upload(f));
    }

    /**
     * {@code post(String url, Map headers, byte[] body) -> SendError}. {@code SendError} is a uniffi nullable
     * error type, so returning null is "sent successfully": the worker drains its queue instead of backing
     * off and retrying forever, which is what pointing it at a dead host would cause.
     *
     * <p>Runs on a Rust/JNA callback thread: counters only, no Context, no IPC, no allocation on the
     * blocking path.
     */
    private static XC_MethodHook upload(final HookReport.Feature f) {
        return new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) {
                HookReport.fired(f);
                if (p.args[0] instanceof String) StatusReporter.noteHost((String) p.args[0]);
                if (Observation.OBSERVE_ONLY) return;
                if (!ConfigClient.getBoolean(Contract.KEY_KILL_MOOSE)) {
                    HookReport.disabledByConfig(f, Contract.KEY_KILL_MOOSE + " off");
                    return;
                }
                p.setResult(null);
                HookReport.substituted(f, "upload dropped");
            }
        };
    }

    private static void workerSwitches(ClassLoader cl) {
        HookReport.Feature f = HookReport.of("moose-worker", "Moose worker switches");
        Class<?> c = Resolvers.cls(cl, WORKER, f);
        if (c == null) return;

        int n = Resolvers.byPrefix(c, f, "setSendEvents", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) {
                HookReport.fired(f);
                if (Observation.OBSERVE_ONLY) return;
                if (!ConfigClient.getBoolean(Contract.KEY_KILL_MOOSE)) {
                    HookReport.disabledByConfig(f, Contract.KEY_KILL_MOOSE + " off");
                    return;
                }
                if (p.args.length > 0 && p.args[0] instanceof Boolean) {
                    p.args[0] = Boolean.FALSE;
                    HookReport.substituted(f, "sendEvents forced false");
                }
            }
        });

        n += Resolvers.byPrefix(c, f, "setSendLog", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) {
                HookReport.fired(f);
                if (Observation.OBSERVE_ONLY) return;
                if (!ConfigClient.getBoolean(Contract.KEY_KILL_MOOSE)) {
                    HookReport.disabledByConfig(f, Contract.KEY_KILL_MOOSE + " off");
                    return;
                }
                if (p.args.length > 0 && p.args[0] != null) {
                    p.args[0] = null;
                    HookReport.substituted(f, "log listener dropped");
                }
            }
        });

        // The endpoint arrives from remote config, so the requested domain is recorded, never rewritten:
        // rewriting it to loopback turns every upload into a connection-refused retry loop.
        n += Resolvers.byPrefix(c, f, "setEndpointDomain", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) {
                HookReport.fired(f);
                if (p.args.length > 0 && p.args[0] instanceof String) {
                    StatusReporter.noteHost((String) p.args[0]);
                    HookReport.log("moose-worker|ENDPOINT|" + p.args[0]);
                }
            }
        });

        // Which of the two booleans in start-P2gvcXM(String,String,J,J,Z,I,Z) means what is not yet known;
        // the vector is logged once instead of guessed at.
        n += Resolvers.byPrefix(c, f, "start", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) {
                HookReport.fired(f);
                HookReport.log("moose-worker|START|" + describeArgs(p.args));
            }
        });

        if (n == 0) HookReport.noMatch(f, "no Worker switch matched on " + c.getName());
    }

    private static void coreSwitches(ClassLoader cl) {
        HookReport.Feature f = HookReport.of("moose-core", "Moose enable/init");
        Class<?> c = Resolvers.cls(cl, NORDVPNAPP, f);
        if (c == null) return;

        int n = Resolvers.byName(c, f, "mooseNordvpnappEnable", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) {
                HookReport.fired(f);
                if (Observation.OBSERVE_ONLY) return;
                if (!ConfigClient.getBoolean(Contract.KEY_KILL_MOOSE)) {
                    HookReport.disabledByConfig(f, Contract.KEY_KILL_MOOSE + " off");
                    return;
                }
                p.setResult(null);
                HookReport.substituted(f, "mooseNordvpnappEnable skipped");
            }
        });

        n += Resolvers.byPrefix(c, f, "mooseNordvpnappInit", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) {
                HookReport.fired(f);
                if (Observation.OBSERVE_ONLY) return;
                if (!ConfigClient.getBoolean(Contract.KEY_KILL_MOOSE)) {
                    HookReport.disabledByConfig(f, Contract.KEY_KILL_MOOSE + " off");
                    return;
                }
                for (int i = 0; i < p.args.length; i++) {
                    if (p.args[i] instanceof Boolean) {
                        p.args[i] = Boolean.FALSE;
                        HookReport.substituted(f, "init arg[" + i + "] false");
                    }
                }
            }
        });

        if (n == 0) HookReport.noMatch(f, "no enable/init matched on " + c.getName());
    }

    /**
     * One feature per event family so the manager can say which traffic stopped. ServiceQuality is kept on by
     * default because it carries connect/disconnect diagnostics; the behavioural UI events and the debugger
     * log channel are the ones with no functional purpose.
     */
    private static void eventCategories(ClassLoader cl) {
        category(cl, "nordvpnappSendUserInterface", "moose-ui", "Moose UI behavioural events",
                Contract.KEY_MOOSE_UI_EVENTS, true);
        category(cl, "nordvpnappSendDebugger", "moose-debugger", "Moose debugger log events",
                Contract.KEY_MOOSE_DEBUGGER, true);
        // ServiceQuality is counted and named but never blocked. Measured on 2026-10-03: substituting 0 into
        // this family's methods stopped NordLynx from connecting at all -- the app's connection state machine
        // reads the return value, so "0 = accepted" is false here. The other two families were substituted in
        // the same session while the tunnel came up fine, which is what separates them from this one.
        category(cl, "nordvpnappSendServiceQuality", "moose-quality",
                "Moose service-quality events (read-only)", null, false);
    }

    private static void category(ClassLoader cl, String prefix, String featureId, String label, String key,
                                 boolean blockable) {
        HookReport.Feature f = HookReport.of(featureId, label);
        Class<?> c = Resolvers.cls(cl, NORDVPNAPP, f);
        if (c == null) return;
        int n = Resolvers.byPrefix(c, f, prefix, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) {
                HookReport.fired(f);
                // Sampled before every gate: the point of the inspector is to learn which events the app
                // actually emits, and that is only useful if it is recorded while nothing is changed.
                HookReport.sample(f, p.method.getName());
                if (!blockable) {
                    HookReport.disabledByConfig(f, "read-only: its int return is consumed by the connect path");
                    return;
                }
                if (Observation.OBSERVE_ONLY) return;
                if (!ConfigClient.getBoolean(key)) {
                    HookReport.disabledByConfig(f, key + " off");
                    return;
                }
                p.setResult(0);
                HookReport.substituted(f, p.method.getName());
            }
        });
        if (n == 0) HookReport.noMatch(f, "no method with prefix " + prefix);
    }

    private static String describeArgs(Object[] args) {
        if (args == null) return "null";
        StringBuilder sb = new StringBuilder(64);
        sb.append(args.length).append(':');
        for (Object a : args) {
            if (a == null) sb.append(" null");
            else if (a instanceof String) sb.append(" \"").append(a).append('"');
            else sb.append(' ').append(a).append('(').append(a.getClass().getSimpleName()).append(')');
        }
        return sb.toString();
    }

    private static String simple(String className) {
        int i = className.lastIndexOf('.');
        return i < 0 ? className : className.substring(i + 1);
    }
}
