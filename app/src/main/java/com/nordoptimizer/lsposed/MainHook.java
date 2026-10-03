package com.nordoptimizer.lsposed;

import android.app.Application;
import android.app.Instrumentation;

import com.nordoptimizer.lsposed.common.Contract;
import com.nordoptimizer.lsposed.common.StatusReporter;
import com.nordoptimizer.lsposed.core.HookReport;
import com.nordoptimizer.lsposed.core.Observation;
import com.nordoptimizer.lsposed.core.Resolvers;
import com.nordoptimizer.lsposed.hooks.AppsFlyerHook;
import com.nordoptimizer.lsposed.hooks.ConnectionFactsHook;
import com.nordoptimizer.lsposed.hooks.JunkPacketSender;
import com.nordoptimizer.lsposed.hooks.MooseWorkerHook;
import com.nordoptimizer.lsposed.hooks.NetworkSinkholeHook;
import com.nordoptimizer.lsposed.hooks.PromoDebloatHook;
import com.nordoptimizer.lsposed.hooks.SdkSuppressionHook;
import com.nordoptimizer.lsposed.hooks.ThreatStatsHook;
import com.nordoptimizer.lsposed.hooks.VpnOptimizationHook;

import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

public class MainHook implements IXposedHookLoadPackage {

    private static final AtomicBoolean CONTEXT_TAKEN = new AtomicBoolean(false);
    private static final AtomicBoolean LOADED = new AtomicBoolean(false);

    @Override
    public void handleLoadPackage(LoadPackageParam lpparam) {
        if (!Contract.TARGET_PKG.equals(lpparam.packageName)) return;

        // Bisection sentinel: "-PhookGroups=off" lets LSPosed load this module into Nord's process and then
        // runs none of our code at all, which separates "PairIP reacts to a hook" from "PairIP reacts to
        // LSPosed being present in the process".
        if ("off".equals(BuildConfig.HOOK_GROUPS)) return;

        String process = lpparam.processName == null ? lpparam.packageName : lpparam.processName;
        // Observed on 9.14.1/2121: LSPosed calls this twice in the same pid. Installing everything twice is
        // harmless to the app but doubles every resolved/fired/substituted counter, which is the one thing
        // this module's report exists to get right. The classloader hash is logged to show whether the two
        // calls are the same load or two different ones.
        HookReport.log("INIT|pkg=" + lpparam.packageName + "|proc=" + process
                + "|cl=" + System.identityHashCode(lpparam.classLoader)
                + "|groups=" + BuildConfig.HOOK_GROUPS
                + "|supportedTarget=" + Contract.SUPPORTED_TARGET + "|observeOnly=" + Observation.OBSERVE_ONLY);
        if (!LOADED.compareAndSet(false, true)) {
            HookReport.log("INIT|dup|already installed in this process, skipped");
            return;
        }

        Resolvers.init(lpparam.classLoader);
        // The context sources are infrastructure, not a group: every config read, report push and deferred
        // job runs through them, so they install whenever any group is selected. (The pre-1.6.0 build gated
        // them behind wants("context") and returned early, which made every single-group bisection build
        // install nothing at all.)
        installContextSources(process, lpparam.classLoader);

        run("dns", () -> NetworkSinkholeHook.init(lpparam.classLoader));
        run("facts", () -> ConnectionFactsHook.init(lpparam.classLoader));
        run("junk", () -> JunkPacketSender.init(lpparam.classLoader));
        run("moose", () -> MooseWorkerHook.init(lpparam.classLoader));
        run("sdk", () -> SdkSuppressionHook.init(lpparam.classLoader));
        run("appsflyer", () -> AppsFlyerHook.init(lpparam.classLoader));
        run("debloat", () -> PromoDebloatHook.init(lpparam.classLoader));
        run("tp-stats", () -> ThreatStatsHook.init(lpparam.classLoader));
        run("vpn", () -> VpnOptimizationHook.init(lpparam.classLoader));
    }

    /** Build-time group selector, so one hook set at a time can be tested against a target that reacts badly. */
    private static boolean wants(String group) {
        String configured = BuildConfig.HOOK_GROUPS;
        if (configured == null || configured.isEmpty()) return false;
        if ("all".equals(configured)) return true;
        for (String g : configured.split(",")) {
            if (g.trim().equals(group)) return true;
        }
        return false;
    }

    /**
     * NordVPN's manifest application class is PairIP's, which declares no {@code onCreate}, so hooking
     * {@code android.app.Application.onCreate} yields the wrong instance and no ordering guarantees. The
     * framework {@code Instrumentation} is the stable point: {@code newApplication} reveals which class is
     * really being instantiated, and {@code callApplicationOnCreate} is where {@code mBase} is guaranteed to
     * exist, so that is where the Context is taken. Hooking the app's own class is kept behind a flag: a
     * {@code de.robv.android.xposed} presence probe lives in this APK, and a hooked app-owned method is
     * exactly what such a check can find.
     */
    private static void installContextSources(String process, ClassLoader cl) {
        HookReport.Feature f = HookReport.of("context", "Context acquisition (framework)");
        int hooked = 0;
        try {
            Set<?> a = XposedBridge.hookAllMethods(Instrumentation.class, "newApplication", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) {
                    HookReport.fired(f);
                    Object requested = p.args != null && p.args.length > 1 ? p.args[1] : "-";
                    Object result = p.getResult();
                    HookReport.log("CTX|newApplication|requested=" + requested + "|instance="
                            + (result == null ? "null" : result.getClass().getName()));
                }
            });
            hooked += a == null ? 0 : a.size();

            Set<?> b = XposedBridge.hookAllMethods(Instrumentation.class, "callApplicationOnCreate",
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam p) {
                            Object arg = p.args != null && p.args.length > 0 ? p.args[0] : null;
                            if (!(arg instanceof Application)) return;
                            if (!CONTEXT_TAKEN.compareAndSet(false, true)) return;
                            HookReport.fired(f);
                            HookReport.signature(f, "android.app.Instrumentation#callApplicationOnCreate");
                            StatusReporter.noteAttached((Application) arg,
                                    "Instrumentation.callApplicationOnCreate", process);
                        }
                    });
            hooked += b == null ? 0 : b.size();
        } catch (Throwable t) {
            HookReport.error(f, "context install", t);
        }
        if (hooked == 0) {
            HookReport.noMatch(f, "Instrumentation.newApplication/callApplicationOnCreate unavailable");
        } else {
            HookReport.installed(f, hooked, "Instrumentation.newApplication + callApplicationOnCreate");
        }

        if (Observation.DIAGNOSTIC_APP_CLASS_HOOKS) {
            HookReport.Feature diag = HookReport.of("context-app", "App class (diagnostic)");
            Class<?> appClass = Resolvers.cls(cl, "com.nordvpn.android.NordVPNApplication", diag);
            if (appClass != null) {
                Resolvers.byName(appClass, diag, "attachBaseContext", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) {
                        HookReport.log("CTX|appClass=attachBaseContext|args=" + p.args.length);
                    }
                });
            }
        }
    }

    private static void run(String label, Runnable body) {
        if (!wants(label)) return;
        try {
            body.run();
        } catch (Throwable t) {
            HookReport.log(label + "|INIT_ERROR|" + t);
        }
    }
}
