package com.nordoptimizer.lsposed.hooks;

import android.os.Bundle;

import com.nordoptimizer.lsposed.common.ConfigClient;
import com.nordoptimizer.lsposed.common.Contract;
import com.nordoptimizer.lsposed.core.HookReport;
import com.nordoptimizer.lsposed.core.Observation;
import com.nordoptimizer.lsposed.core.Resolvers;

import de.robv.android.xposed.XC_MethodHook;

/**
 * Third-party tracker SDKs present in this build.
 *
 * <p>{@code com.braze.Braze} does not exist here — the singleton class is renamed — so the reachable Braze
 * surface is the {@code @JavascriptInterface} entry points, whose names cannot be mangled because WebView JS
 * resolves them by string. Everything else about Braze is stopped at the DNS layer.
 *
 * <p>GA4 uploads are performed by Google Play services in {@code com.google.android.gms}, outside this
 * module's scope. What is in scope is the event intake inside NordVPN's own process.
 */
public final class SdkSuppressionHook {

    private static final String FIREBASE_ANALYTICS = "com.google.firebase.analytics.FirebaseAnalytics";
    private static final String BRAZE_JS_BRIDGE = "com.braze.ui.JavascriptInterfaceBase";

    private SdkSuppressionHook() {
    }

    public static void init(ClassLoader cl) {
        firebase(cl);
        braze(cl);
    }

    /**
     * {@code logEvent} is renamed to {@code a(String, Bundle)V} in this build, so it is matched by signature.
     * Hooking it by the name {@code logEvent} matches nothing and, if the result set is ignored, logs a
     * suppression that never happened.
     */
    private static void firebase(ClassLoader cl) {
        HookReport.Feature f = HookReport.of("firebase", "FirebaseAnalytics intake");
        Class<?> c = Resolvers.cls(cl, FIREBASE_ANALYTICS, f);
        if (c == null) return;

        XC_MethodHook suppress = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) {
                HookReport.fired(f);
                if (Observation.OBSERVE_ONLY) return;
                if (!ConfigClient.getBoolean(Contract.KEY_KILL_SDKS)) {
                    HookReport.disabledByConfig(f, Contract.KEY_KILL_SDKS + " off");
                    return;
                }
                Object name = p.args.length > 0 ? p.args[0] : null;
                HookReport.log("firebase|EVENT|" + name);
                p.setResult(null);
                HookReport.substituted(f, String.valueOf(name));
            }
        };

        int n = Resolvers.byShape(c, f, m -> {
            if (Resolvers.isSynthetic(m) || m.getReturnType() != void.class) return false;
            Class<?>[] p = m.getParameterTypes();
            return p.length == 2 && p[0] == String.class && Bundle.class.isAssignableFrom(p[1]);
        }, "(String,Bundle)->void", suppress);

        n += Resolvers.byName(c, f, "setCurrentScreen", suppress);
        if (n == 0) HookReport.noMatch(f, "no FirebaseAnalytics intake method matched");
    }

    private static void braze(ClassLoader cl) {
        HookReport.Feature f = HookReport.of("braze", "Braze JS bridge");
        Class<?> c = Resolvers.cls(cl, BRAZE_JS_BRIDGE, f);
        if (c == null) return;
        XC_MethodHook noop = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) {
                HookReport.fired(f);
                if (Observation.OBSERVE_ONLY) return;
                if (!ConfigClient.getBoolean(Contract.KEY_KILL_SDKS)) {
                    HookReport.disabledByConfig(f, Contract.KEY_KILL_SDKS + " off");
                    return;
                }
                p.setResult(null);
                HookReport.substituted(f, p.method.getName());
            }
        };
        // logButtonClick is left out deliberately: in both 9.13.2/2102 and 9.14.1/2121 the only declaration
        // of that name in this class is abstract, so it cannot be hooked and would leave a permanent,
        // misleading PARTIAL verdict on this row.
        String[] names = {"logCustomEventWithJSON", "logPurchaseWithJSON",
                "changeUser", "requestImmediateDataFlush"};
        int total = 0;
        for (String name : names) total += Resolvers.byName(c, f, name, noop);
        if (total == 0) HookReport.noMatch(f, "no Braze JS bridge method matched");
    }
}
