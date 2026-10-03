package com.nordoptimizer.lsposed.hooks;

import com.nordoptimizer.lsposed.common.ConfigClient;
import com.nordoptimizer.lsposed.common.Contract;
import com.nordoptimizer.lsposed.core.HookReport;
import com.nordoptimizer.lsposed.core.Observation;
import com.nordoptimizer.lsposed.core.Resolvers;

import de.robv.android.xposed.XC_MethodHook;

/**
 * AppsFlyer is the attribution and advertising SDK in this build, and until now nothing covered it: it
 * reports install, sessions, in-app purchases and (via {@code logLocation}) location.
 *
 * <p>Its public class is an abstract facade — every member of {@code com.appsflyer.AppsFlyerLib} is flagged
 * abstract, and the concrete implementation today is {@code com.appsflyer.internal.AFa1zSDK}, a name that
 * changes with each AppsFlyer release. So the impl is never hardcoded: the name-stable
 * {@code getInstance()} is called and the returned object's own class is what gets hooked.
 *
 * <p>{@code init} and {@code stop} are deliberately left alone. Suppressing {@code start} and the log methods
 * is enough to stop the data leaving, without leaving the SDK in a state it cannot recover from.
 */
public final class AppsFlyerHook {

    private static final String LIB = "com.appsflyer.AppsFlyerLib";

    private static final String[] SUPPRESS = {
            "start", "logEvent", "logSession", "logLocation", "sendPurchaseData",
            "sendInAppPurchaseData", "logAdRevenue", "collectDataFromLauncherActivity",
    };

    private AppsFlyerHook() {
    }

    public static void init(ClassLoader cl) {
        HookReport.Feature f = HookReport.of("appsflyer", "AppsFlyer attribution");
        // Deferred: calling getInstance() constructs the SDK singleton, and doing that during package load
        // would be a behaviour change in a build whose whole claim is that it changes nothing. It runs on the
        // module's own thread once the target has bound its application.
        ConfigClient.post(() -> resolveAndHook(cl, f));
    }

    private static void resolveAndHook(ClassLoader cl, HookReport.Feature f) {
        Object instance = Resolvers.singleton(cl, LIB, "getInstance", f);
        if (instance == null) return;

        XC_MethodHook noop = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) {
                HookReport.fired(f);
                HookReport.sample(f, p.method.getName());
                if (Observation.OBSERVE_ONLY) return;
                if (!ConfigClient.getBoolean(Contract.KEY_KILL_SDKS)) {
                    HookReport.disabledByConfig(f, Contract.KEY_KILL_SDKS + " off");
                    return;
                }
                p.setResult(null);
                HookReport.substituted(f, p.method.getName());
            }
        };

        int n = 0;
        for (String name : SUPPRESS) {
            n += Resolvers.hookInstance(instance, f,
                    m -> name.equals(m.getName()) && !Resolvers.isSynthetic(m), name, noop);
        }
        if (n == 0) {
            HookReport.noMatch(f, "no AppsFlyer entry point on " + instance.getClass().getName());
        }
    }
}
