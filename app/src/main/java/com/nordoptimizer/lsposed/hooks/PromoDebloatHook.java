package com.nordoptimizer.lsposed.hooks;

import com.nordoptimizer.lsposed.common.ConfigClient;
import com.nordoptimizer.lsposed.common.Contract;
import com.nordoptimizer.lsposed.core.HookReport;
import com.nordoptimizer.lsposed.core.Observation;
import com.nordoptimizer.lsposed.core.Resolvers;

import de.robv.android.xposed.XC_MethodHook;

/**
 * Upsell, survey and nag surfaces, each target verified present in 9.13.2.
 *
 * <p>Most of these are Kotlin {@code suspend} functions or {@code Flow} producers. A suspend function's JVM
 * return type is always {@code Object}, so a guard like {@code retType == int.class} is never true: the hook
 * installs, fires, changes nothing, and still reports success. Returning a correctly boxed value from a
 * suspend call is valid — a result that is not {@code COROUTINE_SUSPENDED} means "completed now".
 *
 * <p>The {@code Flow}-returning getters are deliberately left alone: they are fed from the underlying stored
 * value instead, which is what they derive from anyway.
 */
public final class PromoDebloatHook {

    private static final String CSAT_REPO =
            "com.nordvpn.android.persistence.repositories.settings.CsatTriggerRepository";
    private static final String TP_STORE =
            "com.nordvpn.android.persistence.preferences.threatProtection.ThreatProtectionPromotionDataStore";
    private static final String PROMO_API =
            "com.nordvpn.android.communication.domain.promotion.PromotionApiCommunicatorImpl";
    private static final String FEEDBACK_DAO =
            "com.nordvpn.android.persistence.dao.FeedbackFeaturePromptDao_Impl";
    private static final String PROMO_DAO = "com.nordvpn.android.persistence.dao.PromotionDao_Impl";
    private static final String APP_MESSAGE_DAO = "com.nordvpn.android.persistence.dao.AppMessageDao_Impl";
    private static final String CSAT_DAO = "com.nordvpn.android.persistence.dao.CsatTriggerDao_Impl";
    private static final String[] REMINDERS = {
            "com.nordvpn.android.mobile.purchaseUI.reminder.PromoDealReminderReceiver",
            "com.nordvpn.android.mobile.purchaseUI.reminder.CompleteAccountRegistrationReminderReceiver",
            "com.nordvpn.android.domain.purchaseUI.reminder.periodic.receiver.PeriodicPromoDealReminderReceiver",
    };

    private PromoDebloatHook() {
    }

    public static void init(ClassLoader cl) {
        csat(cl);
        writePath(cl);
        threatProtectionSheet(cl);
        promotions(cl);
        feedback(cl);
        reminders(cl);
    }

    /**
     * Preventing the rows is cheaper and safer than deleting them later or aborting the fragment that would
     * have shown them: all four are suspend functions returning {@code Object}, so the correct substitution is
     * {@code kotlin.Unit} — the same value the real body would have completed with.
     */
    private static void writePath(ClassLoader cl) {
        HookReport.Feature f = HookReport.of("marketing-writes", "Marketing rows at the write path");
        XC_MethodHook skip = skipUnit(f, "row not stored");
        int classes = 0;
        int n = 0;
        Class<?> promo = Resolvers.cls(cl, PROMO_DAO, f);
        if (promo != null) {
            classes++;
            n += Resolvers.byName(promo, f, "insertPromotions", skip);
            n += Resolvers.byName(promo, f, "insertMetadata", skip);
        }
        Class<?> messages = Resolvers.cls(cl, APP_MESSAGE_DAO, f);
        if (messages != null) {
            classes++;
            n += Resolvers.byName(messages, f, "insert", skip);
        }
        Class<?> csatDao = Resolvers.cls(cl, CSAT_DAO, f);
        if (csatDao != null) {
            classes++;
            n += Resolvers.byName(csatDao, f, "insert", skip);
        }
        if (classes == 0) HookReport.classMissing(f, "none of the marketing DAO classes resolved");
        else if (n == 0) HookReport.noMatch(f, "no marketing write method resolved");
    }

    /**
     * The CSAT survey machinery is driven from VPN state changes; all three handlers return void, which makes
     * them the safest suppression in the module.
     */
    private static void csat(ClassLoader cl) {
        HookReport.Feature f = HookReport.of("csat", "CSAT survey triggers");
        Class<?> c = Resolvers.cls(cl, CSAT_REPO, f);
        if (c == null) return;
        XC_MethodHook skip = skipVoid(f, "survey trigger suppressed");
        int n = 0;
        n += Resolvers.byName(c, f, "handleVpnTrigger", skip);
        n += Resolvers.byName(c, f, "handleVpnDisconnect", skip);
        n += Resolvers.byName(c, f, "handleVpnPause", skip);
        if (n == 0) HookReport.noMatch(f, "no CsatTriggerRepository handler matched");
    }

    private static void threatProtectionSheet(ClassLoader cl) {
        HookReport.Feature f = HookReport.of("tp-sheet", "Threat Protection keep-active sheet");
        Class<?> c = Resolvers.cls(cl, TP_STORE, f);
        if (c == null) return;

        int n = Resolvers.byName(c, f, "threatProtectionKeepActiveTpBottomSheetShown", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) {
                HookReport.fired(f);
                if (Observation.OBSERVE_ONLY || !enabled(f)) return;
                if (!Resolvers.isSuspend(p.method)) {
                    HookReport.log("tp-sheet|SHAPE|expected suspend, got " + Resolvers.returnType(p.method));
                    return;
                }
                p.setResult(Boolean.TRUE);
                HookReport.substituted(f, "sheet already shown");
            }
        });

        n += Resolvers.byName(c, f, "setShowThreatProtectionKeepActiveTpBottomSheet", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) {
                HookReport.fired(f);
                if (Observation.OBSERVE_ONLY || !enabled(f)) return;
                if (p.args.length > 0 && p.args[0] instanceof Boolean) p.args[0] = Boolean.TRUE;
                Object unit = Resolvers.unit();
                if (unit != null) p.setResult(unit);
                HookReport.substituted(f, "shown flag persisted true");
            }
        });

        if (n == 0) HookReport.noMatch(f, "no Threat Protection sheet state member matched");
    }

    /**
     * Observed, never substituted. {@code getAllPromotions} looks like it returns a list, but the Kotlin
     * type is a wrapped {@code ServiceResult}: substituting {@code Collections.emptyList()} threw
     * {@code ClassCastException} in the caller and killed the app on every cold start (measured
     * 2026-10-04, four crash-looped launches). Promotions are cut one layer down instead, at the database
     * write in {@code marketing-writes}, whose {@code Unit} substitution is shape-safe — so nothing promo
     * ever persists, and this hook only keeps count.
     */
    private static void promotions(ClassLoader cl) {
        HookReport.Feature f = HookReport.of("promo-api", "Promotion API banners");
        Class<?> c = Resolvers.cls(cl, PROMO_API, f);
        if (c == null) return;
        Resolvers.byName(c, f, "getAllPromotions", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) {
                HookReport.fired(f);
                HookReport.disabledByConfig(f, "read-only: its ServiceResult wrapper crashed under"
                        + " substitution; promos are cut at the DB write instead");
            }
        });
    }

    private static void feedback(ClassLoader cl) {
        HookReport.Feature f = HookReport.of("feedback-dao", "In-app survey / rating prompts");
        Class<?> c = Resolvers.cls(cl, FEEDBACK_DAO, f);
        if (c == null) return;

        int n = Resolvers.byName(c, f, "getCountSince", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) {
                HookReport.fired(f);
                if (Observation.OBSERVE_ONLY || !enabled(f)) return;
                if (!Resolvers.isSuspend(p.method)) return;
                // Boxed: the caller unboxes, and an Integer is the only legal value for a suspend Int return.
                p.setResult(Integer.valueOf(999));
                HookReport.substituted(f, "count exceeded threshold");
            }
        });

        n += Resolvers.byName(c, f, "getLastPromptMillis", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) {
                HookReport.fired(f);
                if (Observation.OBSERVE_ONLY || !enabled(f)) return;
                if (!Resolvers.isSuspend(p.method)) return;
                p.setResult(Long.valueOf(System.currentTimeMillis()));
                HookReport.substituted(f, "prompted just now");
            }
        });

        if (n == 0) HookReport.noMatch(f, "no FeedbackFeaturePromptDao member matched");
    }

    private static void reminders(ClassLoader cl) {
        HookReport.Feature f = HookReport.of("reminders", "Promo reminder broadcasts");
        int total = 0;
        for (String name : REMINDERS) {
            Class<?> c = Resolvers.cls(cl, name, f);
            if (c == null) continue;
            total += Resolvers.byName(c, f, "onReceive", skipVoid(f, "reminder suppressed"));
        }
        if (total == 0 && f.state() == HookReport.State.NOT_ATTEMPTED) {
            HookReport.noMatch(f, "no reminder receiver resolved");
        }
    }

    private static boolean enabled(HookReport.Feature f) {
        if (ConfigClient.getBoolean(Contract.KEY_DEBLOAT_NAGS)) return true;
        HookReport.disabledByConfig(f, Contract.KEY_DEBLOAT_NAGS + " off");
        return false;
    }

    private static XC_MethodHook skipVoid(final HookReport.Feature f, final String detail) {
        return new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) {
                HookReport.fired(f);
                if (Observation.OBSERVE_ONLY || !enabled(f)) return;
                if (Resolvers.returnType(p.method) != void.class) {
                    HookReport.log(f.id + "|SHAPE|expected void, got " + Resolvers.returnType(p.method));
                    return;
                }
                p.setResult(null);
                HookReport.substituted(f, detail);
            }
        };
    }

    /** For suspend members: the JVM return type is always {@code Object}, so the value must be {@code Unit}. */
    private static XC_MethodHook skipUnit(final HookReport.Feature f, final String detail) {
        return new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) {
                HookReport.fired(f);
                if (Observation.OBSERVE_ONLY || !enabled(f)) return;
                if (!Resolvers.isSuspend(p.method)) {
                    HookReport.log(f.id + "|SHAPE|expected suspend, got " + Resolvers.returnType(p.method));
                    return;
                }
                Object unit = Resolvers.unit();
                if (unit == null) {
                    HookReport.log(f.id + "|SHAPE|kotlin.Unit unresolved, not substituting");
                    return;
                }
                p.setResult(unit);
                HookReport.substituted(f, detail);
            }
        };
    }
}
