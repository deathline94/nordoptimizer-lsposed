package com.nordoptimizer.lsposed.hooks;

import java.util.Collection;

import com.nordoptimizer.lsposed.core.HookReport;
import com.nordoptimizer.lsposed.core.Resolvers;

import de.robv.android.xposed.XC_MethodHook;

/**
 * What Threat Protection blocked, read from the app's own accounting instead of its UI.
 *
 * <p>Read-only on purpose: Threat Protection Pro filtering happens on the VPN server's resolver, and TP Lite
 * is enforced in {@code libfirewall.so}, so a module cannot add protection — only report what is already
 * recorded. If TP is off this stays empty, and the UI says so rather than showing a zero as an achievement.
 */
public final class ThreatStatsHook {

    private static final String REPOSITORY =
            "com.nordvpn.android.persistence.repositories.settings.ThreatStatisticsRepository";
    private static final String COLLECTOR =
            "com.nordvpn.android.openvpn.internal.threatstats.ThreatStatisticsCollector";

    private static volatile long lastFactMs;

    private ThreatStatsHook() {
    }

    public static void init(ClassLoader cl) {
        HookReport.Feature f = HookReport.of("tp-stats", "Threat Protection blocked domains");

        Class<?> repo = Resolvers.cls(cl, REPOSITORY, f);
        if (repo != null) {
            int n = Resolvers.byName(repo, f, "insertMaliciousDomains", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) {
                    HookReport.fired(f);
                    Object list = p.args.length > 1 ? p.args[1] : null;
                    if (!(list instanceof Collection)) return;
                    Collection<?> domains = (Collection<?>) list;
                    if (domains.isEmpty()) return;
                    HookReport.sample(f, "batch x" + domains.size());
                    // Bursty and only interesting to a human in small doses, so facts are rate limited and
                    // truncated instead of dumping the whole list into the report.
                    long now = System.currentTimeMillis();
                    if (now - lastFactMs < 2000L) return;
                    lastFactMs = now;
                    StringBuilder sb = new StringBuilder(48);
                    int shown = 0;
                    for (Object d : domains) {
                        if (shown++ >= 3) {
                            sb.append(" …");
                            break;
                        }
                        if (sb.length() > 0) sb.append(", ");
                        sb.append(d);
                    }
                    HookReport.fact("TP|blocked|" + domains.size() + "|[" + sb + "]");
                }
            });
            n += Resolvers.byName(repo, f, "incrementDailyStats", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) {
                    HookReport.fired(f);
                }
            });
            if (n == 0) HookReport.noMatch(f, "no ThreatStatisticsRepository write method resolved");
        }

        Class<?> collector = Resolvers.cls(cl, COLLECTOR, f);
        if (collector != null) {
            // Runs per OpenVPN log line: incremented and nothing else. No sampling, no string building,
            // because this fires on every log line the tunnel produces.
            Resolvers.byName(collector, f, "handleLogMessage", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) {
                    HookReport.fired(f);
                }
            });
        }
    }
}
