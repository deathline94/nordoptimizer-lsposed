package com.nordoptimizer.lsposed.hooks;

import android.net.VpnService;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.nordoptimizer.lsposed.common.ConfigClient;
import com.nordoptimizer.lsposed.common.Contract;
import com.nordoptimizer.lsposed.common.StatusReporter;
import com.nordoptimizer.lsposed.core.HookReport;
import com.nordoptimizer.lsposed.core.Observation;
import com.nordoptimizer.lsposed.core.Resolvers;

import de.robv.android.xposed.XC_MethodHook;

/**
 * Two things live here: the OpenVPN configuration text, and the tunnel MTU request.
 *
 * <p>The shipped templates ({@code assets/templates/2.0.0} and {@code 2.1.0}) already emit
 * {@code mssfix 1450}, so appending "if absent" never fired. The value has to be replaced. Whether
 * {@code writeConfigFile} receives the config text or the destination path is still open, so the arg is
 * classified before anything edits it — appending to a path would corrupt the filename.
 *
 * <p>{@code route-metric} and the {@code pull-filter} edits were removed: neither string exists in the
 * Android templates, and on Android routes are installed by {@code VpnService}, not by OpenVPN.
 */
public final class VpnOptimizationHook {

    private static final Pattern MSSFIX = Pattern.compile("(?m)^[ \\t]*mssfix[ \\t]+[0-9]+[ \\t]*$");
    private static final String OPENVPN = "com.nordvpn.android.openvpn.OpenVPN";

    private VpnOptimizationHook() {
    }

    public static void init(ClassLoader cl) {
        openVpnConfig(cl);
        tunnelMtu();
    }

    private static void openVpnConfig(ClassLoader cl) {
        HookReport.Feature f = HookReport.of("openvpn", "OpenVPN config (mssfix)");
        Class<?> c = Resolvers.cls(cl, OPENVPN, f);
        if (c == null) return;

        Resolvers.byName(c, f, "writeConfigFile", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) {
                HookReport.fired(f);
                if (p.args.length == 0 || !(p.args[0] instanceof String)) {
                    HookReport.log("openvpn|ARG|" + (p.args.length == 0 ? "none" : p.args[0]));
                    return;
                }
                String arg = (String) p.args[0];
                boolean looksLikePath = arg.startsWith("/") && arg.indexOf('\n') < 0;
                HookReport.log("openvpn|ARG|len=" + arg.length() + "|path=" + looksLikePath
                        + "|mssfix=" + arg.contains("mssfix"));
                if (Observation.OBSERVE_ONLY || looksLikePath) return;
                if (!ConfigClient.getBoolean(Contract.KEY_OPT_OPENVPN)) {
                    HookReport.disabledByConfig(f, Contract.KEY_OPT_OPENVPN + " off");
                    return;
                }
                int target = ConfigClient.getInt(Contract.KEY_TARGET_MTU);
                Matcher m = MSSFIX.matcher(arg);
                if (m.find()) {
                    String replaced = m.replaceAll("mssfix " + target);
                    p.args[0] = replaced;
                    HookReport.substituted(f, "mssfix replaced -> " + target);
                } else {
                    p.args[0] = arg + "\nmssfix " + target;
                    HookReport.substituted(f, "mssfix appended -> " + target);
                }
            }
        });
    }

    /**
     * {@code VpnService.Builder.setMtu} is framework, so it is safe to hook and will never be renamed. It is
     * not, however, where the real decisions are made for either protocol: the OpenVPN path goes through
     * {@code openvpn.internal.management.TunnelManager.setMtu} and the WireGuard path through
     * {@code com.nordsec.telio.internal.config.Interface$Builder.setMtu}. This therefore starts as a record of
     * what the app actually requests, and clamping is off by default.
     */
    private static void tunnelMtu() {
        HookReport.Feature f = HookReport.of("mtu", "Tunnel MTU request");
        Resolvers.byShape(VpnService.Builder.class, f, m -> "setMtu".equals(m.getName())
                && m.getParameterTypes().length == 1 && m.getParameterTypes()[0] == int.class,
                "VpnService.Builder.setMtu(int)", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) {
                        HookReport.fired(f);
                        if (p.args.length == 0 || !(p.args[0] instanceof Integer)) return;
                        int requested = (Integer) p.args[0];
                        HookReport.log("mtu|REQUEST|" + requested);
                        StatusReporter.noteBuilderMtu(requested);
                        if (Observation.OBSERVE_ONLY) return;
                        if (!ConfigClient.getBoolean(Contract.KEY_CLAMP_MTU)) {
                            HookReport.disabledByConfig(f, Contract.KEY_CLAMP_MTU + " off (default)");
                            return;
                        }
                        int target = ConfigClient.getInt(Contract.KEY_TARGET_MTU);
                        if (requested > target) {
                            p.args[0] = target;
                            HookReport.substituted(f, requested + " -> " + target);
                        }
                    }
                });
    }
}
