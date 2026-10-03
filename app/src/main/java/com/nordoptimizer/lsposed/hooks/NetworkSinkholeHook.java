package com.nordoptimizer.lsposed.hooks;

import java.net.InetAddress;
import java.net.UnknownHostException;

import com.nordoptimizer.lsposed.common.ConfigClient;
import com.nordoptimizer.lsposed.common.DnsTruth;
import com.nordoptimizer.lsposed.common.Contract;
import com.nordoptimizer.lsposed.common.HostList;
import com.nordoptimizer.lsposed.common.StatusReporter;
import com.nordoptimizer.lsposed.core.HookReport;
import com.nordoptimizer.lsposed.core.Observation;
import com.nordoptimizer.lsposed.core.Resolvers;

import de.robv.android.xposed.XC_MethodHook;

/**
 * The Android counterpart of the Windows hosts-file sinkhole. {@code java.net.InetAddress} is used because
 * it is framework code (never re-obfuscated) and is the only Java-layer point that sees third-party SDK
 * traffic: NordVPN's own OkHttp types are renamed to short identifiers, so an interceptor-style hook cannot
 * be written against them at all.
 *
 * <p>Coverage limits, stated rather than implied: Nord's API traffic can resolve through its own DoH
 * resolver ({@code com.nordvpn.android.communication.nordtls.NordTlsCompositeDns}) and native code
 * ({@code libtelio}, {@code libopenvpn}) uses its own resolver. Neither passes through here.
 */
public final class NetworkSinkholeHook {

    private NetworkSinkholeHook() {
    }

    public static void init(ClassLoader cl) {
        HookReport.Feature f = HookReport.of("dns", "DNS sinkhole (InetAddress)");
        // One String parameter only: InetAddress also has a private getAllByName(String, boolean) that the
        // public overload delegates to, and hooking both would count every lookup twice.
        Resolvers.byShape(InetAddress.class, f, m -> {
            String n = m.getName();
            if (!n.equals("getByName") && !n.equals("getAllByName")) return false;
            Class<?>[] p = m.getParameterTypes();
            return p.length == 1 && p[0] == String.class;
        }, "InetAddress.{get,getAllByName}(String)", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) {
                String host = (String) p.args[0];
                StatusReporter.noteHost(host);
                if (!HostList.matches(host)) return;
                HookReport.fired(f);
                HookReport.sample(f, host);
                HostList.counted(host);
                if (Observation.OBSERVE_ONLY) return;
                if (!ConfigClient.getBoolean(Contract.KEY_BLOCK_TELEMETRY)) {
                    HookReport.disabledByConfig(f, Contract.KEY_BLOCK_TELEMETRY + " off");
                    return;
                }
                // UnknownHostException is what OkHttp's Dns.lookup already handles. Returning loopback
                // instead would turn a mistake in this list into a TLS hostname-verification failure.
                p.setThrowable(new UnknownHostException("sinkholed: " + host));
                HookReport.substituted(f, "refused " + host);
            }

            /**
             * A network that censors VPNs usually poisons DNS for the provider's own domains first, and that
             * failure looks nothing like a blocked handshake: measured on this device, {@code api.nordvpn.com}
             * resolved to 10.10.34.36 (a private address; the real answer is a Cloudflare pair), so the app
             * retried its API ten times and never reached the WireGuard stage. Reported once per host, because
             * a module that changes nothing should at least make the reason visible.
             */
            @Override
            protected void afterHookedMethod(MethodHookParam p) {
                if (!(p.args[0] instanceof String)) return;
                String host = (String) p.args[0];
                if (!Contract.isNordDomain(host)) return;
                Object result = p.getResult();
                if (result == null || !DnsTruth.isPrivateAnswer(result)) return;
                HookReport.sample(f, "poison " + host + "->" + describe(result));
                // Observe mode measures the poison but never substitutes: the OBSERVE_ONLY contract is
                // "install and measure everything, changing nothing", and this after-hook was the one path
                // that violated it.
                if (Observation.OBSERVE_ONLY) return;
                if (!ConfigClient.getBoolean(Contract.KEY_DEPOISON_DNS)) return;
                InetAddress[] truth = DnsTruth.lookup(host);
                if (truth == null || truth.length == 0) {
                    // Nothing cached: go get the real answer from the app's own resolver now, so the next
                    // attempt by the app (it retries its API about ten times) is served the truth.
                    DnsTruth.request(host);
                    return;
                }
                boolean wantsArray = result instanceof InetAddress[];
                p.setResult(wantsArray ? truth : truth[0]);
                HookReport.substituted(f, "depoisoned " + host + " -> " + describe(truth));
                if (SEEN_POISON.add(host)) {
                    HookReport.fact("DNS|DEPOISON|" + host + "|" + describe(result) + " -> "
                            + describe(truth) + " | " + DnsTruth.stats());
                }
            }
        });
    }

    private static final java.util.Set<String> SEEN_POISON =
            java.util.Collections.newSetFromMap(new java.util.concurrent.ConcurrentHashMap<String, Boolean>());

    private static java.util.List<InetAddress> addresses(Object result) {
        java.util.List<InetAddress> out = new java.util.ArrayList<>(2);
        if (result instanceof InetAddress) out.add((InetAddress) result);
        else if (result instanceof InetAddress[]) {
            for (InetAddress a : (InetAddress[]) result) out.add(a);
        }
        return out;
    }

    private static String describe(Object result) {
        StringBuilder sb = new StringBuilder(48);
        for (InetAddress a : addresses(result)) {
            if (a == null) continue;
            if (sb.length() > 0) sb.append(',');
            sb.append(a.getHostAddress());
        }
        return sb.toString();
    }
}
