package com.nordoptimizer.lsposed.hooks;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import com.nordoptimizer.lsposed.common.ConfigClient;
import com.nordoptimizer.lsposed.common.Contract;
import com.nordoptimizer.lsposed.common.DnsTruth;
import com.nordoptimizer.lsposed.common.StatusReporter;
import com.nordoptimizer.lsposed.common.UdpDns;
import com.nordoptimizer.lsposed.core.HookReport;
import com.nordoptimizer.lsposed.core.Resolvers;

import de.robv.android.xposed.XC_MethodHook;

/**
 * What the tunnel was actually handed, per connect. This replaces the Windows tool's "connected but no
 * internet" claim with a measurement: the DNS servers, MTU, address families and LAN decision the app really
 * passed to {@code VpnService}, plus which resolver path served name lookups.
 *
 * <p>Observe-only by construction — nothing here mutates an argument. The real MTU and DNS choices are made
 * in {@code TunnelManager} and telio's {@code Interface$Builder}, not in {@code VpnService.Builder}, so those
 * are the places worth reading. Overriding them is out of scope for this module.
 */
public final class ConnectionFactsHook {

    private static final int MAX_DNS = 4;
    private static final Object LOCK = new Object();

    // Written from hook callbacks on arbitrary threads, read under the same lock in emit() — so every
    // write goes through record()/LOCK too, not just the reads.
    private static int openVpnMtu;
    private static int wireGuardMtu;
    private static boolean lanRoutes;
    private static boolean familiesAllowed;
    private static boolean magicDnsSeen;
    private static final List<String> DNS = new ArrayList<>();

    private ConnectionFactsHook() {
    }

    public static void init(ClassLoader cl) {
        HookReport.Feature openVpn = HookReport.of("facts-openvpn", "OpenVPN tunnel facts");
        HookReport.Feature wireGuard = HookReport.of("facts-wireguard", "WireGuard tunnel facts");
        HookReport.Feature resolver = HookReport.of("facts-resolver", "Resolver path");

        Class<?> tunnel = Resolvers.cls(cl, Contract.OPENVPN_TUNNEL_MANAGER, openVpn);
        if (tunnel != null) {
            int n = 0;
            n += Resolvers.byName(tunnel, openVpn, "setMtu", record(openVpn, p -> openVpnMtu = (Integer) p.args[0]));
            n += Resolvers.byName(tunnel, openVpn, "addDns", record(openVpn, p -> addDns(String.valueOf(p.args[0]))));
            n += Resolvers.byName(tunnel, openVpn, "addLocalNetworksToRoutes",
                    record(openVpn, p -> lanRoutes = p.args.length > 0 && Boolean.TRUE.equals(p.args[0])));
            n += Resolvers.byName(tunnel, openVpn, "allowFamilies", record(openVpn, p -> familiesAllowed = true));
            Resolvers.byName(tunnel, openVpn, "openTunnel", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) {
                    HookReport.fired(openVpn);
                    emit(openVpn, "openvpn", p.getResult() != null);
                }
            });
            if (n == 0) HookReport.noMatch(openVpn, "no TunnelManager setter resolved");
        }

        Class<?> builder = Resolvers.cls(cl, Contract.TELIO_INTERFACE_BUILDER, wireGuard);
        if (builder != null) {
            Resolvers.byName(builder, wireGuard, "setMtu", record(wireGuard, p -> wireGuardMtu = (Integer) p.args[0]));
            Resolvers.byName(builder, wireGuard, "addDnsServer", record(wireGuard, p -> addDns(String.valueOf(p.args[0]))));
            Resolvers.byName(builder, wireGuard, "addDnsServers",
                    record(wireGuard, p -> addDnsAll(p.args[0])));
        }

        Class<?> telio = Resolvers.cls(cl, Contract.TELIO, wireGuard);
        if (telio != null) {
            Resolvers.byName(telio, wireGuard, "enableMagicDns", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) {
                    HookReport.fired(wireGuard);
                    synchronized (LOCK) {
                        magicDnsSeen = true;
                    }
                    if (p.args.length > 0 && p.args[0] instanceof Collection) addDnsAll(p.args[0]);
                }
            });
            Resolvers.byName(telio, wireGuard, "disableMagicDns", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) {
                    HookReport.fired(wireGuard);
                    HookReport.fact("TUNNEL|nordlynx|magicDns=disabled");
                }
            });
        }

        Class<?> telioTunnel = Resolvers.cls(cl, Contract.TELIO_TUNNEL_MANAGER, wireGuard);
        if (telioTunnel != null) {
            Resolvers.byName(telioTunnel, wireGuard, "establishVpnTunnel", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) {
                    HookReport.fired(wireGuard);
                    emit(wireGuard, "nordlynx", p.getResult() != null);
                }
            });
        }

        Class<?> dns = Resolvers.cls(cl, Contract.NORDTLS_DNS, resolver);
        if (dns != null) {
            // Nord's own DoH-capable resolver. Counted, never intercepted: it is why an InetAddress sinkhole
            // cannot accidentally cut the app's own API traffic.
            Resolvers.byName(dns, resolver, "lookup", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) {
                    HookReport.fired(resolver);
                    Object arg = p.args.length > 0 ? p.args[0] : null;
                    synchronized (LOCK) {
                        if (p.thisObject != null && dohLookup == null) {
                            dohInstance = p.thisObject;
                            dohLookup = (java.lang.reflect.Method) p.method;
                            DnsTruth.setFetcher(host -> {
                                try {
                                    return invokeResolver(host);
                                } catch (Throwable ignored) {
                                    // Measured: the app's resolver delegates to the system one for these names,
                                    // so its failure is not evidence about the name, only about the path.
                                }
                                InetAddress[] direct = UdpDns.query(host);
                                if (direct == null) throw new IllegalStateException("no path answered " + host);
                                return java.util.Arrays.asList(direct);
                            });
                            probe(resolver);
                        }
                    }
                    // Nord's own resolver is the one uncensored path on this network: keep its answers so a
                    // poisoned system lookup can be corrected with them.
                    if (arg instanceof String) DnsTruth.note((String) arg, p.getResult());
                    if (arg != null) HookReport.sample(resolver, String.valueOf(arg));
                }
            });
        }
    }

    /** The app's own resolver, captured from a live call: the only uncensored path on this network. */
    private static volatile Object dohInstance;
    private static volatile java.lang.reflect.Method dohLookup;

    private static Object invokeResolver(String host) throws Exception {
        Object instance = dohInstance;
        java.lang.reflect.Method m = dohLookup;
        if (instance == null || m == null) throw new IllegalStateException("resolver not captured");
        m.setAccessible(true);
        return m.invoke(instance, host);
    }

    /**
     * One measurement per process: what the system resolver says for Nord's API host versus what the app's own
     * DoH says. On the development network these differ, and the difference is the actual cause of
     * "stays on Connecting", so it is reported rather than inferred from a failing connect.
     */
    // One measurement per process; the LOCK-guarded dohLookup == null capture above is the only call site,
    // so probe() itself needs no second guard.
    private static void probe(HookReport.Feature f) {
        ConfigClient.post(() -> {
            for (String host : Contract.NORD_PROBE_HOSTS) {
                String system;
                try {
                    InetAddress[] a = InetAddress.getAllByName(host);
                    StringBuilder sb = new StringBuilder();
                    for (InetAddress x : a) {
                        if (sb.length() > 0) sb.append(',');
                        sb.append(x.getHostAddress());
                    }
                    system = sb.toString();
                } catch (Throwable t) {
                    system = "err:" + t.getClass().getSimpleName();
                }
                String direct;
                try {
                    InetAddress[] d = UdpDns.query(host);
                    direct = d == null ? "none" : java.util.Arrays.toString(d);
                } catch (Throwable t) {
                    direct = "err:" + t;
                }
                String truth;
                try {
                    Object r = invokeResolver(host);
                    DnsTruth.note(host, r);
                    InetAddress[] fixed = DnsTruth.lookup(host);
                    truth = fixed == null ? "none" : java.util.Arrays.toString(fixed);
                } catch (Throwable t) {
                    // The cause is the whole point: without it "the app's resolver cannot be called from here"
                    // and "the app's resolver is also blocked" look identical.
                    Throwable c = t instanceof java.lang.reflect.InvocationTargetException ? t.getCause() : t;
                    truth = "err:" + (c == null ? t : c);
                }
                HookReport.fact("DNS|PROBE|" + host + "|system=" + system + "|doh=" + truth
                        + "|udpdns=" + direct);
            }
        });
    }

    private interface Recorder {
        void capture(XC_MethodHook.MethodHookParam p);
    }

    private static XC_MethodHook record(HookReport.Feature f, Recorder body) {
        return new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) {
                HookReport.fired(f);
                try {
                    synchronized (LOCK) {
                        body.capture(p);
                    }
                } catch (Throwable t) {
                    HookReport.error(f, "record", t);
                }
            }
        };
    }

    private static void addDns(String host) {
        // telio hands over InetAddress values, whose toString() is "/1.2.3.4", alongside plain strings, so
        // the same server would otherwise appear twice.
        if (host != null && host.startsWith("/")) host = host.substring(1);
        synchronized (LOCK) {
            if (DNS.size() < MAX_DNS && host != null && !DNS.contains(host)) DNS.add(host);
        }
    }

    private static void addDnsAll(Object value) {
        if (!(value instanceof Collection)) return;
        for (Object o : (Collection<?>) value) addDns(String.valueOf(o));
    }

    private static void emit(HookReport.Feature f, String protocol, boolean gotTun) {
        String dns;
        int mtu;
        boolean lan;
        boolean families;
        boolean magic;
        synchronized (LOCK) {
            dns = String.join(",", DNS);
            mtu = protocol.equals("nordlynx") ? wireGuardMtu : openVpnMtu;
            lan = lanRoutes;
            families = familiesAllowed;
            magic = magicDnsSeen;
            DNS.clear();
            openVpnMtu = 0;
            wireGuardMtu = 0;
            lanRoutes = false;
            familiesAllowed = false;
            magicDnsSeen = false;
        }
        int builder = StatusReporter.builderMtu();
        HookReport.fact("TUNNEL|" + protocol + "|tun=" + (gotTun ? "ok" : "null")
                + "|mtu=" + (mtu == 0 ? "not-set" : mtu)
                + "|builderMtu=" + (builder == 0 ? "not-set" : builder)
                + "|dns=" + (dns.isEmpty() ? "server-pushed-or-none" : dns)
                + "|lan=" + (lan ? "routes-added" : "no")
                + "|v6=" + (families ? "allowed" : "default")
                + (magic ? "|magicDns=yes" : ""));
    }
}
