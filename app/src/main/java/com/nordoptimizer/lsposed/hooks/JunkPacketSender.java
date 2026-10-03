package com.nordoptimizer.lsposed.hooks;

import android.content.Context;
import android.os.Build;

import com.nordoptimizer.lsposed.common.ConfigClient;
import com.nordoptimizer.lsposed.common.Contract;
import com.nordoptimizer.lsposed.core.HookReport;
import com.nordoptimizer.lsposed.core.Resolvers;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;

/**
 * AmneziaWG-style junk packets for NordLynx: {@code Jc} unparseable UDP datagrams of random size in
 * {@code [Jmin, Jmax]} written to the tunnel's own socket immediately before its WireGuard initiation, so
 * the traffic in front of a handshake looks like noise to deep packet inspection.
 *
 * <p>All sending is native ({@code nordjunk.c} patches the {@code sendto} PLT slot of the app's own
 * libraries and bursts into the handshake's own descriptor), because every Java route was measured dead on
 * device: a hook on {@code java.net.DatagramSocket.send} never fires while the tunnel is up, the descriptors
 * handed to {@code VpnService.protect(int)} cannot be attributed to the tunnel (the dual-stack-port rule
 * matched 0 of ~230 fds every measured connect), and {@code /proc/net/udp} plus {@code /proc/self/fd} are
 * unreadable from the app process, which killed the socket-inode diff as well. Those strategies and their
 * supporting code were removed in 1.6.0; what remains is what actually fires.
 *
 * <p>Config injection remains impossible and is why this is done at the socket layer:
 * {@code telio.internal.config.Attribute} parses the ini against a key whitelist, and {@code WgInterface}/
 * {@code WgPeer} are fixed-arity typed structs with no field that could carry {@code Jc}/{@code Jmin}/
 * {@code Jmax}.
 *
 * <p>What this cannot do: it does not alter the handshake packet itself, so against inspection that matches
 * WireGuard's message format rather than the absence of prior traffic, this alone is not enough. Amnezia's
 * {@code H1-H4}/{@code A1-A4} parameters do that, and they need both ends.
 */
public final class JunkPacketSender {

    private static final int MAX_JUNK_PACKETS = 20;
    /** Nord's WireGuard endpoints listen here; it is also what recognises the handshake destination. */
    private static final int DEFAULT_WG_PORT = 51820;

    /**
     * The native half. Loaded once per process; a missing or ABI-mismatched library is reported and the
     * feature stays off rather than failing silently, because "junk is on" that sends nothing is exactly the
     * kind of false success this module exists to catch.
     */
    private static volatile boolean nativeLoaded;
    private static final String NATIVE_FAILURE;

    static {
        String failure = null;
        try {
            System.loadLibrary("nordjunk");
        } catch (Throwable t) {
            failure = t.getClass().getSimpleName() + ":" + t.getMessage();
        }
        NATIVE_FAILURE = failure;
    }

    private static native int nativeArm(int dstPort, int count, int min, int max);

    /** Total junk bursts written by the native hook; the only evidence of it that reaches the report. */
    private static native long nativeBursts();

    /** Last parameter set handed to the native side, so the maps scan happens once per change. */
    private static volatile String armedWith;
    private static volatile long lastBursts;
    /** The WireGuard endpoint, learned from the config string and the telio peer, for the native port filter. */
    private static volatile int peerPort;
    private static volatile String host;

    /**
     * LSPosed's module classloader does not resolve the APK-embedded native library (measured:
     * {@code UnsatisfiedLinkError ... base.apk!/lib/arm64-v8a couldn't find "libnordjunk.so"}), so it is
     * extracted from the module APK and loaded by absolute path. Android 10+ refuses to {@code dlopen} a
     * library the app can still write, which is why the file is made read-only before the load.
     */
    private static synchronized boolean ensureNativeLoaded() {
        if (nativeLoaded) return true;
        if (NATIVE_FAILURE == null) {
            nativeLoaded = true;
            return true;
        }
        Context ctx = ConfigClient.context();
        if (ctx == null) return false;
        java.util.zip.ZipFile zip = null;
        try {
            // LSPosed loads the module dex from memory, so getCodeSource() is null; the module's own APK path
            // comes from the package manager instead.
            java.io.File apk = null;
            try {
                String source = ctx.getPackageManager()
                        .getApplicationInfo(Contract.MODULE_PKG, 0).sourceDir;
                if (source != null) apk = new java.io.File(source);
            } catch (Throwable ignored) {
                // Module not visible to the target's package manager: fall back below.
            }
            if (apk == null || !apk.isFile()) {
                String desc = JunkPacketSender.class.getClassLoader().toString();
                int at = desc.indexOf("module=");
                if (at < 0) return false;
                int end = desc.indexOf(',', at);
                if (end < 0) return false;
                apk = new java.io.File(desc.substring(at + "module=".length(), end));
            }
            zip = new java.util.zip.ZipFile(apk);
            java.util.zip.ZipEntry entry = null;
            for (String abi : new String[]{Build.CPU_ABI, "arm64-v8a"}) {
                entry = zip.getEntry("lib/" + abi + "/libnordjunk.so");
                if (entry != null) break;
            }
            if (entry == null) return false;
            java.io.File dir = new java.io.File(ctx.getCodeCacheDir(), "njord");
            if (!dir.isDirectory() && !dir.mkdirs()) return false;
            java.io.File out = new java.io.File(dir, "libnordjunk.so");
            // setReadOnly() is what lets Android 10+ allow the dlopen at all, which also means a later process
            // cannot overwrite the file: unlink it first, which only needs write permission on the directory.
            if (out.exists() && !out.delete()) {
                HookReport.log("junk|NATIVE-STALE-UNLINKABLE|" + out.getAbsolutePath());
                return false;
            }
            java.io.InputStream in = zip.getInputStream(entry);
            java.io.OutputStream os = new java.io.FileOutputStream(out);
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) os.write(buf, 0, n);
            os.close();
            in.close();
            if (!out.setReadOnly()) return false;
            System.load(out.getAbsolutePath());
            nativeLoaded = true;
            HookReport.log("junk|NATIVE-EXTRACTED|" + out.getAbsolutePath());
            return true;
        } catch (Throwable t) {
            HookReport.log("junk|NATIVE-EXTRACT-FAILED|" + t);
            return false;
        } finally {
            if (zip != null) try {
                zip.close();
            } catch (Throwable ignored) {
            }
        }
    }

    /** @return how many PLT slots were patched, or a negative number when the native path is unavailable. */
    private static int armNative(String signature) {
        if (!ensureNativeLoaded()) {
            HookReport.log("junk|NATIVE-MISSING|" + NATIVE_FAILURE);
            return -1;
        }
        int count = clamp(ConfigClient.getInt(Contract.KEY_JUNK_COUNT), 0, MAX_JUNK_PACKETS);
        int min = clamp(ConfigClient.getInt(Contract.KEY_JUNK_MIN), 1, 1200);
        int max = clamp(ConfigClient.getInt(Contract.KEY_JUNK_MAX), min, 1400);
        int p = peerPort > 0 ? peerPort : DEFAULT_WG_PORT;
        int slots = nativeArm(p, count, min, max);
        HookReport.log("junk|NATIVE-ARM|port=" + p + "|n=" + count + "|sizes=" + min + "-" + max
                + "|slots=" + slots + "|want=" + signature);
        return slots;
    }

    public static void init(ClassLoader cl) {
        HookReport.Feature f = HookReport.of("junk", "NordLynx junk packets");
        learnPeerPort(cl, f);
        armAtConnect(cl, f);
        // Not armed here: the config is pulled asynchronously after attach, so reading it during
        // handleLoadPackage would see the compiled defaults. ensureArmed() runs at connect time instead.
    }

    /** Arm the native sendto hook if the settings now say to. Called from the connect-time hooks. */
    private static void ensureArmed() {
        if (!ConfigClient.getBoolean(Contract.KEY_JUNK)) return;
        String want = ConfigClient.getInt(Contract.KEY_JUNK_COUNT) + ":"
                + ConfigClient.getInt(Contract.KEY_JUNK_MIN) + ":"
                + ConfigClient.getInt(Contract.KEY_JUNK_MAX) + ":"
                + (peerPort > 0 ? peerPort : DEFAULT_WG_PORT);
        if (want.equals(armedWith)) return;
        armedWith = want;
        armNative(want);
    }

    /**
     * The tunnel's {@code establishVpnTunnel} is the one guaranteed connect-time point in this process, so it
     * arms the native hook with the final endpoint knowledge and starts the burst reporting.
     */
    private static void armAtConnect(ClassLoader cl, HookReport.Feature f) {
        Class<?> manager = Resolvers.cls(cl, Contract.TELIO_TUNNEL_MANAGER, f);
        if (manager == null) return;
        Resolvers.byName(manager, f, "establishVpnTunnel", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) {
                if (!ConfigClient.getBoolean(Contract.KEY_JUNK)) return;
                ensureArmed();
                // The native hook writes into logcat, which the manager never sees, so a working injection
                // would still read as "INSTALLED BUT NEVER FIRED". Pulling the burst count back into the
                // feature makes the row mean what it says. Sampled at the instant the tunnel is established
                // the counter is usually still zero - the first sendto, which is what triggers the injection,
                // happens after that returns - so the rechecks below are scheduled unconditionally rather
                // than only after a first positive count (the pre-1.6.0 bug that hid working junk until the
                // next connect).
                reportBursts(f);
                ConfigClient.postDelayed(() -> reportBursts(f), 4000);
                ConfigClient.postDelayed(() -> reportBursts(f), 12000);
            }
        });
    }

    private static void reportBursts(HookReport.Feature f) {
        if (!nativeLoaded) return;
        long n = nativeBursts();
        if (n <= lastBursts) return;
        lastBursts = n;
        HookReport.fired(f);
        HookReport.substituted(f, n + " native junk bursts");
        HookReport.fact("JUNK|native-bursts|" + n);
    }

    /**
     * The endpoint is learned from the config the app is about to hand to Rust, so a server on a port other
     * than 51820 is still recognised. Neither source is required: {@code DEFAULT_WG_PORT} alone covers Nord's
     * own endpoints.
     */
    private static void learnPeerPort(ClassLoader cl, HookReport.Feature f) {
        Class<?> request = Resolvers.cls(cl, Contract.TELIO_CONNECTION_REQUEST, f);
        if (request != null) {
            Resolvers.byName(request, f, "getConfig", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) {
                    if (p.getResult() instanceof String) readEndpointPort((String) p.getResult());
                    ensureArmed();
                }
            });
        }
        Class<?> peer = Resolvers.cls(cl, Contract.TELIO_PEER, f);
        if (peer != null) {
            Resolvers.byName(peer, f, "getEndpoint", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) {
                    Object endpoint = p.getResult();
                    if (endpoint == null) return;
                    try {
                        Object pt = XposedHelpers.getObjectField(endpoint, "port");
                        if (pt instanceof Integer) peerPort = (Integer) pt;
                        Object hh = XposedHelpers.getObjectField(endpoint, "host");
                        if (hh instanceof String) host = (String) hh;
                    } catch (Throwable ignored) {
                        // Different telio build: the config string path still covers it.
                    }
                }
            });
        }
    }

    /** Pull the port out of the {@code Endpoint=<host>:<port>} line of a WireGuard config. */
    private static void readEndpointPort(String config) {
        int i = config.indexOf("Endpoint=");
        if (i < 0) return;
        String line = config.substring(i + "Endpoint=".length());
        int end = line.length();
        for (int k = 0; k < line.length(); k++) {
            char ch = line.charAt(k);
            if (ch == '\n' || ch == '\r' || ch == ' ') {
                end = k;
                break;
            }
        }
        String value = line.substring(0, end).trim();
        int colon = value.lastIndexOf(':');
        if (colon <= 0) return;
        host = value.substring(0, colon);
        try {
            peerPort = Integer.parseInt(value.substring(colon + 1));
        } catch (NumberFormatException ignored) {
            // Bracketed IPv6 or an unexpected form: the default port still applies.
        }
    }

    private static int clamp(int value, int low, int high) {
        if (value < low) return low;
        return Math.min(value, high);
    }
}
