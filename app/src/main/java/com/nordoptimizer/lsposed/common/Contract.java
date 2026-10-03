package com.nordoptimizer.lsposed.common;

import android.net.Uri;

import java.util.LinkedHashMap;
import java.util.Map;

/** Single owner of the module/target contract: authority, IPC methods, setting keys and their defaults. */
public final class Contract {

    public static final String MODULE_PKG = "com.nordoptimizer.lsposed";
    public static final String TARGET_PKG = "com.nordvpn.android";

    public static final String AUTHORITY = "com.nordoptimizer.lsposed.status";
    public static final Uri CONTENT_URI = Uri.parse("content://" + AUTHORITY + "/state");
    public static final String PREFS_NAME = "nord_optimizer_prefs";

    /**
     * Every hook target was read out of these exact builds; anything else is untested against it.
     *
     * <p>These live here rather than on {@code MainHook} because the manager must show them, and
     * {@code MainHook} implements {@code IXposedHookLoadPackage} against a {@code compileOnly} API jar that
     * is not in the APK — touching that class from the manager's own process fails with
     * {@code NoClassDefFoundError}.
     */
    public static final String[] SUPPORTED_TARGETS = {"9.13.2/2102", "9.14.1/2121"};
    public static final String SUPPORTED_TARGET = String.join(" or ", SUPPORTED_TARGETS);

    public static boolean isSupported(String target) {
        if (target == null) return false;
        for (String s : SUPPORTED_TARGETS) {
            if (s.equals(target)) return true;
        }
        return false;
    }

    /**
     * Hook target classes, read out of the supported builds' dex. One owner, because the same names were
     * previously duplicated across hook files and drift here means a silent NO MATCHING METHOD.
     */
    public static final String OPENVPN_TUNNEL_MANAGER =
            "com.nordvpn.android.openvpn.internal.management.TunnelManager";
    public static final String NORDTLS_DNS = "com.nordvpn.android.communication.nordtls.NordTlsCompositeDns";
    public static final String TELIO = "com.nordsec.telio.Telio";
    public static final String TELIO_TUNNEL_MANAGER =
            "com.nordsec.telio.internal.management.VpnServiceTunnelManager";
    public static final String TELIO_INTERFACE_BUILDER = "com.nordsec.telio.internal.config.Interface$Builder";
    public static final String TELIO_CONNECTION_REQUEST =
            "com.nordsec.telio.vpnConnection.LibtelioConnectionRequest";
    public static final String TELIO_PEER = "com.nordsec.telio.internal.config.Peer";

    /** Nord's API hosts, probed once per process to measure system-resolver poisoning. */
    public static final String[] NORD_PROBE_HOSTS = {"api.nordvpn.com", "pdp.nordvpn.com"};

    /** Nord-owned domains, the scope of poisoned-answer correction. See {@link DnsTruth}. */
    public static boolean isNordDomain(String host) {
        return host != null && (host.endsWith("nordvpn.com") || host.endsWith("nordvpn.net")
                || host.contains("napps-"));
    }

    /** Bundle keys of the report the target pushes back. One owner; written by {@link StatusReporter}. */
    public static final String FIELD_PID = "pid";
    public static final String FIELD_SOURCE = "source";
    public static final String FIELD_PROCESS = "process";
    public static final String FIELD_TARGET_VERSION = "target_version";
    public static final String FIELD_ATTACHED_AT = "attached_at";
    public static final String FIELD_DIGEST = "digest";
    public static final String FIELD_OBSERVE_ONLY = "observe_only";
    public static final String FIELD_ROWS = "rows";
    public static final String FIELD_HOSTS = "hosts";
    public static final String FIELD_SAMPLES = "samples";
    public static final String FIELD_FACTS = "facts";
    public static final String FIELD_COUNTERS = "counters";
    public static final String FIELD_SELFTEST = "selftest";

    /**
     * Verdict strings the report rows carry and the manager colours on. One owner: the producer
     * ({@code HookReport}) and the consumer (MainActivity) previously matched on two independent copies of
     * these exact strings.
     */
    public static final String VERDICT_CLASS_MISSING = "TARGET CLASS MISSING";
    public static final String VERDICT_NO_MATCHING_METHOD = "NO MATCHING METHOD";
    public static final String VERDICT_NOT_ATTEMPTED = "NOT ATTEMPTED";
    public static final String VERDICT_NEVER_FIRED = "INSTALLED BUT NEVER FIRED";
    public static final String VERDICT_NO_EFFECT = "FIRES BUT CHANGES NOTHING";
    public static final String VERDICT_WORKING = "WORKING";
    public static final String VERDICT_PARTIAL_SUFFIX = " (PARTIAL: a target did not resolve)";

    public static final String METHOD_CONFIG = "config";
    public static final String METHOD_VERSION = "version";
    public static final String METHOD_REPORT = "report";

    public static final String KEY_GENERATION = "generation";
    public static final String PREFIX_BOOL = "b.";
    public static final String PREFIX_INT = "i.";
    public static final String PREFIX_STRING = "s.";

    public static final String KEY_BLOCK_TELEMETRY = "block_telemetry";
    public static final String KEY_KILL_MOOSE = "kill_moose";
    public static final String KEY_KILL_SDKS = "kill_sdks";
    public static final String KEY_OPT_OPENVPN = "opt_openvpn";
    public static final String KEY_CLAMP_MTU = "clamp_mtu";
    public static final String KEY_DEBLOAT_NAGS = "debloat_nags";
    public static final String KEY_MOOSE_UI_EVENTS = "moose_block_ui_events";
    public static final String KEY_MOOSE_DEBUGGER = "moose_block_debugger";
    public static final String KEY_VERBOSE = "verbose_logging";
    public static final String KEY_TARGET_MTU = "target_mtu";
    /** Bumping this asks the target process to re-probe every hook target without hooking anything. */
    public static final String KEY_SELFTEST_NONCE = "selftest_nonce";

    /** P6: the sinkhole list as data rather than source. Newline or comma separated host names. */
    public static final String KEY_EXTRA_HOSTS = "extra_blocked_hosts";
    public static final String KEY_DISABLED_DEFAULT_HOSTS = "disabled_default_hosts";

    /**
     * Junk packets. Separate, deliberately unparseable UDP datagrams sent just before a WireGuard handshake
     * so the traffic in front of it looks like noise. AmneziaWG documents these as client-side only: a stock
     * peer drops the frames and processes the real handshake. Off by default because it adds traffic.
     */
    public static final String KEY_JUNK = "junk_packets";
    /**
     * Replace a poisoned (private-address) answer for a Nord domain with the answer the app already got
     * from its own DNS-over-HTTPS resolver. See {@link DnsTruth} for why this is needed on this network.
     */
    public static final String KEY_DEPOISON_DNS = "depoison_dns";
    public static final String KEY_JUNK_COUNT = "junk_count";
    public static final String KEY_JUNK_MIN = "junk_min";
    public static final String KEY_JUNK_MAX = "junk_max";

    public static final int DEFAULT_TARGET_MTU = 1360;
    public static final int DEFAULT_JUNK_COUNT = 5;
    public static final int DEFAULT_JUNK_MIN = 50;
    public static final int DEFAULT_JUNK_MAX = 128;

    /**
     * Defaults for what is armed once {@code OBSERVE_ONLY} is off. Three features earn no default because
     * their precondition has never been observed on a device: the two {@code nordvpnappSend*} families return
     * {@code int} and 0 = accepted is still an assumption (substituting 0 unverified could stall a queue), and
     * the OpenVPN rewrite has never seen {@code writeConfigFile}'s argument — the field next to it suggests a
     * path, and running a config-text regex over a path would break OpenVPN.
     */
    private static final Map<String, Boolean> BOOL_DEFAULTS = new LinkedHashMap<>();
    private static final Map<String, Integer> INT_DEFAULTS = new LinkedHashMap<>();
    private static final Map<String, String> STRING_DEFAULTS = new LinkedHashMap<>();

    static {
        BOOL_DEFAULTS.put(KEY_BLOCK_TELEMETRY, true);
        BOOL_DEFAULTS.put(KEY_KILL_MOOSE, true);
        BOOL_DEFAULTS.put(KEY_KILL_SDKS, true);
        BOOL_DEFAULTS.put(KEY_OPT_OPENVPN, false);
        // Touching live connectivity is the one change that can make VPN use worse, so it earns no default.
        BOOL_DEFAULTS.put(KEY_CLAMP_MTU, false);
        BOOL_DEFAULTS.put(KEY_DEBLOAT_NAGS, true);
        BOOL_DEFAULTS.put(KEY_MOOSE_UI_EVENTS, false);
        BOOL_DEFAULTS.put(KEY_MOOSE_DEBUGGER, false);
        BOOL_DEFAULTS.put(KEY_VERBOSE, false);
        BOOL_DEFAULTS.put(KEY_JUNK, false);
        BOOL_DEFAULTS.put(KEY_DEPOISON_DNS, true);
        INT_DEFAULTS.put(KEY_TARGET_MTU, DEFAULT_TARGET_MTU);
        INT_DEFAULTS.put(KEY_SELFTEST_NONCE, 0);
        INT_DEFAULTS.put(KEY_JUNK_COUNT, DEFAULT_JUNK_COUNT);
        INT_DEFAULTS.put(KEY_JUNK_MIN, DEFAULT_JUNK_MIN);
        INT_DEFAULTS.put(KEY_JUNK_MAX, DEFAULT_JUNK_MAX);
        STRING_DEFAULTS.put(KEY_EXTRA_HOSTS, "");
        STRING_DEFAULTS.put(KEY_DISABLED_DEFAULT_HOSTS, "");
    }

    private Contract() {
    }

    public static Map<String, Boolean> boolKeys() {
        return BOOL_DEFAULTS;
    }

    public static Map<String, Integer> intKeys() {
        return INT_DEFAULTS;
    }

    public static Map<String, String> stringKeys() {
        return STRING_DEFAULTS;
    }

    public static boolean defaultBool(String key) {
        Boolean v = BOOL_DEFAULTS.get(key);
        return v != null && v;
    }

    public static int defaultInt(String key) {
        Integer v = INT_DEFAULTS.get(key);
        return v == null ? 0 : v;
    }

    public static String defaultString(String key) {
        String v = STRING_DEFAULTS.get(key);
        return v == null ? "" : v;
    }

    /** Manager UI copy per boolean setting, so a new key is one edit here rather than a parallel switch. */
    private static final Map<String, String> SETTING_LABELS = new LinkedHashMap<>();
    private static final Map<String, String> SETTING_SUMMARIES = new LinkedHashMap<>();

    static {
        SETTING_LABELS.put(KEY_BLOCK_TELEMETRY, "DNS sinkhole");
        SETTING_SUMMARIES.put(KEY_BLOCK_TELEMETRY,
                "Refuse resolution for tracker hosts that exist in this APK. Nord's own API can resolve over "
                        + "its DoH resolver and is not affected.");
        SETTING_LABELS.put(KEY_KILL_MOOSE, "Moose analytics");
        SETTING_SUMMARIES.put(KEY_KILL_MOOSE,
                "Drops uploads at the Rust worker's HTTP callback and forces its send flags off.");
        SETTING_LABELS.put(KEY_KILL_SDKS, "Firebase + Braze intake");
        SETTING_SUMMARIES.put(KEY_KILL_SDKS,
                "Event intake inside NordVPN only. GA4 uploads run inside Google Play services, outside this "
                        + "module's scope.");
        SETTING_LABELS.put(KEY_OPT_OPENVPN, "OpenVPN mssfix rewrite");
        SETTING_SUMMARIES.put(KEY_OPT_OPENVPN,
                "Replaces the template's mssfix 1450. Held back until the argument is confirmed to be config "
                        + "text rather than a file path.");
        SETTING_LABELS.put(KEY_CLAMP_MTU, "Tunnel MTU clamp (experimental)");
        SETTING_SUMMARIES.put(KEY_CLAMP_MTU,
                "Off by default and only lowers a request above the target. The real MTU decisions live in "
                        + "TunnelManager and telio, which this does not touch.");
        SETTING_LABELS.put(KEY_DEBLOAT_NAGS, "Nag and survey suppression");
        SETTING_SUMMARIES.put(KEY_DEBLOAT_NAGS,
                "CSAT survey triggers, promo reminder broadcasts, Threat Protection keep-active sheet, "
                        + "rating prompts, and promo storage (promotions never reach the database, so no "
                        + "banner can be shown later).");
        SETTING_LABELS.put(KEY_MOOSE_UI_EVENTS, "Moose: UI behavioural events");
        SETTING_SUMMARIES.put(KEY_MOOSE_UI_EVENTS,
                "UiItems Click/Hover/Show and Notifications Open/Close/Show.");
        SETTING_LABELS.put(KEY_MOOSE_DEBUGGER, "Moose: debugger log channel");
        SETTING_SUMMARIES.put(KEY_MOOSE_DEBUGGER, "The debugger log and exception-capture channels.");
        SETTING_LABELS.put(KEY_VERBOSE, "Verbose hook logging");
        SETTING_SUMMARIES.put(KEY_VERBOSE, "Logs every suppressed event by name. Chatty inside the target.");
        SETTING_LABELS.put(KEY_JUNK, "NordLynx junk packets");
        SETTING_SUMMARIES.put(KEY_JUNK,
                "Sends unparseable UDP datagrams just before each WireGuard handshake so the traffic ahead of "
                        + "it looks like noise. Client-side only: Nord's peer drops them and handles the real "
                        + "handshake normally. It does not hide the handshake packet itself, so against deep "
                        + "inspection that matches WireGuard's signature this alone may not be enough.");
        SETTING_LABELS.put(KEY_DEPOISON_DNS, "Correct poisoned Nord DNS");
        SETTING_SUMMARIES.put(KEY_DEPOISON_DNS,
                "When the system resolver answers a Nord domain with a private address (measured: "
                        + "api.nordvpn.com -> 10.10.34.36), hand back the address the app already learned from "
                        + "its own DNS-over-HTTPS resolver. Nothing is invented, and only public answers are "
                        + "ever used.");
    }

    public static String settingLabel(String key) {
        String v = SETTING_LABELS.get(key);
        return v == null ? key : v;
    }

    public static String settingSummary(String key) {
        String v = SETTING_SUMMARIES.get(key);
        return v == null ? "" : v;
    }
}
