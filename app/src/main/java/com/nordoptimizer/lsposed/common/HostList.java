package com.nordoptimizer.lsposed.common;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The sinkhole list as data instead of source: a verified default set the user can subtract from and add to.
 *
 * <p>Rebuilt only when the preference signature changes, and the last lookup is memoised, because this is
 * consulted on every name resolution in the target process.
 */
public final class HostList {

    /** Every one of these was found in the APK. The Windows tool's hosts were not. */
    public static final String[] DEFAULT_HOSTS = {
            "braze.com",              // sondheim.braze.com, sdk.iad-01.braze.com
            "iamcache.braze",
            "app-measurement.com",
            "google-analytics.com",
            "doubleclick.net",
            "appsflyer.com",
            "appsflyersdk.com",
            "firebase-settings.crashlytics.com",
            "boi9osyg1uwtyafn.com",
            "icpsuawn1zy5amys.com",
            "x9fnzrtl4x8pynsf.com",
            "zwyr157wwiu6eior.com",
    };

    /**
     * Not blocked by default and dangerous to block: these carry login, the server list, pricing, Threat
     * Protection, Meshnet and push. Shown as a warning if the user types one in, rather than silently
     * refused — it is their list.
     */
    public static final String[] FUNCTIONAL_HOSTS = {
            "api.nordvpn.com", "api-nc.nordvpn.com", "pdp.nordvpn.com", "tp.nordvpn.com",
            "order.nordvpn.com", "my.nordaccount.com", "downloads.nordcdn.com",
            "nordvpn.zendesk.com", "firebaseinstallations.googleapis.com",
            "firebaseremoteconfig.googleapis.com", "mesh.nordsec.com", "nordlayer.com",
    };

    private static final int MAX_COUNTS = 64;

    private static volatile String[] effective = DEFAULT_HOSTS;
    private static volatile String signature = null;
    private static volatile String lastQueried;
    private static volatile boolean lastVerdict;
    private static final Map<String, Integer> COUNTS =
            Collections.synchronizedMap(new LinkedHashMap<String, Integer>(16, 0.75f, false));

    private HostList() {
    }

    public static void invalidate() {
        String next = ConfigClient.getString(Contract.KEY_EXTRA_HOSTS) + "#"
                + ConfigClient.getString(Contract.KEY_DISABLED_DEFAULT_HOSTS);
        if (next.equals(signature)) return;
        signature = next;
        List<String> out = new ArrayList<>();
        String disabled = normalize(ConfigClient.getString(Contract.KEY_DISABLED_DEFAULT_HOSTS));
        for (String host : DEFAULT_HOSTS) {
            if (!contains(disabled, host)) out.add(host);
        }
        for (String host : split(ConfigClient.getString(Contract.KEY_EXTRA_HOSTS))) {
            if (!out.contains(host)) out.add(host);
        }
        effective = out.toArray(new String[0]);
        lastQueried = null;
    }

    public static boolean matches(String host) {
        if (host == null) return false;
        // The one-slot memo is on every name resolution in the process from several threads, so it is guarded:
        // an unsynchronized read-modify-write could persist host B's verdict under host A's name.
        synchronized (HostList.class) {
            if (host.equals(lastQueried)) return lastVerdict;
            String lower = host.toLowerCase();
            boolean verdict = false;
            for (String blocked : effective) {
                if (lower.equals(blocked) || lower.endsWith("." + blocked)) {
                    verdict = true;
                    break;
                }
            }
            lastQueried = host;
            lastVerdict = verdict;
            return verdict;
        }
    }

    public static boolean isFunctional(String host) {
        if (host == null) return false;
        String lower = host.toLowerCase();
        for (String f : FUNCTIONAL_HOSTS) {
            if (lower.equals(f) || lower.endsWith("." + f)) return true;
        }
        return false;
    }

    /** Counted per host so the manager can show what actually tried to phone home, not just a total. */
    public static void counted(String host) {
        if (host == null) return;
        synchronized (COUNTS) {
            Integer v = COUNTS.get(host);
            if (v == null) {
                // Oldest host is evicted rather than new ones being dropped, so counters keep moving when a
                // long session sees more distinct hosts than the cap.
                while (COUNTS.size() >= MAX_COUNTS) {
                    java.util.Iterator<String> it = COUNTS.keySet().iterator();
                    if (!it.hasNext()) break;
                    it.next();
                    it.remove();
                }
            }
            COUNTS.put(host, v == null ? 1 : v + 1);
        }
    }

    public static String[] counters() {
        synchronized (COUNTS) {
            List<String> lines = new ArrayList<>(COUNTS.size());
            for (Map.Entry<String, Integer> e : COUNTS.entrySet()) {
                lines.add(e.getKey() + " x" + e.getValue());
            }
            return lines.toArray(new String[0]);
        }
    }

    private static String[] split(String raw) {
        if (raw == null || raw.trim().isEmpty()) return new String[0];
        List<String> out = new ArrayList<>();
        for (String part : raw.split("[,;\\s]+")) {
            String host = strip(part);
            if (!host.isEmpty() && !out.contains(host)) out.add(host);
        }
        return out.toArray(new String[0]);
    }

    private static String normalize(String raw) {
        StringBuilder sb = new StringBuilder();
        for (String host : split(raw)) {
            if (sb.length() > 0) sb.append(' ');
            sb.append(host);
        }
        return sb.toString();
    }

    private static boolean contains(String spaceSeparated, String host) {
        return (" " + spaceSeparated + " ").contains(" " + host + " ");
    }

    /** Accepts a bare host or a pasted URL and normalises it to a lowercase host without port or path. */
    private static String strip(String value) {
        if (value == null) return "";
        String v = value.trim().toLowerCase();
        int scheme = v.indexOf("://");
        if (scheme >= 0) v = v.substring(scheme + 3);
        int end = v.length();
        for (int i = 0; i < v.length(); i++) {
            char ch = v.charAt(i);
            if (ch == '/' || ch == '?' || ch == '#' || ch == ':') {
                end = i;
                break;
            }
        }
        v = v.substring(0, end);
        while (v.endsWith(".")) v = v.substring(0, v.length() - 1);
        return v;
    }
}
