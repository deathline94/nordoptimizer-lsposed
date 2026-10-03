package com.nordoptimizer.lsposed.common;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.os.Bundle;
import android.os.Process;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

import com.nordoptimizer.lsposed.core.HookReport;
import com.nordoptimizer.lsposed.core.Observation;

/** Target-process runtime state, pushed into the module process through {@link ConfigClient}. */
public final class StatusReporter {

    private static final int MAX_HOSTS = 64;

    private static final LinkedHashSet<String> HOSTS = new LinkedHashSet<>();
    private static volatile int pid;
    private static volatile String attachSource = "none";
    private static volatile String processName = "?";
    private static volatile String targetVersion = "?";
    private static volatile long attachedAt = 0L;
    /** Last MTU the app asked the framework for, from {@code VpnService.Builder.setMtu}. 0 = never asked. */
    private static volatile int builderMtu = 0;

    private StatusReporter() {
    }

    public static void noteAttached(Context context, String source, String process) {
        if (context == null) return;
        pid = Process.myPid();
        attachSource = source;
        processName = process == null ? "?" : process;
        attachedAt = System.currentTimeMillis();
        targetVersion = readVersion(context);
        HookReport.log("ATTACH|ok|src=" + attachSource + "|proc=" + processName + "|pid=" + pid
                + "|target=" + targetVersion);
        ConfigClient.attach(context);
        ConfigClient.pushReport(context, false);
    }

    private static String readVersion(Context context) {
        try {
            PackageInfo info = context.getPackageManager().getPackageInfo(Contract.TARGET_PKG, 0);
            return info.versionName + "/" + info.versionCode;
        } catch (Throwable t) {
            return "unknown";
        }
    }

    /**
     * Records a host for the manager's seen list. Accepts bare hostnames and URLs; anything that does not
     * reduce to a hostname — a bare path ({@code /v2/app/events}) or an empty remainder — is dropped rather
     * than recorded as if it were a host.
     */
    public static void noteHost(String raw) {
        String host = normalizeHost(raw);
        if (host == null) return;
        synchronized (HOSTS) {
            if (HOSTS.contains(host)) return;
            HOSTS.add(host);
            if (HOSTS.size() > MAX_HOSTS) HOSTS.remove(HOSTS.iterator().next());
        }
    }

    private static String normalizeHost(String raw) {
        if (raw == null) return null;
        String v = raw.trim().toLowerCase();
        int scheme = v.indexOf("://");
        if (scheme >= 0) v = v.substring(scheme + 3);
        int at = v.indexOf('@');               // user:pass@host form
        if (at >= 0) v = v.substring(at + 1);
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
        // A recordable host carries a dot and no whitespace; anything else (a path, a fragment of one) is
        // not a host and previously ended up in the manager's list as junk.
        if (v.isEmpty() || v.indexOf('.') < 0 || v.indexOf(' ') >= 0) return null;
        return v;
    }

    public static String[] observedHosts() {
        synchronized (HOSTS) {
            return HOSTS.toArray(new String[0]);
        }
    }

    public static String targetVersion() {
        return targetVersion;
    }

    public static Bundle reportBundle() {
        List<HookReport.Feature> features = HookReport.snapshot();
        if (features.isEmpty() && pid == 0) return null;
        String[] rows = new String[features.size()];
        List<String> samples = new ArrayList<>();
        for (int i = 0; i < features.size(); i++) {
            HookReport.Feature f = features.get(i);
            rows[i] = f.id + '|' + f.label + '|' + f.state() + '|' + HookReport.verdict(f)
                    + "|r=" + f.resolved() + "|f=" + f.fired() + "|s=" + f.substituted()
                    + "|e=" + f.errors() + '|' + f.detail();
            for (String sample : HookReport.samplesOf(f)) samples.add(f.id + '|' + sample);
        }
        Bundle b = new Bundle();
        b.putInt(Contract.FIELD_PID, pid);
        b.putString(Contract.FIELD_SOURCE, attachSource);
        b.putString(Contract.FIELD_PROCESS, processName);
        b.putString(Contract.FIELD_TARGET_VERSION, targetVersion);
        b.putLong(Contract.FIELD_ATTACHED_AT, attachedAt);
        b.putString(Contract.FIELD_DIGEST, HookReport.digest());
        b.putBoolean(Contract.FIELD_OBSERVE_ONLY, Observation.OBSERVE_ONLY);
        b.putStringArray(Contract.FIELD_ROWS, rows);
        b.putStringArray(Contract.FIELD_HOSTS, observedHosts());
        b.putStringArray(Contract.FIELD_SAMPLES, samples.toArray(new String[0]));
        b.putStringArray(Contract.FIELD_FACTS, HookReport.facts().toArray(new String[0]));
        b.putStringArray(Contract.FIELD_COUNTERS, HostList.counters());
        b.putStringArray(Contract.FIELD_SELFTEST, ConfigClient.selfTestLines());
        // Whether the target's last config poll reached the provider: the difference between "module not
        // loaded" and "module loaded but the manager's process is unreachable".
        b.putBoolean(ConfigClient.FIELD_PROVIDER_REACHABLE, ConfigClient.isProviderReachable());
        return b;
    }

    public static void noteBuilderMtu(int mtu) {
        builderMtu = mtu;
    }

    public static int builderMtu() {
        return builderMtu;
    }
}
