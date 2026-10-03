package com.nordoptimizer.lsposed.common;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;
import android.os.Process;

/**
 * The only channel between the two processes. It is exported because the hooked NordVPN process has to reach
 * it, and a permission cannot be used instead: the target app does not declare one. Access is therefore
 * decided by calling UID, and the data kept here is counters and setting values only.
 */
public class StatusProvider extends ContentProvider {

    private static volatile Bundle lastReport;
    private static volatile long lastReportAt;

    @Override
    public boolean onCreate() {
        ConfigManager.init(getContext());
        return true;
    }

    @Override
    public Bundle call(String method, String arg, Bundle extras) {
        boolean self = isSelf();
        boolean target = isTarget();
        boolean shell = isShell();
        if (!self && !target && !shell) {
            throw new SecurityException("NordOptimizer: caller uid " + Binder.getCallingUid() + " is not allowed");
        }
        if (Contract.METHOD_REPORT.equals(method)) {
            // Only the module itself and the hooked process may write; adb shell stays read-only.
            if (extras != null && (self || target)) {
                lastReport = extras;
                lastReportAt = System.currentTimeMillis();
            }
            return null;
        }
        ConfigManager.init(getContext());
        Bundle out = new Bundle();
        if (Contract.METHOD_CONFIG.equals(method)) {
            ConfigManager.writeTo(out);
        } else if (Contract.METHOD_VERSION.equals(method)) {
            out.putLong(Contract.KEY_GENERATION, ConfigManager.generation());
        } else {
            return null;
        }
        return out;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"key", "value"});
        Bundle report = lastReport;
        long age = report == null ? -1 : System.currentTimeMillis() - lastReportAt;
        cursor.addRow(new Object[]{"report_age_ms", String.valueOf(age)});
        if (report != null) {
            cursor.addRow(new Object[]{Contract.FIELD_PID, String.valueOf(report.getInt(Contract.FIELD_PID))});
            cursor.addRow(new Object[]{Contract.FIELD_SOURCE, report.getString(Contract.FIELD_SOURCE)});
            cursor.addRow(new Object[]{Contract.FIELD_PROCESS, report.getString(Contract.FIELD_PROCESS)});
            cursor.addRow(new Object[]{Contract.FIELD_TARGET_VERSION,
                    report.getString(Contract.FIELD_TARGET_VERSION)});
            cursor.addRow(new Object[]{Contract.FIELD_DIGEST, report.getString(Contract.FIELD_DIGEST)});
            cursor.addRow(new Object[]{Contract.FIELD_OBSERVE_ONLY,
                    String.valueOf(report.getBoolean(Contract.FIELD_OBSERVE_ONLY))});
            cursor.addRow(new Object[]{"provider_reachable",
                    String.valueOf(report.getBoolean(ConfigClient.FIELD_PROVIDER_REACHABLE))});
            String[] rows = report.getStringArray(Contract.FIELD_ROWS);
            if (rows != null) {
                for (String row : rows) cursor.addRow(new Object[]{"hook", row});
            }
            String[] hosts = report.getStringArray(Contract.FIELD_HOSTS);
            if (hosts != null) {
                for (String host : hosts) cursor.addRow(new Object[]{"host", host});
            }
            for (String column : new String[]{Contract.FIELD_SAMPLES, Contract.FIELD_FACTS,
                    Contract.FIELD_COUNTERS, Contract.FIELD_SELFTEST}) {
                String[] values = report.getStringArray(column);
                if (values == null) continue;
                for (String value : values) cursor.addRow(new Object[]{column, value});
            }
        }
        Bundle config = new Bundle();
        ConfigManager.writeTo(config);
        for (String key : config.keySet()) cursor.addRow(new Object[]{"config", key + "=" + config.get(key)});
        return cursor;
    }

    @Override
    public String getType(Uri uri) {
        return "vnd.android.cursor.item/nord_optimizer_status";
    }

    /** Nothing here is a data store; the hook table and config are served by {@link #call} and {@link #query}. */
    @Override
    public Uri insert(Uri uri, ContentValues values) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        throw new UnsupportedOperationException();
    }

    public static Bundle lastReport() {
        return lastReport;
    }

    public static long lastReportAt() {
        return lastReportAt;
    }

    private boolean isSelf() {
        return Binder.getCallingUid() == Process.myUid();
    }

    private boolean isShell() {
        return Binder.getCallingUid() == Process.SHELL_UID;
    }

    private boolean isTarget() {
        try {
            String pkg = getContext().getPackageManager().getNameForUid(Binder.getCallingUid());
            return Contract.TARGET_PKG.equals(pkg);
        } catch (Throwable t) {
            return false;
        }
    }
}
