package com.nordoptimizer.lsposed.common;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;

import java.util.function.Consumer;

/**
 * Module-process side of the config. The target process cannot read this file directly: it is written
 * {@code MODE_PRIVATE}, and from API 24 SELinux blocks the cross-app read no matter what
 * {@code XSharedPreferences.makeReadable()} claims to do. That is why the old build appeared to remember
 * settings and silently used defaults after every restart. Reads and writes go through
 * {@link StatusProvider} instead.
 */
public final class ConfigManager {

    private static SharedPreferences prefs;

    private ConfigManager() {
    }

    public static void init(Context context) {
        prefs = context.getApplicationContext()
                .getSharedPreferences(Contract.PREFS_NAME, Context.MODE_PRIVATE);
    }

    /**
     * These read the module process's own preferences. They must not delegate to {@link ConfigClient}, which
     * is the target process's cache and would hand back compiled defaults here — making the provider serve
     * defaults to the target no matter what the user picked.
     */
    public static boolean getBoolean(String key) {
        SharedPreferences p = prefs;
        return p == null ? Contract.defaultBool(key) : p.getBoolean(key, Contract.defaultBool(key));
    }

    public static void setBoolean(Context context, String key, boolean value) {
        apply(context, editor -> editor.putBoolean(key, value));
    }

    public static int getInt(String key) {
        SharedPreferences p = prefs;
        return p == null ? Contract.defaultInt(key) : p.getInt(key, Contract.defaultInt(key));
    }

    public static void setInt(Context context, String key, int value) {
        apply(context, editor -> editor.putInt(key, value));
    }

    public static String getString(String key) {
        SharedPreferences p = prefs;
        if (p == null) return Contract.defaultString(key);
        String v = p.getString(key, null);
        return v == null ? Contract.defaultString(key) : v;
    }

    public static void setString(Context context, String key, String value) {
        String safe = value == null ? "" : value;
        apply(context, editor -> editor.putString(key, safe));
    }

    /**
     * Every write bumps the generation counter, which is what lets the target process poll cheaply: it pulls
     * the whole table only when this number moves. Synchronized because UI toggles and provider calls land on
     * different threads, and two interleaved read-modify-writes would emit a duplicate generation, which the
     * target's change detection would miss.
     */
    private static synchronized void apply(Context context, Consumer<SharedPreferences.Editor> mutation) {
        SharedPreferences p = prefs;
        if (p == null) init(context);
        p = prefs;
        long generation = p.getLong(Contract.KEY_GENERATION, 0L) + 1;
        SharedPreferences.Editor editor = p.edit();
        mutation.accept(editor);
        editor.putLong(Contract.KEY_GENERATION, generation);
        editor.apply();
    }

    public static void writeTo(Bundle out) {
        out.putLong(Contract.KEY_GENERATION, generation());
        for (String key : Contract.boolKeys().keySet()) {
            out.putBoolean(Contract.PREFIX_BOOL + key, getBoolean(key));
        }
        for (String key : Contract.intKeys().keySet()) {
            out.putInt(Contract.PREFIX_INT + key, getInt(key));
        }
        for (String key : Contract.stringKeys().keySet()) {
            out.putString(Contract.PREFIX_STRING + key, getString(key));
        }
    }

    public static long generation() {
        SharedPreferences p = prefs;
        return p == null ? 0L : p.getLong(Contract.KEY_GENERATION, 0L);
    }
}
