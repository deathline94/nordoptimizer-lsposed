package com.nordoptimizer.lsposed.core;

public final class Observation {

    /**
     * Install and measure every hook, changing nothing. Kept permanently as a build switch so a future
     * NordVPN update can be triaged by re-reading the install table instead of guessing which hook broke:
     * set it back to {@code true} and the same APK reports without altering anything.
     */
    public static final boolean OBSERVE_ONLY = false;

    /**
     * NordVPN keeps a {@code de.robv.android.xposed} presence probe and a frida probe with an error path.
     * A hook on one of the app's own classes is visible to both; a framework hook is not, so the app-class
     * context hooks stay off unless deliberately debugging.
     */
    public static final boolean DIAGNOSTIC_APP_CLASS_HOOKS = false;

    public static volatile boolean verbose = false;

    private Observation() {
    }
}
