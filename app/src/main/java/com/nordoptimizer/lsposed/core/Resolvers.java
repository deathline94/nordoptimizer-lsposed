package com.nordoptimizer.lsposed.core;

import java.lang.reflect.Member;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

/**
 * NordVPN re-obfuscates third-party types on every release, so a method name is not a stable identifier.
 * Rule enforced here: trust a class name only where the app keeps its own names, and match methods by
 * signature instead. Kotlin {@code internal} members are name-mangled ({@code setSendEvents-OGnWXxg}), so
 * those need prefix matching, never an exact name.
 */
public final class Resolvers {

    public interface Shape {
        boolean matches(Method m);
    }

    /** Every shape actually asked for, so the self-test can re-check it later without hooking again. */
    private static final class Spec {
        final String featureId;
        final String className;
        final String label;
        final Shape shape;

        Spec(String featureId, String className, String label, Shape shape) {
            this.featureId = featureId;
            this.className = className;
            this.label = label;
            this.shape = shape;
        }
    }

    private static final List<Spec> SPECS = Collections.synchronizedList(new ArrayList<Spec>());

    private static volatile Method hookMethodApi;
    private static volatile boolean hookMethodProbed;
    private static volatile Class<?> continuationType;
    private static volatile Object unitValue;
    private static volatile ClassLoader appClassLoader;

    /** Kept so a later request (self-test) can resolve targets without another {@code LoadPackageParam}. */
    public static ClassLoader classLoader() {
        return appClassLoader;
    }

    private Resolvers() {
    }

    /** Resolve the types whose own names R8 keeps, once per hooked process. */
    public static void init(ClassLoader cl) {
        appClassLoader = cl;
        if (continuationType == null) {
            continuationType = XposedHelpers.findClassIfExists("kotlin.coroutines.Continuation", cl);
        }
        if (unitValue == null) {
            unitValue = resolveUnit(cl);
        }
    }

    /**
     * {@code kotlin.Unit} resolved from the target's own classloader. Measured on 9.14.1: a plain
     * {@code getField("INSTANCE")} can come back empty, so the fallback scans for the one static whose type
     * is the class itself — the object singleton's backing field survives R8 renaming even when the field
     * name does not.
     */
    private static Object resolveUnit(ClassLoader cl) {
        Class<?> unit = XposedHelpers.findClassIfExists("kotlin.Unit", cl);
        if (unit == null) {
            HookReport.log("resolvers|unit|kotlin.Unit not resolvable from " + cl);
            return null;
        }
        try {
            return unit.getField("INSTANCE").get(null);
        } catch (Throwable ignored) {
            for (java.lang.reflect.Field fld : unit.getDeclaredFields()) {
                try {
                    if (Modifier.isStatic(fld.getModifiers()) && fld.getType() == unit) {
                        fld.setAccessible(true);
                        Object v = fld.get(null);
                        if (v != null) return v;
                    }
                } catch (Throwable ignored2) {
                    // Try the next static of the same type.
                }
            }
            HookReport.log("resolvers|unit|no singleton field on " + unit.getName());
            return null;
        }
    }

    public static Class<?> cls(ClassLoader cl, String name, HookReport.Feature f) {
        Class<?> c = XposedHelpers.findClassIfExists(name, cl);
        if (c == null) HookReport.classMissing(f, name);
        return c;
    }

    /**
     * Exact-name hook. Uses the same guarded walk as {@link #byShape} rather than
     * {@code hookAllMethods}, because the latter can reach an abstract declaration inherited from the
     * framework base class ({@code BroadcastReceiver.onReceive}) and attempt to hook a body that does not
     * exist.
     */
    public static int byName(Class<?> c, HookReport.Feature f, String name, XC_MethodHook cb) {
        return byShape(c, f, m -> name.equals(m.getName()) && !isSynthetic(m), name, cb);
    }

    /** Prefix hook for Kotlin-mangled names; walks up until some level matches. */
    public static int byPrefix(Class<?> c, HookReport.Feature f, String prefix, XC_MethodHook cb) {
        return byShape(c, f, m -> m.getName().startsWith(prefix) && !isSynthetic(m), prefix + "*", cb);
    }

    public static int byShape(Class<?> c, HookReport.Feature f, Shape shape, String label, XC_MethodHook cb) {
        register(f.id, c, label, shape);
        List<Method> concrete = new ArrayList<>();
        int abstracts = match(c, shape, concrete);
        int total = 0;
        for (Method m : concrete) {
            total += hook(m, cb);
            HookReport.signature(f, describe(m, m.getDeclaringClass()));
        }
        if (total == 0) {
            HookReport.noMatch(f, abstracts > 0
                    ? label + ": only abstract/native declarations found (" + abstracts
                    + "); implementation must be resolved from a live instance"
                    : "no method matching " + label + " on " + c.getName());
        } else {
            HookReport.installed(f, total, label);
        }
        return total;
    }

    /**
     * Collect the concrete methods a shape matches, walking up the superclass chain and stopping at the first
     * level that yields something. Returns how many matches were skipped for having no body: an abstract
     * facade method ({@code AppsFlyerLib}, {@code UniFfiHttpClient}) looks like a hit but cannot be hooked,
     * and reporting it as installed would repeat the exact mistake this module exists to fix.
     */
    private static int match(Class<?> c, Shape shape, List<Method> out) {
        int abstracts = 0;
        for (Class<?> k = c; k != null && k != Object.class; k = k.getSuperclass()) {
            Method[] declared;
            try {
                declared = k.getDeclaredMethods();
            } catch (Throwable t) {
                break;
            }
            List<Method> atThisLevel = new ArrayList<>();
            for (Method m : declared) {
                if (!shape.matches(m)) continue;
                if (Modifier.isAbstract(m.getModifiers()) || Modifier.isNative(m.getModifiers())) {
                    abstracts++;
                    continue;
                }
                atThisLevel.add(m);
            }
            if (!atThisLevel.isEmpty()) {
                out.addAll(atThisLevel);
                break;
            }
        }
        return abstracts;
    }

    /**
     * The concrete implementation of an SDK whose public class is an abstract facade. The impl class name is
     * obfuscated per release ({@code com.appsflyer.internal.AFa1zSDK} today), so it is never hardcoded: the
     * name-stable static accessor is called and the returned object's class is what gets hooked.
     */
    public static Object singleton(ClassLoader cl, String className, String accessor, HookReport.Feature f) {
        Class<?> c = cls(cl, className, f);
        if (c == null) return null;
        try {
            Method m = c.getDeclaredMethod(accessor);
            m.setAccessible(true);
            Object instance = m.invoke(null);
            if (instance == null) {
                HookReport.noMatch(f, className + "." + accessor + "() returned null");
                return null;
            }
            HookReport.signature(f, className + "#" + accessor + "()->" + instance.getClass().getName());
            return instance;
        } catch (Throwable t) {
            HookReport.noMatch(f, className + "." + accessor + "() unreachable: " + t);
            return null;
        }
    }

    /** Hook through a live instance's own class, for facades and for objects captured from arguments. */
    public static int hookInstance(Object instance, HookReport.Feature f, Shape shape, String label,
                                   XC_MethodHook cb) {
        if (instance == null) return 0;
        return byShape(instance.getClass(), f, shape, label + "@" + shortName(instance.getClass()), cb);
    }

    private static void register(String featureId, Class<?> c, String label, Shape shape) {
        for (Spec s : SPECS) {
            if (s.featureId.equals(featureId) && s.className.equals(c.getName()) && s.label.equals(label)) {
                return;
            }
        }
        SPECS.add(new Spec(featureId, c.getName(), label, shape));
    }

    /**
     * Re-check every registered target without hooking anything: the answer to "did Nord rename it?" before
     * any hook is trusted on a new build.
     */
    public static List<String> runSelfTest(ClassLoader cl) {
        List<String> lines = new ArrayList<>();
        List<Spec> specs;
        synchronized (SPECS) {
            specs = new ArrayList<>(SPECS);
        }
        for (Spec s : specs) {
            Class<?> c = XposedHelpers.findClassIfExists(s.className, cl);
            if (c == null) {
                lines.add(s.featureId + "|MISSING_CLASS|" + s.className);
                continue;
            }
            List<Method> hits = new ArrayList<>();
            int abstracts = match(c, s.shape, hits);
            if (!hits.isEmpty()) {
                lines.add(s.featureId + "|PASS|r=" + hits.size() + "|" + describe(hits.get(0), c));
            } else if (abstracts > 0) {
                lines.add(s.featureId + "|ABSTRACT_ONLY|" + abstracts + "|" + s.label);
            } else {
                lines.add(s.featureId + "|NO_MATCH|" + s.label + "|" + c.getName());
            }
        }
        return lines;
    }

    /**
     * {@code hookMethod(Member, XC_MethodHook)} is the only way to bind a single resolved overload. It is
     * absent from the local compile stub but present on LSPosed's runtime classpath, so look it up rather
     * than widening the stub.
     */
    private static int hook(Method m, XC_MethodHook cb) {
        if (!hookMethodProbed) {
            hookMethodProbed = true;
            try {
                hookMethodApi = XposedBridge.class.getMethod("hookMethod", Member.class, XC_MethodHook.class);
            } catch (Throwable t) {
                hookMethodApi = null;
            }
        }
        if (hookMethodApi != null) {
            try {
                hookMethodApi.invoke(null, m, cb);
                return 1;
            } catch (Throwable ignored) {
                return 0;
            }
        }
        try {
            // Fallback for runtimes without hookMethod: this hooks every same-name overload, not just m, so
            // per-feature counters over such a set are inflated. Logged loudly for exactly that reason.
            HookReport.log("resolvers|hookMethod missing: falling back to hookAllMethods on "
                    + m.getDeclaringClass().getName() + "#" + m.getName());
            Set<?> unhooked = XposedBridge.hookAllMethods(m.getDeclaringClass(), m.getName(), cb);
            return unhooked == null ? 0 : unhooked.size();
        } catch (Throwable ignored) {
            return 0;
        }
    }

    /** Xposed hands back a {@code Member}; the suspend test needs the parameter list. */
    public static boolean isSuspend(Member m) {
        if (!(m instanceof Method)) return false;
        Class<?> c = continuationType;
        if (c == null) return false;
        Class<?>[] p = ((Method) m).getParameterTypes();
        return p.length > 0 && c.isAssignableFrom(p[p.length - 1]);
    }

    public static Class<?> returnType(Member m) {
        return m instanceof Method ? ((Method) m).getReturnType() : void.class;
    }

    /** Kotlin emits {@code $default} and bridge overloads that forward to the real method; hooking both counts twice. */
    public static boolean isSynthetic(Method m) {
        return (m.getModifiers() & 0x1000) != 0;
    }

    /** {@code kotlinx.coroutines.flow.Flow} is renamed; its single abstract {@code collect} is not. */
    public static boolean isFlow(Class<?> k) {
        Class<?> c = continuationType;
        if (k == null || !k.isInterface() || c == null) return false;
        int abstractCount = 0;
        boolean collects = false;
        try {
            for (Method m : k.getMethods()) {
                if (m.isDefault() || m.isSynthetic() || Modifier.isStatic(m.getModifiers())) {
                    continue;
                }
                abstractCount++;
                Class<?>[] p = m.getParameterTypes();
                if ("collect".equals(m.getName()) && p.length == 2 && c.isAssignableFrom(p[1])
                        && m.getReturnType() == Object.class) {
                    collects = true;
                }
            }
        } catch (Throwable t) {
            return false;
        }
        return abstractCount == 1 && collects;
    }

    /** Value a substituted suspend call must return; retried lazily in case init ran too early to resolve it. */
    public static Object unit() {
        Object v = unitValue;
        if (v == null && !unitRetryDone) {
            unitRetryDone = true;
            ClassLoader cl = appClassLoader;
            if (cl != null) {
                v = resolveUnit(cl);
                if (v != null) unitValue = v;
            }
        }
        return v;
    }

    private static volatile boolean unitRetryDone;

    public static String describe(Method m, Class<?> owner) {
        return owner.getName() + "#" + m.getName() + "(" + params(m) + ")" + shortName(m.getReturnType());
    }

    private static String params(Method m) {
        StringBuilder sb = new StringBuilder();
        Class<?>[] p = m.getParameterTypes();
        for (int i = 0; i < p.length; i++) {
            if (i > 0) sb.append(',');
            sb.append(shortName(p[i]));
        }
        return sb.toString();
    }

    private static String shortName(Class<?> c) {
        if (c == null) return "?";
        if (c.isArray()) return shortName(c.getComponentType()) + "[]";
        if (c == int.class) return "I";
        if (c == long.class) return "J";
        if (c == boolean.class) return "Z";
        if (c == float.class) return "F";
        if (c == double.class) return "D";
        if (c == byte.class) return "B";
        if (c == char.class) return "C";
        if (c == short.class) return "S";
        if (c == void.class) return "V";
        String n = c.getName();
        int dot = Math.max(n.lastIndexOf('.'), n.lastIndexOf('$'));
        return n.substring(dot + 1);
    }
}
