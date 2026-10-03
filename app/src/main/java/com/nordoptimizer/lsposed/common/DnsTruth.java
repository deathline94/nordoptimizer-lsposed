package com.nordoptimizer.lsposed.common;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.nordoptimizer.lsposed.core.HookReport;

/**
 * Answers the app's own DNS-over-HTTPS resolver produced, kept so they can be handed back when the system
 * resolver returns something impossible.
 *
 * <p>Why this exists: on the network this module is developed against, {@code api.nordvpn.com} resolves to
 * {@code 10.10.34.36} -- a private address, i.e. deliberate DNS poisoning -- while Nord's own resolver
 * ({@code communication.nordtls.NordTlsCompositeDns}, DoH/DoT with ECH) returns the real Cloudflare answers.
 * Android's Private DNS is blocked there too, so the app has one uncensored path and one poisoned one, and the
 * connect fails whenever a component happens to ask the poisoned one. Correcting the poisoned answer with the
 * app's own truthful result is what lets it reach its API and start a handshake at all.
 *
 * <p>Nothing is invented here: only addresses the app already learned for that exact name, and only public
 * ones, are ever returned.
 */
public final class DnsTruth {

    private static final int MAX_HOSTS = 64;
    private static final long TTL_MS = 30 * 60 * 1000L;

    private static final class Entry {
        final InetAddress[] addresses;
        final long at;

        Entry(InetAddress[] addresses, long at) {
            this.addresses = addresses;
            this.at = at;
        }
    }

    private static final Map<String, Entry> CACHE = new LinkedHashMap<String, Entry>(16, 0.75f, true);
    private static final java.util.concurrent.atomic.AtomicLong LEARNED =
            new java.util.concurrent.atomic.AtomicLong();
    private static final java.util.concurrent.atomic.AtomicLong USED =
            new java.util.concurrent.atomic.AtomicLong();

    private DnsTruth() {
    }

    /** The result of a name lookup as a flat list: a single {@link InetAddress} or an array of them. */
    public static List<InetAddress> addressesOf(Object result) {
        List<InetAddress> out = new ArrayList<>(2);
        if (result instanceof InetAddress) out.add((InetAddress) result);
        else if (result instanceof InetAddress[]) {
            for (InetAddress a : (InetAddress[]) result) out.add(a);
        }
        return out;
    }

    /** True when the address is private/loopback/link-local: no public service lives there. */
    public static boolean isPrivateAddress(InetAddress a) {
        return a.isSiteLocalAddress() || a.isLoopbackAddress() || a.isLinkLocalAddress()
                || a.isAnyLocalAddress();
    }

    /** The signature of DNS poisoning: a non-empty answer that is entirely private. */
    public static boolean isPrivateAnswer(Object result) {
        List<InetAddress> list = addressesOf(result);
        if (list.isEmpty()) return false;
        for (InetAddress a : list) {
            if (a == null || !isPrivateAddress(a)) return false;
        }
        return true;
    }

    /**
     * Ask the app's own resolver for a name. Installed by the facts hook once it has seen a live
     * {@code NordTlsCompositeDns}, because waiting for the app to happen to query the poisoned name is not a
     * mechanism: the connect fails while it waits.
     */
    public interface Fetcher {
        Object fetch(String host) throws Exception;
    }

    private static volatile Fetcher fetcher;
    private static final java.util.Set<String> IN_FLIGHT =
            java.util.Collections.newSetFromMap(new java.util.concurrent.ConcurrentHashMap<String, Boolean>());
    private static volatile Thread worker;

    public static void setFetcher(Fetcher f) {
        fetcher = f;
    }

    /**
     * Fetch and cache the truthful answer for a name that just came back poisoned. Returns immediately; the
     * caller's own retry (the app retries its API about ten times per attempt) is what benefits.
     */
    public static void request(final String host) {
        final Fetcher f = fetcher;
        if (f == null || host == null) return;
        if (lookup(host) != null) return;
        if (!IN_FLIGHT.add(host)) return;
        Thread t = worker;
        if (t == null) {
            synchronized (DnsTruth.class) {
                t = worker;
                if (t == null) {
                    t = new Thread(null, DnsTruth::drain, "dns-truth", 64 * 1024);
                    t.setDaemon(true);
                    worker = t;
                }
            }
        }
        synchronized (QUEUE) {
            QUEUE.add(new Object[]{host, f});
            QUEUE.notifyAll();
        }
    }

    private static final java.util.List<Object[]> QUEUE = new java.util.ArrayList<>();

    private static void drain() {
        for (; ; ) {
            String host;
            Fetcher f;
            synchronized (QUEUE) {
                while (QUEUE.isEmpty()) {
                    try {
                        QUEUE.wait();
                    } catch (InterruptedException e) {
                        return;
                    }
                }
                Object[] job = QUEUE.remove(0);
                host = (String) job[0];
                f = (Fetcher) job[1];
            }
            try {
                note(host, f.fetch(host));
                HookReport.log("dns-truth|fetched|" + host + "|" + stats());
            } catch (Throwable err) {
                HookReport.log("dns-truth|failed|" + host + "|" + err);
            } finally {
                IN_FLIGHT.remove(host);
            }
        }
    }

    /** Record a resolver answer. Values may be {@link InetAddress}es or address strings. */
    public static void note(String host, Object values) {
        if (host == null || values == null) return;
        List<InetAddress> out = new ArrayList<>(4);
        Iterable<?> items = values instanceof Iterable ? (Iterable<?>) values : java.util.Collections.singletonList(values);
        for (Object o : items) {
            InetAddress a = toAddress(o);
            if (a == null) continue;
            // Private/loopback answers are the poison, never the truth worth caching.
            if (isPrivateAddress(a)) continue;
            out.add(a);
        }
        if (out.isEmpty()) return;
        InetAddress[] array = out.toArray(new InetAddress[0]);
        synchronized (CACHE) {
            if (CACHE.size() >= MAX_HOSTS) {
                java.util.Iterator<String> it = CACHE.keySet().iterator();
                if (it.hasNext()) {
                    it.next();
                    it.remove();
                }
            }
            CACHE.put(host.toLowerCase(), new Entry(array, System.currentTimeMillis()));
        }
        LEARNED.incrementAndGet();
    }

    /** A still-valid truthful answer for this host, or null. */
    public static InetAddress[] lookup(String host) {
        if (host == null) return null;
        Entry e;
        synchronized (CACHE) {
            e = CACHE.get(host.toLowerCase());
            if (e != null && System.currentTimeMillis() - e.at > TTL_MS) {
                CACHE.remove(host.toLowerCase());
                e = null;
            }
        }
        if (e != null) USED.incrementAndGet();
        return e == null ? null : e.addresses;
    }

    private static InetAddress toAddress(Object o) {
        if (o instanceof InetAddress) return (InetAddress) o;
        if (!(o instanceof String)) return null;
        try {
            String s = ((String) o).trim();
            if (s.startsWith("/")) s = s.substring(1);
            int slash = s.indexOf('/');
            if (slash > 0) s = s.substring(0, slash);
            // Only accept a literal address: never resolve here, or the poison comes back.
            if (!s.matches("^[0-9.]+$") && !s.matches("^[0-9a-fA-F:.]+$")) return null;
            return InetAddress.getByName(s);
        } catch (Throwable t) {
            return null;
        }
    }

    public static String stats() {
        synchronized (CACHE) {
            return "learned=" + LEARNED.get() + " used=" + USED.get() + " hosts=" + CACHE.size();
        }
    }
}
