package com.nordoptimizer.lsposed.common;

import java.io.ByteArrayOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * A DNS client that needs no DNS.
 *
 * <p>Why this exists: on the network this module is developed against, the system resolver answers
 * {@code api.nordvpn.com} with {@code 10.10.34.36} (a private address) and {@code pdp.nordvpn.com} with
 * NXDOMAIN, both measured from inside NordVPN's own process. The app's DoH-capable resolver turned out not to
 * be an independent path either -- called for those names it threw {@code java.net.UnknownHostException}, i.e.
 * it delegates to the same poisoned resolver. Without truthful addresses for its own API hosts the app never
 * reaches the WireGuard stage, so no amount of pre-handshake noise can make it connect.
 *
 * <p>This asks a public resolver directly, over UDP to a literal address, so nothing has to be resolved first.
 * Only A records are requested and only public answers are returned; a blocked or spoofed reply is a failure
 * like any other and leaves the caller with nothing cached.
 *
 * <p>Known limitation, stated rather than hidden: while the VPN tunnel is up, an unprotected socket like this
 * one is captured by it and the query goes to the tunnel's resolver instead. That is acceptable here because
 * the answer is only needed during connection setup, when no tunnel exists yet.
 */
public final class UdpDns {

    private static final int[] RESOLVERS = {
            Integer.valueOf(0x08080808),   // 8.8.8.8 (Google)
            Integer.valueOf(0x01010101),   // 1.1.1.1 (Cloudflare)
            Integer.valueOf(0x09090909),   // 9.9.9.9 (Quad9)
    };
    private static final int TIMEOUT_MS = 1500;
    private static final Random RANDOM = new Random();

    private UdpDns() {
    }

    /** @return public IPv4 answers for {@code host}, or null if no resolver answered usefully. */
    public static InetAddress[] query(String host) {
        if (host == null || host.isEmpty()) return null;
        byte[] query = buildQuery(host);
        if (query == null) return null;
        for (int literal : RESOLVERS) {
            try {
                InetAddress server = InetAddress.getByAddress(new byte[]{
                        (byte) (literal >>> 24), (byte) (literal >>> 16), (byte) (literal >>> 8), (byte) literal});
                byte[] answer = exchange(server, query);
                // The first two bytes of the answer must echo the query's transaction id: an off-path spoofed
                // reply with a public address is exactly the attack this class exists to escape.
                int expectedId = ((query[0] & 0xFF) << 8) | (query[1] & 0xFF);
                List<InetAddress> parsed = parseAnswer(answer, expectedId);
                if (!parsed.isEmpty()) return parsed.toArray(new InetAddress[0]);
            } catch (Throwable ignored) {
                // Blocked, timed out, or refused: try the next resolver.
            }
        }
        return null;
    }

    private static byte[] buildQuery(String host) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream(64);
            int id = RANDOM.nextInt(0xFFFF);
            out.write((id >>> 8) & 0xFF);
            out.write(id & 0xFF);
            out.write(0x01);  // recursion desired
            out.write(0x00);
            out.write(0x00); out.write(0x01);   // one question
            out.write(0x00); out.write(0x00);   // answer count
            out.write(0x00); out.write(0x00);   // authority count
            out.write(0x00); out.write(0x00);   // additional count
            for (String label : host.split("\\.")) {
                if (label.isEmpty()) continue;
                byte[] b = label.getBytes("US-ASCII");
                if (b.length > 63) return null;
                out.write(b.length);
                out.write(b, 0, b.length);
            }
            out.write(0);
            out.write(0x00); out.write(0x01);   // type A
            out.write(0x00); out.write(0x01);   // class IN
            return out.toByteArray();
        } catch (Throwable t) {
            return null;
        }
    }

    private static byte[] exchange(InetAddress server, byte[] query) throws Exception {
        DatagramSocket socket = new DatagramSocket();
        try {
            socket.setSoTimeout(TIMEOUT_MS);
            socket.send(new DatagramPacket(query, query.length, server, 53));
            byte[] buf = new byte[1024];
            DatagramPacket response = new DatagramPacket(buf, buf.length);
            socket.receive(response);
            byte[] out = new byte[response.getLength()];
            System.arraycopy(buf, 0, out, 0, response.getLength());
            return out;
        } finally {
            socket.close();
        }
    }

    private static List<InetAddress> parseAnswer(byte[] msg, int expectedId) {
        List<InetAddress> out = new ArrayList<>(2);
        if (msg == null || msg.length < 12) return out;
        int id = ((msg[0] & 0xFF) << 8) | (msg[1] & 0xFF);
        if (id != expectedId) return out;                      // not the answer to our query
        int flags = ((msg[2] & 0xFF) << 8) | (msg[3] & 0xFF);
        if ((flags & 0x8000) == 0) return out;                 // not an answer
        if ((flags & 0x000F) != 0) return out;                 // any rcode but NOERROR
        int questions = ((msg[4] & 0xFF) << 8) | (msg[5] & 0xFF);
        int answers = ((msg[6] & 0xFF) << 8) | (msg[7] & 0xFF);
        int i = 12;
        for (int q = 0; q < questions && i < msg.length; q++) {
            i = skipName(msg, i);
            i += 4;                                            // qtype + qclass
        }
        for (int a = 0; a < answers && i + 10 < msg.length; a++) {
            i = skipName(msg, i);
            if (i + 10 > msg.length) break;
            int type = ((msg[i] & 0xFF) << 8) | (msg[i + 1] & 0xFF);
            int rdLength = ((msg[i + 8] & 0xFF) << 8) | (msg[i + 9] & 0xFF);
            i += 10;
            if (type == 1 && rdLength == 4 && i + 4 <= msg.length) {
                try {
                    InetAddress addr = InetAddress.getByAddress(
                            new byte[]{msg[i], msg[(i + 1)], msg[(i + 2)], msg[(i + 3)]});
                    // A private answer here would be the poison we are trying to escape, not a fix.
                    if (!DnsTruth.isPrivateAddress(addr)) {
                        out.add(addr);
                    }
                } catch (Throwable ignored) {
                }
            }
            i += rdLength;
        }
        return out;
    }

    /** Follows or steps over a compressed name; returns the offset after it. */
    private static int skipName(byte[] msg, int i) {
        while (i < msg.length) {
            int len = msg[i] & 0xFF;
            if (len == 0) return i + 1;
            if ((len & 0xC0) == 0xC0) return i + 2;            // pointer: terminates the question name
            i += 1 + len;
        }
        return i;
    }
}
