package edu.adelaide.util;

import jakarta.servlet.http.HttpServletRequest;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class IpUtil {
  private IpUtil() {}

  // RFC 7239: Forwarded: for=1.2.3.4;proto=http;by=...
  private static final Pattern FORWARDED_FOR = Pattern.compile("for=\"?\\[?([^;,\"]+)\\]?");

  /** ============ HTTP ============ */
  public static String getClientIp(HttpServletRequest req) {
    if (req == null) return null;

    String xff = firstHeader(req, "X-Forwarded-For");
    if (notBlank(xff)) {
      // first hop
      return normalizeHost(xff.split(",")[0].trim());
    }

    String ip = firstHeader(req, "X-Real-IP");
    if (notBlank(ip)) return normalizeHost(ip);

    String cf = firstHeader(req, "CF-Connecting-IP");       // Cloudflare
    if (notBlank(cf)) return normalizeHost(cf);

    String tci = firstHeader(req, "True-Client-IP");        // Akamai
    if (notBlank(tci)) return normalizeHost(tci);

    String fwd = firstHeader(req, "Forwarded");
    if (notBlank(fwd)) {
      Matcher m = FORWARDED_FOR.matcher(fwd);
      if (m.find()) return normalizeHost(m.group(1));
    }

    return normalizeHost(req.getRemoteAddr());
  }

  public static Integer getClientPort(HttpServletRequest req) {
    return (req == null) ? null : req.getRemotePort(); // Temporary port, for logging only
  }

  /** ============ Spring WebSocket (non-reactive) ============ */
  public static String getClientIp(org.springframework.web.socket.WebSocketSession session) {
    if (session == null) return null;

    // headers from handshake (behind reverse proxy)
    String xff = firstHeader(session.getHandshakeHeaders().get("X-Forwarded-For"));
    if (notBlank(xff)) return normalizeHost(xff.split(",")[0].trim());

    String xrip = firstHeader(session.getHandshakeHeaders().get("X-Real-IP"));
    if (notBlank(xrip)) return normalizeHost(xrip);

    String cf = firstHeader(session.getHandshakeHeaders().get("CF-Connecting-IP"));
    if (notBlank(cf)) return normalizeHost(cf);

    String tci = firstHeader(session.getHandshakeHeaders().get("True-Client-IP"));
    if (notBlank(tci)) return normalizeHost(tci);

    InetSocketAddress ra = session.getRemoteAddress();
    return (ra == null) ? null : normalizeHost(ra.getAddress() != null ? ra.getAddress().getHostAddress() : null);
  }

  public static Integer getClientPort(org.springframework.web.socket.WebSocketSession session) {
    if (session == null) return null;
    InetSocketAddress ra = session.getRemoteAddress();
    return (ra == null) ? null : ra.getPort();
  }

  /** ============ WebFlux WebSocket ============ */
  public static String getClientIp(org.springframework.web.reactive.socket.WebSocketSession session) {
    if (session == null) return null;

    var headers = session.getHandshakeInfo().getHeaders();
    String xff = firstHeader(headers.get("X-Forwarded-For"));
    if (notBlank(xff)) return normalizeHost(xff.split(",")[0].trim());

    String xrip = firstHeader(headers.get("X-Real-IP"));
    if (notBlank(xrip)) return normalizeHost(xrip);

    String cf = firstHeader(headers.get("CF-Connecting-IP"));
    if (notBlank(cf)) return normalizeHost(cf);

    String tci = firstHeader(headers.get("True-Client-IP"));
    if (notBlank(tci)) return normalizeHost(tci);

    InetSocketAddress ra = session.getHandshakeInfo().getRemoteAddress();
    return (ra == null) ? null : normalizeHost(ra.getAddress() != null ? ra.getAddress().getHostAddress() : null);
  }

  public static Integer getClientPort(org.springframework.web.reactive.socket.WebSocketSession session) {
    if (session == null) return null;
    InetSocketAddress ra = session.getHandshakeInfo().getRemoteAddress();
    return (ra == null) ? null : ra.getPort();
  }

  /** ============ Convenience: return both ============ */
  public record ClientAddr(String ip, Integer port) {}

  public static ClientAddr resolve(HttpServletRequest req) {
    return new ClientAddr(getClientIp(req), getClientPort(req));
  }
  public static ClientAddr resolve(org.springframework.web.socket.WebSocketSession s) {
    return new ClientAddr(getClientIp(s), getClientPort(s));
  }
  public static ClientAddr resolve(org.springframework.web.reactive.socket.WebSocketSession s) {
    return new ClientAddr(getClientIp(s), getClientPort(s));
  }

  /** ============ helpers ============ */
  private static String firstHeader(jakarta.servlet.http.HttpServletRequest req, String name) {
    String v = req.getHeader(name);
    return (notBlank(v) ? v : null);
  }
  private static String firstHeader(List<String> vals) {
    if (vals == null || vals.isEmpty()) return null;
    for (String v : vals) if (notBlank(v)) return v;
    return null;
  }
  private static boolean notBlank(String s) { return s != null && !s.isBlank() && !"unknown".equalsIgnoreCase(s); }

  /** Normalize host: strip quotes/brackets/ports; keep IPv6 as-is. */
  private static String normalizeHost(String host) {
    if (!notBlank(host)) return null;
    host = host.trim().replace("\"", "");

    // If bracketed IPv6 like [2001:db8::1]:443
    if (host.startsWith("[")) {
      int end = host.indexOf(']');
      if (end > 0) return host.substring(1, end);
      return host.substring(1);
    }

    // If contains multiple colons it's IPv6 literal without brackets -> return as-is
    int colonCount = 0;
    for (int i = 0; i < host.length(); i++) if (host.charAt(i) == ':') colonCount++;
    if (colonCount > 1) return host;

    // IPv4 or hostname possibly with :port -> strip the last colon part
    int idx = host.lastIndexOf(':');
    if (idx > -1) return host.substring(0, idx);
    return host;
  }
}
