package edu.adelaide.util;

import org.springframework.core.env.Environment;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Enumeration;

/**
 * Utilities to resolve the server's advertised host/port for outbound announcements
 * (e.g., in SERVER_HELLO_JOIN payload).
 *
 * Precedence (HOST):
 *   1) explicit override argument
 *   2) Spring property:  server.advertised-host
 *   3) JVM system property: server.advertised-host
 *   4) env vars (first present): ADVERTISED_HOST, HOST, HOST_IP
 *   5) first non-loopback, up, IPv4 from local NICs (prefer site-local)
 *   6) "127.0.0.1"
 *
 * Precedence (PORT):
 *   1) explicit override argument (>0)
 *   2) Spring property:  server.advertised-port
 *   3) JVM system property: server.advertised-port
 *   4) env vars (first present & >0): ADVERTISED_PORT, PORT, SERVER_PORT
 *   5) Spring property:  server.port  (YAML/properties)
 *      (also tries local.server.port which is exposed in tests/random port)
 *   6) JVM system property: server.port
 *   7) env var: SERVER_PORT (last chance)
 *   8) ACTUAL_PORT (if set via WebServerInitializedEvent)
 *   9) 8080
 *
 * All methods are static, side-effect free and thread-safe,
 * except reading ACTUAL_PORT which can be populated at runtime via setActualPort(int).
 */
public final class AdvertisedEndpointUtil {

  private AdvertisedEndpointUtil() {}

  /** Optional runtime-filled actual listening port (e.g., from WebServerInitializedEvent). */
  private static volatile Integer ACTUAL_PORT = null;

  /** Allow wiring the real bound port after server starts (optional). */
  public static void setActualPort(int port) {
    if (port > 0) ACTUAL_PORT = port;
  }

  // ----------------------------------------------------------------------
  // Public API
  // ----------------------------------------------------------------------

  /** Resolve host with precedence; Environment may be null. */
  public static String resolveHost(String override, Environment env) {
    if (!isBlank(override)) return override;

    // Spring property
    String v = prop(env, "server.advertised-host");
    if (!isBlank(v)) return v;

    // JVM sysprop
    v = sysprop("server.advertised-host");
    if (!isBlank(v)) return v;

    // Environment variables
    v = getenv("ADVERTISED_HOST", "HOST", "HOST_IP");
    if (!isBlank(v)) return v;

    // NIC scan
    v = findPrimaryIpv4();
    return (v != null) ? v : "127.0.0.1";
  }

  /** Overload: resolveHost without Environment. */
  public static String resolveHost(String override) {
    return resolveHost(override, null);
  }

  /** Resolve port with precedence; Environment may be null. */
  public static int resolvePort(Integer override, Environment env) {
    if (isPositive(override)) return override;

    Integer p;

    // Spring advertised-port
    p = propInt(env, "server.advertised-port");
    if (isPositive(p)) return p;

    // JVM sysprop advertised-port
    p = syspropInt("server.advertised-port");
    if (isPositive(p)) return p;

    // Env vars commonly used in PaaS/container
    p = envInt("ADVERTISED_PORT", "PORT", "SERVER_PORT");
    if (isPositive(p)) return p;

    // Spring configured listening port (YAML/properties)
    p = propInt(env, "server.port");
    if (isPositive(p)) return p;

    // Spring exposes 'local.server.port' in tests/random-port scenarios
    p = propInt(env, "local.server.port");
    if (isPositive(p)) return p;

    // JVM sysprop server.port
    p = syspropInt("server.port");
    if (isPositive(p)) return p;

    // env SERVER_PORT again as last chance
    p = envInt("SERVER_PORT");
    if (isPositive(p)) return p;

    // If runtime already told us the actual bound port, prefer it
    if (isPositive(ACTUAL_PORT)) return ACTUAL_PORT;

    return 8080;
  }

  /** Overload: resolvePort without Environment. */
  public static int resolvePort(Integer override) {
    return resolvePort(override, null);
  }

  /** Combined resolver returning both values. */
  public static Endpoint resolve(String hostOverride, Integer portOverride, Environment env) {
    return new Endpoint(resolveHost(hostOverride, env), resolvePort(portOverride, env));
  }

  /** Overload: combined resolver without Environment. */
  public static Endpoint resolve(String hostOverride, Integer portOverride) {
    return resolve(hostOverride, portOverride, null);
  }

  /**
   * Try to find a non-loopback, up, IPv4 address (prefer site-local).
   * Returns null if not found or any error occurs.
   */
  public static String findPrimaryIpv4() {
    try {
      String firstIpv4 = null;
      for (Enumeration<NetworkInterface> ifs = NetworkInterface.getNetworkInterfaces();
           ifs != null && ifs.hasMoreElements(); ) {
        NetworkInterface nif = ifs.nextElement();
        if (!nif.isUp() || nif.isLoopback() || nif.isVirtual()) continue;

        for (Enumeration<InetAddress> addrs = nif.getInetAddresses();
             addrs.hasMoreElements(); ) {
          InetAddress a = addrs.nextElement();
          if (!(a instanceof Inet4Address) || a.isLoopbackAddress()) continue;
          String ip = a.getHostAddress();
          if (a.isSiteLocalAddress()) return ip; // prefer RFC1918
          if (firstIpv4 == null) firstIpv4 = ip;
        }
      }
      if (firstIpv4 != null) return firstIpv4;
      return InetAddress.getLocalHost().getHostAddress();
    } catch (Exception e) {
      return null;
    }
  }

  // ----------------------------------------------------------------------
  // Helpers
  // ----------------------------------------------------------------------

  public static record Endpoint(String host, int port) {}

  private static boolean isBlank(String s) {
    return s == null || s.trim().isEmpty();
  }

  private static boolean isPositive(Integer i) {
    return i != null && i > 0;
  }

  /** Read Spring property safely (null if env is null or key missing). */
  private static String prop(Environment env, String key) {
    try { return env != null ? env.getProperty(key) : null; }
    catch (Exception ignored) { return null; }
  }

  private static Integer propInt(Environment env, String key) {
    String v = prop(env, key);
    return parsePositiveInt(v);
  }

  private static String sysprop(String key) {
    try { return System.getProperty(key); }
    catch (SecurityException ignored) { return null; }
  }

  private static Integer syspropInt(String key) {
    return parsePositiveInt(sysprop(key));
  }

  private static String getenv(String... keys) {
    for (String k : keys) {
      try {
        String v = System.getenv(k);
        if (!isBlank(v)) return v;
      } catch (SecurityException ignored) { /* no-op */ }
    }
    return null;
  }

  private static Integer envInt(String... keys) {
    return parsePositiveInt(getenv(keys));
  }

  private static Integer parsePositiveInt(String v) {
    if (isBlank(v)) return null;
    try {
      int p = Integer.parseInt(v.trim());
      return p > 0 ? p : null;
    } catch (NumberFormatException e) {
      return null;
    }
  }
}
