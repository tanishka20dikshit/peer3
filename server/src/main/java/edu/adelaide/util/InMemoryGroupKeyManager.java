package edu.adelaide.util;

import javax.crypto.Cipher;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Runtime-only group-key manager:
 * - No persistence. On process restart, a new group key is created.
 * - Thread-safe. Supports on-demand wrap per user and rotation.
 */
public final class InMemoryGroupKeyManager {

  private static final int GROUP_KEY_LEN = 32; // 32 bytes -> AES-256
  private final SecureRandom rng = new SecureRandom();

  /** Current plaintext group key (lives only in memory). */
  private volatile byte[] groupKey = null;

  /** Version for optimistic coordination (increments on rotate). */
  private final AtomicLong version = new AtomicLong(0L);

  /** Per-user wrapped_key cache (invalidated on rotate). */
  private final Map<String, String> wrappedCache = new ConcurrentHashMap<>();

  /** Ensure we have a group key; create if absent. */
  public void ensureKey() {
    if (groupKey == null) {
      synchronized (this) {
        if (groupKey == null) {
          groupKey = new byte[GROUP_KEY_LEN];
          rng.nextBytes(groupKey);
          version.set(1L);
          wrappedCache.clear();
        }
      }
    }
  }

  /** Force rotate: create a NEW group key; clear all wrapped cache; version++. */
  public long rotate() {
    synchronized (this) {
      groupKey = new byte[GROUP_KEY_LEN];
      rng.nextBytes(groupKey);
      long v = version.incrementAndGet();
      wrappedCache.clear();
      return v;
    }
  }

  /** Get current version (0 means not initialized yet). */
  public long currentVersion() {
    return version.get();
  }

  /**
   * Return wrapped_key for specific user, creating on-demand.
   * Different users get different wrapped_key (RSA-OAEP with user's enc public key).
   */
  public String getOrCreateWrappedKey(String userId, RSAPublicKey userEncPub) throws Exception {
    if (userId == null || userId.isBlank()) throw new IllegalArgumentException("userId blank");
    if (userEncPub == null) throw new IllegalArgumentException("userEncPub null");
    ensureKey();
    // Fast path via cache
    String cached = wrappedCache.get(userId);
    if (cached != null) return cached;
    // Compute and cache
    String wrapped = wrapGroupKeyFor(userEncPub, groupKey);
    wrappedCache.put(userId, wrapped);
    return wrapped;
  }

  /** Bulk wrap convenience. Returns userId->wrapped_key map (reuses cache). */
  public Map<String, String> getOrCreateWrappedKeys(Map<String, RSAPublicKey> userEncPubs) throws Exception {
    ensureKey();
    for (Map.Entry<String, RSAPublicKey> e : userEncPubs.entrySet()) {
      final String uid = e.getKey();
      final RSAPublicKey pub = e.getValue();
      if (uid == null || uid.isBlank() || pub == null) continue;
      wrappedCache.computeIfAbsent(uid, k -> {
        try { return wrapGroupKeyFor(pub, groupKey); } catch (Exception ex) { throw new RuntimeException(ex); }
      });
    }
    return Map.copyOf(wrappedCache);
  }

  /** Low-level RSA-OAEP(SHA-256) wrap; output base64url (no padding). */
  public static String wrapGroupKeyFor(RSAPublicKey encPub, byte[] groupKey) throws Exception {
    Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    c.init(Cipher.ENCRYPT_MODE, encPub);
    byte[] ct = c.doFinal(groupKey);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(ct);
  }
}
