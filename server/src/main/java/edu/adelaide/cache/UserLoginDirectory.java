package edu.adelaide.cache;

import lombok.Getter;
import org.slf4j.Logger; import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Very simple in-memory store for "currently logged-in users", grouped by serverId.
 *
 * Protocol mapping:
 * - On LOCAL_USER_ADVERTISE (login):  upsert(serverId, userId, ...).
 * - On USER_REMOVE (logout):          removeUser(serverId, userId).
 * - On server offline:                removeByServer(serverId).
 * - Queries: listAll(), listByUserId(userId).
 *
 * TOFU key pinning:
 * - verifyOrPinPubkey(userId, pubkey) pins the first seen key, then requires equality afterwards.
 * - verifyOrPinEncPubkey(userId, encPubkey) same for the encryption key.
 * - Keys are NOT removed on logout; they remain pinned unless you explicitly add a "forget" API.
 */
@Service
public class UserLoginDirectory {

  private static final Logger log = LoggerFactory.getLogger(UserLoginDirectory.class);

  /** serverId -> (userId -> UserLogin) */
  private final ConcurrentHashMap<String, ConcurrentHashMap<String, UserLogin>> byServer = new ConcurrentHashMap<>();

  /** TOFU stores (user-scoped), base64url SPKI strings */
  private final ConcurrentHashMap<String, String> pinnedSignKeys = new ConcurrentHashMap<>();
  private final ConcurrentHashMap<String, String> pinnedEncKeys  = new ConcurrentHashMap<>();

  // ----------------- Mutations -----------------

  /**
   * remote user add
   * @param serverId
   * @param userId
   * @param displayName
   */
  public void upsert(String serverId,
                     String userId,
                     String displayName)
  {
    upsert(serverId, userId, displayName, null, null, null, null);
  }

  /** add local user*/
  public void upsert(String serverId,
                     String userId,
                     String displayName,
                     String pubkey,
                     String enc_pubkey,
                     String userIp,
                     Integer userPort)
  {
    if (isBlank(serverId) || isBlank(userId)) return;
    var perServer = byServer.computeIfAbsent(serverId, k -> new ConcurrentHashMap<>());
    perServer.put(
        userId,
        new UserLogin(serverId, userId, displayName, userIp, userPort,
            pubkey, enc_pubkey, System.currentTimeMillis())
    );
    pinnedEncKeys.put(userId,enc_pubkey);
    pinnedSignKeys.put(userId,pubkey);
  }

  /** LOGOUT: remove a single user from a server. */
  public boolean removeUser(String serverId, String userId) {
    if (isBlank(serverId) || isBlank(userId)) return false;
    var perServer = byServer.get(serverId);
    if (perServer == null) return false;
    boolean removed = perServer.remove(userId) != null;
    if (perServer.isEmpty()) byServer.remove(serverId, perServer);
    return removed;
  }

  /** SERVER OFFLINE: remove all users that belong to this server. */
  public int removeByServer(String serverId) {
    if (isBlank(serverId)) return 0;
    var removed = byServer.remove(serverId);
    int n = removed == null ? 0 : removed.size();
    if (n > 0) log.info("[UserLoginDirectory] cleared {} users for offline server {}", n, serverId);
    return n;
  }

  // ----------------- TOFU key pinning -----------------

  /**
   * TOFU for the user's signature public key.
   * - If the key is not pinned yet: pin it.
   * - If pinned: require exact equality; otherwise throw.
   */
  public void verifyOrPinPubkey(String userId, String pubkeyB64u) {
    if (isBlank(userId) || isBlank(pubkeyB64u)) {
      throw new IllegalArgumentException("userId/pubkey must not be blank");
    }
    var normalized = normalize(pubkeyB64u);
    pinnedSignKeys.compute(userId, (k, existing) -> {
      if (existing == null) {
        return normalized;
      }
      if (!existing.equals(normalized)) {
        throw new IllegalStateException("Signature public key mismatch for user " + userId);
      }
      return existing;
    });
  }

  /**
   * TOFU for the user's encryption public key.
   * - If the key is not pinned yet: pin it.
   * - If pinned: require exact equality; otherwise throw.
   */
  public void verifyOrPinEncPubkey(String userId, String encPubkeyB64u) {
    if (isBlank(userId) || isBlank(encPubkeyB64u)) {
      throw new IllegalArgumentException("userId/enc_pubkey must not be blank");
    }
    var normalized = normalize(encPubkeyB64u);
    pinnedEncKeys.compute(userId, (k, existing) -> {
      if (existing == null) {
        return normalized;
      }
      if (!existing.equals(normalized)) {
        throw new IllegalStateException("Encryption public key mismatch for user " + userId);
      }
      return existing;
    });
  }

  /** Lookup pinned signature key for the given user. */
  public String findPubkeyByUserId(String userId) {
    if (isBlank(userId)) return null;
    return pinnedSignKeys.get(userId);
  }
  /** Lookup pinned encryption key for the given user. */
  public String findEncPubkeyByUserId(String userId) {
    if (isBlank(userId)) return null;
    return pinnedEncKeys.get(userId);
  }

  // ----------------- Queries -----------------

  /** Snapshot all logged-in users across all servers. */
  public List<UserLogin> listAll() {
    List<UserLogin> out = new ArrayList<>();
    for (var perServer : byServer.values()) out.addAll(perServer.values());
    return out;
  }

  /** Find all records for a given userId (may be logged in on multiple servers). */
  public List<UserLogin> listByUserId(String userId) {
    if (isBlank(userId)) return List.of();
    List<UserLogin> out = new ArrayList<>();
    for (var e : byServer.entrySet()) {
      var perServer = e.getValue();
      var rec = perServer.get(userId);
      if (rec != null) out.add(rec);
    }
    return out;
  }

  /** Optional: list all users for a specific server. */
  public List<UserLogin> listByServer(String serverId) {
    var perServer = byServer.get(serverId);
    if (perServer == null) return List.of();
    return new ArrayList<>(perServer.values());
  }

  /** Optional: quick existence check. */
  public boolean isLoggedIn(String serverId, String userId) {
    var perServer = byServer.get(serverId);
    return perServer != null && perServer.containsKey(userId);
  }

  // ----------------- Model -----------------

  @Getter
  public static class UserLogin {
    private final String serverId;
    private final String userId;
    private final String displayName;
    /** Client transport details (optional) */
    private final String userIp;     // e.g., "203.0.113.42" or "::1"
    private final Integer userPort;  // e.g., 54321
    private final String pubkey;
    private final String enc_pubkey;

    private final long loginTs;

    public UserLogin(String serverId, String userId, String displayName,
                     String userIp, Integer userPort,
                     String pubkey, String enc_pubkey, long loginTs) {
      this.serverId    = serverId;
      this.userId      = userId;
      this.displayName = displayName;
      this.userIp      = userIp;
      this.userPort    = userPort;
      this.pubkey      = pubkey;
      this.enc_pubkey  = enc_pubkey;
      this.loginTs     = loginTs;
    }

    @Override public String toString() {
      return "UserLogin{" + userId + "@" + serverId + ", name=" + displayName + "}";
    }
  }

  // ----------------- helpers -----------------

  private static boolean isBlank(String s){ return s == null || s.trim().isEmpty(); }
  private static List<String> safeRoles(List<String> in){ return (in == null) ? List.of() : List.copyOf(in); }
  private static Map<String,Object> safeAttrs(Map<String,Object> in){ return (in == null) ? Map.of() : Map.copyOf(in); }

  /** Trim all whitespace/newlines for base64url inputs to avoid accidental mismatches. */
  private static String normalize(String b64u){
    return (b64u == null) ? null : b64u.replaceAll("\\s+","").trim();
  }
}
