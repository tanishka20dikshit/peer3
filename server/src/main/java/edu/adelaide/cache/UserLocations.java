package edu.adelaide.cache;
import org.springframework.stereotype.Component;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * User -> Server location directory (authoritative mapping).
 * Section 5.2: exactly-one-local-server per user at any given moment.
 *
 * Responsibilities:
 *  - advertise(login): set/overwrite user's hosting server and lastSeen
 *  - touch(heartbeat): bump lastSeen if mapping exists
 *  - remove(logout): remove user mapping
 *  - removeByServer(serverId): remove all users hosted by a server (server down)
 *  - lookup(user): get current location
 *  - listByServer(serverId): list users currently on a server
 *  - snapshot(): list of all mappings
 *  - purgeStale(ttl): remove mappings with lastSeen older than ttl (defensive cleanup)
 *
 * Concurrency:
 *  - Uses concurrent maps; updates keep secondary index in sync.
 */
@Component
public class UserLocations {

  public static final class Location {
    public final String userId;
    public final String serverId;
    public final Instant lastSeen;

    /** Client transport details (optional; set by advertiser) */
    public volatile String userIp;     // e.g. "203.0.113.42" or "::1"
    public volatile Integer userPort;  // e.g. 54321

    public Location(String userId, String serverId, Instant lastSeen) {
      this.userId = userId;
      this.serverId = serverId;
      this.lastSeen = lastSeen;
    }

    /** Preserve transport fields when bumping lastSeen. */
    public Location withLastSeen(Instant ts) {
      Location n = new Location(userId, serverId, ts);
      n.userIp = this.userIp;
      n.userPort = this.userPort;
      return n;
    }

    @Override public String toString() {
      return "Location{" + userId + "@" + serverId + ", lastSeen=" + lastSeen + "}";
    }
  }

  /** Primary index: userId -> Location */
  private final ConcurrentMap<String, Location> byUser = new ConcurrentHashMap<>();
  /** Secondary index: serverId -> set(userId) */
  private final ConcurrentMap<String, Set<String>> byServer = new ConcurrentHashMap<>();

  private static boolean isBlank(String s){ return s == null || s.trim().isEmpty(); }

  /**
   * LOGIN / USER_ADVERTISE: set or update user's hosting server.
   * If the user was previously on a different server, update indices accordingly.
   */
  public void advertise(String userId, String serverId) {
    if (isBlank(userId) || isBlank(serverId)) return;
    final Instant now = Instant.now();

    byUser.compute(userId, (uid, oldLoc) -> {
      if (oldLoc != null && !Objects.equals(oldLoc.serverId, serverId)) {
        // remove from old server set
        var oldSet = byServer.get(oldLoc.serverId);
        if (oldSet != null) { oldSet.remove(uid); }
      }
      // add to new server set
      byServer.computeIfAbsent(serverId, k -> ConcurrentHashMap.newKeySet()).add(uid);
      return new Location(userId, serverId, now);
    });
  }

  /**
   * LOGIN / USER_ADVERTISE with transport info (optional).
   * This overload sets userIp/userPort on the Location record.
   */
  public void advertise(String userId, String serverId, String userIp, Integer userPort) {
    if (isBlank(userId) || isBlank(serverId)) return;
    final Instant now = Instant.now();
    byUser.compute(userId, (uid, oldLoc) -> {
      if (oldLoc != null && !Objects.equals(oldLoc.serverId, serverId)) {
        var oldSet = byServer.get(oldLoc.serverId);
        if (oldSet != null) { oldSet.remove(uid); }
      }
      byServer.computeIfAbsent(serverId, k -> ConcurrentHashMap.newKeySet()).add(uid);
      Location loc = new Location(userId, serverId, now);
      loc.userIp = userIp;
      loc.userPort = userPort;
      return loc;
    });
  }

  /** HEARTBEAT from server hosting the user: bump lastSeen without changing server. */
  public void touch(String userId) {
    if (isBlank(userId)) return;
    byUser.computeIfPresent(userId, (uid, loc) -> loc.withLastSeen(Instant.now()));
  }

  /** LOGOUT / USER_REMOVE for a specific user. */
  public void remove(String userId) {
    if (isBlank(userId)) return;
    var loc = byUser.remove(userId);
    if (loc != null) {
      var set = byServer.get(loc.serverId);
      if (set != null) set.remove(userId);
    }
  }

  /** SERVER DOWN: remove all users currently mapped to the given server. Returns number removed. */
  public int removeByServer(String serverId) {
    if (isBlank(serverId)) return 0;
    var set = byServer.remove(serverId);
    if (set == null || set.isEmpty()) return 0;
    int removed = 0;
    for (String uid : set) {
      var loc = byUser.get(uid);
      if (loc != null && Objects.equals(loc.serverId, serverId)) {
        byUser.remove(uid);
        removed++;
      }
    }
    return removed;
  }

  /** Derive current serverId for a user, if any. */
  public Optional<Location> lookup(String userId) {
    if (isBlank(userId)) return Optional.empty();
    return Optional.ofNullable(byUser.get(userId));
  }

  /** List users currently hosted on a server. */
  public List<Location> listByServer(String serverId) {
    if (isBlank(serverId)) return List.of();
    var ids = byServer.getOrDefault(serverId, Set.of());
    List<Location> out = new ArrayList<>(ids.size());
    for (String uid : ids) {
      var loc = byUser.get(uid);
      if (loc != null && Objects.equals(loc.serverId, serverId)) out.add(loc);
    }
    return out;
  }

  /** Snapshot of all locations. */
  public List<Location> snapshot() {
    return new ArrayList<>(byUser.values());
  }

  /**
   * Bulk load from introducer welcome (server/user presence gossip).
   * Any provided mapping overwrites local view for those users.
   */
  public void mergeFromWelcome(Collection<Location> welcome) {
    if (welcome == null) return;
    for (Location l : welcome) {
      if (l == null || isBlank(l.userId) || isBlank(l.serverId)) continue;
      advertise(l.userId, l.serverId);
      touch(l.userId);
    }
  }

  /** Remove mappings older than ttl (ms). */
  public int purgeStale(long maxStalenessMillis) {
    if (maxStalenessMillis <= 0) return 0;
    var cutoff = Instant.now().minusMillis(maxStalenessMillis);
    int removed = 0;
    for (Map.Entry<String, Location> e : byUser.entrySet()) {
      var loc = e.getValue();
      if (loc.lastSeen.isBefore(cutoff)) {
        if (byUser.remove(e.getKey(), loc)) {
          var set = byServer.get(loc.serverId);
          if (set != null) set.remove(loc.userId);
          removed++;
        }
      }
    }
    return removed;
  }
}
