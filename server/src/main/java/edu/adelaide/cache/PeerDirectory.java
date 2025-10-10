package edu.adelaide.cache;

import edu.adelaide.client.IntroducerClient;
import lombok.Getter;
import org.slf4j.Logger; import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class PeerDirectory {

  private static final Logger log = LoggerFactory.getLogger(PeerDirectory.class);

  // Stores Server IDs (UUIDs) mapped to their Peer metadata and liveness info.
  private final ConcurrentHashMap<String, Peer> peerDirectory = new ConcurrentHashMap<>();

  /** Replace current registry using authoritative list from SERVER_WELCOME. */
  public void loadFromWelcome(String selfId, List<IntroducerClient.ClientInfo> clients) {
    peerDirectory.clear();
    long now = System.currentTimeMillis();
    if (clients == null) return;
    for (var c : clients) {
      // NOTE: Your ClientInfo uses 'userId', but for Server-Server comms, this should be the server's ID.
      if (c == null || Objects.equals(c.userId, selfId)) continue; 
      if (c.host == null || c.host.isBlank() || c.port <= 0) continue;
      // Call lastSeen during initialization to avoid immediate failure upon first attempt.
      peerDirectory.put(c.userId, new Peer(c.userId, c.host, c.port, c.pubkeyB64u, now));
    }
  }

  /** Snapshot a list of peers excluding self. */
  public List<Peer> snapshotPeersExcept(String selfId) {
    List<Peer> list = new ArrayList<>(peerDirectory.size());
    for (var p : peerDirectory.values()) {
      if (!Objects.equals(p.serverId, selfId)) list.add(p);
    }
    return list;
  }

  /** Snapshot all peers. */
  public List<Peer> snapshotAll() {
    return new ArrayList<>(peerDirectory.values());
  }

  /** Return current size. */
  public int size() {
    return peerDirectory.size();
  }

  /** Get a peer by serverId. */
  public Peer get(String serverId) {
    if (serverId == null) return null;
    return peerDirectory.get(serverId);
  }

  /** Remove a peer by serverId. */
  public void remove(String serverId) {
    if (serverId == null) return;
    peerDirectory.remove(serverId);
  }

  // ===== Methods required by SERVER_ANNOUNCE handler =====

  /**
   * Find pinned SPKI (base64url) by serverId, or null if absent.
   * Used to verify signatures with a pinned key first.
   */
  public String findPubkeyByServerId(String serverId) {
    Peer p = get(serverId);
    return (p == null) ? null : p.getPubkey();
  }

  /**
   * Upsert a peer entry (id/host/port/pubkey).
   * Strategy:
   *  - always update host/port (endpoint may change)
   *  - pubkey: if non-empty, replace (use this when TOFU/rotate after successful verify)
   *  - if pubkey is null/blank, keep existing pinned value
   */
  public Peer upsert(String serverId, String host, int port, String spkiB64u) {
    if (serverId == null || host == null || host.isBlank() || port <= 0) {
      throw new IllegalArgumentException("upsert: bad args");
    }
    return peerDirectory.compute(serverId, (k, oldVal) -> {
      String newKey = (spkiB64u != null && !spkiB64u.isBlank())
          ? spkiB64u
          : (oldVal != null ? oldVal.getPubkey() : null);
      Peer np = new Peer(serverId, host, port, newKey);
      if (oldVal == null) {
        log.debug("[PeerDirectory] add id={} host={} port={} pinnedKey?={}", serverId, host, port, newKey != null);
      } else {
        boolean keyChanged = !Objects.equals(oldVal.getPubkey(), newKey);
        boolean epChanged = !Objects.equals(oldVal.getHost(), host) || oldVal.getPort() != port;
        log.debug("[PeerDirectory] update id={} host:{}->{} port:{}->{} keyChanged={}",
            serverId, oldVal.getHost(), host, oldVal.getPort(), port, keyChanged);
        if (!keyChanged && !epChanged) {
          // no-op fast path
        }
      }
      return np;
    });
  }

  /** After successfully communicating with the peer, mark lastSeen (using local time to avoid clock drift). */
  public void markSeenNow(String serverId) {
    if (serverId == null) return;
    long now = System.currentTimeMillis();
    // Use computeIfPresent to ensure we only update existing peers, preserving other fields.
    peerDirectory.computeIfPresent(serverId, (k, old) ->
        new Peer(old.serverId, old.host, old.port, old.pubkey, now));
  }

  /** If the timeout is inactive, the session will be removed and the return value is ttlMs in milliseconds. */
  public boolean evictIfStale(String serverId, long ttlMs) {
    if (serverId == null) return false;
    var p = peerDirectory.get(serverId);
    if (p == null) return false;
    long now = System.currentTimeMillis();
    boolean stale = (now - p.lastSeenAtMs) > ttlMs;
    if (stale) {
      peerDirectory.remove(serverId);
      log.info("[PeerDirectory] evicted stale peer id={} lastSeen={}ms ago (ttl={}ms)",
          serverId, (now - p.lastSeenAtMs), ttlMs);
    }
    return stale;
  }

  /** Optional: Check the most recent success time for log output. */
  public long lastSeenAt(String serverId) {
    var p = peerDirectory.get(serverId);
    return (p == null) ? 0L : p.lastSeenAtMs;
  }

  @Getter
  public static class Peer {
    private final String serverId;
    private final String host;
    private final int port;
    private final String pubkey;
    private final long lastSeenAtMs;

    public Peer(String serverId, String host, int port, String pubkey) {
      this(serverId, host, port, pubkey, System.currentTimeMillis());
    }
    public Peer(String serverId, String host, int port, String pubkey, long lastSeenAtMs) {
      this.serverId = serverId; this.host = host; this.port = port; this.pubkey = pubkey; this.lastSeenAtMs = lastSeenAtMs;
    }
    @Override public String toString() { return "Peer{" + serverId + "@" + host + ":" + port + "}"; }
  }
}