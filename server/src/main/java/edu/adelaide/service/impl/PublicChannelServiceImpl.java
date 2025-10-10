package edu.adelaide.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import edu.adelaide.cache.UserLoginDirectory;
import edu.adelaide.dto.ProtocolMessage;
import edu.adelaide.entity.GroupMembers;
import edu.adelaide.mapper.GroupMembersMapper;
import edu.adelaide.service.BaseService;
import edu.adelaide.service.GroupsService;
import edu.adelaide.service.PublicChannelService;
import edu.adelaide.client.ServerLinkClient;
import edu.adelaide.cache.PeerDirectory;
import edu.adelaide.cache.LocalSessionRegistry;
import edu.adelaide.util.InMemoryGroupKeyManager;
import edu.adelaide.util.RsaPublicKeyParser;
import edu.adelaide.util.UnifiedCryptoUtil;
import edu.adelaide.util.UnifiedJsonUtil;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Public channel service that persists membership (DB) and
 * fans out to clients by reading sessions from LocalSessionRegistry.
 *
 * Verbosity note:
 *  - Added detailed INFO/DEBUG/TRACE logs at method entries/exits, with arguments and counters.
 *  - Use TRACE for heavy payloads (JSON frames, snapshots) to avoid noisy logs in production.
 *  - Timings (elapsed ms) are printed for fanout/relay operations.
 */
@Service
public class PublicChannelServiceImpl extends BaseService implements PublicChannelService {

  public static final String PUBLIC_GROUP_ID = "00000000-0000-0000-0000-000000000000";

  private static final String PUBLIC_CHANNEL_ID = "public";
  private static final int    FIXED_EPOCH = 1;
  private static final String GK_B64URL = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  private static final byte[] GK_BYTES  = UnifiedCryptoUtil.base64UrlDecode(GK_B64URL);

  private final RSAPrivateKey myPriv;
  private final String myServerId;

  private final GroupsService groupsService;
  private final GroupMembersMapper groupMembers;
  private final PeerDirectory peerDir;
  private final ServerLinkClient serverLinkClient;
  private final LocalSessionRegistry sessionRegistry;

  private final UserLoginDirectory userLoginDirectory;

  // In-memory snapshot
  private final ConcurrentHashMap<String, GroupMembers> publicChannelMembers = new ConcurrentHashMap<>();
  private final ConcurrentHashMap<String, String> publicServerIds    = new ConcurrentHashMap<>();
  private final AtomicLong publicChannelVersion = new AtomicLong(0);
  private final InMemoryGroupKeyManager gkm = new InMemoryGroupKeyManager();



  public PublicChannelServiceImpl(@Qualifier("serverPrivateKey") RSAPrivateKey myPriv,
                                  @Value("${introducer.client.server-id}") String myServerId,
                                  GroupsService groupsService,
                                  GroupMembersMapper groupMembers,
                                  PeerDirectory peerDir,
                                  ServerLinkClient serverLinkClient,
                                  LocalSessionRegistry sessionRegistry,
                                  UserLoginDirectory userLoginDirectory) {
    this.myPriv = myPriv;
    this.myServerId = myServerId;
    this.groupsService = groupsService;
    this.groupMembers = groupMembers;
    this.peerDir = peerDir;
    this.serverLinkClient = serverLinkClient;
    this.sessionRegistry = sessionRegistry;
    this.userLoginDirectory = userLoginDirectory;
    log.info("[public/init] PublicChannelServiceImpl initialized serverId={} registrySessions={}",
        myServerId, safeSize(sessionRegistry));
  }

  @Override
  public void ensurePublicGroup() {
    log.debug("[public/ensure] ensuring builtin public group exists (groupId={})", PUBLIC_GROUP_ID);
    groupsService.ensureBuiltinPublic();
  }

  @Override
  public void onUserOffline(String userId) {
    log.info("[public/offline] user={} leaving public channel", userId);
    try {
      groupMembers.markLeft(PUBLIC_GROUP_ID, userId);
      log.debug("[public/offline->db] markLeft OK user={}", userId);
    } catch (Exception e) {
      log.warn("[public/offline->db] markLeft FAILED user={} err={}", userId, e.toString());
    }
    publicChannelMembers.computeIfPresent(userId, (k, gm) -> {
      gm.setStatus("left");
      gm.setUpdatedAt(new java.sql.Timestamp(System.currentTimeMillis()));
      return gm;
    });
    publicServerIds.remove(userId);
    // Notify local clients (optional)
//    broadcastPublicChannelUpdatedToClients(false, null);
    log.debug("[public/offline] cache sizes: members={} servers={} version={}",
        publicChannelMembers.size(),  publicServerIds.size(), publicChannelVersion.get());
  }

  // ---------- Publish (client -> our node -> peers) ----------

  /**
   * Backward-compatible signature: ignores external activeUsers; uses LocalSessionRegistry instead.
   */
  @Override
  public void publishToPublic(String fromUser, Object messagePayload,
                              Map<String, WebSocketSession> ignored, boolean excludeSender) {
    long t0 = System.nanoTime();
    log.info("[public/publish] fromUser={} excludeSender={} payloadType={} registrySessions={}"
            + " (ignored activeUsers arg)",
        fromUser, excludeSender, (messagePayload == null ? "null" : messagePayload.getClass().getSimpleName()),
        safeSize(sessionRegistry));
    if (log.isTraceEnabled()) log.trace("[public/publish] payload={}", safeJson(messagePayload));

    doLocalFanout(fromUser, messagePayload, excludeSender);
    relayToPeers(fromUser, messagePayload);

    long elapsedMs = (System.nanoTime() - t0) / 1_000_000;
    log.info("[public/publish] done in {} ms", elapsedMs);
  }

  /** Peer relayed a public message to this node: fanout to local clients only. */
  @Override
  public void handleServerPublicPublish(String fromUser, Object messagePayload) {
    log.info("[public/peer->local] relay fanout fromServerUser={} payloadType={}",
        fromUser, (messagePayload == null ? "null" : messagePayload.getClass().getSimpleName()));
    if (log.isTraceEnabled()) log.trace("[public/peer->local] payload={}", safeJson(messagePayload));
    doLocalFanout(fromUser, messagePayload, false);
  }

  private void doLocalFanout(String fromUser, Object messagePayload, boolean excludeSender) {
    long t0 = System.nanoTime();
    long now = System.currentTimeMillis();
    var snapshot = sessionRegistry.snapshot(); // userId -> session
    int total = snapshot.size();
    int sent = 0, skipped = 0, failures = 0;
    log.debug("[public/local] fanout start fromUser={} excludeSender={} recipients={} atTs={}",
        fromUser, excludeSender, total, now);

    for (var e : snapshot.entrySet()) {
      String uid = e.getKey();
      WebSocketSession sess = e.getValue();
      if (sess == null || !sess.isOpen()) { skipped++; continue; }
      if (excludeSender && uid.equals(fromUser)) { skipped++; continue; }
      try {
        var deliver = new ProtocolMessage();
        deliver.setType("CHANNEL_DELIVER");
        deliver.setFrom(fromUser);
        deliver.setTo(uid);
        deliver.setTs(now);
        deliver.setPayload(Map.of("channel", "public", "message", messagePayload));
        if (log.isTraceEnabled()) log.trace("[public/local->{}] frame={}", uid, safeJson(deliver));
        sendSigned(sess, deliver);
        sent++;
      } catch (Exception ex) {
        failures++;
        log.warn("[public/local->{}] deliver FAILED: {}", uid, ex.toString());
      }
    }
    long elapsedMs = (System.nanoTime() - t0) / 1_000_000;
    log.info("[public/local] fanout finish sent={} skipped={} failures={} recipients={} elapsedMs={}",
        sent, skipped, failures, total, elapsedMs);
  }

  private void relayToPeers(String fromUser, Object messagePayload) {
    long t0 = System.nanoTime();
    try {
      long now = System.currentTimeMillis();
      var relay = new ProtocolMessage();
      relay.setType("SERVER_CHANNEL_PUBLISH");
      relay.setFrom(myServerId);
      relay.setTo("*");
      relay.setTs(now);
      relay.setPayload(Map.of("channel", "public", "from", fromUser, "message", messagePayload));
      String json = UnifiedJsonUtil.toJson(relay);

      var peers = peerDir.snapshotPeersExcept(myServerId);
      int total = peers.size();
      int ok = 0, fail = 0;
      log.debug("[public/relay] start peers={} fromUser={}", total, fromUser);
      if (log.isTraceEnabled()) log.trace("[public/relay] frame={}", json);

      for (var peer : peers) {
        String url = String.format("ws://%s:%d/ws", peer.getHost(), peer.getPort());
        try {
          serverLinkClient.sendJson(peer.getServerId(), url, json);
          ok++;
          log.debug("[public/relay->{}] OK url={}", peer.getServerId(), url);
        } catch (Exception e) {
          fail++;
          log.warn("[public/relay->{}] FAIL url={} err={}", peer.getServerId(), url, e.toString());
        }
      }
      long elapsedMs = (System.nanoTime() - t0) / 1_000_000;
      log.info("[public/relay] done ok={} fail={} peers={} elapsedMs={}", ok, fail, total, elapsedMs);
    } catch (Exception e) {
      log.warn("[public/relay] build frame FAIL err={}", e.toString());
    }
  }

  /** Sign + send to a client session. */
  private void sendSigned(WebSocketSession session, ProtocolMessage msg) throws Exception {
    JsonNode unsigned = UnifiedJsonUtil.getDefaultMapper().valueToTree(msg);
    if (unsigned.has("sig")) {
      com.fasterxml.jackson.databind.node.ObjectNode objectNode = (com.fasterxml.jackson.databind.node.ObjectNode) unsigned;
      objectNode.remove("sig");
    }
    String payloadJson = UnifiedJsonUtil.toJson(unsigned.path("payload"));
    String sig = UnifiedCryptoUtil.rsaSign(payloadJson.getBytes(java.nio.charset.StandardCharsets.UTF_8), this.myPriv);
    com.fasterxml.jackson.databind.node.ObjectNode objectNode = (com.fasterxml.jackson.databind.node.ObjectNode) unsigned;
    objectNode.put("sig", sig);
    String out = unsigned.toString();
    if (log.isTraceEnabled()) log.trace("[public/sendSigned->{}] bytes={} sig.len={}",
        safeSessionId(session), out.length(), sig.length());
    session.sendMessage(new TextMessage(out));
  }

  // ---------- Public membership announce ----------

  /** Convenience overload: use registry internally, push ADD+UPDATED to peers/clients. */
  public void addUserToPublicAndAnnounce(String userId, String displayNameOrNull) {
    long t0 = System.nanoTime();
    if (userId == null || userId.isBlank()) throw new IllegalArgumentException("userId must not be null/blank");
    final long nowMs = Instant.now().toEpochMilli();
    final String displayName = (displayNameOrNull == null || displayNameOrNull.isBlank()) ? userId : displayNameOrNull;

    log.info("[public/add] user={} displayName={}", userId, displayName);



    // 1) DB upsert
    try {
      groupMembers.upsertActive(PUBLIC_GROUP_ID, userId, "member", getWrappedKey(userId));
      log.debug("[public/add->db] upsertActive OK user={}", userId);
    } catch (Exception e) {
      log.warn("[public/add->db] upsertActive FAIL user={} err={}", userId, e.toString());
    }

    // 2) Cache
    var gm = new GroupMembers()
        .setGroupId(PUBLIC_GROUP_ID)
        .setUserId(userId)
        .setRole("member")
        .setStatus("active")
        .setWrappedKey(getWrappedKey(userId))
        .setJoinedAt(new java.sql.Timestamp(nowMs))
        .setUpdatedAt(new java.sql.Timestamp(nowMs));
    publicChannelMembers.put(userId, gm);
    publicServerIds.put(userId, myServerId);

    // 3) Peers: delta ADD
    sendPublicChannelAddToPeers(userId, displayName, nowMs);

    broadcastPublicChannelUpdatedToPeers();

    // 4) Clients: full UPDATED snapshot
    broadcastPublicChannelKey(); // exclude sender can be tuned

    long elapsedMs = (System.nanoTime() - t0) / 1_000_000;
    log.info("[public/add] done user={} elapsedMs={} cache.members={}", userId, elapsedMs, publicChannelMembers.size());
  }

  /** Broadcast FULL snapshot to peer servers as PUBLIC_CHANNEL_UPDATED (no args). */
  private void broadcastPublicChannelUpdatedToPeers() {
    long ts = System.currentTimeMillis();
    long version = publicChannelVersion.incrementAndGet();
    var members = buildMembersSnapshot();

    try {
      var frame = new ProtocolMessage();
      frame.setType("PUBLIC_CHANNEL_UPDATED");
      frame.setFrom(myServerId);
      frame.setTo("*");
      frame.setTs(ts);
      frame.setPayload(Map.of(
          "channel", "public",
          "version", version,
          "wraps", members
      ));
      String json = UnifiedJsonUtil.toJson(frame);

      var peers = peerDir.snapshotPeersExcept(myServerId);
      int ok = 0, fail = 0;
      for (var p : peers) {
        String url = String.format("ws://%s:%d/ws", p.getHost(), p.getPort());
        try {
          serverLinkClient.sendJson(p.getServerId(), url, json);
          ok++;
          log.debug("[public/UPDATED->peer {}] OK url={}", p.getServerId(), url);
          log.debug("[public/UPDATED->json {}] ", json);
        } catch (Exception e) {
          fail++;
          log.warn("[public/UPDATED->peer {}] FAIL url={} err={}", p.getServerId(), url, e.toString());
        }
      }
      log.info("[public/UPDATED->peers] version={} ok={} fail={} peers={}", version, ok, fail, peers.size());
      if (log.isTraceEnabled()) log.trace("[public/UPDATED->peers] frame={}", json);
    } catch (Exception e) {
      log.warn("[public/UPDATED->peers] build/serialize FAIL err={}", e.toString());
    }
  }



  private void sendPublicChannelAddToPeers(String userId, String displayName, long nowMs) {
    final long ifVer = publicChannelVersion.get();

    try {
      var add = new ProtocolMessage();
      add.setType("PUBLIC_CHANNEL_ADD");
      add.setFrom(myServerId);
      add.setTo("*");
      add.setTs(nowMs);
      add.setPayload(Map.of(
          "add", java.util.List.of(userId),
          "if_version", ifVer
      ));
      String json = UnifiedJsonUtil.toJson(add);

      var peers = peerDir.snapshotPeersExcept(myServerId);
      int ok = 0, fail = 0;
      for (var peer : peers) {
        String url = String.format("ws://%s:%d/ws", peer.getHost(), peer.getPort());
        try { serverLinkClient.sendJson(peer.getServerId(), url, json); ok++; }
        catch (Exception e) { fail++; log.warn("[public/add->peer {}] FAIL url={} err={}", peer.getServerId(), url, e.toString()); }
      }
      log.info("[public/add->peers] user={} ok={} fail={} peers={} if_version={}", userId, ok, fail, peers.size(), ifVer);
      log.info("[public/add->peers] json={} ", json);

      if (log.isTraceEnabled()) log.trace("[public/add->peers] frame={}", json);
    } catch (Exception e) {
      log.warn("[public/add->peers] build/serialize FAIL user={} err={}", userId, e.toString());
    }
  }

  /** Build full snapshot for clients. */
  private List<Map<String,Object>> buildMembersSnapshot() {
    var members = new java.util.ArrayList<Map<String,Object>>();
    for (var e : new java.util.ArrayList<>(publicChannelMembers.entrySet())) {
      String uid = e.getKey();
      GroupMembers gm = e.getValue();
      var m = new java.util.HashMap<String,Object>();
      m.put("member_id", uid);
      m.put("wrapped_key", gm.getWrappedKey());
      members.add(m);
    }
    log.debug("[public/snapshot/build] size={}", members.size());
    if (log.isTraceEnabled()) log.trace("[public/snapshot/build] members={}", safeJson(members));
    return members;
  }


  private static byte[] rsaOaepWrap(RSAPublicKey pub, byte[] plaintext) throws Exception {
    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    OAEPParameterSpec spec = new OAEPParameterSpec(
        "SHA-256",
        "MGF1",
        MGF1ParameterSpec.SHA256,          // or new MGF1ParameterSpec("SHA-256")
        PSource.PSpecified.DEFAULT
    );
    cipher.init(Cipher.ENCRYPT_MODE, pub, spec);
    return cipher.doFinal(plaintext);
  }


  private static String base64UrlEncode(byte[] b) {
    return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(b);
  }
  private static byte[] base64UrlDecode(String s) {
    return java.util.Base64.getUrlDecoder().decode(s);
  }

  // ---------- Peer merge APIs ----------

  @Override
  public void mergePeerPublicAdd(Map<String, Object> user) {
    if (user == null) { log.warn("[public/peer/add] null user map"); return; }
    String userId = (String) user.get("user_id");
    if (userId == null || userId.isBlank()) { log.warn("[public/peer/add] missing user_id in {}", user); return; }

    String displayName = (String) user.getOrDefault("display_name", userId);
    String serverId    = (String) user.getOrDefault("server_id", "unknown");
    String role        = (String) user.getOrDefault("role", "member");
    String status      = (String) user.getOrDefault("status", "active");

    long joinedAtMs = 0L;
    Object j = user.get("joined_at");
    if (j instanceof Number n) joinedAtMs = n.longValue();

    try { groupMembers.upsertActive(PUBLIC_GROUP_ID, userId, role,  getWrappedKey(userId)); }
    catch (Exception e) { log.warn("[public/peer/add->db] upsertActive FAIL user={} err={}", userId, e.toString()); }

    var gm = new GroupMembers()
        .setGroupId(PUBLIC_GROUP_ID)
        .setUserId(userId)
        .setRole(role)
        .setStatus(status)
        .setWrappedKey(getWrappedKey(userId))
        .setJoinedAt(joinedAtMs > 0 ? new java.sql.Timestamp(joinedAtMs) : null)
        .setUpdatedAt(new java.sql.Timestamp(System.currentTimeMillis()));
    publicChannelMembers.put(userId, gm);
    publicServerIds.put(userId, serverId);

    log.info("[public/peer/add] merged user={} role={} status={} fromServer={} nowCache.members={}",
        userId, role, status, serverId, publicChannelMembers.size());
    if (log.isTraceEnabled()) log.trace("[public/peer/add] userMap={}", safeJson(user));
  }

  @Override
  public void mergePeerPublicRemove(String userId) {
    if (userId == null || userId.isBlank()) { log.warn("[public/peer/remove] blank userId"); return; }
    try { groupMembers.markLeft(PUBLIC_GROUP_ID, userId); }
    catch (Exception e) { log.warn("[public/peer/remove->db] markLeft FAIL user={} err={}", userId, e.toString()); }

    publicChannelMembers.computeIfPresent(userId, (k, gm) -> {
      gm.setStatus("left");
      gm.setUpdatedAt(new java.sql.Timestamp(System.currentTimeMillis()));
      return gm;
    });
    publicServerIds.remove(userId);
    log.info("[public/peer/remove] user={} removed (left) nowCache.members={}", userId, publicChannelMembers.size());
  }

  @Override
  public void replacePublicSnapshot(long version, List<Map<String, Object>> incomingList) {
    long current = publicChannelVersion.get();
    log.info("[public/snapshot] replace requested incomingVer={} currentVer={} incomingSize={}",
        version, current, (incomingList == null ? 0 : incomingList.size()));

    if (version <= current) {
      log.info("[public/snapshot] ignore older version={} (current={})", version, current);
      return;
    }

    var newMembers = new ConcurrentHashMap<String, GroupMembers>();
    var newSrv     = new ConcurrentHashMap<String, String>();

    if (incomingList != null) {
      for (Map<String, Object> m : incomingList) {
        final boolean isWrap = m.containsKey("member_id");
        final boolean isLegacy = m.containsKey("user_id");

        String userId;
        String wrappedKey = null;
        String serverId;
        String role;
        String status;
        Long   joinedAtMs = null;

        if (isWrap) {
          userId     = (String) m.get("member_id");
          wrappedKey = (String) m.getOrDefault("wrapped_key", null);

          String cachedSrv  = publicServerIds.get(userId);
          GroupMembers cached = publicChannelMembers.get(userId);

          serverId    = (cachedSrv  != null ? cachedSrv  : "unknown");
          role        = (cached != null && cached.getRole() != null) ? cached.getRole() : "member";
          status      = (cached != null && cached.getStatus() != null) ? cached.getStatus() : "active";
          joinedAtMs  = (cached != null && cached.getJoinedAt() != null) ? cached.getJoinedAt().getTime() : null;

        } else if (isLegacy) {
          userId = (String) m.get("user_id");

          wrappedKey = (String) m.getOrDefault("wrapped_key", getWrappedKey(userId));
          serverId    = (String) m.getOrDefault("server_id", "unknown");
          role        = (String) m.getOrDefault("role", "member");
          status      = (String) m.getOrDefault("status", "active");

          Object j = m.get("joined_at");
          if (j instanceof Number n) joinedAtMs = n.longValue();

        } else {
          log.warn("[public/snapshot] skip entry (unknown format): {}", m);
          continue;
        }

        if (userId == null || userId.isBlank()) {
          log.warn("[public/snapshot] skip entry without userId: {}", m);
          continue;
        }

        var gm = new GroupMembers()
            .setGroupId(PUBLIC_GROUP_ID)
            .setUserId(userId)
            .setRole(role)
            .setWrappedKey(wrappedKey)
            .setStatus(status)
            .setJoinedAt(joinedAtMs != null && joinedAtMs > 0 ? new java.sql.Timestamp(joinedAtMs) : null)
            .setUpdatedAt(new java.sql.Timestamp(System.currentTimeMillis()));

        newMembers.put(userId, gm);
        newSrv.put(userId, serverId);
      }
    }

    publicChannelMembers.clear(); publicChannelMembers.putAll(newMembers);
    publicServerIds.clear();      publicServerIds.putAll(newSrv);
    publicChannelVersion.set(version);

    log.info("[public/snapshot] replaced cache with version={} size={} (servers={})",
        version, publicChannelMembers.size(), publicServerIds.size());
    if (log.isTraceEnabled()) log.trace("[public/snapshot] entries={}", safeJson(incomingList));
  }


  /** New: merge 'PUBLIC_CHANNEL_ADD' with payload.add = [userId...] and optimistic 'if_version'. */
  public void mergePeerPublicAddList(java.util.List<String> userIds, long ifVersion) {
    if (userIds == null || userIds.isEmpty()) {
      log.warn("[public/peer/add-list] empty add list");
      return;
    }
    long current = publicChannelVersion.get();
    if (ifVersion != current) {
      log.warn("[public/peer/add-list] drop due to version mismatch: if_version={} current={}", ifVersion, current);
      return;
    }

    long nowMs = System.currentTimeMillis();
    int merged = 0;
    for (String userId : userIds) {
      if (userId == null || userId.isBlank()) continue;
      try { groupMembers.upsertActive(PUBLIC_GROUP_ID, userId, "member",  getWrappedKey(userId)); }
      catch (Exception e) { log.warn("[public/peer/add-list->db] upsertActive FAIL user={} err={}", userId, e.toString()); }

      var gm = new GroupMembers()
          .setGroupId(PUBLIC_GROUP_ID)
          .setUserId(userId)
          .setRole("member")
          .setWrappedKey(getWrappedKey(userId))
          .setStatus("active")
          .setJoinedAt(new java.sql.Timestamp(nowMs))
          .setUpdatedAt(new java.sql.Timestamp(nowMs));
      publicChannelMembers.put(userId, gm);
      publicServerIds.put(userId, "unknown");     // Source server unknown
      merged++;
    }
    log.info("[public/peer/add-list] merged={} if_version={} cache.members={}", merged, ifVersion, publicChannelMembers.size());
  }

  /**
   * Minimal public-channel broadcast with plaintext.
   * - Builds one common payload that matches protocol MSG_PUBLIC_CHANNEL.
   * - Local clients: send MSG_PUBLIC_CHANNEL (same payload).
   * - Remote servers: send SERVER_PUBLIC_DELIVER carrying the SAME payload (+ user_id for routing only).
   *   The destination server should deliver to the client as MSG_PUBLIC_CHANNEL with the SAME payload.
   */
  public void sendPublicMessage(String senderUserId, JsonNode root) {
    long t0 = System.nanoTime();
    final long ts = System.currentTimeMillis();
    JsonNode payload = root.path("payload");
    // Common payload required by protocol for MSG_PUBLIC_CHANNEL
    final java.util.Map<String, Object> commonPayload = new java.util.LinkedHashMap<>();
    commonPayload.put("channel", PUBLIC_CHANNEL_ID);  // protocol: field name 'channel'
    commonPayload.put("epoch",   FIXED_EPOCH);        // fixed epoch as requested
    commonPayload.put("sender",  senderUserId);       // keep sender for UI/attribution if protocol requires
    commonPayload.put("ciphertext", payload.path("ciphertext").asText(null));
    commonPayload.put("sender_pub", payload.path("sender_pub").asText(null));
    commonPayload.put("content_sig", payload.path("content_sig").asText(null));


    // Local sessions snapshot
    var localSessions = sessionRegistry.snapshot(); // userId -> WebSocketSession

    // Bucket remote users by serverId (exclude locals)
    java.util.Map<String, java.util.List<String>> remoteBuckets = new java.util.HashMap<>();
    java.util.Set<String> localUsers = new java.util.HashSet<>(localSessions.keySet());
    userLoginDirectory.listAll().forEach(u -> {
      String uid = u.getUserId();
      if (uid == null || localUsers.contains(uid)) return;
      String sid = u.getServerId();
      if (sid == null || sid.equals(myServerId)) return;
      remoteBuckets.computeIfAbsent(sid, k -> new java.util.ArrayList<>()).add(uid);
    });

    int sentLocal = 0, skipLocal = 0, failLocal = 0;
    int sentS2S = 0, failS2S = 0;

    // Deliver to local clients: MSG_PUBLIC_CHANNEL with common payload
    for (var e : localSessions.entrySet()) {
      String uid = e.getKey();
      WebSocketSession sess = e.getValue();
      if (sess == null || !sess.isOpen()) { skipLocal++; continue; }

      try {
        var msg = new ProtocolMessage();
        msg.setType("MSG_PUBLIC_CHANNEL");  // MUST match protocol
        msg.setFrom(myServerId);
        msg.setTo(uid);
        msg.setTs(ts);
        msg.setPayload(commonPayload);      // identical content structure
        sendSigned(sess, msg);
        sentLocal++;
      } catch (Exception ex) {
        failLocal++;
        log.warn("[public/send->local {}] failed: {}", uid, ex.toString());
      }
    }

    // Cross-server forwarding:
    // Use SERVER_PUBLIC_DELIVER (transport) and keep the SAME payload fields;
    // add 'user_id' ONLY for routing on the destination server; it is NOT part of MSG_PUBLIC_CHANNEL payload.
    for (var entry : remoteBuckets.entrySet()) {
      String destServer = entry.getKey();
      var peer = peerDir.get(destServer);
      if (peer == null) { log.warn("[public/forward] no peer for serverId={}", destServer); continue; }
      String url = String.format("ws://%s:%d/ws", peer.getHost(), peer.getPort());

      for (String uid : entry.getValue()) {
        try {
          var s2s = new ProtocolMessage();
          s2s.setType("SERVER_PUBLIC_DELIVER"); // transport frame between servers
          s2s.setFrom(myServerId);
          s2s.setTo(destServer);
          s2s.setTs(ts);

          // Build payload: user_id for routing + SAME content fields
          var out = new java.util.LinkedHashMap<String,Object>();
          out.put("user_id", uid);                  // routing only (not part of MSG_PUBLIC_CHANNEL content)
          out.putAll(commonPayload);                // channel, epoch, content, sender
          s2s.setPayload(out);

          String json = UnifiedJsonUtil.toJson(s2s);
          serverLinkClient.sendJson(peer.getServerId(), url, json);
          sentS2S++;
        } catch (Exception ex) {
          failS2S++;
          log.warn("[public/forward->{} user={}] failed: {}", destServer, uid, ex.toString());
        }
      }
    }

    long ms = (System.nanoTime() - t0) / 1_000_000;
    log.info("[public/send/plain] epoch={} local(sent/skip/fail)={}/{}/{} s2s(sent/fail)={}/{} elapsedMs={}",
        FIXED_EPOCH, sentLocal, skipLocal, failLocal, sentS2S, failS2S, ms);
  }

  /**
   * Handle SERVER_PUBLIC_DELIVER (S2S) and broadcast to ALL local clients
   * as MSG_PUBLIC_CHANNEL with the SAME content payload shape.
   * - Incoming payload may contain: user_id (routing-only), channel, epoch, content, sender
   * - Client-bound payload: channel, epoch, content, sender (user_id is dropped)
   */
  public void handleServerPublicDeliverBroadcast(JsonNode root) {
    long t0 = System.nanoTime();
    JsonNode payload = root.path("payload");
    if (payload.isMissingNode()) {
      log.warn("[public/s2s] missing payload"); return;
    }

    final String channel = textOrNull(payload, "channel");
    final Integer epoch  = intOrNull(payload, "epoch");
    final String content = textOrNull(payload, "ciphertext");
    final String sender  = textOrNull(payload, "sender"); // include only if present

    if (channel == null || epoch == null || content == null) {
      log.warn("[public/s2s] bad payload (channel/epoch/content required)");
      return;
    }

    // Build client payload (identical content structure; no user_id)
    final java.util.Map<String, Object> clientPayload = new java.util.LinkedHashMap<>();
    clientPayload.put("channel", channel);
    clientPayload.put("epoch",   epoch);
    clientPayload.put("content", content);
    if (sender != null) clientPayload.put("sender", sender);

    long ts = root.path("ts").asLong(System.currentTimeMillis());

    var snapshot = sessionRegistry.snapshot(); // userId -> WebSocketSession
    int sent = 0, skipped = 0, failures = 0;

    for (var e : snapshot.entrySet()) {
      String uid = e.getKey();
      WebSocketSession sess = e.getValue();
      if (sess == null || !sess.isOpen()) { skipped++; continue; }

      try {
        ProtocolMessage out = new ProtocolMessage();
        out.setType("MSG_PUBLIC_CHANNEL");   // convert transport type -> client type
        out.setFrom(myServerId);
        out.setTo(uid);
        out.setTs(ts);
        out.setPayload(clientPayload);
        sendSigned(sess, out);
        sent++;
      } catch (Exception ex) {
        failures++;
        log.warn("[public/s2s->client {}] deliver failed: {}", uid, ex.toString());
      }
    }

    long ms = (System.nanoTime() - t0) / 1_000_000;
    log.info("[public/s2s] broadcast MSG_PUBLIC_CHANNEL done sent={} skipped={} failures={} elapsedMs={}",
        sent, skipped, failures, ms);
  }


  /** Build the shares array using your existing getWrappedKey(userId). */
  private List<Map<String, Object>> buildAllShares() {
    List<Map<String, Object>> shares = new java.util.ArrayList<>();
    List<GroupMembers> groupMembersList = groupMembers.queryAllActive();
    for (GroupMembers gm : groupMembersList) {
      String uid = gm.getUserId();
      if (uid == null || uid.isBlank()) continue;
      String wrapped = gm.getWrappedKey(); // your method
      if (wrapped == null || wrapped.isBlank()) continue;
      shares.add(Map.of(
          "member", uid,
          "wrapped_public_channel_key", wrapped
      ));
    }
    return shares;
  }

  /** 1) Broadcast all wrapped keys to ALL local clients; 2) fan out to remote servers. */
  private void broadcastPublicChannelKey() {
    long t0 = System.nanoTime();
    long ts = System.currentTimeMillis();

    // Build shares once
    List<Map<String, Object>> allShares = buildAllShares();

    // ---- (A) Client broadcast: Public_channel_key_to_client ----
    var clientPayload = new java.util.LinkedHashMap<String, Object>();
    clientPayload.put("channel_id", PUBLIC_CHANNEL_ID);
    clientPayload.put("epoch", FIXED_EPOCH);
    clientPayload.put("shares", allShares);

    var local = sessionRegistry.snapshot(); // userId -> session
    int sent=0, skip=0, fail=0;
    for (var e : local.entrySet()) {
      var sess = e.getValue();
      if (sess == null || !sess.isOpen()) { skip++; continue; }
      try {
        var msg = new ProtocolMessage();
        msg.setType("PUBLIC_CHANNEL_KEY_TO_CLIENT");
        msg.setFrom(myServerId);
        msg.setTo(e.getKey());
        msg.setTs(ts);
        msg.setPayload(clientPayload);
        sendSigned(sess, msg);
        sent++;
      } catch (Exception ex) {
        fail++;
        log.warn("[Public_channel_key_to_client->{}] fail: {}", e.getKey(), ex.toString());
      }
    }
    log.info("[key->clients] ch={} epoch={} shares={} sent={} skip={} fail={}",
        PUBLIC_CHANNEL_ID, FIXED_EPOCH, allShares.size(), sent, skip, fail);

    // ---- (B) S2S fanout: PUBLIC_CHANNEL_KEY_SHARE (bucket by dest server) ----
    sendKeySharesToRemoteServers(allShares, ts);

    log.debug("[broadcastPublicChannelKey] elapsedMs={}", (System.nanoTime()-t0)/1_000_000);
  }

  /** Bucket shares by home server and send PUBLIC_CHANNEL_KEY_SHARE per server. */
  private void sendKeySharesToRemoteServers(List<Map<String,Object>> allShares, long ts) {
    Map<String, List<Map<String, Object>>> buckets = new java.util.HashMap<>();
    // Build serverId -> shares[]
    for (var item : allShares) {
      String uid = (String) item.get("member");
      String sid = findHomeServer(uid);
      if (sid == null || sid.equals(myServerId)) continue;
      buckets.computeIfAbsent(sid, k -> new java.util.ArrayList<>()).add(item);
    }

    for (var entry : buckets.entrySet()) {
      String destServer = entry.getKey();
      var peer = peerDir.get(destServer);
      if (peer == null) { log.warn("[s2s/keyshare] no peer for {}", destServer); continue; }

      var payload = new java.util.LinkedHashMap<String, Object>();
      payload.put("channel_id", PUBLIC_CHANNEL_ID);
      payload.put("epoch", FIXED_EPOCH);
      payload.put("shares", entry.getValue());
      payload.put("creator_pub", serverSigningPublicKeyBase64Url());
      payload.put("content_sig", signContentSig(payload)); // PSS-SHA256 over canonicalized payload core

      var s2s = new ProtocolMessage();
      s2s.setType("PUBLIC_CHANNEL_KEY_SHARE");
      s2s.setFrom(myServerId);
      s2s.setTo(destServer);
      s2s.setTs(ts);
      s2s.setPayload(payload);

      try {
        String url = String.format("ws://%s:%d/ws", peer.getHost(), peer.getPort());
        String json = UnifiedJsonUtil.toJson(s2s);
        serverLinkClient.sendJson(peer.getServerId(), url, json);
        log.info("[s2s/keyshare] ->{} shares={}", destServer, entry.getValue().size());
      } catch (Exception ex) {
        log.warn("[s2s/keyshare] send FAIL to {}: {}", destServer, ex.toString());
      }
    }
  }

  /** Handle incoming PUBLIC_CHANNEL_KEY_SHARE: update local, then broadcast Public_channel_key_to_client. */
  private void handlePublicChannelKeyShare(JsonNode root) {
    JsonNode payload = root.path("payload");
    String channelId = payload.path("channel_id").asText(null);
    int epoch = payload.path("epoch").asInt(0);
    if (channelId == null || epoch == 0) { log.warn("[s2s/keyshare] bad channel/epoch"); return; }

    // (optional) verify 'content_sig' with 'creator_pub'
    String creatorPub = payload.path("creator_pub").asText(null);
    String contentSig = payload.path("content_sig").asText(null);
    if (creatorPub != null && contentSig != null //&& !verifyContentSig(payload, creatorPub, contentSig)
    ) {
      log.warn("[s2s/keyshare] content_sig verify FAILED"); return;
    }

    // Persist/update local wrapped_keys and collect those for local users
    List<Map<String,Object>> localShares = new java.util.ArrayList<>();
    JsonNode shares = payload.path("shares");
    if (shares.isArray()) {
      for (JsonNode it : shares) {
        String uid = it.path("member").asText(null);
        String wrapped = it.path("wrapped_public_channel_key").asText(null);
        if (uid == null || wrapped == null) continue;
        if (isUserLocal(uid)) {
          localShares.add(Map.of("member", uid, "wrapped_public_channel_key", wrapped));
        }
      }
    }
    if (localShares.isEmpty()) return;

    // Broadcast to ALL local clients: Public_channel_key_to_client
    var clientPayload = new java.util.LinkedHashMap<String, Object>();
    clientPayload.put("channel_id", channelId);
    clientPayload.put("epoch", epoch);
    clientPayload.put("shares", localShares);

    var sessions = sessionRegistry.snapshot();
    long ts = root.path("ts").asLong(System.currentTimeMillis());
    int sent=0, skip=0, fail=0;
    for (var e : sessions.entrySet()) {
      var sess = e.getValue();
      if (sess == null || !sess.isOpen()) { skip++; continue; }
      try {
        var msg = new ProtocolMessage();
        msg.setType("Public_channel_key_to_client");
        msg.setFrom(myServerId);
        msg.setTo(e.getKey());
        msg.setTs(ts);
        msg.setPayload(clientPayload);
        sendSigned(sess, msg);
        sent++;
      } catch (Exception ex) {
        fail++;
        log.warn("[Public_channel_key_to_client->{}] FAIL: {}", e.getKey(), ex.toString());
      }
    }
    log.info("[s2s/keyshare] broadcast to clients: localShares={} sent={} skip={} fail={}",
        localShares.size(), sent, skip, fail);
  }

  /**
   * Handle incoming PUBLIC_CHANNEL_KEY_SHARE from a remote server:
   * 1) Update/merge local key cache (DB + in-memory) with all incoming shares.
   * 2) Broadcast the same shares to ALL local clients as "Public_channel_key_to_client".
   *
   * Payload fields expected:
   * - channel_id: string
   * - epoch:      int
   * - shares:     array of { member: string, wrapped_public_channel_key: string }
   * - creator_pub, content_sig: optional (verify if you implemented verifyContentSig)
   */
  public void handleRemoteKeyShareAndBroadcast(JsonNode root) {
    long t0 = System.nanoTime();
    JsonNode payload = root.path("payload");
    if (payload.isMissingNode()) {
      log.warn("[s2s/keyshare] missing payload");
      return;
    }

    final String channelId = payload.path("channel_id").asText(null);
    final int epoch        = payload.path("epoch").asInt(0);
    final JsonNode shares  = payload.path("shares");

    if (channelId == null || epoch == 0 || !shares.isArray()) {
      log.warn("[s2s/keyshare] bad payload: channel_id/epoch/shares");
      return;
    }

    // (Optional) verify content_sig if present
    final String creatorPub = payload.path("creator_pub").asText(null);
    final String contentSig = payload.path("content_sig").asText(null);
    if (creatorPub != null && contentSig != null) {
      try {
        if (!verifyContentSig(payload, creatorPub, contentSig)) {
          log.warn("[s2s/keyshare] content_sig verify FAILED");
          return;
        }
      } catch (Exception ex) {
        log.warn("[s2s/keyshare] content_sig verify ERROR: {}", ex.toString());
        return;
      }
    }

    // 1) Merge into local cache/storage
    int merged = 0, skipped = 0;
    for (JsonNode it : shares) {
      final String uid     = it.path("member").asText(null);
      final String wrapped = it.path("wrapped_public_channel_key").asText(null);
      if (uid == null || uid.isBlank() || wrapped == null || wrapped.isBlank()) {
        skipped++; continue;
      }

      // Persist to DB (idempotent upsert); fallback to in-memory cache on failure
      try {
        groupMembers.upsertActive(PUBLIC_GROUP_ID, uid, "member", wrapped);
      } catch (Exception e) {
        log.warn("[s2s/keyshare->db] upsertActive FAIL user={} err={}", uid, e.toString());
      }

      // Update in-memory snapshot; create or replace
      publicChannelMembers.compute(uid, (k, gm) -> {
        if (gm == null) gm = new GroupMembers().setGroupId(PUBLIC_GROUP_ID).setUserId(uid);
        gm.setRole(gm.getRole() != null ? gm.getRole() : "member");
        gm.setStatus("active");
        gm.setWrappedKey(wrapped);
        gm.setUpdatedAt(new java.sql.Timestamp(System.currentTimeMillis()));
        return gm;
      });

      merged++;
    }
    log.info("[s2s/keyshare] merged={} skipped={} channel={} epoch={}", merged, skipped, channelId, epoch);

    // 2) Broadcast to ALL local clients with identical share list
    final long ts = root.path("ts").asLong(System.currentTimeMillis());
    final java.util.Map<String, Object> clientPayload = new java.util.LinkedHashMap<>();
    clientPayload.put("channel_id", channelId);
    clientPayload.put("epoch",      epoch);
    // Convert shares JsonNode -> Java List for stable serialization
    final java.util.List<?> sharesList = UnifiedJsonUtil.getDefaultMapper().convertValue(shares, java.util.List.class);
    clientPayload.put("shares", sharesList);

    var snapshot = sessionRegistry.snapshot(); // userId -> WebSocketSession
    int sent = 0, fail = 0, skip = 0;

    for (var e : snapshot.entrySet()) {
      WebSocketSession sess = e.getValue();
      if (sess == null || !sess.isOpen()) { skip++; continue; }
      try {
        ProtocolMessage msg = new ProtocolMessage();
        msg.setType("Public_channel_key_to_client");
        msg.setFrom(myServerId);
        msg.setTo(e.getKey());
        msg.setTs(ts);
        msg.setPayload(clientPayload);
        sendSigned(sess, msg);
        sent++;
      } catch (Exception ex) {
        fail++;
        log.warn("[Public_channel_key_to_client->{}] FAIL: {}", e.getKey(), ex.toString());
      }
    }

    long ms = (System.nanoTime() - t0) / 1_000_000;
    log.info("[s2s/keyshare] broadcast to clients done sent={} skip={} fail={} elapsedMs={}", sent, skip, fail, ms);
  }


  // ---------- tiny helpers ----------
  private static String textOrNull(JsonNode n, String field) {
    JsonNode v = n.get(field);
    return (v == null || v.isNull()) ? null : v.asText(null);
  }
  private static Integer intOrNull(JsonNode n, String field) {
    JsonNode v = n.get(field);
    return (v == null || v.isNull() || !v.canConvertToInt()) ? null : v.asInt();
  }

  // ---------- Helpers ----------

  private static int safeSize(LocalSessionRegistry reg) {
    try { return reg == null ? -1 : reg.snapshot().size(); } catch (Throwable t) { return -2; }
  }

  private static String safeSessionId(WebSocketSession s) {
    if (s == null) return "null";
    try { return s.getId(); } catch (Throwable t) { return "?"; }
  }

  private String safeJson(Object o) {
    try { return UnifiedJsonUtil.toPrettyJson(o); } catch (Exception e) { return String.valueOf(o); }
  }

  public String getWrappedKey(String userId) {
    RSAPublicKey encPub = null;
    String wrapped = null;
    try {
      encPub = RsaPublicKeyParser.parse(userLoginDirectory.findPubkeyByUserId(userId));
      wrapped = gkm.getOrCreateWrappedKey(userId, encPub);
    } catch (Exception e) {
      return "";
    }
    return wrapped;
  }

  /** Random 12-byte nonce for AES-GCM. */
  private static byte[] randomNonce(int n) {
    byte[] iv = new byte[n];
    new java.security.SecureRandom().nextBytes(iv);
    return iv;
  }

  /** AES-256-GCM encrypt; returns ciphertext||tag (no AAD for minimal payload). */
  private static byte[] aesGcmEncrypt(byte[] key32, byte[] nonce12, byte[] plaintext) throws Exception {
    javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
    javax.crypto.spec.GCMParameterSpec gcm = new javax.crypto.spec.GCMParameterSpec(128, nonce12);
    javax.crypto.spec.SecretKeySpec key = new javax.crypto.spec.SecretKeySpec(key32, "AES");
    cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key, gcm);
    return cipher.doFinal(plaintext);
  }

  /** Base64URL without padding. */
  private static String b64u(byte[] b) {
    return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(b);
  }

  private String findHomeServer(String userId) {
    return userLoginDirectory.listAll().stream()
        .filter(u -> userId.equals(u.getUserId()))
        .map(u -> u.getServerId()).findFirst().orElse(null);
  }


  private boolean isUserLocal(String userId) {
    if (sessionRegistry.get(userId) != null) return true;
    return userLoginDirectory.listAll().stream()
        .anyMatch(u -> userId.equals(u.getUserId()) && myServerId.equals(u.getServerId()));
  }

  // ======= Drop-in implementations inside PublicChannelServiceImpl =======

  /** Return server's signing public key (SPKI DER) as Base64URL (no padding). */
  private String serverSigningPublicKeyBase64Url() {
    try {
      java.security.interfaces.RSAPublicKey pub;
      if (myPriv instanceof java.security.interfaces.RSAPrivateCrtKey crt) {
        var spec = new java.security.spec.RSAPublicKeySpec(crt.getModulus(), crt.getPublicExponent());
        pub = (java.security.interfaces.RSAPublicKey) java.security.KeyFactory.getInstance("RSA").generatePublic(spec);
      } else {
        // Fallback: assume e=65537 if not CRT; adjust if your key differs.
        var spec = new java.security.spec.RSAPublicKeySpec(((java.security.interfaces.RSAPrivateKey) myPriv).getModulus(),
            java.math.BigInteger.valueOf(65537));
        pub = (java.security.interfaces.RSAPublicKey) java.security.KeyFactory.getInstance("RSA").generatePublic(spec);
      }
      byte[] spki = pub.getEncoded(); // X.509 SubjectPublicKeyInfo (DER)
      return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(spki);
    } catch (Exception e) {
      log.warn("[serverSigningPublicKeyBase64Url] fail: {}", e.toString());
      return "";
    }
  }

  /** Sign content for PUBLIC_CHANNEL_KEY_SHARE.payload -> content_sig (RSASSA-PSS/SHA-256). */
  private String signContentSig(Map<String, Object> payload) {
    try {
      // Build a deterministic minimal-core object in fixed field order:
      var core = new java.util.LinkedHashMap<String, Object>();
      core.put("channel_id", payload.get("channel_id"));
      core.put("epoch",      payload.get("epoch"));
      core.put("shares",     payload.get("shares"));     // expect List<Map<String,Object>>
      core.put("creator_pub",payload.get("creator_pub"));

      byte[] bytes = UnifiedJsonUtil.getDefaultMapper().writeValueAsBytes(core);         // stable JSON via LinkedHashMap
      java.security.Signature sig = java.security.Signature.getInstance("RSASSA-PSS");
      sig.setParameter(new java.security.spec.PSSParameterSpec(
          "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
      sig.initSign(myPriv);
      sig.update(bytes);
      byte[] out = sig.sign();
      return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(out);
    } catch (Exception e) {
      log.warn("[signContentSig] fail: {}", e.toString());
      return "";
    }
  }

  /** Verify content_sig for PUBLIC_CHANNEL_KEY_SHARE.payload using creator_pub (SPKI, b64url). */
  private boolean verifyContentSig(JsonNode payload, String creatorPubB64u, String sigB64u) {
    try {
      // Rebuild the same minimal-core with fixed order (must match signContentSig):
      var core = new java.util.LinkedHashMap<String, Object>();
      core.put("channel_id", payload.path("channel_id").asText(null));
      core.put("epoch",      payload.path("epoch").asInt());
      // Convert shares JSON to a plain Java List for ObjectMapper to serialize deterministically:
      java.util.List<?> shares = UnifiedJsonUtil.getDefaultMapper().convertValue(payload.path("shares"), java.util.List.class);
      core.put("shares", shares);
      core.put("creator_pub", payload.path("creator_pub").asText(null));

      byte[] bytes = UnifiedJsonUtil.getDefaultMapper().writeValueAsBytes(core);

      // Import creator_pub (SPKI DER) and verify RSASSA-PSS/SHA-256
      byte[] spki = java.util.Base64.getUrlDecoder().decode(creatorPubB64u);
      var pk = (java.security.PublicKey) java.security.KeyFactory.getInstance("RSA")
          .generatePublic(new java.security.spec.X509EncodedKeySpec(spki));

      java.security.Signature sig = java.security.Signature.getInstance("RSASSA-PSS");
      sig.setParameter(new java.security.spec.PSSParameterSpec(
          "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
      sig.initVerify(pk);
      sig.update(bytes);
      byte[] sigBytes = java.util.Base64.getUrlDecoder().decode(sigB64u);
      return sig.verify(sigBytes);
    } catch (Exception e) {
      log.warn("[verifyContentSig] fail: {}", e.toString());
      return false;
    }
  }


}
