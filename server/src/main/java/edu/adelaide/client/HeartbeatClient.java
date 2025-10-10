package edu.adelaide.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import edu.adelaide.cache.PeerDirectory;
import edu.adelaide.util.UnifiedCryptoUtil;
import edu.adelaide.util.UnifiedJsonUtil;
import org.slf4j.Logger; import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.socket.client.ReactorNettyWebSocketClient;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class HeartbeatClient {
  private static final Logger log = LoggerFactory.getLogger(HeartbeatClient.class);
  private static final String DEFAULT_SCHEME = "ws";
  private static final String DEFAULT_PATH   = "/peer/heartbeat";

  private final java.security.interfaces.RSAPrivateKey myPrivateKey;
  private final long timeoutMs;
  private final PeerDirectory peerDir;
  private final long ttlMs;

  public HeartbeatClient(java.security.interfaces.RSAPrivateKey myPrivateKey,
                         long timeoutMs,
                         PeerDirectory peerDir,
                         long ttlMs) {
    this.myPrivateKey = myPrivateKey;
    this.timeoutMs = timeoutMs;
    this.peerDir = peerDir;
    this.ttlMs = ttlMs;
  }

  /** Best-effort broadcast; returns {success, fail}. */
  public int[] sendToAll(String myAssignedId, List<PeerDirectory.Peer> peers, Map<String,Object> payload) {
    int ok = 0, fail = 0;

    for (var p : peers) {
      final String url = DEFAULT_SCHEME + "://" + p.getHost() + ":" + p.getPort() + DEFAULT_PATH;
      try {
        // ---- envelope ----
        Map<String,Object> env = new LinkedHashMap<>();
        env.put("type", "SERVER_HEARTBEAT");
        env.put("from", myAssignedId);
        env.put("to",   p.getServerId());
        env.put("ts",   System.currentTimeMillis());
        env.put("payload", (payload == null) ? Map.of() : payload);

        // ---- canonical sign (without "sig") ----
        JsonNode unsigned = UnifiedJsonUtil.getDefaultMapper().valueToTree(env);
        if (unsigned.has("sig")) {
          ObjectNode objectNode = (ObjectNode) unsigned;
          objectNode.remove("sig");
        }
        String canonicalJson = UnifiedJsonUtil.createCanonicalJson(unsigned);
        byte[] canonical = canonicalJson.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        String sigB64u;
        try {
          sigB64u = UnifiedCryptoUtil.rsaSign(canonical, myPrivateKey);
        } catch (Exception e) {
          throw new RuntimeException("Failed to sign heartbeat", e);
        }
        ObjectNode objectNode = (ObjectNode) unsigned;
        objectNode.put("sig", sigB64u);
        String json = UnifiedJsonUtil.toJson(unsigned);

        // ---- send (fire-and-forget) ----
        sendFireAndForget(url, json);

        // Successful sending is considered as "successful communication with the other end", check lastSeen
        peerDir.markSeenNow(p.getServerId());
        ok++;
      } catch (Exception e) {
        fail++;
        long last = peerDir.lastSeenAt(p.getServerId());
        long age  = (last == 0) ? -1 : (System.currentTimeMillis() - last);
        log.warn("[HEARTBEAT] {}:{} failed: {} (lastSeen={}ms ago)",
            p.getHost(), p.getPort(), e.toString(), (age < 0 ? "never" : String.valueOf(age)));
        // Remove on demand on failure
        boolean evicted = peerDir.evictIfStale(p.getServerId(), ttlMs);
        if (evicted) {
          log.info("[HEARTBEAT] evicted peer={} due to consecutive failures > {}ms", p.getServerId(), ttlMs);
        }
      }
    }

    log.info("[HEARTBEAT] done. success={}, fail={}", ok, fail);
    return new int[]{ok, fail};
  }

  private void sendFireAndForget(String wsUrl, String text) {
    ReactorNettyWebSocketClient ws = new ReactorNettyWebSocketClient();
    ws.execute(URI.create(wsUrl), session ->
        session.send(Mono.just(session.textMessage(text))).then()
    ).block(Duration.ofMillis(timeoutMs));
  }
}
