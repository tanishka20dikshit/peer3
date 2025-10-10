package edu.adelaide.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import edu.adelaide.cache.PeerDirectory;
import edu.adelaide.util.AdvertisedEndpointUtil;
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

/** Sends SERVER_ANNOUNCE to all remote servers (fire-and-forget). */
public class PeerAnnounceClient {

  private static final Logger log = LoggerFactory.getLogger(PeerAnnounceClient.class);
  private static final String DEFAULT_SCHEME = "ws";
  private static final String DEFAULT_PATH   = "/peer/announce"; // raw WS handler path

  private final java.security.interfaces.RSAPrivateKey myPrivateKey;
  private final long timeoutMs;

  public PeerAnnounceClient(java.security.interfaces.RSAPrivateKey myPrivateKey, long timeoutMs) {
    this.myPrivateKey = myPrivateKey;
    this.timeoutMs = timeoutMs;
  }

  /** Best-effort broadcast; returns {success, fail}. */
  public int[] announceToAll(String myAssignedId, String myPubkeyB64u, List<PeerDirectory.Peer> peers) {
    var ep = AdvertisedEndpointUtil.resolve(null, null); // my advertised host/port
    int ok = 0, fail = 0;

    for (var p : peers) {
      final String url = DEFAULT_SCHEME + "://" + p.getHost() + ":" + p.getPort() + DEFAULT_PATH;
      try {
        // ---- payload ----
        Map<String,Object> payload = new LinkedHashMap<>();
        payload.put("host",   ep.host());
        payload.put("port",   ep.port());
        payload.put("pubkey", myPubkeyB64u);

        // ---- envelope (NO "sig" yet) ----
        Map<String,Object> env = new LinkedHashMap<>();
        env.put("type",    "SERVER_ANNOUNCE");
        env.put("from",    myAssignedId);
        env.put("to",      p.getServerId());
        env.put("ts",      System.currentTimeMillis());
        env.put("payload", payload);

        // ---- canonicalize & sign (PSS over JSON without "sig") ----
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
          throw new RuntimeException("Failed to sign announce", e);
        }
        ObjectNode objectNode = (ObjectNode) unsigned;
        objectNode.put("sig", sigB64u);
        String json = UnifiedJsonUtil.toJson(unsigned);

        // ---- logs ----
        log.info("[WS OUT][SERVER_ANNOUNCE] to={} url={}", p.getServerId(), url);
        log.debug("[ANNOUNCE PEER] id={} host={} port={} pinnedKey?={}",
            p.getServerId(), p.getHost(), p.getPort(), p.getPubkey() != null);
        log.debug("[ANNOUNCE JSON len={}] {}", json.length(), json);

        // ---- fire-and-forget send (do NOT wait for a reply) ----
        sendFireAndForget(url, json);
        ok++;
      } catch (Exception e) {
        log.warn("[ANNOUNCE] {}:{} failed: {}", p.getHost(), p.getPort(), e.toString());
        fail++;
      }
    }

    log.info("[ANNOUNCE] done. success={}, fail={}", ok, fail);
    return new int[]{ok, fail};
  }

  /** Send one text frame and complete when the frame is sent (no receive/ACK). */
  private void sendFireAndForget(String wsUrl, String text) {
    ReactorNettyWebSocketClient ws = new ReactorNettyWebSocketClient();
    ws.execute(URI.create(wsUrl), session ->
        session.send(Mono.just(session.textMessage(text))).then()
    ).block(Duration.ofMillis(timeoutMs));
  }
}
