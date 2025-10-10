package edu.adelaide.client;

import edu.adelaide.cache.PeerDirectory;
import edu.adelaide.util.UnifiedCryptoUtil;
import edu.adelaide.util.UnifiedJsonUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.socket.client.ReactorNettyWebSocketClient;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPrivateKey;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Generic broadcaster for server→server messages over WebSocket.
 * - Builds {type,from,to,ts,payload,sig} envelopes
 * - Sends to ws://<peer.host>:<peer.port>/ws (path hardcoded here; adjust if needed)
 */
public class ServerBroadcaster {
  private static final Logger log = LoggerFactory.getLogger(ServerBroadcaster.class);
  private static final String DEFAULT_SCHEME = "ws";
  private static final String DEFAULT_PATH   = "/ws";

  private final RSAPrivateKey myPrivateKey;
  private final long timeoutMs;

  public ServerBroadcaster(RSAPrivateKey myPrivateKey, long timeoutMs) {
    this.myPrivateKey = myPrivateKey;
    this.timeoutMs = timeoutMs;
  }

  /** Broadcast arbitrary type to ALL peers (best-effort). Returns {ok, fail}. */
  public int[] broadcast(String myAssignedId, List<PeerDirectory.Peer> peers,
                         String type, Map<String, Object> payload) {
    int ok = 0, fail = 0;
    for (var p : peers) {
      String url = DEFAULT_SCHEME + "://" + p.getHost() + ":" + p.getPort() + DEFAULT_PATH;
      try {
        Map<String, Object> env = buildSigned(myAssignedId, p.getServerId(), type, payload);
        String json = UnifiedJsonUtil.toJson(env);
        log.info("[WS OUT][{}][to={}][url={}][len={}]", type, p.getServerId(), url, json.length());
        String reply = sendOne(url, json);
        log.debug("[WS IN ][{}-ack][url={}][len={}]", type, url, reply != null ? reply.length() : -1);
        ok++;
      } catch (Exception e) {
        log.warn("[BROADCAST:{}] fail to {}:{} -> {}", type, p.getHost(), p.getPort(), e.toString());
        fail++;
      }
    }
    log.info("[BROADCAST:{}] done. success={}, fail={}", type, ok, fail);
    return new int[]{ok, fail};
  }

  /** Helper: broadcast SERVER_ANNOUNCE using the given payload. */
  public int[] announce(String myAssignedId, List<PeerDirectory.Peer> peers,
                        Map<String, Object> payload) {
    return broadcast(myAssignedId, peers, "SERVER_ANNOUNCE", payload);
  }

  /** Helper: broadcast USER_ADVERTISE using the given payload. */
  public int[] userAdvertise(String myAssignedId, List<PeerDirectory.Peer> peers,
                             Map<String, Object> payload) {
    return broadcast(myAssignedId, peers, "USER_ADVERTISE", payload);
  }

  // -------- internals --------

  private Map<String, Object> buildSigned(String from, String to, String type, Map<String, Object> payload) {
    Map<String, Object> env = new LinkedHashMap<>();
    env.put("type", type);
    env.put("from", from);
    env.put("to",   to == null ? "*" : to);
    env.put("ts",   System.currentTimeMillis());
    env.put("payload", payload == null ? Map.of() : payload);

    Map<String, Object> copy = new LinkedHashMap<>(env);
    String canonicalJson = UnifiedJsonUtil.toJson(copy);
    byte[] canonical = canonicalJson.getBytes(StandardCharsets.UTF_8);
    String sig;
    try {
      sig = UnifiedCryptoUtil.rsaSign(canonical, myPrivateKey);
    } catch (Exception e) {
      throw new RuntimeException("Failed to sign message", e);
    }
    env.put("sig", sig);
    return env;
  }

  private String sendOne(String wsUrl, String textToSend) {
    ReactorNettyWebSocketClient ws = new ReactorNettyWebSocketClient();
    AtomicReference<String> replyRef = new AtomicReference<>();
    ws.execute(URI.create(wsUrl), session -> {
      Mono<Void> send = session.send(Mono.just(session.textMessage(textToSend)));
      Mono<Void> recv = session.receive().next()
          .doOnNext(m -> replyRef.set(m.getPayloadAsText()))
          .then();
      return send.then(recv);
    }).block(Duration.ofMillis(timeoutMs));
    return replyRef.get(); // may be null
  }
}
