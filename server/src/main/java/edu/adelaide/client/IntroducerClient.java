package edu.adelaide.client;

import edu.adelaide.dto.ProtocolMessage;
import edu.adelaide.util.AdvertisedEndpointUtil;
import edu.adelaide.util.UnifiedCryptoUtil;
import edu.adelaide.util.UnifiedJsonUtil;
import org.slf4j.Logger; import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.socket.client.ReactorNettyWebSocketClient;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.security.interfaces.RSAPrivateKey;

public class IntroducerClient {
  private static final Logger log = LoggerFactory.getLogger(IntroducerClient.class);

  private final RSAPrivateKey myPrivateKey;
  private final long timeoutMs;

  public IntroducerClient(RSAPrivateKey myPrivateKey, long timeoutMs) {
    this.myPrivateKey = myPrivateKey;
    this.timeoutMs = timeoutMs;
  }

  // ---------------- Build & sign JOIN ----------------

  /** Build a SERVER_HELLO_JOIN envelope (signed). */
  public String buildServerHelloJoinJson(String serverId, String myPubkeyB64u, String introducerAddr) {
    var ep = AdvertisedEndpointUtil.resolve(null, null);  // advertised host/port

    Map<String,Object> payload = new LinkedHashMap<>();
    payload.put("host", ep.host());
    payload.put("port", ep.port());
    payload.put("pubkey", myPubkeyB64u);

    Map<String,Object> env = new LinkedHashMap<>();
    env.put("type", "SERVER_HELLO_JOIN");
    env.put("from", serverId);
    env.put("to", introducerAddr); // Keep original 'to' semantics
    env.put("ts", System.currentTimeMillis());
    env.put("payload", payload);

    String canonStr = UnifiedJsonUtil.createCanonicalJson(UnifiedJsonUtil.getDefaultMapper().valueToTree(env));
    log.debug("[CLIENT CANON] {}", canonStr);
    try {
      byte[] canonical = canonStr.getBytes(java.nio.charset.StandardCharsets.UTF_8);
      env.put("sig", UnifiedCryptoUtil.rsaSign(canonical, myPrivateKey));
    } catch (Exception e) {
      throw new RuntimeException("Failed to sign envelope", e);
    }

    return UnifiedJsonUtil.toJson(env);
  }

  // ---------------- Send & await one reply ----------------

  /** Send one text frame and wait for the first inbound text frame as reply. */
  public String sendWsAndAwaitOneText(String wsUrl, String textToSend) {
    ReactorNettyWebSocketClient ws = new ReactorNettyWebSocketClient();
    AtomicReference<String> replyRef = new AtomicReference<>();

    log.debug("[WS CONNECT] {}", wsUrl);
    try {
      ws.execute(URI.create(wsUrl), session -> {
        var send = session.send(Mono.just(session.textMessage(textToSend)));
        var recv = session.receive().next().doOnNext(m -> replyRef.set(m.getPayloadAsText())).then();
        return send.then(recv);
      }).block(Duration.ofMillis(timeoutMs));
    } catch (Exception e) {
      log.warn("[WS ERROR][url={}][timeoutMs={}] {}", wsUrl, timeoutMs, e.toString());
      throw new IllegalStateException("WebSocket call failed: " + e.getMessage(), e);
    }

    String reply = replyRef.get();
    if (reply == null) {
      log.warn("[WS TIMEOUT][url={}] No reply within {} ms", wsUrl, timeoutMs);
      throw new IllegalStateException("No reply received from introducer within timeout");
    }
    return reply;
  }

  // ---------------- Parse & verify WELCOME ----------------

  /** Parse SERVER_WELCOME and extract assigned_id + clients[]. */
  @SuppressWarnings("unchecked")
  public WelcomeResult parseWelcome(String json) {
    ProtocolMessage m = UnifiedJsonUtil.fromJson(json, ProtocolMessage.class);
    if (!"SERVER_WELCOME".equals(m.getType()))
      throw new IllegalStateException("Unexpected reply type: " + m.getType());

    Map<String,Object> p = m.getPayload();
    String assignedId = (String) p.get("assigned_id");

    List<ClientInfo> clients = new ArrayList<>();
    Object arr = p.get("clients");
    if (arr instanceof List<?> list) {
      for (Object it : list) {
        if (it instanceof Map<?,?> c) {
          String userId = asString(c.get("user_id"));
          String host   = asString(c.get("host"));
          Integer port  = asInt(c.get("port"));
          String pk     = asString(c.get("pubkey"));
          clients.add(new ClientInfo(userId, host, port == null ? -1 : port, pk));
        }
      }
    }

    log.debug("[PARSED][assignedId={}][clientsCount={}]", assignedId, clients.size());
    return new WelcomeResult(assignedId, clients);
  }

  private static String asString(Object o){ return (o instanceof String)?(String)o:null; }
  private static Integer asInt(Object o){
    if (o instanceof Number i) return i.intValue();
    if (o instanceof String s) try { return Integer.parseInt(s);} catch (Exception ignored) {}
    return null;
  }

  // ---------- Small data holders ----------

  public static final class ClientInfo {
    public final String userId, host, pubkeyB64u; public final int port;
    public ClientInfo(String userId, String host, int port, String pubkeyB64u){
      this.userId=userId; this.host=host; this.port=port; this.pubkeyB64u=pubkeyB64u;
    }
    @Override public String toString() { return "ClientInfo{userId='" + userId + "', host='" + host + "', port=" + port + "}"; }
  }

  public static final class WelcomeResult {
    public final String assignedId; public final List<ClientInfo> clients;
    public WelcomeResult(String assignedId, List<ClientInfo> clients){
      this.assignedId=assignedId; this.clients=clients==null?Collections.emptyList():clients;
    }
  }
}
