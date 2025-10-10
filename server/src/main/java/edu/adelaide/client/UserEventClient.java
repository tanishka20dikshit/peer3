package edu.adelaide.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import edu.adelaide.util.UnifiedCryptoUtil;
import edu.adelaide.util.UnifiedJsonUtil;
import org.slf4j.Logger; import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.socket.client.ReactorNettyWebSocketClient;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

@Component
public class UserEventClient {

  private static final Logger log = LoggerFactory.getLogger(UserEventClient.class);

  private final java.security.interfaces.RSAPrivateKey myPrivateKey;
  private final long timeoutMs;

  public UserEventClient(java.security.interfaces.RSAPrivateKey myPrivateKey) {
    this.myPrivateKey = myPrivateKey;
    this.timeoutMs = 5000;
  }

  // ======================= Public builders (no roles/attrs) =======================

  /** Build a LOCAL_USER_ADVERTISE event JSON (signed). */
  public String buildAdvertiseUserJson(String serverId,
                                       String to,
                                       String userId,
                                       String displayName,
                                       String userIp,
                                       Integer userPort) {
    Map<String, Object> payload = new LinkedHashMap<>();
    String uid = (userId == null || userId.isBlank()) ? displayName : userId;
    payload.put("user_id", uid);
    if (displayName != null && !displayName.isBlank()) payload.put("user_name", displayName);
    if (userIp != null && !userIp.isBlank()) payload.put("user_ip", userIp);
    if (userPort != null) payload.put("user_port", userPort);
    return buildSignedEventJson("USER_ADVERTISE", serverId, to, payload);
  }

  /** Build a USER_REMOVE event JSON (signed). */
  public String buildRemoveUserJson(String serverId,
                                    String to,
                                    String userId,
                                    String reason) {
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("user_id", userId);
    if (reason != null && !reason.isBlank()) payload.put("reason", reason);
    return buildSignedEventJson("USER_REMOVE", serverId, to, payload);
  }

  // ======================= Convenience senders =======================

  public void advertiseFireAndForget(String wsUrl, String json) {
    sendFireAndForget(wsUrl, json, "USER_ADVERTISE");
  }

  public void removeFireAndForget(String wsUrl, String json) {
    sendFireAndForget(wsUrl, json, "USER_REMOVE");
  }

  // ======================= Core build & sign =======================

  private String buildSignedEventJson(String type,
                                      String serverId,
                                      String to,
                                      Map<String, Object> payload) {
    Map<String, Object> env = new LinkedHashMap<>();
    env.put("type", type);
    env.put("from", serverId);
    env.put("to",   to);
    env.put("ts",   System.currentTimeMillis());
    env.put("payload", payload == null ? Map.of() : payload);

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
      throw new RuntimeException("Failed to sign message", e);
    }
    ObjectNode objectNode = (ObjectNode) unsigned;
    objectNode.put("sig", sigB64u);

    String json = UnifiedJsonUtil.toJson(unsigned);
    if (log.isDebugEnabled()) {
      log.debug("[USER EVENT OUT] type={} ts={} canonHash={} len={}",
          type, unsigned.path("ts").asLong(), sha256b64(canonical), json.length());
      log.trace("[USER EVENT JSON] {}", json);
    }
    return json;
  }

  // ======================= WS send helpers =======================

  public void sendFireAndForget(String wsUrl, String json, String typeForLog) {
    ReactorNettyWebSocketClient ws = new ReactorNettyWebSocketClient();
    log.info("[WS OUT][{}] url={}", typeForLog, wsUrl);
    log.info("[WS OUT][{}] json={}", typeForLog, json);
    ws.execute(URI.create(wsUrl), session ->
        session.send(Mono.just(session.textMessage(json))).then()
    ).block(Duration.ofMillis(timeoutMs));
  }

  // ======================= small utils =======================

  private static String sha256b64(byte[] bytes){
    try {
      return UnifiedCryptoUtil.base64UrlEncode(UnifiedCryptoUtil.sha256(bytes));
    } catch (Exception e) {
      return "ERR";
    }
  }
}
