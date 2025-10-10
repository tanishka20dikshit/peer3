package edu.adelaide.server;

import com.fasterxml.jackson.databind.JsonNode;
import edu.adelaide.cache.UserLoginDirectory;
import edu.adelaide.cache.PeerDirectory;
import edu.adelaide.util.MessageProcessingUtil;
import edu.adelaide.util.UnifiedCryptoUtil;
import edu.adelaide.util.UnifiedJsonUtil;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/** Receive LOCAL_USER_ADVERTISE / USER_REMOVE from peer servers (raw JSON over WS). */
@Component
public class ServerUserWsHandler extends BaseWebSocketHandler {
  
  private final UserLoginDirectory userLoginDir;
  private final PeerDirectory peerDir;
  
  @Value("${introducer.client.server-id}")
  private String myServerId;

  public ServerUserWsHandler(UserLoginDirectory userLoginDir, 
                             PeerDirectory peerDir,
                             @Qualifier("serverPrivateKey") RSAPrivateKey myPriv) {
    super(myPriv);
    this.userLoginDir = userLoginDir;
    this.peerDir = peerDir;
  }
  
  @Override
  protected String getServerId() {
    return myServerId;
  }

  @Override
  public void handleTextMessage(@NonNull WebSocketSession session, @NonNull TextMessage message) {
    final String raw = message.getPayload();
    final String remote = safeRemoteAddress(session);
    log.info("[PEER USER EVT][RECV][from={}][len={}] {}", remote, raw.length(), raw);

    try {
      JsonNode root = parseJsonSafely(raw, "UserEventHandler");
      if (root == null) {
        log.warn("[PEER USER EVT] BAD_JSON: failed to parse message");
        return;
      }

      final String type = MessageProcessingUtil.getStringField(root, "type", "");
      final String fromServer = MessageProcessingUtil.getStringField(root, "from", "");
      final JsonNode payload = root.path("payload");
      final String sigB64u = MessageProcessingUtil.getStringField(root, "sig", "");

      if (MessageProcessingUtil.isBlank(type) || MessageProcessingUtil.isBlank(fromServer) || payload.isMissingNode()) {
        log.warn("[PEER USER EVT] invalid envelope");
        return;
      }

      // --- Verify signature from peer server ---
      if (!verifyEnvelopeSig(root, fromServer)) {
        log.warn("[PEER USER EVT] sig verify failed from={}", fromServer);
        return;
      }

      switch (type) {
        case "USER_ADVERTISE" -> {
          String userId = MessageProcessingUtil.getStringField(payload, "user_id", "");
          String userName = MessageProcessingUtil.getStringField(payload, "user_name", userId);
          String userIp = MessageProcessingUtil.getStringField(payload, "user_ip", null);
          Integer userPort = payload.hasNonNull("user_port") ? MessageProcessingUtil.getIntField(payload, "user_port", 0) : null;

          // No roles/attrs; we also do not propagate keys here.
          userLoginDir.upsert(fromServer, userId, userName);
          log.info("[PEER USER ADVERTISE] {} from {} (ip={},port={})", userId, fromServer, userIp, userPort);
        }
        case "USER_REMOVE" -> {
          String userId = MessageProcessingUtil.getStringField(payload, "user_id", "");
          boolean removed = userLoginDir.removeUser(fromServer, userId);
          log.info("[PEER USER REMOVE] {} from {} => {}", userId, fromServer, removed);
        }
        default -> log.warn("[PEER USER EVT] unknown type={} from={}", type, fromServer);
      }

      // optional: simple ack
      session.sendMessage(new TextMessage("{\"ok\":true}"));

    } catch (Exception e) {
      log.warn("[PEER USER EVT] error: {}", e.toString());
    }
  }

  /** Verify RSASSA-PSS(SHA-256) signature over canonical JSON without 'sig'. */
  private boolean verifyEnvelopeSig(JsonNode root, String fromServer) {
    try {
      // 1) resolve peer server public key (base64url SPKI DER) from PeerDirectory
      String spkiB64u = peerDir.findPubkeyByServerId(fromServer);
      if (MessageProcessingUtil.isBlank(spkiB64u)) return false;

      RSAPublicKey pub = UnifiedCryptoUtil.loadRSAPublicKeyFromBase64Url(spkiB64u);

      // 2) build canonical bytes (remove 'sig')
      String canonicalJson = UnifiedJsonUtil.createCanonicalJson(root);
      byte[] canonical = canonicalJson.getBytes(java.nio.charset.StandardCharsets.UTF_8);

      // 3) verify PSS
      String sigB64u = MessageProcessingUtil.getStringField(root, "sig", "");
      return UnifiedCryptoUtil.rsaVerify(canonical, sigB64u, pub);
    } catch (Exception e) {
      return false;
    }
  }
}
