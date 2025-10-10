package edu.adelaide.server;

import com.fasterxml.jackson.databind.JsonNode;
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

/**
 * SERVER_HEARTBEAT receiver (raw WebSocket).
 *
 * - Require pinned key for verification (no TOFU on heartbeat).
 * - Verify signature over canonical JSON of the RAW envelope with "sig" removed.
 * - Do NOT trust remote ts for liveness; mark lastSeen using local time.
 * - No ACK is sent (fire-and-forget).
 */
@Component
public class ServerHeartbeatWsHandler extends BaseWebSocketHandler {

  private final PeerDirectory peerDir;
  
  @Value("${introducer.client.server-id}")
  private String myServerId;

  public ServerHeartbeatWsHandler(PeerDirectory peerDir,
                                  @Qualifier("serverPrivateKey") RSAPrivateKey myPriv) {
    super(myPriv);
    this.peerDir = peerDir;
  }
  
  @Override
  protected String getServerId() {
    return myServerId;
  }

  @Override
  public void handleTextMessage(@NonNull WebSocketSession session, @NonNull TextMessage message) throws Exception {
    final String raw = message.getPayload();

    // 0) Parse raw JSON safely
    final JsonNode root = parseJsonSafely(raw, "HeartbeatHandler");
    if (root == null) {
      log.warn("[HB] BAD_JSON: failed to parse message");
      return;
    }

    if (!"SERVER_HEARTBEAT".equals(MessageProcessingUtil.getStringField(root, "type", null))) {
      // Not our message type; ignore silently.
      return;
    }

    final String from   = MessageProcessingUtil.getStringField(root, "from", null);
    final String sigB64 = MessageProcessingUtil.getStringField(root, "sig", null);
    if (MessageProcessingUtil.isBlank(from) || MessageProcessingUtil.isBlank(sigB64)) {
      log.warn("[HB] missing from/sig");
      return;
    }

    // 1) Fetch pinned SPKI for 'from' (heartbeat requires a pinned key)
    final String pinnedSpki = peerDir.findPubkeyByServerId(from);
    if (MessageProcessingUtil.isBlank(pinnedSpki)) {
      // We don't TOFU on heartbeat to avoid key swap; wait for ANNOUNCE/JOIN to pin first.
      log.warn("[HB] no pinned key for '{}', ignore", from);
      return;
    }

    // 2) Build canonical from RAW by removing "sig" ONLY, to avoid numeric drift
    final String canonicalJson = UnifiedJsonUtil.createCanonicalJson(root);
    final byte[] canonical = canonicalJson.getBytes(java.nio.charset.StandardCharsets.UTF_8);

    // 3) Verify RSASSA-PSS(SHA-256, saltLen=32) using pinned pubkey
    final RSAPublicKey pub = UnifiedCryptoUtil.loadRSAPublicKeyFromBase64Url(pinnedSpki);
    final boolean ok = UnifiedCryptoUtil.rsaVerify(canonical, sigB64, pub);
    if (!ok) {
      log.warn("[HB] BAD_SIGNATURE from={}", from);
      return;
    }

    // 4) Mark liveness using LOCAL time (do not trust remote ts to avoid clock skew)
    peerDir.markSeenNow(from);

    // Optional debug: show remote ts for reference only
    long remoteTs = MessageProcessingUtil.getLongField(root, "ts", -1L);
    log.debug("[HB OK] from={} remoteTs={} (ignored for liveness)", from, remoteTs);
  }
}
