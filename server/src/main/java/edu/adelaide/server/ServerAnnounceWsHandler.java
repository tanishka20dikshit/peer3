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

/**
 * Server -> receives SERVER_ANNOUNCE from other peers.
 * Flow:
 *   - Parse RAW JSON
 *   - Remove "sig" and canonicalize
 *   - Verify RSASSA-PSS(SHA256) using pinned pubkey (from PeerDirectory) of 'from';
 *     if no pinned, TOFU: use payload.pubkey; if claimed verification succeeds then pin/rotate
 *   - Validate payload {host,port,pubkey}
 *   - Upsert into PeerDirectory
 *   - No reply required (fire-and-forget)
 */
@Component
public class ServerAnnounceWsHandler extends BaseWebSocketHandler {
  
  private final PeerDirectory peerDir;
  
  @Value("${introducer.client.server-id}")
  private String myServerId;

  public ServerAnnounceWsHandler(PeerDirectory peerDir,
                                 @Qualifier("serverPrivateKey") java.security.interfaces.RSAPrivateKey myPriv) {
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
    log.info("[ANNOUNCE IN][id={}][len={}]", safeSessionId(session), raw.length());

    JsonNode root = parseJsonSafely(raw, "AnnounceHandler");
    if (root == null) {
      log.warn("[ANNOUNCE] BAD_JSON: failed to parse message");
      return;
    }

    final String type = MessageProcessingUtil.getStringField(root, "type", null);
    if (!"SERVER_ANNOUNCE".equals(type)) {
      log.warn("[ANNOUNCE] UNKNOWN_TYPE: {}", type);
      return;
    }

    final String from = MessageProcessingUtil.getStringField(root, "from", null);
    final String to   = MessageProcessingUtil.getStringField(root, "to", null);
    final long   ts   = MessageProcessingUtil.getLongField(root, "ts", -1);
    final JsonNode payload = root.path("payload");
    final String sigB64u   = MessageProcessingUtil.getStringField(root, "sig", null);

    if (MessageProcessingUtil.isBlank(sigB64u)) {
      log.warn("[ANNOUNCE] BAD_SIGNATURE: missing sig");
      return;
    }

    // ---- canonicalize RAW without "sig" ----
    String canonicalJson = UnifiedJsonUtil.createCanonicalJson(root);
    byte[] canonical = canonicalJson.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    log.debug("[ANNOUNCE IN ts={} canonHash={} from={} to={}]",
        ts, UnifiedCryptoUtil.base64UrlEncode(UnifiedCryptoUtil.sha256(canonical)), from, to);

    // ---- pick pubkey: pinned first; else claimed (TOFU) ----
    String pinnedSpki  = peerDir.findPubkeyByServerId(from);
    String claimedSpki = MessageProcessingUtil.getStringField(payload, "pubkey", null);

    java.security.interfaces.RSAPublicKey pubPinned  = null;
    java.security.interfaces.RSAPublicKey pubClaimed = null;
    try {
      if (MessageProcessingUtil.isNotBlank(pinnedSpki))
        pubPinned  = UnifiedCryptoUtil.loadRSAPublicKeyFromBase64Url(pinnedSpki);
      if (MessageProcessingUtil.isNotBlank(claimedSpki))
        pubClaimed = UnifiedCryptoUtil.loadRSAPublicKeyFromBase64Url(claimedSpki);
    } catch (Exception ignore) {}

    if (pubPinned == null && pubClaimed == null) {
      log.warn("[ANNOUNCE VERIFY] No key available for verify (from={})", from);
      return;
    }

    boolean ok = false; String used = null;
    if (pubPinned != null) {
      ok = UnifiedCryptoUtil.rsaVerify(canonical, sigB64u, pubPinned);
      if (ok) used = "pinned";
    }
    if (!ok && pubClaimed != null && (pinnedSpki == null || !pinnedSpki.equals(claimedSpki))) {
      ok = UnifiedCryptoUtil.rsaVerify(canonical, sigB64u, pubClaimed);
      if (ok) used = "claimed";
    }
    log.debug("[ANNOUNCE VERIFY] ok={} usedKey={} pinnedPresent={} claimedPresent={}",
        ok, used, pubPinned != null, pubClaimed != null);
    if (!ok) {
      log.warn("[ANNOUNCE] BAD_SIGNATURE: verify failed (from={})", from);
      return;
    }

    // ---- payload validation AFTER verify ----
    String host = MessageProcessingUtil.getStringField(payload, "host", null);
    Integer port = asIntNode(payload.get("port"));      // Compatible with 8091 / 8091.0
    String pub  = MessageProcessingUtil.getStringField(payload, "pubkey", null);
    if (MessageProcessingUtil.isBlank(host) || port == null || port <= 0) {
      log.warn("[ANNOUNCE] BAD_PAYLOAD host/port (from={}) host={} port={}", from, host, port);
      return;
    }

    // ---- upsert directory ----
    String keyToStore = "claimed".equals(used) ? pub : (pinnedSpki != null ? pinnedSpki : pub);
    // Example: peerDir.upsert(from, host, port, keyToStore);
    savePeer(peerDir, from, host, port, keyToStore);

    log.info("[ANNOUNCE OK] from={} host={} port={} pinnedNow={} ",
        from, host, port, keyToStore != null);
  }

  // ---- adapt to your PeerDirectory API here ----
  private static void savePeer(PeerDirectory dir, String id, String host, int port, String pkB64u) {
    dir.upsert(id, host, port, pkB64u);
  }

  private static Integer asIntNode(JsonNode n){
    if (n == null || n.isNull()) return null;
    if (n.isInt() || n.isLong()) return n.intValue();
    if (n.isDouble() || n.isFloat() || n.isBigDecimal()) return n.decimalValue().intValue();
    if (n.isTextual()) {
      try { return new java.math.BigDecimal(n.asText().trim()).intValue(); } catch (Exception ignore) {}
    }
    return null;
  }
}
