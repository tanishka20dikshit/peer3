package edu.adelaide.server;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import edu.adelaide.model.ProtocolMessage;
import edu.adelaide.model.ServerInfo;
import edu.adelaide.service.IntroducerService;
import edu.adelaide.util.UnifiedJsonUtil;
import edu.adelaide.util.UnifiedCryptoUtil;
import edu.adelaide.util.MessageProcessingUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.lang.NonNull;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Introducer WebSocket handler (SOCP v1.3, minimal)
 *
 * - Verify inbound SERVER_HELLO_JOIN signature using server public key (pinned first, else TOFU from payload).
 * - Register/pin endpoint + pubkey.
 * - Reply SERVER_WELCOME signed by introducer private key.
 * - Reply signed ERROR on failures.
 *
 * Signature rule:
 *   Sign/verify canonical JSON of {type, from, to, ts, payload} (WITHOUT "sig").
 *   RSASSA-PSS(SHA-256, MGF1-SHA256, saltLen=32), signature is base64url (no padding).
 */
@Component
public class IntroducerWsHandler extends BaseWebSocketHandler {

  private static final Logger log = LoggerFactory.getLogger(IntroducerWsHandler.class);

  private final IntroducerService introducerService;

  public IntroducerWsHandler(
      IntroducerService svc,
      @Qualifier("introducerPrivateKey") java.security.interfaces.RSAPrivateKey introducerPrivateKey) {
    super(introducerPrivateKey);
    this.introducerService = svc;
  }
  
  @Override
  protected String getServerId() {
    return "introducer";
  }

  @Override
  public void handleTextMessage(@NonNull WebSocketSession session, @NonNull TextMessage message) throws Exception {
    log.info("user.dir={}", System.getProperty("user.dir"));
    long __t0 = System.nanoTime();
    final String raw = message.getPayload();

    // Basic inbound information
    log.info("[WS IN] id={} remote={} len={}",
        safeSessionId(session),
        safeRemoteAddress(session),
        raw.length());
    log.debug("[WS IN] sha256={} preview={}",
        sha256b64(raw.getBytes(java.nio.charset.StandardCharsets.UTF_8)),
        preview(raw, 256));

    final ProtocolMessage in;
    try {
      in = UnifiedJsonUtil.fromJson(raw, ProtocolMessage.class);
    } catch (Exception e) {
      log.warn("[WS IN] parse FAIL id={} err={}", safeSessionId(session), trim(e.getMessage()));
      sendErrorMessage(session, "*", "BAD_JSON", trim(e.getMessage()));
      return;
    }

    if (in == null || MessageProcessingUtil.isBlank(in.getType())) {
      log.warn("[WS IN] missing type id={}", safeSessionId(session));
      sendErrorMessage(session, safeFrom(in), "UNKNOWN_TYPE", "Missing 'type'");
      return;
    }

    log.debug("[WS IN] meta type={} from={} to={} ts={}",
        in.getType(), in.getFrom(), in.getTo(), in.getTs());

    if (!"SERVER_HELLO_JOIN".equals(in.getType())) {
      log.warn("[WS IN] unsupported type={} id={}", in.getType(), safeSessionId(session));
      sendErrorMessage(session, safeFrom(in), "UNKNOWN_TYPE", "Unsupported type: " + in.getType());
      return;
    }

    handleJoin(session, in, raw);

    // Total elapsed time
    long __ms = (System.nanoTime() - __t0) / 1_000_000;
    log.debug("[WS IN] handled type={} elapsedMs={}", in.getType(), __ms);
  }


  private void handleJoin(WebSocketSession session, ProtocolMessage in, String raw) throws Exception {
    long __t0 = System.nanoTime();
    log.debug("[JOIN] start id={} from={} raw.len={}", safeSessionId(session), in.getFrom(), raw.length());

    JsonNode root = UnifiedJsonUtil.parseJson(raw);
    JsonNode sigNode = root.get("sig");
    if (sigNode == null || sigNode.isNull() || MessageProcessingUtil.isBlank(sigNode.asText())) {
      log.warn("[JOIN] missing sig id={}", safeSessionId(session));
      sendErrorMessage(session, safeFrom(in), "BAD_SIGNATURE", "Missing 'sig'");
      return;
    }
    final String inboundSigB64u = sigNode.asText();
    ((ObjectNode) root).remove("sig");
    final String canonicalJson = UnifiedJsonUtil.createCanonicalJson(root);
    final byte[] canonBytes = canonicalJson.getBytes(java.nio.charset.StandardCharsets.UTF_8);

    // Inbound canonical overview
    long tsIn = root.has("ts") ? root.get("ts").asLong() : -1L;
    log.trace("[JOIN] tsIn={} canon.sha256={} payload.preview={}",
        tsIn, sha256b64(canonBytes), preview(root.toString(), 512));

    final Map<String, Object> p = asMap(in.getPayload());
    final String claimedPubKeyB64u = (p == null) ? null : asString(p.get("pubkey"));
    final String pinnedPubKeyB64u  = findRegisteredPubkeyByServerId(in.getFrom());

    java.security.interfaces.RSAPublicKey pubPinned  = null;
    java.security.interfaces.RSAPublicKey pubClaimed = null;
    if (MessageProcessingUtil.isNotBlank(pinnedPubKeyB64u)) {
      try { pubPinned = UnifiedCryptoUtil.loadRSAPublicKeyFromBase64Url(pinnedPubKeyB64u); }
      catch (Exception ex) { log.warn("[JOIN] load pinned pub FAIL err={}", ex.toString()); }
    }
    if (MessageProcessingUtil.isNotBlank(claimedPubKeyB64u)) {
      try { pubClaimed = UnifiedCryptoUtil.loadRSAPublicKeyFromBase64Url(claimedPubKeyB64u); }
      catch (Exception ex) { log.warn("[JOIN] load claimed pub FAIL err={}", ex.toString()); }
    }

    // Key availability
    log.debug("[JOIN] keys pinned.present={} claimed.present={}",
        (pubPinned != null), (pubClaimed != null));

    boolean ok = false;
    String usedKey = null;

    if (pubPinned != null) {
      ok = UnifiedCryptoUtil.rsaVerify(canonBytes, inboundSigB64u, pubPinned);
      log.debug("[JOIN] verify pinned.ok={}", ok);
      if (ok) usedKey = "pinned";
    }
    if (!ok && pubClaimed != null && (pinnedPubKeyB64u == null || (claimedPubKeyB64u != null && !claimedPubKeyB64u.equals(pinnedPubKeyB64u)))) {
      ok = UnifiedCryptoUtil.rsaVerify(canonBytes, inboundSigB64u, pubClaimed);
      log.debug("[JOIN] verify claimed.ok={}", ok);
      if (ok) usedKey = "claimed";
    }
    if (!ok) {
      log.warn("[JOIN] verify FAIL");
      sendErrorMessage(session, safeFrom(in), "BAD_SIGNATURE", "Signature verify failed");
      return;
    }
    log.info("[JOIN] verify OK usedKey={}", usedKey);

    if (p == null) {
      log.warn("[JOIN] missing payload");
      sendErrorMessage(session, safeFrom(in), "BAD_PAYLOAD", "Missing payload");
      return;
    }
    final String host = asString(p.get("host"));
    final Integer port = asInt(p.get("port"));
    final String pubkeySelfReport = asString(p.get("pubkey"));
    log.debug("[JOIN] payload host={} port={} pub.self.present={}",
        host, port, MessageProcessingUtil.isNotBlank(pubkeySelfReport));

    if (MessageProcessingUtil.isBlank(host) || port == null || port <= 0) {
      log.warn("[JOIN] bad host/port");
      sendErrorMessage(session, safeFrom(in), "BAD_PAYLOAD", "host/port required");
      return;
    }

    final String assigned = introducerService.assignServerId(in.getFrom());
    final String pubkeyToStore = ("claimed".equals(usedKey))
        ? pubkeySelfReport
        : (pinnedPubKeyB64u != null ? pinnedPubKeyB64u : pubkeySelfReport);

    // Registration information
    log.info("[JOIN] assigned={} store.pub.present={} store.pub.len={}",
        assigned, MessageProcessingUtil.isNotBlank(pubkeyToStore), (pubkeyToStore==null?0:pubkeyToStore.length()));

    introducerService.registerServer(assigned, host, port, pubkeyToStore);
    log.debug("[JOIN] register OK host={} port={}", host, port);

    Map<String, Object> welcome = new LinkedHashMap<>();
    welcome.put("assigned_id", assigned);
    List<ServerInfo> clients = introducerService.listKnownServers(); // {user_id, host, port, pubkey}
    welcome.put("clients", clients);
    log.debug("[JOIN] knownServers.size={}", (clients==null?0:clients.size()));

    ProtocolMessage out = new ProtocolMessage();
    out.setType("SERVER_WELCOME");
    out.setFrom("introducer");
    out.setTo(assigned);
    out.setTs(Instant.now().toEpochMilli());
    out.setPayload(welcome);
    out.setSig(null);

    JsonNode unsignedNode = UnifiedJsonUtil.toJsonNode(out);
    if (unsignedNode.has("sig")) {
      ((ObjectNode) unsignedNode).remove("sig");
    }
    String canonicalJsonOut = UnifiedJsonUtil.createCanonicalJson(unsignedNode);
    byte[] canonical = canonicalJsonOut.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    String sigB64u = UnifiedCryptoUtil.rsaSign(canonical, privateKey);

    long tsOut = unsignedNode.has("ts") ? unsignedNode.get("ts").asLong() : -1L;
    log.debug("[JOIN] OUT ts={} canon.sha256={} payload.preview={}",
        tsOut, sha256b64(canonical), preview(unsignedNode.toString(), 512));

    ((ObjectNode) unsignedNode).put("sig", sigB64u);

    try {
      if (privateKey instanceof java.security.interfaces.RSAPrivateCrtKey crt) {
        var selfPub = UnifiedCryptoUtil.extractPublicKeyFromCRT(crt);
        boolean selfOk = UnifiedCryptoUtil.rsaVerify(canonical, sigB64u, selfPub);
        log.debug("[JOIN] SELF-VERIFY ok={}", selfOk);
      } else {
        log.trace("[JOIN] SELF-VERIFY skipped (not RSAPrivateCrtKey)");
      }
    } catch (Exception ex) {
      log.debug("[JOIN] SELF-VERIFY error={}", ex.toString());
    }

    String outJson = UnifiedJsonUtil.toJson(unsignedNode);
    log.info("[WS OUT] type=SERVER_WELCOME len={} sha256={} preview={}",
        outJson.length(),
        sha256b64(outJson.getBytes(java.nio.charset.StandardCharsets.UTF_8)),
        preview(outJson, 256));

    long __ts = System.nanoTime();
    session.sendMessage(new TextMessage(outJson));
    long __sendMs = (System.nanoTime() - __ts) / 1_000_000;

    long __ms = (System.nanoTime() - __t0) / 1_000_000;
    log.info("[JOIN] done assigned={} sendMs={} totalMs={}", assigned, __sendMs, __ms);
  }


  /** Send standardized ERROR envelope (also signed for consistency). */
  private void sendError(WebSocketSession session, String to, String code, String detail) throws Exception {
    long __t0 = System.nanoTime();

    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("code", code);
    payload.put("detail", detail);

    ProtocolMessage err = new ProtocolMessage();
    err.setType("ERROR");
    err.setFrom("introducer");
    err.setTo(MessageProcessingUtil.isBlank(to) ? "*" : to);
    err.setTs(Instant.now().toEpochMilli());
    err.setPayload(payload);
    err.setSig(null);

    JsonNode unsigned = UnifiedJsonUtil.toJsonNode(err);
    if (unsigned.has("sig")) ((ObjectNode) unsigned).remove("sig");
    String canonicalJson = UnifiedJsonUtil.createCanonicalJson(unsigned);
    byte[] canonical = canonicalJson.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    String sigB64u = UnifiedCryptoUtil.rsaSign(canonical, privateKey);

    long tsErr = unsigned.has("ts") ? unsigned.get("ts").asLong() : -1L;
    log.debug("[ERROR OUT] ts={} code={} canon.sha256={} detail.preview={}",
        tsErr, code, sha256b64(canonical), preview(detail, 256));

    ((ObjectNode) unsigned).put("sig", sigB64u);
    String outJson = UnifiedJsonUtil.toJson(unsigned);

    log.warn("[WS OUT] type=ERROR code={} len={} sha256={} preview={}",
        code, outJson.length(),
        sha256b64(outJson.getBytes(java.nio.charset.StandardCharsets.UTF_8)),
        preview(outJson, 256));

    session.sendMessage(new TextMessage(outJson));

    long __ms = (System.nanoTime() - __t0) / 1_000_000;
    log.debug("[ERROR OUT] code={} elapsedMs={}", code, __ms);
  }

  // -------- helpers (minimal) --------

  private String findRegisteredPubkeyByServerId(String serverId) {
    if (MessageProcessingUtil.isBlank(serverId)) return null;
    try {
      List<ServerInfo> list = introducerService.listKnownServers();
      if (list != null) for (ServerInfo si : list) {
        if (serverId.equals(si.getUser_id())) return si.getPubkey();
      }
    } catch (Exception ignore) {}
    return null;
  }

  private static String safeFrom(ProtocolMessage in) {
    return (in != null && in.getFrom() != null) ? in.getFrom() : "*";
  }

  @SuppressWarnings("unchecked")
  private static Map<String,Object> asMap(Object o){ return (o instanceof Map)?(Map<String,Object>)o:null; }

  private static String asString(Object o){ return (o instanceof String)?(String)o:null; }

  private static Integer asInt(Object o){
    if (o instanceof Integer) return (Integer)o;
    if (o instanceof Long) return ((Long)o).intValue();
    if (o instanceof Double) return ((Double)o).intValue();
    if (o instanceof String) try { return Integer.parseInt((String) o); } catch (Exception ignore) {}
    return null;
  }

  private static String trim(String s) {
    if (s == null) return null;
    s = s.replace('\n',' ');
    return s.length() > 200 ? s.substring(0,200) + "..." : s;
  }

  private static String sha256b64(byte[] bytes){
    try {
      var md = java.security.MessageDigest.getInstance("SHA-256");
      return java.util.Base64.getEncoder().encodeToString(md.digest(bytes));
    } catch (Exception e) { return "ERR"; }
  }


  private static String preview(String s, int max) {
    if (s == null) return "null";
    String one = s.replace('\n',' ').replace('\r',' ');
    return one.length() <= max ? one : one.substring(0, max) + "...";
  }


}
