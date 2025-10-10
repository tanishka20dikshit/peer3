package edu.adelaide.server;

import com.fasterxml.jackson.databind.JsonNode;
import edu.adelaide.cache.LocalSessionRegistry;
import edu.adelaide.cache.UserLoginDirectory;
import edu.adelaide.dto.ProtocolMessage;
import edu.adelaide.service.PublicChannelService;
import edu.adelaide.service.UserPresenceService;
import edu.adelaide.client.ServerLinkClient;
import edu.adelaide.cache.PeerDirectory;
import edu.adelaide.util.UnifiedJsonUtil;
import edu.adelaide.util.MessageProcessingUtil;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;

import java.security.interfaces.RSAPrivateKey;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Main server websocket handler:
 * - Enforces "single WebSocket per user" (new login kicks old).
 * - Tracks session→user for clean shutdown.
 * - Delegates public channel fanout to PublicChannelService (which uses LocalSessionRegistry).
 *
 * Verbosity note:
 *  - Added INFO/DEBUG/TRACE logs, plus timings for critical paths (ns→ms).
 *  - Full frames/payloads only at TRACE level to avoid log explosion.
 */
@Component
public class ServerMainWsHandler extends BaseWebSocketHandler {

    private final PeerDirectory peerDir;
    private final UserLoginDirectory userLoginDirectory;
    private final UserPresenceService userPresenceService;
    private final ServerLinkClient serverLinkClient;
    private final PublicChannelService publicChannelService;
    private final LocalSessionRegistry sessionRegistry;

    /** Reverse index: sessionId → userId. */
    private final Map<String, String> sessionUser = new ConcurrentHashMap<>();


    @Value("${introducer.client.server-id}")
    private String myServerId;

    public ServerMainWsHandler(@Qualifier("serverPrivateKey") RSAPrivateKey myPriv,
                               PeerDirectory peerDir,
                               UserLoginDirectory userLoginDirectory,
                               UserPresenceService userPresenceService,
                               ServerLinkClient serverLinkClient,
                               PublicChannelService publicChannelService,
                               LocalSessionRegistry sessionRegistry) {
        super(myPriv);
        this.peerDir = peerDir;
        this.userLoginDirectory = userLoginDirectory;
        this.userPresenceService = userPresenceService;
        this.serverLinkClient = serverLinkClient;
        this.publicChannelService = publicChannelService;
        this.sessionRegistry = sessionRegistry;
        log.info("[ws/init] ServerMainWsHandler init serverId={} peers={} sessions={}",
            safeStr(myServerId), safePeersCount(), safeSessions());
    }

    @Override
    protected String getServerId() {
        return myServerId;
    }

    @Override
    public void handleTextMessage(@NonNull WebSocketSession session, @NonNull TextMessage message) {
        long t0 = System.nanoTime();
        String senderId = "*";
        try {
            String raw = message.getPayload();
            if (raw == null || raw.isEmpty()) {
                sendErrorMessage(session, "*", "BAD_JSON", "Empty message payload");
                return;
            }
            JsonNode root = parseJsonSafely(raw, "MainHandler");
            if (root == null) {
                sendErrorMessage(session, "*", "BAD_JSON", "Malformed or unparsable message");
                return;
            }
            String type = MessageProcessingUtil.getStringField(root, "type", "");
            senderId = MessageProcessingUtil.getStringField(root, "from", "*");
            int bytes = raw.length();
            log.info("[ws/in] type={} from={} bytes={} sid={}", type, senderId, bytes, safeSessionId(session));
            log.info("[ws/in/frame] {}", formatJsonForLog(root));

            switch (type) {
                case "USER_HELLO" -> handleUserHello(session, root);
                case "MSG_DIRECT" -> handleMsgDirect(session, root);
                case "SERVER_DELIVER" -> handleServerDeliver(root);
                case "FILE_START" -> handleFileStart(session, root);
                case "FILE_CHUNK" -> handleFileChunk(session, root);
                case "FILE_END"   -> handleFileEnd(session, root);
                case "SERVER_CHANNEL_PUBLISH" -> handleServerChannelPublish(root);
                case "PUBLIC_CHANNEL_ADD" -> handlePeerPublicAdd(root);
                case "PUBLIC_CHANNEL_REMOVE" -> handlePeerPublicRemove(root);
                case "PUBLIC_CHANNEL_UPDATED" -> handlePeerPublicSnapshot(root);
                case "PUBLIC_CHANNEL_KEY_SHARE" -> handleRemoteKeyShareAndBroadcast(root);
                case "MSG_PUBLIC_CHANNEL" -> handlePublicMessage(root);
                case "SERVER_PUBLIC_DELIVER" -> handleServerPublicDeliverBroadcast(root);
                case "LIST_USERS" -> handleListRequest(session, senderId);
                case "ACK" -> handleAck(root);
                case "ERROR" -> handleError(root);
                default -> {
                    log.warn("[ws/in] UNKNOWN type={} from={} sid={}", type, senderId, safeSessionId(session));
                    sendErrorMessage(session, senderId, "UNKNOWN_TYPE", "Received unknown type: " + type);
                }
            }
        } catch (Exception e) {
            log.error("[ws/in] error from {} sid={} err={}", senderId, safeSessionId(session), e.toString(), e);
            sendErrorMessage(session, senderId, "BAD_JSON", "Malformed or unparsable message");
        } finally {
            long elapsedMs = (System.nanoTime() - t0) / 1_000_000;
            log.debug("[ws/in] handled from={} elapsedMs={}", senderId, elapsedMs);
        }
    }

    /** USER_HELLO: single-session per user (kick the previous one), presence gossip, and public announce. */
    private void handleUserHello(WebSocketSession session, JsonNode root) {
        long t0 = System.nanoTime();
        try {
            String userId = MessageProcessingUtil.getStringField(root, "from", "*");
            String displayName = MessageProcessingUtil.getStringField(root.path("payload"), "display_name", userId);
            log.info("[hello] from={} sid={} displayName={}", userId, safeSessionId(session), displayName);

            // 1. Check all online users from /list (across servers)
            boolean userOnlineAnywhere = userLoginDirectory.listAll().stream()
                    .anyMatch(u -> userId.equals(u.getUserId()));

            if (userOnlineAnywhere) {
                // This UUID already has an active session on some server.
                log.info("[hello] reject: user {} already online on another server", userId);
                sendErrorMessage(session, userId, "ALREADY_LOGGED_IN", "User already connected elsewhere");
                try { session.close(new CloseStatus(4001, "Already logged in elsewhere")); } catch (Exception ignore) {}
                return;
            }

            // 2. Proceed to bind locally (only if not online anywhere)
            sessionRegistry.put(userId, session);
            sessionUser.put(session.getId(), userId);
            log.debug("[hello] bound user={} -> sid={} totalSessions={}", userId, safeSessionId(session), safeSessions());

            // 3. Presence gossip
            String pubkey = MessageProcessingUtil.getStringField(root.path("payload"), "pubkey", null);
            String encPubkey = MessageProcessingUtil.getStringField(root.path("payload"), "enc_pubkey", null);
            userPresenceService.loginHereAndBroadcast(userId, userId, pubkey, encPubkey, null, null);
            log.debug("[hello] presence broadcasted for user={} pubkey?={} encPub?={}", userId, pubkey != null, encPubkey != null);

            // 4. Announce into public (ADD + UPDATED to clients/peers)
            publicChannelService.addUserToPublicAndAnnounce(userId, displayName);

            // 5. Welcome
            ProtocolMessage resp = MessageProcessingUtil.createMessage("USER_WELCOME", myServerId, userId, 
                Map.of("msg", "Welcome " + userId));
            sendSignedMessage(session, resp);
            log.info("[hello] welcome sent to user={} sid={}", userId, safeSessionId(session));

        } catch (Exception e) {
            log.warn("[hello] error: {}", e.toString(), e);
        } finally {
            long elapsedMs = (System.nanoTime() - t0) / 1_000_000;
            log.debug("[hello] done elapsedMs={}", elapsedMs);
        }
    }


    /** Handle direct messages */
    private void handleMsgDirect(WebSocketSession session, JsonNode root) {
        String fromUser = MessageProcessingUtil.getStringField(root, "from", null);
        String toUser   = MessageProcessingUtil.getStringField(root, "to", null);
        long ts         = MessageProcessingUtil.getLongField(root, "ts", 0);
        JsonNode payload = root.path("payload");

        if (fromUser == null || toUser == null || payload.isMissingNode()) {
            sendErrorMessage(session, fromUser != null ? fromUser : "*", "BAD_FORMAT", "Missing from/to/payload");
            return;
        }

        // Try local first (use sessionRegistry, not activeUsers)
        WebSocketSession recipientSession = sessionRegistry.get(toUser);

        if (recipientSession != null && recipientSession.isOpen()) {
            log.info("[DELIVER LOCAL] {} -> {}", fromUser, toUser);

            Map<String,Object> outPayload = new LinkedHashMap<>();
            outPayload.put("ciphertext", MessageProcessingUtil.getStringField(payload, "ciphertext", null));
            outPayload.put("sender", fromUser);
            outPayload.put("sender_pub", MessageProcessingUtil.getStringField(payload, "sender_pub", null));
            outPayload.put("content_sig", MessageProcessingUtil.getStringField(payload, "content_sig", null));
            
            ProtocolMessage deliver = MessageProcessingUtil.createMessage("USER_DELIVER", fromUser, toUser, outPayload);
            deliver.setTs(ts);

            try {
                sendSignedMessage(recipientSession, deliver);
            } catch (Exception e) {
                log.warn("Failed to deliver DM to {}: {}", toUser, e.toString());
            }
            return;
        }

        // Otherwise, forward to remote server
        String destServer = userLoginDirectory.listAll().stream()
                .filter(u -> u.getUserId().equals(toUser))
                .map(u -> u.getServerId())
                .findFirst()
                .orElse(null);

        if (destServer == null) {
            log.info("[DM FAIL] {} -> {} (unknown location)", fromUser, toUser);
            sendErrorMessage(session, fromUser, "USER_NOT_FOUND", "Recipient not found: " + toUser);
            return;
        }

        forwardToServer(destServer, fromUser, toUser, ts, payload);
    }


    /** FROM peer: relay user DM to local user if online. */
    private void handleServerDeliver(JsonNode root) {
        String toServer = MessageProcessingUtil.getStringField(root, "to", null);
        long ts         = MessageProcessingUtil.getLongField(root, "ts", 0);
        JsonNode payload= root.path("payload");
        if (!Objects.equals(toServer, myServerId)) { log.debug("[peer/dm] toServer={} != myServerId={}, ignore", toServer, myServerId); return; }
        String userId   = MessageProcessingUtil.getStringField(payload, "user_id", null);
        if (userId == null) { log.warn("[peer/dm] missing user_id"); return; }

        WebSocketSession recipient = sessionRegistry.get(userId);
        if (recipient != null && recipient.isOpen()) {
            var outPayload = new LinkedHashMap<String,Object>();
            outPayload.put("ciphertext", MessageProcessingUtil.getStringField(payload, "ciphertext", null));
            outPayload.put("sender", MessageProcessingUtil.getStringField(payload, "sender", null));
            outPayload.put("sender_pub", MessageProcessingUtil.getStringField(payload, "sender_pub", null));
            outPayload.put("content_sig", MessageProcessingUtil.getStringField(payload, "content_sig", null));
            
            ProtocolMessage deliver = MessageProcessingUtil.createMessage("USER_DELIVER", 
                MessageProcessingUtil.getStringField(payload, "sender", "peer"), userId, outPayload);
            deliver.setTs(ts);
            
            try { sendSignedMessage(recipient, deliver); log.debug("[peer/dm] delivered to {} sid={}", userId, safeSessionId(recipient)); }
            catch (Exception ex) { log.warn("[peer/dm] deliver FAIL user={} err={}", userId, ex.toString()); }
        } else {
            log.info("[peer/dm] user={} offline locally; drop", userId);
        }
    }

    /** FROM peer: public channel publish → fanout to local clients. */
    private void handleServerChannelPublish(JsonNode root) {
        String channel = MessageProcessingUtil.getStringField(root.path("payload"), "channel", null);
        if (!"public".equals(channel)) { log.debug("[peer/pub] non-public channel={}, ignore", channel); return; }
        String fromUser = MessageProcessingUtil.getStringField(root.path("payload"), "from", null);
        JsonNode msgNode= root.path("payload").path("message");
        if (fromUser == null || msgNode.isMissingNode()) { log.warn("[peer/pub] invalid payload"); return; }
        log.info("[peer/pub] fromUser={} -> local fanout", fromUser);
        publicChannelService.handleServerPublicPublish(fromUser, UnifiedJsonUtil.getDefaultMapper().convertValue(msgNode, Object.class));
    }

    /** FROM peer: membership delta (specification：payload.add=[userId...], payload.if_version=<long>) */
    private void handlePeerPublicAdd(JsonNode root) {
        JsonNode payload = root.path("payload");
        if (payload.isMissingNode()) { log.warn("[peer/public/add] missing payload"); return; }

        long ifVersion = MessageProcessingUtil.getLongField(payload, "if_version", -1L);
        JsonNode addArr = payload.path("add");
        if (!addArr.isArray()) {
            log.warn("[peer/public/add] 'add' is not array, got={}", addArr);
            return;
        }

        java.util.List<String> ids = new java.util.ArrayList<>();
        addArr.forEach(n -> { if (n != null) ids.add(n.asText()); });

        log.info("[peer/public/add] add.size={} if_version={}", ids.size(), ifVersion);
        // new entrance
        publicChannelService.mergePeerPublicAddList(ids, ifVersion);
    }

    private void handlePeerPublicRemove(JsonNode root) {
        String userId = MessageProcessingUtil.getStringField(root.path("payload"), "user_id", null);
        log.info("[peer/public/remove] user={} ", userId);
        if (userId != null) publicChannelService.mergePeerPublicRemove(userId);
    }
    private void handlePeerPublicSnapshot(JsonNode root) {
        long version = MessageProcessingUtil.getLongField(root.path("payload"), "version", 0L);

        JsonNode wrapsNode = root.path("payload").path("wraps");
        List<Map<String, Object>> list;

        if (wrapsNode != null && wrapsNode.isArray() && wrapsNode.size() > 0) {
            list = UnifiedJsonUtil.getDefaultMapper().convertValue(wrapsNode,
                new com.fasterxml.jackson.core.type.TypeReference<List<Map<String, Object>>>() {});
            log.info("[peer/public/snapshot] NEW-FORMAT version={} wraps={}", version, (list == null ? 0 : list.size()));
        } else {
            JsonNode membersNode = root.path("payload").path("members");
            list = UnifiedJsonUtil.getDefaultMapper().convertValue(membersNode,
                new com.fasterxml.jackson.core.type.TypeReference<List<Map<String, Object>>>() {});
            log.info("[peer/public/snapshot] LEGACY-FORMAT version={} members={}", version, (list == null ? 0 : list.size()));
        }

        publicChannelService.replacePublicSnapshot(version, list);
    }

    private void handleRemoteKeyShareAndBroadcast(JsonNode root) {
        publicChannelService.handleRemoteKeyShareAndBroadcast(root);
    }


    /** Forward a DM to another server. */
    private void forwardToServer(String destServer, String fromUser, String toUser, long ts, JsonNode payload) {
        long t0 = System.nanoTime();
        try {
            var peer = peerDir.get(destServer);
            if (peer == null) { log.warn("[dm/forward] no peer for serverId={}", destServer); return; }

            ProtocolMessage serverDeliver = new ProtocolMessage();
            serverDeliver.setType("SERVER_DELIVER");
            serverDeliver.setFrom(myServerId);
            serverDeliver.setTo(destServer);
            serverDeliver.setTs(ts);
            var outPayload = new LinkedHashMap<String,Object>();
            outPayload.put("user_id", toUser);
            outPayload.put("ciphertext", payload.path("ciphertext").asText(null));
            outPayload.put("sender", fromUser);
            outPayload.put("sender_pub", payload.path("sender_pub").asText(null));
            outPayload.put("content_sig", payload.path("content_sig").asText(null));
            serverDeliver.setPayload(outPayload);

            String url = String.format("ws://%s:%d/ws", peer.getHost(), peer.getPort());
            String json = UnifiedJsonUtil.toJson(serverDeliver);
            if (log.isTraceEnabled()) log.trace("[dm/forward->{}] frame={} url={}", destServer, json, url);
            serverLinkClient.sendJson(peer.getServerId(), url, json);
            log.info("[dm/forward] {} -> {} via server={} url={}", fromUser, toUser, destServer, url);
        } catch (Exception e) {
            log.warn("[dm/forward] FAIL server={} err={}", destServer, e.toString());
        } finally {
            log.debug("[dm/forward] elapsedMs={}", (System.nanoTime()-t0)/1_000_000);
        }
    }

    /** File Transfer is just forwarded. */
    private void handleFileStart(WebSocketSession session, JsonNode root) {
        handleFileTransfer(session, root);
    }

    private void handleFileChunk(WebSocketSession session, JsonNode root) {
        handleFileTransfer(session, root);
    }

    private void handleFileEnd(WebSocketSession session, JsonNode root) {
        handleFileTransfer(session, root);
    }

    private void handleFileTransfer(WebSocketSession session, JsonNode root) {
        String fromUser = MessageProcessingUtil.getStringField(root, "from", null);
        String toUser = MessageProcessingUtil.getStringField(root, "to", null);
        long ts = MessageProcessingUtil.getLongField(root, "ts", 0);
        JsonNode payload = root.path("payload");
        String type = MessageProcessingUtil.getStringField(root, "type", null);

        if (fromUser == null || toUser == null || payload.isMissingNode()) {
            log.warn("[file] BAD_FORMAT type={} from={} to={}", type, fromUser, toUser);
            return;
        }

        // Try local first
        WebSocketSession local = sessionRegistry.get(toUser);
        if (local != null && local.isOpen()) {
            try {
                ProtocolMessage deliver = MessageProcessingUtil.createMessage(type, fromUser, toUser, 
                    UnifiedJsonUtil.getDefaultMapper().convertValue(payload, java.util.Map.class));
                deliver.setTs(ts);
                sendSignedMessage(local, deliver);
                log.debug("[file/local] {} {} -> {}", type, fromUser, toUser);
                return;
            } catch (Exception e) {
                log.warn("[file/local] fail {} -> {} err={}", fromUser, toUser, e.toString());
            }
        }

        // Remote forward (same as DM)
        String destServer = userLoginDirectory.listAll().stream()
                .filter(u -> u.getUserId().equals(toUser))
                .map(u -> u.getServerId())
                .findFirst()
                .orElse(null);

        if (destServer == null) {
            log.info("[file/forward] {} -> {} unknown dest", fromUser, toUser);
            return;
        }

        try {
            var peer = peerDir.get(destServer);
            if (peer == null) {
                log.warn("[file/forward] no peer for serverId={}", destServer);
                return;
            }

            String url = String.format("ws://%s:%d/ws", peer.getHost(), peer.getPort());
            String json = UnifiedJsonUtil.toJson(root); // just resend original message frame
            serverLinkClient.sendJson(peer.getServerId(), url, json);
            log.info("[file/forward] {} {} -> {} via {}", type, fromUser, toUser, destServer);
        } catch (Exception e) {
            log.warn("[file/forward] FAIL {} -> {} err={}", fromUser, toUser, e.toString());
        }
    }



    /** Handle LIST request */
    private void handleListRequest(WebSocketSession session, String fromUser) {
        List<Map<String, Object>> users = new ArrayList<>();
        for (var u : userLoginDirectory.listAll()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("server_id", u.getServerId());
            m.put("user_id", u.getUserId());
            m.put("user_name", u.getDisplayName());
            users.add(m);
        }

        ProtocolMessage resp = MessageProcessingUtil.createMessage("LIST_RESULT", myServerId, fromUser, 
            Map.of("count", users.size(), "users", users));

        try {
            sendSignedMessage(session, resp);
        } catch (Exception e) {
            log.warn("Failed to send LIST_RESULT to {}: {}", fromUser, e.toString());
        }
    }

    private void handleAck(JsonNode root) {
        log.info("[ACK] from={} msg_ref={}",
            MessageProcessingUtil.getStringField(root, "from", "?"),
            MessageProcessingUtil.getStringField(root.path("payload"), "msg_ref", null));
    }

    private void handleError(JsonNode root) {
        log.warn("[ERROR FRAME] from={} code={} detail={}",
            MessageProcessingUtil.getStringField(root, "from", "?"),
            MessageProcessingUtil.getStringField(root.path("payload"), "code", null),
            MessageProcessingUtil.getStringField(root.path("payload"), "detail", null));
        if (log.isTraceEnabled()) log.trace("[ERROR FRAME/full] {}", formatJsonForLog(root));
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) {
        String userId = sessionUser.remove(session.getId());
        log.info("[ws/close] sid={} user={} code={} reason={}", safeSessionId(session), userId, status.getCode(), status.getReason());
        if (userId != null) {
            sessionRegistry.removeIf(userId, session);
            userPresenceService.logoutHereAndBroadcast(userId, "disconnect");
            try { publicChannelService.onUserOffline(userId); } catch (Exception ex) { log.warn("[ws/close] onUserOffline err={}", ex.toString()); }
        }
    }


    private void handlePublicMessage(JsonNode root) {
        String userId = MessageProcessingUtil.getStringField(root, "from", "*");
        publicChannelService.sendPublicMessage(userId, root);
    }

    private void handleServerPublicDeliverBroadcast(JsonNode root) {
        publicChannelService.handleServerPublicDeliverBroadcast(root);
    }



    // ----------------- helpers -----------------
    private int safePeersCount() { try { return peerDir.snapshotPeersExcept("__none__").size(); } catch (Throwable t) { return -1; } }
    private int safeSessions() { try { return sessionRegistry.snapshot().size(); } catch (Throwable t) { return -1; } }
    private static String safeStr(String s) { return s==null?"null":s; }
}
