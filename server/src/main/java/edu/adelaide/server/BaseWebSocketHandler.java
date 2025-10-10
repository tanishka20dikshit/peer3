package edu.adelaide.server;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import edu.adelaide.dto.ProtocolMessage;
import edu.adelaide.util.SoCpSigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;

import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;

/**
 * Base WebSocket handler that extracts common functionality for JSON processing, signature verification, and message sending
 */
public abstract class BaseWebSocketHandler extends TextWebSocketHandler {
    
    protected static final Logger log = LoggerFactory.getLogger(BaseWebSocketHandler.class);
    protected final ObjectMapper objectMapper = new ObjectMapper();
    protected final RSAPrivateKey privateKey;
    
    public BaseWebSocketHandler(RSAPrivateKey privateKey) {
        this.privateKey = privateKey;
    }
    
    /**
     * Safely parse JSON message
     */
    protected JsonNode parseJsonSafely(String rawMessage, String handlerName) {
        try {
            if (rawMessage == null || rawMessage.trim().isEmpty()) {
                log.warn("[{}] Empty message received", handlerName);
                return null;
            }
            return objectMapper.readTree(rawMessage);
        } catch (Exception e) {
            log.warn("[{}] Failed to parse JSON: {}", handlerName, e.getMessage());
            return null;
        }
    }
    
    /**
     * Verify message signature
     */
    protected boolean verifySignature(JsonNode root, String fromServer, String handlerName) {
        try {
            String sigB64u = root.path("sig").asText(null);
            if (sigB64u == null || sigB64u.isBlank()) {
                log.warn("[{}] Missing signature from {}", handlerName, fromServer);
                return false;
            }
            
            // Build canonicalized JSON (remove signature field)
            ObjectNode unsigned = root.deepCopy();
            unsigned.remove("sig");
            byte[] canonical = SoCpSigner.canonicalBytesFromJson(objectMapper.writeValueAsString(unsigned));
            
            // TODO: Implement actual key management logic
            // For now, return true. Actual implementation should get public key from PeerDirectory for verification
            return true;
        } catch (Exception e) {
            log.warn("[{}] Signature verification failed for {}: {}", handlerName, fromServer, e.getMessage());
            return false;
        }
    }
    
    /**
     * Send signed message
     */
    protected void sendSignedMessage(WebSocketSession session, ProtocolMessage message) {
        try {
            JsonNode unsigned = objectMapper.valueToTree(message);
            if (unsigned.has("sig")) {
                ((ObjectNode) unsigned).remove("sig");
            }
            
            String payloadJson = objectMapper.writeValueAsString(unsigned.path("payload"));
            String sig = SoCpSigner.signB64u(payloadJson.getBytes(java.nio.charset.StandardCharsets.UTF_8), privateKey);
            ((ObjectNode) unsigned).put("sig", sig);
            
            String json = unsigned.toString();
            session.sendMessage(new TextMessage(json));
            
            log.debug("[sendSigned] Sent message type={} to={}", message.getType(), message.getTo());
        } catch (Exception e) {
            log.warn("[sendSigned] Failed to send message: {}", e.getMessage());
        }
    }
    
    /**
     * Send error message
     */
    protected void sendErrorMessage(WebSocketSession session, String to, String code, String detail) {
        try {
            ProtocolMessage error = new ProtocolMessage();
            error.setType("ERROR");
            error.setFrom(getServerId());
            error.setTo(to);
            error.setTs(Instant.now().toEpochMilli());
            error.setPayload(Map.of("code", code, "detail", detail));
            
            sendSignedMessage(session, error);
            log.debug("[sendError] Sent error code={} to={}", code, to);
        } catch (Exception e) {
            log.warn("[sendError] Failed to send error message: {}", e.getMessage());
        }
    }
    
    /**
     * Safely get session ID
     */
    protected static String safeSessionId(WebSocketSession session) {
        try {
            return session == null ? "null" : session.getId();
        } catch (Exception e) {
            return "?";
        }
    }
    
    /**
     * Safely get remote address
     */
    protected static String safeRemoteAddress(WebSocketSession session) {
        try {
            return session == null ? "null" : Objects.toString(session.getRemoteAddress());
        } catch (Exception e) {
            return "?";
        }
    }
    
    /**
     * Format JSON for log output
     */
    protected String formatJsonForLog(Object obj) {
        try {
            return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(obj);
        } catch (Exception e) {
            return String.valueOf(obj);
        }
    }
    
    /**
     * Get server ID (subclasses need to implement)
     */
    protected abstract String getServerId();
    
    /**
     * Handle connection established
     */
    @Override
    public void afterConnectionEstablished(WebSocketSession session) {
        log.info("[{}] Connection established: sid={} remote={}", 
            getClass().getSimpleName(), safeSessionId(session), safeRemoteAddress(session));
    }
    
    /**
     * Handle connection closed
     */
    @Override
    public void afterConnectionClosed(WebSocketSession session, org.springframework.web.socket.CloseStatus status) {
        log.info("[{}] Connection closed: sid={} code={} reason={}", 
            getClass().getSimpleName(), safeSessionId(session), status.getCode(), status.getReason());
    }
}
