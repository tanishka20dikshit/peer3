package edu.adelaide.server;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import edu.adelaide.model.ProtocolMessage;
import edu.adelaide.util.UnifiedCryptoUtil;
import edu.adelaide.util.UnifiedJsonUtil;
import edu.adelaide.util.MessageProcessingUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;
import org.springframework.lang.NonNull;

import java.security.interfaces.RSAPrivateKey;
import java.util.Objects;

/**
 * Base WebSocket handler that extracts common functionality for JSON processing, signature verification, and message sending
 */
public abstract class BaseWebSocketHandler extends TextWebSocketHandler {
    
    protected static final Logger log = LoggerFactory.getLogger(BaseWebSocketHandler.class);
    protected final ObjectMapper objectMapper = UnifiedJsonUtil.getDefaultMapper();
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
            return UnifiedJsonUtil.parseJson(rawMessage);
        } catch (Exception e) {
            log.warn("[{}] Failed to parse JSON: {}", handlerName, e.getMessage());
            return null;
        }
    }
    
    /**
     * Verify message signature
     */
    protected boolean verifySignature(JsonNode message, String signature, String publicKeyB64) {
        try {
            if (MessageProcessingUtil.isBlank(signature) || MessageProcessingUtil.isBlank(publicKeyB64)) {
                return false;
            }
            
            // Create canonical JSON for verification
            String canonicalJson = UnifiedJsonUtil.createCanonicalJson(message);
            byte[] canonicalBytes = canonicalJson.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            
            // Load public key and verify
            var publicKey = UnifiedCryptoUtil.loadRSAPublicKeyFromBase64Url(publicKeyB64);
            return UnifiedCryptoUtil.rsaVerify(canonicalBytes, signature, publicKey);
        } catch (Exception e) {
            log.warn("Signature verification failed: {}", e.getMessage());
            return false;
        }
    }
    
    /**
     * Send signed message
     */
    protected void sendSignedMessage(WebSocketSession session, ProtocolMessage message) throws Exception {
        Objects.requireNonNull(session, "WebSocket session cannot be null");
        Objects.requireNonNull(message, "Message cannot be null");
        
        // Create unsigned message
        JsonNode unsignedNode = UnifiedJsonUtil.toJsonNode(message);
        if (unsignedNode.has("sig")) {
            ((ObjectNode) unsignedNode).remove("sig");
        }
        
        // Create canonical JSON and sign
        String canonicalJson = UnifiedJsonUtil.createCanonicalJson(unsignedNode);
        byte[] canonicalBytes = canonicalJson.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        String signature = UnifiedCryptoUtil.rsaSign(canonicalBytes, privateKey);
        
        // Add signature to message
        ((ObjectNode) unsignedNode).put("sig", signature);
        
        // Send message
        String jsonMessage = UnifiedJsonUtil.toJson(unsignedNode);
        session.sendMessage(new TextMessage(jsonMessage));
        
        log.debug("Sent signed message: type={}, to={}", message.getType(), message.getTo());
    }
    
    /**
     * Send error message
     */
    protected void sendErrorMessage(WebSocketSession session, String to, String code, String detail) throws Exception {
        ProtocolMessage errorMessage = MessageProcessingUtil.createErrorMessage(
            getServerId(), 
            MessageProcessingUtil.isBlank(to) ? "*" : to, 
            code, 
            detail
        );
        sendSignedMessage(session, errorMessage);
        log.warn("Sent error message: code={}, detail={}", code, detail);
    }
    
    /**
     * Get safe session ID
     */
    protected String safeSessionId(WebSocketSession session) {
        if (session == null) return "null";
        try {
            return session.getId();
        } catch (Exception e) {
            return "?";
        }
    }
    
    /**
     * Get safe remote address
     */
    protected String safeRemoteAddress(WebSocketSession session) {
        if (session == null) {
            return "unknown";
        }
        try {
            var remoteAddr = session.getRemoteAddress();
            return remoteAddr != null ? remoteAddr.toString() : "unknown";
        } catch (Exception e) {
            return "unknown";
        }
    }
    
    /**
     * Format JSON for logging
     */
    protected String formatJsonForLog(Object obj) {
        return UnifiedJsonUtil.formatForLog(obj);
    }
    
    /**
     * Get server ID (to be implemented by subclasses)
     */
    protected abstract String getServerId();
    
    @Override
    public void afterConnectionEstablished(@NonNull WebSocketSession session) throws Exception {
        log.info("WebSocket connection established: id={}, remote={}", 
            safeSessionId(session), safeRemoteAddress(session));
        super.afterConnectionEstablished(session);
    }
    
    @Override
    public void afterConnectionClosed(@NonNull WebSocketSession session, @NonNull org.springframework.web.socket.CloseStatus status) throws Exception {
        log.info("WebSocket connection closed: id={}, status={}", 
            safeSessionId(session), status);
        super.afterConnectionClosed(session, status);
    }
}
