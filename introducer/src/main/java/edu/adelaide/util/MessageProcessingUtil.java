package edu.adelaide.util;

import com.fasterxml.jackson.databind.JsonNode;
import edu.adelaide.model.ProtocolMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Map;

/**
 * Message processing utility class that provides common message construction, validation, and processing functionality
 */
public final class MessageProcessingUtil {
    
    private static final Logger log = LoggerFactory.getLogger(MessageProcessingUtil.class);
    
    private MessageProcessingUtil() {}
    
    /**
     * Create protocol message
     */
    @SuppressWarnings("unchecked")
    public static ProtocolMessage createMessage(String type, String from, String to, Object payload) {
        ProtocolMessage message = new ProtocolMessage();
        message.setType(type);
        message.setFrom(from);
        message.setTo(to);
        message.setTs(Instant.now().toEpochMilli());
        if (payload instanceof Map) {
            message.setPayload((Map<String, Object>) payload);
        } else {
            // For non-Map type payloads, need to convert to Map or use other processing methods
            log.warn("Payload is not a Map, type: {}", payload != null ? payload.getClass() : "null");
        }
        return message;
    }
    
    /**
     * Create error message
     */
    public static ProtocolMessage createErrorMessage(String from, String to, String code, String detail) {
        Map<String, Object> errorPayload = Map.of(
            "code", code,
            "detail", detail
        );
        return createMessage("ERROR", from, to, errorPayload);
    }
    
    /**
     * Create acknowledgment message
     */
    public static ProtocolMessage createAckMessage(String from, String to, String originalType) {
        Map<String, Object> ackPayload = Map.of(
            "original_type", originalType,
            "status", "ack"
        );
        return createMessage("ACK", from, to, ackPayload);
    }
    
    /**
     * Validate message
     */
    public static boolean validateMessage(ProtocolMessage message) {
        if (message == null) {
            log.warn("Message is null");
            return false;
        }
        
        if (isBlank(message.getType())) {
            log.warn("Message type is blank");
            return false;
        }
        
        if (isBlank(message.getFrom())) {
            log.warn("Message from is blank");
            return false;
        }
        
        if (message.getTs() <= 0) {
            log.warn("Message timestamp is invalid: {}", message.getTs());
            return false;
        }
        
        return true;
    }
    
    /**
     * Validate protocol message with additional checks
     */
    public static boolean validateProtocolMessage(ProtocolMessage message) {
        if (!validateMessage(message)) {
            return false;
        }
        
        // Additional protocol-specific validations
        if (!isValidTimestamp(message.getTs())) {
            log.warn("Message timestamp is too old or in the future: {}", message.getTs());
            return false;
        }
        
        return true;
    }
    
    /**
     * Get string field from JsonNode with default value
     */
    public static String getStringField(JsonNode node, String fieldName, String defaultValue) {
        if (node == null || !node.has(fieldName)) {
            return defaultValue;
        }
        JsonNode fieldNode = node.get(fieldName);
        return fieldNode.isNull() ? defaultValue : fieldNode.asText(defaultValue);
    }
    
    /**
     * Get required string field from JsonNode
     */
    public static String getRequiredStringField(JsonNode node, String fieldName) {
        if (node == null || !node.has(fieldName)) {
            throw new IllegalArgumentException("Required field '" + fieldName + "' is missing");
        }
        JsonNode fieldNode = node.get(fieldName);
        if (fieldNode.isNull()) {
            throw new IllegalArgumentException("Required field '" + fieldName + "' is null");
        }
        return fieldNode.asText();
    }
    
    /**
     * Get long field from JsonNode with default value
     */
    public static long getLongField(JsonNode node, String fieldName, long defaultValue) {
        if (node == null || !node.has(fieldName)) {
            return defaultValue;
        }
        JsonNode fieldNode = node.get(fieldName);
        return fieldNode.isNull() ? defaultValue : fieldNode.asLong(defaultValue);
    }
    
    /**
     * Get int field from JsonNode with default value
     */
    public static int getIntField(JsonNode node, String fieldName, int defaultValue) {
        if (node == null || !node.has(fieldName)) {
            return defaultValue;
        }
        JsonNode fieldNode = node.get(fieldName);
        return fieldNode.isNull() ? defaultValue : fieldNode.asInt(defaultValue);
    }
    
    /**
     * Get boolean field from JsonNode with default value
     */
    public static boolean getBooleanField(JsonNode node, String fieldName, boolean defaultValue) {
        if (node == null || !node.has(fieldName)) {
            return defaultValue;
        }
        JsonNode fieldNode = node.get(fieldName);
        return fieldNode.isNull() ? defaultValue : fieldNode.asBoolean(defaultValue);
    }
    
    /**
     * Get object field from JsonNode
     */
    public static JsonNode getObjectField(JsonNode node, String fieldName) {
        if (node == null || !node.has(fieldName)) {
            return null;
        }
        return node.get(fieldName);
    }
    
    /**
     * Check if field exists and is not empty
     */
    public static boolean hasNonEmptyField(JsonNode node, String fieldName) {
        if (node == null || !node.has(fieldName)) {
            return false;
        }
        JsonNode fieldNode = node.get(fieldName);
        return !fieldNode.isNull() && !fieldNode.asText().trim().isEmpty();
    }
    
    /**
     * Extract message information for logging
     */
    public static MessageInfo extractMessageInfo(ProtocolMessage message) {
        return new MessageInfo(
            message.getType(),
            message.getFrom(),
            message.getTo(),
            message.getTs(),
            message.getPayload() != null ? message.getPayload().size() : 0
        );
    }
    
    /**
     * Message information for logging
     */
    public static class MessageInfo {
        private final String type;
        private final String from;
        private final String to;
        private final Long timestamp;
        private final int payloadSize;
        
        public MessageInfo(String type, String from, String to, Long timestamp, int payloadSize) {
            this.type = type;
            this.from = from;
            this.to = to;
            this.timestamp = timestamp;
            this.payloadSize = payloadSize;
        }
        
        public String getType() { return type; }
        public String getFrom() { return from; }
        public String getTo() { return to; }
        public Long getTimestamp() { return timestamp; }
        public int getPayloadSize() { return payloadSize; }
        
        @Override
        public String toString() {
            return String.format("MessageInfo{type='%s', from='%s', to='%s', ts=%d, payloadSize=%d}",
                type, from, to, timestamp, payloadSize);
        }
    }
    
    /**
     * Validate timestamp (not too old, not in the future)
     */
    public static boolean isValidTimestamp(long timestamp) {
        long now = Instant.now().toEpochMilli();
        long fiveMinutesAgo = now - (5 * 60 * 1000);
        long fiveMinutesFromNow = now + (5 * 60 * 1000);
        
        return timestamp >= fiveMinutesAgo && timestamp <= fiveMinutesFromNow;
    }
    
    /**
     * Create log prefix for message processing
     */
    public static String createLogPrefix(String handlerName, String messageType) {
        return String.format("[%s:%s]", handlerName, messageType);
    }
    
    /**
     * Safe string equality check
     */
    public static boolean safeEquals(String a, String b) {
        if (a == null && b == null) return true;
        if (a == null || b == null) return false;
        return a.equals(b);
    }
    
    /**
     * Check if string is blank
     */
    public static boolean isBlank(String str) {
        return str == null || str.trim().isEmpty();
    }
    
    /**
     * Check if string is not blank
     */
    public static boolean isNotBlank(String str) {
        return !isBlank(str);
    }
}
