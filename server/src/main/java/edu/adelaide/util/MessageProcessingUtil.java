package edu.adelaide.util;

import com.fasterxml.jackson.databind.JsonNode;
import edu.adelaide.dto.ProtocolMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;

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
    public static ProtocolMessage createAckMessage(String from, String to, String msgRef) {
        Map<String, Object> ackPayload = Map.of("msg_ref", msgRef);
        return createMessage("ACK", from, to, ackPayload);
    }
    
    /**
     * Validate message basic fields
     */
    public static boolean validateMessage(JsonNode message, String... requiredFields) {
        if (message == null || !message.isObject()) {
            log.warn("Message is null or not an object");
            return false;
        }
        
        for (String field : requiredFields) {
            if (!message.has(field) || message.get(field).isNull()) {
                log.warn("Missing required field: {}", field);
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Validate protocol message
     */
    public static boolean validateProtocolMessage(JsonNode message) {
        return validateMessage(message, "type", "from", "to", "ts");
    }
    
    /**
     * Safely get string field
     */
    public static String getStringField(JsonNode node, String fieldName, String defaultValue) {
        if (node == null || !node.has(fieldName)) {
            return defaultValue;
        }
        JsonNode field = node.get(fieldName);
        return field.isNull() ? defaultValue : field.asText(defaultValue);
    }
    
    /**
     * Safely get string field (not allowed to be empty)
     */
    public static String getRequiredStringField(JsonNode node, String fieldName) {
        String value = getStringField(node, fieldName, null);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Required field '" + fieldName + "' is missing or empty");
        }
        return value;
    }
    
    /**
     * Safely get long field
     */
    public static long getLongField(JsonNode node, String fieldName, long defaultValue) {
        if (node == null || !node.has(fieldName)) {
            return defaultValue;
        }
        JsonNode field = node.get(fieldName);
        return field.isNull() ? defaultValue : field.asLong(defaultValue);
    }
    
    /**
     * Safely get integer field
     */
    public static int getIntField(JsonNode node, String fieldName, int defaultValue) {
        if (node == null || !node.has(fieldName)) {
            return defaultValue;
        }
        JsonNode field = node.get(fieldName);
        return field.isNull() ? defaultValue : field.asInt(defaultValue);
    }
    
    /**
     * Safely get boolean field
     */
    public static boolean getBooleanField(JsonNode node, String fieldName, boolean defaultValue) {
        if (node == null || !node.has(fieldName)) {
            return defaultValue;
        }
        JsonNode field = node.get(fieldName);
        return field.isNull() ? defaultValue : field.asBoolean(defaultValue);
    }
    
    /**
     * Safely get object field
     */
    public static JsonNode getObjectField(JsonNode node, String fieldName) {
        if (node == null || !node.has(fieldName)) {
            return null;
        }
        JsonNode field = node.get(fieldName);
        return field.isNull() ? null : field;
    }
    
    /**
     * Check if field exists and is not empty
     */
    public static boolean hasNonEmptyField(JsonNode node, String fieldName) {
        if (node == null || !node.has(fieldName)) {
            return false;
        }
        JsonNode field = node.get(fieldName);
        if (field.isNull()) {
            return false;
        }
        if (field.isTextual()) {
            return !field.asText().isBlank();
        }
        return true;
    }
    
    /**
     * Extract message basic information
     */
    public static MessageInfo extractMessageInfo(JsonNode message) {
        if (message == null) {
            return null;
        }
        
        String type = getStringField(message, "type", null);
        String from = getStringField(message, "from", null);
        String to = getStringField(message, "to", null);
        long timestamp = getLongField(message, "ts", 0L);
        
        return new MessageInfo(type, from, to, timestamp);
    }
    
    /**
     * Message information class
     */
    public static class MessageInfo {
        private final String type;
        private final String from;
        private final String to;
        private final long timestamp;
        
        public MessageInfo(String type, String from, String to, long timestamp) {
            this.type = type;
            this.from = from;
            this.to = to;
            this.timestamp = timestamp;
        }
        
        public String getType() { return type; }
        public String getFrom() { return from; }
        public String getTo() { return to; }
        public long getTimestamp() { return timestamp; }
        
        @Override
        public String toString() {
            return String.format("MessageInfo{type='%s', from='%s', to='%s', timestamp=%d}", 
                type, from, to, timestamp);
        }
    }
    
    /**
     * Validate if timestamp is within reasonable range
     */
    public static boolean isValidTimestamp(long timestamp) {
        long now = Instant.now().toEpochMilli();
        long oneHour = 60 * 60 * 1000L;
        
        // Allow 1 hour time deviation
        return Math.abs(now - timestamp) <= oneHour;
    }
    
    /**
     * Create message log prefix
     */
    public static String createLogPrefix(String messageType, String from, String to) {
        return String.format("[%s] from=%s to=%s", messageType, from, to);
    }
    
    /**
     * Safely compare two strings
     */
    public static boolean safeEquals(String a, String b) {
        return Objects.equals(a, b);
    }
    
    /**
     * Check if string is blank or empty
     */
    public static boolean isBlank(String str) {
        return str == null || str.isBlank();
    }
    
    /**
     * Check if string is not blank and not empty
     */
    public static boolean isNotBlank(String str) {
        return str != null && !str.isBlank();
    }
}
