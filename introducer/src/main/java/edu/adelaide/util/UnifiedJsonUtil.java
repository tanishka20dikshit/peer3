package edu.adelaide.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

/**
 * Unified JSON processing utility class that integrates Jackson and Gson functionality
 * Solves the problem of mixed JSON processing libraries in the project
 */
public final class UnifiedJsonUtil {
    
    private static final Logger log = LoggerFactory.getLogger(UnifiedJsonUtil.class);
    
    // Thread-safe ObjectMapper instances
    private static final ObjectMapper DEFAULT_MAPPER = createDefaultMapper();
    private static final ObjectMapper PRETTY_MAPPER = createPrettyMapper();
    
    private UnifiedJsonUtil() {}
    
    /**
     * Create default ObjectMapper
     */
    private static ObjectMapper createDefaultMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
        return mapper;
    }
    
    /**
     * Create formatted output ObjectMapper
     */
    private static ObjectMapper createPrettyMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
        mapper.configure(SerializationFeature.INDENT_OUTPUT, true);
        return mapper;
    }
    
    /**
     * Convert object to JSON string
     */
    public static String toJson(Object obj) {
        Objects.requireNonNull(obj, "Object cannot be null");
        try {
            return DEFAULT_MAPPER.writeValueAsString(obj);
        } catch (JsonProcessingException e) {
            log.error("Failed to serialize object to JSON", e);
            throw new RuntimeException("JSON serialization failed", e);
        }
    }
    
    /**
     * Convert object to formatted JSON string
     */
    public static String toPrettyJson(Object obj) {
        Objects.requireNonNull(obj, "Object cannot be null");
        try {
            return PRETTY_MAPPER.writeValueAsString(obj);
        } catch (JsonProcessingException e) {
            log.error("Failed to serialize object to pretty JSON", e);
            throw new RuntimeException("JSON serialization failed", e);
        }
    }
    
    /**
     * Convert JSON string to object
     */
    public static <T> T fromJson(String json, Class<T> clazz) {
        Objects.requireNonNull(json, "JSON string cannot be null");
        Objects.requireNonNull(clazz, "Class cannot be null");
        try {
            return DEFAULT_MAPPER.readValue(json, clazz);
        } catch (JsonProcessingException e) {
            log.error("Failed to deserialize JSON to object", e);
            throw new RuntimeException("JSON deserialization failed", e);
        }
    }
    
    /**
     * Safely parse JSON string, return null on failure
     */
    public static <T> T tryFromJson(String json, Class<T> clazz) {
        try {
            return fromJson(json, clazz);
        } catch (Exception e) {
            log.debug("Failed to parse JSON safely: {}", e.getMessage());
            return null;
        }
    }
    
    /**
     * Parse JSON string to JsonNode
     */
    public static JsonNode parseJson(String json) {
        Objects.requireNonNull(json, "JSON string cannot be null");
        try {
            return DEFAULT_MAPPER.readTree(json);
        } catch (JsonProcessingException e) {
            log.error("Failed to parse JSON string", e);
            throw new RuntimeException("JSON parsing failed", e);
        }
    }
    
    /**
     * Safely parse JSON string to JsonNode, return null on failure
     */
    public static JsonNode tryParseJson(String json) {
        try {
            return parseJson(json);
        } catch (Exception e) {
            log.debug("Failed to parse JSON safely: {}", e.getMessage());
            return null;
        }
    }
    
    /**
     * Validate if JSON string is valid
     */
    public static boolean isValidJson(String json) {
        if (json == null || json.trim().isEmpty()) {
            return false;
        }
        try {
            DEFAULT_MAPPER.readTree(json);
            return true;
        } catch (JsonProcessingException e) {
            return false;
        }
    }
    
    /**
     * Convert object to JsonNode
     */
    public static JsonNode toJsonNode(Object obj) {
        Objects.requireNonNull(obj, "Object cannot be null");
        return DEFAULT_MAPPER.valueToTree(obj);
    }
    
    /**
     * Convert JsonNode to object
     */
    public static <T> T fromJsonNode(JsonNode node, Class<T> clazz) {
        Objects.requireNonNull(node, "JsonNode cannot be null");
        Objects.requireNonNull(clazz, "Class cannot be null");
        try {
            return DEFAULT_MAPPER.treeToValue(node, clazz);
        } catch (JsonProcessingException e) {
            log.error("Failed to convert JsonNode to object", e);
            throw new RuntimeException("JsonNode conversion failed", e);
        }
    }
    
    /**
     * Create canonical JSON string (for signing)
     * Remove signature field and sort keys
     */
    public static String createCanonicalJson(JsonNode node) {
        Objects.requireNonNull(node, "JsonNode cannot be null");
        try {
            // Remove signature field
            ObjectNode canonical = node.deepCopy();
            if (canonical.has("sig")) {
                canonical.remove("sig");
            }
            
            // Use default mapper output to ensure consistent key order
            return DEFAULT_MAPPER.writeValueAsString(canonical);
        } catch (JsonProcessingException e) {
            log.error("Failed to create canonical JSON", e);
            throw new RuntimeException("Canonical JSON creation failed", e);
        }
    }
    
    /**
     * Format JSON for log output
     */
    public static String formatForLog(Object obj) {
        if (obj == null) {
            return "null";
        }
        try {
            return toPrettyJson(obj);
        } catch (Exception e) {
            return obj.toString();
        }
    }
    
    /**
     * Get default ObjectMapper instance
     */
    public static ObjectMapper getDefaultMapper() {
        return DEFAULT_MAPPER;
    }
    
    /**
     * Get formatted ObjectMapper instance
     */
    public static ObjectMapper getPrettyMapper() {
        return PRETTY_MAPPER;
    }
}
