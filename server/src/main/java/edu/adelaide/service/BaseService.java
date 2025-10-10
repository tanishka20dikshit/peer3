package edu.adelaide.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

/**
 * Base service class that provides common parameter validation, exception handling, and logging functionality
 */
public abstract class BaseService {
    
    protected final Logger log = LoggerFactory.getLogger(getClass());
    
    /**
     * Validate string parameter is not blank
     */
    protected void validateNotBlank(String value, String paramName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(paramName + " cannot be null or blank");
        }
    }
    
    /**
     * Validate object parameter is not null
     */
    protected void validateNotNull(Object value, String paramName) {
        Objects.requireNonNull(value, paramName + " cannot be null");
    }
    
    /**
     * Validate ID parameter
     */
    protected void validateId(String id, String paramName) {
        validateNotBlank(id, paramName);
        if (id.trim().isEmpty()) {
            throw new IllegalArgumentException(paramName + " cannot be empty");
        }
    }
    
    /**
     * Validate composite primary key
     */
    protected void validateCompositeKey(String key1, String key2, String paramName1, String paramName2) {
        validateId(key1, paramName1);
        validateId(key2, paramName2);
    }
    
    /**
     * Log operation start
     */
    protected void logOperationStart(String operation, Object... params) {
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder("Starting ").append(operation);
            if (params.length > 0) {
                sb.append(" with params: ");
                for (int i = 0; i < params.length; i += 2) {
                    if (i + 1 < params.length) {
                        sb.append(params[i]).append("=").append(params[i + 1]);
                        if (i + 2 < params.length) {
                            sb.append(", ");
                        }
                    }
                }
            }
            log.debug(sb.toString());
        }
    }
    
    /**
     * Log operation completion
     */
    protected void logOperationComplete(String operation, Object result) {
        if (log.isDebugEnabled()) {
            log.debug("Completed {} with result: {}", operation, result);
        }
    }
    
    /**
     * Log operation failure
     */
    protected void logOperationError(String operation, Exception e) {
        log.error("Failed to execute {}: {}", operation, e.getMessage(), e);
    }
    
    /**
     * Safely execute database operation
     */
    protected <T> T executeWithTransaction(String operation, DatabaseOperation<T> dbOp) {
        logOperationStart(operation);
        try {
            T result = dbOp.execute();
            logOperationComplete(operation, result);
            return result;
        } catch (Exception e) {
            logOperationError(operation, e);
            throw new RuntimeException("Database operation failed: " + operation, e);
        }
    }
    
    /**
     * Safely execute database operation (no return value)
     */
    protected void executeWithTransaction(String operation, VoidDatabaseOperation dbOp) {
        logOperationStart(operation);
        try {
            dbOp.execute();
            logOperationComplete(operation, "success");
        } catch (Exception e) {
            logOperationError(operation, e);
            throw new RuntimeException("Database operation failed: " + operation, e);
        }
    }
    
    /**
     * Database operation interface
     */
    @FunctionalInterface
    protected interface DatabaseOperation<T> {
        T execute() throws Exception;
    }
    
    /**
     * Database operation interface with no return value
     */
    @FunctionalInterface
    protected interface VoidDatabaseOperation {
        void execute() throws Exception;
    }
    
    /**
     * Check operation result
     */
    protected void checkOperationResult(int affectedRows, String operation) {
        if (affectedRows <= 0) {
            throw new IllegalStateException(operation + " failed: no rows affected");
        }
    }
    
    /**
     * Check operation result (allow 0 rows affected)
     */
    protected void checkOperationResultAllowZero(int affectedRows, String operation) {
        if (affectedRows < 0) {
            throw new IllegalStateException(operation + " failed: negative rows affected");
        }
    }
    
    /**
     * Safely get object or default value
     */
    protected <T> T getOrDefault(T value, T defaultValue) {
        return value != null ? value : defaultValue;
    }
    
    /**
     * Safely get string or default value
     */
    protected String getStringOrDefault(String value, String defaultValue) {
        return (value != null && !value.isBlank()) ? value : defaultValue;
    }
}
