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
            log.debug("Starting operation: {} with params: {}", operation, java.util.Arrays.toString(params));
        }
    }
    
    /**
     * Log operation completion
     */
    protected void logOperationComplete(String operation, Object result) {
        if (log.isDebugEnabled()) {
            log.debug("Completed operation: {} with result: {}", operation, result);
        }
    }
    
    /**
     * Log operation error
     */
    protected void logOperationError(String operation, Exception e) {
        log.error("Operation failed: {}", operation, e);
    }
    
    /**
     * Execute database operation with transaction
     */
    protected <T> T executeWithTransaction(DatabaseOperation<T> dbOp) {
        try {
            logOperationStart("Database operation");
            T result = dbOp.execute();
            logOperationComplete("Database operation", result);
            return result;
        } catch (Exception e) {
            logOperationError("Database operation", e);
            throw new RuntimeException("Database operation failed", e);
        }
    }
    
    /**
     * Execute void database operation with transaction
     */
    protected void executeWithTransaction(VoidDatabaseOperation dbOp) {
        try {
            logOperationStart("Void database operation");
            dbOp.execute();
            logOperationComplete("Void database operation", "success");
        } catch (Exception e) {
            logOperationError("Void database operation", e);
            throw new RuntimeException("Database operation failed", e);
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
     * Void database operation interface
     */
    @FunctionalInterface
    protected interface VoidDatabaseOperation {
        void execute() throws Exception;
    }
    
    /**
     * Check operation result
     */
    protected void checkOperationResult(int rows, String operation) {
        if (rows <= 0) {
            throw new IllegalStateException(operation + " failed: no rows affected");
        }
    }
    
    /**
     * Check operation result allowing zero rows
     */
    protected void checkOperationResultAllowZero(int rows, String operation) {
        if (rows < 0) {
            throw new IllegalStateException(operation + " failed: negative rows affected");
        }
    }
    
    /**
     * Get value or default
     */
    protected <T> T getOrDefault(T value, T defaultValue) {
        return value != null ? value : defaultValue;
    }
    
    /**
     * Get string value or default
     */
    protected String getStringOrDefault(String value, String defaultValue) {
        return (value != null && !value.isBlank()) ? value : defaultValue;
    }
}
