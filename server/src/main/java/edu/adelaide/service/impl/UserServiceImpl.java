package edu.adelaide.service.impl;

import edu.adelaide.dto.CreateUserRequest;
import edu.adelaide.dto.PageResult;
import edu.adelaide.entity.UserInfo;
import edu.adelaide.service.BaseService;
import edu.adelaide.service.UserService;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory implementation of UserService for demo purposes.
 * In production, this would use a real database.
 */
@Service
public class UserServiceImpl extends BaseService implements UserService {

    private final Map<String, UserInfo> localUsers = new ConcurrentHashMap<>();

    @Override
    public String createUser(CreateUserRequest request) {
        return executeWithTransaction("createUser", () -> {
            validateNotNull(request, "CreateUserRequest");
            validateNotBlank(request.getUsername(), "username");
            
            UserInfo user = new UserInfo();
            user.setUserId(UUID.randomUUID().toString()); // Spec 5.1 UUIDv4
            user.setUsername(request.getUsername());
            user.setEmail(request.getEmail());
            user.setPhoneNumber(request.getPhoneNumber());
            user.setPassword(request.getPassword());
            user.setCreateTime(new Date());
            user.setUpdateTime(new Date());
            localUsers.put(user.getUserId(), user);
            return user.getUserId();
        });
    }

    @Override
    public Optional<UserInfo> findByUserId(String userId) {
        validateId(userId, "userId");
        return Optional.ofNullable(localUsers.get(userId));
    }

    @Override
    public Optional<List<UserInfo>> findByUsername(String username) {
        validateNotBlank(username, "username");
        List<UserInfo> matches = new ArrayList<>();
        for (UserInfo u : localUsers.values()) {
            if (u.getUsername() != null && u.getUsername().equalsIgnoreCase(username)) {
                matches.add(u);
            }
        }
        return matches.isEmpty() ? Optional.empty() : Optional.of(matches);
    }

    @Override
    public List<UserInfo> listUsers(int page, int size) {
        if (page < 0 || size <= 0) {
            throw new IllegalArgumentException("Page must be >= 0 and size must be > 0");
        }
        return new ArrayList<>(localUsers.values())
                .subList(page * size, Math.min((page + 1) * size, localUsers.size()));
    }

    @Override
    public boolean existsByUserId(String userId) {
        validateId(userId, "userId");
        return localUsers.containsKey(userId);
    }

    @Override
    public PageResult<UserInfo> pageAll(int page, int size) {
        if (page < 0 || size <= 0) {
            throw new IllegalArgumentException("Page must be >= 0 and size must be > 0");
        }
        List<UserInfo> all = new ArrayList<>(localUsers.values());
        int total = all.size();
        int from = Math.min(page * size, total);
        int to = Math.min(from + size, total);
        return new PageResult<>(page, size, total, all.subList(from, to));
    }

    @Override
    public boolean userExists(String userId) {
        validateId(userId, "userId");
        return localUsers.containsKey(userId);
    }

    @Override
    public UserInfo registerLocalUser(String userId, Map<String, Object> payload) {
        return executeWithTransaction("registerLocalUser", () -> {
            validateNotNull(payload, "payload");
            
            UserInfo user = new UserInfo();
            user.setUserId(userId != null ? userId : UUID.randomUUID().toString());
            user.setUsername((String) payload.getOrDefault("username", "anonymous"));
            user.setEmail((String) payload.get("email"));
            user.setPhoneNumber((String) payload.get("phone"));
            user.setCreateTime(new Date());
            user.setUpdateTime(new Date());
            localUsers.put(user.getUserId(), user);
            return user;
        });
    }
}
