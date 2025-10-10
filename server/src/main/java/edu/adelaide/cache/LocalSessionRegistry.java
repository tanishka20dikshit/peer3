package edu.adelaide.cache;


import org.springframework.stereotype.Component;
import org.springframework.web.socket.WebSocketSession;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class LocalSessionRegistry {
  private final Map<String, WebSocketSession> activeUsers = new ConcurrentHashMap<>();

  public void put(String userId, WebSocketSession session) {
    activeUsers.put(userId, session);
  }
  public void removeIf(String userId, WebSocketSession session) {
    activeUsers.remove(userId, session);
  }
  public Map<String, WebSocketSession> snapshot() {
    return Map.copyOf(activeUsers);
  }

  public WebSocketSession get(String userId) {
    return activeUsers.get(userId);
  }
}
