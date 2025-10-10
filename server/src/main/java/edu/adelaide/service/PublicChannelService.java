package edu.adelaide.service;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.web.socket.WebSocketSession;

import java.util.List;
import java.util.Map;

/**
 * Service to support the built-in 'public' channel:
 *  - Ensure public group exists
 *  - Audit membership on login/logout (optional)
 *  - Fanout locally to all active WebSocket sessions
 *  - Relay to peer servers
 */
public interface PublicChannelService {

  /** Ensure built-in 'public' group exists (idempotent). */
  void ensurePublicGroup();

  /** Mark user online in 'public' for auditing (optional). */
  void addUserToPublicAndAnnounce(String userId, String displayName);

  /** Mark user offline (left) for auditing (optional). */
  void onUserOffline(String userId);

  /**
   * Publish a message to the public channel locally and relay to peers.
   * @param fromUser sender user id
   * @param messagePayload arbitrary JSON-compatible object (already parsed)
   * @param activeUsers in-memory userId -> WebSocketSession map
   * @param excludeSender whether to exclude echo back to the sender
   */
  void publishToPublic(String fromUser,
                       Object messagePayload,
                       Map<String, WebSocketSession> activeUsers,
                       boolean excludeSender);

  /**
   * Handle relay from peer server: deliver to local active users.
   */
  void handleServerPublicPublish(String fromUser,
                                 Object messagePayload);


  // PublicChannelService.java
  void mergePeerPublicAdd(Map<String, Object> user);
  void mergePeerPublicRemove(String userId);
  void replacePublicSnapshot(long version, java.util.List<Map<String, Object>> members);

  void mergePeerPublicAddList(List<String> ids, long ifVersion);

  void sendPublicMessage(String userId, JsonNode root);

  void handleServerPublicDeliverBroadcast(JsonNode root);

  void handleRemoteKeyShareAndBroadcast(JsonNode root);
}
