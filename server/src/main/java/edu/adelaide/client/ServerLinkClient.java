package edu.adelaide.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.client.standard.StandardWebSocketClient;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;

/**
 * Minimal client to send JSON frames to other servers over WebSocket.
 */
@Component
public class ServerLinkClient {
    private static final Logger log = LoggerFactory.getLogger(ServerLinkClient.class);

    private final StandardWebSocketClient wsClient = new StandardWebSocketClient();
    private final ConcurrentHashMap<String, WebSocketSession> sessions = new ConcurrentHashMap<>();

    public void sendJson(String serverId, String url, String json) {
        try {
            WebSocketSession session = sessions.computeIfAbsent(serverId, id -> {
                try {
                    return wsClient
                        .doHandshake(new org.springframework.web.socket.handler.TextWebSocketHandler() {}, url)
                        .get();
                } catch (InterruptedException | ExecutionException e) {
                    throw new RuntimeException("Failed WS connect to " + url, e);
                }
            });
            if (session != null && session.isOpen()) {
                session.sendMessage(new TextMessage(json));
            } else {
                log.warn("Session to {} not open", serverId);
            }
        } catch (Exception e) {
            log.error("Failed to send to {}: {}", serverId, e.toString());
        }
    }
}
