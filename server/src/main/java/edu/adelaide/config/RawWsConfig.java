package edu.adelaide.config;

import edu.adelaide.server.ServerAnnounceWsHandler;
import edu.adelaide.server.ServerHeartbeatWsHandler;
import edu.adelaide.server.ServerMainWsHandler;
import edu.adelaide.server.ServerUserWsHandler;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;

@Configuration
@EnableWebSocket
public class RawWsConfig implements WebSocketConfigurer {

    private final ServerAnnounceWsHandler announceHandler;
    private final ServerHeartbeatWsHandler heartbeatHandler;
    private final ServerMainWsHandler mainHandler;
    private final ServerUserWsHandler userHandler;

    public RawWsConfig(ServerAnnounceWsHandler announceHandler,
                       ServerHeartbeatWsHandler heartbeatHandler,
                       ServerMainWsHandler mainHandler,
                       ServerUserWsHandler userHandler) {
        this.announceHandler = announceHandler;
        this.heartbeatHandler = heartbeatHandler;
        this.mainHandler = mainHandler;
        this.userHandler = userHandler;
    }

    @Override
    public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
        registry.addHandler(announceHandler,  "/peer/announce").setAllowedOrigins("*");
        registry.addHandler(heartbeatHandler, "/peer/heartbeat").setAllowedOrigins("*");
        registry.addHandler(mainHandler,      "/ws").setAllowedOrigins("*");
        registry.addHandler(userHandler,      "/peer/user").setAllowedOrigins("*");
    }
}
