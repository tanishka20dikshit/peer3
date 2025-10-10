package edu.adelaide.config;

import edu.adelaide.server.IntroducerWsHandler;
import org.springframework.context.annotation.Configuration;
import org.springframework.lang.NonNull;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;

@Configuration
@EnableWebSocket
public class WebSocketConfig implements WebSocketConfigurer {

    private final IntroducerWsHandler handler;

    public WebSocketConfig(IntroducerWsHandler handler) {
        this.handler = handler;
    }

    @Override
    public void registerWebSocketHandlers(@NonNull WebSocketHandlerRegistry registry) {
        registry.addHandler(handler, "/ws")
            .setAllowedOrigins("*");
    }
}
