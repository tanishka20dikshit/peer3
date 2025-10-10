package edu.adelaide.config;

import edu.adelaide.cache.LocalSessionRegistry;
import edu.adelaide.cache.UserLoginDirectory;
import edu.adelaide.service.PublicChannelService;
import edu.adelaide.service.UserPresenceService;
import edu.adelaide.cache.PeerDirectory;
import edu.adelaide.server.ServerMainWsHandler;
import edu.adelaide.client.ServerLinkClient;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.interfaces.RSAPrivateKey;

/**
 * Configuration class to define core server components that require constructor injection.
 */
@Configuration
public class ServerConfig {

    /**
     * Defines the ServerMainWsHandler bean.
     * * Spring will automatically inject the dependencies:
     * 1. The RSAPrivateKey, which is assumed to be defined elsewhere (likely in 
     * a KeyConfig or another setup file) and tagged with @Qualifier("serverPrivateKey").
     * 2. The PeerDirectory, which is a @Service.
     * * This bean definition resolves the "bean could not be found" error.
     */
    @Bean
    public ServerMainWsHandler serverMainWsHandler(
        @Qualifier("serverPrivateKey") RSAPrivateKey myPriv, 
        PeerDirectory peerDir,
        UserLoginDirectory userLoginDirectory,
        UserPresenceService userPresenceService,
        ServerLinkClient serverLinkClient,
        PublicChannelService publicChannelService,
        LocalSessionRegistry sessionRegistry
    ) {
        // Spring calls this constructor to create the handler instance
        return new ServerMainWsHandler(myPriv, peerDir, userLoginDirectory, userPresenceService, serverLinkClient, publicChannelService, sessionRegistry);
    }
    
    // NOTE: You can add other server-wide configuration beans here, 
    // such as a global ObjectMapper setup or your RSAPrivateKey bean definition 
    // if it's not already in its own file.
}