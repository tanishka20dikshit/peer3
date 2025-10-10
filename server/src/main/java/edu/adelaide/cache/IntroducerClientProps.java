package edu.adelaide.cache;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@ConfigurationProperties(prefix = "introducer")
@Getter @Setter
public class IntroducerClientProps {

  /** My identity + defaults for client */
  private Client client = new Client();

  /** Static Bootstrap List from config */
  private List<BootstrapServer> bootstrapServers;

  @Getter @Setter
  public static class Client {
    /** our server id */
    private String serverId;
    /** ws timeout per attempt (ms) */
    private long timeoutMs = 5000;
  }

  @Getter @Setter
  public static class BootstrapServer {
    /** introducer ip or hostname */
    private String host;
    /** introducer port */
    private int port;
    /** introducer's SPKI base64url */
    private String pubkey;

    /** ws url builder (plain ws; can be changed to wss if TLS is required) */
    public String wsUrl() { return "ws://" + host + ":" + port + "/ws"; }
    /** logical 'to' field as "<ip>:<port>" per your spec */
    public String toAddr() { return host + ":" + port; }
  }
}
