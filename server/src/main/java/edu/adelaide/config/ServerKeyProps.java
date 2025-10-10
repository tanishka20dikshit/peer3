package edu.adelaide.config;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "server")
public class ServerKeyProps {
  /** e.g. classpath:config/keys/server_private.pem */
  private Resource privateKeyLocation;
  /** optional inline PEM */
  private String privateKeyPem;

  public Resource getPrivateKeyLocation() { return privateKeyLocation; }
  public void setPrivateKeyLocation(Resource privateKeyLocation) { this.privateKeyLocation = privateKeyLocation; }
  public String getPrivateKeyPem() { return privateKeyPem; }
  public void setPrivateKeyPem(String privateKeyPem) { this.privateKeyPem = privateKeyPem; }
}
