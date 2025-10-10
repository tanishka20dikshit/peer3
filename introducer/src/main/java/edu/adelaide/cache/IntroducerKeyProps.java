package edu.adelaide.cache;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;

@Setter
@Getter
@ConfigurationProperties(prefix = "introducer")
public class IntroducerKeyProps {
  /** e.g. classpath:config/keys/introducer_private.pem */
  private Resource privateKeyLocation;
  /** or inline PEM text (BEGIN/END PRIVATE KEY ...) */
  private String privateKeyPem;

}
