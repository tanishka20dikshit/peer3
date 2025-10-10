package edu.adelaide.config;

import edu.adelaide.cache.IntroducerKeyProps;
import edu.adelaide.util.UnifiedCryptoUtil;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPrivateKey;

@Configuration
@EnableConfigurationProperties(IntroducerKeyProps.class)
public class IntroducerCryptoConfig {

  @Bean("introducerPrivateKey")
  public RSAPrivateKey introducerPrivateKey(IntroducerKeyProps props) throws Exception {
    if (props.getPrivateKeyPem()!=null && !props.getPrivateKeyPem().isBlank()) {
      return UnifiedCryptoUtil.loadRSAPrivateKeyFromPemString(props.getPrivateKeyPem().trim());
    }
    Resource loc = props.getPrivateKeyLocation();
    if (loc == null || !loc.exists()) {
      throw new IllegalStateException("introducer.private-key-location not found");
    }
    String pem = new String(loc.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    return UnifiedCryptoUtil.loadRSAPrivateKeyFromPemString(pem);
  }
}
