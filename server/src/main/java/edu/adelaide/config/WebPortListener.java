package edu.adelaide.config;
import edu.adelaide.util.AdvertisedEndpointUtil;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

@Component
public class WebPortListener {
  @EventListener(org.springframework.boot.web.context.WebServerInitializedEvent.class)
  public void onReady(org.springframework.boot.web.context.WebServerInitializedEvent e) {
    AdvertisedEndpointUtil.setActualPort(e.getWebServer().getPort());
  }
}
