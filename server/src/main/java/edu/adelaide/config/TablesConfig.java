package edu.adelaide.config;
import edu.adelaide.cache.SeenIdsCache;
import edu.adelaide.cache.ServersRegistry;
import edu.adelaide.cache.UserLocations;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.*;
import org.springframework.scheduling.annotation.EnableScheduling;

@Configuration
@EnableScheduling
public class TablesConfig {

  private static final Logger log = LoggerFactory.getLogger(TablesConfig.class);

  @Bean public SeenIdsCache seenIdsCache() { return new SeenIdsCache(); }
  @Bean public ServersRegistry serversRegistry() { return new ServersRegistry(); }
  @Bean public UserLocations userLocations() { return new UserLocations(); }

//  @Scheduled(fixedDelay = 15_000L)
//  public void housekeeping(SeenIdsCache seen, UserLocations locs) {
//    seen.purge();
//    int removed = locs.purgeStale(60_000L);
//    if (removed > 0) log.debug("Purged {} stale user locations", removed);
//  }
}
