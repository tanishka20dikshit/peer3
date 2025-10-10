package edu.adelaide.runtime;

import edu.adelaide.client.HeartbeatClient;
import edu.adelaide.cache.IntroducerClientProps;
import edu.adelaide.cache.PeerDirectory;
import edu.adelaide.util.AdvertisedEndpointUtil;
import org.slf4j.Logger; import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.lang.management.ManagementFactory;
import java.security.interfaces.RSAPrivateKey;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

@Component
public class HeartbeatScheduler {

  private static final Logger log = LoggerFactory.getLogger(HeartbeatScheduler.class);

  private final IntroducerClientProps props;
  private final IntroducerBootstrapRunner bootstrap;
  private final PeerDirectory peerDir;
  private final HeartbeatClient sender;
  private final AtomicLong seq = new AtomicLong(0);

  /** TTL (timeout removal threshold), default 45s */
  private final long ttlMs;

  public HeartbeatScheduler(IntroducerClientProps props,
                            IntroducerBootstrapRunner bootstrap,
                            PeerDirectory peerDir,
                            @Qualifier("serverPrivateKey") RSAPrivateKey myPrivateKey,
                            @Value("${app.peer.ttl-ms:45000}") long ttlMs) {
    this.props = props;
    this.bootstrap = bootstrap;
    this.peerDir = peerDir;
    this.ttlMs = ttlMs;

    long timeoutMs = props.getClient().getTimeoutMs();
    this.sender = new HeartbeatClient(myPrivateKey, timeoutMs, peerDir, ttlMs);
  }

  /** Heartbeat period (default 10s) */
  @Scheduled(
      fixedDelayString   = "${app.heartbeat.interval-ms:10000}",
      initialDelayString = "${app.heartbeat.initial-delay-ms:5000}"
  )
  public void tick() {
    String selfId = bootstrap.getAssignedServerId();
    if (selfId == null || selfId.isBlank()) {
      log.debug("[HB] skip: selfId not assigned yet");
      return;
    }

    var peers = peerDir.snapshotPeersExcept(selfId);
    if (peers.isEmpty()) {
      log.debug("[HB] no peers");
      return;
    }

    var ep = AdvertisedEndpointUtil.resolve(null, null);
    Map<String,Object> payload = new LinkedHashMap<>();
    payload.put("seq", seq.incrementAndGet());
    payload.put("uptime_ms", ManagementFactory.getRuntimeMXBean().getUptime());
    payload.put("host", ep.host());
    payload.put("port", ep.port());
    payload.put("status", "alive");

    sender.sendToAll(selfId, peers, payload);
  }
}
