package edu.adelaide.service;

import edu.adelaide.cache.UserLoginDirectory;
import edu.adelaide.client.UserEventClient;
import edu.adelaide.cache.IntroducerClientProps;
import edu.adelaide.cache.PeerDirectory;
import org.slf4j.Logger; import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class UserPresenceService {
  private static final Logger log = LoggerFactory.getLogger(UserPresenceService.class);

  /** WebSocket path for user events on peer servers. */
  private static final String USER_EVENT_WS_PATH = "/peer/user";

  private final IntroducerClientProps props;
  private final UserLoginDirectory userLoginDir;
  private final PeerDirectory peerDir;
  private final UserEventClient userEventClient;
  private final PublicChannelService publicChannelService;

  public UserPresenceService(IntroducerClientProps props,
                             UserLoginDirectory userLoginDir,
                             PeerDirectory peerDir,
                             UserEventClient userEventClient,
                             PublicChannelService publicChannelService) {
    this.props = props;
    this.userLoginDir = userLoginDir;
    this.peerDir = peerDir;
    this.userEventClient = userEventClient;
    this.publicChannelService = publicChannelService;
  }

  /** Log the user in locally (TOFU pin + presence) and broadcast LOCAL_USER_ADVERTISE to peers. */
  public Result loginHereAndBroadcast(String userId, String displayName,
                                      String signPubKeyBase64url, String encPubKeyBase64url, String ip, Integer port) {
    final String selfId = props.getClient().getServerId();

    // 1) Local TOFU/presence（
    // userLoginDir.verifyOrPinPubkey(userId, signPubKeyBase64url);
    // userLoginDir.verifyOrPinEncPubkey(userId, encPubKeyBase64url);
    userLoginDir.upsert(selfId, userId, nvl(displayName), signPubKeyBase64url, encPubKeyBase64url, ip, port);

    // 2) Broadcast to peers (one-by-one)
    var peers = peerDir.snapshotPeersExcept(selfId);
    int ok = 0, fail = 0;

    // loginHereAndBroadcast(...)
    for (var p : peers) {
      final String ws = "ws://" + p.getHost() + ":" + p.getPort() + USER_EVENT_WS_PATH;
      final String toDest = (p.getServerId() != null && !p.getServerId().isBlank()) ? p.getServerId() : "*";
      try {
        String json = userEventClient.buildAdvertiseUserJson(
            selfId, toDest, userId, nvl(displayName),
            /* userIp */ null, /* userPort */ null
        );
        userEventClient.advertiseFireAndForget(ws, json);
        ok++;
      } catch (Exception e) {
        log.warn("[USER_ADVERTISE] {} -> {} failed: {}", selfId, p, e.toString());
        fail++;
      }
    }

    // 3) Joining a public channel should be another entrance, but now it is added after adding new users for ease of processing.
//    publicChannelService.addUserToPublicAndAnnounce(userId, null);

    return new Result(ok, fail);
  }

  /** Log the user out locally and broadcast USER_REMOVE to peers. */
  public Result logoutHereAndBroadcast(String userId, String reason) {
    final String selfId = props.getClient().getServerId();

    // 1) Local removal
    boolean removed = userLoginDir.removeUser(selfId, userId);
    if (!removed) log.info("[USER_REMOVE local] user={} not present on {}", userId, selfId);

    // 2) Broadcast
    var peers = peerDir.snapshotPeersExcept(selfId);
    int ok = 0, fail = 0;
    for (var p : peers) {
      final String ws = "ws://" + p.getHost() + ":" + p.getPort() + USER_EVENT_WS_PATH;
      final String toDest = (p.getServerId() != null && !p.getServerId().isBlank()) ? p.getServerId() : "*";
      try {
        String json = userEventClient.buildRemoveUserJson(
            selfId, toDest, userId, nvl(reason)
        );
        userEventClient.removeFireAndForget(ws, json);
        ok++;
      } catch (Exception e) {
        log.warn("[USER_REMOVE] {} -> {} failed: {}", selfId, p, e.toString());
        fail++;
      }
    }

    return new Result(ok, fail);
  }

  public record Result(int success, int fail) {}

  private static String nvl(String s){ return (s == null) ? "" : s; }
}
