package edu.adelaide.runtime;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import edu.adelaide.client.IntroducerClient;
import edu.adelaide.client.IntroducerClient.WelcomeResult;
import edu.adelaide.cache.IntroducerClientProps;
import edu.adelaide.client.PeerAnnounceClient;
import edu.adelaide.cache.PeerDirectory;
import edu.adelaide.util.UnifiedCryptoUtil;
import edu.adelaide.util.UnifiedJsonUtil;
import org.slf4j.Logger; import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

@Component
public class IntroducerBootstrapRunner implements ApplicationRunner {

  private static final Logger log = LoggerFactory.getLogger(IntroducerBootstrapRunner.class);

  private final IntroducerClientProps props;
  private final RSAPrivateKey myPrivateKey;
  private final PeerDirectory peerDir;

  private volatile String assignedServerId;

  public IntroducerBootstrapRunner(IntroducerClientProps props,
                                   @Qualifier("serverPrivateKey") RSAPrivateKey myPrivateKey,
                                   PeerDirectory peerDir) {
    this.props = props;
    this.myPrivateKey = myPrivateKey;
    this.peerDir = peerDir;
  }

  @Override
  public void run(ApplicationArguments args) {
    log.info("===== BOOTSTRAP (try in YAML order, stop on first success) START =====");
    try {
      // STEP1) Read local public key SPKI (base64url)
      String myPubkeyB64u = readBase64UrlFromClasspath("config/keys/server_public_spki.base64url.txt");
      log.info("[STEP1] Local SPKI loaded (len={})", myPubkeyB64u.length());

      // Get introducers from YAML
      List<IntroducerClientProps.BootstrapServer> servers = props.getBootstrapServers();
      if (servers == null || servers.isEmpty()) {
        throw new IllegalStateException("Bootstrap list is empty");
      }

      IntroducerClient joiner      = new IntroducerClient(myPrivateKey, props.getClient().getTimeoutMs());
      PeerAnnounceClient announcer = new PeerAnnounceClient(myPrivateKey, props.getClient().getTimeoutMs());

      RuntimeException last = null;

      // STEP2) Try in YAML order and return if successful
      for (var bs : servers) {
        final String wsUrl = bs.wsUrl();
        final String to    = bs.toAddr();
        final String pinnedSpki = trimOrNull(bs.getPubkey());

        if (isBlank(pinnedSpki)) {
          log.warn("[STEP2] Skip {}: missing pinned SPKI in YAML", wsUrl);
          continue;
        }

        log.info("[TRY] Introducer {} (to={}), pinned SPKI len={}", wsUrl, to, pinnedSpki.length());

        try {
          // STEP3) Constructing a JOIN (Signature)
          String joinJson = joiner.buildServerHelloJoinJson(props.getClient().getServerId(), myPubkeyB64u, to);
          log.debug("[STEP3] JOIN request len={}\n{}", joinJson.length(), joinJson);

          // STEP4) Send and wait for reply
          String reply = joiner.sendWsAndAwaitOneText(wsUrl, joinJson);
          log.info("[STEP4] Reply len={} from {}", reply.length(), wsUrl);
          log.debug("[WELCOME RAW]\n{}", reply);

          // STEP5) Signature verification on RAW JSON (remove 'sig' then canonicalize)
          verifyWelcomeSignatureRaw(reply, pinnedSpki);
          log.info("[STEP5] Signature verified");

          // STEP6) Analysis (parse assigned_id + clients[])
          WelcomeResult wr = joiner.parseWelcome(reply);
          log.info("[STEP6] Parsed: assignedId={}, peers={}", wr.assignedId, wr.clients.size());

          // STEP7) Submit: save assigned_id + refresh PeerDirectory
          this.assignedServerId = wr.assignedId;
          peerDir.loadFromWelcome(assignedServerId, wr.clients);
          log.info("[STEP7] Committed: assigned_id={}, peer directory size={}", assignedServerId, wr.clients.size());

          // STEP8) Broadcast: Send self-announcement to all peers
          var peers = peerDir.snapshotPeersExcept(assignedServerId);
          announcer.announceToAll(assignedServerId, myPubkeyB64u, peers);
          log.info("[STEP8] Announced to {} peers", peers.size());

          log.info("===== BOOTSTRAP DONE (first successful introducer) =====");
          // Stop traversal after success
          return;
        } catch (RuntimeException e) {
          log.warn("[FAIL] Introducer {} failed: {}", wsUrl, e.toString());
          last = e;
        }
      }

      // all introducer fail
      throw (last != null ? last : new IllegalStateException("All bootstrap introducers failed"));

    } catch (Exception e) {
      log.error("Bootstrap flow failed: {}", e.getMessage(), e);
      log.info("===== BOOTSTRAP END (FAILED) =====");
    }
  }

  public String getAssignedServerId(){ return assignedServerId; }

  // --------- helpers ---------

  /** Verify SERVER_WELCOME signature using RAW JSON (remove 'sig' then canonicalize). */
  private static void verifyWelcomeSignatureRaw(String raw, String introducerSpkiB64u) {
    try {
      JsonNode root = UnifiedJsonUtil.parseJson(raw);

      JsonNode type = root.get("type");
      if (type == null || !"SERVER_WELCOME".equals(type.asText())) {
        throw new IllegalStateException("Unexpected reply type: " + (type == null ? "null" : type.asText()));
      }

      JsonNode sigNode = root.get("sig");
      if (sigNode == null || sigNode.isNull() || sigNode.asText().isBlank()) {
        throw new IllegalStateException("WELCOME missing signature");
      }
      String sigB64u = sigNode.asText();
      ((ObjectNode) root).remove("sig"); // IMPORTANT: sign/verify without 'sig'

      String canonicalJson = UnifiedJsonUtil.createCanonicalJson(root);
      byte[] canonical = canonicalJson.getBytes(java.nio.charset.StandardCharsets.UTF_8);
      log.debug("[CLIENT CANON IN] {}", canonicalJson);
      RSAPublicKey introducerPub = UnifiedCryptoUtil.loadRSAPublicKeyFromBase64Url(introducerSpkiB64u);

      boolean ok = UnifiedCryptoUtil.rsaVerify(canonical, sigB64u, introducerPub);
      if (!ok) throw new IllegalStateException("WELCOME signature verification failed");
    } catch (RuntimeException re) {
      throw re;
    } catch (Exception e) {
      throw new IllegalStateException("WELCOME signature verify error: " + e.getMessage(), e);
    }
  }

  private static String readBase64UrlFromClasspath(String path) {
    try (var in = new ClassPathResource(path).getInputStream()) {
      // strip all whitespace/newlines just in case
      return new String(in.readAllBytes(), StandardCharsets.US_ASCII).replaceAll("\\s+","").trim();
    } catch (Exception e) {
      throw new IllegalStateException("Cannot read " + path + " from classpath", e);
    }
  }
  private static String trimOrNull(String s) { return (s == null) ? null : s.trim(); }
  private static boolean isBlank(String s) { return s == null || s.trim().isEmpty(); }
}
