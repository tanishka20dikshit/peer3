package edu.adelaide.cache;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import edu.adelaide.model.ServerInfo;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * File-backed registry of joined servers.
 * JSON layout:
 * {
 *   "version": 1,
 *   "updated": 1700000000000,
 *   "servers": {
 *     "server-uuid": {
 *       "host": "203.0.113.10",
 *       "port": 9000,
 *       "pubkey": "BASE64URL(SPKI)",
 *       "fingerprint": "sha256:ABCD...",
 *       "first_seen": 1700000000000,
 *       "last_seen" : 1700000005000,
 *       "status": "alive"
 *     }
 *   }
 * }
 */
public class ServerRegistryStore {

  private final Path file;
  private final ObjectMapper om = new ObjectMapper()
      .enable(SerializationFeature.INDENT_OUTPUT)
      .setSerializationInclusion(JsonInclude.Include.NON_NULL);

  private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
  private final Map<String, ServerRecord> cache = new LinkedHashMap<>();
  private int version = 1;
  private long updated = 0L;

  public ServerRegistryStore(String path) {
    try {
      this.file = Paths.get(path);
      Path dir = file.getParent();
      if (dir != null) Files.createDirectories(dir);

      if (Files.exists(file) && Files.size(file) > 0) {
        load();
      } else {
        save(); // create empty registry file
      }
    } catch (IOException e) {
      throw new IllegalStateException("Init registry failed: " + path, e);
    }
  }

  /** Upsert a server record and persist. */
  public void upsert(String serverId, String host, int port, String pubkeyB64u) {
    long now = Instant.now().toEpochMilli();
    lock.writeLock().lock();
    try {
      ServerRecord r = cache.get(serverId);
      if (r == null) {
        r = new ServerRecord();
        r.first_seen = now;
        r.status = "alive";
      }
      r.host = host;
      r.port = port;
      r.pubkey = pubkeyB64u;
      r.fingerprint = "sha256:" + sha256Hex(base64urlDecode(pubkeyB64u));
      r.last_seen = now;

      cache.put(serverId, r);
      updated = now;
      save();
    } finally {
      lock.writeLock().unlock();
    }
  }

  /** Return a snapshot of all servers (copy). */
  public List<ServerSnapshot> listAll() {
    lock.readLock().lock();
    try {
      List<ServerSnapshot> out = new ArrayList<>();
      cache.forEach((id, r) -> out.add(new ServerSnapshot(id, r.host, r.port, r.pubkey, r.fingerprint, r.first_seen, r.last_seen, r.status)));
      return out;
    } finally {
      lock.readLock().unlock();
    }
  }

  public List<ServerInfo> listForWelcomePayload() {
    lock.readLock().lock();
    try {
      List<ServerInfo> out = new ArrayList<>(cache.size());
      cache.entrySet().stream()
          .sorted((a, b) -> Long.compare(b.getValue().last_seen, a.getValue().last_seen))
          .forEach(e -> {
            String id = e.getKey();
            ServerRecord r = e.getValue();
            out.add(new ServerInfo(id, r.host, r.port, r.pubkey));
          });
      return out;
    } finally {
      lock.readLock().unlock();
    }
  }

  // ---------- persistence ----------

  private void load() {
    try {
      String json = Files.readString(file, StandardCharsets.UTF_8).trim();
      if (json.isEmpty()) { save(); return; }
      RegistryFile rf = om.readValue(json, RegistryFile.class);
      cache.clear();
      if (rf.servers != null) cache.putAll(rf.servers);
      version = rf.version == 0 ? 1 : rf.version;
      updated = rf.updated;
    } catch (Exception e) {
      // If corrupted, keep empty in-memory and rewrite
      save();
    }
  }

  private void save() {
    try {
      RegistryFile rf = new RegistryFile();
      rf.version = version;
      rf.updated = updated == 0L ? Instant.now().toEpochMilli() : updated;
      rf.servers = new LinkedHashMap<>(cache);
      String json = om.writeValueAsString(rf);
      Files.writeString(file, json, StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
    } catch (IOException e) {
      throw new IllegalStateException("Persist registry failed: " + file, e);
    }
  }

  // ---------- helpers & DTOs ----------

  private static byte[] base64urlDecode(String b64u) {
    return Base64.getUrlDecoder().decode(b64u);
  }

  private static String sha256Hex(byte[] bytes) {
    try {
      byte[] d = MessageDigest.getInstance("SHA-256").digest(bytes);
      StringBuilder sb = new StringBuilder(d.length * 2);
      for (byte b : d) sb.append(String.format("%02x", b));
      return sb.toString();
    } catch (Exception e) {
      return "error";
    }
  }

  /** On-disk record */
  public static class ServerRecord {
    public String host;
    public int port;
    public String pubkey;
    public String fingerprint;
    public long first_seen;
    public long last_seen;
    public String status;
  }

  /** On-disk file wrapper */
  public static class RegistryFile {
    public int version;
    public long updated;
    public Map<String, ServerRecord> servers;
  }

  /** Read-only snapshot DTO for callers. */
  public record ServerSnapshot(
      String serverId, String host, int port, String pubkey, String fingerprint,
      long firstSeen, long lastSeen, String status) {}
}
