package edu.adelaide.service;

import edu.adelaide.model.ServerInfo;
import edu.adelaide.cache.ServerRegistryStore;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.List;
import java.util.UUID;

/** Introducer logic backed by a JSON file registry. */
@Service
public class IntroducerService extends BaseService {

  private final ServerRegistryStore store;

  public IntroducerService(
      @Value("${introducer.registry:file:./data/server-registry.json}") Resource target,
      @Value("classpath:data/server-registry.json") Resource seed) {
    // file:... → Path; if it is classpath:, an error will be thrown to avoid writing it by mistake
    Path path = toWritablePath(target);
    ensureParent(path);

    if (Files.notExists(path) || isEmpty(path)) {
      // First run: If there is a seed in the classpath, copy it; otherwise write an empty skeleton
      try {
        if (seed.exists()) {
          Files.copy(seed.getInputStream(), path, StandardCopyOption.REPLACE_EXISTING);
        } else {
          writeEmptyRegistry(path);
        }
      } catch (Exception e) {
        throw new IllegalStateException("Init registry failed: " + path, e);
      }
    }
    this.store = new ServerRegistryStore(path.toString());
  }

  private static Path toWritablePath(Resource r) {
    try {
      return r.getFile().toPath();
    } catch (Exception e) {
      throw new IllegalArgumentException(
          "introducer.registry must be a file:… path (writable). Do not use classpath: here.", e);
    }
  }

  private static void ensureParent(Path p) {
    try { Path dir = p.getParent(); if (dir != null) Files.createDirectories(dir); }
    catch (Exception e) { throw new IllegalStateException("Create dir failed: " + p, e); }
  }
  private static boolean isEmpty(Path p) {
    try { return Files.size(p) == 0; } catch (Exception e) { return true; }
  }

  private static void writeEmptyRegistry(Path p) {
    try {
      String json = """
        { "version": 1, "updated": %d, "servers": {} }
        """.formatted(System.currentTimeMillis());
      Files.writeString(p, json, StandardCharsets.UTF_8,
          StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
    } catch (Exception e) {
      throw new IllegalStateException("Write empty registry failed: " + p, e);
    }
  }

  /** Assign a stable server_id (generate UUID v4 if missing/placeholder). */
  public String assignServerId(String requestedId) {
    validateNotNull(requestedId, "requestedId");
    
    if (requestedId.isBlank() || "server_id".equals(requestedId)) {
      return UUID.randomUUID().toString();
    }
    return requestedId;
  }

  /** Register/refresh the joining server's info (address + pinned pubkey). */
  public void registerServer(String serverId, String host, int port, String pubkey) {
    validateNotBlank(serverId, "serverId");
    validateNotBlank(host, "host");
    if (port <= 0) {
      throw new IllegalArgumentException("port must be positive");
    }
    
    logOperationStart("registerServer", serverId, host, port);
    store.upsert(serverId, host, port, pubkey);
    logOperationComplete("registerServer", "success");
  }

  /** Return known servers to include in SERVER_WELCOME. */
  public List<ServerInfo> listKnownServers() {
    logOperationStart("listKnownServers");
    List<ServerInfo> result = store.listForWelcomePayload();
    logOperationComplete("listKnownServers", result != null ? result.size() : 0);
    return result;
  }

}
