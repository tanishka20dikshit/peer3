package edu.adelaide.cache;
import org.springframework.stereotype.Component;
import java.net.URI;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class ServersRegistry {

  public static final class ServerInfo {
    public final String serverId;
    public final String publicKeyPem;
    volatile Instant lastSeen = Instant.now();
    final Set<URI> addresses = ConcurrentHashMap.newKeySet();

    public ServerInfo(String serverId, String publicKeyPem) {
      this.serverId = serverId;
      this.publicKeyPem = publicKeyPem;
    }
    public Set<URI> addresses() { return Collections.unmodifiableSet(addresses); }
  }

  private final Map<String, ServerInfo> servers = new ConcurrentHashMap<>();

  public ServerInfo upsertServer(String serverId, String publicKeyPem) {
    Objects.requireNonNull(serverId, "serverId");
    return servers.compute(serverId, (id, old) -> {
      if (old == null) return new ServerInfo(serverId, publicKeyPem);
      ServerInfo s = old;
      if (publicKeyPem != null && !publicKeyPem.isBlank() && !publicKeyPem.equals(old.publicKeyPem)) {
        s = new ServerInfo(serverId, publicKeyPem);
        s.addresses.addAll(old.addresses);
      }
      s.lastSeen = Instant.now();
      return s;
    });
  }

  public void addAddress(String serverId, URI addr) {
    Objects.requireNonNull(serverId, "serverId");
    Objects.requireNonNull(addr, "addr");
    servers.computeIfAbsent(serverId, id -> new ServerInfo(id, null)).addresses.add(addr);
  }

  public Optional<ServerInfo> get(String serverId) { return Optional.ofNullable(servers.get(serverId)); }
  public Collection<ServerInfo> list() { return Collections.unmodifiableCollection(servers.values()); }
  public void markSeen(String serverId) { Optional.ofNullable(servers.get(serverId)).ifPresent(s -> s.lastSeen = Instant.now()); }
  public void remove(String serverId) { servers.remove(serverId); }
}
