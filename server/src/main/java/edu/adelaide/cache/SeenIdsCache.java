package edu.adelaide.cache;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;


public class SeenIdsCache {

  private final Map<String, Long> seen = new ConcurrentHashMap<>();
  private final long ttlMillis;
  private final int maxEntries;

  public SeenIdsCache() {
    this(Duration.ofMinutes(5), 100_000);
  }
  public SeenIdsCache(Duration ttl, int maxEntries) {
    this.ttlMillis = ttl.toMillis();
    this.maxEntries = maxEntries;
  }

  public boolean isDuplicateAndMark(String id) {
    if (id == null || id.isBlank()) return false;
    long now = System.currentTimeMillis();
    Long prev = seen.putIfAbsent(id, now);
    if (prev != null) return true;
    if (seen.size() > maxEntries) purge(now);
    return false;
  }

  public void purge() { purge(System.currentTimeMillis()); }

  private void purge(long now) {
    long cutoff = now - ttlMillis;
    for (Map.Entry<String, Long> e : seen.entrySet()) {
      if (e.getValue() < cutoff) {
        seen.remove(e.getKey(), e.getValue());
      }
    }
  }

  public int size() { return seen.size(); }
}