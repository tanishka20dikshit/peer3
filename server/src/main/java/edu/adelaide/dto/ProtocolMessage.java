package edu.adelaide.dto;

import lombok.Getter;
import lombok.Setter;

import java.util.Map;
import java.util.Objects;

/**
 * SOCP envelope DTO for server <-> introducer messages.
 *
 * Fields follow the spec image:
 *  - type:   STRING (case-sensitive)
 *  - from:   UUID of server/user
 *  - to:     UUID of server/user, or "*"
 *  - ts:     Unix timestamp in milliseconds
 *  - payload: JSON object represented as Map<String, Object>
 *  - sig:    BASE64URL signature over the canonical payload
 *
 * This class is a plain POJO: no JSON/Gson dependencies.
 * Serialization/validation/signing are handled outside.
 */
@Setter
@Getter
public class ProtocolMessage {

  private String type;
  private String from;
  private String to;
  private long ts;
  private Map<String, Object> payload; // key-value pairs for the message body
  private String sig;                  // base64url signature string

  public ProtocolMessage() {
  }

  public ProtocolMessage(String type, String from, String to, long ts, Map<String, Object> payload, String sig) {
    this.type = type;
    this.from = from;
    this.to = to;
    this.ts = ts;
    this.payload = payload;
    this.sig = sig;
  }
  @Override
  public String toString() {
    return "ProtocolMessage{" +
        "type='" + type + '\'' +
        ", from='" + from + '\'' +
        ", to='" + to + '\'' +
        ", ts=" + ts +
        ", payload=" + payload +
        ", sig='" + (sig == null ? null : "[redacted]") + '\'' +
        '}';
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof ProtocolMessage)) return false;
    ProtocolMessage that = (ProtocolMessage) o;
    return ts == that.ts &&
        Objects.equals(type, that.type) &&
        Objects.equals(from, that.from) &&
        Objects.equals(to, that.to) &&
        Objects.equals(payload, that.payload) &&
        Objects.equals(sig, that.sig);
  }

  @Override
  public int hashCode() {
    return Objects.hash(type, from, to, ts, payload, sig);
  }
}

