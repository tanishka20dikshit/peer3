package edu.adelaide.model;

import lombok.Getter;
import lombok.Setter;

/** Minimal server entry used in SERVER_WELCOME payload. */
@Setter
@Getter
public class ServerInfo {
  private String user_id;   // UUID v4
  private String host;        // WS host/IP
  private int port;           // WS port
  private String pubkey;

  public ServerInfo(String user_id, String host, int port, String pubkey) {
    this.user_id = user_id;
    this.host = host;
    this.port = port;
    this.pubkey = pubkey;
  }

}
