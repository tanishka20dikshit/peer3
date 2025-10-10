package edu.adelaide.controller;

import edu.adelaide.cache.UserLoginDirectory;
import edu.adelaide.cache.UserLoginDirectory.UserLogin;
import edu.adelaide.service.UserPresenceService;
import edu.adelaide.util.IpUtil;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.*;

@RestController
@RequestMapping("/api/admin")
public class AdminMockController {

  private final UserPresenceService userPresenceService;
  private final UserLoginDirectory userLoginDirectory; // NEW

  public AdminMockController(UserPresenceService userPresenceService,
                             UserLoginDirectory userLoginDirectory) { // NEW
    this.userPresenceService = userPresenceService;
    this.userLoginDirectory = userLoginDirectory; // NEW
  }

  // HTTP (Swagger call)
  @GetMapping("/whoami")
  public Map<String,Object> who(HttpServletRequest req){
    var addr = IpUtil.resolve(req);
    return Map.of("ip", addr.ip(), "port", addr.port());
  }

  @Operation(summary = "Mock: Log in a hard-coded user and broadcast LOCAL_USER_ADVERTISE")
  @PostMapping("/mockUserLogin")
  public ResponseEntity<Map<String,Object>> mockUserLogin(HttpServletRequest req) {
    // Hard-coded demo user; replace with any test values you want
    String userId = "demo_user_01";
    String displayName = "Demo User";
    String pubkey = "TEST_USER_SIGN_PUBKEY_B64URL";   // user's signature public key (SPKI b64url)
    String encPubkey = "TEST_USER_ENC_PUBKEY_B64URL"; // user's encryption public key (SPKI b64url)
    var addr = IpUtil.resolve(req);

    var r = userPresenceService.loginHereAndBroadcast(userId, displayName, pubkey, encPubkey, addr.ip(), addr.port());
    return ResponseEntity.ok(Map.of(
        "type","OK",
        "user_id", userId,
        "broadcast_success", r.success(),
        "broadcast_fail", r.fail()
    ));
  }

  @Operation(summary = "Mock: Log out the hard-coded user and broadcast USER_REMOVE")
  @PostMapping("/mockUserLogout")
  public ResponseEntity<Map<String,Object>> mockUserLogout() {
    String userId = "demo_user_01"; // same ID as in mockUserLogin
    var r = userPresenceService.logoutHereAndBroadcast(userId, "manual");
    return ResponseEntity.ok(Map.of(
        "type","OK",
        "user_id", userId,
        "broadcast_success", r.success(),
        "broadcast_fail", r.fail()
    ));
  }

  // ========================= NEW =========================
  @Operation(summary = "List current online users across all servers")
  @GetMapping("/onlineUsers")
  public ResponseEntity<Map<String, Object>> listOnlineUsers() {
    List<Map<String, Object>> users = new ArrayList<>();
    for (UserLogin u : userLoginDirectory.listAll()) {
      Map<String, Object> m = new LinkedHashMap<>();
      m.put("server_id", nvl(u.getServerId()));
      m.put("user_id",   nvl(u.getUserId()));
      m.put("user_name", nvl(u.getDisplayName()));
      m.put("user_ip", u.getUserIp());
      m.put("pubkey", u.getPubkey());
      m.put("enc_pubkey", u.getEnc_pubkey());
      m.put("user_port", u.getUserPort());
      m.put("login_ts",  u.getLoginTs());
      users.add(m);
    }
    return ResponseEntity.ok(Map.of(
        "count", users.size(),
        "users", users
    ));
  }
  // ========================= NEW =========================

  private static String nvl(String s){ return (s == null) ? "" : s; }

  private static HttpServletRequest currentRequest() {
    var attrs = RequestContextHolder.getRequestAttributes();
    if (attrs instanceof ServletRequestAttributes sra) return sra.getRequest();
    return null;
  }

  private static String extractClientIp(HttpServletRequest req) {
    String xff = req.getHeader("X-Forwarded-For");
    if (xff != null && !xff.isBlank()) {
      String first = xff.split(",")[0].trim();
      if (!first.isBlank()) return first;
    }
    String real = req.getHeader("X-Real-IP");
    if (real != null && !real.isBlank()) return real.trim();
    return req.getRemoteAddr();
  }
}
