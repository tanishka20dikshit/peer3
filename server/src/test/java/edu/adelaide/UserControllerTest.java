package edu.adelaide;

import com.fasterxml.jackson.databind.ObjectMapper;
import edu.adelaide.dto.CreateUserRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;

import java.util.concurrent.ThreadLocalRandom;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Controller integration tests for:
 *  - POST /api/users/createUser
 *  - GET  /api/users/queryUsers
 *
 * NOTE:
 *  - DB is assumed to already contain:
 *      U1001/alice, U1002/bob, U1003/charlie
 *  - If you enabled an auth interceptor, the "X-Auth-Token" header avoids 401.
 */
@SpringBootTest
@AutoConfigureMockMvc
class UserControllerTest {

  @Autowired private MockMvc mockMvc;
  @Autowired private ObjectMapper om;
  @Autowired private JdbcTemplate jdbcTemplate;

  private static String randomNumericSuffix(int digits) {
    int bound = (int) Math.pow(10, digits);
    return "_" + String.format("%0" + digits + "d",
        ThreadLocalRandom.current().nextInt(bound));
  }

  @Test
  @DisplayName("Insert user with username + random suffix; DB should persist the same value")
  void createUser_withRandomSuffix_insertsExpectedUsername() throws Exception {
    // Compose a unique username for observability (e.g., alice_0427)
    String base = "ddddd";
    String username = base + randomNumericSuffix(4);

    // Use a unique email to avoid unique-constraint conflicts
    String email = "alice+" + System.currentTimeMillis() + "@example.com";

    // Build request
    CreateUserRequest req = new CreateUserRequest();
    req.setUsername(username);
    req.setEmail(email);
    req.setPhoneNumber(null);
    req.setPassword("demo-pass");

    mockMvc.perform(post("/api/users/createUser")
            .contentType(MediaType.APPLICATION_JSON)
            .header("X-Auth-Token", "test-token")
            .content(om.writeValueAsString(req)))
        .andExpect(status().isCreated());

    // Verify by querying the DB directly
    String savedUsername = jdbcTemplate.queryForObject(
        "SELECT username FROM t_user_info WHERE email = ?",
        (rs, rowNum) -> rs.getString(1),
        email
    );
    assertThat(savedUsername).isEqualTo(username);

  }

  /* ---------- GET /api/users/queryUsers ---------- */

  @Test
  @DisplayName("GET /api/users/queryUsers?userId=U1001 -> return alice")
  void getByUserId_shouldReturnAlice() throws Exception {
    mockMvc.perform(get("/api/users/queryUsers")
            .param("userId", "U1001")
            .header("X-Auth-Token", "test-token"))
        .andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
        .andExpect(jsonPath("$.userId", is("U1001")))
        .andExpect(jsonPath("$.username", is("alice")));
  }

  @Test
  @DisplayName("GET /api/users/queryUsers?username=bob -> return array contains U1002/bob")
  void getByUsername_shouldReturnArrayContainingBob() throws Exception {
    mockMvc.perform(get("/api/users/queryUsers")
            .param("username", "bob")
            .header("X-Auth-Token", "test-token"))
        .andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
        .andExpect(jsonPath("$", isA(java.util.List.class)))
        .andExpect(jsonPath("$[*].userId", hasItem("U1002")))
        .andExpect(jsonPath("$[*].username", hasItem("bob")));
  }

  @Test
  @DisplayName("GET /api/users/queryUsers?page=0&size=2 -> Return to the paging structure")
  void pageAll_shouldReturnPagedResult() throws Exception {
    mockMvc.perform(get("/api/users/queryUsers")
            .param("page", "0")
            .param("size", "2")
            .header("X-Auth-Token", "test-token"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.page", is(0)))
        .andExpect(jsonPath("$.size", is(2)))
        .andExpect(jsonPath("$.items", isA(java.util.List.class)))
        .andExpect(jsonPath("$.items", hasSize(lessThanOrEqualTo(2))))
        .andExpect(jsonPath("$.total", greaterThanOrEqualTo(1)));
  }

  @Test
  @DisplayName("GET /api/users/queryUsers?userId=U1001&username=not-match -> 400")
  void userIdUsernameMismatch_shouldReturn400() throws Exception {
    mockMvc.perform(get("/api/users/queryUsers")
            .param("userId", "U1001")
            .param("username", "not-match")
            .header("X-Auth-Token", "test-token"))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.code", is(400)));
  }

  @Test
  @DisplayName("GET /api/users/queryUsers?userId=NOPE -> 404")
  void notFound_shouldReturn404() throws Exception {
    mockMvc.perform(get("/api/users/queryUsers")
            .param("userId", "NOPE")
            .header("X-Auth-Token", "test-token"))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.code", is(404)));
  }
}
