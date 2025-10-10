package edu.adelaide.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

/**
 * Request body for creating a user.
 */
@Setter
@Getter
public class CreateUserRequest {

  // Optional: if empty, service will generate a UUID
  @Size(max = 64)
  private String userId;

  @NotBlank
  @Size(max = 50)
  private String username;

  @Email
  @Size(max = 100)
  private String email;

  @Size(max = 20)
  private String phoneNumber;

  @NotBlank
  @Size(max = 255)
  private String password; // NOTE: store hashed password in production

}
