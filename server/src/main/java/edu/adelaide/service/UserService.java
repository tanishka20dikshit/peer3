package edu.adelaide.service;

import edu.adelaide.dto.CreateUserRequest;
import edu.adelaide.dto.PageResult;
import edu.adelaide.entity.UserInfo;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * User operations.
 */
public interface UserService {

  /** Create a user record in DB */
  String createUser(CreateUserRequest request);

  /** Find user by business userId */
  Optional<UserInfo> findByUserId(String userId);

  /** Find user by username */
  Optional<List<UserInfo>> findByUsername(String username);

  /** Simple paging list */
  List<UserInfo> listUsers(int page, int size);

  /** Check by userId existence */
  boolean existsByUserId(String userId);

  /** Query all users by page */
  PageResult<UserInfo> pageAll(int page, int size);

  /** New: check if a user already exists locally (spec 9.1) */
  boolean userExists(String userId);

  /** New: register a new local user (spec 9.1) */
  UserInfo registerLocalUser(String userId, Map<String, Object> payload);
}
