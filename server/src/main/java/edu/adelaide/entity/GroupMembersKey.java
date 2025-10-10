package edu.adelaide.entity;

import java.io.Serializable;
import java.util.Objects;

/**
 * Composite primary key for table `group_members`: (group_id, user_id).
 */
public class GroupMembersKey implements Serializable {
  private static final long serialVersionUID = 1L;

  private String groupId; // CHAR(36)
  private String userId;  // VARCHAR(64)

  public GroupMembersKey() {}

  public GroupMembersKey(String groupId, String userId) {
    this.groupId = groupId;
    this.userId = userId;
  }

  public String getGroupId() { return groupId; }
  public GroupMembersKey setGroupId(String groupId) { this.groupId = groupId; return this; }

  public String getUserId() { return userId; }
  public GroupMembersKey setUserId(String userId) { this.userId = userId; return this; }

  @Override public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof GroupMembersKey that)) return false;
    return Objects.equals(groupId, that.groupId) &&
        Objects.equals(userId, that.userId);
  }

  @Override public int hashCode() { return Objects.hash(groupId, userId); }

  @Override public String toString() {
    return "GroupMembersKey{groupId='" + groupId + "', userId='" + userId + "'}";
  }
}
