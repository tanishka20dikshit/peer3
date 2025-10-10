package edu.adelaide.entity;

import java.io.Serializable;
import java.sql.Timestamp;

/**
 * Entity for table `group_members` with composite PK (group_id, user_id).
 */
public class GroupMembers implements Serializable {
    private static final long serialVersionUID = 1L;

    private String groupId;      // PK part 1
    private String userId;       // PK part 2
    private String role;         // owner | admin | member | readonly


    private String wrappedKey;         // owner | admin | member | readonly
    private String status;       // active | left | banned
    private Timestamp muteUntil; // nullable
    private Timestamp joinedAt;  // not null (by schema default)
    private Timestamp updatedAt; // not null (by schema default)

    public String getGroupId() { return groupId; }
    public GroupMembers setGroupId(String groupId) { this.groupId = groupId; return this; }

    public String getUserId() { return userId; }
    public GroupMembers setUserId(String userId) { this.userId = userId; return this; }

    public String getRole() { return role; }
    public GroupMembers setRole(String role) { this.role = role; return this; }


    public String getWrappedKey() {
        return wrappedKey;
    }

    public GroupMembers setWrappedKey(String wrappedKey) {
        this.wrappedKey = wrappedKey;
        return this;
    }

    public String getStatus() { return status; }
    public GroupMembers setStatus(String status) { this.status = status; return this; }

    public Timestamp getMuteUntil() { return muteUntil; }
    public GroupMembers setMuteUntil(Timestamp muteUntil) { this.muteUntil = muteUntil; return this; }

    public Timestamp getJoinedAt() { return joinedAt; }
    public GroupMembers setJoinedAt(Timestamp joinedAt) { this.joinedAt = joinedAt; return this; }

    public Timestamp getUpdatedAt() { return updatedAt; }
    public GroupMembers setUpdatedAt(Timestamp updatedAt) { this.updatedAt = updatedAt; return this; }
}
