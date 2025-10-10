package edu.adelaide.service;

import edu.adelaide.entity.GroupMembers;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Service for table `group_members` with a composite primary key (group_id, user_id).
 */
public interface GroupMembersService {

  /** Insert a row; the caller must set both PK fields: groupId and userId. */
  boolean create(GroupMembers row);

  /** Select by composite primary key. Returns null if not found. */
  GroupMembers getByPk(String groupId, String userId);

  /** Update by PK (selective). Row must contain groupId and userId. */
  boolean updateSelective(GroupMembers row);

  /** Update by PK (non-selective). Row must contain groupId and userId. */
  boolean updateAll(GroupMembers row);

  /** Delete by composite primary key. */
  boolean deleteByPk(String groupId, String userId);

  // ---- Domain helpers (all require composite PK) ----

  /** Update role for a member (owner | admin | member | readonly). */
  boolean updateRole(String groupId, String userId, String newRole);

  /** Update status for a member (active | left | banned). */
  boolean updateStatus(String groupId, String userId, String newStatus);

  /** Set or clear mute_until; pass null to clear. */
  boolean setMuteUntil(String groupId, String userId, LocalDateTime until);

  /** Upsert membership as ACTIVE (INSERT ... ON DUPLICATE KEY UPDATE). */
//  boolean upsertActive(String groupId, String userId, String roleOrNull);

  /** Mark membership as LEFT (audit-friendly). */
  boolean markLeft(String groupId, String userId);
}
