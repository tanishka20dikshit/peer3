package edu.adelaide.service.impl;

import edu.adelaide.entity.GroupMembers;
import edu.adelaide.entity.GroupMembersKey;
import edu.adelaide.mapper.GroupMembersMapper;
import edu.adelaide.service.BaseService;
import edu.adelaide.service.GroupMembersService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.time.LocalDateTime;

/**
 * Implementation of GroupMembersService for composite PK (group_id, user_id).
 */
@Service
public class GroupMembersServiceImpl extends BaseService implements GroupMembersService {

  private final GroupMembersMapper groupMembersMapper;

  public GroupMembersServiceImpl(GroupMembersMapper groupMembersMapper) {
    this.groupMembersMapper = groupMembersMapper;
  }

  // ----------------------------------------------------
  // CRUD
  // ----------------------------------------------------

  @Override
  @Transactional
  public boolean create(GroupMembers row) {
    return executeWithTransaction("createGroupMember", () -> {
      validateNotNull(row, "row");
      validateCompositeKey(row.getGroupId(), row.getUserId(), "groupId", "userId");
      
      int n = groupMembersMapper.insertSelective(row);
      checkOperationResult(n, "Insert group_members");
      return true;
    });
  }

  @Override
  public GroupMembers getByPk(String groupId, String userId) {
    validateCompositeKey(groupId, userId, "groupId", "userId");
    return groupMembersMapper.selectByPrimaryKey(new GroupMembersKey(groupId, userId));
  }

  @Override
  @Transactional
  public boolean updateSelective(GroupMembers row) {
    return executeWithTransaction("updateSelective", () -> {
      validateNotNull(row, "row");
      validateCompositeKey(row.getGroupId(), row.getUserId(), "groupId", "userId");
      
      int rows = groupMembersMapper.updateByPrimaryKeySelective(row);
      return rows > 0;
    });
  }

  @Override
  @Transactional
  public boolean updateAll(GroupMembers row) {
    return executeWithTransaction("updateAll", () -> {
      validateNotNull(row, "row");
      validateCompositeKey(row.getGroupId(), row.getUserId(), "groupId", "userId");
      
      int rows = groupMembersMapper.updateByPrimaryKey(row);
      return rows > 0;
    });
  }

  @Override
  @Transactional
  public boolean deleteByPk(String groupId, String userId) {
    return executeWithTransaction("deleteByPk", () -> {
      validateCompositeKey(groupId, userId, "groupId", "userId");
      int rows = groupMembersMapper.deleteByPrimaryKey(new GroupMembersKey(groupId, userId));
      return rows > 0;
    });
  }

  // ----------------------------------------------------
  // Domain helpers
  // ----------------------------------------------------

  @Override
  @Transactional
  public boolean updateRole(String groupId, String userId, String newRole) {
    return executeWithTransaction("updateRole", () -> {
      validateCompositeKey(groupId, userId, "groupId", "userId");
      
      GroupMembers patch = new GroupMembers()
          .setGroupId(groupId)
          .setUserId(userId)
          .setRole(newRole);
      int rows = groupMembersMapper.updateByPrimaryKeySelective(patch);
      return rows > 0;
    });
  }

  @Override
  @Transactional
  public boolean updateStatus(String groupId, String userId, String newStatus) {
    return executeWithTransaction("updateStatus", () -> {
      validateCompositeKey(groupId, userId, "groupId", "userId");
      
      GroupMembers patch = new GroupMembers()
          .setGroupId(groupId)
          .setUserId(userId)
          .setStatus(newStatus);
      int rows = groupMembersMapper.updateByPrimaryKeySelective(patch);
      return rows > 0;
    });
  }

  @Override
  @Transactional
  public boolean setMuteUntil(String groupId, String userId, LocalDateTime until) {
    return executeWithTransaction("setMuteUntil", () -> {
      validateCompositeKey(groupId, userId, "groupId", "userId");
      
      GroupMembers patch = new GroupMembers()
          .setGroupId(groupId)
          .setUserId(userId)
          .setMuteUntil(until == null ? null : Timestamp.valueOf(until));
      int rows = groupMembersMapper.updateByPrimaryKeySelective(patch);
      return rows > 0;
    });
  }

//  @Override
//  @Transactional
//  public boolean upsertActive(String groupId, String userId, String roleOrNull) {
//    requirePk(groupId, userId);
//    return groupMembersMapper.upsertActive(groupId, userId, roleOrNull) > 0;
//  }

  @Override
  @Transactional
  public boolean markLeft(String groupId, String userId) {
    return executeWithTransaction("markLeft", () -> {
      validateCompositeKey(groupId, userId, "groupId", "userId");
      int rows = groupMembersMapper.markLeft(groupId, userId);
      return rows > 0;
    });
  }
}
