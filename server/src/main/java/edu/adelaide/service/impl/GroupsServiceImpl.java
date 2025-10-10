package edu.adelaide.service.impl;

import edu.adelaide.entity.Groups;
import edu.adelaide.mapper.GroupsMapper;
import edu.adelaide.service.BaseService;
import edu.adelaide.service.GroupsService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;
import java.util.UUID;

/**
 * Implementation of GroupsService using the primary-key based GroupsMapper.
 */
@Service
public class GroupsServiceImpl extends BaseService implements GroupsService {

  /** Fixed ID for the built-in 'public' group (all-zero UUID). */
  private static final String BUILTIN_PUBLIC_ID = "00000000-0000-0000-0000-000000000000";

  private final GroupsMapper groupsMapper;

  public GroupsServiceImpl(GroupsMapper groupsMapper) {
    this.groupsMapper = groupsMapper;
  }

  @Override
  @Transactional
  public String create(Groups group) {
    return executeWithTransaction("createGroup", () -> {
      validateNotNull(group, "group");
      
      // Assign a random UUID if not provided
      if (group.getGroupId() == null || group.getGroupId().isBlank()) {
        group.setGroupId(UUID.randomUUID().toString());
      }
      // Minimal sanity: name should not be null
      validateNotBlank(group.getName(), "group name");
      
      // Insert (selective to avoid overwriting DB defaults)
      int rows = groupsMapper.insertSelective(group);
      checkOperationResult(rows, "Insert groups");
      return group.getGroupId();
    });
  }

  @Override
  @Transactional
  public void ensureBuiltinPublic() {
    executeWithTransaction("ensureBuiltinPublic", () -> {
      Groups existing = groupsMapper.selectByPrimaryKey(BUILTIN_PUBLIC_ID);
      if (existing != null) {
        // Make sure basic invariants are correct; fix if necessary
        boolean needFix = false;
        if (!Objects.equals(existing.getName(), "public")) {
          existing.setName("public"); needFix = true;
        }
        if (existing.getKind() != null && !"public".equals(existing.getKind())) {
          existing.setKind("public"); needFix = true;
        }
        // If your schema includes is_deleted (TINYINT), keep it active
        if (existing.getIsDeleted() != null && existing.getIsDeleted()) {
          existing.setIsDeleted(false); needFix = true;
        }
        if (needFix) {
          groupsMapper.updateByPrimaryKeySelective(existing);
        }
        return null;
      }

      Groups pub = new Groups();
      pub.setGroupId(BUILTIN_PUBLIC_ID);
      pub.setName("public");
      pub.setKind("public");
      pub.setDescription("Built-in public channel");
      // If exists in your entity:
      pub.setIsDeleted(false);

      int rows = groupsMapper.insertSelective(pub);
      checkOperationResult(rows, "Insert built-in public group");
      return null;
    });
  }

  @Override
  public Groups getById(String groupId) {
    validateId(groupId, "groupId");
    return groupsMapper.selectByPrimaryKey(groupId);
  }

  @Override
  @Transactional
  public boolean updateSelective(Groups group) {
    return executeWithTransaction("updateSelective", () -> {
      validateNotNull(group, "group");
      validateId(group.getGroupId(), "groupId");
      
      int rows = groupsMapper.updateByPrimaryKeySelective(group);
      return rows > 0;
    });
  }

  @Override
  @Transactional
  public boolean updateAll(Groups group) {
    return executeWithTransaction("updateAll", () -> {
      validateNotNull(group, "group");
      validateId(group.getGroupId(), "groupId");
      
      int rows = groupsMapper.updateByPrimaryKey(group);
      return rows > 0;
    });
  }

  @Override
  @Transactional
  public boolean updateWithBlobs(Groups group) {
    return executeWithTransaction("updateWithBlobs", () -> {
      validateNotNull(group, "group");
      validateId(group.getGroupId(), "groupId");
      
      int rows = groupsMapper.updateByPrimaryKeyWithBLOBs(group);
      return rows > 0;
    });
  }

  @Override
  @Transactional
  public boolean softDelete(String groupId) {
    return executeWithTransaction("softDelete", () -> {
      validateId(groupId, "groupId");
      
      // This assumes your Groups entity has an isDeleted field (TINYINT)
      Groups patch = new Groups();
      patch.setGroupId(groupId);
      patch.setIsDeleted(true);
      int rows = groupsMapper.updateByPrimaryKeySelective(patch);
      return rows > 0;
    });
  }

  @Override
  @Transactional
  public boolean deleteById(String groupId) {
    return executeWithTransaction("deleteById", () -> {
      validateId(groupId, "groupId");
      int rows = groupsMapper.deleteByPrimaryKey(groupId);
      return rows > 0;
    });
  }
}
