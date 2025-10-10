package edu.adelaide.service;

import edu.adelaide.entity.Groups;

/**
 * Service for CRUD operations on the 'groups' table using primary-key based mapper methods.
 * Notes:
 *  - This service only uses methods available in GroupsMapper you provided.
 *  - If you need search/list features (e.g., by name), you will need additional mapper methods.
 */
public interface GroupsService {

  /**
   * Create a new group.
   * If groupId is null/blank, a random UUID v4 string will be assigned.
   * Returns the final groupId.
   */
  String create(Groups group);

  /**
   * Upsert the built-in "public" group (id = all-zero UUID).
   * Idempotent: if already exists, it does nothing; otherwise inserts the row.
   */
  void ensureBuiltinPublic();

  /**
   * Get a group by primary key (group_id).
   * Returns null if not found.
   */
  Groups getById(String groupId);

  /**
   * Update a group by primary key using selective update.
   * Only non-null fields in 'group' will be updated.
   * Returns true if at least one row was updated.
   */
  boolean updateSelective(Groups group);

  /**
   * Update a group by primary key with all fields (non-selective).
   * Returns true if at least one row was updated.
   */
  boolean updateAll(Groups group);

  /**
   * Update a group by primary key including BLOB/TEXT columns, if your entity has them.
   * Returns true if at least one row was updated.
   */
  boolean updateWithBlobs(Groups group);

  /**
   * Soft delete helper: set is_deleted = 1 for the given group_id (if your schema has this column).
   * Returns true if at least one row was updated.
   */
  boolean softDelete(String groupId);

  /**
   * Hard delete a group by primary key.
   * Returns true if at least one row was deleted.
   */
  boolean deleteById(String groupId);
}
