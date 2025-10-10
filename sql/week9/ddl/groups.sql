-- ============================================================================
-- Table: groups  (stores channels / groups, including the built-in 'public')
-- Notes:
--   - Uses UUID v4 as primary key (CHAR(36)).
--   - 'name' is unique globally; drop/change the UNIQUE index if you need multi-tenant scopes.
-- ============================================================================
CREATE TABLE IF NOT EXISTS `groups` (
                                        `group_id`   CHAR(36)     NOT NULL COMMENT 'Primary key, UUID v4',
                                        `name`       VARCHAR(100) NOT NULL COMMENT 'Human-readable group/channel name (e.g., public, dev, ops)',
                                        `kind`       ENUM('public','private') NOT NULL DEFAULT 'private' COMMENT 'Channel type',
                                        `description` TEXT        NULL COMMENT 'Optional description',
                                        `created_by` VARCHAR(64)  NULL COMMENT 'Creator user_id; NULL for built-in groups like public',
                                        `is_deleted` TINYINT(1)   NOT NULL DEFAULT 0 COMMENT 'Soft delete flag (0=active, 1=deleted)',
                                        `created_at` TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Creation timestamp',
                                        `updated_at` TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Last update timestamp',
                                        PRIMARY KEY (`group_id`),
                                        UNIQUE KEY `uq_groups_name` (`name`)
) ENGINE=InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci;

-- Seed the built-in public channel (id is fixed to all-zero UUID for convenience).
INSERT INTO `groups` (`group_id`, `name`, `kind`, `description`, `created_by`)
VALUES ('00000000-0000-0000-0000-000000000000', 'public', 'public', 'Built-in public channel', NULL)
ON DUPLICATE KEY UPDATE `name` = VALUES(`name`);
