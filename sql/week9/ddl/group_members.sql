
CREATE TABLE IF NOT EXISTS `group_members` (
                                               `group_id`   CHAR(36)     NOT NULL COMMENT 'FK to groups.group_id',
                                               `user_id`    VARCHAR(64)  NOT NULL COMMENT 'User identifier (e.g., U1001 or UUID)',
                                               `role`       ENUM('owner','admin','member','readonly') NOT NULL DEFAULT 'member' COMMENT 'Member role in the group',
                                               `wrapped_key`VARCHAR(512) NOT NULL COMMENT 'wrapped_key',
                                               `status`     ENUM('active','left','banned') NOT NULL DEFAULT 'active' COMMENT 'Membership status',
                                               `mute_until` DATETIME     NULL COMMENT 'Optional mute expiry; NULL means not muted',
                                               `joined_at`  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'When the user joined the group',
                                               `updated_at` TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Last update timestamp',
                                               PRIMARY KEY (`group_id`, `user_id`)

) ENGINE=InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci;

ALTER TABLE `group_members`
    ADD COLUMN `wrapped_key` VARCHAR(2048) NULL
        COMMENT 'Per-member wrapped group key (base64url of RSA-OAEP/PBKDF etc.)'
        AFTER `mute_until`;
