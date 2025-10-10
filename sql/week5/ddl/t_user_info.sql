CREATE TABLE t_user_info (
     id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT 'Primary key ID',
     user_id VARCHAR(64) NOT NULL UNIQUE COMMENT 'Unique business user ID',
     username VARCHAR(50) NOT NULL COMMENT 'Username or nickname',
     email VARCHAR(100) UNIQUE COMMENT 'Email address',
     phone_number VARCHAR(20) UNIQUE COMMENT 'Phone number',
     password VARCHAR(255) NOT NULL COMMENT 'Hashed password',
     salt VARCHAR(64) DEFAULT NULL COMMENT 'Password salt',
     role VARCHAR(20) DEFAULT 'user' COMMENT 'User role (e.g., admin, user)',
     status TINYINT DEFAULT 1 COMMENT 'Account status: 0=disabled, 1=active',
     avatar_url VARCHAR(255) DEFAULT NULL COMMENT 'Profile picture URL',
     last_login_time DATETIME DEFAULT NULL COMMENT 'Last login time',
     create_time DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT 'Record creation time',
     update_time DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Last update time'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='User information table';
