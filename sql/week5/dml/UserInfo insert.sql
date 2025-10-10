-- Insert demo users into t_user_info
INSERT INTO t_user_info (user_id, username, email, phone_number, password, salt, role, status, avatar_url, last_login_time)
VALUES
    ('U1001', 'alice', 'alice@example.com', '1234567890', '$2a$10$abc123hashedpassword', 'abc123', 'admin', 1, 'https://example.com/avatar/alice.png', NOW()),
    ('U1002', 'bob',   'bob@example.com',   '0987654321', '$2a$10$xyz789hashedpassword', 'xyz789', 'user',  1, 'https://example.com/avatar/bob.png',   NULL),
    ('U1003', 'charlie', 'charlie@example.com', NULL, '$2a$10$qwe456hashedpassword', 'qwe456', 'user', 0, NULL, NULL);
