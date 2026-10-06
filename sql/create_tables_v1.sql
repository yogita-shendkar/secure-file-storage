CREATE TABLE User (
    u_id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    role ENUM('admin', 'user') DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    approved_at TIMESTAMP NULL,
    approved_by INT NULL,
    last_login_at TIMESTAMP NULL
);
CREATE TABLE Admin (
    a_id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL
);

CREATE TABLE File (

    f_id INT AUTO_INCREMENT PRIMARY KEY,
    f_name VARCHAR(255) NOT NULL,
    f_path VARCHAR(500) NOT NULL,
    owner_id INT,
    upload_date TIMESTAMP default current_timestamp ,
    file_size BIGINT UNSIGNED NULL,
    mime_type VARCHAR(100) NULL,
    sha256_hash CHAR(64) NULL,
    FOREIGN KEY (owner_id) REFERENCES User(u_id)
);

CREATE TABLE Permission (
    p_id INT AUTO_INCREMENT PRIMARY KEY,
    access_level VARCHAR(50) NOT NULL,
    admin_id INT,
    user_id INT,
    file_id INT,
    FOREIGN KEY (admin_id) REFERENCES Admin(a_id),
    FOREIGN KEY (user_id) REFERENCES User(u_id),
    FOREIGN KEY (file_id) REFERENCES File(f_id) ON DELETE SET NULL
);

CREATE TABLE file_shares (
    share_id INT AUTO_INCREMENT PRIMARY KEY,
    file_id INT NOT NULL,
    shared_by INT NOT NULL,
    shared_with INT NOT NULL,
    access_level ENUM('download') NOT NULL DEFAULT 'download',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP NULL,
    UNIQUE KEY unique_file_recipient (file_id, shared_with),
    FOREIGN KEY (file_id) REFERENCES File(f_id) ON DELETE CASCADE,
    FOREIGN KEY (shared_by) REFERENCES User(u_id),
    FOREIGN KEY (shared_with) REFERENCES User(u_id)
);

CREATE TABLE Audit_log (
    log_id INT AUTO_INCREMENT PRIMARY KEY,
    action_type VARCHAR(100),
    action_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    actor_id INT,
    actor_type VARCHAR(10),
    detail TEXT,
    file_id INT NULL,
    ip_address VARCHAR(45),
    success BOOLEAN NOT NULL DEFAULT TRUE,
    FOREIGN KEY (file_id) REFERENCES File(f_id)
);