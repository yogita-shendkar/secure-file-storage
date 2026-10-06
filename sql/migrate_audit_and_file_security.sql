-- Run once against an existing database created with create_tables_v1.sql.
ALTER TABLE User
    ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ADD COLUMN approved_at TIMESTAMP NULL,
    ADD COLUMN approved_by INT NULL,
    ADD COLUMN last_login_at TIMESTAMP NULL;

ALTER TABLE File
    ADD COLUMN file_size BIGINT UNSIGNED NULL,
    ADD COLUMN mime_type VARCHAR(100) NULL,
    ADD COLUMN sha256_hash CHAR(64) NULL;

ALTER TABLE Audit_log
    ADD COLUMN detail TEXT,
    ADD COLUMN file_id INT NULL,
    ADD COLUMN ip_address VARCHAR(45),
    ADD COLUMN success BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE Audit_log
    ADD CONSTRAINT fk_audit_file FOREIGN KEY (file_id) REFERENCES File(f_id) ON DELETE SET NULL;

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
