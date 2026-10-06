-- Run this once if migrate_audit_and_file_security.sql was already applied.
ALTER TABLE Audit_log
    DROP FOREIGN KEY fk_audit_file;

ALTER TABLE Audit_log
    ADD CONSTRAINT fk_audit_file
    FOREIGN KEY (file_id) REFERENCES File(f_id) ON DELETE SET NULL;