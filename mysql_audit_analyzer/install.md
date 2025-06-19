CREATE DATABASE auditdb DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;


CREATE USER 'audit_user'@'192.168.1.1' IDENTIFIED BY 'yoga1688';
GRANT SELECT, INSERT,DELETE,UPDATE ON auditdb.audit_log TO 'audit_user'@'10.199.36.75';
FLUSH PRIVILEGES;


CREATE TABLE audit_log (
    log_date      DATE,
    timestamp     VARCHAR(20),
    server_host   VARCHAR(100),
    username      VARCHAR(64),
    host          VARCHAR(100),
    connection_id VARCHAR(20),
    query_id      VARCHAR(20),
    operation     VARCHAR(20),
    dbname        VARCHAR(100),
    query         TEXT,
    retcode       INT,
    INDEX (log_date),
    INDEX (username),
    INDEX (host),
    INDEX (operation)
);


