CREATE TABLE audit_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    log_date DATE,
    timestamp VARCHAR(32),
    server_host VARCHAR(64),
    username VARCHAR(64),
    host VARCHAR(64),
    connection_id VARCHAR(32),
    query_id VARCHAR(32),
    operation VARCHAR(16),
    dbname VARCHAR(64),
    query TEXT,
    retcode INT,
    INDEX (log_date),
    INDEX (username),
    INDEX (host),
    INDEX (operation),
    INDEX (retcode)
);
