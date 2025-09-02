-- MySQL Audit Log Security Analyzer - 安全索引優化腳本
-- 使用預存程序檢查索引是否存在後再建立
-- 相容於所有 MySQL 版本

USE auditdb;

-- 建立一個臨時預存程序來安全建立索引
DELIMITER $$

DROP PROCEDURE IF EXISTS CreateIndexIfNotExists $$
CREATE PROCEDURE CreateIndexIfNotExists(
    IN table_name VARCHAR(255),
    IN index_name VARCHAR(255), 
    IN index_definition TEXT
)
BEGIN
    DECLARE index_exists INT DEFAULT 0;
    
    -- 檢查索引是否已經存在
    SELECT COUNT(*) INTO index_exists 
    FROM information_schema.statistics 
    WHERE table_schema = DATABASE() 
    AND table_name = table_name 
    AND index_name = index_name;
    
    -- 如果索引不存在，則建立索引
    IF index_exists = 0 THEN
        SET @sql = CONCAT('CREATE INDEX ', index_name, ' ON ', table_name, ' ', index_definition);
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
        SELECT CONCAT('Created index: ', index_name) as Result;
    ELSE
        SELECT CONCAT('Index already exists: ', index_name) as Result;
    END IF;
END$$

DELIMITER ;

-- 執行索引建立
CALL CreateIndexIfNotExists('audit_log', 'idx_timestamp', '(timestamp)');
CALL CreateIndexIfNotExists('audit_log', 'idx_failed_login', '(operation, retcode, timestamp)');
CALL CreateIndexIfNotExists('audit_log', 'idx_privileged_ops', '(operation, timestamp)');
CALL CreateIndexIfNotExists('audit_log', 'idx_username_timestamp', '(username, timestamp)');
CALL CreateIndexIfNotExists('audit_log', 'idx_host_operation', '(host, operation, timestamp)');
CALL CreateIndexIfNotExists('audit_log', 'idx_retcode_operation', '(retcode, operation, timestamp)');
CALL CreateIndexIfNotExists('audit_log', 'idx_log_date', '(log_date)');

-- 清理臨時預存程序
DROP PROCEDURE IF EXISTS CreateIndexIfNotExists;

-- 顯示所有索引
SHOW INDEX FROM audit_log;

-- 分析資料表統計資訊
ANALYZE TABLE audit_log;

SELECT 'All indexes have been created successfully!' as Status;
