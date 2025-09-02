-- MySQL Audit Log Security Analyzer - Index Optimization Script
-- 如果您已經有現有的 audit_log 資料表，請執行此腳本來新增最佳化索引

USE auditdb;

-- 檢查現有索引
-- SHOW INDEX FROM audit_log;

-- 新增最佳化索引（如果不存在的話）

-- 主要時間戳記索引（用於日期範圍查詢）
CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_log (timestamp);

-- 失敗登入分析專用複合索引
CREATE INDEX IF NOT EXISTS idx_failed_login ON audit_log (operation, retcode, timestamp);

-- 特權操作分析專用複合索引
CREATE INDEX IF NOT EXISTS idx_privileged_ops ON audit_log (operation, timestamp);

-- 使用者活動分析專用複合索引
CREATE INDEX IF NOT EXISTS idx_username_timestamp ON audit_log (username, timestamp);

-- 主機/IP 分析專用複合索引
CREATE INDEX IF NOT EXISTS idx_host_operation ON audit_log (host, operation, timestamp);

-- 錯誤分析專用複合索引
CREATE INDEX IF NOT EXISTS idx_retcode_operation ON audit_log (retcode, operation, timestamp);

-- 確保 log_date 索引存在（用於資料分區）
CREATE INDEX IF NOT EXISTS idx_log_date ON audit_log (log_date);

-- 顯示新建立的索引
SHOW INDEX FROM audit_log;

-- 分析資料表統計資訊以優化查詢計劃
ANALYZE TABLE audit_log;

SELECT 'Index optimization completed!' as Status;
