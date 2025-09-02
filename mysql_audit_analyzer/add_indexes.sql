


#!/usr/bin/env python3




# -*- coding: utf-8 -*-

首先檢查現有索引狀況：
USE auditdb;
SHOW INDEX FROM audit_log;




按重要性順序手動建立索引：




1.
時間戳記索引（最重要）：
CREATE INDEX idx_timestamp ON audit_log (timestamp);用途：所有日期範圍查詢的基礎索引

2.
失敗登入分析索引：
CREATE INDEX idx_failed_login ON audit_log (operation,retcode, timestamp);
用途：偵測暴力破解攻擊和可疑登入活動

3.
特權操作分析索引：
CREATE INDEX idx_privileged_ops ON audit_log
(operation, timestamp);
用途：監控管理員權限操作和特權提升

4.
使用者活動分析索引：
CREATE INDEX idx_username_timestamp ON audit_log
(username, timestamp);
用途：使用者行為分析和內部威脅偵測

5.
主機/IP分析索引：
CREATE INDEX idx_host_operation ON audit_log (host,operation, timestamp);
用途：網路安全分析和未授權IP偵測

6.
錯誤分析索引：
CREATE INDEX idx_retcode_operation ON audit_log
(retcode, operation, timestamp);
用途：系統錯誤監控和異常行為分析




建立完成後的檢查：
-- 查看所有索引
SHOW INDEX FROM audit_log;




-- 更新統計資訊
ANALYZE TABLE audit_log;




你可以先執行前 3
個最重要的索引，測試效能後再決定是否繼續建立其他索引。每執行一個就可以測試一下查詢效能的改善。







import os, sys, argparse, gzip, csv, calendar, tempfile, time, psutil, threading




from datetime import datetime, timedelta




from typing import List, Optional




import pymysql




import smtplib




from email.message import EmailMessage




from contextlib import contextmanager




import queue




import threading




# 全域資源監控變數




_resource_monitor = None




_query_semaphore = None




class ResourceMonitor:




    """資源監控類別 - 監控記憶體使用量並提供告警"""




    def __init__(self, max_memory_mb=1024):




        self.max_memory_mb = max_memory_mb




        self.max_memory_bytes = max_memory_mb * 1024 * 1024




        self.process = psutil.Process()




        self.monitoring = False




    def get_memory_usage_mb(self):




        """取得目前記憶體使用量 (MB)"""




        try:




            memory_info = self.process.memory_info()




            return memory_info.rss / 1024 / 1024




        except:




            return 0




    def check_memory_limit(self):




        """檢查記憶體是否超過限制"""




        current_mb = self.get_memory_usage_mb()




        if current_mb > self.max_memory_mb:




            print(f"⚠️  記憶體使用量警告: {current_mb:.1f}MB / {self.max_memory_mb}MB")




            return False




        return True




    def force_gc_if_needed(self):




        """必要時強制垃圾回收"""




        import gc




        if not self.check_memory_limit():




            print("🗑️  執行垃圾回收以釋放記憶體...")




            gc.collect()




            time.sleep(0.5)  # 給系統時間釋放記憶體




            return True




        return False




class SimpleConnectionPool:




    """簡單的 MySQL 連接池實現"""




    def __init__(self, host, port, user, password, database, charset='utf8mb4',




                 max_connections=10, **kwargs):




        self.host = host




        self.port = port




        self.user = user




        self.password = password




        self.database = database




        self.charset = charset




        self.max_connections = max_connections




        self.kwargs = kwargs




        self._pool = queue.Queue(maxsize=max_connections)




        self._lock = threading.Lock()




        self._created_connections = 0




    def get_connection(self):




        """從連接池獲取連接"""




        try:




            # 嘗試從池中獲取現有連接




            conn = self._pool.get_nowait()




            # 檢查連接是否仍然有效




            try:




                conn.ping(reconnect=True)




                return conn




            except:




                # 連接已失效，創建新連接




                pass




        except queue.Empty:




            pass




        # 創建新連接




        with self._lock:




            if self._created_connections < self.max_connections:




                conn = pymysql.connect(




                    host=self.host,




                    port=self.port,




                    user=self.user,




                    password=self.password,




                    database=self.database,




                    charset=self.charset,




                    autocommit=True,




                    local_infile=True,




                    **self.kwargs




                )




                self._created_connections += 1




                return conn




        # 池已滿，等待可用連接




        return self._pool.get(timeout=30)




    def release_connection(self, conn):




        """釋放連接回池中"""




        if conn and conn.open:




            try:




                self._pool.put_nowait(conn)




            except queue.Full:




                # 池已滿，關閉連接




                conn.close()




# 加入 tqdm 支援




try:




    from tqdm import tqdm




    TQDM_AVAILABLE = True




except ImportError:




    TQDM_AVAILABLE = False




    print("⚠️  建議安裝 tqdm 以獲得更好的進度顯示：pip install tqdm")




# 加入 dotenv 支援




try:




    from dotenv import load_dotenv




    load_dotenv()




except ImportError:




    print("❌ 請先安裝 python-dotenv：pip install python-dotenv")




    sys.exit(1)




try:




    from reportlab.lib.pagesizes import A4




    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle




    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle




    from reportlab.lib import colors




    REPORTLAB_AVAILABLE = True




except ImportError:




    REPORTLAB_AVAILABLE = False




class Config:




    def __init__(self):




        self.mysql_host = os.getenv('MYSQL_HOST', 'localhost')




        self.mysql_port = int(os.getenv('MYSQL_PORT', '3306'))




        self.mysql_user = os.getenv('MYSQL_USER', 'root')




        self.mysql_password = os.getenv('MYSQL_PASSWORD', '')




        self.mysql_db = os.getenv('MYSQL_DB', 'auditdb')




        # 新增資料庫連線池和效能相關設定




        self.db_pool_size = int(os.getenv('DB_POOL_SIZE', '5'))




        self.db_max_overflow = int(os.getenv('DB_MAX_OVERFLOW', '10'))




        self.db_pool_timeout = int(os.getenv('DB_POOL_TIMEOUT', '30'))




        self.db_query_timeout = int(os.getenv('DB_QUERY_TIMEOUT', '300'))




        self.max_fetch_size = int(os.getenv('MAX_FETCH_SIZE', '100000'))




        self.batch_fetch_size = int(os.getenv('BATCH_FETCH_SIZE', '10000'))




        self.query_retry_count = int(os.getenv('QUERY_RETRY_COUNT', '3'))




        self.retry_delay = float(os.getenv('RETRY_DELAY', '1.0'))




        # 資源限制和節流控制




        self.max_memory_usage_mb = int(os.getenv('MAX_MEMORY_USAGE_MB', '1024'))




        self.query_throttle_delay = float(os.getenv('QUERY_THROTTLE_DELAY', '0.1'))




        self.enable_resource_monitoring = os.getenv('ENABLE_RESOURCE_MONITORING', 'true').lower() == 'true'




        self.max_concurrent_queries = int(os.getenv('MAX_CONCURRENT_QUERIES', '3'))




        self.log_base_path = os.getenv('LOG_BASE_PATH', '/var/log/mysql/audit')




        self.log_file_prefix = os.getenv('LOG_FILE_PREFIX', 'server_audit.log')




        self.output_dir = os.getenv('OUTPUT_DIR', '/tmp/mysql_reports')




        self.failed_login_threshold = int(os.getenv('FAILED_LOGIN_THRESHOLD', '5'))




        self.allowed_ips = [ip.strip() for ip in os.getenv('ALLOWED_IPS', '').split(',') if ip.strip()]




        self.after_hours_users = [u.strip() for u in os.getenv('AFTER_HOURS_USERS', '').split(',') if u.strip()]




        self.work_hour_start = int(os.getenv('WORK_HOUR_START', '9'))




        self.work_hour_end = int(os.getenv('WORK_HOUR_END', '18'))




        self.privileged_users = [u.strip() for u in os.getenv('PRIVILEGED_USERS', '').split(',') if u.strip()]




        self.report_title = os.getenv('REPORT_TITLE', 'MySQL Audit Log Security Analysis Report')




        self.company_name = os.getenv('COMPANY_NAME', 'Your Company')




        self.generate_pdf = os.getenv('GENERATE_PDF', 'true').lower() == 'true'




        self.generate_csv = os.getenv('GENERATE_CSV', 'true').lower() == 'true'




        self.privileged_keywords = [k.strip() for k in os.getenv(




            'PRIVILEGED_KEYWORDS',




            'CREATE USER,DROP USER,GRANT,REVOKE,CREATE DATABASE,DROP DATABASE,CREATE TABLE,DROP TABLE,ALTER USER,SET PASSWORD'




        ).split(',') if k.strip()]




        self.send_email = os.getenv('SEND_EMAIL', 'false').lower() == 'true'




        self.smtp_server = os.getenv('SMTP_SERVER', '')




        self.smtp_port = int(os.getenv('SMTP_PORT', '25'))




        self.mail_from = os.getenv('MAIL_FROM', '')




        self.mail_to = [m.strip() for m in os.getenv('MAIL_TO', '').split(',') if m.strip()]




        # 新增 LOAD DATA INFILE 相關設定




        self.use_load_data_infile = os.getenv('USE_LOAD_DATA_INFILE', 'true').lower() == 'true'




        self.temp_dir = os.getenv('TEMP_DIR', '/tmp')




    def get_log_file_path(self, date_str: str = None) -> str:




        return os.path.join(self.log_base_path, self.log_file_prefix if not date_str else f"{self.log_file_prefix}-{date_str}")




    def as_dict(self):




        return {




            "MYSQL_HOST": self.mysql_host,




            "MYSQL_PORT": self.mysql_port,




            "MYSQL_USER": self.mysql_user,




            "MYSQL_PASSWORD": self.mysql_password,




            "MYSQL_DB": self.mysql_db,




            "LOG_BASE_PATH": self.log_base_path,




            "LOG_FILE_PREFIX": self.log_file_prefix,




            "OUTPUT_DIR": self.output_dir,




            "FAILED_LOGIN_THRESHOLD": self.failed_login_threshold,




            "ALLOWED_IPS": self.allowed_ips,




            "AFTER_HOURS_USERS": self.after_hours_users,




            "WORK_HOUR_START": self.work_hour_start,




            "WORK_HOUR_END": self.work_hour_end,




            "PRIVILEGED_USERS": self.privileged_users,




            "REPORT_TITLE": self.report_title,




            "COMPANY_NAME": self.company_name,




            "GENERATE_PDF": self.generate_pdf,




            "GENERATE_CSV": self.generate_csv,




            "PRIVILEGED_KEYWORDS": self.privileged_keywords,




            "SEND_EMAIL": self.send_email,




            "SMTP_SERVER": self.smtp_server,




            "SMTP_PORT": self.smtp_port,




            "MAIL_FROM": self.mail_from,




            "MAIL_TO": self.mail_to,




            "USE_LOAD_DATA_INFILE": self.use_load_data_infile,




            "TEMP_DIR": self.temp_dir,




        }




def init_resource_monitoring(config: Config):




    """初始化資源監控"""




    global _resource_monitor, _query_semaphore




    if config.enable_resource_monitoring:




        _resource_monitor = ResourceMonitor(config.max_memory_usage_mb)




        print(f"✅ 資源監控初始化完成 (記憶體限制: {config.max_memory_usage_mb}MB)")




    _query_semaphore = threading.Semaphore(config.max_concurrent_queries)




    print(f"✅ 查詢並行控制初始化完成 (最大並行: {config.max_concurrent_queries})")




# 全域連線池變數




_connection_pool = None




def init_connection_pool(config: Config):




    """




    初始化資料庫連線池




    """




    global _connection_pool




    if _connection_pool is None:




        _connection_pool = SimpleConnectionPool(




            host=config.mysql_host,




            port=config.mysql_port,




            user=config.mysql_user,




            password=config.mysql_password,




            database=config.mysql_db,




            charset='utf8mb4',




            max_connections=config.db_pool_size + config.db_max_overflow,




            # 連線超時設定




            connect_timeout=30,




            read_timeout=config.db_query_timeout,




            write_timeout=config.db_query_timeout,




            # 優化設定




            cursorclass=pymysql.cursors.SSCursor,  # 使用伺服器端游標




        )




        print(f"✅ 資料庫連線池初始化完成 (池大小: {config.db_pool_size}, 最大連線: {config.db_pool_size + config.db_max_overflow})")




@contextmanager




def get_db_conn(config: Config):




    """




    取得資料庫連線 (使用連線池和自動釋放)




    """




    if _connection_pool is None:




        init_connection_pool(config)




    conn = None




    try:




        conn = _connection_pool.get_connection()




        yield conn




    except Exception as e:




        if conn:




            conn.rollback()




        raise e




    finally:




        if conn:




            _connection_pool.release_connection(conn)




def get_legacy_db_conn(config: Config):




    """




    取得傳統資料庫連線 (用於不支援 context manager 的舊程式碼)




    """




    return pymysql.connect(




        host=config.mysql_host,




        port=config.mysql_port,




        user=config.mysql_user,




        password=config.mysql_password,




        database=config.mysql_db,




        charset='utf8mb4',




        autocommit=True,




        local_infile=True,




        connect_timeout=30,




        read_timeout=config.db_query_timeout,




        write_timeout=config.db_query_timeout




    )




def execute_query_with_retry(conn, query, params=None, config=None, fetch_mode='fetchall'):




    """




    執行查詢並加入重試機制、記憶體管理和資源監控




    Args:




        conn: 資料庫連線




        query: SQL查詢語句




        params: 查詢參數




        config: 設定物件




        fetch_mode: 'fetchall', 'fetchone', 'fetchmany', 'iterator'




    Returns:




        查詢結果




    """




    global _resource_monitor, _query_semaphore




    retry_count = config.query_retry_count if config else 3




    retry_delay = config.retry_delay if config else 1.0




    max_fetch_size = config.max_fetch_size if config else 100000




    batch_size = config.batch_fetch_size if config else 10000




    throttle_delay = config.query_throttle_delay if config else 0.1




    # 資源監控和並行控制




    if _resource_monitor:




        _resource_monitor.force_gc_if_needed()




    # 使用信號量控制並行查詢數量




    if _query_semaphore:




        _query_semaphore.acquire()




    try:




        for attempt in range(retry_count):




            try:




                # 查詢節流




                if throttle_delay > 0:




                    time.sleep(throttle_delay)




                with conn.cursor() as cur:




                    # 設定查詢超時和優化參數




                    if config:




                        cur.execute(f"SET SESSION innodb_lock_wait_timeout = {min(config.db_query_timeout, 50)}")




                        cur.execute("SET SESSION query_cache_type = ON")




                        cur.execute(f"SET SESSION max_execution_time = {config.db_query_timeout * 1000}")




                    cur.execute(query, params)




                    if fetch_mode == 'fetchone':




                        result = cur.fetchone()




                    elif fetch_mode == 'fetchmany':




                        result = cur.fetchmany(batch_size)




                    elif fetch_mode == 'iterator':




                        result = cur  # 回傳游標迭代器，節省記憶體




                    elif fetch_mode == 'fetchall_safe':




                        # 安全的 fetchall，限制結果數量並監控記憶體




                        results = []




                        count = 0




                        while True:




                            # 檢查記憶體使用量




                            if _resource_monitor and not _resource_monitor.check_memory_limit():




                                print(f"⚠️  記憶體不足，查詢結果截斷於 {count:,} 筆")




                                break




                            batch = cur.fetchmany(batch_size)




                            if not batch:




                                break




                            results.extend(batch)




                            count += len(batch)




                            if count >= max_fetch_size:




                                print(f"⚠️  查詢結果超過限制 ({max_fetch_size:,} 筆)，已截斷")




                                break




                        result = results




                    else:  # fetchall (default)




                        result = cur.fetchall()




                    return result




            except (pymysql.Error, Exception) as e:




                if attempt < retry_count - 1:




                    print(f"⚠️  查詢失敗，第 {attempt + 1}/{retry_count} 次重試... 錯誤: {str(e)}")




                    time.sleep(retry_delay * (attempt + 1))  # 指數退避




                else:




                    print(f"❌ 查詢最終失敗: {str(e)}")




                    raise e




    finally:




        # 釋放信號量




        if _query_semaphore:




            _query_semaphore.release()




def get_file_line_count(file_path):




    """快速計算檔案行數，用於進度條"""




    try:




        if file_path.endswith('.gz'):




            with gzip.open(file_path, 'rt', encoding='utf-8', errors='ignore') as f:




                return sum(1 for _ in f)




        else:




            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:




                return sum(1 for _ in f)




    except:




        return 0




def import_log_file_to_db_optimized(file_path, log_date, conn, config):




    """




    使用 LOAD DATA INFILE 優化版本的日誌匯入函數（加入進度條）




    """




    print(f"🚀 開始優化匯入 {file_path}...")




    # 計算檔案行數用於進度條




    if TQDM_AVAILABLE:




        print("📊 正在計算檔案大小...")




        total_lines = get_file_line_count(file_path)




        if total_lines == 0:




            print(f"⚠️  檔案 {file_path} 沒有資料")




            return




    # 建立臨時 CSV 檔案




    temp_csv = tempfile.NamedTemporaryFile(




        mode='w',




        suffix='.csv',




        dir=config.temp_dir,




        delete=False,




        encoding='utf-8'




    )




    try:




        # 讀取原始日誌檔案並轉換為標準 CSV 格式




        with (gzip.open(file_path, 'rt', encoding='utf-8', errors='ignore')




              if file_path.endswith('.gz')




              else open(file_path, 'r', encoding='utf-8', errors='ignore')) as f:




            reader = csv.reader(f)




            writer = csv.writer(temp_csv, quoting=csv.QUOTE_ALL)




            # 建立進度條




            if TQDM_AVAILABLE:




                progress_bar = tqdm(




                    total=total_lines,




                    desc="📝 處理日誌資料",




                    unit="行",




                    unit_scale=True,




                    colour='green'




                )




            row_count = 0




            start_time = datetime.now()




            for row in reader:




                # 確保欄位數量一致




                row += [''] * (10 - len(row))




                timestamp, server_host, username, host, connection_id, query_id, operation, database, query, retcode = row[:10]




                # 處理 retcode




                try:




                    retcode = int(retcode) if retcode else 0




                except:




                    retcode = 0




                # 寫入臨時 CSV 檔案




                writer.writerow([




                    log_date, timestamp, server_host, username, host,




                    connection_id, query_id, operation, database, query, retcode




                ])




                row_count += 1




                # 更新進度條




                if TQDM_AVAILABLE:




                    progress_bar.update(1)




                    if row_count % 10000 == 0:  # 每 10000 筆更新一次描述




                        progress_bar.set_postfix({




                            '已處理': f'{row_count:,}',




                            '速度': f'{row_count/(datetime.now()-start_time).total_seconds():.0f}/秒'




                        })




            if TQDM_AVAILABLE:




                progress_bar.close()




        temp_csv.close()




        if row_count == 0:




            print(f"⚠️  檔案 {file_path} 沒有資料")




            return




        processing_time = (datetime.now() - start_time).total_seconds()




        print(f"✅ 資料處理完成: {row_count:,} 筆，耗時 {processing_time:.2f} 秒")




        # 使用 LOAD DATA LOCAL INFILE 批量載入




        print("💾 正在載入資料到資料庫...")




        db_start_time = datetime.now()




        with conn.cursor() as cur:




            # 先檢查是否已存在該日期的資料，如果有則先刪除




            cur.execute("DELETE FROM audit_log WHERE log_date = %s", (log_date,))




            deleted_count = cur.rowcount




            if deleted_count > 0:




                print(f"🗑️  刪除舊資料 {deleted_count:,} 筆")




            # 執行 LOAD DATA LOCAL INFILE




            load_sql = f"""




            LOAD DATA LOCAL INFILE '{temp_csv.name}'




            INTO TABLE audit_log




            FIELDS TERMINATED BY ','




            OPTIONALLY ENCLOSED BY '"'




            LINES TERMINATED BY '\\n'




            (log_date, timestamp, server_host, username, host, connection_id, query_id, operation, dbname, query, retcode)




            """




            cur.execute(load_sql)




            # 獲取實際載入的行數




            cur.execute("SELECT ROW_COUNT()")




            loaded_rows = cur.fetchone()[0]




            db_duration = (datetime.now() - db_start_time).total_seconds()




            total_duration = (datetime.now() - start_time).total_seconds()




            print(f"✅ 優化匯入 {os.path.basename(file_path)} 完成")




            print(f"   📊 處理資料: {row_count:,} 筆")




            print(f"   📥 載入資料: {loaded_rows:,} 筆")




            print(f"   ⏱️  處理耗時: {processing_time:.2f} 秒")




            print(f"   💾 載入耗時: {db_duration:.2f} 秒")




            print(f"   🕒 總耗時: {total_duration:.2f} 秒")




            print(f"   🚀 總速度: {loaded_rows/total_duration:.0f} 筆/秒")




    except Exception as e:




        print(f"❌ 優化匯入失敗: {e}")




        # 如果 LOAD DATA INFILE 失敗，回退到原始方法




        print("🔄 回退到原始匯入方法...")




        import_log_file_to_db_fallback(file_path, log_date, conn)




    finally:




        # 清理臨時檔案




        try:




            os.unlink(temp_csv.name)




        except:




            pass




def import_log_file_to_db_fallback(file_path, log_date, conn):




    """




    原始的逐筆插入方法（作為備用方案，加入進度條）




    """




    print(f"📝 使用原始方法匯入 {file_path}...")




    # 計算檔案行數用於進度條




    if TQDM_AVAILABLE:




        print("📊 正在計算檔案大小...")




        total_lines = get_file_line_count(file_path)




        if total_lines == 0:




            print(f"⚠️  檔案 {file_path} 沒有資料")




            return




    with (gzip.open(file_path, 'rt', encoding='utf-8', errors='ignore')




          if file_path.endswith('.gz')




          else open(file_path, 'r', encoding='utf-8', errors='ignore')) as f:




        reader = csv.reader(f)




        data = []




        # 建立進度條




        if TQDM_AVAILABLE:




            progress_bar = tqdm(




                total=total_lines,




                desc="📝 讀取日誌資料",




                unit="行",




                unit_scale=True,




                colour='blue'




            )




        start_time = datetime.now()




        for row in reader:




            row += [''] * (10 - len(row))




            timestamp, server_host, username, host, connection_id, query_id, operation, database, query, retcode = row[:10]




            try:




                retcode = int(retcode) if retcode else 0




            except:




                retcode = 0




            data.append((log_date, timestamp, server_host, username, host, connection_id, query_id, operation, database, query, retcode))




            if TQDM_AVAILABLE:




                progress_bar.update(1)




        if TQDM_AVAILABLE:




            progress_bar.close()




        if not data:




            print(f"⚠️  檔案 {file_path} 沒有資料")




            return




        processing_time = (datetime.now() - start_time).total_seconds()




        print(f"✅ 資料讀取完成: {len(data):,} 筆，耗時 {processing_time:.2f} 秒")




        # 資料庫操作




        print("💾 正在寫入資料庫...")




        db_start_time = datetime.now()




        with conn.cursor() as cur:




            # 先刪除該日期的舊資料




            cur.execute("DELETE FROM audit_log WHERE log_date = %s", (log_date,))




            deleted_count = cur.rowcount




            if deleted_count > 0:




                print(f"🗑️  刪除舊資料 {deleted_count:,} 筆")




            # 批量插入（使用 executemany）




            sql = """INSERT INTO audit_log




                    (log_date, timestamp, server_host, username, host, connection_id, query_id, operation, dbname, query, retcode)




                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""




            # 如果資料量很大，可以分批處理




            batch_size = 10000




            if len(data) > batch_size:




                if TQDM_AVAILABLE:




                    batch_progress = tqdm(




                        total=len(data),




                        desc="💾 批量寫入",




                        unit="筆",




                        unit_scale=True,




                        colour='cyan'




                    )




                for i in range(0, len(data), batch_size):




                    batch = data[i:i+batch_size]




                    cur.executemany(sql, batch)




                    if TQDM_AVAILABLE:




                        batch_progress.update(len(batch))




                if TQDM_AVAILABLE:




                    batch_progress.close()




            else:




                cur.executemany(sql, data)




            db_duration = (datetime.now() - db_start_time).total_seconds()




            total_duration = (datetime.now() - start_time).total_seconds()




            print(f"✅ 原始方法匯入 {os.path.basename(file_path)} 完成")




            print(f"   📊 載入資料: {len(data):,} 筆")




            print(f"   ⏱️  讀取耗時: {processing_time:.2f} 秒")




            print(f"   💾 寫入耗時: {db_duration:.2f} 秒")




            print(f"   🕒 總耗時: {total_duration:.2f} 秒")




            print(f"   🐌 總速度: {len(data)/total_duration:.0f} 筆/秒")




def import_log_file_to_db(file_path, log_date, conn, config=None):




    """




    主要的日誌匯入函數 - 根據設定選擇優化或原始方法




    """




    if config and config.use_load_data_infile:




        import_log_file_to_db_optimized(file_path, log_date, conn, config)




    else:




        import_log_file_to_db_fallback(file_path, log_date, conn)




def get_log_files_for_month(config, month_str):




    log_files = []




    year, month = map(int, month_str.split('-'))




    days_in_month = calendar.monthrange(year, month)[1]




    for day in range(1, days_in_month + 1):




        date_str = f"{year:04d}-{month:02d}-{day:02d}"




        log_path = config.get_log_file_path(date_str)




        if os.path.exists(log_path):




            log_files.append((log_path, date_str))




        elif os.path.exists(log_path + '.gz'):




            log_files.append((log_path + '.gz', date_str))




    return log_files




def get_log_file_for_date(config, date_str):




    log_path = config.get_log_file_path(date_str)




    if os.path.exists(log_path):




        return (log_path, date_str)




    elif os.path.exists(log_path + '.gz'):




        return (log_path + '.gz', date_str)




    else:




        return None




# ========== 分析查詢（加入進度顯示） ==========




def run_analysis_with_progress(analysis_functions, conn, date_filter, date_filter_value, config):




    """




    執行所有分析功能並顯示進度




    """




    results = {}




    if TQDM_AVAILABLE:




        progress_bar = tqdm(




            total=len(analysis_functions),




            desc="🔍 執行安全分析",




            unit="項目",




            colour='magenta'




        )




    for name, func, args in analysis_functions:




        start_time = datetime.now()




        if TQDM_AVAILABLE:




            progress_bar.set_description(f"🔍 分析: {name}")




        try:




            if args:




                results[name] = func(conn, date_filter, date_filter_value, *args, config=config)




            else:




                results[name] = func(conn, date_filter, date_filter_value, config=config)




            duration = (datetime.now() - start_time).total_seconds()




            if not TQDM_AVAILABLE:




                print(f"✅ {name} 完成 ({duration:.2f}秒)")




        except Exception as e:




            print(f"❌ {name} 失敗: {e}")




            results[name] = None




        if TQDM_AVAILABLE:




            progress_bar.update(1)




    if TQDM_AVAILABLE:




        progress_bar.close()




    return results




def analyze_summary(conn, date_filter, date_filter_value, config=None):




    """基本統計分析 - 使用優化查詢"""




    if isinstance(date_filter_value, tuple):




        params = date_filter_value




    else:




        params = (date_filter_value,)




    query = f"SELECT COUNT(*), COUNT(DISTINCT username), COUNT(DISTINCT host) FROM audit_log WHERE {date_filter}"




    result = execute_query_with_retry(conn, query, params, config, 'fetchone')




    if result:




        total_events, unique_users, unique_hosts = result




        return {




            'total_events': total_events,




            'unique_users': unique_users,




            'unique_hosts': unique_hosts




        }




    return {'total_events': 0, 'unique_users': 0, 'unique_hosts': 0}




def analyze_failed_logins(conn, date_filter, date_filter_value, threshold=5, config=None):




    """失敗登入分析 - 使用優化查詢和結果限制"""




    if isinstance(date_filter_value, tuple):




        params = date_filter_value + (threshold,)




        params2 = date_filter_value




    else:




        params = (date_filter_value, threshold)




        params2 = (date_filter_value,)




    # 查詢可疑使用者 (加入 LIMIT 限制)




    query1 = f"""SELECT username, COUNT(*) as fail_count




                FROM audit_log




                WHERE operation='CONNECT' AND retcode!=0 AND {date_filter}




                GROUP BY username




                HAVING fail_count >= %s




                ORDER BY fail_count DESC




                LIMIT 1000"""




    by_user = execute_query_with_retry(conn, query1, params, config, 'fetchall_safe')




    # 查詢可疑IP (加入 LIMIT 限制)




    query2 = f"""SELECT host, COUNT(*) as fail_count




                FROM audit_log




                WHERE operation='CONNECT' AND retcode!=0 AND {date_filter}




                GROUP BY host




                HAVING fail_count >= %s




                ORDER BY fail_count DESC




                LIMIT 1000"""




    by_ip = execute_query_with_retry(conn, query2, params, config, 'fetchall_safe')




    # 總失敗次數




    query3 = f"SELECT COUNT(*) FROM audit_log WHERE operation='CONNECT' AND retcode!=0 AND {date_filter}"




    total_result = execute_query_with_retry(conn, query3, params2, config, 'fetchone')




    total = total_result[0] if total_result else 0




    return {




        'total': total,




        'by_user': by_user or [],




        'by_ip': by_ip or []




    }




def analyze_privileged_operations(conn, date_filter, date_filter_value, keywords, config=None):




    """特權操作分析 - 使用優化查詢和結果限制"""




    like_clauses = " OR ".join(["UPPER(query) LIKE %s" for _ in keywords])




    like_params = [f"%{k.upper()}%" for k in keywords]




    if isinstance(date_filter_value, tuple):




        params = like_params + list(date_filter_value)




    else:




        params = like_params + [date_filter_value]




    # 按使用者統計特權操作 (限制結果數量)




    query1 = f"""SELECT username, COUNT(*) as cnt




                FROM audit_log




                WHERE operation='QUERY' AND ({like_clauses}) AND {date_filter}




                GROUP BY username




                ORDER BY cnt DESC




                LIMIT 500"""




    by_user = execute_query_with_retry(conn, query1, params, config, 'fetchall_safe')




    # 總特權操作數量




    query2 = f"""SELECT COUNT(*) FROM audit_log




                WHERE operation='QUERY' AND ({like_clauses}) AND {date_filter}"""




    total_result = execute_query_with_retry(conn, query2, params, config, 'fetchone')




    total = total_result[0] if total_result else 0




    # 詳細特權操作記錄 (限制數量並截短查詢內容)




    query3 = f"""SELECT username,




                        CASE WHEN LENGTH(query) > 200 THEN CONCAT(LEFT(query, 200), '...') ELSE query END as query_short,




                        timestamp




                FROM audit_log




                WHERE operation='QUERY' AND ({like_clauses}) AND {date_filter}




                ORDER BY timestamp DESC




                LIMIT 1000"""




    details = execute_query_with_retry(conn, query3, params, config, 'fetchall_safe')




    return {




        'total': total,




        'by_user': by_user or [],




        'details': details or []




    }




def analyze_operation_stats(conn, date_filter, date_filter_value, config=None):




    """操作類型統計分析 - 使用優化查詢"""




    if isinstance(date_filter_value, tuple):




        params = date_filter_value




    else:




        params = (date_filter_value,)




    query = f"""SELECT operation, COUNT(*) as cnt




                FROM audit_log




                WHERE {date_filter}




                GROUP BY operation




                ORDER BY cnt DESC




                LIMIT 100"""




    result = execute_query_with_retry(conn, query, params, config, 'fetchall_safe')




    return result or []




def analyze_error_codes(conn, date_filter, date_filter_value, config=None):




    """錯誤代碼分析 - 使用優化查詢"""




    if isinstance(date_filter_value, tuple):




        params = date_filter_value




    else:




        params = (date_filter_value,)




    # 錯誤代碼統計 (限制結果數量)




    query1 = f"""SELECT retcode, COUNT(*) as cnt




                FROM audit_log




                WHERE retcode!=0 AND operation!='CHANGEUSER' AND {date_filter}




                GROUP BY retcode




                ORDER BY cnt DESC




                LIMIT 100"""




    error_codes = execute_query_with_retry(conn, query1, params, config, 'fetchall_safe')




    # 總錯誤數量




    query2 = f"SELECT COUNT(*) FROM audit_log WHERE retcode!=0 AND operation!='CHANGEUSER' AND {date_filter}"




    total_result = execute_query_with_retry(conn, query2, params, config, 'fetchone')




    total_errors = total_result[0] if total_result else 0




    return {




        'total_errors': total_errors,




        'error_codes': error_codes or []




    }




def analyze_after_hours_access(conn, date_filter, date_filter_value, users, wh_start, wh_end):




    if not users:




        return {'total': 0, 'details': []}




    user_list = ','.join(["'%s'" % u for u in users])




    with conn.cursor() as cur:




        if isinstance(date_filter_value, tuple):




            params = date_filter_value




        else:




            params = (date_filter_value,)




        cur.execute(




            f"""SELECT username, host, operation, timestamp




                FROM audit_log




                WHERE username IN ({user_list}) AND {date_filter}




            """,




            params




        )




        rows = cur.fetchall()




        after_hours = []




        for username, host, operation, ts in rows:




            try:




                dt = datetime.strptime(ts, "%Y%m%d %H:%M:%S")




            except:




                continue




            if dt.weekday() >= 5 or not (wh_start <= dt.hour < wh_end):




                after_hours.append((username, host, operation, dt.strftime('%Y-%m-%d %H:%M:%S')))




        return {'total': len(after_hours), 'details': after_hours[:50]}




def analyze_privileged_user_logins(conn, date_filter, date_filter_value, users):




    if not users:




        return {'total': 0, 'by_user': [], 'details': []}




    user_list = ','.join(["'%s'" % u for u in users])




    with conn.cursor() as cur:




        if isinstance(date_filter_value, tuple):




            params = date_filter_value




        else:




            params = (date_filter_value,)




        cur.execute(




            f"""SELECT username, COUNT(*) as cnt




                FROM audit_log




                WHERE operation='CONNECT' AND username IN ({user_list}) AND {date_filter}




                GROUP BY username




                ORDER BY cnt DESC




            """,




            params




        )




        by_user = cur.fetchall()




        cur.execute(




            f"""SELECT username, host, timestamp




                FROM audit_log




                WHERE operation='CONNECT' AND username IN ({user_list}) AND {date_filter}




                ORDER BY timestamp DESC




            """,




            params




        )




        details = cur.fetchall()




        cur.execute(




            f"""SELECT COUNT(*) FROM audit_log




                WHERE operation='CONNECT' AND username IN ({user_list}) AND {date_filter}




            """,




            params




        )




        total = cur.fetchone()[0]




        return {'total': total, 'by_user': by_user, 'details': details}




def analyze_non_whitelisted_ips(conn, date_filter, date_filter_value, allowed_ips):




    if not allowed_ips:




        return {'total': 0, 'by_ip': [], 'details': []}




    ip_list = ','.join(["'%s'" % ip for ip in allowed_ips])




    with conn.cursor() as cur:




        if isinstance(date_filter_value, tuple):




            params = date_filter_value




        else:




            params = (date_filter_value,)




# 續前面的程式碼...




        cur.execute(




            f"""SELECT host, COUNT(*) as cnt




                FROM audit_log




                WHERE host NOT IN ({ip_list}) AND operation!='CHANGEUSER' AND {date_filter}




                GROUP BY host




                ORDER BY cnt DESC




            """,




            params




        )




        by_ip = cur.fetchall()




        cur.execute(




            f"""SELECT username, host, operation, timestamp




                FROM audit_log




                WHERE host NOT IN ({ip_list}) AND operation!='CHANGEUSER' AND {date_filter}




                ORDER BY timestamp DESC




            """,




            params




        )




        details = cur.fetchall()




        cur.execute(




            f"""SELECT COUNT(*) FROM audit_log




                WHERE host NOT IN ({ip_list}) AND operation!='CHANGEUSER' AND {date_filter}




            """,




            params




        )




        total = cur.fetchone()[0]




        return {'total': total, 'by_ip': by_ip, 'details': details}




# ========== 報表產生（CSV）（加入進度顯示） ==========




def generate_csv_report(output_dir, report_title, summary, failed, priv_ops, priv_user_logins, op_stats, err, after_hours, non_whitelisted, period_label):




    """




    產生 CSV 報表（加入進度顯示）




    """




    os.makedirs(output_dir, exist_ok=True)




    csv_file = os.path.join(output_dir, f'mysql_audit_analysis_{period_label}.csv')




    # 計算總共要寫入的區塊數量




    total_sections = 9




    if TQDM_AVAILABLE:




        progress_bar = tqdm(




            total=total_sections,




            desc="📊 產生 CSV 報表",




            unit="區塊",




            colour='yellow'




        )




    w = lambda row: writer.writerow(row)




    with open(csv_file, 'w', newline='', encoding='utf-8') as f:




        writer = csv.writer(f)




        # 標題




        w([f'{report_title} - {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'])




        w([])




        # 基本統計




        if TQDM_AVAILABLE:




            progress_bar.set_description("📊 寫入基本統計")




        w(['=== Basic Statistics ==='])




        w(['Total Events', summary['total_events']])




        w(['Unique Users', summary['unique_users']])




        w(['Unique Hosts', summary['unique_hosts']])




        w([])




        if TQDM_AVAILABLE:




            progress_bar.update(1)




        # 失敗登入分析




        if TQDM_AVAILABLE:




            progress_bar.set_description("📊 寫入失敗登入分析")




        w(['=== Failed Login Analysis ==='])




        w(['Total Failed Logins', failed['total']])




        w([])




        if failed['by_user']:




            w(['Suspicious Users (Above Threshold)'])




            w(['Username', 'Failed Count'])




            for row in failed['by_user']:




                w(list(row))




            w([])




        if failed['by_ip']:




            w(['Suspicious IPs (Above Threshold)'])




            w(['IP Address', 'Failed Count'])




            for row in failed['by_ip']:




                w(list(row))




            w([])




        if TQDM_AVAILABLE:




            progress_bar.update(1)




        # 特權操作分析




        if TQDM_AVAILABLE:




            progress_bar.set_description("📊 寫入特權操作分析")




        w(['=== Privileged Operations Analysis ==='])




        w(['Total Privileged Operations', priv_ops['total']])




        w([])




        if priv_ops['by_user']:




            w(['By User Statistics'])




            w(['Username', 'Operation Count'])




            for row in priv_ops['by_user']:




                w(list(row))




            w([])




        if priv_ops.get('details'):




            w(['Detailed Privileged Operations (SQL)'])




            w(['Username', 'SQL', 'Timestamp'])




            for row in priv_ops['details']:




                w(list(row))




            w([])




        if TQDM_AVAILABLE:




            progress_bar.update(1)




        # 特權帳號登入分析




        if TQDM_AVAILABLE:




            progress_bar.set_description("📊 寫入特權帳號登入分析")




        w(['=== Privileged Account Login Analysis ==='])




        w(['Total Privileged Account Logins', priv_user_logins['total']])




        if priv_user_logins['by_user']:




            w(['Username', 'Login Count'])




            for row in priv_user_logins['by_user']:




                w(list(row))




        w([])




        if priv_user_logins['details']:




            w(['Detailed Privileged Account Login Records'])




            w(['Username', 'Host', 'Timestamp'])




            for row in priv_user_logins['details']:




                w(list(row))




            w([])




        if TQDM_AVAILABLE:




            progress_bar.update(1)




        # 操作類型統計




        if TQDM_AVAILABLE:




            progress_bar.set_description("📊 寫入操作類型統計")




        w(['=== Operation Type Statistics ==='])




        w(['Operation Type', 'Count'])




        for row in op_stats:




            w(list(row))




        w([])




        if TQDM_AVAILABLE:




            progress_bar.update(1)




        # 錯誤分析




        if TQDM_AVAILABLE:




            progress_bar.set_description("📊 寫入錯誤分析")




        w(['=== Error Analysis ==='])




        w(['Total Errors', err['total_errors']])




        w([])




        if err['error_codes']:




            w(['Error Code Statistics'])




            w(['Error Code', 'Count'])




            for row in err['error_codes']:




                w(list(row))




        w([])




        if TQDM_AVAILABLE:




            progress_bar.update(1)




        # 非上班時間存取分析




        if TQDM_AVAILABLE:




            progress_bar.set_description("📊 寫入非上班時間存取分析")




        w(['=== After-hours Access (Specify account) ==='])




        w(['Total After-hours Access', after_hours['total']])




        if after_hours['details']:




            w(['Username', 'Host', 'Operation', 'Time'])




            for row in after_hours['details']:




                w(list(row))




        w([])




        if TQDM_AVAILABLE:




            progress_bar.update(1)




        # 非白名單 IP 存取分析




        if TQDM_AVAILABLE:




            progress_bar.set_description("📊 寫入非白名單 IP 分析")




        w(['=== Non-whitelisted IP Access Analysis ==='])




        w(['Total Events from Non-whitelisted IPs', non_whitelisted['total']])




        if non_whitelisted['by_ip']:




            w(['Non-whitelisted IPs'])




            w(['IP Address', 'Event Count'])




            for row in non_whitelisted['by_ip']:




                w(list(row))




            w([])




        if non_whitelisted['details']:




            w(['Details (Username, Host, Operation, Time)'])




            for row in non_whitelisted['details']:




                w(list(row))




        w([])




        if TQDM_AVAILABLE:




            progress_bar.update(1)




        # 完成




        if TQDM_AVAILABLE:




            progress_bar.set_description("📊 CSV 報表完成")




            progress_bar.update(1)




    if TQDM_AVAILABLE:




        progress_bar.close()




    print(f"✅ CSV report generated: {csv_file}")




    return csv_file




# ========== 報表產生（PDF）（加入進度顯示） ==========




def generate_pdf_report(output_dir, report_title, summary, failed, priv_ops, priv_user_logins, op_stats, err, after_hours, non_whitelisted, period_label):




    """




    產生 PDF 報表（加入進度顯示）




    """




    if not REPORTLAB_AVAILABLE:




        print("❌ ReportLab not installed, PDF report cannot be generated.")




        return None




    os.makedirs(output_dir, exist_ok=True)




    pdf_file = os.path.join(output_dir, f'mysql_audit_analysis_{period_label}.pdf')




    print("📄 正在產生 PDF 報表...")




    start_time = datetime.now()




    doc = SimpleDocTemplate(pdf_file, pagesize=A4)




    styles = getSampleStyleSheet()




    story = []




    # 標題




    story.append(Paragraph(f"<b>{report_title}</b>", styles['Title']))




    story.append(Spacer(1, 12))




    story.append(Paragraph(f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))




    story.append(Spacer(1, 8))




    def add_table(title, data, colnames):




        story.append(Spacer(1, 8))




        story.append(Paragraph(f"<b>{title}</b>", styles['Heading3']))




        if not data:




            story.append(Paragraph("(No data)", styles['Normal']))




        else:




            table = Table([colnames] + list(data), hAlign='LEFT')




            table.setStyle(TableStyle([




                ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),




                ('GRID', (0,0), (-1,-1), 0.5, colors.grey),




                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),




            ]))




            story.append(table)




    # 基本統計




    story.append(Paragraph("<b>=== Basic Statistics ===</b>", styles['Heading2']))




    story.append(Paragraph(f"Total Events: {summary['total_events']}<br />"




                        f"Unique Users: {summary['unique_users']}<br />"




                        f"Unique Hosts: {summary['unique_hosts']}", styles['Normal']))




    # 各種分析表格




    add_table("Suspicious Users (Failed Logins)", failed['by_user'], ['Username', 'Failed Count'])




    add_table("Suspicious IPs (Failed Logins)", failed['by_ip'], ['IP Address', 'Failed Count'])




    add_table("Privileged Operations by User", priv_ops['by_user'], ['Username', 'Operation Count'])




    add_table("Detailed Privileged Operations (SQL)", priv_ops.get('details', []), ['Username', 'SQL', 'Timestamp'])




    add_table("Privileged Account Login Statistics", priv_user_logins['by_user'], ['Username', 'Login Count'])




    add_table("Privileged Account Login Details", priv_user_logins['details'], ['Username', 'IP Address', 'Timestamp'])




    add_table("Operation Type Statistics", op_stats, ['Operation', 'Count'])




    add_table("Error Code Statistics", err['error_codes'], ['Error Code', 'Count'])




    add_table("After-hours Access (Specify account)", after_hours['details'], ['Username', 'IP Address', 'Operation', 'Timestamp'])




    add_table("Non-whitelisted IPs", non_whitelisted['by_ip'], ['IP Address', 'Event Count'])




    add_table("Non-whitelisted IP Access Details", non_whitelisted['details'], ['Username', 'IP Address', 'Operation', 'Timestamp'])




    doc.build(story)




    duration = (datetime.now() - start_time).total_seconds()




    print(f"✅ PDF report generated: {pdf_file} (耗時 {duration:.2f} 秒)")




    return pdf_file




# ========== 郵件寄送 ==========




def send_email_with_attachment(config: Config, subject, body, attachment_path):




    if not (config.smtp_server and config.mail_from and config.mail_to):




        print("❌ SMTP 或收件人設定不完整，無法寄信。")




        return




    print("📧 正在寄送郵件...")




    start_time = datetime.now()




    msg = EmailMessage()




    msg['Subject'] = subject




    msg['From'] = config.mail_from




    msg['To'] = ', '.join(config.mail_to)




    msg.set_content(body)




    with open(attachment_path, 'rb') as f:




        file_data = f.read()




        file_name = os.path.basename(attachment_path)




    maintype, subtype = ('application', 'pdf') if file_name.endswith('.pdf') else ('application', 'octet-stream')




    msg.add_attachment(file_data, maintype=maintype, subtype=subtype, filename=file_name)




    try:




        with smtplib.SMTP(config.smtp_server, config.smtp_port) as server:




            server.send_message(msg)




        duration = (datetime.now() - start_time).total_seconds()




        print(f"📧 郵件已寄出至: {', '.join(config.mail_to)} (耗時 {duration:.2f} 秒)")




    except Exception as e:




        print(f"❌ 郵件寄送失敗: {e}")




# ========== 主程式（加入完整的進度追蹤） ==========




def main():




    parser = argparse.ArgumentParser(description='MySQL Audit Log Security Analyzer (MySQL backend) - Enhanced with Progress Tracking')




    parser.add_argument('--import-date', help='Import logs for specific date (format: YYYY-MM-DD)')




    parser.add_argument('--import-month', help='Import logs for specific month (format: YYYY-MM)')




    parser.add_argument('--analyze-date', help='Analyze logs for specific date (format: YYYY-MM-DD)')




    parser.add_argument('--analyze-month', help='Analyze logs for specific month (format: YYYY-MM)')




    parser.add_argument('--output-dir', help='Output directory')




    parser.add_argument('--csv-only', action='store_true', help='Generate CSV report only')




    parser.add_argument('--show-env', action='store_true', help='Show all env/config parameters and exit')




    parser.add_argument('--disable-load-data', action='store_true', help='Disable LOAD DATA INFILE optimization')




    parser.add_argument('--disable-progress', action='store_true', help='Disable progress bars (useful for automation)')




    args = parser.parse_args()




    config = Config()




    # 如果指定了 --disable-progress，則全域停用 tqdm




    if args.disable_progress:




        global TQDM_AVAILABLE




        TQDM_AVAILABLE = False




        print("⚠️  已停用進度條顯示")




    # 如果指定了 --disable-load-data，則關閉優化




    if args.disable_load_data:




        config.use_load_data_infile = False




        print("⚠️  已停用 LOAD DATA INFILE 優化")




    # 顯示所有 env 設定




    if args.show_env:




        print("🔎 目前抓到的 .env/環境變數參數如下：\n")




        for k, v in config.as_dict().items():




            print(f"{k}: {v}")




        return




    # 程式開始執行時間




    program_start_time = datetime.now()




    print(f"🚀 程式開始執行: {program_start_time.strftime('%Y-%m-%d %H:%M:%S')}")




    # 初始化資源監控




    try:




        init_resource_monitoring(config)




    except Exception as e:




        print(f"⚠️  資源監控初始化失敗: {e}")




    # 初始化連線池




    try:




        init_connection_pool(config)




    except Exception as e:




        print(f"❌ 資料庫連線池初始化失敗: {e}")




        print("🔄 嘗試使用傳統連線方式...")




        try:




            test_conn = get_legacy_db_conn(config)




            test_conn.close()




            print("✅ 資料庫連線測試成功")




        except Exception as e2:




            print(f"❌ 資料庫完全無法連線: {e2}")




            return




    # 匯入日誌




    if args.import_date:




        print(f"\n📅 開始匯入單日日誌: {args.import_date}")




        log = get_log_file_for_date(config, args.import_date)




        if log:




            try:




                conn = get_legacy_db_conn(config)  # 匯入使用傳統連線




                import_log_file_to_db(log[0], log[1], conn, config)




                conn.close()




            except Exception as e:




                print(f"❌ 匯入過程發生錯誤: {e}")




                if 'conn' in locals():




                    conn.close()




        else:




            print(f"❌ No log file found for {args.import_date}")




        total_duration = (datetime.now() - program_start_time).total_seconds()




        print(f"\n🎉 單日匯入完成！總耗時: {total_duration:.2f} 秒")




        return




    elif args.import_month:




        print(f"\n📅 開始匯入月份日誌: {args.import_month}")




        logs = get_log_files_for_month(config, args.import_month)




        if not logs:




            print(f"❌ No log files found for {args.import_month}")




            return




        total_files = len(logs)




        print(f"📁 找到 {total_files} 個日誌檔案")




        # 月份匯入進度條




        if TQDM_AVAILABLE:




            month_progress = tqdm(




                total=total_files,




                desc="📂 月份匯入進度",




                unit="檔案",




                colour='green'




            )




        import_stats = {




            'total_files': 0,




            'success_files': 0,




            'failed_files': 0,




            'total_records': 0




        }




        conn = None




        try:




            conn = get_legacy_db_conn(config)  # 月份匯入使用傳統連線




            for i, (log_path, log_date) in enumerate(logs, 1):




                if not TQDM_AVAILABLE:




                    print(f"\n📁 處理檔案 {i}/{total_files}: {os.path.basename(log_path)}")




                else:




                    month_progress.set_description(f"📁 處理: {os.path.basename(log_path)}")




                try:




                    import_log_file_to_db(log_path, log_date, conn, config)




                    import_stats['success_files'] += 1




                except Exception as e:




                    print(f"❌ 檔案 {log_path} 匯入失敗: {e}")




                    import_stats['failed_files'] += 1




        except Exception as e:




            print(f"❌ 月份匯入過程發生錯誤: {e}")




        finally:




            if conn:




                conn.close()




        # 統計處理




        import_stats['total_files'] = len(logs)




        if TQDM_AVAILABLE:




            month_progress.close()




        total_duration = (datetime.now() - program_start_time).total_seconds()




        print(f"\n🎉 月份匯入完成！")




        print(f"   📁 總檔案數: {import_stats['total_files']}")




        print(f"   ✅ 成功檔案: {import_stats['success_files']}")




        print(f"   ❌ 失敗檔案: {import_stats['failed_files']}")




        print(f"   ⏱️  總耗時: {total_duration:.2f} 秒")




        print(f"   📊 平均每檔: {total_duration/import_stats['total_files']:.2f} 秒")




        return




    # 分析階段




    print(f"\n🔍 開始進行安全分析...")




    analysis_start_time = datetime.now()




  # 以 timestamp 欄位為主進行查詢




    if args.analyze_month:




        year, month = map(int, args.analyze_month.split('-'))




        days_in_month = calendar.monthrange(year, month)[1]




        ts_start = f"{year:04d}{month:02d}01 00:00:00"




        ts_end = f"{year:04d}{month:02d}{days_in_month:02d} 23:59:59"




        period_label = args.analyze_month.replace('-', '')




        date_filter = "timestamp BETWEEN %s AND %s"




        date_filter_value = (ts_start, ts_end)




        print(f"📊 分析期間: {args.analyze_month} ({ts_start} 到 {ts_end})")




    else:




        date_str = args.analyze_date if args.analyze_date else datetime.now().strftime('%Y-%m-%d')




        y, m, d = map(int, date_str.split('-'))




        ts_start = f"{y:04d}{m:02d}{d:02d} 00:00:00"




        ts_end = f"{y:04d}{m:02d}{d:02d} 23:59:59"




        period_label = date_str.replace('-', '')




        date_filter = "timestamp BETWEEN %s AND %s"




        date_filter_value = (ts_start, ts_end)




        print(f"📊 分析日期: {date_str} ({ts_start} 到 {ts_end})")




    # 定義所有分析功能




    analysis_functions = [




        ("基本統計", analyze_summary, None),




        ("失敗登入分析", analyze_failed_logins, (config.failed_login_threshold,)),




        ("特權操作分析", analyze_privileged_operations, (config.privileged_keywords,)),




        ("操作類型統計", analyze_operation_stats, None),




        ("錯誤代碼分析", analyze_error_codes, None),




        ("非上班時間存取", analyze_after_hours_access, (config.after_hours_users, config.work_hour_start, config.work_hour_end)),




        ("特權帳號登入", analyze_privileged_user_logins, (config.privileged_users,)),




        ("非白名單IP分析", analyze_non_whitelisted_ips, (config.allowed_ips,))




    ]




    # 執行分析 (使用連線池)




    try:




        with get_db_conn(config) as conn:




            results = run_analysis_with_progress(analysis_functions, conn, date_filter, date_filter_value, config)




    except Exception as e:




        print(f"❌ 分析過程發生錯誤，嘗試使用傳統連線: {e}")




        try:




            conn = get_legacy_db_conn(config)




            results = run_analysis_with_progress(analysis_functions, conn, date_filter, date_filter_value, config)




            conn.close()




        except Exception as e2:




            print(f"❌ 分析完全失敗: {e2}")




            return




    # 解構結果




    summary = results.get("基本統計", {})




    failed = results.get("失敗登入分析", {})




    priv_ops = results.get("特權操作分析", {})




    op_stats = results.get("操作類型統計", [])




    err = results.get("錯誤代碼分析", {})




    after_hours = results.get("非上班時間存取", {})




    priv_user_logins = results.get("特權帳號登入", {})




    non_whitelisted = results.get("非白名單IP分析", {})




    analysis_duration = (datetime.now() - analysis_start_time).total_seconds()




    print(f"✅ 安全分析完成，耗時 {analysis_duration:.2f} 秒")




    # 報表產生階段




    print(f"\n📊 開始產生報表...")




    report_start_time = datetime.now()




    output_dir = args.output_dir or config.output_dir




    csv_file = None




    pdf_file = None




    if config.generate_csv:




        csv_file = generate_csv_report(output_dir, config.report_title, summary, failed, priv_ops, priv_user_logins, op_stats, err, after_hours, non_whitelisted, period_label)




    if config.generate_pdf and not args.csv_only:




        pdf_file = generate_pdf_report(output_dir, config.report_title, summary, failed, priv_ops, priv_user_logins, op_stats, err, after_hours, non_whitelisted, period_label)




        if pdf_file and config.send_email:




            # 取得分析期間的日期資訊




            if args.analyze_month:




                year, month = map(int, args.analyze_month.split('-'))




                period_text = f"{year}年{month:02d}月"




            else:




                date_str = args.analyze_date if args.analyze_date else datetime.now().strftime('%Y-%m-%d')




                year, month, day = map(int, date_str.split('-'))




                period_text = f"{year}年{month:02d}月{day:02d}日"




            send_email_with_attachment(




                config,




                subject=f"HamiPass MySQL 稽核日誌安全分析報告 ({period_label})",




                body=f"檢附 HamiPass MySQL 稽核日誌安全分析報告，分析期間為 {period_text}。",




                attachment_path=pdf_file




            )




        elif pdf_file:




            print("✉️  SEND_EMAIL=false，未進行郵件寄送。")




    elif args.csv_only:




        print("✉️  已指定 --csv-only，不產生PDF亦不寄信。")




    else:




        print("✉️  未產生PDF，不進行寄信。")




    report_duration = (datetime.now() - report_start_time).total_seconds()




    print(f"✅ 報表產生完成，耗時 {report_duration:.2f} 秒")




    # 總結




    total_duration = (datetime.now() - program_start_time).total_seconds()




    print("\n" + "="*60)




    print("📊 Analysis Result Summary")




    print("="*60)




    print(f"📅 分析期間: {period_label}")




    print(f"📈 總事件數: {summary.get('total_events', 0):,}")




    print(f"👥 獨特使用者: {summary.get('unique_users', 0):,}")




    print(f"🖥️  獨特主機: {summary.get('unique_hosts', 0):,}")




    print(f"❌ 失敗登入: {failed.get('total', 0):,}")




    print(f"🔐 特權操作: {priv_ops.get('total', 0):,}")




    print(f"👑 特權帳號登入: {priv_user_logins.get('total', 0):,}")




    print(f"⚠️  錯誤事件: {err.get('total_errors', 0):,}")




    print(f"🚫 非白名單IP事件: {non_whitelisted.get('total', 0):,}")




    if failed.get('by_user'):




        print(f"⚠️  可疑使用者: {len(failed['by_user'])}")




    if failed.get('by_ip'):




        print(f"⚠️  可疑IP: {len(failed['by_ip'])}")




    if non_whitelisted.get('by_ip'):




        print(f"⚠️  非白名單IP: {len(non_whitelisted['by_ip'])}")




    if after_hours.get('total'):




        print(f"⚠️  非上班時間存取: {after_hours['total']}")




    print("\n" + "="*60)




    print("⏱️  執行時間統計")




    print("="*60)




    print(f"🔍 分析耗時: {analysis_duration:.2f} 秒")




    print(f"📊 報表耗時: {report_duration:.2f} 秒")




    print(f"🕒 總執行時間: {total_duration:.2f} 秒")




    print(f"🏁 程式結束: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")




if __name__ == "__main__":




    main()




首先檢查現有索引狀況：
USE auditdb;
SHOW INDEX FROM audit_log;




按重要性順序手動建立索引：




1.
時間戳記索引（最重要）：
CREATE INDEX idx_timestamp ON audit_log (timestamp);用途：所有日期範圍查詢的基礎索引

2.
失敗登入分析索引：
CREATE INDEX idx_failed_login ON audit_log (operation,retcode, timestamp);
用途：偵測暴力破解攻擊和可疑登入活動

3.
特權操作分析索引：
CREATE INDEX idx_privileged_ops ON audit_log
(operation, timestamp);
用途：監控管理員權限操作和特權提升

4.
使用者活動分析索引：
CREATE INDEX idx_username_timestamp ON audit_log
(username, timestamp);
用途：使用者行為分析和內部威脅偵測

5.
主機/IP分析索引：
CREATE INDEX idx_host_operation ON audit_log (host,operation, timestamp);
用途：網路安全分析和未授權IP偵測

6.
錯誤分析索引：
CREATE INDEX idx_retcode_operation ON audit_log
(retcode, operation, timestamp);
用途：系統錯誤監控和異常行為分析




建立完成後的檢查：
-- 查看所有索引
SHOW INDEX FROM audit_log;




-- 更新統計資訊
ANALYZE TABLE audit_log;




你可以先執行前 3
個最重要的索引，測試效能後再決定是否繼續建立其他索引。每執行一個就可以測試一下查詢效能的改善。




