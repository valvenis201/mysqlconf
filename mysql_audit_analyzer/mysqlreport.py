#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
            print(f"⚠️  記憶體使用量警告: {current_mb:.1f}MB / {self.max_memory_mb}MB")
            return False
        return True
        
    def force_gc_if_needed(self):
        """必要時強制垃圾回收"""
        import gc
        if not self.check_memory_limit():
            print("🗑️  執行垃圾回收以釋放記憶體...")
            gc.collect()
            time.sleep(0.5)  # 給系統時間釋放記憶體
            return True
        return False

class MySQL57ConnectionPool:
    """
    針對 MySQL 5.7.27 優化的連接池實現
    支援連接健康檢查、重試機制和資源監控
    """
    def __init__(self, host, port, user, password, database, charset='utf8mb4', 
                 min_connections=2, max_connections=10, max_idle_time=300, **kwargs):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.database = database
        self.charset = charset
        self.min_connections = min_connections
        self.max_connections = max_connections
        self.max_idle_time = max_idle_time  # 最大關置時間（秒）
        self.kwargs = kwargs
        
        # 連接池和管理結構
        self._pool = queue.Queue(maxsize=max_connections)
        self._active_connections = set()  # 活躍連接集合
        self._connection_timestamps = {}  # 連接時間戳
        self._lock = threading.Lock()
        self._created_connections = 0
        self._stats = {
            'created': 0,
            'reused': 0,
            'failed': 0,
            'closed': 0
        }
        
        # 初始化最小連接數
        self._initialize_pool()
        
        # 啟動清理線程
        self._cleanup_thread = threading.Thread(target=self._cleanup_idle_connections, daemon=True)
        self._cleanup_thread.start()
        
    def _create_connection(self):
        """創建 MySQL 5.7.27 優化的連接"""
        try:
            conn = pymysql.connect(
                host=self.host,
                port=self.port,
                user=self.user,
                password=self.password,
                database=self.database,
                charset=self.charset,
                autocommit=True,
                local_infile=True,
                connect_timeout=30,
                read_timeout=600,
                write_timeout=600,
                # MySQL 5.7.27 優化參數
                sql_mode='STRICT_TRANS_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO',
                init_command="""
                    SET SESSION tmp_table_size = 67108864;
                    SET SESSION max_heap_table_size = 67108864;
                    SET SESSION sort_buffer_size = 2097152;
                    SET SESSION join_buffer_size = 2097152;
                    SET SESSION read_buffer_size = 131072;
                    SET SESSION read_rnd_buffer_size = 262144;
                    SET SESSION big_tables = 1;
                    SET SESSION innodb_lock_wait_timeout = 50;
                    SET SESSION net_read_timeout = 600;
                    SET SESSION net_write_timeout = 600;
                    SET SESSION query_cache_type = OFF;
                """,
                **self.kwargs
            )
            self._stats['created'] += 1
            return conn
        except Exception as e:
            self._stats['failed'] += 1
            raise e
            
    def _initialize_pool(self):
        """初始化連接池至最小連接數"""
        for _ in range(self.min_connections):
            try:
                conn = self._create_connection()
                self._pool.put_nowait(conn)
                self._connection_timestamps[id(conn)] = time.time()
                self._created_connections += 1
            except Exception as e:
                print(f"⚠️  初始化連接池失敗: {e}")
                break
                
    def _is_connection_valid(self, conn):
        """檢查連接是否有效"""
        try:
            if not conn or not conn.open:
                return False
            # 使用輕量級檢查
            conn.ping(reconnect=False)
            return True
        except:
            return False
            
    def _cleanup_idle_connections(self):
        """清理關置連接的後台線程"""
        while True:
            try:
                time.sleep(60)  # 每分鐘檢查一次
                current_time = time.time()
                
                with self._lock:
                    # 檢查池中的連接
                    temp_connections = []
                    
                    # 取出所有連接進行檢查
                    while not self._pool.empty():
                        try:
                            conn = self._pool.get_nowait()
                            conn_id = id(conn)
                            
                            # 檢查連接是否過期或無效
                            if (conn_id in self._connection_timestamps and 
                                current_time - self._connection_timestamps[conn_id] > self.max_idle_time) or \
                               not self._is_connection_valid(conn):
                                # 連接過期或無效，關閉它
                                try:
                                    conn.close()
                                    self._stats['closed'] += 1
                                except:
                                    pass
                                if conn_id in self._connection_timestamps:
                                    del self._connection_timestamps[conn_id]
                                self._created_connections -= 1
                            else:
                                # 連接仍然有效，保留它
                                temp_connections.append(conn)
                        except queue.Empty:
                            break
                    
                    # 將有效連接放回池中
                    for conn in temp_connections:
                        try:
                            self._pool.put_nowait(conn)
                        except queue.Full:
                            # 池已滿，關閉多餘連接
                            try:
                                conn.close()
                                self._stats['closed'] += 1
                            except:
                                pass
                    
                    # 確保最小連接數
                    current_pool_size = self._pool.qsize()
                    if current_pool_size < self.min_connections:
                        for _ in range(self.min_connections - current_pool_size):
                            try:
                                conn = self._create_connection()
                                self._pool.put_nowait(conn)
                                self._connection_timestamps[id(conn)] = time.time()
                                self._created_connections += 1
                            except:
                                break
                                
            except Exception as e:
                print(f"⚠️  連接池清理線程發生錯誤: {e}")
                
    def get_connection(self, timeout=30):
        """從連接池獲取連接，支援重試機制"""
        retry_count = 3
        
        for attempt in range(retry_count):
            try:
                # 嘗試從池中獲取現有連接
                try:
                    conn = self._pool.get(timeout=min(timeout, 10))
                    
                    # 檢查連接是否有效
                    if self._is_connection_valid(conn):
                        with self._lock:
                            self._active_connections.add(id(conn))
                            self._connection_timestamps[id(conn)] = time.time()
                            self._stats['reused'] += 1
                        return conn
                    else:
                        # 連接無效，嘗試創建新連接
                        try:
                            conn.close()
                        except:
                            pass
                        
                except queue.Empty:
                    pass
                
                # 創建新連接
                with self._lock:
                    if self._created_connections < self.max_connections:
                        conn = self._create_connection()
                        self._created_connections += 1
                        self._active_connections.add(id(conn))
                        self._connection_timestamps[id(conn)] = time.time()
                        return conn
                    
                # 如果到達最大連接數，等待一會兒再試
                if attempt < retry_count - 1:
                    time.sleep(1)
                    
            except Exception as e:
                if attempt < retry_count - 1:
                    print(f"⚠️  獲取連接失敗，第 {attempt + 1} 次重試: {e}")
                    time.sleep(1)
                else:
                    raise e
        
        raise Exception("無法獲取資料庫連接，連接池已滿")
    
    def release_connection(self, conn):
        """釋放連接回池中"""
        if not conn:
            return
            
        conn_id = id(conn)
        
        with self._lock:
            if conn_id in self._active_connections:
                self._active_connections.remove(conn_id)
        
        if self._is_connection_valid(conn):
            try:
                # 重設連接狀態
                with conn.cursor() as cur:
                    cur.execute("ROLLBACK")
                    
                self._connection_timestamps[conn_id] = time.time()
                self._pool.put_nowait(conn)
            except queue.Full:
                # 池已滿，關閉連接
                try:
                    conn.close()
                    self._stats['closed'] += 1
                except:
                    pass
                with self._lock:
                    self._created_connections -= 1
                    if conn_id in self._connection_timestamps:
                        del self._connection_timestamps[conn_id]
            except Exception as e:
                # 連接出錯，關閉它
                try:
                    conn.close()
                    self._stats['closed'] += 1
                except:
                    pass
                with self._lock:
                    self._created_connections -= 1
                    if conn_id in self._connection_timestamps:
                        del self._connection_timestamps[conn_id]
        else:
            # 連接無效，關閉它
            try:
                conn.close()
                self._stats['closed'] += 1
            except:
                pass
            with self._lock:
                self._created_connections -= 1
                if conn_id in self._connection_timestamps:
                    del self._connection_timestamps[conn_id]
                    
    def get_stats(self):
        """獲取連接池統計資訊"""
        with self._lock:
            return {
                'created_connections': self._created_connections,
                'active_connections': len(self._active_connections),
                'pool_size': self._pool.qsize(),
                'max_connections': self.max_connections,
                'min_connections': self.min_connections,
                'stats': self._stats.copy()
            }
            
    def close_all(self):
        """關閉所有連接"""
        with self._lock:
            # 關閉池中的連接
            while not self._pool.empty():
                try:
                    conn = self._pool.get_nowait()
                    conn.close()
                    self._stats['closed'] += 1
                except:
                    pass
                    
            # 清理狀態
            self._created_connections = 0
            self._active_connections.clear()
            self._connection_timestamps.clear()


# 加入 tqdm 支援
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False
    print("⚠️  建議安裝 tqdm 以獲得更好的進度顯示：pip install tqdm")

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
    初始化 MySQL 5.7.27 優化的資料庫連線池
    """
    global _connection_pool
    if _connection_pool is None:
        _connection_pool = MySQL57ConnectionPool(
            host=config.mysql_host,
            port=config.mysql_port,
            user=config.mysql_user,
            password=config.mysql_password,
            database=config.mysql_db,
            charset='utf8mb4',
            min_connections=max(1, config.db_pool_size // 2),  # 最小連接數
            max_connections=config.db_pool_size + config.db_max_overflow,
            max_idle_time=300,  # 5分鐘關置時間
        )
        print(f"✅ MySQL 5.7.27 連線池初始化完成")
        print(f"   最小連接: {_connection_pool.min_connections}")
        print(f"   最大連接: {_connection_pool.max_connections}")
        print(f"   關置時間: {_connection_pool.max_idle_time}秒")

@contextmanager
def get_db_conn(config: Config):
    """
    取得資料庫連線 (使用 MySQL 5.7.27 優化連線池和自動釋放)
    """
    if _connection_pool is None:
        init_connection_pool(config)
    
    conn = None
    start_time = time.time()
    
    try:
        conn = _connection_pool.get_connection(timeout=config.db_pool_timeout)
        
        # 記錄連接獲取時間
        get_time = time.time() - start_time
        if get_time > 5:  # 如果獲取連接超過5秒，給出警告
            print(f"⚠️  連接獲取耗時: {get_time:.2f}秒")
            
        yield conn
        
    except Exception as e:
        if conn:
            try:
                conn.rollback()
            except:
                pass  # 忽略 rollback 錯誤
        raise e
    finally:
        if conn:
            _connection_pool.release_connection(conn)

def get_legacy_db_conn(config: Config):
    """
    取得傳統資料庫連線 (用於不支援 context manager 的舊程式碼)
    針對 MySQL 5.7.27 優化
    """
    connection = pymysql.connect(
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
        write_timeout=config.db_query_timeout,
        # MySQL 5.7.27 優化參數
        sql_mode='STRICT_TRANS_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO',
        init_command="""
            SET SESSION tmp_table_size = 67108864;
            SET SESSION max_heap_table_size = 67108864;
            SET SESSION sort_buffer_size = 2097152;
            SET SESSION join_buffer_size = 2097152;
            SET SESSION read_buffer_size = 131072;
            SET SESSION read_rnd_buffer_size = 262144;
            SET SESSION big_tables = 1;
            SET SESSION innodb_lock_wait_timeout = 50;
            SET SESSION net_read_timeout = 600;
            SET SESSION net_write_timeout = 600;
        """
    )
    return connection

def get_connection_pool_stats():
    """獲取連接池統計資訊"""
    global _connection_pool
    if _connection_pool and hasattr(_connection_pool, 'get_stats'):
        return _connection_pool.get_stats()
    return None

def close_connection_pool():
    """關閉連接池"""
    global _connection_pool
    if _connection_pool and hasattr(_connection_pool, 'close_all'):
        _connection_pool.close_all()
        _connection_pool = None
        print("✅ 連接池已關閉")

def get_simple_db_conn(config: Config):
    """
    取得簡單的資料庫連線用於分析 (不使用連接池)
    針對 MySQL 5.7.27 優化
    """
    connection = pymysql.connect(
        host=config.mysql_host,
        port=config.mysql_port,
        user=config.mysql_user,
        password=config.mysql_password,
        database=config.mysql_db,
        charset='utf8mb4',
        autocommit=True,
        connect_timeout=30,
        read_timeout=600,  # 分析查詢可能需要更長時間
        write_timeout=600,
        cursorclass=pymysql.cursors.DictCursor,  # 使用字典游標便於結果處理
        # MySQL 5.7.27 分析查詢優化參數
        sql_mode='STRICT_TRANS_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO',
        init_command="""
            SET SESSION tmp_table_size = 134217728;
            SET SESSION max_heap_table_size = 134217728;
            SET SESSION sort_buffer_size = 4194304;
            SET SESSION join_buffer_size = 4194304;
            SET SESSION read_buffer_size = 262144;
            SET SESSION read_rnd_buffer_size = 524288;
            SET SESSION big_tables = 1;
            SET SESSION optimizer_search_depth = 62;
            SET SESSION query_cache_type = OFF;
            SET SESSION innodb_lock_wait_timeout = 120;
            SET SESSION net_read_timeout = 1200;
            SET SESSION net_write_timeout = 1200;
        """
    )
    return connection

def execute_simple_query(conn, query, params=None, max_rows=10000):
    """
    執行簡單查詢用於分析 (不使用複雜的重試和資源監控)
    """
    try:
        with conn.cursor() as cur:
            cur.execute(query, params)
            # 限制結果數量以防止記憶體問題
            if "SELECT COUNT" in query.upper() or "LIMIT" in query.upper():
                return cur.fetchall()
            else:
                return cur.fetchmany(max_rows)
    except Exception as e:
        print(f"❌ 查詢執行失敗: {e}")
        return []

def execute_analysis_query(conn, query, params=None, use_simple=True):
    """
    執行分析查詢，可選擇簡單模式或複雜模式
    """
    if use_simple:
        return execute_simple_query(conn, query, params)
    else:
        return execute_query_with_retry(conn, query, params, None, 'fetchall')

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
                            # MySQL 5.7.27 查詢優化參數設定
                    if config:
                        try:
                            # 設定 MySQL 5.7.27 特定的優化參數
                            optimization_sql = f"""
                                SET SESSION innodb_lock_wait_timeout = {min(config.db_query_timeout, 120)};
                                SET SESSION max_execution_time = {config.db_query_timeout * 1000};
                                SET SESSION optimizer_search_depth = 62;
                                SET SESSION eq_range_index_dive_limit = 200;
                            """
                            for sql in optimization_sql.strip().split(';'):
                                if sql.strip():
                                    cur.execute(sql.strip())
                        except Exception as opt_error:
                            # 忽略優化參數設置失敗，但記錄警告
                            print(f"⚠️  MySQL 5.7.27 優化參數設置失敗: {opt_error}")
                    
                    cur.execute(query, params)
                    
                    if fetch_mode == 'fetchone':
                        result = cur.fetchone()
                    elif fetch_mode == 'fetchmany':
                        result = cur.fetchmany(batch_size)
                    elif fetch_mode == 'iterator':
                        result = cur  # 回傳游標迭代器，節省記憶體
                    elif fetch_mode == 'fetchall_safe':
                        # 安全的 fetchall，限制結果數量並監控記憶體
                        results = []
                        count = 0
                        while True:
                            # 檢查記憶體使用量
                            if _resource_monitor and not _resource_monitor.check_memory_limit():
                                print(f"⚠️  記憶體不足，查詢結果截斷於 {count:,} 筆")
                                break
                            
                            batch = cur.fetchmany(batch_size)
                            if not batch:
                                break
                            results.extend(batch)
                            count += len(batch)
                            
                            if count >= max_fetch_size:
                                print(f"⚠️  查詢結果超過限制 ({max_fetch_size:,} 筆)，已截斷")
                                break
                        result = results
                    else:  # fetchall (default)
                        result = cur.fetchall()
                    
                    return result
                        
            except (pymysql.Error, Exception) as e:
                if attempt < retry_count - 1:
                    print(f"⚠️  查詢失敗，第 {attempt + 1}/{retry_count} 次重試... 錯誤: {str(e)}")
                    time.sleep(retry_delay * (attempt + 1))  # 指數退避
                else:
                    print(f"❌ 查詢最終失敗: {str(e)}")
                    raise e
    finally:
        # 釋放信號量
        if _query_semaphore:
            _query_semaphore.release()
        
        # 如果是長時間查詢，輸出統計資訊
        if _connection_pool and hasattr(_connection_pool, 'get_stats'):
            stats = _connection_pool.get_stats()
            if stats['active_connections'] > stats['max_connections'] * 0.8:
                print(f"⚠️  連接池使用率過高: {stats['active_connections']}/{stats['max_connections']}")

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
            print(f"⚠️  檔案 {file_path} 沒有資料")
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
                    if row_count % 10000 == 0:  # 每 10000 筆更新一次描述
                        progress_bar.set_postfix({
                            '已處理': f'{row_count:,}',
                            '速度': f'{row_count/(datetime.now()-start_time).total_seconds():.0f}/秒'
                        })
            
            if TQDM_AVAILABLE:
                progress_bar.close()
        
        temp_csv.close()
        
        if row_count == 0:
            print(f"⚠️  檔案 {file_path} 沒有資料")
            return
        
        processing_time = (datetime.now() - start_time).total_seconds()
        print(f"✅ 資料處理完成: {row_count:,} 筆，耗時 {processing_time:.2f} 秒")
        
        # 使用 MySQL 5.7.27 優化的 LOAD DATA LOCAL INFILE 批量載入
        print("💾 正在使用 MySQL 5.7.27 優化載入資料到資料庫...")
        db_start_time = datetime.now()
        
        with conn.cursor() as cur:
            # 先檢查是否已存在該日期的資料，如果有則先刪除
            delete_sql = "DELETE FROM audit_log WHERE log_date = %s"
            cur.execute(delete_sql, (log_date,))
            deleted_count = cur.rowcount
            if deleted_count > 0:
                print(f"🗑️  刪除舊資料 {deleted_count:,} 筆")
            
            # MySQL 5.7.27 特定的 LOAD DATA LOCAL INFILE 語法
            load_sql = f"""
            LOAD DATA LOCAL INFILE '{temp_csv.name.replace(chr(92), '/')}'
            INTO TABLE audit_log
            CHARACTER SET utf8mb4
            FIELDS TERMINATED BY ','
            OPTIONALLY ENCLOSED BY '"'
            ESCAPED BY '"'
            LINES TERMINATED BY '\\n'
            (log_date, timestamp, server_host, username, host, connection_id, query_id, operation, dbname, query, retcode)
            """
            
            # 執行 LOAD DATA 並捕捉可能的錯誤
            try:
                cur.execute(load_sql)
                # 獲取實際載入的行數
                cur.execute("SELECT ROW_COUNT()")
                loaded_rows = cur.fetchone()[0]
                
                # 獲取 MySQL 警告訊息
                cur.execute("SHOW WARNINGS")
                warnings = cur.fetchall()
                if warnings:
                    print(f"⚠️  MySQL 警告 ({len(warnings)} 個):")
                    for level, code, message in warnings[:5]:  # 只顯示前5個警告
                        print(f"   {level} {code}: {message}")
                    if len(warnings) > 5:
                        print(f"   ... 及其他 {len(warnings) - 5} 個警告")
                        
            except pymysql.Error as mysql_error:
                error_code = mysql_error.args[0] if mysql_error.args else 0
                error_msg = mysql_error.args[1] if len(mysql_error.args) > 1 else str(mysql_error)
                
                print(f"❌ MySQL LOAD DATA 錯誤 {error_code}: {error_msg}")
                
                # 常見錯誤的特定處理
                if error_code in [1148, 1290, 2061]:  # LOAD DATA LOCAL INFILE 相關錯誤
                    print("🔄 LOAD DATA LOCAL INFILE 被禁用或不支持，將回退到原始方法")
                    return import_log_file_to_db_fallback(file_path, log_date, conn)
                elif error_code in [1062]:  # 重複鍵錯誤
                    print(f"⚠️  偵測到重複資料，嘗試先清理後再載入")
                    cur.execute("DELETE FROM audit_log WHERE log_date = %s", (log_date,))
                    cur.execute(load_sql)  # 重試
                    cur.execute("SELECT ROW_COUNT()")
                    loaded_rows = cur.fetchone()[0]
                else:
                    # 其他錯誤，拋出異常
                    raise mysql_error
            
            db_duration = (datetime.now() - db_start_time).total_seconds()
            total_duration = (datetime.now() - start_time).total_seconds()
            
            print(f"✅ 優化匯入 {os.path.basename(file_path)} 完成")
            print(f"   📊 處理資料: {row_count:,} 筆")
            print(f"   📥 載入資料: {loaded_rows:,} 筆")
            print(f"   ⏱️  處理耗時: {processing_time:.2f} 秒")
            print(f"   💾 載入耗時: {db_duration:.2f} 秒")
            print(f"   🕒 總耗時: {total_duration:.2f} 秒")
            print(f"   🚀 總速度: {loaded_rows/total_duration:.0f} 筆/秒")
            
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
            print(f"⚠️  檔案 {file_path} 沒有資料")
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
            print(f"⚠️  檔案 {file_path} 沒有資料")
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
                print(f"🗑️  刪除舊資料 {deleted_count:,} 筆")
            
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
            print(f"   📊 載入資料: {len(data):,} 筆")
            print(f"   ⏱️  讀取耗時: {processing_time:.2f} 秒")
            print(f"   💾 寫入耗時: {db_duration:.2f} 秒")
            print(f"   🕒 總耗時: {total_duration:.2f} 秒")
            print(f"   🐌 總速度: {len(data)/total_duration:.0f} 筆/秒")

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

def run_analysis_with_progress(analysis_functions, conn, date_filter, date_filter_value, config, use_simple=False):
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
                results[name] = func(conn, date_filter, date_filter_value, *args, config=config, use_simple=use_simple)
            else:
                results[name] = func(conn, date_filter, date_filter_value, config=config, use_simple=use_simple)
            
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

def analyze_summary(conn, date_filter, date_filter_value, config=None, use_simple=False):
    """基本統計分析 - 使用優化查詢"""
    if isinstance(date_filter_value, tuple):
        params = date_filter_value
    else:
        params = (date_filter_value,)
    
    query = f"SELECT COUNT(*) as total_events, COUNT(DISTINCT username) as unique_users, COUNT(DISTINCT host) as unique_hosts FROM audit_log WHERE {date_filter}"
    result = execute_analysis_query(conn, query, params, use_simple)
    
    if result and len(result) > 0:
        row = result[0]
        return {
            'total_events': row['total_events'],
            'unique_users': row['unique_users'],
            'unique_hosts': row['unique_hosts']
        }
    return {'total_events': 0, 'unique_users': 0, 'unique_hosts': 0}

def analyze_failed_logins(conn, date_filter, date_filter_value, threshold=5, config=None, use_simple=False):
    """失敗登入分析 - 使用優化查詢和結果限制"""
    if isinstance(date_filter_value, tuple):
        params = date_filter_value + (threshold,)
        params2 = date_filter_value
    else:
        params = (date_filter_value, threshold)
        params2 = (date_filter_value,)
    
    # 查詢可疑使用者 (使用 FORCE INDEX 和 MySQL 5.7.27 優化)
    query1 = f"""SELECT username, COUNT(*) as fail_count
                FROM audit_log FORCE INDEX (operation, username)
                WHERE operation='CONNECT' AND retcode!=0 AND {date_filter}
                GROUP BY username
                HAVING fail_count >= %s
                ORDER BY fail_count DESC
                LIMIT 1000"""
    by_user = execute_analysis_query(conn, query1, params, use_simple)
    
    # 查詢可疑IP (使用 FORCE INDEX 和 MySQL 5.7.27 優化)
    query2 = f"""SELECT host, COUNT(*) as fail_count
                FROM audit_log FORCE INDEX (operation, host)
                WHERE operation='CONNECT' AND retcode!=0 AND {date_filter}
                GROUP BY host
                HAVING fail_count >= %s
                ORDER BY fail_count DESC
                LIMIT 1000"""
    by_ip = execute_analysis_query(conn, query2, params, use_simple)
    
    # 總失敗次數 (使用 FORCE INDEX)
    query3 = f"SELECT COUNT(*) FROM audit_log FORCE INDEX (operation) WHERE operation='CONNECT' AND retcode!=0 AND {date_filter}"
    total_result = execute_analysis_query(conn, query3, params2, use_simple)
    if total_result and len(total_result) > 0:
        total = total_result[0]['COUNT(*)'] if use_simple else total_result[0][0]
    else:
        total = 0
    
    return {
        'total': total,
        'by_user': by_user or [],
        'by_ip': by_ip or []
    }

def analyze_privileged_operations(conn, date_filter, date_filter_value, keywords, config=None, use_simple=False):
    """特權操作分析 - 使用優化查詢和結果限制"""
    like_clauses = " OR ".join(["UPPER(query) LIKE %s" for _ in keywords])
    like_params = [f"%{k.upper()}%" for k in keywords]
    if isinstance(date_filter_value, tuple):
        params = like_params + list(date_filter_value)
    else:
        params = like_params + [date_filter_value]

    # 按使用者統計特權操作 (使用 FORCE INDEX 和 MySQL 5.7.27 優化)
    query1 = f"""SELECT username, COUNT(*) as cnt
                FROM audit_log FORCE INDEX (operation, username)
                WHERE operation='QUERY' AND ({like_clauses}) AND {date_filter}
                GROUP BY username
                ORDER BY cnt DESC
                LIMIT 500"""
    by_user = execute_query_with_retry(conn, query1, params, config, 'fetchall_safe')

    # 總特權操作數量 (使用 FORCE INDEX)
    query2 = f"""SELECT COUNT(*) FROM audit_log FORCE INDEX (operation)
                WHERE operation='QUERY' AND ({like_clauses}) AND {date_filter}"""
    total_result = execute_query_with_retry(conn, query2, params, config, 'fetchone')
    total = total_result[0] if total_result else 0

    # 詳細特權操作記錄 (使用 FORCE INDEX 和查詢優化)
    query3 = f"""SELECT username, 
                        CASE WHEN CHAR_LENGTH(query) > 200 THEN CONCAT(LEFT(query, 200), '...') ELSE query END as query_short,
                        timestamp
                FROM audit_log FORCE INDEX (operation)
                WHERE operation='QUERY' AND ({like_clauses}) AND {date_filter}
                ORDER BY timestamp DESC
                LIMIT 1000"""
    details = execute_query_with_retry(conn, query3, params, config, 'fetchall_safe')

    return {
        'total': total,
        'by_user': by_user or [],
        'details': details or []
    }

def analyze_operation_stats(conn, date_filter, date_filter_value, config=None, use_simple=False):
    """操作類型統計分析 - 使用優化查詢"""
    if isinstance(date_filter_value, tuple):
        params = date_filter_value
    else:
        params = (date_filter_value,)
    
    # 使用 FORCE INDEX 和 MySQL 5.7.27 優化
    query = f"""SELECT operation, COUNT(*) as cnt
                FROM audit_log FORCE INDEX (operation)
                WHERE {date_filter}
                GROUP BY operation
                ORDER BY cnt DESC
                LIMIT 100"""
    
    result = execute_query_with_retry(conn, query, params, config, 'fetchall_safe')
    return result or []

def analyze_error_codes(conn, date_filter, date_filter_value, config=None, use_simple=False):
    """錯誤代碼分析 - 使用優化查詢"""
    if isinstance(date_filter_value, tuple):
        params = date_filter_value
    else:
        params = (date_filter_value,)
    
    # 錯誤代碼統計 (使用 FORCE INDEX 和 MySQL 5.7.27 優化)
    query1 = f"""SELECT retcode, COUNT(*) as cnt
                FROM audit_log FORCE INDEX (operation)
                WHERE retcode!=0 AND operation!='CHANGEUSER' AND {date_filter}
                GROUP BY retcode
                ORDER BY cnt DESC
                LIMIT 100"""
    error_codes = execute_query_with_retry(conn, query1, params, config, 'fetchall_safe')
    
    # 總錯誤數量 (使用 FORCE INDEX)
    query2 = f"SELECT COUNT(*) FROM audit_log FORCE INDEX (operation) WHERE retcode!=0 AND operation!='CHANGEUSER' AND {date_filter}"
    total_result = execute_query_with_retry(conn, query2, params, config, 'fetchone')
    total_errors = total_result[0] if total_result else 0
    
    return {
        'total_errors': total_errors,
        'error_codes': error_codes or []
    }

def analyze_after_hours_access(conn, date_filter, date_filter_value, users, wh_start, wh_end, config=None, use_simple=False):
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

def analyze_privileged_user_logins(conn, date_filter, date_filter_value, users, config=None, use_simple=False):
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

def analyze_non_whitelisted_ips(conn, date_filter, date_filter_value, allowed_ips, config=None, use_simple=False):
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
        print("⚠️  已停用進度條顯示")
    
    # 如果指定了 --disable-load-data，則關閉優化
    if args.disable_load_data:
        config.use_load_data_infile = False
        print("⚠️  已停用 LOAD DATA INFILE 優化")

    # 顯示所有 env 設定
    if args.show_env:
        print("🔎 目前抓到的 .env/環境變數參數如下：\n")
        for k, v in config.as_dict().items():
            print(f"{k}: {v}")
        return

    # 程式開始執行時間和統計初始化
    program_start_time = datetime.now()
    print(f"🚀 MySQL 5.7.27 稿核日誌分析程式開始執行: {program_start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # 程式執行統計
    execution_stats = {
        'start_time': program_start_time,
        'import_files': 0,
        'import_success': 0,
        'import_failed': 0,
        'total_records_imported': 0,
        'analysis_queries': 0,
        'analysis_time': 0,
        'errors': [],
        'warnings': []
    }
    
    # 初始化資源監控
    try:
        init_resource_monitoring(config)
    except Exception as e:
        print(f"⚠️  資源監控初始化失敗: {e}")
    
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
                conn = get_legacy_db_conn(config)  # 匯入使用傳統連線
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
            conn = get_legacy_db_conn(config)  # 月份匯入使用傳統連線
            
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
        print(f"   📁 總檔案數: {import_stats['total_files']}")
        print(f"   ✅ 成功檔案: {import_stats['success_files']}")
        print(f"   ❌ 失敗檔案: {import_stats['failed_files']}")
        print(f"   ⏱️  總耗時: {total_duration:.2f} 秒")
        print(f"   📊 平均每檔: {total_duration/import_stats['total_files']:.2f} 秒")
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
    
    # 執行分析 (使用簡單連線)
    conn = None
    try:
        print("🔗 建立資料庫連線...")
        conn = get_simple_db_conn(config)
        print("✅ 資料庫連線成功")
        
        # 先檢查是否有資料
        print("🔍 檢查資料是否存在...")
        check_query = f"SELECT COUNT(*) as count FROM audit_log WHERE {date_filter}"
        check_result = execute_simple_query(conn, check_query, date_filter_value)
        
        if not check_result or check_result[0]['count'] == 0:
            print("⚠️  指定日期範圍內沒有資料，跳過分析")
            return
            
        print(f"✅ 找到 {check_result[0]['count']:,} 筆資料，開始分析...")
        results = run_analysis_with_progress(analysis_functions, conn, date_filter, date_filter_value, config, use_simple=True)
    except Exception as e:
        print(f"❌ 分析過程發生錯誤: {e}")
        return
    finally:
        if conn:
            conn.close()
            print("🔗 資料庫連線已關閉")
    
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
            print("✉️  SEND_EMAIL=false，未進行郵件寄送。")
    elif args.csv_only:
        print("✉️  已指定 --csv-only，不產生PDF亦不寄信。")
    else:
        print("✉️  未產生PDF，不進行寄信。")

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
    print(f"🖥️  獨特主機: {summary.get('unique_hosts', 0):,}")
    print(f"❌ 失敗登入: {failed.get('total', 0):,}")
    print(f"🔐 特權操作: {priv_ops.get('total', 0):,}")
    print(f"👑 特權帳號登入: {priv_user_logins.get('total', 0):,}")
    print(f"⚠️  錯誤事件: {err.get('total_errors', 0):,}")
    print(f"🚫 非白名單IP事件: {non_whitelisted.get('total', 0):,}")
    
    if failed.get('by_user'):
        print(f"⚠️  可疑使用者: {len(failed['by_user'])}")
    if failed.get('by_ip'):
        print(f"⚠️  可疑IP: {len(failed['by_ip'])}")
    if non_whitelisted.get('by_ip'):
        print(f"⚠️  非白名單IP: {len(non_whitelisted['by_ip'])}")
    if after_hours.get('total'):
        print(f"⚠️  非上班時間存取: {after_hours['total']}")
    
    print("\n" + "="*60)
    print("⏱️  執行時間統計")
    print("="*60)
    print(f"🔍 分析耗時: {analysis_duration:.2f} 秒")
    print(f"📊 報表耗時: {report_duration:.2f} 秒")
    print(f"🕒 總執行時間: {total_duration:.2f} 秒")
    print(f"🏁 程式結束: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # 最終清理和統計輸出
    execution_stats['end_time'] = datetime.now()
    execution_stats['total_duration'] = (execution_stats['end_time'] - execution_stats['start_time']).total_seconds()
    
    # 顯示執行統計
    print("\n" + "="*60)
    print("📈 MySQL 5.7.27 Program Execution Statistics")
    print("="*60)
    print(f"⏰ 執行時間: {execution_stats['start_time'].strftime('%Y-%m-%d %H:%M:%S')} - {execution_stats['end_time'].strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🕒 總耗時: {execution_stats['total_duration']:.2f} 秒")
    if execution_stats['import_files'] > 0:
        print(f"📁 匯入統計: {execution_stats['import_success']}/{execution_stats['import_files']} 檔案成功")
        print(f"📈 匯入成功率: {execution_stats['import_success']/execution_stats['import_files']*100:.1f}%")
    if execution_stats['total_records_imported'] > 0:
        print(f"📊 總匯入記錄: {execution_stats['total_records_imported']:,} 筆")
        print(f"⚡ 匯入速度: {execution_stats['total_records_imported']/execution_stats['total_duration']:.0f} 筆/秒")
    if execution_stats['analysis_queries'] > 0:
        print(f"🔍 分析查詢: {execution_stats['analysis_queries']} 個 (耗時 {execution_stats['analysis_time']:.2f} 秒)")
        if execution_stats['analysis_time'] > 0:
            print(f"⚡ 查詢效率: {execution_stats['analysis_queries']/execution_stats['analysis_time']:.1f} 查詢/秒")
    
    # 錯誤和警告總結
    if execution_stats['errors']:
        print(f"\n❌ 錯誤總數: {len(execution_stats['errors'])}")
        for i, error in enumerate(execution_stats['errors'][:3], 1):  # 只顯示前3個錯誤
            print(f"   {i}. {error[:100]}{'...' if len(error) > 100 else ''}")
        if len(execution_stats['errors']) > 3:
            print(f"   ... 及其他 {len(execution_stats['errors']) - 3} 個錯誤")
            
    if execution_stats['warnings']:
        print(f"\n⚠️  警告總數: {len(execution_stats['warnings'])}")
        for i, warning in enumerate(execution_stats['warnings'][:3], 1):  # 只顯示前3個警告
            print(f"   {i}. {warning}")
        if len(execution_stats['warnings']) > 3:
            print(f"   ... 及其他 {len(execution_stats['warnings']) - 3} 個警告")
    
    # 最終清理
    try:
        close_connection_pool()
    except Exception as e:
        print(f"⚠️  連線池清理警告: {e}")
    
    # 根據執行結果返回適當的退出碼
    if execution_stats['errors']:
        print("\n⚠️  程式執行完成，但有錯誤發生")
        sys.exit(1)
    elif execution_stats['warnings']:
        print("\n✅ 程式執行完成，但有警告")
    else:
        print("\n🎉 程式執行完成，無錯誤")

if __name__ == "__main__":
    main()
