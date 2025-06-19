#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, argparse, gzip, csv, calendar
from datetime import datetime, timedelta
from typing import List, Optional
import pymysql
import smtplib
from email.message import EmailMessage

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
        }

def get_db_conn(config: Config):
    return pymysql.connect(
        host=config.mysql_host,
        port=config.mysql_port,
        user=config.mysql_user,
        password=config.mysql_password,
        database=config.mysql_db,
        charset='utf8mb4',
        autocommit=True
    )

def import_log_file_to_db(file_path, log_date, conn):
    with (gzip.open(file_path, 'rt', encoding='utf-8', errors='ignore') if file_path.endswith('.gz') else open(file_path, 'r', encoding='utf-8', errors='ignore')) as f:
        reader = csv.reader(f)
        data = []
        for row in reader:
            row += [''] * (10 - len(row))
            timestamp, server_host, username, host, connection_id, query_id, operation, database, query, retcode = row[:10]
            try:
                retcode = int(retcode)
            except:
                retcode = 0
            data.append((log_date, timestamp, server_host, username, host, connection_id, query_id, operation, database, query, retcode))
        with conn.cursor() as cur:
            sql = """INSERT INTO audit_log
                    (log_date, timestamp, server_host, username, host, connection_id, query_id, operation, dbname, query, retcode)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
            cur.executemany(sql, data)
        print(f"✅ 匯入 {file_path} 完成，共 {len(data)} 筆")

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

# ========== 分析查詢 ==========

def analyze_summary(conn, date_filter, date_filter_value):
    with conn.cursor() as cur:
        if isinstance(date_filter_value, tuple):
            params = date_filter_value
        else:
            params = (date_filter_value,)
        cur.execute("SELECT COUNT(*), COUNT(DISTINCT username), COUNT(DISTINCT host) FROM audit_log WHERE " + date_filter, params)
        total_events, unique_users, unique_hosts = cur.fetchone()
        return {
            'total_events': total_events,
            'unique_users': unique_users,
            'unique_hosts': unique_hosts
        }

def analyze_failed_logins(conn, date_filter, date_filter_value, threshold=5):
    with conn.cursor() as cur:
        if isinstance(date_filter_value, tuple):
            params = date_filter_value + (threshold,)
            params2 = date_filter_value
        else:
            params = (date_filter_value, threshold)
            params2 = (date_filter_value,)
        cur.execute(
            f"""SELECT username, COUNT(*) as fail_count
                FROM audit_log
                WHERE operation='CONNECT' AND retcode!=0 AND {date_filter}
                GROUP BY username
                HAVING fail_count >= %s
                ORDER BY fail_count DESC
            """,
            params
        )
        by_user = cur.fetchall()
        cur.execute(
            f"""SELECT host, COUNT(*) as fail_count
                FROM audit_log
                WHERE operation='CONNECT' AND retcode!=0 AND {date_filter}
                GROUP BY host
                HAVING fail_count >= %s
                ORDER BY fail_count DESC
            """,
            params
        )
        by_ip = cur.fetchall()
        cur.execute(
            f"SELECT COUNT(*) FROM audit_log WHERE operation='CONNECT' AND retcode!=0 AND {date_filter}",
            params2
        )
        total = cur.fetchone()[0]
        return {
            'total': total,
            'by_user': by_user,
            'by_ip': by_ip
        }

def analyze_privileged_operations(conn, date_filter, date_filter_value, keywords):
    like_clauses = " OR ".join(["UPPER(query) LIKE %s" for _ in keywords])
    like_params = [f"%{k.upper()}%" for k in keywords]
    if isinstance(date_filter_value, tuple):
        params = like_params + list(date_filter_value)
    else:
        params = like_params + [date_filter_value]

    with conn.cursor() as cur:
        cur.execute(
            f"""SELECT username, COUNT(*) as cnt
                FROM audit_log
                WHERE operation='QUERY' AND ({like_clauses}) AND {date_filter}
                GROUP BY username
                ORDER BY cnt DESC
            """,
            params
        )
        by_user = cur.fetchall()
        cur.execute(
            f"""SELECT COUNT(*) FROM audit_log
                WHERE operation='QUERY' AND ({like_clauses}) AND {date_filter}
            """,
            params
        )
        total = cur.fetchone()[0]
        cur.execute(
            f"""SELECT username, query, timestamp
                FROM audit_log
                WHERE operation='QUERY' AND ({like_clauses}) AND {date_filter}
                ORDER BY timestamp DESC
            """,
            params
        )
        details = cur.fetchall()
        return {
            'total': total,
            'by_user': by_user,
            'details': details
        }

def analyze_operation_stats(conn, date_filter, date_filter_value):
    with conn.cursor() as cur:
        if isinstance(date_filter_value, tuple):
            params = date_filter_value
        else:
            params = (date_filter_value,)
        cur.execute(
            f"""SELECT operation, COUNT(*) as cnt
                FROM audit_log
                WHERE {date_filter}
                GROUP BY operation
                ORDER BY cnt DESC
            """,
            params
        )
        return cur.fetchall()

def analyze_error_codes(conn, date_filter, date_filter_value):
    with conn.cursor() as cur:
        if isinstance(date_filter_value, tuple):
            params = date_filter_value
        else:
            params = (date_filter_value,)
        cur.execute(
            f"""SELECT retcode, COUNT(*) as cnt
                FROM audit_log
                WHERE retcode!=0 AND {date_filter}
                GROUP BY retcode
                ORDER BY cnt DESC
            """,
            params
        )
        error_codes = cur.fetchall()
        cur.execute(
            f"SELECT COUNT(*) FROM audit_log WHERE retcode!=0 AND {date_filter}",
            params
        )
        total_errors = cur.fetchone()[0]
        return {
            'total_errors': total_errors,
            'error_codes': error_codes
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
        cur.execute(
            f"""SELECT host, COUNT(*) as cnt
                FROM audit_log
                WHERE host NOT IN ({ip_list}) AND {date_filter}
                GROUP BY host
                ORDER BY cnt DESC
            """,
            params
        )
        by_ip = cur.fetchall()
        cur.execute(
            f"""SELECT username, host, operation, timestamp
                FROM audit_log
                WHERE host NOT IN ({ip_list}) AND {date_filter}
                ORDER BY timestamp DESC
            """,
            params
        )
        details = cur.fetchall()
        cur.execute(
            f"""SELECT COUNT(*) FROM audit_log
                WHERE host NOT IN ({ip_list}) AND {date_filter}
            """,
            params
        )
        total = cur.fetchone()[0]
        return {'total': total, 'by_ip': by_ip, 'details': details}

# ========== 報表產生（CSV） ==========

def generate_csv_report(output_dir, report_title, summary, failed, priv_ops, priv_user_logins, op_stats, err, after_hours, non_whitelisted, period_label):
    os.makedirs(output_dir, exist_ok=True)
    csv_file = os.path.join(output_dir, f'mysql_audit_analysis_{period_label}.csv')
    w = lambda row: writer.writerow(row)
    with open(csv_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        w([f'{report_title} - {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'])
        w([]); w(['=== Basic Statistics ==='])
        w(['Total Events', summary['total_events']])
        w(['Unique Users', summary['unique_users']])
        w(['Unique Hosts', summary['unique_hosts']])
        w([])
        w(['=== Failed Login Analysis ==='])
        w(['Total Failed Logins', failed['total']]); w([])
        if failed['by_user']:
            w(['Suspicious Users (Above Threshold)'])
            w(['Username', 'Failed Count'])
            for row in failed['by_user']: w(list(row))
            w([])
        if failed['by_ip']:
            w(['Suspicious IPs (Above Threshold)'])
            w(['IP Address', 'Failed Count'])
            for row in failed['by_ip']: w(list(row))
            w([])
        w(['=== Privileged Operations Analysis ==='])
        w(['Total Privileged Operations', priv_ops['total']]); w([])
        if priv_ops['by_user']:
            w(['By User Statistics']); w(['Username', 'Operation Count'])
            for row in priv_ops['by_user']: w(list(row))
            w([])
        if priv_ops.get('details'):
            w(['Detailed Privileged Operations (SQL)'])
            w(['Username', 'SQL', 'Timestamp'])
            for row in priv_ops['details']:
                w(list(row))
            w([])
        w(['=== Privileged Account Login Analysis ==='])
        w(['Total Privileged Account Logins', priv_user_logins['total']])
        if priv_user_logins['by_user']:
            w(['Username', 'Login Count'])
            for row in priv_user_logins['by_user']: w(list(row))
        w([])
        if priv_user_logins['details']:
            w(['Detailed Privileged Account Login Records'])
            w(['Username', 'Host', 'Timestamp'])
            for row in priv_user_logins['details']:
                w(list(row))
            w([])
        w(['=== Operation Type Statistics ===']); w(['Operation Type', 'Count'])
        for row in op_stats: w(list(row))
        w([])
        w(['=== Error Analysis ===']); w(['Total Errors', err['total_errors']]); w([])
        if err['error_codes']:
            w(['Error Code Statistics']); w(['Error Code', 'Count'])
            for row in err['error_codes']: w(list(row))
        w([])
        w(['=== After-hours Access (Specify account) ==='])
        w(['Total After-hours Access', after_hours['total']])
        if after_hours['details']:
            w(['Username', 'Host', 'Operation', 'Time'])
            for row in after_hours['details']:
                w(list(row))
        w([])
        w(['=== Non-whitelisted IP Access Analysis ==='])
        w(['Total Events from Non-whitelisted IPs', non_whitelisted['total']])
        if non_whitelisted['by_ip']:
            w(['Non-whitelisted IPs'])
            w(['IP Address', 'Event Count'])
            for row in non_whitelisted['by_ip']: w(list(row))
            w([])
        if non_whitelisted['details']:
            w(['Details (Username, Host, Operation, Time)'])
            for row in non_whitelisted['details']:
                w(list(row))
        w([])
    print(f"✅ CSV report generated: {csv_file}")
    return csv_file

# ========== 報表產生（PDF） ==========

def generate_pdf_report(output_dir, report_title, summary, failed, priv_ops, priv_user_logins, op_stats, err, after_hours, non_whitelisted, period_label):
    if not REPORTLAB_AVAILABLE:
        print("❌ ReportLab not installed, PDF report cannot be generated.")
        return None
    os.makedirs(output_dir, exist_ok=True)
    pdf_file = os.path.join(output_dir, f'mysql_audit_analysis_{period_label}.pdf')
    doc = SimpleDocTemplate(pdf_file, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []
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

    story.append(Paragraph("<b>=== Basic Statistics ===</b>", styles['Heading2']))
    story.append(Paragraph(f"Total Events: {summary['total_events']}<br />"
                        f"Unique Users: {summary['unique_users']}<br />"
                        f"Unique Hosts: {summary['unique_hosts']}", styles['Normal']))

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
    print(f"✅ PDF report generated: {pdf_file}")
    return pdf_file

# ========== 郵件寄送 ==========

def send_email_with_attachment(config: Config, subject, body, attachment_path):
    if not (config.smtp_server and config.mail_from and config.mail_to):
        print("❌ SMTP 或收件人設定不完整，無法寄信。")
        return
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
        print(f"📧 郵件已寄出至: {', '.join(config.mail_to)}")
    except Exception as e:
        print(f"❌ 郵件寄送失敗: {e}")

# ========== 主程式 ==========

def main():
    parser = argparse.ArgumentParser(description='MySQL Audit Log Security Analyzer (MySQL backend)')
    parser.add_argument('--import-date', help='Import logs for specific date (format: YYYY-MM-DD)')
    parser.add_argument('--import-month', help='Import logs for specific month (format: YYYY-MM)')
    parser.add_argument('--analyze-date', help='Analyze logs for specific date (format: YYYY-MM-DD)')
    parser.add_argument('--analyze-month', help='Analyze logs for specific month (format: YYYY-MM)')
    parser.add_argument('--output-dir', help='Output directory')
    parser.add_argument('--csv-only', action='store_true', help='Generate CSV report only')
    parser.add_argument('--show-env', action='store_true', help='Show all env/config parameters and exit')
    args = parser.parse_args()
    config = Config()

    # 顯示所有 env 設定
    if args.show_env:
        print("🔎 目前抓到的 .env/環境變數參數如下：\n")
        for k, v in config.as_dict().items():
            print(f"{k}: {v}")
        return

    conn = get_db_conn(config)

    # 匯入日誌
    if args.import_date:
        log = get_log_file_for_date(config, args.import_date)
        if log:
            import_log_file_to_db(log[0], log[1], conn)
        else:
            print(f"❌ No log file found for {args.import_date}")
        return
    elif args.import_month:
        logs = get_log_files_for_month(config, args.import_month)
        if not logs:
            print(f"❌ No log files found for {args.import_month}")
            return
        for log_path, log_date in logs:
            import_log_file_to_db(log_path, log_date, conn)
        return

    # 分析
    if args.analyze_month:
        # 修正：正確支援 DATE 型態的 log_date
        year, month = map(int, args.analyze_month.split('-'))
        days_in_month = calendar.monthrange(year, month)[1]
        date_start = f"{year:04d}-{month:02d}-01"
        date_end = f"{year:04d}-{month:02d}-{days_in_month:02d}"
        period_label = args.analyze_month.replace('-', '')
        date_filter = "log_date BETWEEN %s AND %s"
        date_filter_value = (date_start, date_end)
    else:
        date_str = args.analyze_date if args.analyze_date else datetime.now().strftime('%Y-%m-%d')
        period_label = date_str.replace('-', '')
        date_filter = "log_date = %s"
        date_filter_value = date_str

    summary = analyze_summary(conn, date_filter, date_filter_value)
    failed = analyze_failed_logins(conn, date_filter, date_filter_value, config.failed_login_threshold)
    priv_ops = analyze_privileged_operations(conn, date_filter, date_filter_value, config.privileged_keywords)
    op_stats = analyze_operation_stats(conn, date_filter, date_filter_value)
    err = analyze_error_codes(conn, date_filter, date_filter_value)
    after_hours = analyze_after_hours_access(conn, date_filter, date_filter_value, config.after_hours_users, config.work_hour_start, config.work_hour_end)
    priv_user_logins = analyze_privileged_user_logins(conn, date_filter, date_filter_value, config.privileged_users)
    non_whitelisted = analyze_non_whitelisted_ips(conn, date_filter, date_filter_value, config.allowed_ips)

    output_dir = args.output_dir or config.output_dir
    csv_file = None
    pdf_file = None
    if config.generate_csv:
        csv_file = generate_csv_report(output_dir, config.report_title, summary, failed, priv_ops, priv_user_logins, op_stats, err, after_hours, non_whitelisted, period_label)
    if config.generate_pdf and not args.csv_only:
        pdf_file = generate_pdf_report(output_dir, config.report_title, summary, failed, priv_ops, priv_user_logins, op_stats, err, after_hours, non_whitelisted, period_label)
        if pdf_file and config.send_email:
            send_email_with_attachment(
                config,
                subject=f"{config.report_title} ({period_label})",
                body=f"附件為 {config.company_name} MySQL 稽核日誌安全分析報告。",
                attachment_path=pdf_file
            )
        elif pdf_file:
            print("✉️  SEND_EMAIL=false，未進行郵件寄送。")
    elif args.csv_only:
        print("✉️  已指定 --csv-only，不產生PDF亦不寄信。")
    else:
        print("✉️  未產生PDF，不進行寄信。")

    print("\n" + "="*50)
    print("📊 Analysis Result Summary")
    print("="*50)
    print(f"Total Events: {summary['total_events']}")
    print(f"Failed Logins: {failed['total']}")
    print(f"Privileged Operations: {priv_ops['total']}")
    print(f"Privileged Account Logins: {priv_user_logins['total']}")
    print(f"Error Events: {err['total_errors']}")
    print(f"Non-whitelisted IP Events: {non_whitelisted['total']}")
    if failed['by_user']:
        print(f"\n⚠️  Suspicious Users: {len(failed['by_user'])}")
    if failed['by_ip']:
        print(f"⚠️  Suspicious IPs: {len(failed['by_ip'])}")
    if non_whitelisted['by_ip']:
        print(f"⚠️  Non-whitelisted IPs: {len(non_whitelisted['by_ip'])}")
    if after_hours['total']:
        print(f"⚠️  After-hours access (Specify account): {after_hours['total']}")

if __name__ == "__main__":
    main()
