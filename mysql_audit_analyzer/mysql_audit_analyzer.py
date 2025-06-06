#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MySQL Audit Log Security Analyzer (with Privileged Account Login Analysis)
"""

import csv, os, sys, argparse, re, json, smtplib
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from pathlib import Path
from typing import List, Optional
from email.message import EmailMessage
from email.utils import formataddr

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

try:
    from dotenv import load_dotenv
    DOTENV_AVAILABLE = True
except ImportError:
    DOTENV_AVAILABLE = False

class Config:
    def __init__(self, env_file=None):
        self.env_file = env_file or '.env'
        self.load_config()
    def load_config(self):
        if DOTENV_AVAILABLE and os.path.exists(self.env_file):
            load_dotenv(self.env_file)
        getenv = os.getenv
        self.company_name = getenv('COMPANY_NAME', 'Your Company')
        self.report_title = getenv('REPORT_TITLE', 'MySQL Audit Log Security Analysis Report')
        self.log_base_path = getenv('LOG_BASE_PATH', '/var/log/mysql/audit')
        self.log_file_prefix = getenv('LOG_FILE_PREFIX', 'server_audit.log')
        self.output_dir = getenv('OUTPUT_DIR', '/tmp/mysql_reports')
        self.failed_login_threshold = int(getenv('FAILED_LOGIN_THRESHOLD', '5'))
        self.suspicious_ips = [ip.strip() for ip in getenv('SUSPICIOUS_IPS', '').split(',') if ip.strip()]
        self.include_detailed_logs = getenv('INCLUDE_DETAILED_LOGS', 'true').lower() == 'true'
        self.max_events_in_report = int(getenv('MAX_EVENTS_IN_REPORT', '1000'))
        self.after_hours_users = [u.strip() for u in getenv('AFTER_HOURS_USERS', '').split(',') if u.strip()]
        self.work_hour_start = int(getenv('WORK_HOUR_START', '9'))
        self.work_hour_end = int(getenv('WORK_HOUR_END', '18'))
        self.privileged_users = [u.strip() for u in getenv('PRIVILEGED_USERS', '').split(',') if u.strip()]
        self.smtp_host = getenv('SMTP_HOST', '')
        self.smtp_port = int(getenv('SMTP_PORT', '587'))
        self.smtp_user = getenv('SMTP_USER', '')
        self.smtp_password = getenv('SMTP_PASSWORD', '')
        self.mail_from = getenv('MAIL_FROM', self.smtp_user)
        self.mail_to = [m.strip() for m in getenv('MAIL_TO', '').split(',') if m.strip()]
        self.mail_subject = getenv('MAIL_SUBJECT', self.report_title)
        self.generate_pdf = getenv('GENERATE_PDF', 'true').lower() == 'true'
        self.generate_csv = getenv('GENERATE_CSV', 'true').lower() == 'true'
        self.send_email = getenv('SEND_EMAIL', 'false').lower() == 'true'
    def get_log_file_path(self, date_str: str = None) -> str:
        return os.path.join(self.log_base_path, self.log_file_prefix if not date_str else f"{self.log_file_prefix}-{date_str}")
    def show_config(self):
        print("=== MySQL Audit Log Analyzer Configuration ===")
        attrs = [
            'company_name','report_title','log_base_path','log_file_prefix','output_dir',
            'failed_login_threshold','suspicious_ips','include_detailed_logs','max_events_in_report',
            'after_hours_users','privileged_users','work_hour_start','work_hour_end',
            'generate_pdf','generate_csv','send_email'
        ]
        for a in attrs:
            print(f"{a.replace('_',' ').title()}: {getattr(self,a)}")
        today = datetime.now().strftime('%Y-%m-%d')
        yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
        for label, date in [("Today's Log", today), ("Yesterday's Log", yesterday)]:
            path = self.get_log_file_path(date)
            print(f"{label}: {path} {'✅' if os.path.exists(path) else '❌'}")

class AuditLogEntry:
    def __init__(self, line: str):
        self.raw_line = line.strip()
        self.parse_line()
    def parse_line(self):
        try:
            reader = csv.reader([self.raw_line])
            fields = next(reader)
            fields += [''] * (10 - len(fields))
            (self.timestamp, self.server_host, self.username, self.host,
             self.connection_id, self.query_id, self.operation, self.database,
             self.query, self.retcode) = fields[:10]
            try: self.retcode = int(self.retcode)
            except: self.retcode = 0
        except Exception:
            self.timestamp = self.server_host = self.username = self.host = ''
            self.connection_id = self.query_id = self.operation = ''
            self.database = self.query = ''
            self.retcode = 0
    def is_failed_login(self) -> bool:
        return self.operation == 'CONNECT' and self.retcode != 0
    def is_privileged_operation(self) -> bool:
        if self.operation != 'QUERY': return False
        keywords = [
            'CREATE USER', 'DROP USER', 'GRANT', 'REVOKE',
            'CREATE DATABASE', 'DROP DATABASE', 'CREATE TABLE',
            'DROP TABLE', 'ALTER USER', 'SET PASSWORD'
        ]
        q = self.query.upper()
        return any(k in q for k in keywords)
    def get_datetime(self) -> Optional[datetime]:
        for fmt in ['%Y%m%d %H:%M:%S', '%Y%m%d', '%Y%m%d%H%M%S']:
            try: return datetime.strptime(self.timestamp, fmt)
            except: continue
        return None

class SecurityAnalyzer:
    def __init__(self, config: Config):
        self.config = config
        self.entries: List[AuditLogEntry] = []
        self.analysis_results = {}
    def load_log_file(self, file_path: str) -> bool:
        if not os.path.exists(file_path):
            print(f"❌ Log file does not exist: {file_path}")
            return False
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [l for l in f if l.strip()]
        print(f"📁 Loading log file: {file_path}\n📄 Total lines: {len(lines)}")
        for line in lines:
            entry = AuditLogEntry(line)
            if entry.timestamp:
                self.entries.append(entry)
        print(f"✅ Successfully parsed {len(self.entries)} log records")
        return True
    def analyze(self):
        print("🔍 Starting security analysis...")
        self.analysis_results['total_events'] = len(self.entries)
        self.analysis_results['unique_users'] = len(set(e.username for e in self.entries))
        self.analysis_results['unique_hosts'] = len(set(e.host for e in self.entries))
        self._analyze_failed_logins()
        self._analyze_suspicious_ips()
        self._analyze_privileged_operations()
        self._analyze_operation_stats()
        self._analyze_error_codes()
        self._analyze_after_hours_access()
        self._analyze_privileged_user_logins()
        print("✅ Security analysis completed")
    def _analyze_failed_logins(self):
        failed = [e for e in self.entries if e.is_failed_login()]
        by_user = Counter(e.username for e in failed)
        by_ip = Counter(e.host for e in failed)
        threshold = self.config.failed_login_threshold
        self.analysis_results['failed_logins'] = {
            'total': len(failed),
            'by_user': dict(by_user.most_common(10)),
            'by_ip': dict(by_ip.most_common(10)),
            'suspicious_users': {u: c for u, c in by_user.items() if c >= threshold},
            'suspicious_ips': {ip: c for ip, c in by_ip.items() if c >= threshold},
            'details': failed[:50]
        }
    def _analyze_suspicious_ips(self):
        if not self.config.suspicious_ips:
            self.analysis_results['suspicious_ip_activity'] = {'total': 0, 'details': []}
            return
        suspicious = [e for e in self.entries if self._is_suspicious_ip(e.host)]
        self.analysis_results['suspicious_ip_activity'] = {
            'total': len(suspicious),
            'details': suspicious[:50]
        }
    def _is_suspicious_ip(self, ip: str) -> bool:
        for s_ip in self.config.suspicious_ips:
            if not s_ip: continue
            if '/' in s_ip:
                net = s_ip.split('/')[0]
                if ip.startswith(net.rsplit('.', 1)[0]):
                    return True
            elif ip == s_ip:
                return True
        return False
    def _analyze_privileged_operations(self):
        priv_ops = [e for e in self.entries if e.is_privileged_operation()]
        by_user = Counter(e.username for e in priv_ops)
        self.analysis_results['privileged_operations'] = {
            'total': len(priv_ops),
            'by_user': dict(by_user.most_common(10)),
            'details': priv_ops[:50]
        }
    def _analyze_operation_stats(self):
        op_counts = Counter(e.operation for e in self.entries)
        self.analysis_results['operation_stats'] = dict(op_counts.most_common())
    def _analyze_error_codes(self):
        errors = [e for e in self.entries if e.retcode != 0]
        codes = Counter(e.retcode for e in errors)
        self.analysis_results['error_analysis'] = {
            'total_errors': len(errors),
            'error_codes': dict(codes.most_common()),
            'details': errors[:50]
        }
    def _analyze_after_hours_access(self):
        users = self.config.after_hours_users
        wh_start, wh_end = self.config.work_hour_start, self.config.work_hour_end
        after_hours = []
        for e in self.entries:
            if e.username in users:
                dt = e.get_datetime()
                if dt:
                    if dt.weekday() >= 5 or not (wh_start <= dt.hour < wh_end):
                        after_hours.append(e)
        self.analysis_results['after_hours_access'] = {
            'total': len(after_hours),
            'details': after_hours[:50]
        }
    def _analyze_privileged_user_logins(self):
        users = self.config.privileged_users
        priv_logins = [e for e in self.entries if e.operation == 'CONNECT' and e.username in users]
        by_user = Counter(e.username for e in priv_logins)
        self.analysis_results['privileged_user_logins'] = {
            'total': len(priv_logins),
            'by_user': dict(by_user.most_common()),
            'details': priv_logins[:50]
        }

class ReportGenerator:
    def __init__(self, config: Config, analysis_results: dict):
        self.config = config
        self.analysis_results = analysis_results
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    def generate_csv_report(self, output_dir: str) -> str:
        os.makedirs(output_dir, exist_ok=True)
        csv_file = os.path.join(output_dir, f'mysql_audit_analysis_{self.timestamp}.csv')
        w = lambda row: writer.writerow(row)
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            w([f'{self.config.report_title} - {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'])
            w([]); w(['=== Basic Statistics ==='])
            w(['Total Events', self.analysis_results.get('total_events', 0)])
            w(['Unique Users', self.analysis_results.get('unique_users', 0)])
            w(['Unique Hosts', self.analysis_results.get('unique_hosts', 0)])
            w([])
            # Failed login analysis
            failed = self.analysis_results.get('failed_logins', {})
            w(['=== Failed Login Analysis ==='])
            w(['Total Failed Logins', failed.get('total', 0)]); w([])
            if failed.get('suspicious_users'):
                w(['Suspicious Users (Above Threshold)'])
                w(['Username', 'Failed Count'])
                for user, count in failed['suspicious_users'].items(): w([user, count])
                w([])
            if failed.get('suspicious_ips'):
                w(['Suspicious IPs (Above Threshold)'])
                w(['IP Address', 'Failed Count'])
                for ip, count in failed['suspicious_ips'].items(): w([ip, count])
                w([])
            # Privileged operations analysis
            priv_ops = self.analysis_results.get('privileged_operations', {})
            w(['=== Privileged Operations Analysis ==='])
            w(['Total Privileged Operations', priv_ops.get('total', 0)]); w([])
            if priv_ops.get('by_user'):
                w(['By User Statistics']); w(['Username', 'Operation Count'])
                for user, count in priv_ops['by_user'].items(): w([user, count])
                w([])
            # Privileged user login analysis
            priv_user_logins = self.analysis_results.get('privileged_user_logins', {})
            w(['=== Privileged Account Login Analysis ==='])
            w(['Total Privileged Account Logins', priv_user_logins.get('total', 0)])
            if priv_user_logins.get('by_user'):
                w(['Username', 'Login Count'])
                for user, count in priv_user_logins['by_user'].items(): w([user, count])
            w([])
            if priv_user_logins.get('details'):
                w(['Detailed Privileged Account Login Records'])
                w(['Username', 'Host', 'Timestamp'])
                for e in priv_user_logins['details']:
                    dt = e.get_datetime()
                    w([e.username, e.host, dt.strftime('%Y-%m-%d %H:%M:%S') if dt else e.timestamp])
                w([])
            # Operation statistics
            w(['=== Operation Type Statistics ===']); w(['Operation Type', 'Count'])
            for op, c in self.analysis_results.get('operation_stats', {}).items(): w([op, c])
            w([])
            # Error analysis
            err = self.analysis_results.get('error_analysis', {})
            w(['=== Error Analysis ===']); w(['Total Errors', err.get('total_errors', 0)]); w([])
            if err.get('error_codes'):
                w(['Error Code Statistics']); w(['Error Code', 'Count'])
                for code, count in err['error_codes'].items(): w([code, count])
            w([])
            # After-hours access
            after_hours = self.analysis_results.get('after_hours_access', {})
            w(['=== After-hours Access (Specify account) ==='])
            w(['Total After-hours Access', after_hours.get('total', 0)])
            if after_hours.get('details'):
                w(['Username', 'Host', 'Operation', 'Time'])
                for e in after_hours['details']:
                    dt = e.get_datetime()
                    w([e.username, e.host, e.operation, dt.strftime('%Y-%m-%d %H:%M:%S') if dt else e.timestamp])
            w([])
        print(f"✅ CSV report generated: {csv_file}")
        return csv_file
    def generate_pdf_report(self, output_dir: str) -> str:
        if not REPORTLAB_AVAILABLE:
            print("❌ ReportLab not installed, cannot generate PDF report\nPlease run: pip install reportlab")
            return None
        os.makedirs(output_dir, exist_ok=True)
        pdf_file = os.path.join(output_dir, f'mysql_audit_analysis_{self.timestamp}.pdf')
        doc = SimpleDocTemplate(pdf_file, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        def add_table(data, font=12):
            table = Table(data)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), font),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(table)
        title_style = ParagraphStyle(
            'CustomTitle', parent=styles['Heading1'],
            fontSize=16, spaceAfter=30, alignment=1
        )
        story.append(Paragraph(self.config.report_title, title_style))
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        story.append(Spacer(1, 20))
        story.append(Paragraph("Basic Statistics", styles['Heading2']))
        add_table([
            ['Total Events', str(self.analysis_results.get('total_events', 0))],
            ['Unique Users', str(self.analysis_results.get('unique_users', 0))],
            ['Unique Hosts', str(self.analysis_results.get('unique_hosts', 0))]
        ], 14)
        story.append(Spacer(1, 20))
        # Security warnings
        story.append(Paragraph("Security Warnings", styles['Heading2']))
        failed = self.analysis_results.get('failed_logins', {})
        if failed.get('suspicious_users') or failed.get('suspicious_ips'):
            if failed.get('suspicious_users'):
                story.append(Paragraph("⚠️ Suspicious user activity detected:", styles['Normal']))
                for user, count in failed['suspicious_users'].items():
                    story.append(Paragraph(f"• {user}: {count} failed logins", styles['Normal']))
                story.append(Spacer(1, 10))
            if failed.get('suspicious_ips'):
                story.append(Paragraph("⚠️ Suspicious IP activity detected:", styles['Normal']))
                for ip, count in failed['suspicious_ips'].items():
                    story.append(Paragraph(f"• {ip}: {count} failed logins", styles['Normal']))
        else:
            story.append(Paragraph("✅ No obvious security threats detected", styles['Normal']))
        story.append(Spacer(1, 20))
        # Operation statistics
        story.append(Paragraph("Operation Type Statistics", styles['Heading2']))
        op_data = [['Operation Type', 'Count']]
        for op, c in list(self.analysis_results.get('operation_stats', {}).items())[:10]:
            op_data.append([op, str(c)])
        if len(op_data) > 1: add_table(op_data)
        story.append(Spacer(1, 20))
        # Privileged user login analysis
        story.append(Paragraph("Privileged Account Login Analysis", styles['Heading2']))
        priv_user_logins = self.analysis_results.get('privileged_user_logins', {})
        story.append(Paragraph(f"Total privileged account logins: {priv_user_logins.get('total', 0)}", styles['Normal']))
        if priv_user_logins.get('by_user'):
            data = [['Username', 'Login Count']]
            for user, count in priv_user_logins['by_user'].items():
                data.append([user, str(count)])
            add_table(data, 10)
        story.append(Spacer(1, 20))
        if priv_user_logins.get('details'):
            story.append(Paragraph("Detailed Privileged Account Login Records (Top 50)", styles['Heading3']))
            data = [['Username', 'Host', 'Timestamp']]
            for e in priv_user_logins['details']:
                dt = e.get_datetime()
                data.append([e.username, e.host, dt.strftime('%Y-%m-%d %H:%M:%S') if dt else e.timestamp])
            add_table(data, 10)
            story.append(Spacer(1, 20))
        # After-hours access
        story.append(Paragraph("After-hours Access (Specify account)", styles['Heading2']))
        after_hours = self.analysis_results.get('after_hours_access', {})
        story.append(Paragraph(f"Total after-hours access: {after_hours.get('total', 0)}", styles['Normal']))
        if after_hours.get('details'):
            data = [['Username', 'Host', 'Operation', 'Time']]
            for e in after_hours['details']:
                dt = e.get_datetime()
                data.append([e.username, e.host, e.operation, dt.strftime('%Y-%m-%d %H:%M:%S') if dt else e.timestamp])
            add_table(data, 10)
        story.append(Spacer(1, 20))
        doc.build(story)
        print(f"✅ PDF report generated: {pdf_file}")
        return pdf_file

def send_email_with_attachment(config: Config, attachment_path: str, body: str = ""):
    if not config.smtp_host or not config.mail_to:
        print("❌ SMTP 設定不完整，無法發送郵件")
        return False
    msg = EmailMessage()
    msg['Subject'] = getattr(config, 'mail_subject', 'MySQL Audit Log Report')
    msg['From'] = formataddr((getattr(config, 'company_name', ''), getattr(config, 'mail_from', '')))
    msg['To'] = ", ".join(getattr(config, 'mail_to', []))
    msg.set_content(body or f'報表使用昨日紀錄生成，詳見附件：{os.path.basename(attachment_path)}')
    with open(attachment_path, 'rb') as f:
        file_data = f.read()
        file_name = os.path.basename(attachment_path)
        msg.add_attachment(file_data, maintype='application', subtype='pdf', filename=file_name)
    try:
        with smtplib.SMTP(getattr(config, 'smtp_host', ''), getattr(config, 'smtp_port', 25)) as smtp:
            smtp.send_message(msg)
        print(f"✅ 郵件已發送至 {getattr(config, 'mail_to', [])}")
        return True
    except Exception as e:
        print(f"❌ 發送郵件失敗: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description='MySQL Audit Log Security Analyzer')
    parser.add_argument('--date', help='Analyze logs for specific date (format: YYYY-MM-DD, default: today)')
    parser.add_argument('--output-dir', help='Output directory')
    parser.add_argument('--csv-only', action='store_true', help='Generate CSV report only')
    parser.add_argument('--pdf-only', action='store_true', help='Generate PDF report only')
    parser.add_argument('--show-config', action='store_true', help='Show current configuration')
    parser.add_argument('--env-file', help='Specify environment file path')
    args = parser.parse_args()
    config = Config(args.env_file)
    if args.show_config:
        config.show_config()
        return
    date_str = args.date if args.date else datetime.now().strftime('%Y-%m-%d')
    print(f"📅 Analysis date: {date_str}")
    log_file_path = config.get_log_file_path(date_str)
    analyzer = SecurityAnalyzer(config)
    if not analyzer.load_log_file(log_file_path):
        return
    analyzer.analyze()
    output_dir = args.output_dir or config.output_dir
    report_generator = ReportGenerator(config, analyzer.analysis_results)
    generated_files = []
    generate_csv = config.generate_csv if not args.pdf_only else False
    generate_pdf = config.generate_pdf if not args.csv_only else False
    if generate_csv:
        csv_file = report_generator.generate_csv_report(output_dir)
        if csv_file: generated_files.append(csv_file)
    if generate_pdf:
        pdf_file = report_generator.generate_pdf_report(output_dir)
        if pdf_file:
            generated_files.append(pdf_file)
            if config.send_email:
                send_email_with_attachment(config, pdf_file)
            else:
                print("✉️  SEND_EMAIL 設定為 false，未寄出郵件")
    print("\n" + "="*50)
    print("📊 Analysis Result Summary")
    print("="*50)
    print(f"Total Events: {analyzer.analysis_results.get('total_events', 0)}")
    print(f"Failed Logins: {analyzer.analysis_results.get('failed_logins', {}).get('total', 0)}")
    print(f"Privileged Operations: {analyzer.analysis_results.get('privileged_operations', {}).get('total', 0)}")
    print(f"Privileged Account Logins: {analyzer.analysis_results.get('privileged_user_logins', {}).get('total', 0)}")
    print(f"Error Events: {analyzer.analysis_results.get('error_analysis', {}).get('total_errors', 0)}")
    failed_logins = analyzer.analysis_results.get('failed_logins', {})
    if failed_logins.get('suspicious_users'):
        print(f"\n⚠️  Suspicious Users: {len(failed_logins['suspicious_users'])}")
    if failed_logins.get('suspicious_ips'):
        print(f"⚠️  Suspicious IPs: {len(failed_logins['suspicious_ips'])}")
    after_hours = analyzer.analysis_results.get('after_hours_access', {})
    if after_hours.get('total', 0):
        print(f"⚠️  After-hours access (Specify account): {after_hours.get('total', 0)}")
    print(f"\n📁 Generated report files:")
    for file_path in generated_files:
        print(f"   • {file_path}")

if __name__ == "__main__":
    main()
