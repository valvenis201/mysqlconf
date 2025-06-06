#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MySQL Audit Log Security Analyzer (with Privileged Account Login Analysis)
"""

import csv
import os
import sys
import argparse
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from pathlib import Path
import re
from typing import Dict, List, Tuple, Optional
import json
import smtplib
from email.message import EmailMessage
from email.utils import formataddr

# Try to import optional dependencies
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

try:
    from dotenv import load_dotenv
    DOTENV_AVAILABLE = True
except ImportError:
    DOTENV_AVAILABLE = False

class Config:
    """Configuration management class"""
    def __init__(self, env_file=None):
        self.env_file = env_file or '.env'
        self.load_config()
    
    def load_config(self):
        """Load configuration"""
        # Load environment variables file
        if DOTENV_AVAILABLE and os.path.exists(self.env_file):
            load_dotenv(self.env_file)
        
        # Basic configuration
        self.company_name = os.getenv('COMPANY_NAME', 'Your Company')
        self.report_title = os.getenv('REPORT_TITLE', 'MySQL Audit Log Security Analysis Report')
        
        # Log file configuration
        self.log_base_path = os.getenv('LOG_BASE_PATH', '/var/log/mysql/audit')
        self.log_file_prefix = os.getenv('LOG_FILE_PREFIX', 'server_audit.log')
        self.output_dir = os.getenv('OUTPUT_DIR', '/tmp/mysql_reports')
        
        # Security thresholds
        self.failed_login_threshold = int(os.getenv('FAILED_LOGIN_THRESHOLD', '5'))
        self.suspicious_ips = os.getenv('SUSPICIOUS_IPS', '').split(',') if os.getenv('SUSPICIOUS_IPS') else []
        
        # Report configuration
        self.include_detailed_logs = os.getenv('INCLUDE_DETAILED_LOGS', 'true').lower() == 'true'
        self.max_events_in_report = int(os.getenv('MAX_EVENTS_IN_REPORT', '1000'))

        # After-hours access config
        self.after_hours_users = os.getenv('AFTER_HOURS_USERS', '').split(',') if os.getenv('AFTER_HOURS_USERS') else []
        self.work_hour_start = int(os.getenv('WORK_HOUR_START', '9'))  # 09:00
        self.work_hour_end = int(os.getenv('WORK_HOUR_END', '18'))    # 18:00

        # Privileged users config
        self.privileged_users = os.getenv('PRIVILEGED_USERS', '').split(',') if os.getenv('PRIVILEGED_USERS') else []

        # Email settings
        self.smtp_host = os.getenv('SMTP_HOST', '')
        self.smtp_port = int(os.getenv('SMTP_PORT', '587'))
        self.smtp_user = os.getenv('SMTP_USER', '')
        self.smtp_password = os.getenv('SMTP_PASSWORD', '')
        self.mail_from = os.getenv('MAIL_FROM', self.smtp_user)
        self.mail_to = os.getenv('MAIL_TO', '').split(',') if os.getenv('MAIL_TO') else []
        self.mail_subject = os.getenv('MAIL_SUBJECT', self.report_title)

        # Report output control
        self.generate_pdf = os.getenv('GENERATE_PDF', 'true').lower() == 'true'
        self.generate_csv = os.getenv('GENERATE_CSV', 'true').lower() == 'true'

        # Email send control
        self.send_email = os.getenv('SEND_EMAIL', 'false').lower() == 'true'
    
    def get_log_file_path(self, date_str: str = None) -> str:
        """Get log file path"""
        if date_str is None:
            # Current day's log file
            return os.path.join(self.log_base_path, self.log_file_prefix)
        else:
            # Historical log file
            return os.path.join(self.log_base_path, f"{self.log_file_prefix}-{date_str}")
    
    def show_config(self):
        """Display current configuration"""
        print("=== MySQL Audit Log Analyzer Configuration ===")
        print(f"Company Name: {self.company_name}")
        print(f"Report Title: {self.report_title}")
        print(f"Log Base Path: {self.log_base_path}")
        print(f"Log File Prefix: {self.log_file_prefix}")
        print(f"Output Directory: {self.output_dir}")
        print(f"Failed Login Threshold: {self.failed_login_threshold}")
        print(f"Suspicious IP List: {self.suspicious_ips}")
        print(f"Include Detailed Logs: {self.include_detailed_logs}")
        print(f"Max Events in Report: {self.max_events_in_report}")
        print(f"After-hours Users: {self.after_hours_users}")
        print(f"Privileged Users: {self.privileged_users}")
        print(f"Work Hour Start: {self.work_hour_start}")
        print(f"Work Hour End: {self.work_hour_end}")
        print(f"Generate PDF: {self.generate_pdf}")
        print(f"Generate CSV: {self.generate_csv}")
        print(f"Send Email: {self.send_email}")
        print()
        
        # Check file paths
        today = datetime.now().strftime('%Y-%m-%d')
        yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
        
        current_log = self.get_log_file_path()
        yesterday_log = self.get_log_file_path(yesterday)
        
        print("=== File Path Check ===")
        print(f"Today's Log: {current_log} {'✅' if os.path.exists(current_log) else '❌'}")
        print(f"Yesterday's Log: {yesterday_log} {'✅' if os.path.exists(yesterday_log) else '❌'}")

class AuditLogEntry:
    """Audit log entry class"""
    def __init__(self, line: str):
        self.raw_line = line.strip()
        self.parse_line()
    
    def parse_line(self):
        """Parse log line"""
        try:
            # Use CSV reader to parse
            reader = csv.reader([self.raw_line])
            fields = next(reader)
            
            if len(fields) >= 6:
                self.timestamp = fields[0] if fields[0] else ''
                self.server_host = fields[1] if len(fields) > 1 else ''
                self.username = fields[2] if len(fields) > 2 else ''
                self.host = fields[3] if len(fields) > 3 else ''
                self.connection_id = fields[4] if len(fields) > 4 else ''
                self.query_id = fields[5] if len(fields) > 5 else ''
                self.operation = fields[6] if len(fields) > 6 else ''
                self.database = fields[7] if len(fields) > 7 else ''
                self.query = fields[8] if len(fields) > 8 else ''
                self.retcode = fields[9] if len(fields) > 9 else '0'
            else:
                # Handle incomplete lines
                self.timestamp = fields[0] if len(fields) > 0 else ''
                self.server_host = fields[1] if len(fields) > 1 else ''
                self.username = fields[2] if len(fields) > 2 else ''
                self.host = fields[3] if len(fields) > 3 else ''
                self.connection_id = fields[4] if len(fields) > 4 else ''
                self.query_id = fields[5] if len(fields) > 5 else ''
                self.operation = ''
                self.database = ''
                self.query = ''
                self.retcode = '0'
            
            # Convert return code to integer
            try:
                self.retcode = int(self.retcode)
            except (ValueError, TypeError):
                self.retcode = 0
                
        except Exception as e:
            # If parsing fails, set default values
            self.timestamp = ''
            self.server_host = ''
            self.username = ''
            self.host = ''
            self.connection_id = ''
            self.query_id = ''
            self.operation = ''
            self.database = ''
            self.query = ''
            self.retcode = 0
    
    def is_failed_login(self) -> bool:
        """Check if this is a failed login"""
        return self.operation == 'CONNECT' and self.retcode != 0
    
    def is_privileged_operation(self) -> bool:
        """Check if this is a privileged operation"""
        if self.operation != 'QUERY':
            return False
        
        privileged_keywords = [
            'CREATE USER', 'DROP USER', 'GRANT', 'REVOKE',
            'CREATE DATABASE', 'DROP DATABASE', 'CREATE TABLE',
            'DROP TABLE', 'ALTER USER', 'SET PASSWORD'
        ]
        
        query_upper = self.query.upper()
        return any(keyword in query_upper for keyword in privileged_keywords)
    
    def get_datetime(self) -> Optional[datetime]:
        try:
            # 支援 YYYYMMDD HH:MM:SS
            if ' ' in self.timestamp:
                return datetime.strptime(self.timestamp, '%Y%m%d %H:%M:%S')
            elif len(self.timestamp) == 8:  # YYYYMMDD
                return datetime.strptime(self.timestamp, '%Y%m%d')
            elif len(self.timestamp) == 14:  # YYYYMMDDHHMMSS
                return datetime.strptime(self.timestamp, '%Y%m%d%H%M%S')
            else:
                return None
        except ValueError:
            return None

class SecurityAnalyzer:
    """Security analyzer"""
    def __init__(self, config: Config):
        self.config = config
        self.entries: List[AuditLogEntry] = []
        self.analysis_results = {}
    
    def load_log_file(self, file_path: str) -> bool:
        """Load log file"""
        if not os.path.exists(file_path):
            print(f"❌ Log file does not exist: {file_path}")
            return False
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            print(f"📁 Loading log file: {file_path}")
            print(f"📄 Total lines: {len(lines)}")
            
            for line in lines:
                if line.strip():  # Skip empty lines
                    entry = AuditLogEntry(line)
                    if entry.timestamp:  # Only add valid entries
                        self.entries.append(entry)
            
            print(f"✅ Successfully parsed {len(self.entries)} log records")
            return True
            
        except Exception as e:
            print(f"❌ Error loading log file: {e}")
            return False
    
    def analyze(self):
        """Perform security analysis"""
        print("🔍 Starting security analysis...")
        
        # Basic statistics
        self.analysis_results['total_events'] = len(self.entries)
        self.analysis_results['unique_users'] = len(set(entry.username for entry in self.entries))
        self.analysis_results['unique_hosts'] = len(set(entry.host for entry in self.entries))
        
        # Analyze failed logins
        self._analyze_failed_logins()
        
        # Analyze suspicious IPs
        self._analyze_suspicious_ips()
        
        # Analyze privileged operations
        self._analyze_privileged_operations()
        
        # Analyze operation statistics
        self._analyze_operation_stats()
        
        # Analyze error codes
        self._analyze_error_codes()

        # Analyze after-hours access
        self._analyze_after_hours_access()

        # Analyze privileged user logins
        self._analyze_privileged_user_logins()
        
        print("✅ Security analysis completed")
    
    def _analyze_failed_logins(self):
        """Analyze failed logins"""
        failed_logins = [entry for entry in self.entries if entry.is_failed_login()]
        
        # Count failures by user
        failed_by_user = Counter(entry.username for entry in failed_logins)
        
        # Count failures by IP
        failed_by_ip = Counter(entry.host for entry in failed_logins)
        
        # Find users and IPs exceeding threshold
        suspicious_users = {user: count for user, count in failed_by_user.items() 
                          if count >= self.config.failed_login_threshold}
        
        suspicious_ips = {ip: count for ip, count in failed_by_ip.items() 
                         if count >= self.config.failed_login_threshold}
        
        self.analysis_results['failed_logins'] = {
            'total': len(failed_logins),
            'by_user': dict(failed_by_user.most_common(10)),
            'by_ip': dict(failed_by_ip.most_common(10)),
            'suspicious_users': suspicious_users,
            'suspicious_ips': suspicious_ips,
            'details': failed_logins[:50]  # Save first 50 detailed records
        }
    
    def _analyze_suspicious_ips(self):
        """Analyze suspicious IPs"""
        if not self.config.suspicious_ips:
            self.analysis_results['suspicious_ip_activity'] = {'total': 0, 'details': []}
            return
        
        suspicious_activities = []
        
        for entry in self.entries:
            if self._is_suspicious_ip(entry.host):
                suspicious_activities.append(entry)
        
        self.analysis_results['suspicious_ip_activity'] = {
            'total': len(suspicious_activities),
            'details': suspicious_activities[:50]
        }
    
    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP is suspicious"""
        for suspicious_ip in self.config.suspicious_ips:
            if suspicious_ip.strip():
                if '/' in suspicious_ip:
                    # CIDR format check (simplified)
                    network = suspicious_ip.split('/')[0]
                    if ip.startswith(network.rsplit('.', 1)[0]):
                        return True
                else:
                    # Exact match
                    if ip == suspicious_ip.strip():
                        return True
        return False
    
    def _analyze_privileged_operations(self):
        """Analyze privileged operations"""
        privileged_ops = [entry for entry in self.entries if entry.is_privileged_operation()]
        
        # Count by user
        ops_by_user = Counter(entry.username for entry in privileged_ops)
        
        self.analysis_results['privileged_operations'] = {
            'total': len(privileged_ops),
            'by_user': dict(ops_by_user.most_common(10)),
            'details': privileged_ops[:50]
        }
    
    def _analyze_operation_stats(self):
        """Analyze operation statistics"""
        operation_counts = Counter(entry.operation for entry in self.entries)
        
        self.analysis_results['operation_stats'] = dict(operation_counts.most_common())
    
    def _analyze_error_codes(self):
        """Analyze error codes"""
        error_entries = [entry for entry in self.entries if entry.retcode != 0]
        error_codes = Counter(entry.retcode for entry in error_entries)
        
        self.analysis_results['error_analysis'] = {
            'total_errors': len(error_entries),
            'error_codes': dict(error_codes.most_common()),
            'details': error_entries[:50]
        }

    def _analyze_after_hours_access(self):
        """分析特定帳號在非上班時段的存取紀錄（週六日整天皆算非上班時段）"""
        after_hours_users = getattr(self.config, 'after_hours_users', [])
        work_hour_start = getattr(self.config, 'work_hour_start', 9)
        work_hour_end = getattr(self.config, 'work_hour_end', 18)

        after_hours_access = []
        for entry in self.entries:
            if entry.username in after_hours_users:
                dt = entry.get_datetime()
                if dt:
                    # 週六(5)、週日(6)整天都算非上班時段
                    if dt.weekday() >= 5:
                        after_hours_access.append(entry)
                    elif not (work_hour_start <= dt.hour < work_hour_end):
                        after_hours_access.append(entry)
        self.analysis_results['after_hours_access'] = {
            'total': len(after_hours_access),
            'details': after_hours_access[:50]
        }

    def _analyze_privileged_user_logins(self):
        """分析特權帳號登入（CONNECT）行為"""
        privileged_users = getattr(self.config, 'privileged_users', [])
        privileged_users = [u.strip() for u in privileged_users if u.strip()]
        privileged_login_entries = [
            entry for entry in self.entries
            if entry.operation == 'CONNECT' and entry.username in privileged_users
        ]
        logins_by_user = Counter(entry.username for entry in privileged_login_entries)
        self.analysis_results['privileged_user_logins'] = {
            'total': len(privileged_login_entries),
            'by_user': dict(logins_by_user.most_common()),
            'details': privileged_login_entries[:50]
        }

class ReportGenerator:
    """Report generator"""
    def __init__(self, config: Config, analysis_results: dict):
        self.config = config
        self.analysis_results = analysis_results
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    def generate_csv_report(self, output_dir: str) -> str:
        """Generate CSV report"""
        os.makedirs(output_dir, exist_ok=True)
        
        csv_file = os.path.join(output_dir, f'mysql_audit_analysis_{self.timestamp}.csv')
        
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Title
            writer.writerow([f'{self.config.report_title} - {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'])
            writer.writerow([])
            
            # Basic statistics
            writer.writerow(['=== Basic Statistics ==='])
            writer.writerow(['Total Events', self.analysis_results.get('total_events', 0)])
            writer.writerow(['Unique Users', self.analysis_results.get('unique_users', 0)])
            writer.writerow(['Unique Hosts', self.analysis_results.get('unique_hosts', 0)])
            writer.writerow([])
            
            # Failed login analysis
            failed_logins = self.analysis_results.get('failed_logins', {})
            writer.writerow(['=== Failed Login Analysis ==='])
            writer.writerow(['Total Failed Logins', failed_logins.get('total', 0)])
            writer.writerow([])
            
            if failed_logins.get('suspicious_users'):
                writer.writerow(['Suspicious Users (Above Threshold)'])
                writer.writerow(['Username', 'Failed Count'])
                for user, count in failed_logins['suspicious_users'].items():
                    writer.writerow([user, count])
                writer.writerow([])
            
            if failed_logins.get('suspicious_ips'):
                writer.writerow(['Suspicious IPs (Above Threshold)'])
                writer.writerow(['IP Address', 'Failed Count'])
                for ip, count in failed_logins['suspicious_ips'].items():
                    writer.writerow([ip, count])
                writer.writerow([])
            
            # Privileged operations analysis
            privileged_ops = self.analysis_results.get('privileged_operations', {})
            writer.writerow(['=== Privileged Operations Analysis ==='])
            writer.writerow(['Total Privileged Operations', privileged_ops.get('total', 0)])
            writer.writerow([])
            
            if privileged_ops.get('by_user'):
                writer.writerow(['By User Statistics'])
                writer.writerow(['Username', 'Operation Count'])
                for user, count in privileged_ops['by_user'].items():
                    writer.writerow([user, count])
                writer.writerow([])
            
            # Privileged user login analysis
            priv_user_logins = self.analysis_results.get('privileged_user_logins', {})
            writer.writerow(['=== Privileged Account Login Analysis ==='])
            writer.writerow(['Total Privileged Account Logins', priv_user_logins.get('total', 0)])
            if priv_user_logins.get('by_user'):
                writer.writerow(['Username', 'Login Count'])
                for user, count in priv_user_logins['by_user'].items():
                    writer.writerow([user, count])
            writer.writerow([])

            # --- 新增詳細登入行為 ---
            if priv_user_logins.get('details'):
                writer.writerow(['Detailed Privileged Account Login Records'])
                writer.writerow(['Username', 'Host', 'Timestamp'])
                for entry in priv_user_logins['details']:
                    dt = entry.get_datetime()
                    writer.writerow([
                        entry.username,
                        entry.host,
                        dt.strftime('%Y-%m-%d %H:%M:%S') if dt else entry.timestamp
                    ])
                writer.writerow([])
            # --- end ---

            # Operation statistics
            writer.writerow(['=== Operation Type Statistics ==='])
            writer.writerow(['Operation Type', 'Count'])
            for operation, count in self.analysis_results.get('operation_stats', {}).items():
                writer.writerow([operation, count])
            writer.writerow([])
            
            # Error analysis
            error_analysis = self.analysis_results.get('error_analysis', {})
            writer.writerow(['=== Error Analysis ==='])
            writer.writerow(['Total Errors', error_analysis.get('total_errors', 0)])
            writer.writerow([])
            
            if error_analysis.get('error_codes'):
                writer.writerow(['Error Code Statistics'])
                writer.writerow(['Error Code', 'Count'])
                for code, count in error_analysis['error_codes'].items():
                    writer.writerow([code, count])
            writer.writerow([])

            # After-hours access
            after_hours = self.analysis_results.get('after_hours_access', {})
            writer.writerow(['=== After-hours Access (Specify account) ==='])
            writer.writerow(['Total After-hours Access', after_hours.get('total', 0)])
            if after_hours.get('details'):
                writer.writerow(['Username', 'Host', 'Operation', 'Time'])
                for entry in after_hours['details']:
                    dt = entry.get_datetime()
                    writer.writerow([entry.username, entry.host, entry.operation, dt.strftime('%Y-%m-%d %H:%M:%S') if dt else entry.timestamp])
            writer.writerow([])
        
        print(f"✅ CSV report generated: {csv_file}")
        return csv_file
    
    def generate_pdf_report(self, output_dir: str) -> str:
        """Generate PDF report"""
        if not REPORTLAB_AVAILABLE:
            print("❌ ReportLab not installed, cannot generate PDF report")
            print("Please run: pip install reportlab")
            return None
        
        os.makedirs(output_dir, exist_ok=True)
        
        pdf_file = os.path.join(output_dir, f'mysql_audit_analysis_{self.timestamp}.pdf')
        
        doc = SimpleDocTemplate(pdf_file, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=16,
            spaceAfter=30,
            alignment=1  # Center
        )
        
        story.append(Paragraph(self.config.report_title, title_style))
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Basic statistics
        story.append(Paragraph("Basic Statistics", styles['Heading2']))
        basic_stats = [
            ['Total Events', str(self.analysis_results.get('total_events', 0))],
            ['Unique Users', str(self.analysis_results.get('unique_users', 0))],
            ['Unique Hosts', str(self.analysis_results.get('unique_hosts', 0))]
        ]
        
        table = Table(basic_stats)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(table)
        story.append(Spacer(1, 20))
        
        # Security warnings
        story.append(Paragraph("Security Warnings", styles['Heading2']))
        
        failed_logins = self.analysis_results.get('failed_logins', {})
        if failed_logins.get('suspicious_users') or failed_logins.get('suspicious_ips'):
            if failed_logins.get('suspicious_users'):
                story.append(Paragraph("⚠️ Suspicious user activity detected:", styles['Normal']))
                for user, count in failed_logins['suspicious_users'].items():
                    story.append(Paragraph(f"• {user}: {count} failed logins", styles['Normal']))
                story.append(Spacer(1, 10))
            
            if failed_logins.get('suspicious_ips'):
                story.append(Paragraph("⚠️ Suspicious IP activity detected:", styles['Normal']))
                for ip, count in failed_logins['suspicious_ips'].items():
                    story.append(Paragraph(f"• {ip}: {count} failed logins", styles['Normal']))
        else:
            story.append(Paragraph("✅ No obvious security threats detected", styles['Normal']))
        
        story.append(Spacer(1, 20))
        
        # Operation statistics
        story.append(Paragraph("Operation Type Statistics", styles['Heading2']))
        operation_data = [['Operation Type', 'Count']]
        for operation, count in list(self.analysis_results.get('operation_stats', {}).items())[:10]:
            operation_data.append([operation, str(count)])
        
        if len(operation_data) > 1:
            table = Table(operation_data)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(table)
        story.append(Spacer(1, 20))

        # Privileged user login analysis
        story.append(Paragraph("Privileged Account Login Analysis", styles['Heading2']))
        priv_user_logins = self.analysis_results.get('privileged_user_logins', {})
        story.append(Paragraph(f"Total privileged account logins: {priv_user_logins.get('total', 0)}", styles['Normal']))
        if priv_user_logins.get('by_user'):
            data = [['Username', 'Login Count']]
            for user, count in priv_user_logins['by_user'].items():
                data.append([user, str(count)])
            table = Table(data)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(table)
        story.append(Spacer(1, 20))

        # --- 新增詳細登入行為 ---
        if priv_user_logins.get('details'):
            story.append(Paragraph("Detailed Privileged Account Login Records (Top 50)", styles['Heading3']))
            data = [['Username', 'Host', 'Timestamp']]
            for entry in priv_user_logins['details']:
                dt = entry.get_datetime()
                data.append([
                    entry.username,
                    entry.host,
                    dt.strftime('%Y-%m-%d %H:%M:%S') if dt else entry.timestamp
                ])
            table = Table(data)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(table)
            story.append(Spacer(1, 20))
        # --- end ---

        # After-hours access
        story.append(Paragraph("After-hours Access (Specify account)", styles['Heading2']))
        after_hours = self.analysis_results.get('after_hours_access', {})
        story.append(Paragraph(f"Total after-hours access: {after_hours.get('total', 0)}", styles['Normal']))
        if after_hours.get('details'):
            data = [['Username', 'Host', 'Operation', 'Time']]
            for entry in after_hours['details']:
                dt = entry.get_datetime()
                data.append([
                    entry.username, entry.host, entry.operation,
                    dt.strftime('%Y-%m-%d %H:%M:%S') if dt else entry.timestamp
                ])
            table = Table(data)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(table)
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

    # 加入 PDF 附件
    with open(attachment_path, 'rb') as f:
        file_data = f.read()
        file_name = os.path.basename(attachment_path)
        msg.add_attachment(file_data, maintype='application', subtype='pdf', filename=file_name)

    try:
        # 直接連線 SMTP，不啟用 TLS、不登入
        with smtplib.SMTP(getattr(config, 'smtp_host', ''), getattr(config, 'smtp_port', 25)) as smtp:
            smtp.send_message(msg)
        print(f"✅ 郵件已發送至 {getattr(config, 'mail_to', [])}")
        return True
    except Exception as e:
        print(f"❌ 發送郵件失敗: {e}")
        return False

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='MySQL Audit Log Security Analyzer')
    parser.add_argument('--date', help='Analyze logs for specific date (format: YYYY-MM-DD, default: today)')
    parser.add_argument('--output-dir', help='Output directory')
    parser.add_argument('--csv-only', action='store_true', help='Generate CSV report only')
    parser.add_argument('--pdf-only', action='store_true', help='Generate PDF report only')
    parser.add_argument('--show-config', action='store_true', help='Show current configuration')
    parser.add_argument('--env-file', help='Specify environment file path')
    
    args = parser.parse_args()
    
    # Load configuration
    config = Config(args.env_file)
    
    if args.show_config:
        config.show_config()
        return
    
    # 決定分析日期（預設為今天）
    if args.date:
        try:
            analysis_date = datetime.strptime(args.date, '%Y-%m-%d')
            date_str = analysis_date.strftime('%Y-%m-%d')
        except ValueError:
            print("❌ Invalid date format, please use YYYY-MM-DD format")
            return
    else:
        analysis_date = datetime.now()
        date_str = analysis_date.strftime('%Y-%m-%d')
    
    print(f"📅 Analysis date: {date_str}")
    
    # 不論今天或歷史，**都用 date_str 當尾碼**
    log_file_path = config.get_log_file_path(date_str)
    
    # Initialize analyzer
    analyzer = SecurityAnalyzer(config)
    
    # Load and analyze logs
    if not analyzer.load_log_file(log_file_path):
        return
    
    analyzer.analyze()
    
    # Determine output directory
    output_dir = args.output_dir or config.output_dir
    
    # Generate reports（依照 env 設定與參數決定）
    report_generator = ReportGenerator(config, analyzer.analysis_results)
    generated_files = []

    # 決定是否產生 CSV/PDF
    generate_csv = config.generate_csv if not args.pdf_only else False
    generate_pdf = config.generate_pdf if not args.csv_only else False

    if generate_csv:
        csv_file = report_generator.generate_csv_report(output_dir)
        if csv_file:
            generated_files.append(csv_file)

    if generate_pdf:
        pdf_file = report_generator.generate_pdf_report(output_dir)
        if pdf_file:
            generated_files.append(pdf_file)
            if config.send_email:
                send_email_with_attachment(config, pdf_file)
            else:
                print("✉️  SEND_EMAIL 設定為 false，未寄出郵件")
    
    # Display result summary
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
