#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MySQL 審計日誌 PDF 報表生成器
每日自動分析 MySQL 審計日誌並生成 PDF 報表

版本: 1.0.0
日期: 2024-05-27
"""

import os
import re
import logging
import sys
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from pathlib import Path
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from dotenv import load_dotenv


class ConfigManager:
    """配置管理器，支援 .env 檔案和環境變數"""
    
    def __init__(self, env_file=".env"):
        self.env_file = env_file
        self.config = {}
        self.load_config()
    
    def load_config(self):
        """載入配置"""
        # 1. 載入 .env 檔案 (如果存在且有 dotenv)
        load_dotenv(self.env_file)

        
        # 2. 設定預設值並從環境變數讀取
        defaults = {
            'LOG_DIR': '/var/log/mysql/audit',
            'OUTPUT_DIR': '/tmp/mysql_reports',
            'LOG_LEVEL': 'INFO',
            'LOG_FILE': '/var/log/mysql/audit/mysql_audit_analyzer.log',
            'PDF_FONT_SIZE': '10',
            'PDF_TITLE_FONT_SIZE': '18',
            'PDF_HEADING_FONT_SIZE': '14',
            'MAX_ERROR_EVENTS': '50',
            'MAX_FAILED_LOGINS': '50',
            'TOP_USERS_COUNT': '10',
            'TOP_OPERATIONS_COUNT': '10',
            'CUSTOM_FONT_PATH': '',
            'DATE_FORMAT': '%Y-%m-%d',
            'TIMESTAMP_FORMAT': '%Y%m%d %H:%M:%S',
            'LOG_DELIMITER': ',',
            'MIN_LOG_FIELDS': '8',
            'REPORT_TITLE': 'MySQL Audit ReportV1',
            'COMPANY_NAME': ''
        }
        
        for key, default_value in defaults.items():
            self.config[key] = os.getenv(key, default_value)
        
        # 3. 類型轉換
        self._convert_types()
    
    def _convert_types(self):
        """轉換配置值的類型"""
        int_keys = [
            'PDF_FONT_SIZE', 'PDF_TITLE_FONT_SIZE', 'PDF_HEADING_FONT_SIZE',
            'MAX_ERROR_EVENTS', 'MAX_FAILED_LOGINS', 'TOP_USERS_COUNT',
            'TOP_OPERATIONS_COUNT', 'MIN_LOG_FIELDS'
        ]
        
        for key in int_keys:
            try:
                self.config[key] = int(self.config[key])
            except (ValueError, TypeError):
                print(f"警告: {key} 值無效，使用預設值")
                # 保持原始字串值，讓程式使用預設值
    
    def get(self, key, default=None):
        """取得配置值"""
        return self.config.get(key, default)
    
    def get_int(self, key, default=0):
        """取得整數配置值"""
        try:
            return int(self.config.get(key, default))
        except (ValueError, TypeError):
            return default
    
    def get_bool(self, key, default=False):
        """取得布林配置值"""
        value = self.config.get(key, str(default)).lower()
        return value in ('true', '1', 'yes', 'on')
    
    def print_config(self):
        """印出當前配置"""
        print("\n📋 當前配置:")
        print("-" * 50)
        for key, value in sorted(self.config.items()):
            print(f"{key:20} = {value}")
        print("-" * 50)

class MySQLAuditAnalyzer:
    def __init__(self, config_file=".env"):
        self.config = ConfigManager(config_file)
        self.setup_logging()
        self.setup_directories()
        self.setup_fonts()
        
    def setup_logging(self):
        """設定日誌記錄"""
        log_level = getattr(logging, self.config.get('LOG_LEVEL', 'INFO').upper())
        log_file = self.config.get('LOG_FILE')
        
        # 確保日誌目錄存在
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
        self.logger.info("MySQL 審計分析器已啟動")
        
    def setup_directories(self):
        """確保輸出目錄存在"""
        output_dir = self.config.get('OUTPUT_DIR')
        if not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
            self.logger.info(f"已創建輸出目錄: {output_dir}")
            
    def setup_fonts(self):
        """設定中文字體支援"""
        try:
            # 優先使用配置中的字體路徑
            custom_font = self.config.get('CUSTOM_FONT_PATH')
            if custom_font and os.path.exists(custom_font):
                try:
                    pdfmetrics.registerFont(TTFont('CustomFont', custom_font))
                    self.font_name = 'CustomFont'
                    self.logger.info(f"已註冊自定義字體: {custom_font}")
                    return
                except Exception as e:
                    self.logger.warning(f"無法註冊自定義字體 {custom_font}: {e}")
            
            # 嘗試使用系統中的中文字體
            font_paths = [
                '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
                '/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf',
                '/System/Library/Fonts/Arial.ttf',  # macOS
                'C:\\Windows\\Fonts\\arial.ttf',  # Windows
                '/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc',  # 中文字體
            ]
            
            font_registered = False
            for font_path in font_paths:
                if os.path.exists(font_path):
                    try:
                        pdfmetrics.registerFont(TTFont('CustomFont', font_path))
                        self.font_name = 'CustomFont'
                        font_registered = True
                        self.logger.info(f"已註冊字體: {font_path}")
                        break
                    except Exception as e:
                        self.logger.warning(f"無法註冊字體 {font_path}: {e}")
                        continue
            
            if not font_registered:
                self.font_name = 'Helvetica'
                self.logger.warning("使用預設字體 Helvetica")
                
        except Exception as e:
            self.logger.error(f"字體設定錯誤: {e}")
            self.font_name = 'Helvetica'
    
    def get_log_file(self, target_date=None):
        """取得指定日期的日誌檔案路徑"""
        log_dir = self.config.get('LOG_DIR')
        
        if target_date:
            if isinstance(target_date, str):
                try:
                    date_obj = datetime.strptime(target_date, self.config.get('DATE_FORMAT'))
                except ValueError:
                    self.logger.error(f"日期格式錯誤: {target_date}")
                    raise
            else:
                date_obj = target_date
        else:
            date_obj = datetime.now() - timedelta(days=1)
        
        date_str = date_obj.strftime(self.config.get('DATE_FORMAT'))
        log_file = os.path.join(log_dir, f"server_audit.log-{date_str}")
        
        if not os.path.exists(log_file):
            self.logger.warning(f"找不到指定日期的日誌檔案: {log_file}")
            # 嘗試當前日誌檔案
            current_log = os.path.join(log_dir, "server_audit.log")
            if os.path.exists(current_log):
                self.logger.info(f"使用當前日誌檔案: {current_log}")
                return current_log
            else:
                raise FileNotFoundError(f"找不到日誌檔案: {log_file}")
        
        return log_file
    
    def parse_audit_log_line(self, line):
        """解析審計日誌行"""
        try:
            delimiter = self.config.get('LOG_DELIMITER')
            min_fields = self.config.get_int('MIN_LOG_FIELDS')
            
            parts = line.strip().split(delimiter)
            
            if len(parts) < min_fields:
                return None
                
            return {
                'timestamp': parts[0],
                'server': parts[1],
                'username': parts[2],
                'host': parts[3],
                'connection_id': parts[4],
                'query_id': parts[5],
                'operation': parts[6],
                'database': parts[7] if len(parts) > 7 else '',
                'query': parts[8] if len(parts) > 8 else '',
                'retcode': parts[9] if len(parts) > 9 else '0'
            }
        except Exception as e:
            self.logger.warning(f"無法解析日誌行: {line[:100]}... 錯誤: {e}")
            return None
    
    def analyze_log_file(self, log_file):
        """分析日誌檔案"""
        self.logger.info(f"開始分析日誌檔案: {log_file}")
        
        stats = {
            'total_events': 0,
            'users': set(),
            'hosts': set(),
            'databases': set(),
            'operations': Counter(),
            'errors': [],
            'failed_logins': [],
            'user_activity': Counter(),
            'hourly_activity': Counter(),
            'analysis_date': datetime.now().strftime(self.config.get('DATE_FORMAT'))
        }
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    if not line.strip():
                        continue
                        
                    record = self.parse_audit_log_line(line)
                    if not record:
                        continue
                    
                    stats['total_events'] += 1
                    stats['users'].add(record['username'])
                    stats['hosts'].add(record['host'])
                    
                    if record['database']:
                        stats['databases'].add(record['database'])
                    
                    stats['operations'][record['operation']] += 1
                    stats['user_activity'][record['username']] += 1
                    
                    # 提取小時資訊
                    try:
                        if len(record['timestamp']) >= 11:
                            hour = record['timestamp'][9:11]
                            stats['hourly_activity'][hour] += 1
                    except:
                        pass
                    
                    # 檢查錯誤事件
                    if record['retcode'] != '0' and record['retcode']:
                        if len(stats['errors']) < self.config.get_int('MAX_ERROR_EVENTS'):
                            stats['errors'].append({
                                'timestamp': record['timestamp'],
                                'username': record['username'],
                                'host': record['host'],
                                'operation': record['operation'],
                                'retcode': record['retcode'],
                                'query': record['query'][:100] if record['query'] else ''
                            })
                    
                    # 檢查失敗登入
                    if record['operation'] == 'FAILED_CONNECT':
                        if len(stats['failed_logins']) < self.config.get_int('MAX_FAILED_LOGINS'):
                            stats['failed_logins'].append({
                                'timestamp': record['timestamp'],
                                'username': record['username'],
                                'host': record['host']
                            })
                        
        except Exception as e:
            self.logger.error(f"讀取日誌檔案錯誤: {e}")
            raise
        
        self.logger.info(f"分析完成: 總事件數 {stats['total_events']}")
        return stats
    
    def create_pdf_report(self, stats, output_file):
        """生成 PDF 報表"""
        self.logger.info(f"開始生成 PDF 報表: {output_file}")
        
        # 建立 PDF 文件
        doc = SimpleDocTemplate(
            output_file,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )
        
        # 建立樣式
        styles = getSampleStyleSheet()
        
        # 從配置讀取字體大小
        title_font_size = self.config.get_int('PDF_TITLE_FONT_SIZE', 18)
        heading_font_size = self.config.get_int('PDF_HEADING_FONT_SIZE', 14)
        normal_font_size = self.config.get_int('PDF_FONT_SIZE', 10)
        
        # 標題樣式
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontName=self.font_name,
            fontSize=title_font_size,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.darkblue
        )
        
        # 副標題樣式
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontName=self.font_name,
            fontSize=heading_font_size,
            spaceAfter=12,
            textColor=colors.darkgreen
        )
        
        # 內容樣式
        normal_style = ParagraphStyle(
            'CustomNormal',
            parent=styles['Normal'],
            fontName=self.font_name,
            fontSize=normal_font_size
        )
        
        # 建立內容
        story = []
        
        # 標題
        report_title = self.config.get('REPORT_TITLE', 'MySQL Audit Report')
        company_name = self.config.get('COMPANY_NAME', '')
        
        if company_name:
            story.append(Paragraph(company_name, normal_style))
            story.append(Spacer(1, 10))
        
        title_text = f"{report_title} - {stats['analysis_date']}"
        story.append(Paragraph(title_text, title_style))
        story.append(Spacer(1, 20))
        
        # 總覽統計
        story.append(Paragraph("Overview Statistics", heading_style))
        overview_data = [
            ['Metric', 'Value'],
            ['Total Events', str(stats['total_events'])],
            ['Active Users', str(len(stats['users']))],
            ['Connected Hosts', str(len(stats['hosts']))],
            ['Databases Used', str(len(stats['databases']))],
            ['Error Events', str(len(stats['errors']))],
            ['Failed Logins', str(len(stats['failed_logins']))]
        ]
        
        overview_table = Table(overview_data, colWidths=[3*inch, 2*inch])
        overview_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), self.font_name),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('FONTNAME', (0, 1), (-1, -1), self.font_name),
            ('FONTSIZE', (0, 1), (-1, -1), normal_font_size),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(overview_table)
        story.append(Spacer(1, 20))
        
        # Top 活躍用戶
        top_users_count = self.config.get_int('TOP_USERS_COUNT', 10)
        story.append(Paragraph(f"Top {top_users_count} Active Users", heading_style))
        user_data = [['Username', 'Activity Count']]
        for user, count in stats['user_activity'].most_common(top_users_count):
            user_data.append([str(user), str(count)])
        
        user_table = Table(user_data, colWidths=[3*inch, 2*inch])
        user_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.darkblue),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, -1), self.font_name),
            ('FONTSIZE', (0, 0), (-1, -1), normal_font_size),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightcyan),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(user_table)
        story.append(Spacer(1, 20))
        
        # Top 操作類型
        top_ops_count = self.config.get_int('TOP_OPERATIONS_COUNT', 10)
        story.append(Paragraph(f"Top {top_ops_count} Operations", heading_style))
        op_data = [['Operation Type', 'Count']]
        for operation, count in stats['operations'].most_common(top_ops_count):
            op_data.append([str(operation), str(count)])
        
        op_table = Table(op_data, colWidths=[3*inch, 2*inch])
        op_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgreen),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.darkgreen),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, -1), self.font_name),
            ('FONTSIZE', (0, 0), (-1, -1), normal_font_size),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.honeydew),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(op_table)
        story.append(Spacer(1, 20))
        
        # 錯誤事件
        if stats['errors']:
            story.append(Paragraph("Error Events", heading_style))
            error_data = [['Time', 'User', 'Host', 'Operation', 'Error Code']]
            for error in stats['errors']:
                error_data.append([
                    str(error['timestamp']),
                    str(error['username']),
                    str(error['host']),
                    str(error['operation']),
                    str(error['retcode'])
                ])
            
            error_table = Table(error_data, colWidths=[1.5*inch, 1*inch, 1.5*inch, 1*inch, 1*inch])
            error_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.red),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, -1), self.font_name),
                ('FONTSIZE', (0, 0), (-1, -1), normal_font_size-1),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.mistyrose),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(error_table)
            story.append(Spacer(1, 20))
        
        # 失敗登入事件
        if stats['failed_logins']:
            story.append(Paragraph("Failed Login Events", heading_style))
            login_data = [['Time', 'Username', 'Source Host']]
            for login in stats['failed_logins']:
                login_data.append([
                    str(login['timestamp']),
                    str(login['username']),
                    str(login['host'])
                ])
            
            login_table = Table(login_data, colWidths=[2*inch, 1.5*inch, 2.5*inch])
            login_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.orange),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, -1), self.font_name),
                ('FONTSIZE', (0, 0), (-1, -1), normal_font_size),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.papayawhip),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(login_table)
        
        # 生成 PDF
        try:
            doc.build(story)
            self.logger.info(f"PDF 報表生成成功: {output_file}")
        except Exception as e:
            self.logger.error(f"PDF 生成錯誤: {e}")
            raise
    
    def generate_report(self, target_date=None):
        """生成報表主函數"""
        try:
            # 取得日誌檔案
            log_file = self.get_log_file(target_date)
            
            # 分析日誌
            stats = self.analyze_log_file(log_file)
            
            # 生成 PDF 檔案名稱
            if target_date:
                if isinstance(target_date, str):
                    date_str = target_date
                else:
                    date_str = target_date.strftime(self.config.get('DATE_FORMAT'))
            else:
                yesterday = datetime.now() - timedelta(days=1)
                date_str = yesterday.strftime(self.config.get('DATE_FORMAT'))
            
            output_dir = self.config.get('OUTPUT_DIR')
            output_file = os.path.join(output_dir, f"mysql_audit_report_{date_str}.pdf")
            
            # 生成 PDF 報表
            self.create_pdf_report(stats, output_file)
            
            self.logger.info(f"報表生成完成: {output_file}")
            return output_file
            
        except Exception as e:
            self.logger.error(f"報表生成失敗: {e}")
            raise

def main():
    """主函數"""
    import argparse
    
    parser = argparse.ArgumentParser(description='MySQL 審計日誌分析器')
    parser.add_argument('--config', '-c', default='.env', 
                       help='配置檔案路徑 (預設: .env)')
    parser.add_argument('--date', '-d', 
                       help='分析指定日期的日誌 (格式: YYYY-MM-DD)')
    parser.add_argument('--show-config', action='store_true',
                       help='顯示當前配置')
    
    args = parser.parse_args()
    
    try:
        analyzer = MySQLAuditAnalyzer(args.config)
        
        if args.show_config:
            analyzer.config.print_config()
            return 0
        
        report_file = analyzer.generate_report(args.date)
        print(f"✅ MySQL 審計報表已生成: {report_file}")
        
    except Exception as e:
        print(f"❌ 錯誤: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
