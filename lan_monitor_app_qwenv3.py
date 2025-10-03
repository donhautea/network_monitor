import streamlit as st
import pandas as pd
import subprocess
import re
import time
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go
import requests
import ipaddress
import socket
import psutil
from collections import defaultdict
import sqlite3
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import schedule
import threading
import toml
import io
import base64
import warnings
import os
import signal

# Critical ports that are commonly targeted by attackers
CRITICAL_PORTS = {
    # Remote Access & Administration
    21: "FTP (File Transfer Protocol)",
    22: "SSH (Secure Shell)",
    23: "Telnet",
    25: "SMTP (Simple Mail Transfer)",
    53: "DNS",
    80: "HTTP (Web Server)",
    110: "POP3 (Post Office Protocol)",
    135: "RPC Endpoint Mapper",
    139: "NetBIOS Session Service",
    143: "IMAP (Internet Message Access)",
    443: "HTTPS (Secure Web)",
    445: "SMB (Server Message Block)",
    993: "IMAPS (Secure IMAP)",
    995: "POP3S (Secure POP3)",
    
    # Database & Application Services
    1433: "Microsoft SQL Server",
    1521: "Oracle Database",
    3306: "MySQL Database",
    3389: "RDP (Remote Desktop)",
    5432: "PostgreSQL",
    5900: "VNC (Virtual Network Computing)",
    6379: "Redis",
    8080: "HTTP Alternate",
    8443: "HTTPS Alternate",
    9200: "Elasticsearch",
    9300: "Elasticsearch Transport",
    27017: "MongoDB",
    
    # Vulnerable/High-Risk Services
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram Service",
    161: "SNMP",
    389: "LDAP",
    512: "rexec",
    513: "rlogin",
    514: "rsh",
    636: "LDAPS",
    1080: "SOCKS Proxy",
    1723: "PPTP VPN",
    5060: "SIP (VoIP)",
    5901: "VNC Display 1",
    5902: "VNC Display 2",
    
    # Legacy/Deprecated Services
    20: "FTP Data",
    69: "TFTP",
    111: "RPCbind",
    119: "NNTP",
    162: "SNMP Trap",
    515: "LPD (Line Printer Daemon)",
    548: "AFP (Apple Filing Protocol)",
    631: "IPP (Internet Printing)",
    993: "IMAPS",
    995: "POP3S"
}

# High-risk port ranges
HIGH_RISK_PORT_RANGES = [
    (1, 1024),      # Well-known ports
    (3300, 3400),   # Database ports
    (5000, 5100),   # Development/Testing ports
    (8000, 8100),   # Development web servers
    (9000, 9100),   # Development services
    (10000, 10100)  # Webmin and other admin tools
]

# Initialize session state
if 'devices' not in st.session_state:
    st.session_state.devices = pd.DataFrame(columns=[
        'IP', 'MAC', 'Vendor', 'First Seen', 'Last Seen', 
        'Is External', 'Hostname', 'Location', 'ISP'
    ])
if 'alerts' not in st.session_state:
    st.session_state.alerts = []
if 'connections' not in st.session_state:
    st.session_state.connections = pd.DataFrame(columns=[
        'Local IP', 'Local Port', 'Remote IP', 'Remote Port', 
        'Status', 'PID', 'Process', 'Timestamp'
    ])
if 'suspicious_activity' not in st.session_state:
    st.session_state.suspicious_activity = []
if 'last_scan' not in st.session_state:
    st.session_state.last_scan = datetime.now()
if 'last_traffic_scan' not in st.session_state:
    st.session_state.last_traffic_scan = datetime.now()
if 'port_scan_tracker' not in st.session_state:
    st.session_state.port_scan_tracker = defaultdict(list)
if 'email_job' not in st.session_state:
    st.session_state.email_job = None
if 'auto_terminate_enabled' not in st.session_state:
    st.session_state.auto_terminate_enabled = False
if 'terminate_threshold' not in st.session_state:
    st.session_state.terminate_threshold = 3  # Number of high-risk connections before auto-terminate

st.set_page_config(page_title="Network Monitor", layout="wide")
st.title("🔍 Advanced Network Activity Monitor")

# Sidebar configuration
st.sidebar.header("⚙️ Configuration")
scan_interval = st.sidebar.slider("Network Scan Interval (seconds)", 5, 60, 15)
traffic_scan_interval = st.sidebar.slider("Traffic Scan Interval (seconds)", 2, 30, 5)
suspicious_port_threshold = st.sidebar.number_input("Port Scan Threshold (ports/min)", 10, 100, 30)
high_risk_port_threshold = st.sidebar.number_input("High-Risk Port Threshold", 5, 50, 15)

# Auto-terminate configuration
st.sidebar.header("🛡️ Auto-Terminate")
st.session_state.auto_terminate_enabled = st.sidebar.checkbox("Enable Auto-Terminate Suspicious Apps", value=st.session_state.auto_terminate_enabled)
st.session_state.terminate_threshold = st.sidebar.number_input("Terminate Threshold", 1, 10, st.session_state.terminate_threshold, 
                                                              help="Number of high-risk connections before auto-termination")

# Email configuration
st.sidebar.header("📧 Email Reporting")
email_interval = st.sidebar.selectbox(
    "Report Frequency", 
    ["Disabled", "Hourly", "Daily", "Weekly"]
)
email_time = st.sidebar.time_input("Report Time", datetime.now().time())

# Function to get existing table columns
def get_table_columns(table_name):
    try:
        conn = sqlite3.connect('network_monitor.db', timeout=20.0)
        cursor = conn.cursor()
        cursor.execute(f"PRAGMA table_info({table_name})")
        columns = [row[1] for row in cursor.fetchall()]
        conn.close()
        return columns
    except Exception as e:
        st.error(f"Error getting table columns: {str(e)}")
        return []

# Function to add column if it doesn't exist
def add_column_if_not_exists(table_name, column_name, column_type, default_value=None):
    try:
        conn = sqlite3.connect('network_monitor.db', timeout=20.0)
        cursor = conn.cursor()
        
        # Check if column exists
        cursor.execute(f"PRAGMA table_info({table_name})")
        columns = [row[1] for row in cursor.fetchall()]
        
        if column_name not in columns:
            # Add column
            if default_value is not None:
                cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type} DEFAULT '{default_value}'")
            else:
                cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")
            conn.commit()
        
        conn.close()
        return True
    except Exception as e:
        st.error(f"Error adding column {column_name} to {table_name}: {str(e)}")
        return False

# Database setup with proper schema migration
def init_database():
    conn = sqlite3.connect('network_monitor.db', timeout=20.0)
    cursor = conn.cursor()
    
    # Create devices table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            mac TEXT,
            vendor TEXT,
            first_seen TEXT,
            last_seen TEXT,
            is_external INTEGER,
            hostname TEXT,
            location TEXT,
            isp TEXT
        )
    ''')
    
    # Create connections table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            local_ip TEXT,
            local_port INTEGER,
            remote_ip TEXT,
            remote_port INTEGER,
            status TEXT,
            pid INTEGER,
            process TEXT,
            timestamp TEXT
        )
    ''')
    
    # Create alerts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            alert_type TEXT,
            message TEXT
        )
    ''')
    
    # Create port scan tracking table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS port_scan_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            port INTEGER,
            timestamp TEXT,
            count INTEGER DEFAULT 1
        )
    ''')
    
    # Create terminated processes table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS terminated_processes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            process_name TEXT,
            pid INTEGER,
            reason TEXT
        )
    ''')
    
    conn.commit()
    conn.close()
    
    # Schema migration - add new columns if they don't exist
    # For connections table
    add_column_if_not_exists('connections', 'is_suspicious', 'INTEGER', 0)
    add_column_if_not_exists('connections', 'risk_level', 'TEXT', 'Low')
    
    # For alerts table
    add_column_if_not_exists('alerts', 'severity', 'TEXT', 'Medium')

# Initialize database
init_database()

# Database operations with retry logic
def execute_db_operation(query, params=None, fetch=False):
    max_retries = 5
    for attempt in range(max_retries):
        try:
            conn = sqlite3.connect('network_monitor.db', timeout=20.0)
            cursor = conn.cursor()
            
            if params:
                if fetch:
                    result = cursor.execute(query, params).fetchall()
                else:
                    cursor.execute(query, params)
            else:
                if fetch:
                    result = cursor.execute(query).fetchall()
                else:
                    cursor.execute(query)
            
            if not fetch:
                conn.commit()
            conn.close()
            
            if fetch:
                return result
            return True
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e) and attempt < max_retries - 1:
                time.sleep(0.1 * (attempt + 1))  # Exponential backoff
                continue
            else:
                st.error(f"Database error: {str(e)}")
                if not fetch:
                    try:
                        conn.close()
                    except:
                        pass
                return False
        except Exception as e:
            st.error(f"Database error: {str(e)}")
            if not fetch:
                try:
                    conn.close()
                except:
                    pass
            return False
    return False

# Function to save terminated process to database
def save_terminated_process(process_name, pid, reason):
    timestamp_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    execute_db_operation('''
        INSERT INTO terminated_processes (timestamp, process_name, pid, reason)
        VALUES (?, ?, ?, ?)
    ''', (timestamp_str, process_name, pid, reason))

# Function to terminate a process
def terminate_process(pid, process_name):
    try:
        if pid and pid > 0:
            # Get process object
            process = psutil.Process(pid)
            
            # Terminate the process
            process.terminate()
            process.wait(timeout=3)  # Wait up to 3 seconds
            
            # If process is still alive, kill it forcefully
            if process.is_running():
                process.kill()
                process.wait(timeout=3)
            
            st.success(f"Successfully terminated process: {process_name} (PID: {pid})")
            save_terminated_process(process_name, pid, "Manual termination")
            save_alert_to_db('Process Terminated', f"Terminated suspicious process: {process_name} (PID: {pid})", 'High')
            return True
    except psutil.NoSuchProcess:
        st.warning(f"Process {process_name} (PID: {pid}) no longer exists")
        return False
    except psutil.AccessDenied:
        st.error(f"Access denied when trying to terminate process: {process_name} (PID: {pid})")
        save_alert_to_db('Termination Failed', f"Failed to terminate process: {process_name} (PID: {pid}) - Access denied", 'High')
        return False
    except Exception as e:
        st.error(f"Error terminating process {process_name} (PID: {pid}): {str(e)}")
        save_alert_to_db('Termination Error', f"Error terminating process: {process_name} (PID: {pid}) - {str(e)}", 'High')
        return False
    return False

# Function to auto-terminate suspicious processes
def auto_terminate_suspicious_processes(connections_df):
    if not st.session_state.auto_terminate_enabled:
        return []
    
    terminated_processes = []
    
    # Group connections by process
    process_groups = connections_df.groupby(['PID', 'Process'])
    
    for (pid, process_name), group in process_groups:
        # Count high-risk connections for this process
        high_risk_count = len(group[group['Risk Level'].isin(['High', 'Medium'])])
        
        # If threshold exceeded and process can be terminated
        if high_risk_count >= st.session_state.terminate_threshold and pid and pid > 0:
            try:
                # Don't terminate system processes
                if process_name.lower() in ['system', 'idle', 'system idle process']:
                    continue
                
                # Terminate the process
                if terminate_process(pid, process_name):
                    terminated_processes.append({
                        'PID': pid,
                        'Process': process_name,
                        'Connections': high_risk_count
                    })
            except Exception as e:
                st.error(f"Error in auto-termination: {str(e)}")
    
    return terminated_processes

# Function to save device to database
def save_device_to_db(device):
    # Convert timestamps to strings
    first_seen_str = device['First Seen'].strftime('%Y-%m-%d %H:%M:%S') if isinstance(device['First Seen'], datetime) else str(device['First Seen'])
    last_seen_str = device['Last Seen'].strftime('%Y-%m-%d %H:%M:%S') if isinstance(device['Last Seen'], datetime) else str(device['Last Seen'])
    
    # Check if device already exists
    result = execute_db_operation('SELECT id FROM devices WHERE mac = ?', (device['MAC'],), fetch=True)
    if result and len(result) > 0:
        # Update existing device
        execute_db_operation('''
            UPDATE devices SET last_seen = ?, hostname = ?, location = ?, isp = ?, is_external = ?
            WHERE mac = ?
        ''', (last_seen_str, device['Hostname'], device['Location'], 
              device['ISP'], int(device['Is External']), device['MAC']))
    else:
        # Insert new device
        execute_db_operation('''
            INSERT INTO devices (ip, mac, vendor, first_seen, last_seen, is_external, hostname, location, isp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (device['IP'], device['MAC'], device['Vendor'], first_seen_str, 
              last_seen_str, int(device['Is External']), device['Hostname'], 
              device['Location'], device['ISP']))

# Function to save connection to database with security analysis
def save_connection_to_db(connection):
    # Convert timestamp to string
    timestamp_str = connection['Timestamp'].strftime('%Y-%m-%d %H:%M:%S') if isinstance(connection['Timestamp'], datetime) else str(connection['Timestamp'])
    
    # Determine if connection is suspicious and risk level
    is_suspicious = 0
    risk_level = "Low"
    
    # Check for critical ports
    if connection['Remote Port'] in CRITICAL_PORTS:
        is_suspicious = 1
        risk_level = "High"
    # Check for high-risk port ranges
    elif any(start <= connection['Remote Port'] <= end for start, end in HIGH_RISK_PORT_RANGES):
        is_suspicious = 1
        risk_level = "Medium"
    # Check for external connections to non-standard ports
    elif connection.get('Is External', False) and connection['Remote Port'] > 1024:
        is_suspicious = 1
        risk_level = "Medium"
    
    # Get current columns in connections table
    connection_columns = get_table_columns('connections')
    has_security_columns = 'is_suspicious' in connection_columns and 'risk_level' in connection_columns
    
    if has_security_columns:
        execute_db_operation('''
            INSERT INTO connections (local_ip, local_port, remote_ip, remote_port, status, pid, process, timestamp, is_suspicious, risk_level)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (connection['Local IP'], connection['Local Port'], connection['Remote IP'], 
              connection['Remote Port'], connection['Status'], connection['PID'], 
              connection['Process'], timestamp_str, is_suspicious, risk_level))
    else:
        # Fallback for older schema
        execute_db_operation('''
            INSERT INTO connections (local_ip, local_port, remote_ip, remote_port, status, pid, process, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (connection['Local IP'], connection['Local Port'], connection['Remote IP'], 
              connection['Remote Port'], connection['Status'], connection['PID'], 
              connection['Process'], timestamp_str))

# Function to save alert to database
def save_alert_to_db(alert_type, message, severity="Medium"):
    timestamp_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Get current columns in alerts table
    alert_columns = get_table_columns('alerts')
    has_severity_column = 'severity' in alert_columns
    
    if has_severity_column:
        execute_db_operation('''
            INSERT INTO alerts (timestamp, alert_type, message, severity)
            VALUES (?, ?, ?, ?)
        ''', (timestamp_str, alert_type, message, severity))
    else:
        # Fallback for older schema
        execute_db_operation('''
            INSERT INTO alerts (timestamp, alert_type, message)
            VALUES (?, ?, ?)
        ''', (timestamp_str, alert_type, message))

# Function to track port scan attempts
def track_port_scan_attempt(ip, port):
    timestamp_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Check if this IP/port combination already exists in last 5 minutes
    result = execute_db_operation('''
        SELECT id, count FROM port_scan_attempts 
        WHERE ip = ? AND port = ? AND timestamp > datetime('now', '-5 minutes')
    ''', (ip, port), fetch=True)
    
    if result and len(result) > 0:
        # Update existing record
        record_id = result[0][0]
        current_count = result[0][1]
        execute_db_operation('''
            UPDATE port_scan_attempts 
            SET count = count + 1, timestamp = ? 
            WHERE id = ?
        ''', (timestamp_str, record_id))
        return current_count + 1
    else:
        # Insert new record
        execute_db_operation('''
            INSERT INTO port_scan_attempts (ip, port, timestamp, count)
            VALUES (?, ?, ?, 1)
        ''', (ip, port, timestamp_str))
        return 1

# Function to get summary report data
def get_summary_report():
    try:
        # Get device statistics
        devices_result = execute_db_operation('''
            SELECT is_external, COUNT(*) as count FROM devices GROUP BY is_external
        ''', fetch=True)
        
        total_devices_result = execute_db_operation('SELECT COUNT(*) as count FROM devices', fetch=True)
        total_devices = total_devices_result[0][0] if total_devices_result else 0
        
        external_devices = 0
        if devices_result:
            for row in devices_result:
                if row[0] == 1:  # is_external = 1
                    external_devices = row[1]
        
        # Get alert statistics
        alerts_result = execute_db_operation('''
            SELECT alert_type, COUNT(*) as count FROM alerts 
            WHERE timestamp > datetime('now', '-1 day') 
            GROUP BY alert_type
        ''', fetch=True)
        
        total_alerts_result = execute_db_operation('''
            SELECT COUNT(*) as count FROM alerts 
            WHERE timestamp > datetime('now', '-1 day')
        ''', fetch=True)
        total_alerts = total_alerts_result[0][0] if total_alerts_result else 0
        
        # Get connection statistics
        connections_result = execute_db_operation('''
            SELECT COUNT(*) as count FROM connections 
            WHERE timestamp > datetime('now', '-1 day')
        ''', fetch=True)
        total_connections = connections_result[0][0] if connections_result else 0
        
        # Get suspicious connections (if column exists)
        suspicious_connections = 0
        connection_columns = get_table_columns('connections')
        if 'is_suspicious' in connection_columns:
            try:
                suspicious_result = execute_db_operation('''
                    SELECT COUNT(*) as count FROM connections 
                    WHERE is_suspicious = 1 AND timestamp > datetime('now', '-1 day')
                ''', fetch=True)
                suspicious_connections = suspicious_result[0][0] if suspicious_result else 0
            except:
                suspicious_connections = 0
        
        # Get recent devices
        recent_devices_result = execute_db_operation('''
            SELECT ip, mac, vendor, last_seen, is_external, hostname, location, isp 
            FROM devices 
            ORDER BY last_seen DESC 
            LIMIT 20
        ''', fetch=True)
        
        recent_devices = []
        if recent_devices_result:
            for row in recent_devices_result:
                recent_devices.append({
                    'IP': row[0],
                    'MAC': row[1],
                    'Vendor': row[2],
                    'Last Seen': row[3],
                    'Is External': bool(row[4]),
                    'Hostname': row[5],
                    'Location': row[6],
                    'ISP': row[7]
                })
        
        # Get recent alerts
        alert_columns = get_table_columns('alerts')
        if 'severity' in alert_columns:
            recent_alerts_result = execute_db_operation('''
                SELECT timestamp, alert_type, message, severity FROM alerts 
                ORDER BY timestamp DESC 
                LIMIT 20
            ''', fetch=True)
        else:
            recent_alerts_result = execute_db_operation('''
                SELECT timestamp, alert_type, message FROM alerts 
                ORDER BY timestamp DESC 
                LIMIT 20
            ''', fetch=True)
        
        recent_alerts = []
        if recent_alerts_result:
            for row in recent_alerts_result:
                if len(row) == 4:  # Has severity column
                    recent_alerts.append({
                        'Timestamp': row[0],
                        'Type': row[1],
                        'Message': row[2],
                        'Severity': row[3] if row[3] else 'Medium'
                    })
                else:  # No severity column
                    recent_alerts.append({
                        'Timestamp': row[0],
                        'Type': row[1],
                        'Message': row[2],
                        'Severity': 'Medium'
                    })
        
        # Get high-risk connections (if column exists)
        high_risk_connections = []
        if 'risk_level' in connection_columns:
            try:
                high_risk_result = execute_db_operation('''
                    SELECT remote_ip, remote_port, process, timestamp, risk_level
                    FROM connections 
                    WHERE risk_level IN ('High', 'Medium') 
                    AND timestamp > datetime('now', '-1 day')
                    ORDER BY timestamp DESC 
                    LIMIT 20
                ''', fetch=True)
                
                if high_risk_result:
                    for row in high_risk_result:
                        service_name = CRITICAL_PORTS.get(row[1], f"Port {row[1]}")
                        high_risk_connections.append({
                            'Remote IP': row[0],
                            'Port': row[1],
                            'Service': service_name,
                            'Process': row[2],
                            'Timestamp': row[3],
                            'Risk Level': row[4]
                        })
            except:
                high_risk_connections = []
        
        # Convert results to proper format
        alerts_by_type = []
        if alerts_result:
            for row in alerts_result:
                alerts_by_type.append({'alert_type': row[0], 'count': row[1]})
        
        return {
            'total_devices': total_devices,
            'external_devices': external_devices,
            'total_alerts': total_alerts,
            'alerts_by_type': alerts_by_type,
            'total_connections': total_connections,
            'suspicious_connections': suspicious_connections,
            'recent_devices': recent_devices,
            'recent_alerts': recent_alerts,
            'high_risk_connections': high_risk_connections
        }
    except Exception as e:
        st.error(f"Error getting summary report: {str(e)}")
        return {
            'total_devices': 0,
            'external_devices': 0,
            'total_alerts': 0,
            'alerts_by_type': [],
            'total_connections': 0,
            'suspicious_connections': 0,
            'recent_devices': [],
            'recent_alerts': [],
            'high_risk_connections': []
        }

# Function to create charts for email (with fallback)
def _finalize_and_export(fig, scale=2):
    # Force opaque backgrounds (helps in some email clients)
    fig.update_layout(paper_bgcolor="white", plot_bgcolor="white")
    # Larger scale -> crisper PNGs
    return fig.to_image(format="png", width=800, height=600, scale=scale)


def create_email_charts(report_data):
    charts = {}
    try:
        # 1) Alert distribution (categorical -> explicit color)
        if report_data['alerts_by_type']:
            alerts_df = pd.DataFrame(report_data['alerts_by_type'])
            # Ensure stable color mapping by using the category as the color
            fig = px.pie(
                alerts_df,
                values='count',
                names='alert_type',
                color='alert_type',  # <-- forces categorical coloring
                title='Alert Types Distribution'
            )
            charts['alerts_pie'] = _finalize_and_export(fig)

        # 2) Risk level distribution (explicit colors for High/Normal)
        if report_data['suspicious_connections'] > 0 or report_data['total_connections'] > 0:
            risk_df = pd.DataFrame({
                'Risk Level': ['High Risk', 'Normal'],
                'Count': [
                    report_data['suspicious_connections'],
                    max(0, report_data['total_connections'] - report_data['suspicious_connections'])
                ]
            })
            # Provide a discrete color sequence to avoid grayscale fallback
            fig = px.bar(
                risk_df,
                x='Risk Level',
                y='Count',
                color='Risk Level',  # <-- categorical color
                color_discrete_sequence=px.colors.qualitative.Set1,
                title='Connection Risk Distribution'
            )
            fig.update_traces(marker_line_width=0.5)
            charts['risk_bar'] = _finalize_and_export(fig)

        # 3) Network statistics (categorical color as well)
        stats_data = {
            'Category': ['Total Devices', 'External Devices', 'Connections (24h)', 'Alerts (24h)'],
            'Count': [report_data['total_devices'], report_data['external_devices'],
                      report_data['total_connections'], report_data['total_alerts']]
        }
        if report_data['suspicious_connections'] > 0:
            stats_data['Category'].append('Suspicious Conn')
            stats_data['Count'].append(report_data['suspicious_connections'])

        stats_df = pd.DataFrame(stats_data)
        fig = px.bar(
            stats_df,
            x='Category',
            y='Count',
            color='Category',  # <-- categorical color
            color_discrete_sequence=px.colors.qualitative.Bold,
            title='Network Statistics Overview'
        )
        fig.update_traces(marker_line_width=0.5)
        charts['stats_bar'] = _finalize_and_export(fig)

    except Exception as e:
        st.warning(f"Could not generate charts: {e}. Sending report without charts.")
        charts = {}

    return charts
    
# Function to send email report with attachments
def send_email_report():
    try:
        # Get report data
        report_data = get_summary_report()
        
        # Create charts (may fail if kaleido not installed)
        charts = create_email_charts(report_data)
        
        # Create email content
        subject = f"Network Monitor Report - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        
        # HTML body with inline styles for email compatibility
        html_body = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .header {{ background-color: #4CAF50; color: white; padding: 20px; text-align: center; }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
                .stats {{ display: flex; justify-content: space-around; text-align: center; flex-wrap: wrap; }}
                .stat-box {{ background-color: #f9f9f9; padding: 10px; border-radius: 5px; margin: 5px; min-width: 120px; }}
                .stat-value {{ font-size: 24px; font-weight: bold; color: #4CAF50; }}
                .stat-label {{ font-size: 14px; color: #666; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .alert-high {{ background-color: #ffebee; }}
                .alert-medium {{ background-color: #fff3e0; }}
                .alert-low {{ background-color: #e8f5e9; }}
                .risk-high {{ background-color: #ffcdd2; font-weight: bold; }}
                .risk-medium {{ background-color: #ffe0b2; }}
                .risk-low {{ background-color: #c8e6c9; }}
                .critical-ports {{ background-color: #ffcdd2; }}
                .high-risk-range {{ background-color: #ffe0b2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Network Monitoring Report</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="section">
                <h2>📊 Network Statistics</h2>
                <div class="stats">
                    <div class="stat-box">
                        <div class="stat-value">{report_data['total_devices']}</div>
                        <div class="stat-label">Total Devices</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">{report_data['external_devices']}</div>
                        <div class="stat-label">External Devices</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">{report_data['total_connections']}</div>
                        <div class="stat-label">Connections (24h)</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">{report_data['total_alerts']}</div>
                        <div class="stat-label">Security Alerts (24h)</div>
                    </div>
            """
        
        if report_data['suspicious_connections'] > 0:
            html_body += f"""
                    <div class="stat-box">
                        <div class="stat-value">{report_data['suspicious_connections']}</div>
                        <div class="stat-label">Suspicious Conn</div>
                    </div>
            """
        
        html_body += """
                </div>
            </div>
            """
        
        # High-risk connections section (only if data exists)
        if report_data['high_risk_connections']:
            html_body += """
            <div class="section">
                <h2>⚠️ High-Risk Connections (Last 24h)</h2>
                <table>
                    <tr>
                        <th>Remote IP</th>
                        <th>Port</th>
                        <th>Service</th>
                        <th>Process</th>
                        <th>Time</th>
                        <th>Risk</th>
                    </tr>
            """
            
            # Add high-risk connections to table
            for conn in report_data['high_risk_connections'][:10]:  # Limit to 10 connections
                risk_class = f" class='risk-{conn['Risk Level'].lower()}'"
                html_body += f"""
                    <tr{risk_class}>
                        <td>{conn['Remote IP']}</td>
                        <td>{conn['Port']}</td>
                        <td>{conn['Service']}</td>
                        <td>{conn['Process']}</td>
                        <td>{conn['Timestamp']}</td>
                        <td>{conn['Risk Level']}</td>
                    </tr>
                """
            
            html_body += """
                </table>
                <p><strong>Key:</strong> 
                <span class="critical-ports">Critical Ports</span> 
                <span class="high-risk-range">High-Risk Port Ranges</span>
                </p>
            </div>
            """
        
        html_body += """
            <div class="section">
                <h2>📡 Recent Devices</h2>
                <table>
                    <tr>
                        <th>IP Address</th>
                        <th>Hostname</th>
                        <th>Vendor</th>
                        <th>Last Seen</th>
                        <th>Type</th>
                    </tr>
        """
        
        # Add recent devices to table
        for device in report_data['recent_devices'][:10]:  # Limit to 10 devices
            device_type = "External" if device['Is External'] else "Internal"
            html_body += f"""
                    <tr>
                        <td>{device['IP']}</td>
                        <td>{device['Hostname']}</td>
                        <td>{device['Vendor']}</td>
                        <td>{device['Last Seen']}</td>
                        <td>{device_type}</td>
                    </tr>
            """
        
        html_body += """
                </table>
            </div>
            
            <div class="section">
                <h2>🚨 Recent Security Alerts</h2>
                <table>
                    <tr>
                        <th>Time</th>
                        <th>Type</th>
                        <th>Message</th>
                    </tr>
        """
        
        # Add recent alerts to table
        for alert in report_data['recent_alerts'][:10]:  # Limit to 10 alerts
            # Default to medium severity if not present
            severity = alert.get('Severity', 'Medium')
            alert_class = f" class='alert-{severity.lower()}'"
                
            html_body += f"""
                    <tr{alert_class}>
                        <td>{alert['Timestamp']}</td>
                        <td>{alert['Type']}</td>
                        <td>{alert['Message']}</td>
                    </tr>
            """
        
        html_body += """
                </table>
            </div>
        """
        
        # Add chart information if charts were generated
        if charts:
            html_body += """
            <div class="section">
                <h2>📈 Charts Included</h2>
                <p>This email includes the following charts as attachments:</p>
                <ul>
                    <li>Alert Types Distribution (Pie Chart)</li>
            """
            if report_data['suspicious_connections'] > 0:
                html_body += "<li>Connection Risk Distribution (Bar Chart)</li>"
            html_body += """
                    <li>Network Statistics Overview (Bar Chart)</li>
                </ul>
            </div>
            """
        else:
            html_body += """
            <div class="section">
                <h2>ℹ️ Note</h2>
                <p>Charts could not be generated. Please install kaleido for chart support:</p>
                <code>pip install -U kaleido</code>
            </div>
            """
        
        html_body += """
            <div class="section">
                <h2>🛡️ Critical Ports Monitored</h2>
                <p>This system monitors connections to the following critical ports commonly targeted by attackers:</p>
                <ul>
        """
        
        # Add critical ports to the list
        for port, service in list(CRITICAL_PORTS.items())[:15]:  # Show first 15
            html_body += f"<li><strong>Port {port}:</strong> {service}</li>"
        
        html_body += """
                </ul>
                <p><em>Plus {more_count} more critical ports...</em></p>
            </div>
            
            <div class="section">
                <p><em>This is an automated report from your Network Monitor system.</em></p>
            </div>
        </body>
        </html>
        """.replace('{more_count}', str(len(CRITICAL_PORTS) - 15))
        
        # Plain text version as fallback
        text_body = f"""
        Network Monitoring Report
        ========================
        
        Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        
        Device Statistics:
        - Total Devices: {report_data['total_devices']}
        - External Devices: {report_data['external_devices']}
        
        Activity Statistics (Last 24 Hours):
        - Total Connections: {report_data['total_connections']}
        - Security Alerts: {report_data['total_alerts']}
        """
        
        if report_data['suspicious_connections'] > 0:
            text_body += f"- Suspicious Connections: {report_data['suspicious_connections']}\n"
        
        text_body += "\nAlert Details:\n"
        
        for alert in report_data['alerts_by_type']:
            text_body += f"  - {alert['alert_type']}: {alert['count']} alerts\n"
        
        if report_data['high_risk_connections']:
            text_body += "\nHigh-Risk Connections:\n"
            for conn in report_data['high_risk_connections'][:10]:
                text_body += f"  - {conn['Remote IP']}:{conn['Port']} ({conn['Service']}) - {conn['Risk Level']} risk\n"
        
        text_body += "\nRecent Devices:\n"
        for device in report_data['recent_devices'][:10]:
            device_type = "External" if device['Is External'] else "Internal"
            text_body += f"  - {device['IP']} ({device['Hostname']}) - {device_type}\n"
        
        text_body += "\nRecent Alerts:\n"
        for alert in report_data['recent_alerts'][:10]:
            severity = alert.get('Severity', 'Medium')
            text_body += f"  - [{alert['Timestamp']}] {alert['Type']} ({severity}): {alert['Message']}\n"
        
        text_body += f"\nCritical Ports Monitored:\n"
        for port, service in list(CRITICAL_PORTS.items())[:10]:
            text_body += f"  - Port {port}: {service}\n"
        text_body += f"  ...and {len(CRITICAL_PORTS) - 10} more critical ports\n"
        
        text_body += "\nThis is an automated report from your Network Monitor system."
        
        # Load email configuration from secrets
        try:
            secrets = toml.load(".streamlit/secrets.toml")
            smtp_config = secrets["smtp"]
            smtp_server = smtp_config["host"]
            smtp_port = smtp_config["port"]
            email_user = smtp_config["username"]
            email_password = smtp_config["password"]
            sender = smtp_config["sender"]
            use_tls = smtp_config["use_tls"]
        except Exception as e:
            st.error(f"Email configuration not found in secrets.toml: {str(e)}")
            return False
        
        # Create message
        msg = MIMEMultipart('alternative')
        msg['From'] = sender
        msg['To'] = sender  # Send to self
        msg['Subject'] = subject
        
        # Attach parts
        part1 = MIMEText(text_body, 'plain')
        part2 = MIMEText(html_body, 'html')
        msg.attach(part1)
        msg.attach(part2)
        
        # Attach charts if available
        for chart_name, chart_bytes in charts.items():
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(chart_bytes)
            encoders.encode_base64(part)
            part.add_header(
                'Content-Disposition',
                f'attachment; filename= {chart_name}.png'
            )
            msg.attach(part)
        
        # Send email
        server = smtplib.SMTP(smtp_server, smtp_port)
        if use_tls:
            server.starttls()
        server.login(email_user, email_password)
        text = msg.as_string()
        server.sendmail(sender, sender, text)
        server.quit()
        
        if charts:
            st.success("Email report sent successfully with charts!")
        else:
            st.success("Email report sent successfully (without charts)!")
        return True
    except Exception as e:
        st.error(f"Failed to send email report: {str(e)}")
        return False

# Function to schedule email reports
def schedule_email_reports():
    if st.session_state.email_job:
        schedule.cancel_job(st.session_state.email_job)
        st.session_state.email_job = None
    
    if email_interval != "Disabled":
        def job():
            send_email_report()
        
        if email_interval == "Hourly":
            st.session_state.email_job = schedule.every().hour.at(email_time.strftime("%M:%S")).do(job)
        elif email_interval == "Daily":
            st.session_state.email_job = schedule.every().day.at(email_time.strftime("%H:%M")).do(job)
        elif email_interval == "Weekly":
            st.session_state.email_job = schedule.every().week.at(email_time.strftime("%H:%M")).do(job)

# Run scheduler in background
def run_scheduler():
    while True:
        schedule.run_pending()
        time.sleep(60)

# Start scheduler thread
if 'scheduler_thread' not in st.session_state:
    st.session_state.scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
    st.session_state.scheduler_thread.start()

# Function to run ARP scan

def scan_network():
    """
    Returns raw text representing ARP/neighbour entries.
    Tries /proc/net/arp, then `ip neigh show`, then `arp -a`.
    Falls back gracefully in cloud environments.
    """
    try:
        # 1) Linux-native (works without extra binaries)
        proc_arp = "/proc/net/arp"
        if os.path.exists(proc_arp):
            with open(proc_arp, "r", encoding="utf-8", errors="ignore") as f:
                data = f.read()
            # Tag the source so the parser can choose the right format
            return "SOURCE:/proc/net/arp\n" + data
    except Exception as e:
        st.warning(f"Reading /proc/net/arp failed: {e}")

    # 2) `ip neigh show` (if the 'ip' tool exists)
    try:
        result = subprocess.run(['ip', 'neigh', 'show'],
                                capture_output=True, text=True, timeout=10)
        if result.returncode == 0 and result.stdout.strip():
            return "SOURCE:ip neigh\n" + result.stdout
    except FileNotFoundError:
        pass
    except Exception as e:
        st.warning(f"`ip neigh show` failed: {e}")

    # 3) `arp -a` (legacy; not available in most containers)
    try:
        result = subprocess.run(['arp', '-a'],
                                capture_output=True, text=True, timeout=10)
        if result.returncode == 0 and result.stdout.strip():
            return "SOURCE:arp -a\n" + result.stdout
    except FileNotFoundError:
        # This is what you are seeing in Streamlit Cloud
        pass
    except Exception as e:
        st.warning(f"`arp -a` failed: {e}")

    # 4) Nothing worked — we are likely in a cloud sandbox
    st.info("LAN ARP scan not available in this environment. "
            "Tip: run this app on a local machine inside your network, "
            "or deploy a small on-prem agent that reports back.")
    return ""



# Function to check if IP is external
def is_external_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local)
    except:
        return False

# Function to get hostname from IP
def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"

# Function to get geolocation data
def get_geolocation(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                return f"{data.get('city', 'Unknown')}, {data.get('regionName', 'Unknown')}, {data.get('country', 'Unknown')}"
        return "Unknown"
    except:
        return "Unknown"

# Function to get ISP information
def get_isp(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                return data.get('isp', 'Unknown')
        return "Unknown"
    except:
        return "Unknown"

# Function to get process name from PID
def get_process_name(pid):
    try:
        process = psutil.Process(pid)
        return process.name()
    except:
        return "Unknown"

# Function to scan network connections with enhanced security detection
def scan_connections():
    connections = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr and conn.raddr:
                process_name = get_process_name(conn.pid) if conn.pid else "System"
                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
                
                # Check for critical ports
                is_critical = remote_port in CRITICAL_PORTS
                is_high_risk_range = any(start <= remote_port <= end for start, end in HIGH_RISK_PORT_RANGES)
                is_external = is_external_ip(remote_ip)
                
                # Track port scan attempts for external IPs connecting to critical ports
                if is_external and (is_critical or is_high_risk_range):
                    attempt_count = track_port_scan_attempt(remote_ip, remote_port)
                    if attempt_count >= high_risk_port_threshold:
                        alert_msg = f"Possible port scanning detected: {remote_ip} connecting to port {remote_port} ({attempt_count} attempts)"
                        save_alert_to_db('Port Scan Attempt', alert_msg, 'High')
                
                connections.append({
                    'Local IP': conn.laddr.ip,
                    'Local Port': conn.laddr.port,
                    'Remote IP': remote_ip,
                    'Remote Port': remote_port,
                    'Status': conn.status,
                    'PID': conn.pid if conn.pid else 0,
                    'Process': process_name,
                    'Timestamp': datetime.now(),
                    'Is External': is_external,
                    'Is Critical Port': is_critical,
                    'Is High Risk Range': is_high_risk_range,
                    'Risk Level': "High" if is_critical else ("Medium" if is_high_risk_range else "Low")
                })
    except Exception as e:
        st.error(f"Connection scan failed: {str(e)}")
    return connections

# Function to detect suspicious activity
def detect_suspicious_activity(connections_df):
    alerts = []
    
    if connections_df.empty:
        return alerts
    
    # Check for port scanning (multiple connections to different ports on same IP)
    remote_ips = connections_df['Remote IP'].unique()
    for ip in remote_ips:
        ip_connections = connections_df[connections_df['Remote IP'] == ip]
        if len(ip_connections) > suspicious_port_threshold:
            alert_msg = f"High connection count to {ip} ({len(ip_connections)} connections)"
            alerts.append({
                'Time': datetime.now().strftime("%H:%M:%S"),
                'Type': 'Potential Port Scan',
                'Message': alert_msg
            })
            save_alert_to_db('Potential Port Scan', alert_msg, 'High')
    
    # Check for connections to critical ports
    critical_connections = connections_df[connections_df['Is Critical Port'] == True]
    for _, conn in critical_connections.iterrows():
        service_name = CRITICAL_PORTS.get(conn['Remote Port'], f"Port {conn['Remote Port']}")
        alert_msg = f"Connection to critical port: {conn['Remote IP']}:{conn['Remote Port']} ({service_name}) by {conn['Process']}"
        alerts.append({
            'Time': datetime.now().strftime("%H:%M:%S"),
            'Type': 'Critical Port Connection',
            'Message': alert_msg
        })
        save_alert_to_db('Critical Port Connection', alert_msg, 'High')
    
    # Check for connections to high-risk port ranges
    high_risk_connections = connections_df[connections_df['Is High Risk Range'] == True]
    for _, conn in high_risk_connections.iterrows():
        alert_msg = f"Connection to high-risk port range: {conn['Remote IP']}:{conn['Remote Port']} by {conn['Process']}"
        alerts.append({
            'Time': datetime.now().strftime("%H:%M:%S"),
            'Type': 'High-Risk Port Connection',
            'Message': alert_msg
        })
        save_alert_to_db('High-Risk Port Connection', alert_msg, 'Medium')
    
    # Check for data transfer to external IPs
    external_connections = connections_df[
        connections_df['Is External'] == True
    ]
    
    if not external_connections.empty:
        for _, conn in external_connections.iterrows():
            alert_msg = f"Connection to external IP: {conn['Remote IP']}:{conn['Remote Port']} ({conn['Process']})"
            alerts.append({
                'Time': datetime.now().strftime("%H:%M:%S"),
                'Type': 'External Connection',
                'Message': alert_msg
            })
            save_alert_to_db('External Connection', alert_msg, 'Medium')
    
    return alerts

# Function to parse ARP output
def parse_arp_output(output):
    """
    Parse ARP/neighbour data from any of:
      - /proc/net/arp (Linux)
      - `ip neigh show`
      - `arp -a`
    Returns a list of device dicts.
    """
    devices = []
    if not output:
        return devices

    # Ensure known_macs exists
    try:
        _km = known_macs
    except NameError:
        _km = {}

    # Identify source
    first_line, *rest = output.splitlines()
    payload = "\n".join(rest) if first_line.startswith("SOURCE:") else output
    source = first_line.replace("SOURCE:", "").strip() if first_line.startswith("SOURCE:") else "unknown"

    now = datetime.now()

    def add_device(ip, mac):
        if not ip or not mac:
            return
        mac_norm = mac.replace('-', ':').lower()
        vendor = _km.get(mac_norm, "Unknown")
        # Check if external (usually false for ARP table)
        ext = is_external_ip(ip)
        hostname = get_hostname(ip) if ext else "Local Network"
        location = get_geolocation(ip) if ext else "Local"
        isp = get_isp(ip) if ext else "Local Network"
        devices.append({
            'IP': ip,
            'MAC': mac_norm,
            'Vendor': vendor,
            'First Seen': now,         # filled by caller if needed
            'Last Seen': now,
            'Is External': ext,
            'Hostname': hostname,
            'Location': location,
            'ISP': isp
        })

    if source == "/proc/net/arp":
        # /proc/net/arp columns: IP address, HW type, Flags, HW address, Mask, Device
        lines = [ln for ln in payload.splitlines() if ln.strip()]
        if lines:
            # skip header
            for ln in lines[1:]:
                parts = re.split(r"\s+", ln.strip())
                if len(parts) >= 6:
                    ip, _, _, mac, _, _ = parts[:6]
                    # filter incomplete entries (MAC "00:00:00:00:00:00")
                    if re.match(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", mac) and mac != "00:00:00:00:00:00":
                        add_device(ip, mac)

    elif source == "ip neigh":
        # Format examples:
        # 192.168.1.10 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
        for ln in payload.splitlines():
            m_ip = re.search(r'(\d+\.\d+\.\d+\.\d+)', ln)
            m_mac = re.search(r'([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}', ln)
            if m_ip and m_mac:
                add_device(m_ip.group(1), m_mac.group(0))

    else:
        # Try generic/arp -a parsing: look for IP + MAC anywhere on the line
        for ln in payload.splitlines():
            m_ip = re.search(r'(\d+\.\d+\.\d+\.\d+)', ln)
            m_mac = re.search(r'([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}', ln)
            if m_ip and m_mac:
                add_device(m_ip.group(1), m_mac.group(0))

    return devices

# Function to detect external access
def detect_external_access(devices_df):
    alerts = []
    # Check for external devices
    external_devices = devices_df[devices_df['Is External'] == True]
    for _, device in external_devices.iterrows():
        alert_msg = f"External device detected: {device['IP']} ({device['Hostname']}) in {device['Location']}"
        alerts.append({
            'Time': datetime.now().strftime("%H:%M:%S"),
            'Type': 'External Device',
            'Message': alert_msg
        })
        save_alert_to_db('External Device', alert_msg, 'High')
    
    # Check for devices not in known devices list
    for _, device in devices_df.iterrows():
        if device['MAC'] not in known_macs and device['Vendor'] == "Unknown" and not device['Is External']:
            alert_msg = f"New local device detected: {device['IP']} ({device['MAC']})"
            alerts.append({
                'Time': datetime.now().strftime("%H:%M:%S"),
                'Type': 'Unknown Device',
                'Message': alert_msg
            })
            save_alert_to_db('Unknown Device', alert_msg, 'Medium')
    return alerts

# Ensure DataFrame has all required columns
required_device_columns = ['IP', 'MAC', 'Vendor', 'First Seen', 'Last Seen', 'Is External', 'Hostname', 'Location', 'ISP']
for col in required_device_columns:
    if col not in st.session_state.devices.columns:
        if col in ['Is External']:
            st.session_state.devices[col] = False
        else:
            st.session_state.devices[col] = ""

required_conn_columns = ['Local IP', 'Local Port', 'Remote IP', 'Remote Port', 'Status', 'PID', 'Process', 'Timestamp', 'Is External', 'Is Critical Port', 'Is High Risk Range', 'Risk Level']
for col in required_conn_columns:
    if col not in st.session_state.connections.columns:
        if col in ['Is External', 'Is Critical Port', 'Is High Risk Range']:
            st.session_state.connections[col] = False
        elif col == 'Risk Level':
            st.session_state.connections[col] = "Low"
        else:
            st.session_state.connections[col] = ""

# Load known devices from secrets
try:
    secrets = toml.load(".streamlit/secrets.toml")
    known_devices_list = secrets.get("known_devices", [])
    known_macs = {}
    for item in known_devices_list:
        if isinstance(item, dict) and 'mac' in item and 'vendor' in item:
            known_macs[item['mac'].lower()] = item['vendor']
except:
    known_macs = {}
    st.warning("No known devices found in secrets.toml")

# Manual refresh button
if st.button("🔄 Refresh Now"):
    # Network scan
    output = scan_network()
    if output:
        devices = parse_arp_output(output)
        new_devices_df = pd.DataFrame(devices)
        
        # Ensure new DataFrame has all required columns
        for col in required_device_columns:
            if col not in new_devices_df.columns:
                new_devices_df[col] = ""
        
        # Update device tracking
        for _, new_device in new_devices_df.iterrows():
            existing = st.session_state.devices[
                st.session_state.devices['MAC'] == new_device['MAC']
            ]
            if existing.empty:
                new_device['First Seen'] = new_device['Last Seen']
                st.session_state.devices = pd.concat(
                    [st.session_state.devices, new_device.to_frame().T], 
                    ignore_index=True
                )
                # Save to database
                save_device_to_db(new_device)
            else:
                # Update existing device info
                idx = existing.index[0]
                st.session_state.devices.loc[idx, [
                    'Last Seen', 'Hostname', 'Location', 'ISP', 'Is External'
                ]] = [
                    new_device['Last Seen'], new_device['Hostname'], 
                    new_device['Location'], new_device['ISP'], new_device['Is External']
                ]
                # Update in database
                save_device_to_db(new_device)
        
        # Detect external access
        new_alerts = detect_external_access(new_devices_df)
        st.session_state.alerts.extend(new_alerts)
        
        st.session_state.last_scan = datetime.now()
    
    # Connection scan
    connections = scan_connections()
    if connections:
        new_connections_df = pd.DataFrame(connections)
        
        # Ensure new DataFrame has all required columns
        for col in required_conn_columns:
            if col not in new_connections_df.columns:
                if col in ['Is External', 'Is Critical Port', 'Is High Risk Range']:
                    new_connections_df[col] = False
                elif col == 'Risk Level':
                    new_connections_df[col] = "Low"
                else:
                    new_connections_df[col] = ""
        
        # Add new connections to history (keep last 1000)
        st.session_state.connections = pd.concat(
            [st.session_state.connections, new_connections_df], 
            ignore_index=True
        )
        if len(st.session_state.connections) > 1000:
            st.session_state.connections = st.session_state.connections.tail(1000)
        
        # Save connections to database with security analysis
        for _, conn in new_connections_df.iterrows():
            save_connection_to_db(conn)
        
        # Auto-terminate suspicious processes if enabled
        terminated_processes = []
        if st.session_state.auto_terminate_enabled:
            terminated_processes = auto_terminate_suspicious_processes(new_connections_df)
        
        # Detect suspicious activity
        new_suspicious = detect_suspicious_activity(new_connections_df)
        st.session_state.suspicious_activity.extend(new_suspicious)
        
        # Add termination alerts
        for proc in terminated_processes:
            st.session_state.suspicious_activity.append({
                'Time': datetime.now().strftime("%H:%M:%S"),
                'Type': 'Process Terminated',
                'Message': f"Auto-terminated {proc['Process']} (PID: {proc['PID']}) due to {proc['Connections']} high-risk connections"
            })
        
        st.session_state.last_traffic_scan = datetime.now()

# Auto-refresh section
st.subheader("🔁 Auto-Refresh Status")
placeholder = st.empty()

# Check if it's time for auto-refresh
time_since_last_scan = (datetime.now() - st.session_state.last_scan).seconds
time_since_last_traffic = (datetime.now() - st.session_state.last_traffic_scan).seconds

auto_scan_performed = False
status_placeholder = None

# Network scan
if time_since_last_scan >= scan_interval:
    status_placeholder = placeholder.info("Scanning network...")
    output = scan_network()
    if output:
        devices = parse_arp_output(output)
        new_devices_df = pd.DataFrame(devices)
        
        # Ensure new DataFrame has all required columns
        for col in required_device_columns:
            if col not in new_devices_df.columns:
                new_devices_df[col] = ""
        
        # Update device tracking
        for _, new_device in new_devices_df.iterrows():
            existing = st.session_state.devices[
                st.session_state.devices['MAC'] == new_device['MAC']
            ]
            if existing.empty:
                new_device['First Seen'] = new_device['Last Seen']
                st.session_state.devices = pd.concat(
                    [st.session_state.devices, new_device.to_frame().T], 
                    ignore_index=True
                )
                # Save to database
                save_device_to_db(new_device)
            else:
                # Update existing device info
                idx = existing.index[0]
                st.session_state.devices.loc[idx, [
                    'Last Seen', 'Hostname', 'Location', 'ISP', 'Is External'
                ]] = [
                    new_device['Last Seen'], new_device['Hostname'], 
                    new_device['Location'], new_device['ISP'], new_device['Is External']
                ]
                # Update in database
                save_device_to_db(new_device)
        
        # Detect external access
        new_alerts = detect_external_access(new_devices_df)
        st.session_state.alerts.extend(new_alerts)
        
        st.session_state.last_scan = datetime.now()
        auto_scan_performed = True

# Traffic scan
if time_since_last_traffic >= traffic_scan_interval:
    if not status_placeholder:  # Only show status if not already shown
        status_placeholder = placeholder.info("Scanning network traffic...")
    connections = scan_connections()
    if connections:
        new_connections_df = pd.DataFrame(connections)
        
        # Ensure new DataFrame has all required columns
        for col in required_conn_columns:
            if col not in new_connections_df.columns:
                if col in ['Is External', 'Is Critical Port', 'Is High Risk Range']:
                    new_connections_df[col] = False
                elif col == 'Risk Level':
                    new_connections_df[col] = "Low"
                else:
                    new_connections_df[col] = ""
        
        # Add new connections to history (keep last 1000)
        st.session_state.connections = pd.concat(
            [st.session_state.connections, new_connections_df], 
            ignore_index=True
        )
        if len(st.session_state.connections) > 1000:
            st.session_state.connections = st.session_state.connections.tail(1000)
        
        # Save connections to database with security analysis
        for _, conn in new_connections_df.iterrows():
            save_connection_to_db(conn)
        
        # Auto-terminate suspicious processes if enabled
        terminated_processes = []
        if st.session_state.auto_terminate_enabled:
            terminated_processes = auto_terminate_suspicious_processes(new_connections_df)
        
        # Detect suspicious activity
        new_suspicious = detect_suspicious_activity(new_connections_df)
        st.session_state.suspicious_activity.extend(new_suspicious)
        
        # Add termination alerts
        for proc in terminated_processes:
            st.session_state.suspicious_activity.append({
                'Time': datetime.now().strftime("%H:%M:%S"),
                'Type': 'Process Terminated',
                'Message': f"Auto-terminated {proc['Process']} (PID: {proc['PID']}) due to {proc['Connections']} high-risk connections"
            })
        
        st.session_state.last_traffic_scan = datetime.now()
        auto_scan_performed = True

if auto_scan_performed and status_placeholder:
    status_placeholder.empty()
    placeholder.success("Auto-scan completed successfully!")
elif not auto_scan_performed:
    next_network = scan_interval - time_since_last_scan
    next_traffic = traffic_scan_interval - time_since_last_traffic
    next_scan = min(next_network, next_traffic)
    placeholder.info(f"Next scan in {next_scan} seconds...")

# Email scheduling
schedule_email_reports()

# Main dashboard
tab1, tab2, tab3, tab4, tab5 = st.tabs(["📡 Devices", "🚨 Alerts", "🔗 Connections", "🛡️ Security", "📊 Reports"])

with tab1:
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Active Devices")
        if not st.session_state.devices.empty:
            display_df = st.session_state.devices.drop(columns=['First Seen'], errors='ignore')
            st.dataframe(display_df, use_container_width=True)
        else:
            st.info("No devices detected. Click 'Refresh Now' to scan.")
    
    with col2:
        # External devices section
        if 'Is External' in st.session_state.devices.columns:
            external_devices = st.session_state.devices[st.session_state.devices['Is External'] == True]
            if not external_devices.empty:
                st.subheader("🌍 External Devices Details")
                for _, device in external_devices.iterrows():
                    with st.expander(f"🌐 {device['IP']} - {device['Hostname']}"):
                        st.write(f"**MAC Address:** {device['MAC']}")
                        st.write(f"**ISP:** {device['ISP']}")
                        st.write(f"**Location:** {device['Location']}")
                        st.write(f"**First Seen:** {device['First Seen']}")
                        st.write(f"**Last Seen:** {device['Last Seen']}")

with tab2:
    st.subheader("Security Alerts")
    all_alerts = st.session_state.alerts + st.session_state.suspicious_activity
    if all_alerts:
        for alert in all_alerts[-20:]:  # Show last 20 alerts
            severity = "Medium"
            if 'External' in alert['Type'] or 'Critical' in alert['Type'] or 'Port Scan' in alert['Type'] or 'Terminated' in alert['Type']:
                severity = "High"
            elif 'High-Risk' in alert['Type'] or 'Suspicious' in alert['Type']:
                severity = "Medium"
                
            if severity == "High":
                st.error(f"**{alert['Time']}** - {alert['Type']}: {alert['Message']}")
            elif severity == "Medium":
                st.warning(f"**{alert['Time']}** - {alert['Type']}: {alert['Message']}")
            else:
                st.info(f"**{alert['Time']}** - {alert['Type']}: {alert['Message']}")
    else:
        st.success("No alerts detected")

with tab3:
    st.subheader("Network Connections")
    if not st.session_state.connections.empty:
        # Show recent connections
        recent_connections = st.session_state.connections.tail(100)
        st.dataframe(recent_connections, use_container_width=True)
        
        # Connection statistics
        st.subheader("Connection Statistics")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            external_conns = st.session_state.connections[
                st.session_state.connections['Is External'] == True
            ]
            st.metric("External Connections", len(external_conns))
        
        with col2:
            unique_ips = st.session_state.connections['Remote IP'].nunique()
            st.metric("Unique Remote IPs", unique_ips)
        
        with col3:
            active_processes = st.session_state.connections['Process'].nunique()
            st.metric("Active Processes", active_processes)
        
        # Connection visualization
        if not st.session_state.connections.empty:
            st.subheader("Connection Map")
            # Show top 20 remote IPs
            top_ips = st.session_state.connections['Remote IP'].value_counts().head(20)
            fig = px.bar(x=top_ips.index, y=top_ips.values, 
                        labels={'x': 'Remote IP', 'y': 'Connection Count'},
                        title="Top Remote IP Connections")
            st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No connection data available. Click 'Refresh Now' to scan.")

with tab4:
    st.subheader("Security Analysis")
    
    # Suspicious activity
    if st.session_state.suspicious_activity:
        st.subheader("Detected Suspicious Activity")
        for alert in st.session_state.suspicious_activity[-10:]:
            if 'Critical' in alert['Type'] or 'Port Scan' in alert['Type'] or 'Terminated' in alert['Type']:
                st.error(f"**{alert['Time']}** - {alert['Type']}: {alert['Message']}")
            elif 'High-Risk' in alert['Type']:
                st.warning(f"**{alert['Time']}** - {alert['Type']}: {alert['Message']}")
            else:
                st.info(f"**{alert['Time']}** - {alert['Type']}: {alert['Message']}")
    else:
        st.success("No suspicious activity detected")
    
    # Manual process termination
    st.subheader("🎯 Manual Process Termination")
    st.warning("⚠️ Warning: Terminating processes can cause system instability. Use with caution!")
    
    # Get running processes
    try:
        running_processes = []
        for proc in psutil.process_iter(['pid', 'name', 'connections']):
            try:
                if proc.info['connections']:
                    running_processes.append({
                        'PID': proc.info['pid'],
                        'Name': proc.info['name'],
                        'Connections': len(proc.info['connections'])
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        if running_processes:
            # Sort by number of connections
            running_processes.sort(key=lambda x: x['Connections'], reverse=True)
            
            # Display top 20 processes with connections
            process_df = pd.DataFrame(running_processes[:20])
            st.dataframe(process_df, use_container_width=True)
            
            # Process termination form
            st.subheader("Terminate Process")
            col1, col2 = st.columns(2)
            with col1:
                selected_pid = st.selectbox("Select Process PID", [p['PID'] for p in running_processes[:20]])
            with col2:
                selected_name = next((p['Name'] for p in running_processes if p['PID'] == selected_pid), "Unknown")
                st.write(f"Selected Process: {selected_name}")
            
            terminate_reason = st.text_input("Termination Reason (Optional)")
            
            if st.button("🛑 Terminate Selected Process", type="secondary"):
                if selected_pid:
                    if terminate_process(selected_pid, selected_name):
                        st.session_state.suspicious_activity.append({
                            'Time': datetime.now().strftime("%H:%M:%S"),
                            'Type': 'Process Terminated',
                            'Message': f"Manually terminated {selected_name} (PID: {selected_pid}) - {terminate_reason or 'No reason provided'}"
                        })
        else:
            st.info("No processes with network connections found.")
            
    except Exception as e:
        st.error(f"Error retrieving running processes: {str(e)}")
    
    # Critical ports monitoring
    st.subheader("Critical Ports Monitoring")
    critical_ports_df = pd.DataFrame(list(CRITICAL_PORTS.items()), columns=['Port', 'Service'])
    st.dataframe(critical_ports_df, use_container_width=True)
    
    # High-risk port ranges
    st.subheader("High-Risk Port Ranges")
    risk_ranges_df = pd.DataFrame(HIGH_RISK_PORT_RANGES, columns=['Start Port', 'End Port'])
    st.dataframe(risk_ranges_df, use_container_width=True)
    
    # Process analysis
    if not st.session_state.connections.empty:
        st.subheader("Process Network Activity")
        process_activity = st.session_state.connections.groupby('Process').agg({
            'Remote IP': 'count',
            'Remote Port': 'nunique'
        }).rename(columns={'Remote IP': 'Connections', 'Remote Port': 'Unique Ports'})
        process_activity = process_activity.sort_values('Connections', ascending=False).head(10)
        st.dataframe(process_activity, use_container_width=True)
    
    # Network visualization
    if not st.session_state.devices.empty and 'Is External' in st.session_state.devices.columns:
        st.subheader("Network Topology")
        ip_parts = st.session_state.devices['IP'].str.split('.', expand=True)
        ip_parts.columns = ['Oct1', 'Oct2', 'Oct3', 'Oct4']
        fig_df = pd.concat([st.session_state.devices, ip_parts], axis=1)
        
        fig = px.scatter(
            fig_df,
            x='Oct4',
            y='Oct3',
            color='Is External',
            hover_data=['IP', 'MAC', 'Hostname', 'Location', 'Last Seen'],
            title="Device Distribution by IP Subnet"
        )
        st.plotly_chart(fig, use_container_width=True)

with tab5:
    st.subheader("📊 Summary Report")
    
    # Generate report
    report_data = get_summary_report()
    
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Total Devices", report_data['total_devices'])
        st.metric("External Devices", report_data['external_devices'])
    
    with col2:
        st.metric("Connections (24h)", report_data['total_connections'])
        st.metric("Security Alerts (24h)", report_data['total_alerts'])
    
    st.subheader("Alert Distribution")
    if report_data['alerts_by_type']:
        alerts_df = pd.DataFrame(report_data['alerts_by_type'])
        fig = px.pie(alerts_df, values='count', names='alert_type', title='Alert Types Distribution')
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No alerts in the last 24 hours")
    
    # Manual report sending
    st.subheader("📧 Email Report")
    if st.button("Send Report Now"):
        if send_email_report():
            st.success("Report sent successfully!")
        else:
            st.error("Failed to send report")

# Add a rerun trigger to create auto-refresh effect
time.sleep(1)
st.rerun()



