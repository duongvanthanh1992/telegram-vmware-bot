import os
import re
import paramiko
from datetime import datetime
from contextlib import contextmanager


class SSHMonitor:
    """Optimized SSH monitor for Ubuntu systems with focused data collection."""
    
    def __init__(self, hostname, username, password=None, private_key_path=None, port=22):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.private_key_path = private_key_path
        self.port = port
        self.client = None

    @contextmanager
    def ssh_connection(self):
        """Context manager for SSH connections."""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect with password or private key
            if self.private_key_path and os.path.exists(self.private_key_path):
                private_key = paramiko.RSAKey.from_private_key_file(self.private_key_path)
                self.client.connect(
                    hostname=self.hostname,
                    port=self.port,
                    username=self.username,
                    pkey=private_key,
                    timeout=30
                )
            elif self.password:
                self.client.connect(
                    hostname=self.hostname,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    timeout=30
                )
            else:
                raise ValueError("Either password or private_key_path must be provided")
                
            yield self.client
            
        except Exception as e:
            print(f"❌ SSH connection failed: {e}")
            raise
        finally:
            if self.client:
                self.client.close()

    def execute_command(self, command, timeout=30, use_sudo=False):
        """Execute command with improved error handling."""
        try:
            needs_sudo = command.strip().startswith('sudo') or use_sudo
            
            if needs_sudo and self.password:
                if not command.strip().startswith('sudo'):
                    command = f"sudo -S {command}"
                elif 'sudo -S' not in command:
                    command = command.replace('sudo', 'sudo -S', 1)
                
                stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
                stdin.write(self.password + '\n')
                stdin.flush()
                stdin.close()
            else:
                stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
            
            output = stdout.read().decode('utf-8').strip()
            error = stderr.read().decode('utf-8').strip()
            exit_code = stdout.channel.recv_exit_status()
            
            return {
                'success': exit_code == 0,
                'output': output,
                'error': error,
                'exit_code': exit_code
            }
            
        except Exception as e:
            return {
                'success': False,
                'output': '',
                'error': str(e),
                'exit_code': -1
            }

    def execute_with_fallback(self, command, timeout=30):
        """Execute command with fallback for permission issues."""
        result = self.execute_command(command, timeout)
        
        if not result['success'] and command.strip().startswith('sudo '):
            # Try without sudo
            fallback_command = command.replace('sudo ', '', 1)
            fallback_result = self.execute_command(fallback_command, timeout)
            if fallback_result['success']:
                fallback_result['warning'] = "Executed without sudo privileges"
                return fallback_result
        
        return result

    def get_basic_monitoring_data(self):
        """Get essential system monitoring data for performance analysis."""
        commands = {
            # System identification
            'hostname': 'hostname -f',
            'uptime': 'uptime',
            'ubuntu_version': 'lsb_release -d',
            'kernel': 'uname -r',
            
            # CPU & Memory Load
            'cpu_info': 'lscpu | grep -E "Model name|CPU\\(s\\):|Architecture|Thread"',
            'load_average': 'cat /proc/loadavg',
            'cpu_usage': 'top -bn1 | grep "Cpu(s)" | awk \'{print "CPU Usage: " $2 " user, " $4 " system, " $8 " idle"}\'',
            'memory_usage': 'free -h',
            'memory_stats': 'cat /proc/meminfo | head -10',
            
            # Disk usage
            'disk_usage': 'df -h | grep -vE "tmpfs|devtmpfs|udev"',
            'disk_io': 'iostat -x 1 2 | tail -n +7 | head -10',
            'disk_space_alert': 'df -h | awk \'NR>1 {gsub(/%/,"",$5); if($5>85) print $0 " - WARNING: " $5 "% full"}\'',
            
            # Network
            'network_interfaces': 'ip -4 addr show | grep -E "inet|^[0-9]"',
            'network_stats': 'cat /proc/net/dev | grep -v "lo:" | head -5',
            'network_connections': 'ss -tuln | head -15',
            
            # Top processes (performance impact)
            'top_cpu_processes': 'ps aux --sort=-%cpu | head -8',
            'top_memory_processes': 'ps aux --sort=-%mem | head -8',
            'process_count': 'ps aux | wc -l',
            
            # System services status
            'failed_services': 'systemctl --failed --no-pager -l',
            
            # Quick system health checks
            'dmesg_errors': 'dmesg -T | tail -20 | grep -i "error\\|fail\\|warning" | tail -5',
            'system_load_check': 'cat /proc/loadavg | awk \'{if($1>$(nproc)) print "HIGH LOAD WARNING: " $1 " (CPUs: " $(nproc) ")"; else print "Load OK: " $1}\'',
        }
        
        results = {}
        for key, cmd in commands.items():
            result = self.execute_with_fallback(cmd)
            results[key] = {
                'output': result['output'] if result['success'] else f"Error: {result['error']}",
                'success': result['success'],
                'warning': result.get('warning', '')
            }
        
        return results

    def get_security_monitoring_data(self):
        """Get focused security data for Ubuntu systems."""
        commands = {
            # Authentication logs
            'recent_auth_failures': 'sudo grep "authentication failure\\|Failed password" /var/log/auth.log | tail -10 2>/dev/null || grep "authentication failure\\|Failed password" /var/log/secure | tail -10 2>/dev/null || echo "Auth logs not accessible"',
            'recent_successful_logins': 'sudo grep "Accepted password\\|Accepted publickey" /var/log/auth.log | tail -8 2>/dev/null || echo "Login logs not accessible"',
            'sudo_activity': 'sudo grep "sudo:" /var/log/auth.log | tail -10 2>/dev/null || echo "Sudo logs not accessible"',
            
            # Current user activity
            'current_users': 'who -u',
            'last_logins': 'last -n 8',
            'login_history': 'lastlog | grep -v "Never" | head -10',
            
            # Process security analysis
            'suspicious_processes': 'ps aux | grep -E "(nc|netcat|socat|nmap|tcpdump)" | grep -v grep',
            'root_processes': 'ps -eo user,pid,ppid,cmd | grep "^root" | grep -vE "(kthreadd|ksoftirqd|init|systemd|dbus)" | head -10',
            'unusual_connections': 'ss -tuln | grep -vE ":22|:80|:443|:53" | grep LISTEN',
            
            # User account security
            'password_policy': 'sudo chage -l $(whoami) 2>/dev/null | head -5 || echo "Password policy not accessible"',
            'user_groups': 'groups',
            'sudo_privileges': 'sudo -l -n 2>&1 | head -5 || echo "Cannot check sudo privileges"',
            
            # Network security
            'ssh_config_check': 'sudo grep -E "PermitRootLogin|PasswordAuthentication|Port" /etc/ssh/sshd_config 2>/dev/null || echo "SSH config not accessible"',
            'firewall_status': 'sudo ufw status 2>/dev/null || iptables -L -n | head -10 2>/dev/null || echo "Firewall status not accessible"',
            'open_ports': 'ss -tuln | grep LISTEN | awk \'{print $5}\' | sort | uniq',
            
        }
        
        results = {}
        for key, cmd in commands.items():
            result = self.execute_with_fallback(cmd, timeout=45)
            results[key] = {
                'output': result['output'] if result['success'] else f"Error: {result['error']}",
                'success': result['success'],
                'warning': result.get('warning', ''),
                'security_relevant': True
            }
        
        return results

    def get_basic_report(self):
        """Get comprehensive basic monitoring report."""
        try:
            with self.ssh_connection():
                print(f"Connected to {self.hostname} for basic monitoring")
                
                report = {
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
                    'hostname': self.hostname,
                    'connection_status': 'Connected',
                    'monitoring_type': 'basic_performance',
                    'data': self.get_basic_monitoring_data()
                }
                return report
            
        except Exception as e:
            return {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
                'hostname': self.hostname,
                'connection_status': f'Failed: {str(e)}',
                'error': str(e),
                'monitoring_type': 'basic_performance'
            }

    def get_security_report(self):
        """Get focused security monitoring report."""
        try:
            with self.ssh_connection():
                print(f"Connected to {self.hostname} for security monitoring")
                
                report = {
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
                    'hostname': self.hostname,
                    'connection_status': 'Connected',
                    'monitoring_type': 'security_analysis',
                    'data': self.get_security_monitoring_data()
                }
                return report
            
        except Exception as e:
            return {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
                'hostname': self.hostname,
                'connection_status': f'Failed: {str(e)}',
                'error': str(e),
                'monitoring_type': 'security_analysis'
            }

def format_basic_report_for_ai(report):
    """Format basic monitoring report for AI analysis."""
    if 'error' in report:
        return f"SSH Connection Failed: {report['error']}"

    data = report.get('data', {})
    
    formatted_report = f"""
UBUNTU SYSTEM PERFORMANCE MONITORING
===================================
Hostname: {report.get('hostname', 'Unknown')}
Timestamp: {report.get('timestamp', 'Unknown')}
Connection: {report.get('connection_status', 'Unknown')}

SYSTEM INFORMATION:
------------------
Hostname: {data.get('hostname', {}).get('output', 'N/A')}
Uptime: {data.get('uptime', {}).get('output', 'N/A')}
Ubuntu Version: {data.get('ubuntu_version', {}).get('output', 'N/A')}
Kernel: {data.get('kernel', {}).get('output', 'N/A')}

CPU & MEMORY & PERFORMANCE:
-----------------
CPU Info: {data.get('cpu_info', {}).get('output', 'N/A')}
Current Load: {data.get('load_average', {}).get('output', 'N/A')}
CPU Usage: {data.get('cpu_usage', {}).get('output', 'N/A')}
Load Check: {data.get('system_load_check', {}).get('output', 'N/A')}
Memory Usage: {data.get('memory_usage', {}).get('output', 'N/A')}
Memory Stats: {data.get('memory_stats', {}).get('output', 'N/A')}

DISK USAGE:
----------
Disk Usage: {data.get('disk_usage', {}).get('output', 'N/A')}
Disk Space Alerts: {data.get('disk_space_alert', {}).get('output', 'No alerts')}

NETWORK STATUS:
--------------
Network Interfaces: {data.get('network_interfaces', {}).get('output', 'N/A')}
Active Connections: {data.get('network_connections', {}).get('output', 'N/A')}

TOP PROCESSES:
-------------
Top CPU Processes:
{data.get('top_cpu_processes', {}).get('output', 'N/A')}

Top Memory Processes:
{data.get('top_memory_processes', {}).get('output', 'N/A')}
Total Processes: {data.get('process_count', {}).get('output', 'N/A')}

SYSTEM SERVICES:
---------------
Failed Services: {data.get('failed_services', {}).get('output', 'None')}

SYSTEM HEALTH:
-------------
Recent System Errors: {data.get('dmesg_errors', {}).get('output', 'None found')}

ANALYSIS FOCUS AREAS:
- Identify performance bottlenecks (CPU, RAM, disk)
- Check for services that may be consuming excessive resources
- Look for any concerning patterns in system behavior
- Suggest immediate actions if critical issues are found
- Provide incident triage priority (HIGH/MEDIUM/LOW)
"""
    return formatted_report


def format_security_report_for_ai(report):
    """Format security monitoring report for AI analysis."""
    if 'error' in report:
        return f"SSH Connection Failed: {report['error']}"

    data = report.get('data', {})
    
    formatted_report = f"""
UBUNTU SYSTEM SECURITY ANALYSIS
==============================
Hostname: {report.get('hostname', 'Unknown')}
Timestamp: {report.get('timestamp', 'Unknown')}
Connection: {report.get('connection_status', 'Unknown')}

AUTHENTICATION SECURITY:
-----------------------
Recent Login Failures:
{data.get('recent_auth_failures', {}).get('output', 'N/A')}

Recent Successful Logins:
{data.get('recent_successful_logins', {}).get('output', 'N/A')}

Sudo Activity:
{data.get('sudo_activity', {}).get('output', 'N/A')}

USER ACTIVITY:
-------------
Current Users: {data.get('current_users', {}).get('output', 'N/A')}
Recent Logins: {data.get('last_logins', {}).get('output', 'N/A')}
Login History: {data.get('login_history', {}).get('output', 'N/A')}
User Groups: {data.get('user_groups', {}).get('output', 'N/A')}
Password Policy : {data.get('password_policy', {}).get('output', 'N/A')}
Sudo Privileges : {data.get('sudo_privileges', {}).get('output', 'N/A')}

PROCESS SECURITY:
----------------
Suspicious Processes:
{data.get('suspicious_processes', {}).get('output', 'None found')}

Root Processes (non-system):
{data.get('root_processes', {}).get('output', 'N/A')}

NETWORK SECURITY:
----------------
Unusual Network Connections:
{data.get('unusual_connections', {}).get('output', 'None found')}

Open Ports:
{data.get('open_ports', {}).get('output', 'N/A')}

SSH Configuration:
{data.get('ssh_config_check', {}).get('output', 'N/A')}

Firewall Status:
{data.get('firewall_status', {}).get('output', 'N/A')}

SECURITY ANALYSIS FOCUS:
- Identify potential security threats or compromises
- Check for unauthorized access attempts or suspicious activity  
- Review system configurations for security weaknesses
- Assess user access patterns and privileges
- Recommend immediate security actions if threats detected
- Provide security risk level (HIGH/MEDIUM/LOW)
"""
    return formatted_report

def get_vm_ssh_basic_analysis_by_ip(ip_address):
    """Get basic SSH monitoring data directly by IP address."""
    # Get SSH credentials from environment
    ssh_username = os.environ.get("LINUX_SSH_USER")
    ssh_password = os.environ.get("LINUX_SSH_PASS")
    ssh_private_key_path = os.environ.get("LINUX_SSH_KEY")
    ssh_port = int(os.environ.get("LINUX_SSH_PORT", 22))

    if not ssh_username:
        return "No SSH username configured"
    
    if not ssh_password and not ssh_private_key_path:
        return "No SSH authentication method configured"
    
    print(f"Connecting directly to {ip_address} for basic monitoring...")
    
    try:
        monitor = SSHMonitor(
            hostname=ip_address,
            username=ssh_username,
            password=ssh_password,
            private_key_path=ssh_private_key_path,
            port=ssh_port
        )
        
        report = monitor.get_basic_report()
        
        if 'error' in report:
            return f"SSH connection failed: {report['error']}"
        print(format_basic_report_for_ai(report))
        return format_basic_report_for_ai(report)
        
    except Exception as e:
        return f"SSH basic monitoring failed: {str(e)}"

def get_vm_ssh_security_analysis_by_ip(ip_address):
    """Get security SSH monitoring data directly by IP address."""
    # Get SSH credentials from environment
    ssh_username = os.environ.get("LINUX_SSH_USER")
    ssh_password = os.environ.get("LINUX_SSH_PASS")
    ssh_private_key_path = os.environ.get("LINUX_SSH_KEY")
    ssh_port = int(os.environ.get("LINUX_SSH_PORT", 22))

    if not ssh_username:
        return "No SSH username configured"
    
    if not ssh_password and not ssh_private_key_path:
        return "No SSH authentication method configured"
    
    print(f"Connecting directly to {ip_address} for security analysis...")
    
    try:
        monitor = SSHMonitor(
            hostname=ip_address,
            username=ssh_username,
            password=ssh_password,
            private_key_path=ssh_private_key_path,
            port=ssh_port
        )
        
        report = monitor.get_security_report()
        
        if 'error' in report:
            return f"SSH connection failed: {report['error']}"
        print(format_security_report_for_ai(report))
        return format_security_report_for_ai(report)
        
    except Exception as e:
        return f"SSH security monitoring failed: {str(e)}"
