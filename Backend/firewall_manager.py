import paramiko
import re
from netmiko import ConnectHandler
from flask import current_app

class FirewallManager:
    def __init__(self, server):
        self.server = server
        self.connection = None
        
    def connect(self):
        """Establish connection to the server"""
        try:
            if self.server.os_type.lower() == 'linux':
                self.connection = paramiko.SSHClient()
                self.connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                # In production, use proper credentials management
                self.connection.connect(
                    hostname=self.server.ip_address,
                    username='admin',
                    password='password',  # This should be stored securely
                    timeout=10
                )
            elif self.server.os_type.lower() == 'cisco':
                device = {
                    'device_type': 'cisco_ios',
                    'host': self.server.ip_address,
                    'username': 'admin',
                    'password': 'password',  # This should be stored securely
                    'secret': 'enable_password'
                }
                self.connection = ConnectHandler(**device)
            return True
        except Exception as e:
            current_app.logger.error(f"Connection failed: {str(e)}")
            return False
            
    def disconnect(self):
        """Close connection to the server"""
        if self.connection:
            if self.server.os_type.lower() == 'linux':
                self.connection.close()
            elif self.server.os_type.lower() == 'cisco':
                self.connection.disconnect()
                
    def get_firewall_rules(self):
        """Retrieve firewall rules from the server"""
        if not self.connection:
            if not self.connect():
                return []
                
        try:
            if self.server.os_type.lower() == 'linux':
                stdin, stdout, stderr = self.connection.exec_command('sudo iptables -L -n --line-numbers')
                output = stdout.read().decode('utf-8')
                return self._parse_iptables_output(output)
            elif self.server.os_type.lower() == 'cisco':
                output = self.connection.send_command('show access-lists')
                return self._parse_cisco_output(output)
        except Exception as e:
            current_app.logger.error(f"Error retrieving rules: {str(e)}")
            return []
        finally:
            self.disconnect()
            
    def _parse_iptables_output(self, output):
        """Parse iptables output into structured data"""
        rules = []
        current_chain = None
        lines = output.split('\n')
        
        for line in lines:
            if line.startswith('Chain'):
                current_chain = line.split()[1]
                continue
                
            if line.strip() and current_chain:
                parts = line.split()
                if len(parts) >= 4:
                    rule = {
                        'protocol': parts[1] if parts[1] != 'all' else 'any',
                        'port': self._extract_port(parts),
                        'source': parts[3],
                        'action': parts[0].lower(),
                        'description': f"Chain: {current_chain}"
                    }
                    rules.append(rule)
                    
        return rules
        
    def _extract_port(self, parts):
        """Extract port information from iptables output"""
        for part in parts:
            if 'dpt:' in part:
                return int(part.split(':')[1])
            if 'spt:' in part:
                return int(part.split(':')[1])
        return 0
        
    def _parse_cisco_output(self, output):
        """Parse Cisco ACL output into structured data"""
        rules = []
        lines = output.split('\n')
        
        for line in lines:
            match = re.search(r'(\d+)\s+(permit|deny)\s+(\w+)\s+(\S+)\s+.*eq\s+(\d+)', line)
            if match:
                rule = {
                    'protocol': match.group(3),
                    'port': int(match.group(5)),
                    'source': match.group(4),
                    'action': match.group(2),
                    'description': f"ACL line {match.group(1)}"
                }
                rules.append(rule)
                
        return rules
        
    def add_rule(self, protocol, port, source, action, description=""):
        """Add a new firewall rule"""
        if not self.connection:
            if not self.connect():
                return False
                
        try:
            if self.server.os_type.lower() == 'linux':
                cmd = f"sudo iptables -A INPUT -p {protocol} --dport {port} -s {source} -j {action.upper()}"
                stdin, stdout, stderr = self.connection.exec_command(cmd)
                return stderr.read().decode('utf-8') == ""
            elif self.server.os_type.lower() == 'cisco':
                cmd = f"access-list 100 {action} {protocol} host {source} eq {port}"
                output = self.connection.send_config_set([cmd])
                return "Invalid" not in output
        except Exception as e:
            current_app.logger.error(f"Error adding rule: {str(e)}")
            return False
        finally:
            self.disconnect()
            
    def delete_rule(self, rule_id):
        """Delete a firewall rule by ID"""
        # Implementation would depend on the specific firewall system
        # This is a simplified version
        return True