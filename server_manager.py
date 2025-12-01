import socket
import subprocess
import platform
from datetime import datetime
from models import db, Server

class ServerManager:
    @staticmethod
    def ping_server(ip_address):
        """Check if server is reachable"""
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '1', ip_address]
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return result.returncode == 0
        except Exception:
            return False
            
    @staticmethod
    def check_ssh(ip_address, port=22, timeout=5):
        """Check if SSH is accessible"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip_address, port))
            sock.close()
            return result == 0
        except Exception:
            return False
            
    @staticmethod
    def update_server_status(server_id):
        """Update server status in database"""
        server = Server.query.get(server_id)
        if not server:
            return False
            
        is_reachable = ServerManager.ping_server(server.ip_address)
        has_ssh = ServerManager.check_ssh(server.ip_address)
        
        if is_reachable and has_ssh:
            server.status = 'online'
        elif is_reachable:
            server.status = 'partial'
        else:
            server.status = 'offline'
            
        server.last_checked = datetime.utcnow()
        db.session.commit()
        return True