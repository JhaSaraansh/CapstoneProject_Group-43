from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask_cors import CORS
from models import db, bcrypt, User, Server, FirewallRule
from firewall_manager import FirewallManager
from server_manager import ServerManager
from config import Config
import logging

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Initialize extensions
    db.init_app(app)
    bcrypt.init_app(app)
    jwt = JWTManager(app)
    CORS(app)
    
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Create tables
    with app.app_context():
        db.create_all()
        
        # Create default admin user if not exists
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', email='admin@example.com')
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
    
    # Auth routes
    @app.route('/api/auth/login', methods=['POST'])
    def login():
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            access_token = create_access_token(identity=username)
            return jsonify(access_token=access_token), 200
            
        return jsonify({"msg": "Bad username or password"}), 401
        
    # Server routes
    @app.route('/api/servers', methods=['GET'])
    @jwt_required()
    def get_servers():
        servers = Server.query.all()
        for server in servers:
            ServerManager.update_server_status(server.id)
            
        return jsonify([{
            'id': s.id,
            'name': s.name,
            'ip_address': s.ip_address,
            'os_type': s.os_type,
            'status': s.status,
            'last_checked': s.last_checked.isoformat() if s.last_checked else None
        } for s in servers])
        
    @app.route('/api/servers', methods=['POST'])
    @jwt_required()
    def add_server():
        data = request.get_json()
        server = Server(
            name=data['name'],
            ip_address=data['ip_address'],
            os_type=data['os_type']
        )
        db.session.add(server)
        db.session.commit()
        return jsonify({'id': server.id}), 201
        
    @app.route('/api/servers/<int:server_id>', methods=['GET'])
    @jwt_required()
    def get_server(server_id):
        server = Server.query.get_or_404(server_id)
        ServerManager.update_server_status(server.id)
        return jsonify({
            'id': server.id,
            'name': server.name,
            'ip_address': server.ip_address,
            'os_type': server.os_type,
            'status': server.status,
            'last_checked': server.last_checked.isoformat() if server.last_checked else None
        })
        
    # Firewall routes
    @app.route('/api/servers/<int:server_id>/firewall', methods=['GET'])
    @jwt_required()
    def get_firewall_rules(server_id):
        server = Server.query.get_or_404(server_id)
        fm = FirewallManager(server)
        rules = fm.get_firewall_rules()
        return jsonify(rules)
        
    @app.route('/api/servers/<int:server_id>/firewall', methods=['POST'])
    @jwt_required()
    def add_firewall_rule(server_id):
        server = Server.query.get_or_404(server_id)
        data = request.get_json()
        
        # Add to database
        rule = FirewallRule(
            server_id=server_id,
            protocol=data['protocol'],
            port=data['port'],
            source=data['source'],
            action=data['action'],
            description=data.get('description', '')
        )
        db.session.add(rule)
        db.session.commit()
        
        # Apply to actual server
        fm = FirewallManager(server)
        success = fm.add_rule(
            data['protocol'],
            data['port'],
            data['source'],
            data['action'],
            data.get('description', '')
        )
        
        if success:
            return jsonify({'id': rule.id}), 201
        else:
            db.session.delete(rule)
            db.session.commit()
            return jsonify({'error': 'Failed to apply rule to server'}), 500
            
    @app.route('/api/servers/<int:server_id>/firewall/<int:rule_id>', methods=['DELETE'])
    @jwt_required()
    def delete_firewall_rule(server_id, rule_id):
        rule = FirewallRule.query.filter_by(id=rule_id, server_id=server_id).first_or_404()
        fm = FirewallManager(rule.server)
        success = fm.delete_rule(rule_id)
        
        if success:
            db.session.delete(rule)
            db.session.commit()
            return jsonify({'message': 'Rule deleted'}), 200
        else:
            return jsonify({'error': 'Failed to delete rule from server'}), 500
            
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=5000)