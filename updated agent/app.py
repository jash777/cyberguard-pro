from flask import Flask, request, jsonify
from flask_socketio import SocketIO
from functools import wraps
import logging
import os
import json
from typing import Dict, Any, List
from updatedrules import IPTablesManager, SystemManager, ApplicationManager

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

logging.basicConfig(filename='agent.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

iptables_manager = IPTablesManager()
system_manager = SystemManager()
app_manager = ApplicationManager()

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if api_key != os.environ.get('API_KEY', 'alpha'):
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def agent_status():
    return "<h1>Agent is running</h1>"

@app.route('/apply-rules', methods=['POST'])
@require_api_key
def apply_rules():
    rules = request.json.get('rules', [])
    results = []
    for rule in rules:
        success = iptables_manager.add_rule(
            protocol=rule['protocol'],
            port=rule['destination_port'],
            action=rule['action']
        )
        results.append({'rule': rule, 'success': success})
    return jsonify({'status': 'completed', 'results': results})

@app.route('/inbound_rule', methods=['POST'])
@require_api_key
def inbound_rules():
    inbound_rule_data = request.json.get('inbound_rule')
    if not inbound_rule_data:
        return jsonify({'error': 'No inbound rule data provided'}), 400
    success = iptables_manager.inbound_rule(inbound_rule_data)
    return jsonify({'status': 'success' if success else 'failed'})

@app.route('/outbound_rule', methods=['POST'])
@require_api_key
def outbound_rules():
    outbound_rule_data = request.json.get('outbound_rule')
    if not outbound_rule_data:
        return jsonify({'error': 'No outbound rule data provided'}), 400
    success = iptables_manager.outbound_rule(outbound_rule_data)
    return jsonify({'status': 'success' if success else 'failed'})

@app.route('/block_port', methods=['POST'])
@require_api_key
def block_port_route():
    port = request.json.get('port')
    if not port:
        return jsonify({"error": "port is required"}), 400
    try:
        port = int(port)
        success = iptables_manager.block_port(port)
        return jsonify({"message": f"port {port} blocked" if success else f"Failed to block port {port}"})
    except ValueError:
        return jsonify({"error": "port must be a number"}), 400

@app.route('/iptables_rules')
@require_api_key
def get_iptables_rules_route():
    try:
        rules = iptables_manager.get_rules()
        return jsonify({
            'status': 'success',
            'rules': rules
        })
    except Exception as e:
        logger.error(f"Unexpected error in get_iptables_rules route: {e}")
        return jsonify({
            'status': 'error',
            'message': 'An unexpected error occurred while retrieving iptables rules',
            'error': str(e)
        }), 500

@app.route('/processes')
@require_api_key
def get_processes():
    return jsonify(system_manager.get_running_processes())

@app.route('/add_user', methods=['POST'])
@require_api_key
def add_user_route():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    groups = data.get('groups', [])

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    success, message = system_manager.add_user(username, password, groups)
    return jsonify({'message': message}), 200 if success else 400

@app.route('/remove_user', methods=['POST'])
@require_api_key
def remove_user_route():
    username = request.json.get('username')
    if not username:
        return jsonify({'error': 'Username is required'}), 400

    success, message = system_manager.remove_user(username)
    return jsonify({'message': message}), 200 if success else 400

@app.route('/users', methods=['GET'])
@require_api_key
def get_users_route():
    return jsonify({'users': system_manager.get_non_default_users()})

@app.route('/applications')
@require_api_key
def get_applications():
    try:
        applications = app_manager.get_installed_applications()
        return jsonify({
            'status': 'success',
            'count': len(applications),
            'applications': applications
        })
    except Exception as e:
        logger.error(f"Error in get_applications route: {e}")
        return jsonify({
            'status': 'error',
            'message': 'An error occurred while retrieving installed applications',
            'error': str(e)
        }), 500

def send_process_data():
    while True:
        socketio.emit('process_data', json.dumps(system_manager.get_running_processes()))
        socketio.sleep(60)  # Update every 60 seconds

@socketio.on('connect')
def handle_connect():
    socketio.start_background_task(send_process_data)

if __name__ == "__main__":
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)