from flask import Flask, request, jsonify
from flask_socketio import SocketIO
from functools import wraps
import logging
import os
import json
from typing import Dict, Any, List
from main import IPTablesManager, SystemManager, ApplicationManager

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


def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if api_key != app.config['API_KEY']:
            return jsonify({'error': 'Invalid API key'}), 401
        return f(*args, **kwargs)
    return decorated_function

def validate_rule_data(rule_data: Dict[str, Any], required_fields: list) -> Dict[str, Any]:
    errors = {}
    for field in required_fields:
        if field not in rule_data:
            errors[field] = f"Missing required field: {field}"
        elif field == 'port' and not isinstance(rule_data[field], int):
            errors[field] = "Port must be an integer"
        elif field == 'protocol' and rule_data[field] not in ['tcp', 'udp']:
            errors[field] = "Protocol must be 'tcp' or 'udp'"
    return errors

@app.route('/apply-rules', methods=['POST'])
@require_api_key
def apply_rules():
    rules = request.json.get('rules', [])
    if not rules:
        return jsonify({'error': 'No rules provided'}), 400
    
    results = []
    for rule in rules:
        errors = validate_rule_data(rule, ['protocol', 'port', 'action'])
        if errors:
            results.append({'rule': rule, 'success': False, 'errors': errors})
        else:
            try:
                success = iptables_manager.add_rule(
                    protocol=rule['protocol'],
                    port=rule['port'],
                    action=rule['action'],
                    chain=rule.get('chain', 'INPUT'),
                    source_ip=rule.get('source_ip'),
                    destination_ip=rule.get('destination_ip'),
                    table=rule.get('table', 'filter')
                )
                results.append({'rule': rule, 'success': success})
            except Exception as e:
                results.append({'rule': rule, 'success': False, 'error': str(e)})
    
    return jsonify({'status': 'completed', 'results': results})

@app.route('/inbound_rule', methods=['POST'])
@require_api_key
def inbound_rules():
    inbound_rule_data = request.json.get('inbound_rule')
    if not inbound_rule_data:
        return jsonify({'error': 'No inbound rule data provided'}), 400
    
    errors = validate_rule_data(inbound_rule_data, ['protocol', 'port'])
    if errors:
        return jsonify({'error': errors}), 400
    
    try:
        success = iptables_manager.inbound_rule(inbound_rule_data)
        return jsonify({
            'status': 'success' if success else 'failed',
            'message': 'Inbound rule added successfully' if success else 'Failed to add inbound rule'
        })
    except Exception as e:
        logger.error(f"Error in inbound_rules: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/outbound_rule', methods=['POST'])
@require_api_key
def outbound_rules():
    outbound_rule_data = request.json.get('outbound_rule')
    if not outbound_rule_data:
        return jsonify({'error': 'No outbound rule data provided'}), 400
    
    errors = validate_rule_data(outbound_rule_data, ['protocol', 'port'])
    if errors:
        return jsonify({'error': errors}), 400
    
    try:
        success = iptables_manager.outbound_rule(outbound_rule_data)
        return jsonify({
            'status': 'success' if success else 'failed',
            'message': 'Outbound rule added successfully' if success else 'Failed to add outbound rule'
        })
    except Exception as e:
        logger.error(f"Error in outbound_rules: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/block_port', methods=['POST'])
@require_api_key
def block_port_route():
    port = request.json.get('port')
    protocol = request.json.get('protocol', 'tcp')
    
    if not port:
        return jsonify({"error": "port is required"}), 400
    
    errors = validate_rule_data({'port': port, 'protocol': protocol}, ['port', 'protocol'])
    if errors:
        return jsonify({"error": errors}), 400
    
    try:
        success = iptables_manager.block_port(port, protocol)
        return jsonify({
            "status": "success" if success else "failed",
            "message": f"Port {port} ({protocol}) blocked" if success else f"Failed to block port {port} ({protocol})"
        })
    except Exception as e:
        logger.error(f"Error in block_port_route: {e}")
        return jsonify({'error': str(e)}), 500

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

@app.route('/delete_rule', methods=['POST'])
@require_api_key
def delete_rule_route():
    rule_data = request.json
    if not rule_data or 'chain' not in rule_data or 'rule_spec' not in rule_data:
        return jsonify({'error': 'Invalid rule data provided'}), 400
    
    try:
        success = iptables_manager.delete_rule(
            chain=rule_data['chain'],
            rule_spec=rule_data['rule_spec'],
            table=rule_data.get('table', 'filter')
        )
        return jsonify({
            'status': 'success' if success else 'failed',
            'message': 'Rule deleted successfully' if success else 'Failed to delete rule'
        })
    except Exception as e:
        logger.error(f"Error in delete_rule_route: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/flush_chain', methods=['POST'])
@require_api_key
def flush_chain_route():
    chain = request.json.get('chain')
    table = request.json.get('table', 'filter')
    
    if not chain:
        return jsonify({'error': 'Chain name is required'}), 400
    
    try:
        success = iptables_manager.flush_chain(chain, table)
        return jsonify({
            'status': 'success' if success else 'failed',
            'message': f'Chain {chain} in table {table} flushed successfully' if success else f'Failed to flush chain {chain} in table {table}'
        })
    except Exception as e:
        logger.error(f"Error in flush_chain_route: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/save_rules', methods=['POST'])
@require_api_key
def save_rules_route():
    filename = request.json.get('filename')
    if not filename:
        return jsonify({'error': 'Filename is required'}), 400
    
    try:
        success = iptables_manager.save_rules(filename)
        return jsonify({
            'status': 'success' if success else 'failed',
            'message': f'Rules saved to {filename} successfully' if success else f'Failed to save rules to {filename}'
        })
    except Exception as e:
        logger.error(f"Error in save_rules_route: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/restore_rules', methods=['POST'])
@require_api_key
def restore_rules_route():
    filename = request.json.get('filename')
    if not filename:
        return jsonify({'error': 'Filename is required'}), 400
    
    try:
        success = iptables_manager.restore_rules(filename)
        return jsonify({
            'status': 'success' if success else 'failed',
            'message': f'Rules restored from {filename} successfully' if success else f'Failed to restore rules from {filename}'
        })
    except Exception as e:
        logger.error(f"Error in restore_rules_route: {e}")
        return jsonify({'error': str(e)}), 500

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