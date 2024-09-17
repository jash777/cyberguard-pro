import logging
from logging.handlers import RotatingFileHandler
from flask import render_template, request, jsonify, session
from database import create_db_connection
from api import make_api_request
from datetime import datetime
import random
from functools import wraps

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Create a file handler
file_handler = RotatingFileHandler('debug.log', maxBytes=10485760, backupCount=5)
file_handler.setLevel(logging.DEBUG)

# Create a formatter
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)

# Add the file handler to the logger
logger.addHandler(file_handler)

def db_connection_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        logger.debug(f"Establishing database connection for function: {f.__name__}")
        connection = create_db_connection()
        if not connection:
            logger.error("Database connection error")
            return jsonify({'error': 'Database connection error'}), 500
        return f(connection, *args, **kwargs)
    return decorated_function

def agent_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        logger.debug(f"Checking for selected agent in function: {f.__name__}")
        if 'selected_agent' not in session:
            logger.warning("Attempted to access agent-specific function without a selected agent")
            return jsonify({'error': 'No agent selected'}), 400
        return f(*args, **kwargs)
    return decorated_function

def index():
    logger.debug("Rendering index page")
    return render_template('index.html')

@db_connection_required
def agents(connection):
    logger.debug("Fetching agents from database")
    try:
        with connection.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT * FROM agents")
            agents = cursor.fetchall()
        logger.info(f"Successfully fetched {len(agents)} agents")
        return render_template('agents.html', agents=agents)
    except Exception as e:
        logger.error(f"Error in agents view: {str(e)}")
        return jsonify({'error': 'An error occurred while fetching agents'}), 500

@db_connection_required
def select_agent(connection, agent_id):
    logger.info(f"Selecting agent with ID: {agent_id}")
    try:
        with connection.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT * FROM agents WHERE id = %s", (agent_id,))
            agent = cursor.fetchone()
        
        if agent:
            session['selected_agent_id'] = agent_id
            session['selected_agent'] = agent['ip_address']
            session['selected_agent_name'] = agent['name']
            logger.info(f"Agent selected successfully: {agent['name']} ({agent['ip_address']})")
            return jsonify({'message': 'Agent selected successfully', 'agent': agent['name']}), 200
        else:
            logger.warning(f"Agent not found with ID: {agent_id}")
            return jsonify({'error': 'Agent not found'}), 404
    except Exception as e:
        logger.error(f"Error in select_agent: {str(e)}")
        return jsonify({'error': 'An error occurred while selecting the agent'}), 500

def users():
    logger.debug("Fetching users from agent")
    response, status_code = make_api_request('users')
    logger.info(f"Users API request status code: {status_code}")
    return render_template('users.html', users=response.get('users', []), error=response.get('error') if status_code != 200 else None)

def applications():
    logger.debug("Fetching applications from agent")
    response, status_code = make_api_request('applications')
    logger.info(f"Applications API request status code: {status_code}")
    return render_template('applications.html', applications=response.get('applications', []), error=response.get('error') if status_code != 200 else None)

@db_connection_required
def manage_agents(connection):
    logger.debug(f"Managing agents: {request.method}")
    try:
        with connection.cursor(dictionary=True) as cursor:
            if request.method == 'GET':
                cursor.execute("SELECT * FROM agents")
                agents = cursor.fetchall()
                logger.info(f"Fetched {len(agents)} agents")
                return jsonify(agents)
            elif request.method == 'POST':
                data = request.json
                query = "INSERT INTO agents (name, ip_address, status) VALUES (%s, %s, %s)"
                cursor.execute(query, (data['name'], data['ip_address'], 'Unknown'))
                connection.commit()
                logger.info(f"Added new agent: {data['name']} ({data['ip_address']})")
                return jsonify({'message': 'Agent added successfully'}), 201
            elif request.method == 'DELETE':
                agent_id = request.args.get('id')
                cursor.execute("DELETE FROM agents WHERE id = %s", (agent_id,))
                connection.commit()
                logger.info(f"Removed agent with ID: {agent_id}")
                return jsonify({'message': 'Agent removed successfully'}), 200
    except Exception as e:
        logger.error(f"Error in manage_agents: {str(e)}")
        return jsonify({'error': 'An error occurred while managing agents'}), 500

@db_connection_required
def check_agent_status(connection, agent_id):
    logger.debug(f"Checking status for agent ID: {agent_id}")
    try:
        with connection.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT * FROM agents WHERE id = %s", (agent_id,))
            agent = cursor.fetchone()
            if not agent:
                logger.warning(f"Agent not found with ID: {agent_id}")
                return jsonify({'error': 'Agent not found'}), 404
            
            new_status = random.choice(['Active', 'Inactive', 'Unreachable'])
            cursor.execute("UPDATE agents SET status = %s, last_check = %s WHERE id = %s", 
                           (new_status, datetime.now(), agent_id))
            connection.commit()
        logger.info(f"Updated status for agent {agent_id} to {new_status}")
        return jsonify({'status': new_status})
    except Exception as e:
        logger.error(f"Error in check_agent_status: {str(e)}")
        return jsonify({'error': 'An error occurred while checking agent status'}), 500

@agent_required
def processes():
    logger.debug("Rendering processes page")
    return render_template('processes.html')

@agent_required
def get_processes():
    logger.info(f"Requesting processes from agent: {session['selected_agent']}")
    response, status_code = make_api_request('processes')
    
    if status_code != 200:
        logger.error(f"Error getting processes. Status code: {status_code}, Response: {response}")
        return jsonify({'error': 'Failed to retrieve processes'}), status_code
    
    if isinstance(response, dict) and 'processes' in response:
        processes = response['processes']
    elif isinstance(response, list):
        processes = response
    else:
        logger.error(f"Unexpected response format: {response}")
        return jsonify({'error': 'Unexpected response format'}), 500

    logger.info(f"Successfully retrieved {len(processes)} processes")
    return jsonify(processes), 200

def manage_users():
    logger.debug(f"Managing users: {request.method}")
    if request.method == 'GET':
        response, status_code = make_api_request('users')
    elif request.method == 'POST':
        response, status_code = make_api_request('add_user', method='POST', data=request.json)
    elif request.method == 'DELETE':
        response, status_code = make_api_request(f"remove_user?username={request.args.get('username')}", method='DELETE')
    else:
        logger.warning(f"Invalid method for manage_users: {request.method}")
        return jsonify({'error': 'Method not allowed'}), 405
    
    logger.info(f"Manage users API request status code: {status_code}")
    return jsonify(response), status_code

@agent_required
def get_applications():
    logger.debug("Fetching applications from agent")
    try:
        response, status_code = make_api_request('applications')
        if status_code == 200:
            # Ensure the response is in the correct format
            if isinstance(response, list):
                applications = response
            elif isinstance(response, dict) and 'applications' in response:
                applications = response['applications']
            else:
                applications = []
            
            # Format the applications data
            formatted_applications = [
                {'name': app, 'version': 'Unknown'} for app in applications
            ]
            
            logger.info(f"Successfully retrieved {len(formatted_applications)} applications")
            return jsonify({'applications': formatted_applications}), 200
        else:
            logger.error(f"Failed to retrieve applications. Status code: {status_code}")
            return jsonify({'error': 'Failed to retrieve applications'}), status_code
    except Exception as e:
        logger.exception("Unexpected error in get_applications route")
        return jsonify({'error': 'An unexpected error occurred while retrieving applications'}), 500

@agent_required
def block_port():
    logger.debug("Blocking port")
    port_data = request.json
    if not port_data or 'port' not in port_data:
        logger.warning("Port number is missing in the request")
        return jsonify({'status': 'error', 'message': 'Port number is required'}), 400

    port = port_data['port']
    if not isinstance(port, int) or port < 1 or port > 65535:
        logger.warning(f"Invalid port number: {port}")
        return jsonify({'status': 'error', 'message': 'Invalid port number'}), 400

    response, status_code = make_api_request('block_port', method='POST', data={'port': port})
    
    if status_code == 200:
        if isinstance(response, dict) and response.get('status') == 'success':
            logger.info(f"Successfully blocked port {port}")
            return jsonify({'status': 'success', 'message': f'Port {port} blocked successfully'}), 200
        else:
            logger.warning(f"Port {port} blocked with a note: {response.get('message', 'Unknown response from agent')}")
            return jsonify({'status': 'success', 'message': f'Port {port} blocked, but with a note: {response.get("message", "Unknown response from agent")}'})
    else:
        logger.error(f"Failed to block port {port}. Status code: {status_code}")
        return jsonify({'status': 'error', 'message': f'Failed to block port {port}. Agent response: {response.get("message", "Unknown error")}'}), status_code

@db_connection_required
def firewall(connection):
    logger.info("Entering firewall function")
    
    try:
        with connection.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT id, name, ip_address FROM agents")
            agents = cursor.fetchall()
        
        logger.info(f"Fetched {len(agents)} agents from the database")
        
        rules = {}
        selected_agent_id = session.get('selected_agent_id')
        selected_agent_ip = session.get('selected_agent')
        
        logger.info(f"Selected agent ID: {selected_agent_id}, IP: {selected_agent_ip}")
        
        if selected_agent_ip:
            logger.info(f"Attempting to fetch rules for agent {selected_agent_ip}")
            response, status_code = make_api_request('iptables_rules')
            logger.info(f"API response status code: {status_code}")
            
            if status_code == 200 and isinstance(response, dict) and response.get('status') == 'success':
                rules = response.get('rules', {})
                logger.info(f"Fetched firewall rules from the agent")
            else:
                logger.error(f"Failed to fetch firewall rules. Status code: {status_code}, Response: {response}")
        else:
            logger.warning("No agent selected, skipping firewall rules fetch")
        
        logger.info(f"Rendering firewall template with {len(agents)} agents and rules for {len(rules)} tables")
        return render_template('firewall.html', agents=agents, rules=rules, selected_agent_id=selected_agent_id)
    except Exception as e:
        logger.error(f"Error in firewall function: {str(e)}")
        return jsonify({'error': 'An error occurred while fetching firewall data'}), 500

@agent_required
def manage_firewall_rules():
    logger.debug(f"Managing firewall rules: {request.method}")
    if request.method == 'GET':
        response, status_code = make_api_request('iptables_rules')
        if status_code == 200 and isinstance(response, dict) and response.get('status') == 'success':
            logger.info("Successfully fetched firewall rules")
            return jsonify(response.get('rules', {})), 200
        logger.error(f"Failed to fetch firewall rules. Status code: {status_code}")
        return jsonify({'error': 'Failed to fetch firewall rules'}), status_code
    
    elif request.method == 'POST':
        rule_data = request.json
        logger.info(f"Applying new firewall rule: {rule_data}")
        response, status_code = make_api_request('apply-rules', method='POST', data={'rules': [rule_data]})
        return jsonify(response), status_code
    
    elif request.method == 'DELETE':
        rule_data = request.json
        logger.info(f"Removing firewall rule: {rule_data}")
        response, status_code = make_api_request('remove-rule', method='POST', data=rule_data)
        return jsonify(response), status_code
    
    else:
        logger.warning(f"Invalid method for manage_firewall_rules: {request.method}")
        return jsonify({'error': 'Method not allowed'}), 405

@db_connection_required
def fetch_and_reapply_rules(connection):
    logger.info("Fetching and reapplying firewall rules")
    try:
        with connection.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT * FROM firewall_rules")
            rules = cursor.fetchall()
        
        logger.info(f"Fetched {len(rules)} rules from database")
        response, status_code = make_api_request('apply-rules', method='POST', data={'rules': rules})
        
        if status_code != 200:
            logger.error(f"Failed to reapply rules. Status code: {status_code}, Response: {response}")
            return jsonify({'error': 'Failed to reapply rules'}), status_code
        
        logger.info("Successfully reapplied firewall rules")
        return jsonify({'message': 'Rules reapplied successfully'}), 200
    except Exception as e:
        logger.error(f"Error in fetch_and_reapply_rules: {str(e)}")
        return jsonify({'error': 'An error occurred while reapplying rules'}), 500

def get_selected_agent():
    logger.debug("Getting selected agent information")
    if 'selected_agent' in session and 'selected_agent_name' in session:
        logger.info(f"Selected agent: {session['selected_agent_name']} ({session['selected_agent']})")
        return jsonify({
            'selected_agent': {
                'name': session['selected_agent_name'],
                'ip_address': session['selected_agent']
            }
        })
    else:
        logger.warning("No agent selected")
        return jsonify({'selected_agent': None})