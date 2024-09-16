from flask import render_template, request, jsonify, session
from database import create_db_connection
from api import make_api_request
from datetime import datetime
import random
import logging

def index():
    return render_template('index.html')

def agents():
    connection = create_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM agents")
        agents = cursor.fetchall()
        cursor.close()
        connection.close()
        return render_template('agents.html', agents=agents)
    return "Database connection error", 500

def select_agent(agent_id):
    logging.info(f"Selecting agent with ID: {agent_id}")
    try:
        connection = create_db_connection()
        if connection:
            cursor = connection.cursor(dictionary=True)
            cursor.execute("SELECT * FROM agents WHERE id = %s", (agent_id,))
            agent = cursor.fetchone()
            cursor.close()
            connection.close()
            
            if agent:
                session['selected_agent_id'] = agent_id
                session['selected_agent'] = agent['ip_address']
                session['selected_agent_name'] = agent['name']
                logging.info(f"Agent selected successfully: {agent['name']} ({agent['ip_address']})")
                return jsonify({'message': 'Agent selected successfully', 'agent': agent['name']}), 200
            else:
                logging.warning(f"Agent not found with ID: {agent_id}")
                return jsonify({'error': 'Agent not found'}), 404
        else:
            logging.error("Database connection error in select_agent")
            return jsonify({'error': 'Database connection error'}), 500
    except Exception as e:
        logging.error(f"Error in select_agent: {str(e)}")
        return jsonify({'error': str(e)}), 500

def users():
    response, status_code = make_api_request('users')
    if status_code == 200:
        return render_template('users.html', users=response.get('users', []))
    else:
        return render_template('users.html', users=[], error=response.get('error', 'An error occurred'))

def applications():
    response, status_code = make_api_request('applications')
    if status_code == 200:
        return render_template('applications.html', applications=response.get('applications', []))
    else:
        return render_template('applications.html', applications=[], error=response.get('error', 'An error occurred'))

# def firewall():
#     connection = create_db_connection()
#     if connection:
#         cursor = connection.cursor(dictionary=True)
#         cursor.execute("SELECT * FROM firewall_rules")
#         rules = cursor.fetchall()
#         cursor.close()
#         connection.close()
#         return render_template('firewall.html', rules=rules)
#     return "Database connection error", 500

def manage_agents():
    connection = create_db_connection()
    if not connection:
        return jsonify({'error': 'Database connection error'}), 500

    cursor = connection.cursor(dictionary=True)

    if request.method == 'GET':
        cursor.execute("SELECT * FROM agents")
        agents = cursor.fetchall()
        cursor.close()
        connection.close()
        return jsonify(agents)

    elif request.method == 'POST':
        data = request.json
        query = "INSERT INTO agents (name, ip_address, status) VALUES (%s, %s, %s)"
        values = (data['name'], data['ip_address'], 'Unknown')
        cursor.execute(query, values)
        connection.commit()
        cursor.close()
        connection.close()
        return jsonify({'message': 'Agent added successfully'}), 201

    elif request.method == 'DELETE':
        agent_id = request.args.get('id')
        query = "DELETE FROM agents WHERE id = %s"
        cursor.execute(query, (agent_id,))
        connection.commit()
        cursor.close()
        connection.close()
        return jsonify({'message': 'Agent removed successfully'}), 200

def check_agent_status(agent_id):
    connection = create_db_connection()
    if not connection:
        return jsonify({'error': 'Database connection error'}), 500

    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM agents WHERE id = %s", (agent_id,))
    agent = cursor.fetchone()

    if not agent:
        cursor.close()
        connection.close()
        return jsonify({'error': 'Agent not found'}), 404
    
    new_status = random.choice(['Active', 'Inactive', 'Unreachable'])
    
    update_query = "UPDATE agents SET status = %s, last_check = %s WHERE id = %s"
    cursor.execute(update_query, (new_status, datetime.now(), agent_id))
    connection.commit()

    cursor.close()
    connection.close()
    return jsonify({'status': new_status})

def processes():
    return render_template('processes.html')

def get_processes():
    if 'selected_agent' not in session:
        logging.warning("Attempted to get processes without a selected agent")
        return jsonify({'error': 'No agent selected'}), 400
    
    logging.info(f"Requesting processes from agent: {session['selected_agent']}")
    response, status_code = make_api_request('processes')
    
    if status_code != 200:
        logging.error(f"Error getting processes. Status code: {status_code}, Response: {response}")
        return jsonify({'error': 'Failed to retrieve processes'}), status_code
    
    return jsonify(response), status_code

def manage_users():
    if request.method == 'GET':
        response, status_code = make_api_request('users')
        return jsonify(response), status_code
    elif request.method == 'POST':
        response, status_code = make_api_request('add_user', method='POST', data=request.json)
        return jsonify(response), status_code
    elif request.method == 'DELETE':
        response, status_code = make_api_request(f"remove_user?username={request.args.get('username')}", method='DELETE')
        return jsonify(response), status_code

def get_applications():
    response, status_code = make_api_request('applications')
    return jsonify(response), status_code

# def manage_firewall_rules():
#     if request.method == 'GET':
#         connection = create_db_connection()
#         if not connection:
#             return jsonify({'error': 'Database connection error'}), 500

#         cursor = connection.cursor(dictionary=True)
#         cursor.execute("SELECT * FROM firewall_rules")
#         rules = cursor.fetchall()
#         cursor.close()
#         connection.close()
#         return jsonify(rules)

#     elif request.method == 'POST':
#         response, status_code = make_api_request('apply-rules', method='POST', data={'rules': [request.json]})
#         return jsonify(response), status_code

#     elif request.method == 'DELETE':
#         connection = create_db_connection()
#         if not connection:
#             return jsonify({'error': 'Database connection error'}), 500

#         cursor = connection.cursor(dictionary=True)
#         rule_id = request.args.get('id')
#         query = "DELETE FROM firewall_rules WHERE id = %s"
#         cursor.execute(query, (rule_id,))
#         connection.commit()
#         cursor.close()
#         connection.close()
#         return jsonify({'message': 'Firewall rule removed successfully'}), 200


# def firewall():
#     logging.info("Entering firewall function")
    
#     # Fetch agents
#     agents = []
#     connection = create_db_connection()
#     if connection:
#         try:
#             cursor = connection.cursor(dictionary=True)
#             cursor.execute("SELECT id, name, ip_address FROM agents")
#             agents = cursor.fetchall()
#             logging.info(f"Fetched {len(agents)} agents from the database")
#         except Exception as e:
#             logging.error(f"Error fetching agents: {str(e)}")
#         finally:
#             if cursor:
#                 cursor.close()
#             connection.close()
#     else:
#         logging.error("Failed to create database connection")

#     # Fetch firewall rules
#     rules = []
#     selected_agent_id = session.get('selected_agent_id')
#     selected_agent_ip = session.get('selected_agent')
    
#     logging.info(f"Selected agent ID: {selected_agent_id}, IP: {selected_agent_ip}")
    
#     if selected_agent_ip:
#         logging.info(f"Attempting to fetch rules for agent {selected_agent_ip}")
#         response, status_code = make_api_request('iptables_rules')
#         logging.info(f"API response status code: {status_code}")
#         logging.info(f"API response content: {response}")
        
#         if status_code == 200 and isinstance(response, dict) and response.get('status') == 'success':
#             rules = response.get('rules', [])
#             logging.info(f"Fetched {len(rules)} firewall rules from the agent")
#         else:
#             logging.error(f"Failed to fetch firewall rules. Status code: {status_code}, Response: {response}")
#     else:
#         logging.warning("No agent selected, skipping firewall rules fetch")

#     logging.info(f"Rendering firewall template with {len(agents)} agents and {len(rules)} rules")
#     return render_template('firewall.html', agents=agents, rules=rules, selected_agent_id=selected_agent_id)

# def manage_firewall_rules():
#     if request.method == 'GET':
#         response, status_code = make_api_request('iptables_rules')
#         if status_code == 200 and isinstance(response, dict) and response.get('status') == 'success':
#             return jsonify(response.get('rules', [])), 200
#         return jsonify({'error': 'Failed to fetch firewall rules'}), status_code

#     elif request.method == 'POST':
#         rule_data = request.json
#         response, status_code = make_api_request('apply-rules', method='POST', data=rule_data)
#         return jsonify(response), status_code

#     elif request.method == 'DELETE':
#         rule_data = request.json
#         response, status_code = make_api_request('remove-rule', method='POST', data=rule_data)
#         return jsonify(response), status_code

def firewall():
    logging.info("Entering firewall function")
    
    # Fetch agents
    agents = []
    connection = create_db_connection()
    if connection:
        try:
            cursor = connection.cursor(dictionary=True)
            cursor.execute("SELECT id, name, ip_address FROM agents")
            agents = cursor.fetchall()
            logging.info(f"Fetched {len(agents)} agents from the database")
        except Exception as e:
            logging.error(f"Error fetching agents: {str(e)}")
        finally:
            if cursor:
                cursor.close()
            connection.close()
    else:
        logging.error("Failed to create database connection")
    
    # Fetch firewall rules
    rules = {}
    selected_agent_id = session.get('selected_agent_id')
    selected_agent_ip = session.get('selected_agent')
    
    logging.info(f"Selected agent ID: {selected_agent_id}, IP: {selected_agent_ip}")
    
    if selected_agent_ip:
        logging.info(f"Attempting to fetch rules for agent {selected_agent_ip}")
        response, status_code = make_api_request('iptables_rules')
        logging.info(f"API response status code: {status_code}")
        logging.info(f"API response content: {response}")
        
        if status_code == 200 and isinstance(response, dict) and response.get('status') == 'success':
            rules = response.get('rules', {})
            logging.info(f"Fetched firewall rules from the agent")
        else:
            logging.error(f"Failed to fetch firewall rules. Status code: {status_code}, Response: {response}")
    else:
        logging.warning("No agent selected, skipping firewall rules fetch")
    
    logging.info(f"Rendering firewall template with {len(agents)} agents and rules for {len(rules)} tables")
    return render_template('firewall.html', agents=agents, rules=rules, selected_agent_id=selected_agent_id)

def manage_firewall_rules():
    if request.method == 'GET':
        response, status_code = make_api_request('iptables_rules')
        if status_code == 200 and isinstance(response, dict) and response.get('status') == 'success':
            return jsonify(response.get('rules', {})), 200
        return jsonify({'error': 'Failed to fetch firewall rules'}), status_code
    
    elif request.method == 'POST':
        rule_data = request.json
        response, status_code = make_api_request('apply-rules', method='POST', data={'rules': [rule_data]})
        return jsonify(response), status_code
    
    elif request.method == 'DELETE':
        rule_data = request.json
        response, status_code = make_api_request('remove-rule', method='POST', data=rule_data)
        return jsonify(response), status_code


def block_port():
    port = request.json.get('port')
    if not port:
        return jsonify({"error": "port is required"}), 400
    
    response, status_code = make_api_request('block_port', method='POST', data={'port': port})
    return jsonify(response), status_code

def fetch_and_reapply_rules():
    # Fetch all rules from the local database
    connection = create_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM firewall_rules")
        rules = cursor.fetchall()
        cursor.close()
        connection.close()

        # Reapply all rules to the agent
        make_api_request('apply-rules', method='POST', data={'rules': rules})
    else:
        print("Failed to connect to the database for rule synchronization")

def get_selected_agent():
    if 'selected_agent' in session and 'selected_agent_name' in session:
        return jsonify({
            'selected_agent': {
                'name': session['selected_agent_name'],
                'ip_address': session['selected_agent']
            }
        })
    else:
        return jsonify({'selected_agent': None})