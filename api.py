import requests
from flask import jsonify, session
from config import API_KEY, AGENT_PORT

def make_api_request(endpoint, method='GET', data=None):
    if 'selected_agent' not in session:
        return jsonify({'error': 'No agent selected'}), 400

    headers = {'X-API-Key': API_KEY}
    url = f"http://{session['selected_agent']}:{AGENT_PORT}/{endpoint}"
    
    try:
        if method == 'GET':
            response = requests.get(url, headers=headers, timeout=5)
        elif method == 'POST':
            response = requests.post(url, json=data, headers=headers, timeout=5)
        elif method == 'DELETE':
            response = requests.delete(url, headers=headers, timeout=5)
        
        response.raise_for_status()
        return response.json(), response.status_code
    except requests.RequestException as e:
        return {'error': f'Error communicating with agent: {str(e)}'}, 500