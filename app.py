from flask import Flask
from config import SECRET_KEY, DEBUG, PORT
import logging
from routes import *

logging.basicConfig(filename='app.log', level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')

# Add a stream handler to also log to console
console = logging.StreamHandler()
console.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)

app = Flask(__name__)
app.secret_key = SECRET_KEY

# Routes
app.route('/')(index)
app.route('/agents')(agents)
app.route('/select_agent/<int:agent_id>', methods=['POST'])(select_agent)
app.route('/users')(users)
app.route('/applications')(applications)
app.route('/firewall')(firewall)
app.route('/processes')(processes)
app.route('/block_port')(block_port)


# API Routes
app.route('/api/agents', methods=['GET', 'POST', 'DELETE'])(manage_agents)
app.route('/api/check_agent_status/<int:agent_id>')(check_agent_status)
app.route('/api/processes')(get_processes)
app.route('/api/users', methods=['GET', 'POST', 'DELETE'])(manage_users)
app.route('/api/applications')(get_applications)
app.route('/api/firewall_rules', methods=['GET', 'POST', 'DELETE'])(manage_firewall_rules)
app.route('/api/selected_agent')(get_selected_agent)
app.route('/api/block_port', methods=['POST','GET'])(block_port)

if __name__ == '__main__':
    app.run(debug=DEBUG, port=PORT)