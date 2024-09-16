import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Database configuration
DB_CONFIG = {
    'host': os.getenv('DB_HOST', '192.168.1.28'),
    'user': os.getenv('DB_USER', 'alpha'),
    'password': os.getenv('DB_PASSWORD', 'alpha#777'),
    'database': os.getenv('DB_NAME', 'alpha'),
    'auth_plugin': 'mysql_native_password'
}

# API configuration
API_KEY = os.getenv('API_KEY', 'alpha')
AGENT_PORT = int(os.getenv('AGENT_PORT', 5000))

# Flask configuration
SECRET_KEY = os.getenv('SECRET_KEY', os.urandom(24))

# Debug mode
DEBUG = os.getenv('DEBUG', 'False').lower() in ('true', '1', 't')

# Port
PORT = int(os.getenv('PORT', 5001))