import asyncio
import logging
import json
from iptables_manager import IPTablesManager
from application_manager import ApplicationManager
from system_manager import SystemManager

# Configure logging
logging.basicConfig(
    filename='system_manager.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)