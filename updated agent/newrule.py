import iptc
import logging
import ipaddress
import psutil
import pwd
import grp
import os
import spwd
import shutil
from pathlib import Path
import crypt
from functools import lru_cache
import re
import subprocess
import json
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any, Tuple, Optional
import secrets
import hashlib
from datetime import datetime
import asyncio
import aiofiles

# Configure logging
logging.basicConfig(
    filename='system_manager.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

class IPTablesManager:
    @staticmethod
    async def add_rule(
        protocol: str,
        port: int,
        action: str,
        chain: str = "INPUT",
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        table: str = "filter"
    ) -> bool:
        try:
            rule = iptc.Rule()
            rule.protocol = protocol.lower()
            iptc_table = iptc.Table(table)
            iptc_chain = iptc.Chain(iptc_table, chain)

            rule.create_target(action.upper())

            if protocol.lower() in ['tcp', 'udp']:
                match = rule.create_match(protocol.lower())
                match.dport = str(port)

            if source_ip:
                ipaddress.ip_network(source_ip)  # Validate IP
                rule.src = source_ip

            if destination_ip:
                ipaddress.ip_network(destination_ip)  # Validate IP
                rule.dst = destination_ip

            iptc_chain.insert_rule(rule)
            logger.info(f"Iptables rule added successfully: {table} {chain} {protocol} {port} {action}")
            return True
        except (iptc.IPTCError, ValueError) as e:
            logger.error(f"Error adding iptables rule: {e}")
            return False

    @staticmethod
    async def get_rules() -> Dict[str, Any]:
        tables = ['filter', 'nat', 'mangle', 'raw']
        all_rules = {}

        for table_name in tables:
            try:
                table = iptc.Table(table_name)
                table_rules = {}

                for chain in table.chains:
                    chain_rules = []
                    for rule in chain.rules:
                        rule_dict = IPTablesManager._parse_rule(rule)
                        chain_rules.append(rule_dict)

                    table_rules[chain.name] = {
                        'policy': chain.policy if hasattr(chain, 'policy') else None,
                        'rules': chain_rules
                    }

                all_rules[table_name] = table_rules
            except iptc.ip4tc.IPTCError as e:
                logger.error(f"Error accessing {table_name} table: {e}")
                all_rules[table_name] = {"error": str(e)}

        return all_rules

    # ... (other methods remain the same)

class SystemManager:
    @staticmethod
    @lru_cache(maxsize=1000)
    async def get_running_processes() -> List[Dict[str, Any]]:
        try:
            return [
                {'pid': proc.info['pid'], 'name': proc.info['name'], 'username': proc.info['username']}
                for proc in psutil.process_iter(['pid', 'name', 'username'])
            ]
        except Exception as e:
            logger.error(f"Error getting running processes: {e}")
            return []

    @staticmethod
    async def add_user(username: str, password: str, groups: Optional[List[str]] = None) -> Tuple[bool, str]:
        if not re.match(r'^[a-z_][a-z0-9_-]{0,31}$', username):
            return False, "Invalid username format"

        if len(password) < 12:
            return False, "Password must be at least 12 characters long"

        try:
            pwd.getpwnam(username)
            return False, f"User {username} already exists"
        except KeyError:
            pass

        try:
            salt = secrets.token_hex(16)
            hashed_password = hashlib.sha512((password + salt).encode()).hexdigest()

            uids = [u.pw_uid for u in pwd.getpwall()]
            next_uid = max(uids) + 1 if uids else 1000

            new_user = f"{username}:x:{next_uid}:{next_uid}::/home/{username}:/bin/bash"

            async with aiofiles.open('/etc/passwd', 'a') as passwd_file:
                await passwd_file.write(new_user + '\n')

            async with aiofiles.open('/etc/shadow', 'a') as shadow_file:
                await shadow_file.write(f"{username}:{hashed_password}:{salt}::0:99999:7:::\n")

            home_dir = Path(f"/home/{username}")
            home_dir.mkdir(mode=0o700, exist_ok=True)
            shutil.chown(str(home_dir), username, username)

            if groups:
                for group in groups:
                    if not re.match(r'^[a-z_][a-z0-9_-]{0,31}$', group):
                        return False, f"Invalid group name: {group}"
                    await asyncio.create_subprocess_exec('usermod', '-aG', group, username)

            logger.info(f"User {username} added successfully")
            return True, f"User {username} added successfully"
        except Exception as e:
            logger.error(f"Error adding user {username}: {e}")
            return False, f"Error adding user {username}: {e}"

    # ... (other methods remain similar, but converted to async where appropriate)

class ApplicationManager:
    @staticmethod
    async def get_installed_applications() -> List[str]:
        applications = set()

        async def add_to_applications(app: str) -> None:
            if app and len(app) > 1:
                applications.add(app.strip())

        async def scan_desktop_files() -> None:
            try:
                desktop_files = Path('/usr/share/applications').glob('*.desktop')
                for desktop_file in desktop_files:
                    async with aiofiles.open(desktop_file, 'r', errors='ignore') as f:
                        content = await f.read()
                        match = re.search(r'^Name=(.+)$', content, re.MULTILINE)
                        if match:
                            await add_to_applications(match.group(1))
            except Exception as e:
                logger.error(f"Error scanning desktop files: {e}")

        async def scan_package_manager(command: List[str], start_index: int = 0) -> None:
            try:
                proc = await asyncio.create_subprocess_exec(
                    *command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await proc.communicate()
                for line in stdout.decode().split('\n')[start_index:]:
                    parts = line.split()
                    if len(parts) >= 2:
                        await add_to_applications(parts[1] if command[0] == 'dpkg' else parts[0])
            except Exception as e:
                logger.error(f"Error using {command[0]}: {e}")

        # ... (other methods remain similar, but converted to async)

        await asyncio.gather(
            scan_desktop_files(),
            scan_package_manager(['dpkg', '-l'], 5),
            scan_package_manager(['rpm', '-qa']),
            # ... (other scanning methods)
        )

        return sorted(list(applications))

# Main execution
async def main():
    iptables_manager = IPTablesManager()
    system_manager = SystemManager()
    app_manager = ApplicationManager()

    # Add an iptables rule
    await iptables_manager.add_rule("tcp", 80, "ACCEPT")

    # Get all iptables rules
    rules = await iptables_manager.get_rules()
    print(json.dumps(rules, indent=2))

    # Get running processes
    processes = await system_manager.get_running_processes()
    print(f"Number of running processes: {len(processes)}")

    # Add a new user
    success, message = await system_manager.add_user("newuser", "securePassword123!", ["users"])
    print(message)

    # Get non-default users
    non_default_users = await system_manager.get_non_default_users()
    print(f"Number of non-default users: {len(non_default_users)}")

    # Get installed applications
    apps = await app_manager.get_installed_applications()
    print(f"Number of installed applications: {len(apps)}")

if __name__ == "__main__":
    asyncio.run(main())