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

logging.basicConfig(filename='Rule.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class IPTablesManager:
    @staticmethod
    def add_rule(protocol: str, port: int, action: str, chain: str = "INPUT", source_ip: Optional[str] = None, destination_ip: Optional[str] = None) -> bool:
        try:
            rule = iptc.Rule()
            rule.protocol = protocol.lower()
            iptc_chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), chain)

            rule.create_target(action.upper())

            if protocol.lower() in ['tcp', 'udp']:
                match = rule.create_match(protocol.lower())
                match.dport = str(port)

            if source_ip:
                ipaddress.ip_network(source_ip)
                rule.src = source_ip

            if destination_ip:
                ipaddress.ip_network(destination_ip)
                rule.dst = destination_ip

            iptc_chain.insert_rule(rule)

            logger.info(f"Iptables rule added successfully: {chain} {protocol} {port} {action}")
            return True
        except (iptc.IPTCError, ValueError) as e:
            logger.error(f"Error adding iptables rule: {e}")
            return False

    @staticmethod
    def block_port(port: int) -> bool:
        return IPTablesManager.add_rule("tcp", port, "DROP")

    @staticmethod
    def inbound_rule(rule_data: Dict[str, Any]) -> bool:
        return IPTablesManager.add_rule(
            protocol=rule_data['protocol'],
            port=rule_data['port'],
            action="ACCEPT",
            chain="INPUT",
            source_ip=rule_data.get('source_ip')
        )

    @staticmethod
    def outbound_rule(rule_data: Dict[str, Any]) -> bool:
        return IPTablesManager.add_rule(
            protocol=rule_data['protocol'],
            port=rule_data['port'],
            action="DROP",
            chain="OUTPUT",
            destination_ip=rule_data.get('destination_ip')
        )

    @staticmethod
    def get_rules() -> Dict[str, Any]:
        tables = ['filter', 'nat', 'mangle', 'raw']
        all_rules = {}

        for table_name in tables:
            try:
                table = iptc.Table(table_name)
                table_rules = {}

                for chain in table.chains:
                    chain_rules = []
                    for rule in chain.rules:
                        rule_dict = {
                            'protocol': rule.protocol,
                            'src': rule.src,
                            'dst': rule.dst,
                            'in_interface': rule.in_interface,
                            'out_interface': rule.out_interface,
                            'target': rule.target.name if rule.target else None,
                            'matches': []
                        }

                        for match in rule.matches:
                            match_dict = {'name': match.name}
                            if match.name == 'tcp' or match.name == 'udp':
                                match_dict['dport'] = match.dport if hasattr(match, 'dport') else None
                                match_dict['sport'] = match.sport if hasattr(match, 'sport') else None
                            rule_dict['matches'].append(match_dict)

                        chain_rules.append(rule_dict)

                    table_rules[chain.name] = {
                        'policy': chain.policy if hasattr(chain, 'policy') else None,
                        'rules': chain_rules
                    }

                all_rules[table_name] = table_rules

            except iptc.ip4tc.IPTCError as e:
                logging.error(f"Error accessing {table_name} table: {e}")
                all_rules[table_name] = {"error": str(e)}

        return all_rules

class SystemManager:
    @staticmethod
    @lru_cache(maxsize=None)
    def get_running_processes() -> List[Dict[str, Any]]:
        try:
            return [
                {'pid': proc.info['pid'], 'name': proc.info['name'], 'username': proc.info['username']}
                for proc in psutil.process_iter(['pid', 'name', 'username'])
            ]
        except Exception as e:
            logger.error(f"Error getting running processes: {e}")
            return []

    @staticmethod
    def add_user(username: str, password: str, groups: Optional[List[str]] = None) -> Tuple[bool, str]:
        try:
            pwd.getpwnam(username)
            return False, f"User {username} already exists"
        except KeyError:
            pass

        try:
            salt = os.urandom(6).hex()
            hashed_password = crypt.crypt(password, f'$6${salt}$')

            uids = [u.pw_uid for u in pwd.getpwall()]
            next_uid = max(uids) + 1 if uids else 1000

            new_user = f"{username}:x:{next_uid}:{next_uid}::/home/{username}:/bin/bash"

            with open('/etc/passwd', 'a') as passwd_file:
                passwd_file.write(new_user + '\n')

            with open('/etc/shadow', 'a') as shadow_file:
                shadow_file.write(f"{username}:{hashed_password}::0:99999:7:::\n")

            Path(f"/home/{username}").mkdir(mode=0o700, exist_ok=True)
            os.chown(f"/home/{username}", next_uid, next_uid)

            if groups:
                for group in groups:
                    subprocess.run(['usermod', '-aG', group, username], check=True)

            logger.info(f"User {username} added successfully")
            return True, f"User {username} added successfully"
        except Exception as e:
            logger.error(f"Error adding user {username}: {e}")
            return False, f"Error adding user {username}: {e}"

    @staticmethod
    def remove_user(username: str) -> Tuple[bool, str]:
        try:
            pwd.getpwnam(username)
        except KeyError:
            return False, f"User {username} does not exist"

        try:
            subprocess.run(['userdel', '-r', username], check=True)
            logger.info(f"User {username} removed successfully")
            return True, f"User {username} removed successfully"
        except Exception as e:
            logger.error(f"Error removing user {username}: {e}")
            return False, f"Error removing user {username}: {e}"

    @staticmethod
    @lru_cache(maxsize=None)
    def get_user_groups(username: str) -> List[str]:
        groups = [g.gr_name for g in grp.getgrall() if username in g.gr_mem]
        gid = pwd.getpwnam(username).pw_gid
        groups.append(grp.getgrgid(gid).gr_name)
        return list(set(groups))

    @staticmethod
    @lru_cache(maxsize=None)
    def get_user_privileges(username: str) -> List[str]:
        privileges = []
        if 'sudo' in SystemManager.get_user_groups(username):
            privileges.append('sudo')
        user_info = pwd.getpwnam(username)
        if user_info.pw_shell not in ['/usr/sbin/nologin', '/bin/false']:
            privileges.append('login')
        if os.path.exists('/etc/pam.d/su'):
            with open('/etc/pam.d/su', 'r') as f:
                if any('pam_wheel.so' in line for line in f) and 'wheel' in SystemManager.get_user_groups(username):
                    privileges.append('su to root')
        return privileges

    @staticmethod
    def get_non_default_users() -> List[Dict[str, Any]]:
        try:
            non_default_users = []
            for user in pwd.getpwall():
                if 1000 <= user.pw_uid < 65534 and user.pw_shell not in ['/usr/sbin/nologin', '/bin/false']:
                    user_info = {
                        'username': user.pw_name,
                        'uid': user.pw_uid,
                        'gid': user.pw_gid,
                        'home': user.pw_dir,
                        'shell': user.pw_shell,
                        'groups': SystemManager.get_user_groups(user.pw_name),
                        'privileges': SystemManager.get_user_privileges(user.pw_name)
                    }
                    try:
                        sp = spwd.getspnam(user.pw_name)
                        user_info.update({
                            'last_password_change': sp.sp_lstchg,
                            'min_password_age': sp.sp_min,
                            'max_password_age': sp.sp_max
                        })
                    except KeyError:
                        pass
                    non_default_users.append(user_info)
            return non_default_users
        except Exception as e:
            logger.error(f"Error getting non-default users: {e}")
            return []

class ApplicationManager:
    @staticmethod
    def get_installed_applications() -> List[str]:
        applications = set()

        def add_to_applications(app: str) -> None:
            if app and len(app) > 1:
                applications.add(app.strip())

        def scan_desktop_files() -> None:
            try:
                for desktop_file in Path('/usr/share/applications').glob('*.desktop'):
                    with open(desktop_file, 'r', errors='ignore') as f:
                        content = f.read()
                        match = re.search(r'^Name=(.+)$', content, re.MULTILINE)
                        if match:
                            add_to_applications(match.group(1))
            except Exception as e:
                logger.error(f"Error scanning desktop files: {e}")

        def scan_package_manager(command: List[str], start_index: int = 0) -> None:
            try:
                result = subprocess.run(command, capture_output=True, text=True)
                for line in result.stdout.split('\n')[start_index:]:
                    parts = line.split()
                    if len(parts) >= 2:
                        add_to_applications(parts[1] if command[0] == 'dpkg' else parts[0])
            except Exception as e:
                logger.error(f"Error using {command[0]}: {e}")

        def scan_bin_directories() -> None:
            for bin_dir in ['/usr/bin', '/usr/local/bin']:
                try:
                    for file in os.listdir(bin_dir):
                        file_path = os.path.join(bin_dir, file)
                        if os.path.isfile(file_path) and os.access(file_path, os.X_OK):
                            add_to_applications(file)
                except Exception as e:
                    logger.error(f"Error scanning {bin_dir}: {e}")

        def list_system_services() -> None:
            try:
                result = subprocess.run(['systemctl', 'list-units', '--type=service', '--all'], capture_output=True, text=True)
                for line in result.stdout.split('\n')[1:]:
                    parts = line.split()
                    if len(parts) >= 5:
                        service_name = parts[0].replace('.service', '')
                        add_to_applications(service_name)
            except Exception as e:
                logger.error(f"Error listing system services: {e}")

        with ThreadPoolExecutor() as executor:
            executor.submit(scan_desktop_files)
            executor.submit(scan_package_manager, ['dpkg', '-l'], 5)
            executor.submit(scan_package_manager, ['rpm', '-qa'])
            executor.submit(scan_bin_directories)
            executor.submit(list_system_services)

        return sorted(list(applications))

# Main execution
if __name__ == "__main__":
    # Example usage
    iptables_manager = IPTablesManager()
    system_manager = SystemManager()
    app_manager = ApplicationManager()

    # Add an iptables rule
    iptables_manager.add_rule("tcp", 80, "ACCEPT")

    # Get all iptables rules
    rules = iptables_manager.get_rules()
    print(json.dumps(rules, indent=2))

    # Get running processes
    processes = system_manager.get_running_processes()
    print(f"Number of running processes: {len(processes)}")

    # Add a new user
    success, message = system_manager.add_user("newuser", "password123", ["users"])
    print(message)

    # Get non-default users
    non_default_users = system_manager.get_non_default_users()
    print(f"Number of non-default users: {len(non_default_users)}")

    # Get installed applications
    apps = app_manager.get_installed_applications()
    print(f"Number of installed applications: {len(apps)}")