# system_manager.py

import logging
import psutil
import pwd
import grp
import os
import spwd
import shutil
from pathlib import Path
import hashlib
import secrets
import re
import asyncio
import aiofiles
from functools import lru_cache
from typing import List, Dict, Any, Tuple, Optional

logger = logging.getLogger(__name__)

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

    @staticmethod
    async def remove_user(username: str) -> Tuple[bool, str]:
        try:
            pwd.getpwnam(username)
        except KeyError:
            return False, f"User {username} does not exist"

        try:
            proc = await asyncio.create_subprocess_exec('userdel', '-r', username)
            await proc.wait()
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
    async def get_non_default_users() -> List[Dict[str, Any]]:
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

    # Add other system-related methods here