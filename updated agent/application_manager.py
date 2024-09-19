# application_manager.py

import logging
import asyncio
import aiofiles
from pathlib import Path
import re
from typing import List, Set

logger = logging.getLogger(__name__)

class ApplicationManager:
    @staticmethod
    async def get_installed_applications() -> List[str]:
        applications: Set[str] = set()

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

        async def scan_bin_directories() -> None:
            for bin_dir in ['/usr/bin', '/usr/local/bin']:
                try:
                    for file in os.listdir(bin_dir):
                        file_path = os.path.join(bin_dir, file)
                        if os.path.isfile(file_path) and os.access(file_path, os.X_OK):
                            await add_to_applications(file)
                except Exception as e:
                    logger.error(f"Error scanning {bin_dir}: {e}")

        async def list_system_services() -> None:
            try:
                proc = await asyncio.create_subprocess_exec(
                    'systemctl', 'list-units', '--type=service', '--all',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await proc.communicate()
                for line in stdout.decode().split('\n')[1:]:
                    parts = line.split()
                    if len(parts) >= 5:
                        service_name = parts[0].replace('.service', '')
                        await add_to_applications(service_name)
            except Exception as e:
                logger.error(f"Error listing system services: {e}")

        await asyncio.gather(
            scan_desktop_files(),
            scan_package_manager(['dpkg', '-l'], 5),
            scan_package_manager(['rpm', '-qa']),
            scan_bin_directories(),
            list_system_services()
        )

        return sorted(list(applications))

