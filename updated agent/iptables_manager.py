# iptables_manager.py

import iptc
import logging
import ipaddress
from typing import Dict, Any, Optional

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

    @staticmethod
    def _parse_rule(rule: iptc.Rule) -> Dict[str, Any]:
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
            if match.name in ['tcp', 'udp']:
                match_dict['dport'] = match.dport if hasattr(match, 'dport') else None
                match_dict['sport'] = match.sport if hasattr(match, 'sport') else None
            elif match.name == 'multiport':
                match_dict['dports'] = match.dports if hasattr(match, 'dports') else None
                match_dict['sports'] = match.sports if hasattr(match, 'sports') else None
            elif match.name == 'state':
                match_dict['state'] = match.state if hasattr(match, 'state') else None
            rule_dict['matches'].append(match_dict)

        return rule_dict

    @staticmethod
    def delete_rule(
        chain: str,
        rule_spec: Dict[str, Any],
        table: str = "filter"
    ) -> bool:
        try:
            iptc_table = iptc.Table(table)
            iptc_chain = iptc.Chain(iptc_table, chain)
            rule = iptc.Rule()

            # Set rule specifications
            if 'protocol' in rule_spec:
                rule.protocol = rule_spec['protocol']
            if 'source_ip' in rule_spec:
                rule.src = rule_spec['source_ip']
            if 'destination_ip' in rule_spec:
                rule.dst = rule_spec['destination_ip']
            if 'target' in rule_spec:
                rule.create_target(rule_spec['target'])

            # Set matches
            if 'port' in rule_spec and rule_spec.get('protocol') in ['tcp', 'udp']:
                match = rule.create_match(rule_spec['protocol'])
                match.dport = str(rule_spec['port'])

            iptc_chain.delete_rule(rule)
            logger.info(f"Iptables rule deleted successfully: {table} {chain} {rule_spec}")
            return True
        except iptc.IPTCError as e:
            logger.error(f"Error deleting iptables rule: {e}")
            return False

    @staticmethod
    def flush_chain(chain: str, table: str = "filter") -> bool:
        try:
            iptc_table = iptc.Table(table)
            iptc_chain = iptc.Chain(iptc_table, chain)
            iptc_chain.flush()
            logger.info(f"Iptables chain flushed successfully: {table} {chain}")
            return True
        except iptc.IPTCError as e:
            logger.error(f"Error flushing iptables chain: {e}")
            return False

    @staticmethod
    def save_rules(filename: str) -> bool:
        try:
            import subprocess
            result = subprocess.run(['iptables-save'], capture_output=True, text=True, check=True)
            with open(filename, 'w') as f:
                f.write(result.stdout)
            logger.info(f"Iptables rules saved to {filename}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Error saving iptables rules: {e}")
            return False
        except IOError as e:
            logger.error(f"Error writing to file {filename}: {e}")
            return False

    @staticmethod
    def restore_rules(filename: str) -> bool:
        try:
            import subprocess
            with open(filename, 'r') as f:
                subprocess.run(['iptables-restore'], input=f.read(), text=True, check=True)
            logger.info(f"Iptables rules restored from {filename}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Error restoring iptables rules: {e}")
            return False
        except IOError as e:
            logger.error(f"Error reading file {filename}: {e}")
            return False