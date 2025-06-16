#!/usr/bin/env python3
"""
Deffain OpenSource Firewall v2.1
Secure and advanced Linux firewall management tool with refined rule management
"""

import subprocess
import sys
import logging
import re
import json
import os
import ipaddress
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
from dataclasses import dataclass
from enum import Enum
import time
from datetime import datetime

class Colors:
    """Terminal color codes for enhanced UI"""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    
    # Main colors
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    # Bright colors
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    
    # Background
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'

class UI:
    """Modern terminal interface for user interaction"""
    
    @staticmethod
    def print_banner():
        """Show Deffain banner art"""
        banner = f"""
{Colors.BRIGHT_CYAN}╔═══════════════════════════════════════════════════════════════╗
║                                                                 ║
║  {Colors.BRIGHT_BLUE}██████╗ ███████╗███████╗███████╗ █████╗ ██╗███╗  ██╗{Colors.BRIGHT_CYAN}         ║
║  {Colors.BRIGHT_BLUE}██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗██║████╗  ██║{Colors.BRIGHT_CYAN}         ║
║  {Colors.BRIGHT_BLUE}██║  ██║█████╗  █████╗  █████╗  ███████║██║██╔██╗ ██║{Colors.BRIGHT_CYAN}         ║
║  {Colors.BRIGHT_BLUE}██║  ██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██║██║██║╚██╗██║{Colors.BRIGHT_CYAN}         ║
║  {Colors.BRIGHT_BLUE}██████╔╝███████╗██║     ██║     ██║  ██║██║██║ ╚████║{Colors.BRIGHT_CYAN}         ║
║  {Colors.BRIGHT_BLUE}╚═════╝ ╚══════╝╚═╝     ╚═╝     ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝{Colors.BRIGHT_CYAN}         ║
║                                                                 ║
║            {Colors.BRIGHT_YELLOW}Modern Firewall Management Tool v2.1{Colors.BRIGHT_CYAN}           ║
║                      {Colors.WHITE}Powered by nftables{Colors.BRIGHT_CYAN}                    ║
╚═══════════════════════════════════════════════════════════════╝{Colors.RESET}
"""
        print(banner)
    
    @staticmethod
    def success(message: str):
        """Prints a success message."""
        print(f"{Colors.BRIGHT_GREEN}✅ {message}{Colors.RESET}")
    
    @staticmethod
    def error(message: str):
        """Prints an error message."""
        print(f"{Colors.BRIGHT_RED}❌ {message}{Colors.RESET}")
    
    @staticmethod
    def warning(message: str):
        """Prints a warning message."""
        print(f"{Colors.BRIGHT_YELLOW}⚠️  {message}{Colors.RESET}")
    
    @staticmethod
    def info(message: str):
        """Prints an informational message."""
        print(f"{Colors.BRIGHT_CYAN}ℹ️  {message}{Colors.RESET}")
    
    @staticmethod
    def loading(message: str):
        """Prints a loading message with a brief pause."""
        print(f"{Colors.BRIGHT_BLUE}🔄 {message}...{Colors.RESET}", end="", flush=True)
        time.sleep(0.5)
        print(f" {Colors.BRIGHT_GREEN}Done!{Colors.RESET}")
    
    @staticmethod
    def separator():
        """Prints a horizontal separator line."""
        print(f"{Colors.DIM}{'─' * 60}{Colors.RESET}")
    
    @staticmethod
    def section_header(title: str):
        """Prints a formatted section header."""
        print(f"\n{Colors.BRIGHT_MAGENTA}┌─ {title.upper()} {Colors.DIM}{'─' * (50 - len(title))}{Colors.RESET}")

class Protocol(Enum):
    """Enumeration for network protocols."""
    TCP = "tcp"
    UDP = "udp"
    BOTH = "both"

class Action(Enum):
    """Enumeration for firewall actions."""
    ACCEPT = "accept"
    DROP = "drop"
    REJECT = "reject"

@dataclass
class FirewallRule:
    """Data structure to represent a single firewall rule."""
    port: int
    protocol: Protocol
    action: Action
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    comment: Optional[str] = None

    def to_dict(self) -> Dict:
        """Converts the FirewallRule object to a dictionary for JSON serialization."""
        return {
            'port': self.port,
            'protocol': self.protocol.value,
            'action': self.action.value,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'comment': self.comment
        }

    @staticmethod
    def from_dict(data: Dict):
        """Creates a FirewallRule object from a dictionary."""
        return FirewallRule(
            port=data['port'],
            protocol=Protocol(data['protocol']),
            action=Action(data['action']),
            source_ip=data.get('source_ip'),
            destination_ip=data.get('destination_ip'),
            comment=data.get('comment')
        )

class InputValidator:
    """Provides methods for validating various input types."""
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """Validates if a string is a valid IP address (IPv4 or IPv6)."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_cidr(cidr: str) -> bool:
        """Validates if a string is a valid CIDR notation."""
        try:
            ipaddress.ip_network(cidr, strict=False)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_port(port: Union[str, int]) -> bool:
        """Validates if a value is a valid port number (1-65535)."""
        try:
            p = int(port)
            return 1 <= p <= 65535
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def validate_protocol(protocol: str) -> bool:
        """Validates if a string is a recognized protocol."""
        return protocol.lower() in ['tcp', 'udp', 'both']
    
    @staticmethod
    def sanitize_string(text: str) -> str:
        """Sanitizes a string to prevent command injection."""
        # Allow alphanumeric, space, dot, hyphen, underscore, slash, and colon characters.
        allowed_chars = re.compile(r'^[a-zA-Z0-9\.\-_/:\s]+$')
        if not allowed_chars.match(text):
            raise ValueError(f"Unsafe characters detected: {text}")
        return text.strip()

class DeffainFirewall:
    """Main class for managing nftables firewall rules."""
    
    def __init__(self, quiet_mode: bool = False):
        self.quiet_mode = quiet_mode
        if not quiet_mode:
            UI.print_banner()
        
        self.check_root()
        self.check_nftables()
        self.validator = InputValidator()
        self.table_name = "deffain_filter"
        self.input_chain = "deffain_input"
        self.output_chain = "deffain_output"
        self.forward_chain = "deffain_forward"
        self.rules_file = "/etc/deffain/rules.json" # Persistent storage for rules
        
        if not quiet_mode:
            UI.loading("Initializing firewall")
        
        # Initial setup and loading of saved rules
        self.setup_nftables()
        self.load_saved_rules()

    def check_root(self) -> None:
        """Ensures the script is run with root privileges."""
        try:
            result = subprocess.run(['id', '-u'], capture_output=True, text=True, check=True)
            if result.stdout.strip() != '0':
                UI.error("This tool requires root privileges! Please run with 'sudo'.")
                sys.exit(1)
        except (subprocess.CalledProcessError, FileNotFoundError):
            UI.error("Permission check failed or 'id' command not found!")
            sys.exit(1)
    
    def check_nftables(self) -> None:
        """Verifies if nftables is installed and accessible."""
        try:
            subprocess.run(['nft', '--version'], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            UI.error("nftables is not installed or not found in your PATH!")
            UI.info("To install: sudo apt-get install nftables (Debian/Ubuntu) or sudo yum install nftables (RHEL/CentOS)")
            sys.exit(1)
    
    def run_nft_command(self, command: List[str]) -> bool:
        """Executes an nftables command securely."""
        try:
            # Basic sanitization for command elements (ensure they are strings)
            if not all(isinstance(arg, str) for arg in command):
                UI.error(f"Unsafe command parameter detected: {command}")
                return False
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True, # Raise CalledProcessError on non-zero exit codes
                timeout=10 # Timeout for commands
            )
            return True
            
        except subprocess.TimeoutExpired:
            UI.error(f"NFT command timed out: {' '.join(command)}")
            return False
        except subprocess.CalledProcessError as e:
            # Display the specific error from nftables
            if not self.quiet_mode:
                UI.warning(f"Error executing NFT command: {' '.join(command)}")
                if e.stderr and "No such file or directory" not in e.stderr: # Ignore expected "no such rule" errors
                    UI.warning(f"Error Details: {e.stderr.strip()}")
            return False
        except Exception as e:
            UI.error(f"An unexpected error occurred: {e}. Command: {' '.join(command)}")
            return False
    
    def setup_nftables(self) -> bool:
        """
        Sets up the base nftables configuration.
        Deletes existing table and adds essential chains/rules.
        """
        UI.info("Setting up nftables base configuration...")
        
        # Delete existing table to ensure a clean state
        self.run_nft_command(['nft', 'delete', 'table', 'inet', self.table_name])
        
        commands = [
            ['nft', 'add', 'table', 'inet', self.table_name],
            ['nft', 'add', 'chain', 'inet', self.table_name, self.input_chain,
             '{ type filter hook input priority 0; policy drop; }'], # Default policy is DROP for incoming
            ['nft', 'add', 'chain', 'inet', self.table_name, self.output_chain,
             '{ type filter hook output priority 0; policy accept; }'], # Default allow outgoing
            ['nft', 'add', 'chain', 'inet', self.table_name, self.forward_chain,
             '{ type filter hook forward priority 0; policy drop; }'], # Default DROP for forwarding
            
            # Essential security rules (always present)
            ['nft', 'add', 'rule', 'inet', self.table_name, self.input_chain,
             'iifname "lo" accept', 'comment "Allow loopback traffic"'],
            ['nft', 'add', 'rule', 'inet', self.table_name, self.input_chain,
             'ct state established,related accept', 'comment "Allow established and related connections"'],
            ['nft', 'add', 'rule', 'inet', self.table_name, self.input_chain,
             'ct state invalid drop', 'comment "Drop invalid packets"'],
            ['nft', 'add', 'rule', 'inet', self.table_name, self.input_chain,
             'ip protocol icmp accept', 'comment "Allow ICMP (ping) for IPv4"'],
            ['nft', 'add', 'rule', 'inet', self.table_name, self.input_chain,
             'ip6 nexthdr icmpv6 accept', 'comment "Allow ICMPv6 (ping) for IPv6"'],
        ]
        
        success_count = 0
        for cmd in commands:
            if self.run_nft_command(cmd):
                success_count += 1
        
        if success_count == len(commands):
            UI.success("Base nftables configuration successfully set up.")
            return True
        else:
            UI.error("Some errors occurred while setting up base nftables configuration.")
            return False
    
    def add_or_update_rule(self, rule: FirewallRule) -> bool:
        """
        Adds a new firewall rule or updates an existing one for the same port/protocol/IP combo.
        Ensures only one rule exists per unique identifier.
        """
        try:
            if not self.validator.validate_port(rule.port):
                UI.error(f"Invalid port: {rule.port}")
                return False
            if rule.source_ip and not (self.validator.validate_ip(rule.source_ip) or self.validator.validate_cidr(rule.source_ip)):
                UI.error(f"Invalid source IP/CIDR: {rule.source_ip}")
                return False
            if rule.destination_ip and not (self.validator.validate_ip(rule.destination_ip) or self.validator.validate_cidr(rule.destination_ip)):
                UI.error(f"Invalid destination IP/CIDR: {rule.destination_ip}")
                return False
            
            protocols_to_apply = []
            if rule.protocol == Protocol.TCP:
                protocols_to_apply = ['tcp']
            elif rule.protocol == Protocol.UDP:
                protocols_to_apply = ['udp']
            elif rule.protocol == Protocol.BOTH:
                protocols_to_apply = ['tcp', 'udp']
            
            all_successful = True
            for proto in protocols_to_apply:
                # 1. First, delete any existing rule that matches this port/protocol/source/dest IP combination
                self._delete_specific_nft_rule(rule, proto)
                
                # 2. Then, add the new/updated rule
                nft_add_command = self._build_nft_rule_command(rule, proto)
                if not self.run_nft_command(nft_add_command):
                    all_successful = False
                    UI.error(f"Failed to apply NFT rule for {rule.port}/{proto.upper()}.")
                    break # Stop if one protocol fails
            
            if all_successful:
                self.save_rule_to_file(rule) # Save/update rule in JSON file
                action_color = Colors.BRIGHT_GREEN if rule.action == Action.ACCEPT else Colors.BRIGHT_RED
                protocol_str = rule.protocol.value.upper()
                
                # Prepare message parts
                source_str = f" from {Colors.BRIGHT_CYAN}{rule.source_ip}{Colors.RESET}" if rule.source_ip else ""
                dest_str = f" to {Colors.BRIGHT_CYAN}{rule.destination_ip}{Colors.RESET}" if rule.destination_ip else ""
                comment_clean = self.validator.sanitize_string(rule.comment) if rule.comment else ""
                comment_str = f" ({Colors.DIM}{comment_clean}{Colors.RESET})" if comment_clean else ""
                
                UI.success(f"Port {Colors.BRIGHT_YELLOW}{rule.port}/{protocol_str}{Colors.RESET} " +
                           f"{action_color}{rule.action.value.upper()}{Colors.RESET}" +
                           source_str + dest_str + comment_str)
            
            return all_successful
            
        except ValueError as e:
            UI.error(f"Rule addition/update error (validation): {e}")
            return False
        except Exception as e:
            UI.error(f"Unexpected error during rule addition/update: {e}")
            return False
    
    def _build_nft_rule_command(self, rule: FirewallRule, protocol: str, action_type: str = "add") -> List[str]:
        """
        Builds an nft command (add or delete) from a FirewallRule object.
        action_type can be "add" or "delete".
        """
        cmd = ['nft', action_type, 'rule', 'inet', self.table_name, self.input_chain]
        
        # Add IP address or CIDR appropriately
        if rule.source_ip:
            cmd.extend(['ip6' if ':' in rule.source_ip else 'ip', 'saddr', rule.source_ip])
        if rule.destination_ip:
            cmd.extend(['ip6' if ':' in rule.destination_ip else 'ip', 'daddr', rule.destination_ip])
        
        cmd.extend([protocol, 'dport', str(rule.port)])
        
        if action_type == "add":
            cmd.append(rule.action.value)
            if rule.comment:
                sanitized_comment = self.validator.sanitize_string(rule.comment)
                cmd.extend(['comment', f'"{sanitized_comment}"'])
        
        return cmd

    def _delete_specific_nft_rule(self, rule: FirewallRule, protocol: str) -> None:
        """
        Attempts to delete an nftables rule based on its identifying parameters
        (port, protocol, source_ip, destination_ip).
        """
        # Build the delete command. Action and comment are not needed for deletion.
        delete_cmd = self._build_nft_rule_command(rule, protocol, action_type="delete")
        self.run_nft_command(delete_cmd) # Errors are caught and logged by run_nft_command
    
    def list_rules(self) -> None:
        """Lists active nftables rules and displays them in a modern format."""
        UI.section_header("Active Firewall Rules")
        
        try:
            result = subprocess.run(
                ['nft', 'list', 'chain', 'inet', self.table_name, self.input_chain],
                capture_output=True, text=True, check=True
            )
            
            lines = result.stdout.split('\n')
            user_rule_count = 0
            
            for line in lines:
                line = line.strip()
                # Skip headers and Deffain's own base rules (loopback, established, etc.)
                if not line or 'chain deffain_input' in line or line.startswith('type filter') or \
                   any(skip in line for skip in ['iifname "lo"', 'ct state established', 'ct state invalid', 'ip protocol icmp', 'ip6 nexthdr']):
                    continue
                
                # Check for rules that are likely user-defined (contain dport or specific IP rules)
                if 'dport' in line or 'saddr' in line or 'daddr' in line:
                    user_rule_count += 1
                    self._format_rule_line(line, user_rule_count)
            
            if user_rule_count == 0:
                UI.info("No user-defined active rules found yet.")
            else:
                UI.separator()
                UI.info(f"Total {user_rule_count} user-defined rules are active.")
            
        except subprocess.CalledProcessError as e:
            UI.error(f"Could not list rules. Error: {e.stderr.strip()}")
        except Exception as e:
            UI.error(f"Unexpected error while listing rules: {e}")
    
    def _format_rule_line(self, line: str, rule_num: int):
        """Parses a single nftables rule line and displays it in a colored, readable format."""
        port_match = re.search(r'(tcp|udp)\s+dport\s+(\d+)', line)
        action_match = re.search(r'(accept|drop|reject)', line)
        comment_match = re.search(r'comment\s+"([^"]*)"', line)
        
        protocol = port_match.group(1).upper() if port_match else "ANY"
        port = port_match.group(2) if port_match else "N/A"
        action = action_match.group(1).upper() if action_match else "UNKNOWN"
        
        # Select color and icon based on action
        action_color = Colors.BRIGHT_GREEN if action == 'ACCEPT' else Colors.BRIGHT_RED if action == 'DROP' else Colors.BRIGHT_YELLOW
        icon = "🟢" if action == 'ACCEPT' else "🔴" if action == 'DROP' else "🟡"
        
        ip_info = ""
        saddr_match = re.search(r'(?:ip|ip6)\s+saddr\s+([^\s]+)', line)
        if saddr_match:
            ip_info += f" from {Colors.BRIGHT_CYAN}{saddr_match.group(1)}{Colors.RESET}"
        
        daddr_match = re.search(r'(?:ip|ip6)\s+daddr\s+([^\s]+)', line)
        if daddr_match:
            ip_info += f" to {Colors.BRIGHT_CYAN}{daddr_match.group(1)}{Colors.RESET}"
        
        comment_info = f" | {Colors.DIM}{comment_match.group(1)}{Colors.RESET}" if comment_match else ""
        
        print(f"{Colors.DIM}{rule_num:2d}.{Colors.RESET} {icon} " +
              f"{Colors.BRIGHT_YELLOW}Port {port}/{protocol}{Colors.RESET} → " +
              f"{action_color}{action}{Colors.RESET}" +
              ip_info + comment_info)
    
    def save_rule_to_file(self, new_rule: FirewallRule) -> bool:
        """
        Saves a rule to rules.json. If a rule with the same port, protocol,
        source_ip, and destination_ip already exists, it updates it.
        """
        try:
            rules_path = Path(self.rules_file)
            rules_path.parent.mkdir(parents=True, exist_ok=True) # Ensure directory exists
            
            rules_data = []
            if rules_path.exists() and rules_path.stat().st_size > 0:
                try:
                    with open(rules_path, 'r', encoding='utf-8') as f:
                        rules_data = [FirewallRule.from_dict(d) for d in json.load(f)]
                except json.JSONDecodeError:
                    UI.warning(f"Rule file corrupted ({self.rules_file}). Recreating.")
                    rules_data = [] # Discard corrupted data

            found = False
            for i, existing_rule in enumerate(rules_data):
                # Unique identifier for a rule: Port, Protocol, Source IP, Destination IP
                # (Action and Comment can change for the same identifier)
                is_same_identifier = (
                    existing_rule.port == new_rule.port and
                    existing_rule.protocol == new_rule.protocol and
                    existing_rule.source_ip == new_rule.source_ip and
                    existing_rule.destination_ip == new_rule.destination_ip
                )

                if is_same_identifier:
                    rules_data[i] = new_rule # Update the existing rule
                    found = True
                    if not self.quiet_mode:
                        UI.info(f"Updated saved rule for Port {new_rule.port}/{new_rule.protocol.value.upper()}.")
                    break
            
            if not found:
                rules_data.append(new_rule) # Add as a new rule
                if not self.quiet_mode:
                    UI.info(f"Added new saved rule for Port {new_rule.port}/{new_rule.protocol.value.upper()}.")

            with open(rules_path, 'w', encoding='utf-8') as f:
                json.dump([r.to_dict() for r in rules_data], f, indent=2, ensure_ascii=False)
            return True
            
        except Exception as e:
            UI.error(f"Could not save rule to file: {self.rules_file}. Error: {e}")
            return False
    
    def load_saved_rules(self) -> bool:
        """
        Loads saved rules from rules.json and applies them to nftables.
        Ensures a clean application to prevent duplicates on nftables side.
        """
        try:
            rules_path = Path(self.rules_file)
            if not rules_path.exists() or rules_path.stat().st_size == 0:
                if not self.quiet_mode:
                    UI.info("No saved rule file found or it is empty. Start adding rules!")
                return True
            
            with open(rules_path, 'r', encoding='utf-8') as f:
                rules_data_dicts = json.load(f)
            
            if not rules_data_dicts:
                if not self.quiet_mode:
                    UI.info("Saved rule file is empty.")
                return True

            applied_count = 0
            for rule_dict in rules_data_dicts:
                try:
                    rule = FirewallRule.from_dict(rule_dict)
                    
                    # For each rule, first delete any potentially existing NFT rule, then add.
                    # This prevents duplicates in NFT when loading from saved file.
                    protocols_to_apply = []
                    if rule.protocol == Protocol.TCP:
                        protocols_to_apply = ['tcp']
                    elif rule.protocol == Protocol.UDP:
                        protocols_to_apply = ['udp']
                    elif rule.protocol == Protocol.BOTH:
                        protocols_to_apply = ['tcp', 'udp']

                    rule_applied_successfully = True
                    for proto in protocols_to_apply:
                        self._delete_specific_nft_rule(rule, proto) # Delete existing
                        nft_add_command = self._build_nft_rule_command(rule, proto)
                        if not self.run_nft_command(nft_add_command):
                            rule_applied_successfully = False
                            break
                    
                    if rule_applied_successfully:
                        applied_count += 1
                        
                except KeyError as ke:
                    UI.warning(f"Missing key in a saved rule: {ke}. Rule skipped: {rule_dict}")
                except ValueError as ve:
                    UI.warning(f"Invalid value in a saved rule: {ve}. Rule skipped: {rule_dict}")
                except Exception as e:
                    UI.warning(f"Unexpected error while loading saved rule: {e}. Rule skipped: {rule_dict}")
            
            if not self.quiet_mode:
                UI.info(f"{applied_count} saved rules successfully loaded and applied to nftables.")
            return True
            
        except json.JSONDecodeError:
            UI.error(f"Rule file ({self.rules_file}) is corrupted. Please check or delete the file.")
            return False
        except Exception as e:
            UI.error(f"Critical error while loading saved rules: {e}")
            return False
            
    def enable_firewall(self) -> bool:
        """Enables the firewall by setting up base nftables and loading saved rules."""
        UI.loading("Enabling firewall")
        if self.setup_nftables(): # Re-creates the table and base chains
            self.load_saved_rules() # Loads and applies rules from file
            UI.success("Firewall successfully enabled and rules loaded.")
            return True
        else:
            UI.error("Firewall could not be enabled.")
            return False
    
    def disable_firewall(self) -> bool:
        """Disables the firewall by deleting Deffain's nftables table."""
        UI.loading("Disabling firewall")
        if self.run_nft_command(['nft', 'delete', 'table', 'inet', self.table_name]):
            UI.success("Deffain Firewall successfully disabled.")
            return True
        else:
            UI.error("Deffain Firewall could not be disabled.")
            return False
    
    def clear_all_saved_rules(self) -> bool:
        """Deletes the rules.json file, effectively clearing all saved user rules."""
        rules_path = Path(self.rules_file)
        if rules_path.exists():
            try:
                os.remove(rules_path)
                UI.success(f"All saved rules cleared from {self.rules_file}.")
                return True
            except OSError as e:
                UI.error(f"Failed to clear saved rules file: {e}")
                return False
        else:
            UI.info("No saved rules file found to clear.")
            return True

    def show_status(self):
        """Displays the current firewall status and active rules."""
        UI.section_header("Firewall Status")
        
        try:
            # Check if Deffain's table exists
            subprocess.run(['nft', 'list', 'table', 'inet', self.table_name],
                           capture_output=True, text=True, check=True, timeout=5)
            UI.success("Deffain Firewall is active and running.")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            UI.error("Deffain Firewall is not active or nftables table not found.")
            return # Don't try to list rules if firewall is not active
        
        print(f"\n{Colors.BRIGHT_BLUE}📊 System Information:{Colors.RESET}")
        print(f"    Time: {Colors.BRIGHT_CYAN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
        print(f"    Managed Table: {Colors.BRIGHT_YELLOW}{self.table_name}{Colors.RESET}")
        print(f"    Default Incoming Policy: {Colors.BRIGHT_RED}DROP{Colors.RESET}")
        print(f"    Default Outgoing Policy: {Colors.BRIGHT_GREEN}ACCEPT{Colors.RESET}")
        
        self.list_rules() # Show user-defined rules

class CommandParser:
    """Parses command line inputs and invokes relevant firewall actions."""
    
    def __init__(self, firewall: DeffainFirewall):
        self.firewall = firewall
        self.validator = InputValidator()
    
    def parse_command(self, command_str: str) -> bool:
        """Parses the given command string and executes the firewall operation."""
        try:
            command_str = command_str.strip()
            lower_command = command_str.lower() 
            
            if lower_command.startswith('port'):
                return self.parse_port_command(command_str)
            elif lower_command == 'status':
                self.firewall.show_status()
                return True
            elif lower_command == 'enable' or lower_command == 'on':
                return self.firewall.enable_firewall()
            elif lower_command == 'disable' or lower_command == 'off':
                return self.firewall.disable_firewall()
            elif lower_command == 'clear-saved-rules':
                return self.firewall.clear_all_saved_rules()
            elif lower_command == 'help':
                self.show_help()
                return True
            else:
                UI.error(f"Unknown command: '{command_str}'")
                self.show_help()
                return False
                
        except Exception as e:
            UI.error(f"Unexpected error while processing command: {e}")
            return False
    
    def parse_port_command(self, command: str) -> bool:
        """Parses port open/close commands and adds/updates rules."""
        # Regex made more robust for different IP formats and optional parts.
        pattern = re.compile(
            r'port\s+(open|close)\s+(\d+)' # action (open/close) and port
            r'(?:\s+(tcp|udp|both))?' # protocol (optional)
            r'(?:\s+(from|to)\s+((?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/\d{1,2})?|' # IPv4 or CIDR
            r'(?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}(?:/\d{1,3})?|' # IPv6 or CIDR
            r'(?:[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}){0,6})?(?:/\d{1,3})?))?' # Abbreviated IPv6
            r'(?:\s+comment\s+"([^"]*)")?', # comment (optional, in quotes)
            re.IGNORECASE
        )
        
        match = pattern.match(command)
        
        if not match:
            UI.error("Invalid port command format.")
            UI.info("Example: port open 22 tcp from 192.168.1.0/24 comment \"SSH Access\"")
            UI.info("Example: port close 80 both")
            return False
        
        action_str, port_str, protocol_str, direction, ip_str, comment = match.groups()
        
        protocol_str = protocol_str if protocol_str else 'tcp' # Default protocol is TCP
        
        if not self.validator.validate_port(port_str):
            UI.error(f"Invalid port number: {port_str}. Port must be between 1-65535.")
            return False
        
        if not self.validator.validate_protocol(protocol_str):
            UI.error(f"Invalid protocol: {protocol_str}. Protocol must be 'tcp', 'udp', or 'both'.")
            return False
        
        source_ip = None
        destination_ip = None
        
        if ip_str:
            if not (self.validator.validate_ip(ip_str) or self.validator.validate_cidr(ip_str)):
                UI.error(f"Invalid IP address or CIDR block: {ip_str}.")
                return False
            
            if direction and direction.lower() == 'from':
                source_ip = ip_str
            elif direction and direction.lower() == 'to':
                destination_ip = ip_str
            else:
                source_ip = ip_str # Default to source IP for input chain
                UI.warning(f"No 'from' or 'to' direction specified for IP address '{ip_str}'. Assumed as source IP.")

        if comment:
            try:
                comment = self.validator.sanitize_string(comment)
            except ValueError as e:
                UI.error(f"Invalid characters in comment: {e}. Comment ignored.")
                comment = None
        
        port = int(port_str)
        protocol = Protocol(protocol_str.lower())
        action = Action.ACCEPT if action_str.lower() == 'open' else Action.DROP
        
        rule = FirewallRule(
            port=port,
            protocol=protocol,
            action=action,
            source_ip=source_ip,
            destination_ip=destination_ip,
            comment=comment
        )
        
        return self.firewall.add_or_update_rule(rule)
    
    def show_help(self):
        """Displays the comprehensive help message."""
        help_text = f"""
{Colors.BRIGHT_CYAN}╭─────────────────────────────────────────────────────────────╮
│                   {Colors.BRIGHT_YELLOW}DEFFAIN FIREWALL COMMANDS{Colors.BRIGHT_CYAN}                  │
╰─────────────────────────────────────────────────────────────╯{Colors.RESET}

{Colors.BRIGHT_BLUE}🔥 CORE COMMANDS:{Colors.RESET}
  {Colors.BRIGHT_GREEN}enable{Colors.RESET} / {Colors.BRIGHT_GREEN}on{Colors.RESET}           Enable firewall and load saved rules
  {Colors.BRIGHT_RED}disable{Colors.RESET} / {Colors.BRIGHT_RED}off{Colors.RESET}          Disable firewall (delete all Deffain rules from nftables)
  {Colors.BRIGHT_CYAN}status{Colors.RESET}                     Show firewall status and active rules
  {Colors.BRIGHT_MAGENTA}clear-saved-rules{Colors.RESET}        Delete all saved rules from disk ({self.firewall.rules_file})
  {Colors.BRIGHT_YELLOW}help{Colors.RESET}                       Show this help menu

{Colors.BRIGHT_BLUE}🚪 PORT MANAGEMENT:{Colors.RESET}
  {Colors.BRIGHT_GREEN}port open{Colors.RESET} <port> [protocol] [from/to ip] [comment "description"]
  {Colors.BRIGHT_RED}port close{Colors.RESET} <port> [protocol] [from/to ip] [comment "description"]

{Colors.BRIGHT_BLUE}📋 PARAMETERS:{Colors.RESET}
  {Colors.BRIGHT_YELLOW}<port>:{Colors.RESET} Port number to open or close (1-65535).
  {Colors.BRIGHT_YELLOW}[protocol]:{Colors.RESET} Optional. 'tcp', 'udp', or 'both'. Default: 'tcp'.
  {Colors.BRIGHT_YELLOW}[from/to ip]:{Colors.RESET} Optional. Specific source ('from') or destination ('to') IP address/CIDR block.
                      Examples: 192.168.1.1, 10.0.0.0/8, 2001:db8::/32
  {Colors.BRIGHT_YELLOW}[comment "description"]:{Colors.RESET} Optional. Adds a description to the rule. Description must be in quotes.

{Colors.BRIGHT_BLUE}💡 USAGE EXAMPLES:{Colors.RESET}
  {Colors.DIM}sudo python3 deffain.py 'port open 22'{Colors.RESET}
  {Colors.DIM}sudo python3 deffain.py 'port open 80 tcp comment "Web Server Access"'{Colors.RESET}
  {Colors.DIM}sudo python3 deffain.py 'port close 22 tcp'{Colors.RESET}
  {Colors.DIM}sudo python3 deffain.py 'status'{Colors.RESET}
  {Colors.DIM}sudo python3 deffain.py 'enable'{Colors.RESET}
  {Colors.DIM}sudo python3 deffain.py 'clear-saved-rules'{Colors.RESET}

{Colors.BRIGHT_BLUE}🔐 SECURITY NOTES:{Colors.RESET}
  • Default incoming policy: {Colors.BRIGHT_RED}DROP{Colors.RESET} (blocks all unwanted traffic)
  • Established and related connections are automatically allowed.
  • Loopback traffic is always open.
  • ICMP (ping) traffic is allowed.

{Colors.DIM}For more information: https://github.com/deffain/firewall{Colors.RESET}
"""
        print(help_text)

def main():
    """Main function - processes command line arguments."""
    if len(sys.argv) < 2:
        UI.print_banner()
        print(f"{Colors.BRIGHT_CYAN}Usage:{Colors.RESET} sudo python3 {sys.argv[0]} '<command>'")
        UI.info(f"Example: sudo python3 {sys.argv[0]} 'help' or 'status'")
        sys.exit(1)

    command_str = sys.argv[1]
    
    # For 'help' command, skip root permission requirement and print output quickly.
    if command_str.lower() == 'help':
        UI.print_banner()
        parser = CommandParser(DeffainFirewall(quiet_mode=True)) 
        parser.show_help()
        sys.exit(0)
    
    firewall = DeffainFirewall()
    parser = CommandParser(firewall)
    parser.parse_command(command_str)

if __name__ == "__main__":
    main()
