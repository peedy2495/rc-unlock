#!/usr/bin/env python3
"""
Remote LUKS unlock tool using Ansible inventory and a kdbx credential database.
"""

from dataclasses import dataclass
from getpass import getpass
from typing import List, Optional, Tuple
import argparse
import io
import os
import re
import sys
import time
import yaml

import paramiko
from pykeepass import PyKeePass

from interactive_shell import (
    InteractiveShellSession,
    ExpectTimeoutError,
    SessionClosedError,
)

# Constants

DEFAULT_SSH_PORT = 22022
DEFAULT_DELAY = 30
SLEEP_AFTER_UNLOCK = 1.0
RECV_BUFFER_SIZE = 1024
SUCCESS_EXIT_CODES = {0}
ENV_VARS = {
    'inventory': 'UR_INVENTORY',
    'group': 'UR_INVENTORY_GROUP',
    'kdbxfile': 'UR_KDBXFILE',
    'entry': 'UR_CDB_ENTRY',
    'password': 'UR_CDB_PW',
    'password_file': 'UR_CDB_PW_FILE',
    'delay': 'UR_DELAY',
}

# Data Structures

@dataclass
class Host:
    """Represents a host from inventory."""
    name: str
    ip: str
    path: str


@dataclass
class Credentials:
    """Represents credentials from credential database."""
    username: str
    luks_password: str
    private_key: str
    default_password: Optional[str] = None


# Custom Exceptions

class CredentialDBError(Exception):
    """Custom exception for credential database errors."""
    pass


class SSHConnectionError(Exception):
    """Custom exception for SSH connection errors."""
    pass


# Main Entry Point

def main() -> int:
    """Main entry point."""
    args = parse_arguments()
    validate_args(args)
    try:
        credentials = get_credentials(args.kdbxfile, args.entry)
    except CredentialDBError as e:
        print(f"❌ {e}")
        return 1
    
    while True:
        hosts = parse_inventory(args.inventory, args.group)
        
        if not hosts:
            print("❌ No valid hosts found in inventory.")
            countdown_timer(args.delay)
            continue
        
        print(f"📋 Found hosts: {len(hosts)}")
        for host in hosts:
            print(f"     {host.name} @ {host.ip} [{host.path}]")
        print()
        
        success_count, total = process_hosts(hosts, credentials)
        
        print(f"{'='*50}")
        print(f"✅ Summary: {success_count}/{total} hosts successfully unlocked\n")
        
        countdown_timer(args.delay)


# CLI and Validation

def parse_arguments() -> argparse.Namespace:
    """Parse and return command line arguments."""
    password_help = """
The password for the credential database can be provided in three ways:
  1. Docker secret file (recommended): Mount secret to /run/secrets/ur_cdb_pw
  2. Environment variable: Set UR_CDB_PW (not recommended for production)
  3. Enter it manually when prompted (most secure but requires interaction)
The methods are checked in order of security (file first, then env, then prompt).
"""
    
    parser = argparse.ArgumentParser(
        description='Unlock remote host boot processes via Ansible inventory and credential database',
        epilog=password_help,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '-i', '--inventory',
        default=os.environ.get(ENV_VARS['inventory']),
        help='Path to Ansible inventory file (or set UR_INVENTORY env var)'
    )
    parser.add_argument(
        '-g', '--group',
        default=os.environ.get(ENV_VARS['group'], 'all'),
        help='Inventory group name (default: all, or set UR_INVENTORY_GROUP env var)'
    )
    parser.add_argument(
        '-d', '--delay',
        type=int,
        default=int(os.environ.get(ENV_VARS['delay'], DEFAULT_DELAY)),
        help=f'Delay between iterations in seconds (default: {DEFAULT_DELAY}, or set UR_DELAY env var)'
    )
    parser.add_argument(
        '-k', '--kdbxfile',
        default=os.environ.get(ENV_VARS['kdbxfile']),
        help='Path to credential database .kdbx file (or set UR_KDBXFILE env var)'
    )
    parser.add_argument(
        '-e', '--entry',
        default=os.environ.get(ENV_VARS['entry']),
        help='Credential database entry title (or set UR_CDB_ENTRY env var)'
    )
    
    return parser.parse_args()


def validate_args(args) -> None:
    """Validate that all required arguments are provided."""
    if not args.inventory:
        print("❌ Error: Inventory path must be provided via -i/--inventory argument or UR_INVENTORY environment variable")
        sys.exit(1)
    
    if not args.kdbxfile:
        print("❌ Error: KDBX file path must be provided via -k/--kdbxfile argument or UR_KDBXFILE environment variable")
        sys.exit(1)
    
    if not args.entry:
        print("❌ Error: Entry title must be provided via -e/--entry argument or UR_CDB_ENTRY environment variable")
        sys.exit(1)


# Inventory Parsing

def parse_inventory(inventory_path: str, group_name: str = 'cc') -> List[Host]:
    """Parse Ansible inventory YAML file and return list of hosts."""
    try:
        with open(inventory_path, 'r') as f:
            inventory = yaml.safe_load(f)
    except FileNotFoundError:
        print(f"❌ Inventory file not found: {inventory_path}")
        return []
    except yaml.YAMLError as e:
        print(f"❌ Error parsing YAML file: {e}")
        return []
    except Exception as e:
        print(f"❌ Error reading inventory: {e}")
        return []
    
    hosts: List[Host] = []
    
    # Handle 'all' group specially
    if group_name == 'all':
        source = inventory.get('all', inventory)
        extract_hosts_from_group(source, hosts, 'all')
    else:
        # Look for specific group
        found = False
        
        # Check in all.children
        if 'all' in inventory and 'children' in inventory['all']:
            if group_name in inventory['all']['children']:
                extract_hosts_from_group(
                    inventory['all']['children'][group_name],
                    hosts,
                    f"all/{group_name}"
                )
                found = True
        
        # Check at root level
        if not found and group_name in inventory:
            extract_hosts_from_group(inventory[group_name], hosts, group_name)
            found = True
        
        if not found:
            print(f"⚠️  Group '{group_name}' not found in inventory")
    
    return hosts


def extract_hosts_from_group(group_data: dict, hosts_list: List[Host], current_path: str = '') -> None:
    """Recursively extract hosts from a group structure with path tracking."""
    if not isinstance(group_data, dict):
        return
    
    # Direct hosts in this group
    if 'hosts' in group_data and isinstance(group_data['hosts'], dict):
        for hostname, host_vars in group_data['hosts'].items():
            if isinstance(host_vars, dict):
                ip = host_vars.get('ansible_host')
                if ip and validate_ip(ip):
                    hosts_list.append(Host(
                        name=hostname,
                        ip=ip,
                        path=current_path if current_path else 'all'
                    ))
                elif ip:
                    print(f"⚠️  Invalid IP for host {hostname}: {ip}")
    
    # Children groups
    if 'children' in group_data and isinstance(group_data['children'], dict):
        for child_name, child_data in group_data['children'].items():
            new_path = f"{current_path}/{child_name}" if current_path else child_name
            extract_hosts_from_group(child_data, hosts_list, new_path)


def validate_ip(ip: str) -> bool:
    """Validate IPv4 address format."""
    pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return bool(re.match(pattern, ip))


# Credential Database

def get_credentials(db_path: str, entry_title: str) -> Credentials:
    """Load credentials from credential database."""
    master_pw = get_db_password()
    
    try:
        kp = PyKeePass(db_path, password=master_pw)
        entry = kp.find_entries(title=entry_title, first=True)
        
        if not entry:
            raise CredentialDBError(f"Entry '{entry_title}' not found")
        
        private_key = None
        key_filename = None
        for attachment in entry.attachments:
            if attachment.filename.startswith('id_'):
                private_key = kp.binaries[attachment.id].decode('utf-8')
                key_filename = attachment.filename
                break
        
        if not private_key:
            raise CredentialDBError("No private key attachment found (must start with 'id_')")
        
        default_password = None
        if entry.custom_properties and 'deployment_password' in entry.custom_properties:
            default_password = entry.custom_properties.get('deployment_password')
        
        creds = Credentials(
            username=entry.username,
            luks_password=entry.password,
            private_key=private_key,
            default_password=default_password
        )
        
        print(f"✅ Credential database entry '{entry_title}' loaded successfully.\n")
        del kp
        return creds
        
    except Exception as e:
        raise CredentialDBError(f"Failed to load credentials: {e}")


def get_db_password() -> str:
    """Get credential database password from Docker secret, environment, or prompt."""
    # Check for custom password file path
    password_file = os.environ.get(ENV_VARS['password_file'])
    if password_file and os.path.exists(password_file):
        try:
            with open(password_file, 'r') as f:
                password = f.read().strip()
            if password:
                print("Using password from secret file")
                return password
        except (IOError, OSError) as e:
            print(f"⚠️  Warning: Could not read password file {password_file}: {e}")
    
    # Check for default Docker secret location
    default_secret_path = '/run/secrets/ur_cdb_pw'
    if os.path.exists(default_secret_path):
        try:
            with open(default_secret_path, 'r') as f:
                password = f.read().strip()
            if password:
                print("Using password from Docker secret")
                return password
        except (IOError, OSError) as e:
            print(f"⚠️  Warning: Could not read Docker secret: {e}")
    
    # Fallback to environment variable (for backward compatibility)
    password = os.environ.get(ENV_VARS['password'])
    if password:
        print("Using password from UR_CDB_PW environment variable")
        return password
    
    # Prompt user
    return getpass("Enter credential database master password: ")


# SSH Operations

def process_hosts(hosts: List[Host], credentials: Credentials) -> Tuple[int, int]:
    """Process all hosts and return success count."""
    success_count = 0
    for host in hosts:
        if unlock_host(host, credentials):
            success_count += 1
    return success_count, len(hosts)


def unlock_host(host: Host, credentials: Credentials) -> bool:
    """Attempt to unlock a single host."""
    print(f"🖥️  Processing host: {host.name} @ {host.ip} [{host.path}]")
    print(f"Host {host.ip}: 🔗 Connecting to {host.ip}:{DEFAULT_SSH_PORT} as {credentials.username}...")
    
    try:
        with SSHClient(host.ip, DEFAULT_SSH_PORT, credentials.username, credentials.private_key) as client:
            print(f"Host {host.ip}: ✅ SSH connection established with private key.")
            return execute_cryptroot_unlock(client, credentials.luks_password, host.ip, credentials.default_password)
    except SSHConnectionError as e:
        print(f"Host {host.ip}: ⚪ Probed - {e}")
        return False


class SSHClient:
    """Context manager for SSH connections."""
    
    def __init__(self, host_ip: str, port: int, username: str, private_key: str):
        self.host_ip = host_ip
        self.port = port
        self.username = username
        self.private_key = private_key
        self.client = None
    
    def __enter__(self):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            pkey = load_private_key(self.private_key)
            self.client.connect(self.host_ip, port=self.port, username=self.username, pkey=pkey)
            return self.client
        except paramiko.AuthenticationException:
            raise SSHConnectionError("Authentication failed")
        except (paramiko.SSHException, OSError, TimeoutError, EOFError):
            raise SSHConnectionError("Currently not in boot state")
        except Exception:
            raise SSHConnectionError("Currently not in boot state")
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.client:
            self.client.close()


def load_private_key(key_data: str) -> paramiko.PKey:
    """Try to load private key in different formats."""
    key_file = io.StringIO(key_data)
    key_types = [
        paramiko.RSAKey,
        paramiko.Ed25519Key,
        paramiko.ECDSAKey,
    ]
    
    for key_type in key_types:
        try:
            return key_type.from_private_key(key_file)
        except paramiko.SSHException:
            key_file.seek(0)
    
    raise ValueError("Unknown or invalid private key format")


def execute_cryptroot_unlock(client: paramiko.SSHClient, luks_password: str, host_ip: str, default_password: Optional[str] = None) -> bool:
    """Execute cryptroot-unlock on remote host using interactive shell."""
    print(f"Host {host_ip}: 🔓 Executing cryptroot-unlock...")
    
    try:
        session = InteractiveShellSession(client, timeout=10.0)
        session.open()
        print(f"Host {host_ip}: 📡 Interactive shell session opened")
        
    except Exception as e:
        print(f"Host {host_ip}: ❌ Failed to open interactive shell: {e}")
        return False
    
    try:
        session.sendline("cryptroot-unlock")
        
        try:
            output = session.expect(r"(Please unlock|Enter passphrase|UNLOCK)", timeout=15.0)
            print(f"Host {host_ip}: 🔑 Password prompt detected")
        except ExpectTimeoutError as e:
            print(f"Host {host_ip}: ⚠️  Did not get passphrase prompt: {e}")
            session.close()
            return False
        except SessionClosedError:
            print(f"Host {host_ip}: ❌ Session closed unexpectedly")
            return False
        
        session.sendline(luks_password)
        
        try:
            output = session.expect(r"set up successfully|bad password or options\?", timeout=15.0)
        except ExpectTimeoutError:
            print(f"Host {host_ip}: ⚠️  Timeout waiting for unlock result, checking buffer...")
            output = session.get_buffer()
        except SessionClosedError:
            print(f"Host {host_ip}: 📝 Session closed (may indicate reboot)")
            output = session.get_buffer()
        
        if "set up successfully" in output:
            print(f"Host {host_ip}: ✅ Unlock successful!")
            session.close()
            return True
        
        if "bad password" in output:
            print(f"Host {host_ip}: ❌ Wrong password")
            session.close()
            
            if default_password:
                print(f"Host {host_ip}: 🔄 Trying to change LUKS password...")
                
                try:
                    session2 = InteractiveShellSession(client, timeout=10.0)
                    session2.open()
                except Exception as e:
                    print(f"Host {host_ip}: ❌ Failed to open session for password change: {e}")
                    return False
                
                device = get_luks_device_interactive(session2, host_ip)
                if not device:
                    session2.close()
                    return False
                
                if not change_luks_password_interactive(session2, device, default_password, luks_password, host_ip):
                    session2.close()
                    return False
                
                print(f"Host {host_ip}: 🔄 Rebooting in 5 seconds...")
                session2.sendline("reboot -f")
                
                try:
                    session2.wait_for_close(timeout=5)
                except Exception:
                    pass
                session2.close()
                
                return True
            
            return False
        
        print(f"Host {host_ip}: ⚠️  Unknown response from cryptroot-unlock")
        print(f"Output: {output[-500:]}")
        session.close()
        return False
        
    except Exception as e:
        print(f"Host {host_ip}: ❌ Unexpected error during unlock: {e}")
        try:
            session.close()
        except Exception:
            pass
        return False


def get_luks_device_interactive(session: InteractiveShellSession, host_ip: str) -> Optional[str]:
    """Get the first LUKS device on the remote host using interactive shell."""
    print(f"Host {host_ip}: 🔍 Determining LUKS device...")
    
    session.clear_buffer()
    
    session.sendline("/usr/sbin/blkid")
    time.sleep(0.5)
    
    try:
        output = session.expect(r"(#|\$)", timeout=10.0)
    except ExpectTimeoutError:
        output = session.get_buffer()
    except SessionClosedError:
        output = session.get_buffer()
    
    full_buffer = session.get_buffer()
    lines = full_buffer.strip().split('\n')
    
    device = None
    for line in lines:
        line = line.strip()
        if line.startswith('/dev/') and 'LUKS' in line:
            device = line.split(':')[0]
            break
    
    if not device:
        print(f"Host {host_ip}: ❌ No LUKS device found, buffer: {full_buffer[-200:]}")
        return None
    
    print(f"Host {host_ip}: 📁 Found LUKS device: {device}")
    return device


def change_luks_password_interactive(
    session: InteractiveShellSession,
    device: str,
    old_password: str,
    new_password: str,
    host_ip: str
) -> bool:
    """Change the LUKS password on the remote host using interactive shell."""
    print(f"Host {host_ip}: 🔐 Changing LUKS password on {device}...")
    
    session.clear_buffer()
    
    cmd = f"echo -e '{old_password}\\n{new_password}\\n{new_password}\\n' | /usr/sbin/cryptsetup luksChangeKey {device} --key-slot 0 --batch-mode 2>&1"
    
    try:
        session.sendline(cmd)
        time.sleep(1)
        output = session.expect(r"(#|\$|success|failed|Error|Command)", timeout=30.0)
    except ExpectTimeoutError:
        print(f"Host {host_ip}: ⚠️  Timeout during password change, checking result...")
        output = session.get_buffer()
    except SessionClosedError:
        print(f"Host {host_ip}: 📝 Session closed (may indicate success)")
        output = session.get_buffer()
    
    if "failed" in output.lower() or "error" in output.lower():
        print(f"Host {host_ip}: ❌ Failed to change LUKS password")
        return False
    
    print(f"Host {host_ip}: ✅ LUKS password changed successfully!")
    return True


# Utilities

def countdown_timer(seconds: int) -> None:
    """Display a countdown timer that updates in place."""
    for remaining in range(seconds, 0, -1):
        sys.stdout.write(f"\r⏳ Waiting {remaining} seconds before next iteration...")
        sys.stdout.flush()
        time.sleep(1)
    sys.stdout.write("\r" + " " * 50 + "\r")
    sys.stdout.flush()
    sys.stdout.flush()


# Let's start with main ;-)

if __name__ == "__main__":
    sys.exit(main())
