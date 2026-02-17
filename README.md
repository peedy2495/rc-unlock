# Remote Cryptroot Unlock Tool

A Python tool to remotely unlock LUKS-encrypted hosts during the initramfs boot phase using SSH. Designed to work with Ansible inventories and KeePass-compatible credential databases.

## Features

- 🔐 **Secure Credential Management**: Uses KeePass (.kdbx) files for storing credentials
- 📦 **Ansible Inventory Support**: Reads host lists from Ansible YAML inventories
- 🔄 **Continuous Monitoring**: Runs in a loop with configurable delays, re-reading inventory each iteration
- 🖥️ **Multiple Hosts**: Unlock multiple hosts in sequence
- 🐳 **Docker Support**: Run in containerized environments
- 🔑 **SSH Key Authentication**: Uses Ed25519 private keys from KeePass attachments
- ⏱️ **Smart Probing**: Gracefully handles hosts not yet in boot state

## Requirements

- Python 3.11+
- KeePass database (.kdbx) with entry containing:
  - Username for SSH connection
  - LUKS decryption password
  - SSH private key (id_ed25519) as attachment
- Ansible inventory file with host definitions
- Target hosts must have:
  - SSH server running on port 22022 during initramfs
  - cryptroot-unlock command available

## Installation

### Local Installation

```bash
# Clone the repository
git clone <repository-url>
cd rc-unlock

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Docker Installation

```bash
# Build the Docker image
docker build -t rc-unlock .
```

## Configuration

### KeePass Database Setup

The tool requires a KeePass database (.kdbx) with a specific entry structure. Each entry must contain the following fields:

#### Required Fields

| Field | Description | Example |
|-------|-------------|---------|
| **Entry Title** | Unique identifier for this entry (used with `-e` flag) | `LUKS unlock` |
| **Username** | SSH username for connecting to the target host | `root` |
| **Password** | LUKS disk encryption password | `MySecretPassword0` |
| **Attachment** | SSH private key file (must start with `id_`) | `id_ed25519`, `id_rsa`, etc. |

#### Entry Structure Details

**Entry Title**
- Used to identify which credentials to load via the `-e` or `--entry` argument
- Can be any descriptive name you choose
- Must match exactly when specified on command line

**Username**
- The SSH username for connecting to hosts in initramfs
- Typically `root` for initramfs unlock operations
- Used for SSH authentication alongside the private key

**Password**
- The LUKS disk encryption passphrase
- This is **NOT** the SSH password - it's the disk unlock password
- Sent to `cryptroot-unlock` command on the remote host
- Kept in memory only, never written to disk

**Attachment: SSH Private Key**
- Must be attached with a filename starting with `id_` (e.g., `id_ed25519`, `id_rsa`, `id_ecdsa`, `id_dsa`)
- The tool automatically uses the **first** attachment that starts with `id_`
- Supports Ed25519, RSA, ECDSA, and DSA key formats
- The private key used for SSH authentication
- Should be the private key corresponding to the authorized key on the target host

#### Example Entry

```
Title:    LUKS unlock
Username: root
Password: MySecretLUKSPassword

Attachments:
  - id_ed25519 (SSH Ed25519 private key file)
```

Or with an RSA key:

```
Title:    production-server
Username: root
Password: DiskEncryptionPassword

Attachments:
  - id_rsa (SSH RSA private key file)
```

### Ansible Inventory

Create a YAML inventory file:

```yaml
all:
  children:
    servers:
      hosts:
        server1:
          ansible_host: 192.168.0.11
        server2:
          ansible_host: 192.168.0.12
```

## Usage

### Command Line Arguments

```
-i, --inventory    Path to Ansible inventory file (or UR_INVENTORY env var)
-g, --group        Inventory group name (default: all)
-d, --delay        Delay between iterations in seconds (default: 30, or set UR_DELAY env var)
-k, --kdbxfile     Path to credential database .kdbx file (or UR_KDBXFILE env var)
-e, --entry        Credential database entry title (or UR_CDB_ENTRY env var)
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `UR_INVENTORY` | Path to Ansible inventory file |
| `UR_INVENTORY_GROUP` | Inventory group name (default: all) |
| `UR_DELAY` | Delay between iterations in seconds (default: 30) |
| `UR_KDBXFILE` | Path to KeePass database |
| `UR_CDB_ENTRY` | KeePass entry title |
| `UR_CDB_PW_FILE` | Path to password file (for Docker secrets, optional) |
| `UR_CDB_PW` | KeePass master password (optional, not recommended for production) |

**Password Priority Order:**
1. **Docker Secret File** (`/run/secrets/ur_cdb_pw` or `UR_CDB_PW_FILE`) - Most secure, recommended for production
2. **Environment Variable** (`UR_CDB_PW`) - Convenient but visible in process lists
3. **Interactive Prompt** - Most secure but requires manual intervention

### Basic Usage

#### With Manual Password Entry

```bash
python rc-unlock.py \
  -i /path/to/inventory.yml \
  -k /path/to/vault.kdbx \
  -e "LUKS unlock"
```

#### With Environment Variables (No Password Prompt)

```bash
export UR_INVENTORY="/path/to/inventory.yml"
export UR_KDBXFILE="/path/to/vault.kdbx"
export UR_CDB_ENTRY="LUKS unlock"
export UR_CDB_PW="your_password"
export UR_DELAY=60

python rc-unlock.py
```

#### Specific Group with Custom Delay

```bash
python rc-unlock.py \
  -i inventory.yml \
  -g cc \
  -k vault.kdbx \
  -e "LUKS unlock" \
  -d 60
```

### Docker Usage

For detailed Docker instructions including:
- Building the image
- Running with volume mounts
- **Using Docker Secrets (recommended)**
- Using Docker Compose
- Environment variable configuration
- Multiple usage examples

**See [DOCKER_USAGE.md](DOCKER_USAGE.md)** for complete documentation.

Quick start with Docker secrets:
```bash
# Create password file
mkdir -p secrets
echo "your_password" > secrets/password.txt
chmod 600 secrets/password.txt

# Run with docker compose
docker compose up -d
```

## How It Works

1. **Load Credentials**: Reads username, LUKS password, and SSH key from KeePass
2. **Parse Inventory**: Extracts hosts from Ansible inventory with their IPs
3. **Iterate**: For each host:
   - Attempt SSH connection on port 22022
   - If host not in boot state: skip gracefully
   - If connected: execute `cryptroot-unlock`
   - Send LUKS password via stdin
   - Wait for completion
4. **Wait**: Countdown timer before next iteration
5. **Repeat**: Re-reads inventory each iteration to detect changes

## Output Examples

### First Iteration with Mixed Results

```
📋 Found hosts: 3
     server1 @ 192.168.0.222 [all/servers]
     server2 @ 192.168.0.223 [all/servers]
     db-server @ 192.168.0.224 [all/servers]

🖥️  Processing host: server1 @ 192.168.0.222 [all/servers]
Host 192.168.0.222: 🔗 Connecting to 192.168.0.222:22022 as root...
Host 192.168.0.222: ✅ SSH connection established with private key.
Host 192.168.0.222: 🔓 Executing cryptroot-unlock...
Host 192.168.0.222: ✅ Unlock successful!

🖥️  Processing host: server2 @ 192.168.0.223 [all/servers]
Host 192.168.0.223: 🔗 Connecting to 192.168.0.223:22022 as root...
Host 192.168.0.223: ⚪ Probed - currently not in boot state

🖥️  Processing host: db-server @ 192.168.0.224 [all/servers]
Host 192.168.0.224: 🔗 Connecting to 192.168.0.224:22022 as root...
Host 192.168.0.224: ❌ Authentication failed.

==================================================
✅ Summary: 1/3 hosts successfully unlocked

⏳ Waiting 30 seconds before next iteration...
```

### Second Iteration - Host Now in Boot State

```
📋 Found hosts: 3
     server1 @ 192.168.0.222 [all/servers]
     server2 @ 192.168.0.223 [all/servers]
     db-server @ 192.168.0.224 [all/servers]

🖥️  Processing host: server2 @ 192.168.0.223 [all/servers]
Host 192.168.0.223: 🔗 Connecting to 192.168.0.223:22022 as root...
Host 192.168.0.223: ✅ SSH connection established with private key.
Host 192.168.0.223: 🔓 Executing cryptroot-unlock...
Host 192.168.0.223: ✅ Unlock successful!

==================================================
✅ Summary: 1/3 hosts successfully unlocked

⏳ Waiting 30 seconds before next iteration...
```

### Using Environment Variables

```
$ export UR_CDB_PW="mypassword"
$ export UR_DELAY=60
$ python rc-unlock.py -i inventory.yml -k vault.kdbx -e "LUKS unlock"
Using password from UR_CDB_PW environment variable
✅ Credential database entry 'LUKS unlock' loaded successfully.

📋 Found hosts: 1
     server1 @ 192.168.0.222 [all/servers]

🖥️  Processing host: server1 @ 192.168.0.222 [all/servers]
Host 192.168.0.222: 🔗 Connecting to 192.168.0.222:22022 as root...
Host 192.168.0.222: ✅ SSH connection established with private key.
Host 192.168.0.222: 🔓 Executing cryptroot-unlock...
Host 192.168.0.222: ✅ Unlock successful!

==================================================
✅ Summary: 1/1 hosts successfully unlocked

⏳ Waiting 60 seconds before next iteration...
```

## Exit Codes

The tool handles special exit codes from `cryptroot-unlock`:
- **0**: Success
- **-1**: Success (process terminated after unlock)
- Other: Error during unlock

## Security Considerations

- **Never commit** your KeePass database or passwords
- **Use Docker secrets** for production deployments (see [DOCKER_USAGE.md](DOCKER_USAGE.md))
- Environment variables (`UR_CDB_PW`) are visible in `docker inspect` and process lists - avoid in production
- The `.gitignore` excludes `*.kdbx`, `secrets/`, and environment files
- Docker image runs as non-root user
- SSH keys are never written to disk, kept in memory only
- Set restrictive permissions on password files: `chmod 600 password.txt`

## Troubleshooting

### "Entry not found"
- Verify the entry title matches exactly (case-sensitive)
- Check that the entry exists in the specified KeePass file

### "No private key attachment found"
- Ensure the SSH key is attached with a filename starting with `id_` (e.g., `id_ed25519`, `id_rsa`)
- The tool uses the first attachment that matches this pattern
- Check attachment is in the correct entry
- Supported formats: `id_ed25519`, `id_rsa`, `id_ecdsa`, `id_dsa`

### "Currently not in boot state"
- Host is not in initramfs/initrd phase yet
- Wait for next iteration (normal behavior)
- Verify SSH is accessible on port 22022

### LSP/IDE Import Errors
These are static analysis warnings, not runtime errors:
- VS Code: Select interpreter from `venv/bin/python`
- PyCharm: Set project interpreter to venv
- Code runs correctly regardless

## Development

### Project Structure

```
rc-unlock/
├── rc-unlock.py    # Main script
├── requirements.txt    # Python dependencies
├── Dockerfile         # Docker image definition
├── .gitignore        # Git ignore patterns
├── .dockerignore     # Docker ignore patterns
├── DOCKER_USAGE.md   # Docker-specific documentation
└── venv/             # Virtual environment (not in git)
```

### Code Organization

The script is organized into logical sections:
1. **Data Structures**: Host and Credentials dataclasses
2. **Exceptions**: Custom error classes
3. **Main Entry Point**: High-level flow
4. **CLI & Validation**: Argument parsing
5. **Inventory Parsing**: Ansible inventory handling
6. **Credential Database**: KeePass integration
7. **SSH Operations**: Connection and unlock logic
8. **Utilities**: Helper functions

## License

[Your License Here]

## Contributing

[Your Contributing Guidelines Here]
