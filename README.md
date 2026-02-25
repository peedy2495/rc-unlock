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

Custom Properties:
  - deployment_password: DeploymentPassword123 (optional)
```

#### Optional: Deployment Password for Secure Password Updates

The tool supports a **secure password update mechanism** using a custom property called `deployment_password`. This is useful for:

- Post-deployment security hardening: After auto-deployments that use temporary/dummy LUKS passwords
- Updating systems that were initially deployed with insecure default passwords
- Rolling to secure passwords without manual intervention

**How it works:**

1. When the primary LUKS password fails (wrong password), the tool checks for a `deployment_password` in the KeePass entry's custom properties
2. If found, it attempts to change the LUKS password:
   - **Old password**: The `deployment_password` value (the temporary/dummy password from deployment)
   - **New password**: The password stored in the KeePass entry's password field (the secure password)
3. On success, the system reboots with the new secure password

**Setting up deployment_password:**

In KeePass, add a custom property to your entry:
- Property name: `deployment_password`
- Property value: The temporary/dummy password used during initial deployment

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

## Security Considerations

- **Never commit** your KeePass database or passwords
- **Use Docker secrets** for production deployments (see [DOCKER_USAGE.md](DOCKER_USAGE.md))
- Environment variables (`UR_CDB_PW`) are visible in `docker inspect` and process lists - avoid in production
- The `.gitignore` excludes `*.kdbx`, `secrets/`, and environment files
- Docker image runs as non-root user
- SSH keys are never written to disk, kept in memory only
- Set restrictive permissions on password files: `chmod 600 password.txt`
