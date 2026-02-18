# Docker Usage Examples

## Build the image

### Standard build:
docker build -t rc-unlock .

### Build with BuildKit (recommended):
```bash
DOCKER_BUILDKIT=1 docker build -t rc-unlock:secure .
```

### Build with custom labels:
```bash
DOCKER_BUILDKIT=1 docker build \
  --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') \
  --build-arg VERSION=$(git describe --tags --always) \
  --build-arg VCS_REF=$(git rev-parse HEAD) \
  -t rc-unlock:secure .
```

## Security Hardening (New in v2.0+)

The Dockerfile includes several security enhancements:

### Image Security Features

- **Distroless runtime**: No shell, no package manager, minimal attack surface
- **Non-root execution**: Runs as user 65532:65532 (distroless default)
- **OCI labels**: Full metadata and traceability
- **HEALTHCHECK**: Built-in container health monitoring
- **Secure COPY**: Application files with restrictive permissions (644)
- **Build isolation**: Non-root user used during pip install

### Runtime Security Options

For maximum security in production, use these runtime flags:

```bash
docker run -d \
  --name rc-unlock \
  --cap-drop=ALL \
  --security-opt=no-new-privileges:true \
  --memory=256m \
  --cpus=0.5 \
  --read-only \
  --tmpfs /tmp:noexec,nosuid,size=100m \
  -v /path/to/inventory:/inventory:ro \
  -v /path/to/vault.kdbx:/secrets/vault.kdbx:ro \
  --secret ur_cdb_pw \
  rc-unlock:secure \
  -i /inventory/all.yml \
  -k /secrets/vault.kdbx \
  -e "LUKS unlock"
```

**Security flags explained:**
- `--cap-drop=ALL`: Remove all Linux capabilities
- `--security-opt=no-new-privileges:true`: Prevent privilege escalation
- `--memory=256m --cpus=0.5`: Resource limits
- `--read-only`: Read-only root filesystem
- `--tmpfs /tmp`: Writable /tmp that disappears on container stop

## Run with Docker Secrets (Recommended)

### Using Docker secrets (most secure):

# Create a secret
echo "your_password" | docker secret create ur_cdb_pw -

# Run with secret
docker run -it \
  -v /path/to/inventory:/inventory \
  -v /path/to/vault.kdbx:/secrets/vault.kdbx \
  --secret ur_cdb_pw \
  rc-unlock \
  -i /inventory/all.yml \
  -k /secrets/vault.kdbx \
  -e "LUKS unlock"

### Using custom secret file path:
docker run -it \
  -v /path/to/inventory:/inventory \
  -v /path/to/vault.kdbx:/secrets/vault.kdbx \
  -v /path/to/password.txt:/secrets/password.txt:ro \
  -e UR_CDB_PW_FILE=/secrets/password.txt \
  rc-unlock \
  -i /inventory/all.yml \
  -k /secrets/vault.kdbx \
  -e "LUKS unlock"

## Run with Environment Variables (Not Recommended for Production)

### Basic usage with environment variable:
docker run -it \
  -v /path/to/inventory:/inventory \
  -v /path/to/vault.kdbx:/secrets/vault.kdbx \
  -e UR_CDB_PW="your_password" \
  rc-unlock \
  -i /inventory/all.yml \
  -k /secrets/vault.kdbx \
  -e "LUKS unlock"

### Using environment variables for all configuration:
docker run -it \
  -v /path/to/inventory:/inventory \
  -v /path/to/vault.kdbx:/secrets/vault.kdbx \
  -e UR_INVENTORY=/inventory/all.yml \
  -e UR_KDBXFILE=/secrets/vault.kdbx \
  -e UR_CDB_ENTRY="LUKS unlock" \
  -e UR_CDB_PW="your_password" \
  -e UR_INVENTORY_GROUP=all \
  rc-unlock

### Interactive mode (password prompt):
docker run -it \
  -v /path/to/inventory:/inventory \
  -v /path/to/vault.kdbx:/secrets/vault.kdbx \
  rc-unlock \
  -i /inventory/all.yml \
  -k /secrets/vault.kdbx \
  -e "LUKS unlock"

## Docker Compose Examples

### Using Docker secrets (Recommended):

Create a `docker-compose.yml` file:

```yaml
services:
  rc-unlock:
    build: .
    volumes:
      - ./inventory:/inventory:ro
      - ./secrets:/secrets:ro
    environment:
      - UR_INVENTORY=/inventory/all.yml
      - UR_KDBXFILE=/secrets/vault.kdbx
      - UR_CDB_ENTRY=LUKS unlock
      - UR_INVENTORY_GROUP=all
      - UR_DELAY=30
    secrets:
      - ur_cdb_pw
    restart: unless-stopped

secrets:
  ur_cdb_pw:
    file: ./secrets/password.txt
```

Then run:
```bash
# Create the password file
echo "your_password" > ./secrets/password.txt

# Start the service
docker compose up -d
```

### Using environment variables (not recommended for production):

```yaml
services:
  rc-unlock:
    build: .
    volumes:
      - ./inventory:/inventory:ro
      - ./secrets:/secrets:ro
    environment:
      - UR_INVENTORY=/inventory/all.yml
      - UR_KDBXFILE=/secrets/vault.kdbx
      - UR_CDB_ENTRY=LUKS unlock
      - UR_CDB_PW=${UR_CDB_PW}
      - UR_INVENTORY_GROUP=all
      - UR_DELAY=30
    restart: unless-stopped
```

### Production-ready with security hardening:

```yaml
services:
  rc-unlock:
    image: rc-unlock:secure
    volumes:
      - ./inventory:/inventory:ro
      - ./secrets:/secrets:ro
    environment:
      - UR_INVENTORY=/inventory/all.yml
      - UR_KDBXFILE=/secrets/vault.kdbx
      - UR_CDB_ENTRY=LUKS unlock
      - UR_INVENTORY_GROUP=all
      - UR_DELAY=30
    secrets:
      - ur_cdb_pw
    restart: unless-stopped
    # Security hardening
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 256M
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,size=100m

secrets:
  ur_cdb_pw:
    file: ./secrets/password.txt
```

## Security Notes

### Credential Security
- **Docker secrets** are the recommended approach for production environments
- **Environment variables** are visible in `docker inspect` and process lists, avoid in production
- **Interactive mode** is the most secure but requires manual intervention
- Mount volumes as read-only (`:ro`) when possible
- Always protect your password files with appropriate filesystem permissions (600)
- Remove password files from shell history: `history -c` or prefix commands with a space

### Container Security
- The container runs as non-root user (65532:65532) for additional security
- **Distroless base image**: No shell, no package manager, minimal attack surface
- **Build isolation**: Dependencies installed as non-root user during build
- **Secure permissions**: Application files have restrictive permissions (644)
- **Resource limits**: Set CPU and memory limits to prevent resource exhaustion
- **Capability dropping**: Remove all unnecessary Linux capabilities with `--cap-drop=ALL`
- **No new privileges**: Prevent privilege escalation attacks with `--security-opt=no-new-privileges:true`
- **Read-only filesystem**: Run with `--read-only` flag and tmpfs for /tmp

### Image Verification
Verify the security features of your built image:
```bash
# Check non-root user
docker inspect rc-unlock:secure --format 'User: {{.Config.User}}'

# Verify no shell
docker run --rm --entrypoint=/bin/sh rc-unlock:secure  # Should fail

# View security labels
docker inspect rc-unlock:secure --format '{{json .Config.Labels}}' | jq
```

## Migration from Environment Variables to Secrets

To migrate from using `UR_CDB_PW` environment variable to Docker secrets:

1. Create a password file:
   ```bash
   mkdir -p secrets
   echo "your_password" > secrets/password.txt
   chmod 600 secrets/password.txt
   ```

2. Use the docker-compose.yml with secrets configuration (see above)

3. Remove `UR_CDB_PW` from your environment

4. The script will automatically detect and use the secret file
