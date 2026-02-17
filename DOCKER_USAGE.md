# Docker Usage Examples

## Build the image

docker build -t rc-unlock .

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

## Security Notes

- **Docker secrets** are the recommended approach for production environments
- **Environment variables** are visible in `docker inspect` and process lists, avoid in production
- **Interactive mode** is the most secure but requires manual intervention
- Mount volumes as read-only (`:ro`) when possible
- The container runs as non-root user for additional security
- Always protect your password files with appropriate filesystem permissions (600)
- Remove password files from shell history: `history -c` or prefix commands with a space

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
