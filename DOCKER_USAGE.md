# Docker Usage Examples

## Build the image

docker build -t rc-unlock .

## Run with mounted volumes

### Basic usage with all files mounted:
docker run -it \
  -v /path/to/inventory:/inventory \
  -v /path/to/vault.kdbx:/secrets/vault.kdbx \
  -e UR_CDB_PW="your_password" \
  rc-unlock \
  -i /inventory/all.yml \
  -k /secrets/vault.kdbx \
  -e "root - test initramfs"

### Using environment variables for all configuration:
docker run -it \
  -v /path/to/inventory:/inventory \
  -v /path/to/vault.kdbx:/secrets/vault.kdbx \
  -e UR_INVENTORY=/inventory/all.yml \
  -e UR_KDBXFILE=/secrets/vault.kdbx \
  -e UR_CDB_ENTRY="root - test initramfs" \
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
  -e "root - test initramfs"

## Docker Compose Example

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
      - UR_CDB_ENTRY=root - test initramfs
      - UR_CDB_PW=${UR_CDB_PW}
      - UR_INVENTORY_GROUP=all
      - UR_DELAY=30
    restart: unless-stopped
```

## Notes

- Mount your inventory file as a volume
- Mount your KeePass database as a volume
- Use environment variables for passwords (safer) or use -it for interactive mode
- The container runs as non-root user for security
