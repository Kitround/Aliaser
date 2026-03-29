# Aliaser

Web app for managing email aliases via OVH, Infomaniak, SimpleLogin, Addy.io, and Cloudflare.

## Project structure

```
app/                — Web application (PHP + JS)
extensions/
  chrome/           — Chrome extension (MV3)
  firefox/          — Firefox extension
docker/             — Dockerfile, entrypoint
docker-compose.yml
aliaser_docker.sh
```

## Requirements

- A server with the app files
- A separate VM running Docker and Portainer
- SSH access from the server to the VM

## Installation

### 1. Generate a secret key

```bash
openssl rand -hex 32
```

Keep this value — it encrypts your credentials.

### 2. Deploy to the VM

```bash
chmod +x aliaser_docker.sh
./aliaser_docker.sh
```

This script syncs the files to the VM and builds the Docker image.

### 3. Create the stack in Portainer

In Portainer → Stacks → Add stack → Web editor:

```yaml
services:
  aliaser:
    image: aliaser:latest
    pull_policy: never
    ports:
      - "8090:80"
    volumes:
      - ~/aliaser/app/json:/var/www/html/json
    environment:
      ALIASER_SECRET_KEY: "your_key_here"
    restart: unless-stopped
```

Replace `your_key_here` with the key generated in step 1.

### 4. Deploy the stack

Click **Deploy the stack**. The app is available at `http://VM_IP:8090`.

## Updates

After modifying the app files, redeploy with:

```bash
./aliaser_docker.sh
```

Portainer will restart the container automatically with the new image.
