# Node 24 LTS.  Drives the MySQL-backed bank app via mysql2 + deasync.
FROM node:24-bookworm-slim

# mysql client tools are not required at runtime (we talk over TCP via mysql2),
# but a tiny CA bundle update keeps TLS happy if anyone enables it later.
# iputils-ping gives the admin "network diagnostics" tool a real `ping` binary
# to shell out to (the OS-command-injection sink in routes/admin.js).
RUN apt-get update \
 && apt-get install -y --no-install-recommends iputils-ping ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json ./
RUN npm install --no-fund --no-audit --omit=dev

COPY . .
RUN mkdir -p /app/data && chmod -R 755 /app/data

ENV PORT=3001 HOST=0.0.0.0
EXPOSE 3001

# Seed runs once before the app boots; if the users table already has rows the
# server skips it (see server.js bottom).  This makes `docker compose up -d`
# fully idempotent.
CMD ["node", "server.js"]
