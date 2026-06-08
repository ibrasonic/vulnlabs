#!/usr/bin/env bash
set -e
for app in vuln-bank vuln-shop vuln-social; do
    echo "=== ${app}: up --build -d ==="
    (cd /mnt/d/TechBooks/VulnLabs/${app} && docker compose up --build -d 2>&1 | tail -8)
done
echo
echo "=== status ==="
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
