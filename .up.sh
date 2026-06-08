#!/usr/bin/env bash
for app in vuln-bank vuln-shop vuln-social; do
  cd "/mnt/d/TechBooks/VulnLabs/${app}" && docker compose up -d 2>&1 | tail -3
done
echo ----
docker ps --format '{{.Names}} {{.Status}}'
