# Misconfigured caching reverse proxy for the web-cache-poisoning demo (Ch 12).
# Dependency-free (Node built-in http only), so no npm install is needed.
FROM node:24-bookworm-slim
WORKDIR /app
COPY cache-proxy.js ./
ENV PORT=8001
EXPOSE 8001
CMD ["node", "cache-proxy.js"]
