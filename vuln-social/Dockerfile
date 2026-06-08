# Node 24 LTS — required for the built-in `node:sqlite` module (DatabaseSync).
FROM node:24-bookworm-slim
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev --no-fund --no-audit
COPY . .
RUN mkdir -p /app/data
ENV PORT=3003 HOST=0.0.0.0
EXPOSE 3003
CMD ["node", "server.js"]
