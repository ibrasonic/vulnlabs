# Node 24 LTS — required for the built-in `node:sqlite` module (DatabaseSync).
FROM node:24-bookworm-slim
WORKDIR /app
COPY package.json ./
RUN npm install --no-fund --no-audit
COPY . .
RUN mkdir -p /app/data
ENV PORT=3002 HOST=0.0.0.0 EMAIL_SERVICE_URL=http://email:5002
EXPOSE 3002
CMD ["node", "server.js"]
