# syntax=docker/dockerfile:1
FROM node:24.22.1-alpine

ENV NODE_ENV=production
WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

RUN chown -R node:node /app
USER node

EXPOSE 8080

# Simple healthcheck. Adjust path if your app exposes /health.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/health || exit 1

CMD ["node", "server.js"]
