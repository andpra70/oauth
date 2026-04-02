FROM node:20-bookworm-slim AS build

WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends python3 make g++ \
  && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json ./
RUN npm ci

COPY src ./src
COPY public ./public
COPY frontend ./frontend
COPY vite.config.js ./vite.config.js
COPY data/oauth ./data/oauth
COPY data/oauth ./bootstrap-data/oauth
COPY .env.example ./.env.example
COPY .env.prod ./.env

RUN npm run ui:build \
  && npm prune --omit=dev \
  && npm cache clean --force


FROM node:20-bookworm-slim

WORKDIR /app

COPY --from=build --chown=node:node /app /app

ENV NODE_ENV=production
ENV PORT=9000

EXPOSE 9000

USER node

CMD ["npm", "start"]
