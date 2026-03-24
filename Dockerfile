FROM node:20-bookworm-slim

WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends python3 make g++ \
  && rm -rf /var/lib/apt/lists/*

COPY package.json ./
RUN npm install --omit=dev \
  && npm cache clean --force

COPY src ./src
COPY public ./public
COPY data/oauth ./data/oauth
COPY data/oauth ./bootstrap-data/oauth
COPY .env.example ./.env.example

RUN mkdir -p /app/data \
  && chown -R node:node /app

ENV NODE_ENV=production
ENV PORT=9000
ENV ISSUER=http://localhost:9000
ENV TRUST_PROXY=false

EXPOSE 9000

USER node

CMD ["npm", "start"]
