FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json tsconfig.json ./
RUN npm ci
COPY src ./src
RUN npm run build

FROM node:22-alpine
WORKDIR /app
ENV ATLAS_MCP_DATA_DIR=/data NODE_ENV=production
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=build /app/dist ./dist
# The volume must be owned by the unprivileged user, or the first write to it fails.
RUN mkdir -p /data && chown node:node /data
VOLUME /data
USER node
ENTRYPOINT ["node", "dist/index.js"]
