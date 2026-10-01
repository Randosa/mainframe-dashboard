FROM node:24-bookworm-slim
WORKDIR /app
COPY package.json pnpm-lock.yaml ./
RUN npm install -g pnpm@11.25.0 && pnpm install --prod --frozen-lockfile --ignore-scripts && mkdir -p /data /secrets && chown node:node /data /secrets
COPY --chown=node:node src ./src
COPY --chown=node:node public ./public
USER node
ENV NODE_ENV=production PORT=3000 DATA_DIR=/data KEY_FILE=/secrets/vault.key
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s CMD node -e "fetch('http://127.0.0.1:3000/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "src/server.js"]
