# walt GUI — build-only image. The install does `docker buildx build` then
# copies /app/build (the SvelteKit adapter-static SPA) to ${WALT_GUI_DIR} on the
# host, where waltd serves it. CodeMirror 6 + shadcn-svelte are bundled by Vite
# at build time — the browser loads nothing from any CDN.

FROM node:22-bookworm-slim AS builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build
