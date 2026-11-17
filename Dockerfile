FROM node:22-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY server.js ./
COPY gatekeeper/ ./gatekeeper/
COPY shared/ ./shared/
# NOTE: circuits/ are the official files from
# https://agentgames.zkverify.io/circuits/ (hashes in README.md).
# They are fetched at build time, hash-verified, so the repo stays
# text-only and Railway can build it straight from GitHub.
# (An earlier Dockerfile flattened everything into /app with one COPY,
# which would have crashed the server — ./shared/hmac would not exist.)
RUN apk add --no-cache curl \
 && mkdir -p circuits \
 && curl -fsSL -o circuits/gatekeeper.wasm https://agentgames.zkverify.io/circuits/gatekeeper.wasm \
 && curl -fsSL -o circuits/gatekeeper_final.zkey https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey \
 && echo "be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f  circuits/gatekeeper.wasm" | sha256sum -c - \
 && echo "adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d  circuits/gatekeeper_final.zkey" | sha256sum -c -
ENV NODE_ENV=production
EXPOSE 8080
CMD ["node", "server.js"]
