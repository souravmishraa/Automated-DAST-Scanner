# Optional: bundles security-framework together with Katana + Nuclei.
# OWASP ZAP still runs via the host's Docker daemon (docker-in-docker or a
# sibling container), so this image needs the docker CLI + socket mounted,
# or you can set zap.mode to "local" and layer ZAP into this image yourself.
#
# Build:  docker build -t security-framework .
# Run:    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
#           -v "$PWD/output:/app/output" security-framework scan https://example.com

FROM golang:1.22-bookworm AS tools

RUN go install github.com/projectdiscovery/katana/cmd/katana@latest \
 && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

FROM node:20-bookworm-slim

# Docker CLI (client only) so the container can drive ZAP via the mounted
# host socket, without bundling a full Docker-in-Docker daemon.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl gnupg \
 && install -m 0755 -d /etc/apt/keyrings \
 && curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
 && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable" \
      > /etc/apt/sources.list.d/docker.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends docker-ce-cli \
 && rm -rf /var/lib/apt/lists/*

COPY --from=tools /go/bin/katana /usr/local/bin/katana
COPY --from=tools /go/bin/nuclei /usr/local/bin/nuclei

WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev --no-audit --no-fund

COPY . .

ENTRYPOINT ["node", "bin/cli.js"]
CMD ["--help"]
