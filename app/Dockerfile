FROM golang:1.26



WORKDIR /app

# Copy dependency files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

RUN go build -a -o app .

# Fallback environment variable (overridden by Kubernetes at runtime)
ENV LOKI_HOST="loki-headless.monitoring.svc.cluster.local"
ENV TEMPO_HOST="tempo.monitoring.svc.cluster.local"

CMD ["./app"]


