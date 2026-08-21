FROM golang:1.26

WORKDIR /work



# Copy the rest of the application code inside ./app
COPY . .

# Build the binary
RUN go build -o /app .

# Fallback environment variable (overridden by Kubernetes at runtime)
ENV LOKI_HOST="loki-headless.monitoring.svc.cluster.local"

CMD ["/app"]
