FROM golang:1.26

WORKDIR /work

COPY . .

RUN go mod download

RUN go build -o /app .


ENV LOKI_HOST="loki-headless.monitoring.svc.cluster.local"


CMD ["/app"]
