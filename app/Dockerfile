FROM golang:1.26

WORKDIR /work

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o /app .


ENV LOKI_HOST="loki-headless.monitoring.svc.cluster.local"


CMD ["/app"]
