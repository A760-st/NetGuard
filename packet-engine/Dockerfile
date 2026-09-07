FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /packet-engine ./cmd/server

FROM alpine:3.18

RUN apk --no-cache add ca-certificates

COPY --from=builder /packet-engine /packet-engine

EXPOSE 8001

CMD ["/packet-engine"]
