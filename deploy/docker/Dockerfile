# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Install ca-certificates for HTTPS/gRPC
RUN apk add --no-cache ca-certificates

# Copy go.mod and go.sum
COPY go.mod go.sum ./

RUN go mod download

# Copy source code
COPY . .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o traceproxy .

# Final stage
FROM scratch

# Copy CA certificates for gRPC/HTTPS connections
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy binary
COPY --from=builder /app/traceproxy /traceproxy

ENTRYPOINT ["/traceproxy"]
