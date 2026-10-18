# Multi-stage production Dockerfile for mcp-jail
FROM golang:1.26-alpine AS builder

WORKDIR /src

# Download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Build standalone statically linked pure-Go binary
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /bin/mcp-jail ./cmd/mcp-jail

# Minimal scratch runtime using distroless static nonroot
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /

COPY --from=builder /bin/mcp-jail /usr/local/bin/mcp-jail

USER nonroot:nonroot

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/mcp-jail"]
CMD ["--help"]
