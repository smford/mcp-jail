# Multi-stage Dockerfile for mcp-jail
FROM --platform=$BUILDPLATFORM golang:alpine AS builder
ENV GOTOOLCHAIN=auto

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -trimpath \
    -ldflags="-s -w -X github.com/smford/mcp-jail/internal/cli.version=${VERSION} -X github.com/smford/mcp-jail/internal/cli.commit=${COMMIT} -X github.com/smford/mcp-jail/internal/cli.date=${DATE}" \
    -o /mcp-jail ./cmd/mcp-jail

# Final distroless nonroot image
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /
COPY --from=builder /mcp-jail /usr/local/bin/mcp-jail

EXPOSE 8080
USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/mcp-jail"]
CMD ["proxy", "--help"]
