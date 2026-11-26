# syntax=docker/dockerfile:1

FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY go.mod *.go setup_ui.html ./
ARG TARGETOS=linux
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/syncnow-relay .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata wget \
    && adduser -D -H -u 10001 syncnow \
    && mkdir -p /data \
    && chown -R syncnow:syncnow /data

COPY --from=builder /out/syncnow-relay /usr/local/bin/syncnow-relay

USER syncnow
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8787

ENV SYNCNOW_RELAY_ADDR=":8787" \
    SYNCNOW_RELAY_DATA="/data" \
    SYNCNOW_RUNTIME="docker" \
    SYNCNOW_AUTH_API="https://api.xtags.top" \
    SYNCNOW_MAX_ENVELOPES="500" \
    SYNCNOW_MAX_BLOB_MB="25" \
    SYNCNOW_BLOB_TTL_DAYS="7" \
    SYNCNOW_MAX_TMP_FILE_MB="1024" \
    SYNCNOW_MAX_TMP_TOTAL_MB="8192" \
    SYNCNOW_TMP_TTL_HOURS="12" \
    SYNCNOW_TMP_ACK_GRACE_MINUTES="30"

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8787/ping >/dev/null 2>&1 || exit 1

ENTRYPOINT ["/usr/local/bin/syncnow-relay"]
