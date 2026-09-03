# syntax=docker/dockerfile:1
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27.1-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION
ARG COMMIT
ARG BUILD_DATE
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,id=hoolicy-go-mod,target=/go/pkg/mod,sharing=shared go mod download
COPY hoolicy.go ./
COPY cmd ./cmd
COPY internal ./internal
COPY sdk ./sdk
RUN --mount=type=cache,id=hoolicy-go-mod,target=/go/pkg/mod,sharing=shared \
    --mount=type=cache,id=hoolicy-go-build,target=/root/.cache/go-build,sharing=shared \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -buildvcs=false -tags=hoolicy_release -trimpath \
    -ldflags="-s -w -buildid= -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${BUILD_DATE}" \
    -o /out/rootfs/hoolicy ./cmd/hoolicy && \
    mkdir -m 1777 /out/rootfs/tmp && \
    touch /out/rootfs/tmp/.keep

FROM scratch
ARG VERSION
ARG COMMIT
ARG BUILD_DATE
LABEL org.opencontainers.image.title="Hoolicy" \
      org.opencontainers.image.description="Understandable repository policy as code" \
      org.opencontainers.image.source="https://github.com/openhoo/hoolicy" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$COMMIT" \
      org.opencontainers.image.created="$BUILD_DATE" \
      org.opencontainers.image.licenses="Apache-2.0"
USER 65532:65532
COPY --from=build /out/rootfs/ /
ENTRYPOINT ["/hoolicy"]
