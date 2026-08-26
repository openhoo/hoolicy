# syntax=docker/dockerfile:1
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26-alpine AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION
ARG COMMIT
ARG BUILD_DATE
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${BUILD_DATE}" \
    -o /out/hoolicy ./cmd/hoolicy

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
COPY --from=build /out/hoolicy /hoolicy
ENTRYPOINT ["/hoolicy"]
