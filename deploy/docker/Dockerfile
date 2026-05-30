# syntax=docker/dockerfile:1.7

# certctl control-plane image.
#
# Reproducible, minimal (distroless "static", well under 20 MB), and
# unprivileged. It carries BOTH the control plane and the isolated signing
# service (AN-4): in single-node mode certctl supervises certctl-signer as a
# child process, so both binaries ship in one image.
#
# Reproducibility: CGO is disabled, paths are trimmed, the build id is pinned
# empty, and VCS stamping is turned off (the build context excludes .git — see
# .dockerignore). Version metadata is injected via --build-arg, and the release
# pipeline rewrites layer timestamps to SOURCE_DATE_EPOCH.

ARG GO_VERSION=1.25

# ---- build stage ----------------------------------------------------------
FROM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src

# Resolve modules first so they cache independently of source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=1970-01-01T00:00:00Z
ARG TARGETOS=linux
ARG TARGETARCH=amd64

ENV CGO_ENABLED=0 \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH} \
    GOFLAGS=-mod=readonly

# The shipped reproducible flags. Build the control plane and the signer with
# identical flags so a rebuild of the same commit yields identical binaries.
ARG LDFLAGS="-s -w -buildid= -X certctl.io/certctl/internal/buildinfo.version=${VERSION} -X certctl.io/certctl/internal/buildinfo.commit=${COMMIT} -X certctl.io/certctl/internal/buildinfo.date=${DATE}"
RUN go build -trimpath -buildvcs=false -ldflags "${LDFLAGS}" -o /out/certctl        ./cmd/certctl
RUN go build -trimpath -buildvcs=false -ldflags "${LDFLAGS}" -o /out/certctl-signer ./cmd/certctl-signer

# ---- runtime stage --------------------------------------------------------
# Distroless "static" is ~2 MB and ships only CA certificates, tzdata, and a
# nonroot user — no shell, no package manager. Pin by digest in production for a
# fully reproducible base; the release pipeline resolves and records it.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/certctl        /usr/local/bin/certctl
COPY --from=build /out/certctl-signer /usr/local/bin/certctl-signer

# 65532 is distroless' "nonroot" uid:gid — the process never runs as root.
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/certctl"]
