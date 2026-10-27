ARG BUILDER_IMAGE=golang:1.26.10-trixie@sha256:e18951cff6896c16909458a8e0cbd52364a347826ff1f5b86d095fe0670d52e7
# Debian rather than distroless/static because the -tags nvml build
# requires cgo, which links libc dynamically. The bridge then
# dlopen()s libnvidia-ml.so.1 at runtime from the host (bind-mounted
# via the NVIDIA Container Toolkit hook or explicit HostPath mount);
# nothing NVIDIA-specific ships in this image.
ARG BASE_IMAGE=gcr.io/distroless/base-debian12:latest@sha256:e7e678c88c59e70e105a46549bb3fbfb3d732ee3b4afd3a19fdab2e15afaa6b3

# The pinned distroless image predates Debian's OpenSSL security update.
# Preserve its runtime libraries while replacing the complete libssl3 package,
# including engines, provider modules, licenses, and scanner package metadata.
FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251 AS openssl

ARG TARGETARCH
WORKDIR /tmp/openssl
RUN test "${TARGETARCH}" = amd64 \
    && apt-get update \
    && apt-get download libssl3=3.0.22-1~deb12u2 \
    && echo 'cb4784740daa9b3b0eaea2b444bbefa686794afbbf3d678d238c1fd9875f2efd  libssl3_3.0.22-1~deb12u2_amd64.deb' | sha256sum -c - \
    && dpkg-deb --extract libssl3_3.0.22-1~deb12u2_amd64.deb /runtime \
    && dpkg-deb --control libssl3_3.0.22-1~deb12u2_amd64.deb /package-control \
    && mkdir -p /runtime/var/lib/dpkg/status.d \
    && cp /package-control/control /runtime/var/lib/dpkg/status.d/libssl3 \
    && cp /package-control/md5sums /runtime/var/lib/dpkg/status.d/libssl3.md5sums

FROM --platform=${BUILDPLATFORM} ${BUILDER_IMAGE} AS builder

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=v0.0.0
ENV VERSION=${VERSION}
ARG GOPROXY
ENV GOPROXY=${GOPROXY}

COPY go.mod go.sum /cache/
RUN cd /cache && go mod download
ADD . /go/src/github.com/inspektor-gadget/inspektor-gadget

WORKDIR /go/src/github.com/inspektor-gadget/inspektor-gadget

# Build with -tags nvml + CGO_ENABLED=1 so the go-nvml cgo shim is
# compiled in (see pkg/gpu-ebpf-bridge/nvml/real.go build tags).
# Cross-compilation of cgo is deferred: only amd64 is built for v1
# (see docs/design/004-gpu-telemetry-enricher.md); a build with
# TARGETARCH != amd64 will fail on the linker step.
RUN \
      --mount=type=cache,target=/root/.cache/go-build \
      --mount=type=cache,target=/go/pkg \
      CGO_ENABLED=1 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
        -ldflags "-X github.com/inspektor-gadget/inspektor-gadget/internal/version.version=${VERSION}" \
        -tags "nvml" \
        -o gpu-ebpf-bridge-${TARGETOS}-${TARGETARCH} \
        github.com/inspektor-gadget/inspektor-gadget/cmd/gpu-ebpf-bridge

FROM ${BASE_IMAGE}

ARG TARGETOS
ARG TARGETARCH

LABEL org.opencontainers.image.source=https://github.com/inspektor-gadget/inspektor-gadget
LABEL org.opencontainers.image.title="Inspektor Gadget gpu-ebpf-bridge"
LABEL org.opencontainers.image.description="Userspace daemon that polls GPU telemetry via NVML and publishes it through bpffs-pinned BPF maps. Meant to be deployed alongside the Inspektor Gadget DaemonSet on GPU-enabled nodes. See docs/design/004-gpu-telemetry-enricher.md for the design."
LABEL org.opencontainers.image.documentation="https://inspektor-gadget.io/docs"
LABEL org.opencontainers.image.licenses=Apache-2.0

COPY --from=openssl /runtime/ /
COPY --from=builder /go/src/github.com/inspektor-gadget/inspektor-gadget/gpu-ebpf-bridge-${TARGETOS}-${TARGETARCH} /usr/bin/gpu-ebpf-bridge
ENTRYPOINT ["/usr/bin/gpu-ebpf-bridge"]
