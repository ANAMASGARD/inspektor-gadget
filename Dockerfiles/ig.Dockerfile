ARG BUILDER_IMAGE=golang:1.26.10-trixie@sha256:e18951cff6896c16909458a8e0cbd52364a347826ff1f5b86d095fe0670d52e7
ARG BASE_IMAGE=gcr.io/distroless/static-debian11:latest@sha256:1dbe426d60caed5d19597532a2d74c8056cd7b1674042b88f7328690b5ead8ed

FROM --platform=${BUILDPLATFORM} ${BUILDER_IMAGE} AS builder

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=v0.0.0
ENV VERSION=${VERSION}
ARG GADGET_BUILDER=ghcr.io/inspektor-gadget/gadget-builder@sha256:1586c58ae4731fb8fb12546c031a352db34c0ce334709b9b54e6c648edae76ad
ENV GADGET_BUILDER=${GADGET_BUILDER}
ARG GOPROXY
ENV GOPROXY=${GOPROXY}

COPY go.mod go.sum /cache/
RUN cd /cache && go mod download
ADD . /go/src/github.com/inspektor-gadget/inspektor-gadget

WORKDIR /go/src/github.com/inspektor-gadget/inspektor-gadget

RUN \
      --mount=type=cache,target=/root/.cache/go-build \
      --mount=type=cache,target=/go/pkg \
      CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
        -ldflags "-X github.com/inspektor-gadget/inspektor-gadget/internal/version.version=${VERSION} \
        -X github.com/inspektor-gadget/inspektor-gadget/cmd/common/image.builderImage=${GADGET_BUILDER} \
        -extldflags '-static'" \
        -tags "netgo" \
        -o ig-${TARGETOS}-${TARGETARCH} \
        github.com/inspektor-gadget/inspektor-gadget/cmd/ig

FROM ${BASE_IMAGE}

ARG TARGETOS
ARG TARGETARCH

LABEL org.opencontainers.image.source=https://github.com/inspektor-gadget/inspektor-gadget
LABEL org.opencontainers.image.title="Inspektor Gadget ig tool"
LABEL org.opencontainers.image.description="Inspektor Gadget is a collection of tools (or gadgets) to debug and inspect Kubernetes resources and applications. This image only includes the ig binary, a standalone tool to run the gadgets."
LABEL org.opencontainers.image.documentation="https://inspektor-gadget.io/docs"
LABEL org.opencontainers.image.licenses=Apache-2.0

COPY --from=builder /go/src/github.com/inspektor-gadget/inspektor-gadget/ig-${TARGETOS}-${TARGETARCH} /usr/bin/ig
ENV HOST_ROOT=/host
ENTRYPOINT ["/usr/bin/ig"]
