FROM --platform=${BUILDPLATFORM} golang:1.26.10-alpine@sha256:a2012b4a1d1f9f7e9f44e0d39b805a901e856b1dd80b4e6ee4338db547050308 AS builder

ARG TARGETARCH

WORKDIR /go/src/github.com/inspektor-gadget/inspektor-gadget/tools/bench
COPY . /go/src/github.com/inspektor-gadget/inspektor-gadget/tools/bench/
RUN GOARCH=${TARGETARCH} go build -o /bench /go/src/github.com/inspektor-gadget/inspektor-gadget/tools/bench

# Final image
FROM gcr.io/distroless/static-debian12:nonroot@sha256:e8a4044e0b4ae4257efa45fc026c0bc30ad320d43bd4c1a7d5271bd241e386d0
COPY --from=builder /bench /bench

CMD ["/bench"]
