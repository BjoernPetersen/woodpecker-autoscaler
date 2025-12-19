FROM golang:1.26 AS build

WORKDIR /src
COPY . .
ARG TARGETOS
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    TARGETARCH=$(dpkg --print-architecture) make build

FROM scratch
ENV GODEBUG="netdns=go"

# copy certs from build image
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
# copy agent binary
COPY --from=build /src/dist/woodpecker-autoscaler /bin/

ENTRYPOINT ["/bin/woodpecker-autoscaler"]
