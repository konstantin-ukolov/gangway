FROM golang:1.24-bookworm AS build
WORKDIR /src
ENV GOTOOLCHAIN=auto

COPY . .

RUN go mod download
RUN go mod verify
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-w -s" -o /out/gangway ./cmd/gangway
RUN mkdir -p /out/helpers && for os in linux darwin windows; do for arch in amd64 arm64; do suffix=""; if [ "$os" = windows ]; then suffix=".exe"; fi; CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags="-w -s" -o /out/helpers/gangway-login-$os-$arch$suffix ./cmd/gangway-login || exit 1; done; done

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/gangway /bin/gangway
COPY --from=build /out/helpers /opt/gangway/helpers
USER nonroot:nonroot
ENTRYPOINT ["/bin/gangway"]
