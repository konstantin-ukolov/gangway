FROM golang:1.24-bookworm AS build
WORKDIR /src
ENV GOTOOLCHAIN=auto

COPY . .

RUN go mod download
RUN go mod verify
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-w -s" -o /out/gangway ./cmd/gangway

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/gangway /bin/gangway
USER nonroot:nonroot
ENTRYPOINT ["/bin/gangway"]
