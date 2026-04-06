FROM golang:1.25-alpine AS build

WORKDIR /src

COPY go.mod ./
COPY go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY cmd ./cmd
COPY server ./server
COPY protocol ./protocol
COPY userdir ./userdir
COPY internal ./internal

ENV CGO_ENABLED=0
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -ldflags="-s -w" -o /out/sgtp-server ./cmd/sgtp-server

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/sgtp-server /usr/local/bin/sgtp-server

CMD ["/usr/local/bin/sgtp-server"]
