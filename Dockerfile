FROM golang:1.23-alpine AS build

WORKDIR /src
RUN apk add --no-cache ca-certificates

COPY go.mod ./
COPY cmd ./cmd
COPY server ./server
COPY protocol ./protocol

ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags="-s -w" -o /out/sgtp-server ./cmd/sgtp-server

FROM alpine:3.20
RUN apk add --no-cache ca-certificates

COPY --from=build /out/sgtp-server /usr/local/bin/sgtp-server

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/sgtp-server"]
