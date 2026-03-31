FROM golang:1.25-alpine AS build

WORKDIR /src
RUN apk add --no-cache ca-certificates

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY server ./server
COPY protocol ./protocol
COPY userdir ./userdir
COPY internal ./internal

ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags="-s -w" -o /out/sgtp-server ./cmd/sgtp-server

FROM alpine:3.20
RUN apk add --no-cache ca-certificates

COPY --from=build /out/sgtp-server /usr/local/bin/sgtp-server

USER 65532:65532
CMD ["/usr/local/bin/sgtp-server"]
