# syntax=docker/dockerfile:1
FROM docker.io/library/golang:1.25-alpine AS builder
ARG GIT_VERSION=unknown

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -o /usr/local/bin/smimesign -ldflags "-X main.versionString=${GIT_VERSION}" .

FROM scratch
COPY --from=builder /usr/local/bin/smimesign /usr/local/bin/smimesign

ENTRYPOINT ["/usr/local/bin/smimesign"]
CMD ["--help"]
