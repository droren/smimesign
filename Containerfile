# syntax=docker/dockerfile:1
FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -o /usr/local/bin/smimesign -ldflags "-X main.versionString=$(git describe --tags)" .

FROM scratch
COPY --from=builder /usr/local/bin/smimesign /usr/local/bin/smimesign

ENTRYPOINT ["/usr/local/bin/smimesign"]
CMD ["--help"]