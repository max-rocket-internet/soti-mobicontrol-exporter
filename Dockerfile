FROM golang:1.14.0 as builder

WORKDIR /go/src/github.com/max-rocket-internet/soti-mobicontrol-exporter
COPY . .

RUN go get
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /go/bin/soti-mobicontrol-exporter /go/src/github.com/max-rocket-internet/soti-mobicontrol-exporter/main.go
RUN adduser --disabled-login --no-create-home --disabled-password --system --uid 101 non-root

FROM alpine:3.9.3
RUN addgroup -S soti-mobicontrol-exporter && adduser -S -G soti-mobicontrol-exporter soti-mobicontrol-exporter
USER soti-mobicontrol-exporter
COPY --from=builder /go/bin/soti-mobicontrol-exporter /usr/local/bin/soti-mobicontrol-exporter
USER 101
ENV USER soti-mobicontrol-exporter

ENTRYPOINT ["soti-mobicontrol-exporter"]
