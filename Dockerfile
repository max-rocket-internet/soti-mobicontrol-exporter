FROM golang:1.14.0 as builder
WORKDIR /go/src/github.com/max-rocket-internet/soti-mobicontrol-exporter
COPY . .
RUN go get
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o soti-mobicontrol-exporter
RUN adduser --disabled-login --no-create-home --disabled-password --system --uid 101 non-root

FROM alpine:3.9.3
RUN addgroup -S non-root && adduser -S -G non-root non-root
USER 101
ENV USER non-root
COPY --from=builder /go/src/github.com/max-rocket-internet/soti-mobicontrol-exporter/soti-mobicontrol-exporter soti-mobicontrol-exporter
CMD ["/soti-mobicontrol-exporter"]
