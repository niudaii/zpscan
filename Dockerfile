FROM golang:1.18.4-alpine as builder
RUN apk add --no-cache make git
RUN apk -U --no-cache add libpcap-dev
RUN apk add gcc g++ make cmake
WORKDIR /zpscan-src
COPY . /zpscan-src
RUN go mod download && \
    make docker && \
    mv ./bin/zpscan-docker /zpscan

FROM alpine:latest
COPY --from=builder /zpscan /
COPY ./config.yaml /
COPY ./resource /

ENTRYPOINT ["/zpscan"]