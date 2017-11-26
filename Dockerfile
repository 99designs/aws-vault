FROM golang:1.9.2 AS build-env

ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

WORKDIR /go/src/github.com/99designs/aws-vault
ADD . /go/src/github.com/99designs/aws-vault
RUN go build -a -tags netgo -ldflags '-w' -o /bin/aws-vault

FROM alpine
COPY --from=build-env /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build-env /bin/aws-vault /aws-vault
ENTRYPOINT ["/aws-vault"]
