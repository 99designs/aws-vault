FROM golang:1.9.2 AS build-env

ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

WORKDIR /go/src/github.com/99designs/aws-vault
ADD . /go/src/github.com/99designs/aws-vault
RUN go get github.com/99designs/keyring \
    github.com/aws/aws-sdk-go/aws \
    github.com/aws/aws-sdk-go/aws/awserr \
    github.com/aws/aws-sdk-go/aws/credentials \
    github.com/aws/aws-sdk-go/aws/session \
    github.com/aws/aws-sdk-go/service/iam \
    github.com/aws/aws-sdk-go/service/sts \
    github.com/mitchellh/go-homedir \
    github.com/skratchdot/open-golang/open \
    golang.org/x/crypto/ssh/terminal \
    gopkg.in/alecthomas/kingpin.v2 \
    gopkg.in/ini.v1
RUN go build -a -tags netgo -ldflags '-w' -o /bin/aws-vault

FROM alpine
COPY --from=build-env /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build-env /bin/aws-vault /aws-vault
RUN apk add python py-pip npm
RUN pip install awscli
RUN npm config set unsafe-perm true
RUN npm install -g s3audit
ENTRYPOINT ["/aws-vault"]
