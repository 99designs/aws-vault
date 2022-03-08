FROM golang:1.17
WORKDIR /usr/src/aws-vault-proxy
COPY . /usr/src/aws-vault-proxy
RUN go build -v -o /usr/local/bin/aws-vault-proxy ./...
CMD ["/usr/local/bin/aws-vault-proxy"]
