package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/gorilla/handlers"
)

func GetReverseProxyTarget() *url.URL {
	url, err := url.Parse(os.Getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI"))
	if err != nil {
		log.Fatalln("Bad AWS_CONTAINER_CREDENTIALS_FULL_URI:", err.Error())
	}
	url.Host = "host.docker.internal:" + url.Port()
	return url
}

func addAuthorizationHeader(authToken string, next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Header.Add("Authorization", authToken)
		next.ServeHTTP(w, r)
	}
}

func main() {
	target := GetReverseProxyTarget()
	authToken := os.Getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN")
	log.Printf("reverse proxying target:%s auth:%s\n", target, authToken)

	handler := handlers.LoggingHandler(os.Stderr,
		addAuthorizationHeader(authToken,
			httputil.NewSingleHostReverseProxy(target)))

	_ = http.ListenAndServe(":80", handler)
}
