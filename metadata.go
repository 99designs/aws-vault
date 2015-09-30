package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"time"
)

const (
	awsTimeFormat = "2006-01-02T15:04:05Z"
)

type metadataHandler struct {
	http.Handler
	credentials *VaultCredentials
}

func NewMetadataHandler(vc *VaultCredentials) http.Handler {
	h := &metadataHandler{credentials: vc}
	router := http.NewServeMux()
	router.HandleFunc("/latest/meta-data/iam/security-credentials/", h.indexHandler)
	router.HandleFunc("/latest/meta-data/iam/security-credentials/local-credentials", h.credentialsHandler)
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		director := func(req *http.Request) {
			req.URL.Scheme = "http"
			req.URL.Host = r.Host
		}
		proxy := &httputil.ReverseProxy{Director: director}
		proxy.ServeHTTP(w, r)
	})

	h.Handler = router
	return h
}

func (s *metadataHandler) indexHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "local-credentials")
}

type credentialsResponse struct {
	AccessKeyID     string `json:"AccessKeyId"`
	Code            string `json:"Code"`
	Expiration      string `json:"Expiration"`
	LastUpdated     string `json:"LastUpdated"`
	SecretAccessKey string `json:"SecretAccessKey"`
	Token           string `json:"Token"`
	Type            string `json:"Type"`
}

func (s *metadataHandler) credentialsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)

	val, err := s.credentials.Get()
	if err != nil {
		http.Error(w, err.Error(), http.StatusGatewayTimeout)
		return
	}

	json.NewEncoder(w).Encode(&credentialsResponse{
		Code:            "Success",
		LastUpdated:     time.Now().Format(awsTimeFormat),
		Type:            "AWS-HMAC",
		AccessKeyID:     val.AccessKeyID,
		SecretAccessKey: val.SecretAccessKey,
		Token:           val.SessionToken,
		Expiration:      s.credentials.Expires().Format(awsTimeFormat),
	})
}
