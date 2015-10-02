package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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
	log.Printf("%s %s", r.Method, r.RequestURI)

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
