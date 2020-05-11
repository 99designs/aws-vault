package server

import (
	"log"
	"net/http"
	"time"
)

type loggingMiddlewareResponseWriter struct {
	http.ResponseWriter
	Code int
}

func (w *loggingMiddlewareResponseWriter) WriteHeader(statusCode int) {
	w.Code = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func withLogging(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestStart := time.Now()
		w2 := &loggingMiddlewareResponseWriter{w, http.StatusOK}
		handler.ServeHTTP(w2, r)
		log.Printf("http: %s: %d %s %s (%s)", r.RemoteAddr, w2.Code, r.Method, r.URL, time.Since(requestStart))
	})
}
