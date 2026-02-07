package vault

import (
	"errors"
	"net/http"
	"testing"
	"time"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	ssotypes "github.com/aws/aws-sdk-go-v2/service/sso/types"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

func TestRetryAfterFromErrorSeconds(t *testing.T) {
	header := http.Header{}
	header.Set("Retry-After", "120")
	resp := &http.Response{StatusCode: http.StatusTooManyRequests, Header: header}
	err := &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: resp},
		},
	}

	delay, ok := retryAfterFromError(err)
	if !ok {
		t.Fatal("expected retry-after delay to be detected")
	}
	if delay != 120*time.Second {
		t.Fatalf("expected 120s retry-after, got %s", delay)
	}
}

func TestRetryAfterFromErrorMissingHeader(t *testing.T) {
	resp := &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{}}
	err := &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: resp},
		},
	}

	delay, ok := retryAfterFromError(err)
	if ok {
		t.Fatalf("expected retry-after to be absent, got %s", delay)
	}
}

func TestIsSSORateLimitError(t *testing.T) {
	if !isSSORateLimitError(&ssotypes.TooManyRequestsException{}) {
		t.Fatal("expected TooManyRequestsException to be rate limit error")
	}

	resp := &http.Response{StatusCode: http.StatusTooManyRequests}
	err := &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: resp},
		},
	}
	if !isSSORateLimitError(err) {
		t.Fatal("expected HTTP 429 response error to be rate limit error")
	}

	if isSSORateLimitError(errors.New("boom")) {
		t.Fatal("expected non-rate-limit error to be false")
	}
}

func TestJitterDelayRange(t *testing.T) {
	base := 10 * time.Second
	min := time.Duration(float64(base) * ssoRetryAfterJitterMin)
	max := time.Duration(float64(base) * ssoRetryAfterJitterMax)

	for i := 0; i < 10; i++ {
		delay := jitterDelay(base)
		if delay < min || delay > max {
			t.Fatalf("expected delay in range %s-%s, got %s", min, max, delay)
		}
	}
}
