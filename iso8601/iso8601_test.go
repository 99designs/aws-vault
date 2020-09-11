package iso8601

import (
	"testing"
	"time"
)

func TestFormat(t *testing.T) {
	input, _ := time.Parse(time.RFC3339, "2009-02-04T21:00:57-08:00")
	want := "2009-02-05T05:00:57Z"
	result := Format(input)
	if result != want {
		t.Errorf("expected %s for %q got %s", want, input, result)
	}
}

func TestFormatForIssue655(t *testing.T) {
	input, _ := time.Parse(time.RFC3339, "2020-09-10T18:16:52+02:00")
	want := "2020-09-10T16:16:52Z"
	result := Format(input)
	if result != want {
		t.Errorf("expected %s for %q got %s", want, input, result)
	}
}
