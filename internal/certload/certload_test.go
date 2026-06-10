package certload

import (
	"math"
	"strings"
	"testing"
)

func TestReadWithLimitUnderLimit(t *testing.T) {
	data, err := ReadWithLimit(strings.NewReader("abc"), 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != "abc" {
		t.Errorf("want abc, got %q", data)
	}
}

func TestReadWithLimitExactLimit(t *testing.T) {
	data, err := ReadWithLimit(strings.NewReader("abcd"), 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != "abcd" {
		t.Errorf("want abcd, got %q", data)
	}
}

func TestReadWithLimitExceeded(t *testing.T) {
	_, err := ReadWithLimit(strings.NewReader("abcde"), 4)
	if err == nil {
		t.Fatal("expected size-limit error")
	}
	if !strings.Contains(err.Error(), "exceeded size limit") {
		t.Errorf("want 'exceeded size limit' error, got: %v", err)
	}
}

// Regression for Fix 11: limit == MaxInt64 used to wrap limit+1 negative,
// making LimitReader return zero bytes.
func TestReadWithLimitMaxInt64NoOverflow(t *testing.T) {
	data, err := ReadWithLimit(strings.NewReader("abc"), math.MaxInt64)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != "abc" {
		t.Errorf("want abc, got %q (overflow regression)", data)
	}
}
