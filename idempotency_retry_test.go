package stripeext

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stripe/stripe-go/v82"
)

func TestRetryStripeIdempotencyInUseConverges(t *testing.T) {
	calls := 0
	value, err := retryStripeIdempotencyInUse(context.Background(), []time.Duration{0, 0}, func() (string, error) {
		calls++
		if calls < 3 {
			return "", &stripe.Error{Code: stripe.ErrorCodeIdempotencyKeyInUse, HTTPStatusCode: 409}
		}
		return "pi_123", nil
	})
	if err != nil || value != "pi_123" || calls != 3 {
		t.Fatalf("retry result = %q, %v, calls=%d", value, err, calls)
	}
}

func TestRetryStripeIdempotencyInUseDoesNotRetryOtherFailures(t *testing.T) {
	want := errors.New("declined")
	calls := 0
	_, err := retryStripeIdempotencyInUse(context.Background(), []time.Duration{0}, func() (string, error) {
		calls++
		return "", want
	})
	if !errors.Is(err, want) || calls != 1 {
		t.Fatalf("error = %v, calls=%d", err, calls)
	}
}
