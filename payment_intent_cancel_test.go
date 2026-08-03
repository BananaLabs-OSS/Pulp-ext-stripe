package stripeext

import "testing"

func TestPaymentIntentCancelTerminal(t *testing.T) {
	for _, status := range []string{"succeeded", "canceled"} {
		if !paymentIntentCancelTerminal(status) {
			t.Fatalf("status %q should skip cancellation", status)
		}
	}
	for _, status := range []string{"requires_capture", "requires_action", "processing", ""} {
		if paymentIntentCancelTerminal(status) {
			t.Fatalf("status %q should not skip cancellation", status)
		}
	}
}
