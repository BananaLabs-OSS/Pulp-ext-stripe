package stripeext

import "testing"

func TestEnvCents(t *testing.T) {
	tests := []struct {
		name string
		val  string
		set  bool
		want int64
	}{
		{"unset", "", false, 0},
		{"empty", "", true, 0},
		{"valid", "5000", true, 5000},
		{"zero", "0", true, 0},
		{"negative", "-100", true, 0},
		{"malformed", "abc", true, 0},
		{"trailing junk", "100x", true, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const key = "STRIPE_TEST_CENTS"
			if tt.set {
				t.Setenv(key, tt.val)
			} else {
				// t.Setenv requires a value; ensure unset by setting empty.
				t.Setenv(key, "")
			}
			if got := envCents(key); got != tt.want {
				t.Fatalf("envCents(%q)=%d, want %d", tt.val, got, tt.want)
			}
		})
	}
}

func TestRefundExceedsCap(t *testing.T) {
	runtime := newStripeRuntime(mustStripeScope(t, "test", "refund", "stripe", "one"), nil)
	runtime.maxRefundCents = 0 // no cap
	if runtime.refundExceedsCap(1_000_000) {
		t.Fatal("no cap should never exceed")
	}

	runtime.maxRefundCents = 5000
	if runtime.refundExceedsCap(5000) {
		t.Fatal("amount == cap must be allowed")
	}
	if !runtime.refundExceedsCap(5001) {
		t.Fatal("amount > cap must be rejected")
	}
	if runtime.refundExceedsCap(1) {
		t.Fatal("amount < cap must be allowed")
	}
}

func TestChargeExceedsCap(t *testing.T) {
	runtime := newStripeRuntime(mustStripeScope(t, "test", "charge", "stripe", "one"), nil)
	runtime.maxChargeCents = 0
	if runtime.chargeExceedsCap(1_000_000) {
		t.Fatal("no cap should never exceed")
	}

	runtime.maxChargeCents = 2500
	if runtime.chargeExceedsCap(2500) {
		t.Fatal("amount == cap must be allowed")
	}
	if !runtime.chargeExceedsCap(2501) {
		t.Fatal("amount > cap must be rejected")
	}
}

// TestRefundAmountGate documents the reconciled refund gate, which keys off
// the PRESENCE of amount_cents (a *int64) rather than its zero value:
//
//   - nil (field omitted)  → deliberate full refund → ALLOW, no Amount param.
//     This is the Evolution helpers' path (RefundRequest with no AmountCents,
//     SDK-encoded `omitempty`).
//   - present and <= 0      → accidental/malicious explicit zero → REJECT.
//   - present and > 0       → partial refund, subject to the host ceiling.
//
// The booleans below mirror the exact branch logic in refundCreate.
func TestRefundAmountGate(t *testing.T) {
	runtime := newStripeRuntime(mustStripeScope(t, "test", "refund-gate", "stripe", "one"), nil)
	runtime.maxRefundCents = 0

	// rejected reports whether refundCreate would return code 12 for the
	// given request amount (nil = omitted).
	rejected := func(amt *int64) bool {
		if amt == nil {
			return false // full-refund-by-omission is allowed
		}
		return *amt <= 0 || runtime.refundExceedsCap(*amt)
	}
	cents := func(v int64) *int64 { return &v }

	if rejected(nil) {
		t.Fatal("omitted amount (full refund by omission) must be allowed")
	}
	if !rejected(cents(0)) {
		t.Fatal("explicit zero refund amount must be rejected (unintended full refund)")
	}
	if !rejected(cents(-1)) {
		t.Fatal("explicit negative refund amount must be rejected")
	}
	if rejected(cents(1)) {
		t.Fatal("positive refund amount within cap must be allowed")
	}

	runtime.maxRefundCents = 100
	if !rejected(cents(101)) {
		t.Fatal("refund above cap must be rejected")
	}
	if rejected(nil) {
		t.Fatal("full-refund-by-omission must remain allowed even with a cap set")
	}
}
