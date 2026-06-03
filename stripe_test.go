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
	defer func() { maxRefundCents = 0 }()

	maxRefundCents = 0 // no cap
	if refundExceedsCap(1_000_000) {
		t.Fatal("no cap should never exceed")
	}

	maxRefundCents = 5000
	if refundExceedsCap(5000) {
		t.Fatal("amount == cap must be allowed")
	}
	if !refundExceedsCap(5001) {
		t.Fatal("amount > cap must be rejected")
	}
	if refundExceedsCap(1) {
		t.Fatal("amount < cap must be allowed")
	}
}

func TestChargeExceedsCap(t *testing.T) {
	defer func() { maxChargeCents = 0 }()

	maxChargeCents = 0
	if chargeExceedsCap(1_000_000) {
		t.Fatal("no cap should never exceed")
	}

	maxChargeCents = 2500
	if chargeExceedsCap(2500) {
		t.Fatal("amount == cap must be allowed")
	}
	if !chargeExceedsCap(2501) {
		t.Fatal("amount > cap must be rejected")
	}
}

// TestRefundAmountGate documents the core HIGH fix: a non-positive refund
// amount is the rejection condition, mirroring the guard in refundCreate
// (req.AmountCents <= 0 || refundExceedsCap(req.AmountCents)). A zero amount
// must be rejected so Stripe never interprets it as a full refund.
func TestRefundAmountGate(t *testing.T) {
	maxRefundCents = 0
	defer func() { maxRefundCents = 0 }()

	reject := func(amt int64) bool { return amt <= 0 || refundExceedsCap(amt) }

	if !reject(0) {
		t.Fatal("zero refund amount must be rejected (would become a full refund)")
	}
	if !reject(-1) {
		t.Fatal("negative refund amount must be rejected")
	}
	if reject(1) {
		t.Fatal("positive refund amount within cap must be allowed")
	}

	maxRefundCents = 100
	if !reject(101) {
		t.Fatal("refund above cap must be rejected")
	}
}
