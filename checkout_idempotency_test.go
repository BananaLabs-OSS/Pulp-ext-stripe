package stripeext

import (
	"testing"

	"github.com/stripe/stripe-go/v82"
	"github.com/vmihailenco/msgpack/v5"
)

type fakeCheckoutSessionCreator struct {
	params *stripe.CheckoutSessionParams
}

func (f *fakeCheckoutSessionCreator) New(params *stripe.CheckoutSessionParams) (*stripe.CheckoutSession, error) {
	f.params = params
	return &stripe.CheckoutSession{ID: "cs_test", URL: "https://checkout.example/cs_test"}, nil
}

func TestCheckoutSessionHostForwardsStableIdempotencyKey(t *testing.T) {
	wire, err := msgpack.Marshal(map[string]any{
		"amount_cents":    int64(2500),
		"currency":        "usd",
		"success_url":     "https://example.test/success",
		"cancel_url":      "https://example.test/cancel",
		"product_name":    "Sessions server",
		"idempotency_key": "checkout:order-42",
	})
	if err != nil {
		t.Fatal(err)
	}
	var req checkoutSessionCreateRequest
	if err := msgpack.Unmarshal(wire, &req); err != nil {
		t.Fatal(err)
	}
	client := &fakeCheckoutSessionCreator{}
	created, err := createCheckoutSession(client, req)
	if err != nil {
		t.Fatal(err)
	}
	if created.ID != "cs_test" {
		t.Fatalf("Checkout Session ID = %q, want cs_test", created.ID)
	}
	if got, want := client.params.IdempotencyKey, stripe.String(req.IdempotencyKey); got == nil || *got != *want {
		t.Fatalf("Stripe idempotency key = %#v, want %#v", got, want)
	}
}

func TestCheckoutSessionParamsPreserveLegacyEmptyKey(t *testing.T) {
	params := checkoutSessionParams(checkoutSessionCreateRequest{
		AmountCents: 100,
		Currency:    "usd",
		SuccessURL:  "https://example.test/success",
		CancelURL:   "https://example.test/cancel",
		ProductName: "Legacy checkout",
	})
	if params.IdempotencyKey != nil {
		t.Fatalf("legacy Stripe idempotency key = %#v, want nil", params.IdempotencyKey)
	}
}
