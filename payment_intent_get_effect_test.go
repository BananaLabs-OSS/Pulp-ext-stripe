package stripeext

import (
	"context"
	"errors"
	"testing"

	"github.com/BananaLabs-OSS/Fiber/pulp/effect"
	"github.com/vmihailenco/msgpack/v5"
)

func TestExecutorCanonicalPaymentIntentGetReturnsNonSecretBoundStatus(t *testing.T) {
	client := &fakeEffectClient{}
	executor := NewExecutor(client, EffectLimits{})
	intent, err := effect.NewIntent(
		"payment-intent-get:1", effect.KindStripePaymentIntentGet, "payment-intent-get:1",
		effect.StripePaymentIntentGetPayload{PaymentIntentID: "pi_123"},
	)
	if err != nil {
		t.Fatal(err)
	}

	receipt, err := executor.ExecuteIntent(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	if err := receipt.ValidateFor(intent); err != nil {
		t.Fatal(err)
	}
	result, err := effect.DecodeResult[effect.StripePaymentIntentGetResult](receipt)
	if err != nil {
		t.Fatal(err)
	}
	want := effect.StripePaymentIntentGetResult{
		PaymentIntentID: "pi_123", Status: "requires_capture", AmountCents: 2500,
		Currency: "usd", CaptureMethod: "manual",
	}
	if result != want {
		t.Fatalf("result = %#v, want %#v", result, want)
	}
	var raw map[string]any
	if err := msgpack.Unmarshal(receipt.Result, &raw); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"client_secret", "customer", "payment_method", "metadata", "last_error", "last_error_code"} {
		if _, ok := raw[forbidden]; ok {
			t.Fatalf("receipt leaked forbidden %q field: %#v", forbidden, raw)
		}
	}

	retry := intent
	retry.ID = "payment-intent-get:retry"
	if _, err := executor.ExecuteIntent(context.Background(), retry); err != nil {
		t.Fatal(err)
	}
	if got, want := len(client.calls), 1; got != want {
		t.Fatalf("provider calls = %d, want %d", got, want)
	}
	conflict, err := effect.NewIntent(
		"payment-intent-get:conflict", effect.KindStripePaymentIntentGet, intent.IdempotencyKey,
		effect.StripePaymentIntentGetPayload{PaymentIntentID: "pi_other"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.ExecuteIntent(context.Background(), conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflict error = %v, want ErrIdempotencyConflict", err)
	}
}

type invalidPaymentIntentGetClient struct{ fakeEffectClient }

func (invalidPaymentIntentGetClient) GetPaymentIntent(
	context.Context, effect.StripePaymentIntentGetPayload,
) (effect.StripePaymentIntentGetResult, error) {
	return effect.StripePaymentIntentGetResult{PaymentIntentID: "pi_123", Status: "requires_capture", AmountCents: 2500, Currency: "USD", CaptureMethod: "manual"}, nil
}

func TestExecutorCanonicalPaymentIntentGetRejectsInvalidProviderResult(t *testing.T) {
	executor := NewExecutor(&invalidPaymentIntentGetClient{}, EffectLimits{})
	intent, err := effect.NewIntent(
		"payment-intent-get:invalid", effect.KindStripePaymentIntentGet, "payment-intent-get:invalid",
		effect.StripePaymentIntentGetPayload{PaymentIntentID: "pi_123"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.ExecuteIntent(context.Background(), intent); err == nil {
		t.Fatal("expected invalid provider result to be rejected")
	}
}
