package stripeext

import (
	"context"
	"errors"
	"testing"

	"github.com/BananaLabs-OSS/Fiber/pulp/effect"
	"github.com/BananaLabs-OSS/Pulp/ext"
	"github.com/vmihailenco/msgpack/v5"
)

func TestExecuteStripeIntentWireCanonicalReplayStable(t *testing.T) {
	client := &fakeEffectClient{}
	executor := NewExecutor(client, EffectLimits{})
	intent, err := effect.NewIntent(
		"customer-1", effect.KindStripeCustomerCreate, "stripe:customer:1",
		effect.StripeCustomerCreatePayload{Email: "owner@example.test"},
	)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := effect.MarshalIntent(intent)
	if err != nil {
		t.Fatal(err)
	}
	first, err := executor.ExecuteStripeIntentWire(context.Background(), wire)
	if err != nil {
		t.Fatal(err)
	}
	second, err := executor.ExecuteStripeIntentWire(context.Background(), wire)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatalf("replay receipt changed: %x != %x", first, second)
	}
	if got := len(client.calls); got != 1 {
		t.Fatalf("provider calls = %d, want 1", got)
	}
}

func TestExecuteStripeIntentWireRejectsEnvelopeAndPayloadRiders(t *testing.T) {
	executor := NewExecutor(&fakeEffectClient{}, EffectLimits{})
	valid, err := effect.NewIntent(
		"customer-1", effect.KindStripeCustomerCreate, "stripe:customer:1",
		effect.StripeCustomerCreatePayload{Email: "owner@example.test"},
	)
	if err != nil {
		t.Fatal(err)
	}
	base, err := msgpack.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]any
	if err := msgpack.Unmarshal(base, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope["unexpected"] = "rider"
	wire, err := msgpack.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.ExecuteStripeIntentWire(context.Background(), wire); err == nil {
		t.Fatal("envelope rider accepted")
	}

	payload, err := msgpack.Marshal(map[string]any{"email": "owner@example.test", "unexpected": "rider"})
	if err != nil {
		t.Fatal(err)
	}
	valid.Payload = payload
	wire, err = msgpack.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.ExecuteStripeIntentWire(context.Background(), wire); err == nil {
		t.Fatal("payload rider accepted")
	}
}

func TestExecuteStripeIntentWireRejectsApplicationSequencing(t *testing.T) {
	executor := NewExecutor(&fakeEffectClient{}, EffectLimits{})
	intent, err := effect.NewIntent(
		"free-1", effect.KindStripeFreeInvoiceFinalize, "stripe:free:1",
		effect.StripeFreeInvoiceFinalizePayload{
			Customer:    effect.StripeCustomerCreatePayload{Email: "owner@example.test"},
			InvoiceItem: effect.StripeFreeInvoiceItem{AmountCents: 100, Currency: "usd", Description: "item"},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := effect.MarshalIntent(intent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.ExecuteStripeIntentWire(context.Background(), wire); !errors.Is(err, ErrStripeHostEffectDenied) {
		t.Fatalf("free invoice error = %v, want ErrStripeHostEffectDenied", err)
	}
}

func TestStripeHostEffectCapabilityRegistersScopedAuthority(t *testing.T) {
	for _, capability := range ext.All() {
		if capability.Name != stripeHostEffectCapability {
			continue
		}
		if capability.Provider != "github.com/BananaLabs-OSS/Pulp-ext-stripe" || capability.Register == nil || capability.Stub == nil {
			t.Fatalf("unexpected host effect capability: %#v", capability)
		}
		return
	}
	t.Fatalf("%s capability is not registered", stripeHostEffectCapability)
}
