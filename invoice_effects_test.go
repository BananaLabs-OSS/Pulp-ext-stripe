package stripeext

import (
	"context"
	"fmt"
	"testing"

	"github.com/BananaLabs-OSS/Fiber/pulp/effect"
)

func TestExecutorExecutesOneCanonicalInvoiceOperation(t *testing.T) {
	tests := []struct {
		kind    string
		payload any
		call    string
	}{
		{
			kind: effect.KindStripeInvoiceItemCreate,
			payload: effect.StripeInvoiceItemCreatePayload{
				CustomerID: "cus_123", InvoiceID: "in_123", AmountCents: 1200, Currency: "usd",
			},
			call: "invoice-item:invoice:item:1",
		},
		{
			kind:    effect.KindStripeInvoiceCreate,
			payload: effect.StripeInvoiceCreatePayload{CustomerID: "cus_123", AutoAdvance: true},
			call:    "invoice-create:invoice:create:1",
		},
		{
			kind:    effect.KindStripeInvoiceFinalize,
			payload: effect.StripeInvoiceFinalizePayload{InvoiceID: "in_123"},
			call:    "invoice-finalize:invoice:finalize:1",
		},
		{
			kind:    effect.KindStripeInvoiceMarkPaid,
			payload: effect.StripeInvoiceMarkPaidPayload{InvoiceID: "in_123"},
			call:    "invoice-mark-paid:invoice:paid:1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			client := &fakeEffectClient{}
			executor := NewExecutor(client, EffectLimits{})
			key := "invoice:" + map[string]string{
				effect.KindStripeInvoiceItemCreate: "item:1",
				effect.KindStripeInvoiceCreate:     "create:1",
				effect.KindStripeInvoiceFinalize:   "finalize:1",
				effect.KindStripeInvoiceMarkPaid:   "paid:1",
			}[tt.kind]
			intent, err := effect.NewIntent("intent:"+tt.kind, tt.kind, key, tt.payload)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := effect.MarshalIntent(intent)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := executor.ExecuteStripeIntentWire(context.Background(), wire); err != nil {
				t.Fatal(err)
			}
			if got := fmt.Sprint(client.calls); got != "["+tt.call+"]" {
				t.Fatalf("calls = %s, want [%s]", got, tt.call)
			}
		})
	}
}

func TestExecutorCanonicalInvoiceOperationReplayCallsProviderOnce(t *testing.T) {
	client := &fakeEffectClient{}
	executor := NewExecutor(client, EffectLimits{})
	intent, err := effect.NewIntent(
		"invoice-finalize-1", effect.KindStripeInvoiceFinalize, "invoice:finalize:replay",
		effect.StripeInvoiceFinalizePayload{InvoiceID: "in_123"},
	)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := executor.ExecuteIntent(context.Background(), intent); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(client.calls); got != 1 {
		t.Fatalf("provider calls = %d, want 1", got)
	}
}
