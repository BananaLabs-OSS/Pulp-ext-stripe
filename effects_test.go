package stripeext

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/BananaLabs-OSS/Fiber/pulp/effect"
	"github.com/BananaLabs-OSS/Pulp/ext"
	"github.com/vmihailenco/msgpack/v5"
)

type fakeEffectClient struct {
	calls []string
}

func (f *fakeEffectClient) CreatePaymentIntent(_ context.Context, _ PaymentIntentEffectPayload, key string) (EffectResult, error) {
	f.calls = append(f.calls, "payment:"+key)
	return EffectResult{PaymentIntent: "pi_123", ClientSecret: "pi_123_secret", Status: "requires_payment_method"}, nil
}
func (f *fakeEffectClient) CreateCheckoutSession(_ context.Context, _ CheckoutSessionEffectPayload, key string) (EffectResult, error) {
	f.calls = append(f.calls, "checkout:"+key)
	return EffectResult{CheckoutSession: "cs_123", CheckoutURL: "https://checkout.example/cs_123"}, nil
}
func (f *fakeEffectClient) CreateSetupIntent(_ context.Context, _ SetupIntentEffectPayload, key string) (EffectResult, error) {
	f.calls = append(f.calls, "setup:"+key)
	return EffectResult{SetupIntent: "seti_123", ClientSecret: "seti_123_secret"}, nil
}
func (f *fakeEffectClient) CreateRefund(_ context.Context, _ RefundEffectPayload, key string) (EffectResult, error) {
	f.calls = append(f.calls, "refund:"+key)
	return EffectResult{Refund: "re_123", Status: "succeeded"}, nil
}
func (f *fakeEffectClient) CapturePaymentIntent(_ context.Context, _ effect.StripePaymentIntentCapturePayload, key string) (effect.StripePaymentIntentMutationResult, error) {
	f.calls = append(f.calls, "capture:"+key)
	return effect.StripePaymentIntentMutationResult{
		PaymentIntentID: "pi_123", Status: "succeeded", Amount: 2500, Currency: "usd",
	}, nil
}
func (f *fakeEffectClient) CancelPaymentIntent(_ context.Context, _ effect.StripePaymentIntentCancelPayload, key string) (effect.StripePaymentIntentMutationResult, error) {
	f.calls = append(f.calls, "cancel:"+key)
	return effect.StripePaymentIntentMutationResult{
		PaymentIntentID: "pi_123", Status: "canceled", Amount: 2500, Currency: "usd",
	}, nil
}
func (f *fakeEffectClient) CreateCustomer(_ context.Context, payload effect.StripeCustomerCreatePayload, key string) (effect.StripeCustomerCreateResult, error) {
	f.calls = append(f.calls, "customer:"+key)
	return effect.StripeCustomerCreateResult{CustomerID: "cus_123", Email: payload.Email}, nil
}
func (f *fakeEffectClient) CreateFreeInvoiceItem(_ context.Context, _ string, _ effect.StripeFreeInvoiceItem, key string) (string, error) {
	f.calls = append(f.calls, "item:"+key)
	return "ii_123", nil
}
func (f *fakeEffectClient) CreateFreeInvoice(_ context.Context, _ string, _ effect.StripeFreeInvoice, key string) (invoiceEffectResult, error) {
	f.calls = append(f.calls, "invoice:"+key)
	return invoiceEffectResult{ID: "in_123", Status: "draft"}, nil
}
func (f *fakeEffectClient) FinalizeFreeInvoice(_ context.Context, _ string, key string) (invoiceEffectResult, error) {
	f.calls = append(f.calls, "finalize:"+key)
	return invoiceEffectResult{ID: "in_123", Status: "open", AmountDue: 0}, nil
}
func (f *fakeEffectClient) MarkFreeInvoicePaid(_ context.Context, _ string, key string) (invoiceEffectResult, error) {
	f.calls = append(f.calls, "paid:"+key)
	return invoiceEffectResult{ID: "in_123", Status: "paid", AmountDue: 0, AmountPaid: 0}, nil
}
func (f *fakeEffectClient) UpsertCoupon(_ context.Context, payload effect.StripeCouponUpsertPayload, key string) (effect.StripeCouponUpsertResult, error) {
	f.calls = append(f.calls, "coupon-upsert:"+key)
	return effect.StripeCouponUpsertResult{
		ExternalKey: payload.ExternalKey, CouponID: "coupon_123", Valid: true,
		AmountOff: payload.AmountOffCents, PercentOff: payload.PercentOff,
		Currency: payload.Currency, Duration: payload.Duration,
		DurationMonths: payload.DurationMonths,
	}, nil
}
func (f *fakeEffectClient) DeleteCoupon(_ context.Context, payload effect.StripeCouponDeletePayload, key string) (effect.StripeCouponDeleteResult, error) {
	f.calls = append(f.calls, "coupon-delete:"+key)
	return effect.StripeCouponDeleteResult{
		ExternalKey: payload.ExternalKey, CouponID: payload.CouponID, Deleted: true,
	}, nil
}
func (f *fakeEffectClient) UpsertPromotionCode(_ context.Context, payload effect.StripePromotionCodeUpsertPayload, key string) (effect.StripePromotionCodeUpsertResult, error) {
	f.calls = append(f.calls, "promotion-upsert:"+key)
	return effect.StripePromotionCodeUpsertResult{
		ExternalKey: payload.ExternalKey, PromotionCodeID: "promo_123",
		CouponID: payload.CouponID, Code: payload.Code, Active: payload.Active,
		MaxRedemptions: payload.MaxRedemptions, ExpiresAtUnix: payload.ExpiresAtUnix,
	}, nil
}
func (f *fakeEffectClient) DeactivatePromotionCode(_ context.Context, payload effect.StripePromotionCodeDeactivatePayload, key string) (effect.StripePromotionCodeDeactivateResult, error) {
	f.calls = append(f.calls, "promotion-deactivate:"+key)
	return effect.StripePromotionCodeDeactivateResult{
		ExternalKey: payload.ExternalKey, PromotionCodeID: payload.PromotionCodeID, Active: false,
	}, nil
}

func TestExecutorReplaysStableEffectWithoutSecondStripeCall(t *testing.T) {
	client := &fakeEffectClient{}
	executor := NewExecutor(client, EffectLimits{})
	effect := Effect{Kind: EffectPaymentIntentCreate, IdempotencyKey: "outbox-order-42-payment", Payload: `{"amount_cents":2500,"currency":"usd"}`}

	first, err := executor.Execute(context.Background(), effect)
	if err != nil {
		t.Fatal(err)
	}
	second, err := executor.Execute(context.Background(), effect)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("replay result = %#v, want %#v", second, first)
	}
	if got, want := len(client.calls), 1; got != want {
		t.Fatalf("Stripe calls = %d, want %d", got, want)
	}
	if got, want := client.calls[0], "payment:outbox-order-42-payment"; got != want {
		t.Fatalf("idempotency key = %q, want %q", got, want)
	}
	if first.PaymentIntent == "" || first.ClientSecret == "" {
		t.Fatalf("payment result must include payment_intent and client_secret: %#v", first)
	}
}

func TestExecutorRejectsIdempotencyKeyReuseWithDifferentPayload(t *testing.T) {
	client := &fakeEffectClient{}
	executor := NewExecutor(client, EffectLimits{})
	key := "outbox-order-42-payment"
	if _, err := executor.Execute(context.Background(), Effect{Kind: EffectPaymentIntentCreate, IdempotencyKey: key, Payload: `{"amount_cents":2500,"currency":"usd"}`}); err != nil {
		t.Fatal(err)
	}
	_, err := executor.Execute(context.Background(), Effect{Kind: EffectPaymentIntentCreate, IdempotencyKey: key, Payload: `{"amount_cents":2600,"currency":"usd"}`})
	if !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("error = %v, want ErrIdempotencyConflict", err)
	}
	if got, want := len(client.calls), 1; got != want {
		t.Fatalf("Stripe calls = %d, want %d", got, want)
	}
}

func TestExecutorRejectsIdempotencyKeyReuseAcrossEffectKinds(t *testing.T) {
	client := &fakeEffectClient{}
	executor := NewExecutor(client, EffectLimits{})
	key := "outbox-order-42-payment"
	if _, err := executor.Execute(context.Background(), Effect{Kind: EffectPaymentIntentCreate, IdempotencyKey: key, Payload: `{"amount_cents":2500,"currency":"usd"}`}); err != nil {
		t.Fatal(err)
	}
	_, err := executor.Execute(context.Background(), Effect{Kind: EffectSetupIntentCreate, IdempotencyKey: key, Payload: `{}`})
	if !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("error = %v, want ErrIdempotencyConflict", err)
	}
	if got, want := len(client.calls), 1; got != want {
		t.Fatalf("Stripe calls = %d, want %d", got, want)
	}
}

func TestExecutorRejectsUnsupportedOrUnstableEffectsBeforeClientCall(t *testing.T) {
	client := &fakeEffectClient{}
	executor := NewExecutor(client, EffectLimits{})
	for _, effect := range []Effect{
		{Kind: "charge.anything", IdempotencyKey: "outbox-1", Payload: `{}`},
		{Kind: EffectPaymentIntentCreate, Payload: `{"amount_cents":2500,"currency":"usd"}`},
		{Kind: EffectRefundCreate, IdempotencyKey: "refund-1", Payload: `{"payment_intent":"pi_123","amount_cents":0}`},
	} {
		if _, err := executor.Execute(context.Background(), effect); err == nil {
			t.Fatalf("Execute(%#v) succeeded", effect)
		}
	}
	if got := len(client.calls); got != 0 {
		t.Fatalf("client calls = %d, want 0", got)
	}
}

type scopedTestCell struct {
	name  string
	scope ext.Scope
}

func (c scopedTestCell) Name() string     { return c.name }
func (c scopedTestCell) Scope() ext.Scope { return c.scope }

func TestScopedExecutorFactoryDoesNotShareMutableClientsAcrossApplications(t *testing.T) {
	var clients []*fakeEffectClient
	factory := NewScopedExecutorFactory(func(key ext.ResourceKey) (*Executor, error) {
		client := &fakeEffectClient{}
		clients = append(clients, client)
		return NewExecutor(client, EffectLimits{}), nil
	})
	makeCell := func(app, instance string) scopedTestCell {
		scope, err := ext.NewScope(app, instance, "sessions", "primary")
		if err != nil {
			t.Fatal(err)
		}
		return scopedTestCell{name: "sessions", scope: scope}
	}
	first, err := factory.ForCell(makeCell("evolution", "a"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := factory.ForCell(makeCell("sessions", "b"))
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("different application scopes received the same executor")
	}
	effect := Effect{Kind: EffectPaymentIntentCreate, IdempotencyKey: "outbox-1", Payload: `{"amount_cents":100,"currency":"usd"}`}
	if _, err := first.Execute(context.Background(), effect); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Execute(context.Background(), effect); err != nil {
		t.Fatal(err)
	}
	if got, want := factory.Count(), 2; got != want {
		t.Fatalf("executor scopes = %d, want %d", got, want)
	}
	if got, want := len(clients), 2; got != want {
		t.Fatalf("clients = %d, want %d", got, want)
	}
	if fmt.Sprint(clients[0].calls) != "[payment:outbox-1]" || fmt.Sprint(clients[1].calls) != "[payment:outbox-1]" {
		t.Fatalf("cross-scope calls = %#v / %#v", clients[0].calls, clients[1].calls)
	}
}

func TestScopedExecutorFactoryKeepsLegacyCellNamespace(t *testing.T) {
	factory := NewScopedExecutorFactory(func(key ext.ResourceKey) (*Executor, error) {
		return NewExecutor(&fakeEffectClient{}, EffectLimits{}), nil
	})
	legacy := legacyTestCell("sessions")
	first, err := factory.ForCell(legacy)
	if err != nil {
		t.Fatal(err)
	}
	second, err := factory.ForCell(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("same legacy cell namespace did not replay its scoped executor")
	}
}

type legacyTestCell string

func (c legacyTestCell) Name() string { return string(c) }

func TestExecutorCanonicalIntentWireReturnsBoundReceipt(t *testing.T) {
	client := &fakeEffectClient{}
	executor := NewExecutor(client, EffectLimits{})
	intent, err := effect.NewIntent(
		"effect-order-42",
		"stripe.payment_intent.create",
		"checkout:order-42",
		paymentIntentCreateRequest{
			AmountCents:    2500,
			Currency:       "usd",
			IdempotencyKey: "checkout:order-42",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := effect.MarshalIntent(intent)
	if err != nil {
		t.Fatal(err)
	}
	receiptWire, err := executor.ExecuteIntentWire(context.Background(), wire)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := effect.UnmarshalReceipt(receiptWire)
	if err != nil {
		t.Fatal(err)
	}
	if err := receipt.ValidateFor(intent); err != nil {
		t.Fatal(err)
	}
	result, err := effect.DecodeResult[EffectResult](receipt)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := result.Kind, EffectKind(effect.KindStripePaymentIntentCreate); got != want {
		t.Fatalf("result kind = %q, want %q", got, want)
	}
	if result.PaymentIntent != "pi_123" || result.ClientSecret != "pi_123_secret" {
		t.Fatalf("canonical result = %#v", result)
	}
	if got, want := client.calls, []string{"payment:checkout:order-42"}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("client calls = %#v, want %#v", got, want)
	}
}

func TestExecutorCanonicalWireAcceptsLegacyKindAlias(t *testing.T) {
	client := &fakeEffectClient{}
	executor := NewExecutor(client, EffectLimits{})
	payload, err := msgpack.Marshal(checkoutSessionCreateRequest{
		AmountCents:    2500,
		Currency:       "usd",
		SuccessURL:     "https://example.test/success",
		CancelURL:      "https://example.test/cancel",
		ProductName:    "Sessions server",
		IdempotencyKey: "checkout:order-43",
	})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := msgpack.Marshal(effect.Intent{
		Version:        effect.VersionV1,
		ID:             "effect-order-43",
		Kind:           "stripe.checkout_session.create",
		IdempotencyKey: "checkout:order-43",
		Payload:        payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	receiptWire, err := executor.ExecuteIntentWire(context.Background(), wire)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := effect.UnmarshalReceipt(receiptWire)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := receipt.Kind, effect.KindStripeCheckoutSessionCreate; got != want {
		t.Fatalf("receipt kind = %q, want %q", got, want)
	}
	if got, want := client.calls, []string{"checkout:checkout:order-43"}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("client calls = %#v, want %#v", got, want)
	}
}

func TestExecutorAliasesShareOneReplayIdentity(t *testing.T) {
	client := &fakeEffectClient{}
	executor := NewExecutor(client, EffectLimits{})
	payload := `{"amount_cents":2500,"currency":"usd"}`
	first, err := executor.Execute(context.Background(), Effect{
		Kind: EffectPaymentIntentCreate, IdempotencyKey: "checkout:order-44", Payload: payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := executor.Execute(context.Background(), Effect{
		Kind:           EffectKind(effect.KindStripePaymentIntentCreate),
		IdempotencyKey: "checkout:order-44",
		Payload:        payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("alias replay result = %#v, want %#v", second, first)
	}
	if got, want := len(client.calls), 1; got != want {
		t.Fatalf("client calls = %d, want %d", got, want)
	}
}

func TestExecutorCanonicalIntentRejectsEmbeddedKeyMismatch(t *testing.T) {
	executor := NewExecutor(&fakeEffectClient{}, EffectLimits{})
	intent, err := effect.NewIntent(
		"effect-order-45",
		effect.KindStripePaymentIntentCreate,
		"checkout:order-45",
		paymentIntentCreateRequest{
			AmountCents:    2500,
			Currency:       "usd",
			IdempotencyKey: "different-key",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.ExecuteIntent(context.Background(), intent); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("error = %v, want ErrIdempotencyConflict", err)
	}
}

func TestExecutorCanonicalSetupAndRefundKinds(t *testing.T) {
	tests := []struct {
		name    string
		kind    string
		key     string
		payload any
		call    string
	}{
		{
			name: "setup intent", kind: effect.KindStripeSetupIntentCreate,
			key: "setup:user-1",
			payload: setupIntentCreateRequest{
				Customer: "cus_1", IdempotencyKey: "setup:user-1",
			},
			call: "setup:setup:user-1",
		},
		{
			name: "refund", kind: effect.KindStripeRefundCreate,
			key: "refund:order-1",
			payload: refundCreateRequest{
				PaymentIntentID: "pi_1", IdempotencyKey: "refund:order-1",
			},
			call: "refund:refund:order-1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &fakeEffectClient{}
			executor := NewExecutor(client, EffectLimits{})
			payload, err := msgpack.Marshal(tt.payload)
			if err != nil {
				t.Fatal(err)
			}
			intent := effect.Intent{
				Version: effect.VersionV1, ID: "effect-" + tt.name,
				Kind: tt.kind, IdempotencyKey: tt.key, Payload: payload,
			}
			receipt, err := executor.ExecuteIntent(context.Background(), intent)
			if err != nil {
				t.Fatal(err)
			}
			if receipt.Status != effect.Completed {
				t.Fatalf("receipt status = %q, want %q", receipt.Status, effect.Completed)
			}
			if got, want := client.calls, []string{tt.call}; fmt.Sprint(got) != fmt.Sprint(want) {
				t.Fatalf("client calls = %#v, want %#v", got, want)
			}
		})
	}
}
