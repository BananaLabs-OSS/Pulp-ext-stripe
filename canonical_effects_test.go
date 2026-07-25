package stripeext

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/BananaLabs-OSS/Fiber/pulp/effect"
	"github.com/vmihailenco/msgpack/v5"
)

func TestExecutorCanonicalMutationKindsAndAliases(t *testing.T) {
	tests := []struct {
		name    string
		kind    string
		payload any
		call    string
	}{
		{
			name: "capture alias", kind: "stripe.payment_intent.capture",
			payload: effect.StripePaymentIntentCapturePayload{PaymentIntentID: "pi_123"},
			call:    "capture:mutation:1",
		},
		{
			name: "cancel canonical", kind: effect.KindStripePaymentIntentCancel,
			payload: effect.StripePaymentIntentCancelPayload{PaymentIntentID: "pi_123"},
			call:    "cancel:mutation:1",
		},
		{
			name: "customer alias", kind: "customer.create",
			payload: effect.StripeCustomerCreatePayload{Email: "person@example.test"},
			call:    "customer:mutation:1",
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
			wire, err := msgpack.Marshal(effect.Intent{
				Version: effect.VersionV1, ID: "intent-1", Kind: tt.kind,
				IdempotencyKey: "mutation:1", Payload: payload,
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
			canonical, err := effect.NormalizeKind(tt.kind)
			if err != nil {
				t.Fatal(err)
			}
			if receipt.Kind != canonical || receipt.Status != effect.Completed {
				t.Fatalf("receipt = %#v, want completed %q", receipt, canonical)
			}
			if got, want := fmt.Sprint(client.calls), "["+tt.call+"]"; got != want {
				t.Fatalf("calls = %s, want %s", got, want)
			}
		})
	}
}

func TestExecutorCanonicalMutationReplayAndConflict(t *testing.T) {
	client := &fakeEffectClient{}
	executor := NewExecutor(client, EffectLimits{})
	intent, err := effect.NewIntent(
		"intent-capture-1", effect.KindStripePaymentIntentCapture, "capture:1",
		effect.StripePaymentIntentCapturePayload{PaymentIntentID: "pi_123"},
	)
	if err != nil {
		t.Fatal(err)
	}
	first, err := executor.ExecuteIntent(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	rebound := intent
	rebound.ID = "intent-capture-retry"
	second, err := executor.ExecuteIntent(context.Background(), rebound)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(first.Result) != fmt.Sprint(second.Result) {
		t.Fatalf("replay result = %v, want %v", second.Result, first.Result)
	}
	if second.IntentID != rebound.ID {
		t.Fatalf("replayed receipt intent = %q, want %q", second.IntentID, rebound.ID)
	}
	if got := len(client.calls); got != 1 {
		t.Fatalf("provider calls = %d, want 1", got)
	}

	conflict, err := effect.NewIntent(
		"intent-capture-conflict", effect.KindStripePaymentIntentCapture, "capture:1",
		effect.StripePaymentIntentCapturePayload{PaymentIntentID: "pi_other"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.ExecuteIntent(context.Background(), conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflict error = %v, want ErrIdempotencyConflict", err)
	}
}

func TestExecutorCanonicalAndLegacyEffectsCannotShareProviderKey(t *testing.T) {
	client := &fakeEffectClient{}
	executor := NewExecutor(client, EffectLimits{})
	intent, err := effect.NewIntent(
		"intent-customer-1", effect.KindStripeCustomerCreate, "globally-unique-key",
		effect.StripeCustomerCreatePayload{Email: "person@example.test"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.ExecuteIntent(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Execute(context.Background(), Effect{
		Kind: EffectPaymentIntentCreate, IdempotencyKey: "globally-unique-key",
		Payload: `{"amount_cents":2500,"currency":"usd"}`,
	}); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("cross-contract error = %v, want ErrIdempotencyConflict", err)
	}
}

func TestExecutorCanonicalMutationConcurrentReplayCallsProviderOnce(t *testing.T) {
	client := &fakeEffectClient{}
	executor := NewExecutor(client, EffectLimits{})
	intent, err := effect.NewIntent(
		"intent-capture-race", effect.KindStripePaymentIntentCapture, "capture:race",
		effect.StripePaymentIntentCapturePayload{PaymentIntentID: "pi_123"},
	)
	if err != nil {
		t.Fatal(err)
	}

	const workers = 32
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := executor.ExecuteIntent(context.Background(), intent)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := len(client.calls); got != 1 {
		t.Fatalf("provider calls = %d, want 1", got)
	}
}

type retryingCompoundClient struct {
	fakeEffectClient
	failStep string
	failed   bool
	counts   map[string]int
}

func newRetryingCompoundClient(failStep string) *retryingCompoundClient {
	return &retryingCompoundClient{failStep: failStep, counts: make(map[string]int)}
}

func (f *retryingCompoundClient) step(name, key string) error {
	f.calls = append(f.calls, name+":"+key)
	f.counts[name]++
	if name == f.failStep && !f.failed {
		f.failed = true
		return errors.New("transient provider failure")
	}
	return nil
}

func (f *retryingCompoundClient) CreateCustomer(
	_ context.Context, payload effect.StripeCustomerCreatePayload, key string,
) (effect.StripeCustomerCreateResult, error) {
	if err := f.step("customer", key); err != nil {
		return effect.StripeCustomerCreateResult{}, err
	}
	return effect.StripeCustomerCreateResult{CustomerID: "cus_123", Email: payload.Email}, nil
}

func (f *retryingCompoundClient) CreateFreeInvoiceItem(
	_ context.Context, _ string, _ effect.StripeFreeInvoiceItem, key string,
) (string, error) {
	if err := f.step("item", key); err != nil {
		return "", err
	}
	return "ii_123", nil
}

func (f *retryingCompoundClient) CreateFreeInvoice(
	_ context.Context, _ string, _ effect.StripeFreeInvoice, key string,
) (invoiceEffectResult, error) {
	if err := f.step("invoice", key); err != nil {
		return invoiceEffectResult{}, err
	}
	return invoiceEffectResult{ID: "in_123", Status: "draft"}, nil
}

func (f *retryingCompoundClient) FinalizeFreeInvoice(
	_ context.Context, _ string, key string,
) (invoiceEffectResult, error) {
	if err := f.step("finalize", key); err != nil {
		return invoiceEffectResult{}, err
	}
	return invoiceEffectResult{ID: "in_123", Status: "open", AmountDue: 0}, nil
}

func (f *retryingCompoundClient) MarkFreeInvoicePaid(
	_ context.Context, _ string, key string,
) (invoiceEffectResult, error) {
	if err := f.step("paid", key); err != nil {
		return invoiceEffectResult{}, err
	}
	return invoiceEffectResult{
		ID: "in_123", Status: "paid", HostedInvoiceURL: "https://invoice.test/in_123",
		AmountDue: 0, AmountPaid: 0,
	}, nil
}

func freeInvoiceIntent(t *testing.T, key string) effect.Intent {
	t.Helper()
	intent, err := effect.NewIntent(
		"intent-free-invoice", effect.KindStripeFreeInvoiceFinalize, key,
		effect.StripeFreeInvoiceFinalizePayload{
			Customer: effect.StripeCustomerCreatePayload{Email: "free@example.test"},
			InvoiceItem: effect.StripeFreeInvoiceItem{
				AmountCents: 2500, Currency: "usd", Description: "Sessions server",
			},
			Invoice: effect.StripeFreeInvoice{
				Description: "Free Sessions order", PromotionCodeID: "promo_100_percent",
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return intent
}

func TestExecutorFreeInvoiceRetryAtEveryStep(t *testing.T) {
	steps := []string{"customer", "item", "invoice", "finalize", "paid"}
	for failedIndex, failedStep := range steps {
		t.Run(failedStep, func(t *testing.T) {
			client := newRetryingCompoundClient(failedStep)
			executor := NewExecutor(client, EffectLimits{})
			intent := freeInvoiceIntent(t, "free:order-42")

			if _, err := executor.ExecuteIntent(context.Background(), intent); err == nil {
				t.Fatal("first execution succeeded, want transient failure")
			}
			receipt, err := executor.ExecuteIntent(context.Background(), intent)
			if err != nil {
				t.Fatal(err)
			}
			result, err := effect.DecodeResult[effect.StripeFreeInvoiceFinalizeResult](receipt)
			if err != nil {
				t.Fatal(err)
			}
			if result.InvoiceID != "in_123" || result.AmountDue != 0 || result.Status != "paid" {
				t.Fatalf("result = %#v", result)
			}

			for index, step := range steps {
				wantCalls := 1
				if index == failedIndex {
					wantCalls = 2
				}
				if got := client.counts[step]; got != wantCalls {
					t.Fatalf("%s calls = %d, want %d", step, got, wantCalls)
				}
			}
			wantKeys := map[string]string{
				"customer": "free:order-42:customer",
				"item":     "free:order-42:item",
				"invoice":  "free:order-42:invoice",
				"finalize": "free:order-42:finalize",
				"paid":     "free:order-42:paid",
			}
			for name, key := range wantKeys {
				found := false
				for _, call := range client.calls {
					if call == name+":"+key {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("missing stable call %q in %#v", name+":"+key, client.calls)
				}
			}
		})
	}
}

func TestExecutorFreeInvoiceConcurrentReplayCallsEachStepOnce(t *testing.T) {
	client := newRetryingCompoundClient("")
	executor := NewExecutor(client, EffectLimits{})
	intent := freeInvoiceIntent(t, "free:order-race")

	const workers = 24
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := executor.ExecuteIntent(context.Background(), intent)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, step := range []string{"customer", "item", "invoice", "finalize", "paid"} {
		if got := client.counts[step]; got != 1 {
			t.Fatalf("%s calls = %d, want 1", step, got)
		}
	}
}

type nonZeroInvoiceClient struct{ fakeEffectClient }

func (f *nonZeroInvoiceClient) FinalizeFreeInvoice(
	_ context.Context, _ string, key string,
) (invoiceEffectResult, error) {
	f.calls = append(f.calls, "finalize:"+key)
	return invoiceEffectResult{ID: "in_123", Status: "open", AmountDue: 25}, nil
}

func TestExecutorFreeInvoiceRefusesNonZeroAmountDue(t *testing.T) {
	client := &nonZeroInvoiceClient{}
	executor := NewExecutor(client, EffectLimits{})
	intent := freeInvoiceIntent(t, "free:order-nonzero")

	for i := 0; i < 2; i++ {
		if _, err := executor.ExecuteIntent(context.Background(), intent); !errors.Is(err, ErrFreeInvoiceNotZero) {
			t.Fatalf("attempt %d error = %v, want ErrFreeInvoiceNotZero", i+1, err)
		}
	}
	for _, call := range client.calls {
		if call == "paid:free:order-nonzero:paid" {
			t.Fatal("nonzero invoice was marked paid")
		}
	}
}

func TestDerivedStripeKeyIsExactAndBounded(t *testing.T) {
	if got, want := derivedStripeKey("free:42", ":invoice"), "free:42:invoice"; got != want {
		t.Fatalf("short derived key = %q, want %q", got, want)
	}
	long := string(make([]byte, 255))
	first := derivedStripeKey(long, ":finalize")
	second := derivedStripeKey(long, ":finalize")
	if first != second || len(first) > 255 {
		t.Fatalf("long derived key is unstable or too long: len=%d", len(first))
	}
}
