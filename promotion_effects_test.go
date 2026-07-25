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

func promotionIntentPayload(kind string) any {
	switch kind {
	case effect.KindStripeCouponUpsert:
		return effect.StripeCouponUpsertPayload{
			ExternalKey: "coupon-local-1", AmountOffCents: 500,
			Currency: "usd", Duration: "once", Name: "Five dollars",
		}
	case effect.KindStripeCouponDelete:
		return effect.StripeCouponDeletePayload{
			ExternalKey: "coupon-local-1", CouponID: "coupon_123",
		}
	case effect.KindStripePromotionCodeUpsert:
		return effect.StripePromotionCodeUpsertPayload{
			ExternalKey: "promotion-local-1", CouponID: "coupon_123",
			Code: "SAVE5", Active: true,
		}
	case effect.KindStripePromotionCodeDeactivate:
		return effect.StripePromotionCodeDeactivatePayload{
			ExternalKey: "promotion-local-1", PromotionCodeID: "promo_123",
		}
	default:
		panic("unsupported test kind " + kind)
	}
}

func TestExecutorCanonicalPromotionAliases(t *testing.T) {
	tests := []struct {
		alias     string
		canonical string
		call      string
	}{
		{"coupon.create", effect.KindStripeCouponUpsert, "coupon-upsert:promotion:key"},
		{"stripe.coupon.delete", effect.KindStripeCouponDelete, "coupon-delete:promotion:key"},
		{"promotion_code.create", effect.KindStripePromotionCodeUpsert, "promotion-upsert:promotion:key"},
		{"stripe.promotion_code.deactivate", effect.KindStripePromotionCodeDeactivate, "promotion-deactivate:promotion:key"},
	}
	for _, tt := range tests {
		t.Run(tt.alias, func(t *testing.T) {
			client := &fakeEffectClient{}
			executor := NewExecutor(client, EffectLimits{})
			payload, err := msgpack.Marshal(promotionIntentPayload(tt.canonical))
			if err != nil {
				t.Fatal(err)
			}
			wire, err := msgpack.Marshal(effect.Intent{
				Version: effect.VersionV1, ID: "promotion-intent", Kind: tt.alias,
				IdempotencyKey: "promotion:key", Payload: payload,
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
			if receipt.Kind != tt.canonical || receipt.Status != effect.Completed {
				t.Fatalf("receipt = %#v, want completed %q", receipt, tt.canonical)
			}
			if got, want := fmt.Sprint(client.calls), "["+tt.call+"]"; got != want {
				t.Fatalf("calls = %s, want %s", got, want)
			}
		})
	}
}

func TestExecutorCanonicalPromotionReplayAndConflict(t *testing.T) {
	client := &fakeEffectClient{}
	executor := NewExecutor(client, EffectLimits{})
	intent, err := effect.NewIntent(
		"coupon-upsert-1", effect.KindStripeCouponUpsert, "coupon:provider-key",
		promotionIntentPayload(effect.KindStripeCouponUpsert),
	)
	if err != nil {
		t.Fatal(err)
	}
	first, err := executor.ExecuteIntent(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	rebound := intent
	rebound.ID = "coupon-upsert-retry"
	second, err := executor.ExecuteIntent(context.Background(), rebound)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(first.Result) != fmt.Sprint(second.Result) || second.IntentID != rebound.ID {
		t.Fatalf("rebound receipt = %#v, first = %#v", second, first)
	}
	if got := len(client.calls); got != 1 {
		t.Fatalf("provider calls = %d, want 1", got)
	}

	conflict, err := effect.NewIntent(
		"coupon-upsert-conflict", effect.KindStripeCouponUpsert, "coupon:provider-key",
		effect.StripeCouponUpsertPayload{
			ExternalKey: "coupon-local-2", PercentOff: 10, Duration: "forever",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.ExecuteIntent(context.Background(), conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflict error = %v, want ErrIdempotencyConflict", err)
	}
}

type retryingPromotionClient struct {
	fakeEffectClient
	failKind string
	failed   bool
}

func (f *retryingPromotionClient) shouldFail(kind, key string) bool {
	if kind == f.failKind && !f.failed {
		f.failed = true
		f.calls = append(f.calls, kind+":"+key)
		return true
	}
	return false
}

func (f *retryingPromotionClient) UpsertCoupon(
	ctx context.Context, payload effect.StripeCouponUpsertPayload, key string,
) (effect.StripeCouponUpsertResult, error) {
	if f.shouldFail("coupon-upsert", key) {
		return effect.StripeCouponUpsertResult{}, errors.New("transient Stripe error")
	}
	return f.fakeEffectClient.UpsertCoupon(ctx, payload, key)
}

func (f *retryingPromotionClient) DeleteCoupon(
	ctx context.Context, payload effect.StripeCouponDeletePayload, key string,
) (effect.StripeCouponDeleteResult, error) {
	if f.shouldFail("coupon-delete", key) {
		return effect.StripeCouponDeleteResult{}, errors.New("transient Stripe error")
	}
	return f.fakeEffectClient.DeleteCoupon(ctx, payload, key)
}

func (f *retryingPromotionClient) UpsertPromotionCode(
	ctx context.Context, payload effect.StripePromotionCodeUpsertPayload, key string,
) (effect.StripePromotionCodeUpsertResult, error) {
	if f.shouldFail("promotion-upsert", key) {
		return effect.StripePromotionCodeUpsertResult{}, errors.New("transient Stripe error")
	}
	return f.fakeEffectClient.UpsertPromotionCode(ctx, payload, key)
}

func (f *retryingPromotionClient) DeactivatePromotionCode(
	ctx context.Context, payload effect.StripePromotionCodeDeactivatePayload, key string,
) (effect.StripePromotionCodeDeactivateResult, error) {
	if f.shouldFail("promotion-deactivate", key) {
		return effect.StripePromotionCodeDeactivateResult{}, errors.New("transient Stripe error")
	}
	return f.fakeEffectClient.DeactivatePromotionCode(ctx, payload, key)
}

func TestExecutorCanonicalPromotionRetriesWithSameProviderKey(t *testing.T) {
	tests := []struct {
		kind string
		call string
	}{
		{effect.KindStripeCouponUpsert, "coupon-upsert"},
		{effect.KindStripeCouponDelete, "coupon-delete"},
		{effect.KindStripePromotionCodeUpsert, "promotion-upsert"},
		{effect.KindStripePromotionCodeDeactivate, "promotion-deactivate"},
	}
	for _, tt := range tests {
		t.Run(tt.call, func(t *testing.T) {
			client := &retryingPromotionClient{failKind: tt.call}
			executor := NewExecutor(client, EffectLimits{})
			intent, err := effect.NewIntent(
				"promotion-retry", tt.kind, "promotion:stable-key",
				promotionIntentPayload(tt.kind),
			)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := executor.ExecuteIntent(context.Background(), intent); err == nil {
				t.Fatal("first execution succeeded, want transient failure")
			}
			if _, err := executor.ExecuteIntent(context.Background(), intent); err != nil {
				t.Fatal(err)
			}
			want := []string{
				tt.call + ":promotion:stable-key",
				tt.call + ":promotion:stable-key",
			}
			if got := fmt.Sprint(client.calls); got != fmt.Sprint(want) {
				t.Fatalf("calls = %s, want %v", got, want)
			}
		})
	}
}

func TestExecutorCanonicalPromotionConcurrentReplayCallsProviderOnce(t *testing.T) {
	client := &fakeEffectClient{}
	executor := NewExecutor(client, EffectLimits{})
	intent, err := effect.NewIntent(
		"promotion-race", effect.KindStripePromotionCodeUpsert, "promotion:race-key",
		promotionIntentPayload(effect.KindStripePromotionCodeUpsert),
	)
	if err != nil {
		t.Fatal(err)
	}

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
	if got := len(client.calls); got != 1 {
		t.Fatalf("provider calls = %d, want 1", got)
	}
}

type invalidPromotionResultClient struct{ fakeEffectClient }

func (f *invalidPromotionResultClient) DeleteCoupon(
	_ context.Context, payload effect.StripeCouponDeletePayload, key string,
) (effect.StripeCouponDeleteResult, error) {
	f.calls = append(f.calls, "coupon-delete:"+key)
	return effect.StripeCouponDeleteResult{
		ExternalKey: payload.ExternalKey, CouponID: payload.CouponID, Deleted: false,
	}, nil
}

func (f *invalidPromotionResultClient) DeactivatePromotionCode(
	_ context.Context, payload effect.StripePromotionCodeDeactivatePayload, key string,
) (effect.StripePromotionCodeDeactivateResult, error) {
	f.calls = append(f.calls, "promotion-deactivate:"+key)
	return effect.StripePromotionCodeDeactivateResult{
		ExternalKey: payload.ExternalKey, PromotionCodeID: payload.PromotionCodeID, Active: true,
	}, nil
}

func TestExecutorRefusesInvalidPromotionProviderAcknowledgements(t *testing.T) {
	for _, kind := range []string{
		effect.KindStripeCouponDelete,
		effect.KindStripePromotionCodeDeactivate,
	} {
		t.Run(kind, func(t *testing.T) {
			client := &invalidPromotionResultClient{}
			executor := NewExecutor(client, EffectLimits{})
			intent, err := effect.NewIntent(
				"invalid-result", kind, "promotion:invalid-result",
				promotionIntentPayload(kind),
			)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := executor.ExecuteIntent(context.Background(), intent); err == nil {
				t.Fatal("invalid provider acknowledgement produced completed receipt")
			}
		})
	}
}
