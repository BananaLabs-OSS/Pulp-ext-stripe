package stripeext

import (
	"testing"

	"github.com/vmihailenco/msgpack/v5"
)

func TestKeyedGuestInvoiceRequestsDecodeAndReachStripeParams(t *testing.T) {
	const key = "free:order-42:step"

	customerWire, err := msgpack.Marshal(map[string]any{
		"email": "person@example.test", "idempotency_key": key,
	})
	if err != nil {
		t.Fatal(err)
	}
	var customerReq customerCreateRequest
	if err := msgpack.Unmarshal(customerWire, &customerReq); err != nil {
		t.Fatal(err)
	}
	assertStripeKey(t, customerParams(customerReq).IdempotencyKey, key)

	itemWire, err := msgpack.Marshal(map[string]any{
		"customer": "cus_123", "amount_cents": int64(2500), "currency": "usd",
		"description": "Sessions server", "idempotency_key": key,
	})
	if err != nil {
		t.Fatal(err)
	}
	var itemReq invoiceItemCreateRequest
	if err := msgpack.Unmarshal(itemWire, &itemReq); err != nil {
		t.Fatal(err)
	}
	assertStripeKey(t, invoiceItemParams(itemReq).IdempotencyKey, key)

	invoiceWire, err := msgpack.Marshal(map[string]any{
		"customer": "cus_123", "collection_method": "charge_automatically",
		"idempotency_key": key,
	})
	if err != nil {
		t.Fatal(err)
	}
	var invoiceReq invoiceCreateRequest
	if err := msgpack.Unmarshal(invoiceWire, &invoiceReq); err != nil {
		t.Fatal(err)
	}
	assertStripeKey(t, invoiceParams(invoiceReq).IdempotencyKey, key)

	idWire, err := msgpack.Marshal(map[string]any{
		"id": "in_123", "idempotency_key": key,
	})
	if err != nil {
		t.Fatal(err)
	}
	var idReq invoiceIDRequest
	if err := msgpack.Unmarshal(idWire, &idReq); err != nil {
		t.Fatal(err)
	}
	assertStripeKey(t, invoiceFinalizeParams(idReq).IdempotencyKey, key)
	payParams := invoicePayParams(idReq)
	assertStripeKey(t, payParams.IdempotencyKey, key)
	if payParams.PaidOutOfBand == nil || !*payParams.PaidOutOfBand {
		t.Fatal("mark-paid request did not retain paid_out_of_band=true")
	}
}

func TestKeyedPromotionRequestsReachStripeParams(t *testing.T) {
	const key = "promotion:local-1:provider"

	coupon := couponParams(couponCreateRequest{
		AmountOffCents: 500, Currency: "usd", Duration: "repeating",
		DurationMonths: 3, IdempotencyKey: key,
	})
	assertStripeKey(t, coupon.IdempotencyKey, key)
	if coupon.DurationInMonths == nil || *coupon.DurationInMonths != 3 {
		t.Fatalf("coupon duration months = %v, want 3", coupon.DurationInMonths)
	}
	assertStripeKey(t, couponDeleteParams(key).IdempotencyKey, key)

	promotion := promotionCodeParams(promotionCodeCreateRequest{
		CouponID: "coupon_123", Code: "SAVE5", Active: true, IdempotencyKey: key,
	})
	assertStripeKey(t, promotion.IdempotencyKey, key)

	deactivate := promotionCodeUpdateParams(promotionCodeUpdateRequest{
		ID: "promo_123", Active: false, IdempotencyKey: key,
	})
	assertStripeKey(t, deactivate.IdempotencyKey, key)
	if deactivate.Active == nil || *deactivate.Active {
		t.Fatal("deactivation request did not retain active=false")
	}
}

func assertStripeKey(t *testing.T, got *string, want string) {
	t.Helper()
	if got == nil || *got != want {
		t.Fatalf("Stripe idempotency key = %v, want %q", got, want)
	}
}
