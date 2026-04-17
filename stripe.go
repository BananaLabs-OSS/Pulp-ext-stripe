// Package stripeext provides the payment.stripe capability for Pulp
// plugins, backed by stripe-go/v82. Covers the API surface Evolution
// uses: Checkout Sessions for purchase flows, webhook signature
// verification for event ingest, PaymentIntent lookups for order
// reconciliation, and Refunds for customer service.
//
// Plugin authors declare the capability:
//
//	capabilities = ["payment.stripe"]
//
// Deployments link via blank import:
//
//	import _ "github.com/BananaLabs-OSS/Pulp-ext-stripe"
//
// Configuration via environment variables:
//
//	STRIPE_SECRET_KEY     — required, `sk_test_...` or `sk_live_...`
//	STRIPE_WEBHOOK_SECRET — optional; required only if the plugin
//	                        verifies inbound webhook signatures
//
// Host imports (all msgpack request/response, error-code return):
//
//	stripe_checkout_session_create(req, resp) → code
//	  req:  {amount_cents, currency, success_url, cancel_url,
//	         product_name, product_description?, metadata?}
//	  resp: {id, url}
//
//	stripe_webhook_verify(req) → code
//	  req:  {payload_bytes, signature_header}
//	  returns error_code; ok means signature valid
//
//	stripe_payment_intent_get(req, resp) → code
//	  req:  {id}
//	  resp: {id, status, amount, currency, metadata}
//
//	stripe_refund_create(req, resp) → code
//	  req:  {payment_intent_id, amount_cents?, reason?}
//	  resp: {id, status}
//
// Error codes: 0 ok, 1 empty input, 2 memory read failed, 3 decode
// failed, 4 stripe API error, 5 encode failed, 6 signature invalid,
// 7 alloc failed, 8 memory write failed, 10 missing STRIPE_SECRET_KEY.
package stripeext

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/BananaLabs-OSS/Pulp/ext"
	"github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/checkout/session"
	"github.com/stripe/stripe-go/v82/paymentintent"
	"github.com/stripe/stripe-go/v82/refund"
	"github.com/stripe/stripe-go/v82/webhook"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/vmihailenco/msgpack/v5"
)

func init() {
	ext.Register(ext.Capability{
		Name:     "payment.stripe",
		Register: bindActive,
		Stub:     bindStub,
	})
}

// ---- initialization ------------------------------------------------------

var (
	initMu        sync.Mutex
	initialized   bool
	webhookSecret string
	initErr       error
)

func ensureConfigured() error {
	initMu.Lock()
	defer initMu.Unlock()
	if initialized {
		return initErr
	}
	initialized = true

	key := os.Getenv("STRIPE_SECRET_KEY")
	if key == "" {
		initErr = fmt.Errorf("stripe: STRIPE_SECRET_KEY required")
		return initErr
	}
	stripe.Key = key
	webhookSecret = os.Getenv("STRIPE_WEBHOOK_SECRET")
	return nil
}

// ---- request / response types -------------------------------------------

type checkoutSessionCreateRequest struct {
	AmountCents        int64             `msgpack:"amount_cents"`
	Currency           string            `msgpack:"currency"`
	SuccessURL         string            `msgpack:"success_url"`
	CancelURL          string            `msgpack:"cancel_url"`
	ProductName        string            `msgpack:"product_name"`
	ProductDescription string            `msgpack:"product_description,omitempty"`
	Metadata           map[string]string `msgpack:"metadata,omitempty"`
}

type checkoutSessionCreateResponse struct {
	ID  string `msgpack:"id"`
	URL string `msgpack:"url"`
}

type webhookVerifyRequest struct {
	Payload         []byte `msgpack:"payload"`
	SignatureHeader string `msgpack:"signature_header"`
}

type paymentIntentGetRequest struct {
	ID string `msgpack:"id"`
}

type paymentIntentGetResponse struct {
	ID       string            `msgpack:"id"`
	Status   string            `msgpack:"status"`
	Amount   int64             `msgpack:"amount"`
	Currency string            `msgpack:"currency"`
	Metadata map[string]string `msgpack:"metadata"`
}

type refundCreateRequest struct {
	PaymentIntentID string `msgpack:"payment_intent_id"`
	AmountCents     int64  `msgpack:"amount_cents,omitempty"`
	Reason          string `msgpack:"reason,omitempty"`
}

type refundCreateResponse struct {
	ID     string `msgpack:"id"`
	Status string `msgpack:"status"`
}

// ---- binding ------------------------------------------------------------

func bindActive(b wazero.HostModuleBuilder, _ ext.Plugin) error {
	b.NewFunctionBuilder().WithFunc(checkoutSessionCreate).Export("stripe_checkout_session_create")
	b.NewFunctionBuilder().WithFunc(webhookVerify).Export("stripe_webhook_verify")
	b.NewFunctionBuilder().WithFunc(paymentIntentGet).Export("stripe_payment_intent_get")
	b.NewFunctionBuilder().WithFunc(refundCreate).Export("stripe_refund_create")
	return nil
}

func bindStub(b wazero.HostModuleBuilder, _ ext.Plugin) error {
	nop4 := func(_ context.Context, _ api.Module, _, _, _, _ uint32) uint32 { return 99 }
	nop2 := func(_ context.Context, _ api.Module, _, _ uint32) uint32 { return 99 }
	b.NewFunctionBuilder().WithFunc(nop4).Export("stripe_checkout_session_create")
	b.NewFunctionBuilder().WithFunc(nop2).Export("stripe_webhook_verify")
	b.NewFunctionBuilder().WithFunc(nop4).Export("stripe_payment_intent_get")
	b.NewFunctionBuilder().WithFunc(nop4).Export("stripe_refund_create")
	return nil
}

// ---- handlers -----------------------------------------------------------

func checkoutSessionCreate(ctx context.Context, m api.Module, reqPtr, reqLen, respPtrOut, respLenOut uint32) uint32 {
	if reqLen == 0 {
		return 1
	}
	data, ok := m.Memory().Read(reqPtr, reqLen)
	if !ok {
		return 2
	}
	var req checkoutSessionCreateRequest
	if err := msgpack.Unmarshal(data, &req); err != nil {
		return 3
	}
	if err := ensureConfigured(); err != nil {
		return 10
	}

	params := &stripe.CheckoutSessionParams{
		Mode:       stripe.String(string(stripe.CheckoutSessionModePayment)),
		SuccessURL: stripe.String(req.SuccessURL),
		CancelURL:  stripe.String(req.CancelURL),
		LineItems: []*stripe.CheckoutSessionLineItemParams{
			{
				PriceData: &stripe.CheckoutSessionLineItemPriceDataParams{
					Currency:   stripe.String(req.Currency),
					UnitAmount: stripe.Int64(req.AmountCents),
					ProductData: &stripe.CheckoutSessionLineItemPriceDataProductDataParams{
						Name:        stripe.String(req.ProductName),
						Description: stripe.String(req.ProductDescription),
					},
				},
				Quantity: stripe.Int64(1),
			},
		},
	}
	for k, v := range req.Metadata {
		params.AddMetadata(k, v)
	}
	s, err := session.New(params)
	if err != nil {
		return 4
	}
	return writeMsgpackResponse(ctx, m, checkoutSessionCreateResponse{
		ID:  s.ID,
		URL: s.URL,
	}, respPtrOut, respLenOut)
}

func webhookVerify(_ context.Context, m api.Module, reqPtr, reqLen uint32) uint32 {
	if reqLen == 0 {
		return 1
	}
	data, ok := m.Memory().Read(reqPtr, reqLen)
	if !ok {
		return 2
	}
	var req webhookVerifyRequest
	if err := msgpack.Unmarshal(data, &req); err != nil {
		return 3
	}
	if err := ensureConfigured(); err != nil {
		return 10
	}
	if webhookSecret == "" {
		return 10
	}
	if _, err := webhook.ConstructEvent(req.Payload, req.SignatureHeader, webhookSecret); err != nil {
		return 6
	}
	return 0
}

func paymentIntentGet(ctx context.Context, m api.Module, reqPtr, reqLen, respPtrOut, respLenOut uint32) uint32 {
	if reqLen == 0 {
		return 1
	}
	data, ok := m.Memory().Read(reqPtr, reqLen)
	if !ok {
		return 2
	}
	var req paymentIntentGetRequest
	if err := msgpack.Unmarshal(data, &req); err != nil {
		return 3
	}
	if err := ensureConfigured(); err != nil {
		return 10
	}
	pi, err := paymentintent.Get(req.ID, nil)
	if err != nil {
		return 4
	}
	resp := paymentIntentGetResponse{
		ID:       pi.ID,
		Status:   string(pi.Status),
		Amount:   pi.Amount,
		Currency: string(pi.Currency),
		Metadata: pi.Metadata,
	}
	return writeMsgpackResponse(ctx, m, resp, respPtrOut, respLenOut)
}

func refundCreate(ctx context.Context, m api.Module, reqPtr, reqLen, respPtrOut, respLenOut uint32) uint32 {
	if reqLen == 0 {
		return 1
	}
	data, ok := m.Memory().Read(reqPtr, reqLen)
	if !ok {
		return 2
	}
	var req refundCreateRequest
	if err := msgpack.Unmarshal(data, &req); err != nil {
		return 3
	}
	if err := ensureConfigured(); err != nil {
		return 10
	}
	params := &stripe.RefundParams{
		PaymentIntent: stripe.String(req.PaymentIntentID),
	}
	if req.AmountCents > 0 {
		params.Amount = stripe.Int64(req.AmountCents)
	}
	if req.Reason != "" {
		params.Reason = stripe.String(req.Reason)
	}
	r, err := refund.New(params)
	if err != nil {
		return 4
	}
	return writeMsgpackResponse(ctx, m, refundCreateResponse{
		ID:     r.ID,
		Status: string(r.Status),
	}, respPtrOut, respLenOut)
}

// writeMsgpackResponse is the same pattern every extension follows:
// marshal the response, allocate via pulp_alloc, write bytes, record
// (ptr, len) at the caller-supplied out-addresses.
func writeMsgpackResponse(ctx context.Context, m api.Module, v any, respPtrOut, respLenOut uint32) uint32 {
	encoded, err := msgpack.Marshal(v)
	if err != nil {
		return 5
	}
	allocFn := m.ExportedFunction("pulp_alloc")
	if allocFn == nil {
		return 7
	}
	var ptr uint32
	if len(encoded) > 0 {
		res, err := allocFn.Call(ctx, uint64(len(encoded)))
		if err != nil || len(res) == 0 {
			return 7
		}
		ptr = uint32(res[0])
		if ptr == 0 {
			return 7
		}
		if !m.Memory().Write(ptr, encoded) {
			return 8
		}
	}
	if !m.Memory().WriteUint32Le(respPtrOut, ptr) {
		return 8
	}
	if !m.Memory().WriteUint32Le(respLenOut, uint32(len(encoded))) {
		return 8
	}
	return 0
}
