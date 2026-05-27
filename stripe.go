// Package stripeext provides the payment.stripe capability for Pulp
// cells, backed by stripe-go/v82. Covers the API surface Evolution
// uses: Checkout Sessions for purchase flows, webhook signature
// verification for event ingest, PaymentIntent lookups for order
// reconciliation, and Refunds for customer service.
//
// Cell authors declare the capability:
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
//	STRIPE_WEBHOOK_SECRET — optional; required only if the cell
//	                        verifies inbound webhook signatures
//
// Host imports (all msgpack request/response, error-code return):
//
//	stripe_checkout_session_create(req, resp) → code
//	  req:  {amount_cents, currency, success_url, cancel_url,
//	         product_name, product_description?, metadata?}
//	  resp: {id, url}
//
//	stripe_checkout_session_get(req, resp) → code
//	  req:  {id}
//	  resp: {id, url, status, payment_intent, payment_status}
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
//	stripe_coupon_create(req, resp) → code
//	  req:  {amount_off_cents?, percent_off?, currency?, duration,
//	         duration_months?, max_redemptions?, redeem_by?, name?,
//	         metadata?}
//	  resp: {id, valid, amount_off?, percent_off?, currency?, duration}
//
//	stripe_promotion_code_create(req, resp) → code
//	  req:  {coupon_id, code?, active, max_redemptions?, expires_at?,
//	         customer?, metadata?}
//	  resp: {id, code, coupon_id, active, max_redemptions, times_redeemed,
//	         expires_at, amount_off?, percent_off?, currency?}
//
//	stripe_promotion_code_lookup(req, resp) → code
//	  req:  {code}
//	  resp: same as promotion_code_create; empty struct if not found
//
//	stripe_promotion_code_update(req, resp) → code
//	  req:  {id, active}
//	  resp: same as promotion_code_create
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
	"github.com/stripe/stripe-go/v82/balance"
	"github.com/stripe/stripe-go/v82/checkout/session"
	"github.com/stripe/stripe-go/v82/coupon"
	"github.com/stripe/stripe-go/v82/customer"
	"github.com/stripe/stripe-go/v82/invoice"
	"github.com/stripe/stripe-go/v82/invoiceitem"
	"github.com/stripe/stripe-go/v82/paymentintent"
	"github.com/stripe/stripe-go/v82/promotioncode"
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
	AutomaticTax       bool              `msgpack:"automatic_tax,omitempty"`
}

type checkoutSessionCreateResponse struct {
	ID  string `msgpack:"id"`
	URL string `msgpack:"url"`
}

type checkoutSessionGetRequest struct {
	ID string `msgpack:"id"`
}

type checkoutSessionGetResponse struct {
	ID            string `msgpack:"id"`
	URL           string `msgpack:"url,omitempty"`
	Status        string `msgpack:"status"`
	PaymentIntent string `msgpack:"payment_intent,omitempty"`
	PaymentStatus string `msgpack:"payment_status,omitempty"`
	CustomerEmail string `msgpack:"customer_email,omitempty"`
	AmountTotal   int64  `msgpack:"amount_total"`
	Currency      string `msgpack:"currency,omitempty"`
}

type webhookVerifyRequest struct {
	Payload         []byte `msgpack:"payload"`
	SignatureHeader string `msgpack:"signature_header"`
}

type paymentIntentCreateRequest struct {
	AmountCents        int64             `msgpack:"amount_cents"`
	Currency           string            `msgpack:"currency"`
	Description        string            `msgpack:"description,omitempty"`
	ReceiptEmail       string            `msgpack:"receipt_email,omitempty"`
	CaptureMethod      string            `msgpack:"capture_method,omitempty"` // "automatic" or "manual"
	PaymentMethodTypes []string          `msgpack:"payment_method_types,omitempty"`
	Customer           string            `msgpack:"customer,omitempty"`
	Metadata           map[string]string `msgpack:"metadata,omitempty"`
	IdempotencyKey     string            `msgpack:"idempotency_key,omitempty"`
	// PromotionCodeID — when set, the discount metadata is recorded on the
	// PaymentIntent so post-payment reconciliation can credit the right
	// Stripe PromotionCode. Stripe doesn't accept a direct `discounts` param
	// on the PaymentIntent API (only Checkout Sessions and Invoices do); the
	// caller is expected to have already computed the post-discount amount.
	// We stamp the ID into metadata so a later Stripe-side report can tie
	// the charge back to the promotion code that produced the discount.
	PromotionCodeID string `msgpack:"promotion_code_id,omitempty"`
	AutomaticTax    bool   `msgpack:"automatic_tax,omitempty"`
}

type paymentIntentGetRequest struct {
	ID string `msgpack:"id"`
}

type paymentIntentResponse struct {
	ID             string            `msgpack:"id"`
	Status         string            `msgpack:"status"`
	Amount         int64             `msgpack:"amount"`
	Currency       string            `msgpack:"currency"`
	ClientSecret   string            `msgpack:"client_secret,omitempty"`
	ReceiptEmail   string            `msgpack:"receipt_email,omitempty"`
	CaptureMethod  string            `msgpack:"capture_method,omitempty"`
	LatestCharge   string            `msgpack:"latest_charge,omitempty"`
	LastErrorMsg   string            `msgpack:"last_error,omitempty"`
	LastErrorCode  string            `msgpack:"last_error_code,omitempty"`
	Metadata       map[string]string `msgpack:"metadata"`
}

type paymentIntentIDRequest struct {
	ID             string `msgpack:"id"`
	IdempotencyKey string `msgpack:"idempotency_key,omitempty"`
}

type refundCreateRequest struct {
	PaymentIntentID string            `msgpack:"payment_intent_id"`
	AmountCents     int64             `msgpack:"amount_cents,omitempty"`
	Reason          string            `msgpack:"reason,omitempty"`
	Metadata        map[string]string `msgpack:"metadata,omitempty"`
	IdempotencyKey  string            `msgpack:"idempotency_key,omitempty"`
}

type refundCreateResponse struct {
	ID     string `msgpack:"id"`
	Status string `msgpack:"status"`
}

type customerCreateRequest struct {
	Email       string            `msgpack:"email,omitempty"`
	Name        string            `msgpack:"name,omitempty"`
	Description string            `msgpack:"description,omitempty"`
	Metadata    map[string]string `msgpack:"metadata,omitempty"`
}

type customerResponse struct {
	ID    string `msgpack:"id"`
	Email string `msgpack:"email,omitempty"`
}

type invoiceCreateRequest struct {
	Customer         string            `msgpack:"customer"`
	Description      string            `msgpack:"description,omitempty"`
	AutoAdvance      bool              `msgpack:"auto_advance,omitempty"`
	CollectionMethod string            `msgpack:"collection_method,omitempty"` // "charge_automatically" or "send_invoice"
	Metadata         map[string]string `msgpack:"metadata,omitempty"`
	// PromotionCodeID — when set, applied as an Invoice-level discount.
	// Stripe's Invoice API supports Discounts (PaymentIntent doesn't), so
	// the cleanest replacement for the legacy paired-invoice-item $0 hack
	// is a real Invoice with a 100%-off (or N-cent-off) PromotionCode
	// attached. Stripe computes the final due amount; auto-advance +
	// charge_automatically settles $0 invoices to paid automatically.
	PromotionCodeID string `msgpack:"promotion_code_id,omitempty"`
}

type invoiceIDRequest struct {
	ID string `msgpack:"id"`
}

type invoiceResponse struct {
	ID             string `msgpack:"id"`
	Status         string `msgpack:"status"`
	HostedInvoice  string `msgpack:"hosted_invoice_url,omitempty"`
	InvoicePDF     string `msgpack:"invoice_pdf,omitempty"`
	AmountDue      int64  `msgpack:"amount_due"`
	AmountPaid     int64  `msgpack:"amount_paid"`
}

type invoiceItemCreateRequest struct {
	Customer    string `msgpack:"customer"`
	Invoice     string `msgpack:"invoice,omitempty"`
	AmountCents int64  `msgpack:"amount_cents"`
	Currency    string `msgpack:"currency"`
	Description string `msgpack:"description,omitempty"`
}

type invoiceItemResponse struct {
	ID string `msgpack:"id"`
}

type balanceResponse struct {
	Available []balanceAmount `msgpack:"available"`
	Pending   []balanceAmount `msgpack:"pending"`
}

type balanceAmount struct {
	Amount   int64  `msgpack:"amount"`
	Currency string `msgpack:"currency"`
}

// ---- binding ------------------------------------------------------------

func bindActive(b wazero.HostModuleBuilder, _ ext.Cell) error {
	b.NewFunctionBuilder().WithFunc(checkoutSessionCreate).Export("stripe_checkout_session_create")
	b.NewFunctionBuilder().WithFunc(checkoutSessionGet).Export("stripe_checkout_session_get")
	b.NewFunctionBuilder().WithFunc(webhookVerify).Export("stripe_webhook_verify")
	b.NewFunctionBuilder().WithFunc(paymentIntentCreate).Export("stripe_payment_intent_create")
	b.NewFunctionBuilder().WithFunc(paymentIntentGet).Export("stripe_payment_intent_get")
	b.NewFunctionBuilder().WithFunc(paymentIntentCapture).Export("stripe_payment_intent_capture")
	b.NewFunctionBuilder().WithFunc(paymentIntentCancel).Export("stripe_payment_intent_cancel")
	b.NewFunctionBuilder().WithFunc(refundCreate).Export("stripe_refund_create")
	b.NewFunctionBuilder().WithFunc(customerCreate).Export("stripe_customer_create")
	b.NewFunctionBuilder().WithFunc(invoiceCreate).Export("stripe_invoice_create")
	b.NewFunctionBuilder().WithFunc(invoiceFinalize).Export("stripe_invoice_finalize")
	b.NewFunctionBuilder().WithFunc(invoiceMarkPaidOutOfBand).Export("stripe_invoice_mark_paid_out_of_band")
	b.NewFunctionBuilder().WithFunc(invoiceItemCreate).Export("stripe_invoice_item_create")
	b.NewFunctionBuilder().WithFunc(balanceGet).Export("stripe_balance_get")
	b.NewFunctionBuilder().WithFunc(couponCreate).Export("stripe_coupon_create")
	b.NewFunctionBuilder().WithFunc(promotionCodeCreate).Export("stripe_promotion_code_create")
	b.NewFunctionBuilder().WithFunc(promotionCodeLookup).Export("stripe_promotion_code_lookup")
	b.NewFunctionBuilder().WithFunc(promotionCodeUpdate).Export("stripe_promotion_code_update")
	return nil
}

func bindStub(b wazero.HostModuleBuilder, _ ext.Cell) error {
	nop4 := func(_ context.Context, _ api.Module, _, _, _, _ uint32) uint32 { return 99 }
	nop2 := func(_ context.Context, _ api.Module, _, _ uint32) uint32 { return 99 }
	b.NewFunctionBuilder().WithFunc(nop4).Export("stripe_checkout_session_create")
	b.NewFunctionBuilder().WithFunc(nop4).Export("stripe_checkout_session_get")
	b.NewFunctionBuilder().WithFunc(nop2).Export("stripe_webhook_verify")
	b.NewFunctionBuilder().WithFunc(nop4).Export("stripe_payment_intent_create")
	b.NewFunctionBuilder().WithFunc(nop4).Export("stripe_payment_intent_get")
	b.NewFunctionBuilder().WithFunc(nop4).Export("stripe_payment_intent_capture")
	b.NewFunctionBuilder().WithFunc(nop4).Export("stripe_payment_intent_cancel")
	b.NewFunctionBuilder().WithFunc(nop4).Export("stripe_refund_create")
	b.NewFunctionBuilder().WithFunc(nop4).Export("stripe_customer_create")
	b.NewFunctionBuilder().WithFunc(nop4).Export("stripe_invoice_create")
	b.NewFunctionBuilder().WithFunc(nop4).Export("stripe_invoice_finalize")
	b.NewFunctionBuilder().WithFunc(nop4).Export("stripe_invoice_mark_paid_out_of_band")
	b.NewFunctionBuilder().WithFunc(nop4).Export("stripe_invoice_item_create")
	b.NewFunctionBuilder().WithFunc(nop4).Export("stripe_balance_get")
	b.NewFunctionBuilder().WithFunc(nop4).Export("stripe_coupon_create")
	b.NewFunctionBuilder().WithFunc(nop4).Export("stripe_promotion_code_create")
	b.NewFunctionBuilder().WithFunc(nop4).Export("stripe_promotion_code_lookup")
	b.NewFunctionBuilder().WithFunc(nop4).Export("stripe_promotion_code_update")
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
	if req.AutomaticTax {
		params.AutomaticTax = &stripe.CheckoutSessionAutomaticTaxParams{
			Enabled: stripe.Bool(true),
		}
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

func checkoutSessionGet(ctx context.Context, m api.Module, reqPtr, reqLen, respPtrOut, respLenOut uint32) uint32 {
	if reqLen == 0 {
		return 1
	}
	data, ok := m.Memory().Read(reqPtr, reqLen)
	if !ok {
		return 2
	}
	var req checkoutSessionGetRequest
	if err := msgpack.Unmarshal(data, &req); err != nil {
		return 3
	}
	if err := ensureConfigured(); err != nil {
		return 10
	}
	s, err := session.Get(req.ID, nil)
	if err != nil {
		return 4
	}
	resp := checkoutSessionGetResponse{
		ID:            s.ID,
		URL:           s.URL,
		Status:        string(s.Status),
		PaymentStatus: string(s.PaymentStatus),
		CustomerEmail: s.CustomerEmail,
		AmountTotal:   s.AmountTotal,
		Currency:      string(s.Currency),
	}
	if s.PaymentIntent != nil {
		resp.PaymentIntent = s.PaymentIntent.ID
	}
	return writeMsgpackResponse(ctx, m, resp, respPtrOut, respLenOut)
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
	// IgnoreAPIVersionMismatch matches Evolution's native code — Stripe
	// accounts can be on a newer API version than the linked stripe-go
	// release and the mismatch is not a security concern for signature
	// verification. ConstructEvent (strict) would reject those events.
	if _, err := webhook.ConstructEventWithOptions(req.Payload, req.SignatureHeader, webhookSecret, webhook.ConstructEventOptions{
		IgnoreAPIVersionMismatch: true,
	}); err != nil {
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
	return writeMsgpackResponse(ctx, m, encodePaymentIntent(pi), respPtrOut, respLenOut)
}

// encodePaymentIntent snapshots the fields callers actually need to
// drive the checkout / capture / refund flow. Keeps one encoding path
// across create/get/capture/cancel.
func encodePaymentIntent(pi *stripe.PaymentIntent) paymentIntentResponse {
	resp := paymentIntentResponse{
		ID:            pi.ID,
		Status:        string(pi.Status),
		Amount:        pi.Amount,
		Currency:      string(pi.Currency),
		ClientSecret:  pi.ClientSecret,
		ReceiptEmail:  pi.ReceiptEmail,
		CaptureMethod: string(pi.CaptureMethod),
		Metadata:      pi.Metadata,
	}
	if pi.LatestCharge != nil {
		resp.LatestCharge = pi.LatestCharge.ID
	}
	if pi.LastPaymentError != nil {
		resp.LastErrorMsg = pi.LastPaymentError.Msg
		resp.LastErrorCode = string(pi.LastPaymentError.Code)
	}
	return resp
}

func paymentIntentCreate(ctx context.Context, m api.Module, reqPtr, reqLen, respPtrOut, respLenOut uint32) uint32 {
	if reqLen == 0 {
		return 1
	}
	data, ok := m.Memory().Read(reqPtr, reqLen)
	if !ok {
		return 2
	}
	var req paymentIntentCreateRequest
	if err := msgpack.Unmarshal(data, &req); err != nil {
		return 3
	}
	if err := ensureConfigured(); err != nil {
		return 10
	}
	params := &stripe.PaymentIntentParams{
		Amount:   stripe.Int64(req.AmountCents),
		Currency: stripe.String(req.Currency),
	}
	if req.Description != "" {
		params.Description = stripe.String(req.Description)
	}
	if req.ReceiptEmail != "" {
		params.ReceiptEmail = stripe.String(req.ReceiptEmail)
	}
	if req.CaptureMethod != "" {
		params.CaptureMethod = stripe.String(req.CaptureMethod)
	}
	if len(req.PaymentMethodTypes) > 0 {
		params.PaymentMethodTypes = stripe.StringSlice(req.PaymentMethodTypes)
	}
	if req.Customer != "" {
		params.Customer = stripe.String(req.Customer)
	}
	for k, v := range req.Metadata {
		params.AddMetadata(k, v)
	}
	// AutomaticTax on PaymentIntents is configured via Stripe Dashboard
	// settings (tax.settings.defaults) rather than per-request params
	// in stripe-go v82+.
	if req.PromotionCodeID != "" {
		// Stamp the Stripe promotion code ID into metadata so the audit
		// trail on Stripe's side can tie this charge to a redemption. The
		// API doesn't accept a Discounts param on PaymentIntent directly
		// (only Checkout Sessions / Invoices do), so the caller has
		// already subtracted the discount; we record the linkage here.
		params.AddMetadata("stripe_promotion_code_id", req.PromotionCodeID)
	}
	if req.IdempotencyKey != "" {
		params.SetIdempotencyKey(req.IdempotencyKey)
	}
	pi, err := paymentintent.New(params)
	if err != nil {
		return 4
	}
	return writeMsgpackResponse(ctx, m, encodePaymentIntent(pi), respPtrOut, respLenOut)
}

func paymentIntentCapture(ctx context.Context, m api.Module, reqPtr, reqLen, respPtrOut, respLenOut uint32) uint32 {
	if reqLen == 0 {
		return 1
	}
	data, ok := m.Memory().Read(reqPtr, reqLen)
	if !ok {
		return 2
	}
	var req paymentIntentIDRequest
	if err := msgpack.Unmarshal(data, &req); err != nil {
		return 3
	}
	if err := ensureConfigured(); err != nil {
		return 10
	}
	params := &stripe.PaymentIntentCaptureParams{}
	if req.IdempotencyKey != "" {
		params.SetIdempotencyKey(req.IdempotencyKey)
	}
	pi, err := paymentintent.Capture(req.ID, params)
	if err != nil {
		return 4
	}
	return writeMsgpackResponse(ctx, m, encodePaymentIntent(pi), respPtrOut, respLenOut)
}

func paymentIntentCancel(ctx context.Context, m api.Module, reqPtr, reqLen, respPtrOut, respLenOut uint32) uint32 {
	if reqLen == 0 {
		return 1
	}
	data, ok := m.Memory().Read(reqPtr, reqLen)
	if !ok {
		return 2
	}
	var req paymentIntentIDRequest
	if err := msgpack.Unmarshal(data, &req); err != nil {
		return 3
	}
	if err := ensureConfigured(); err != nil {
		return 10
	}
	params := &stripe.PaymentIntentCancelParams{}
	if req.IdempotencyKey != "" {
		params.SetIdempotencyKey(req.IdempotencyKey)
	}
	pi, err := paymentintent.Cancel(req.ID, params)
	if err != nil {
		return 4
	}
	return writeMsgpackResponse(ctx, m, encodePaymentIntent(pi), respPtrOut, respLenOut)
}

func customerCreate(ctx context.Context, m api.Module, reqPtr, reqLen, respPtrOut, respLenOut uint32) uint32 {
	if reqLen == 0 {
		return 1
	}
	data, ok := m.Memory().Read(reqPtr, reqLen)
	if !ok {
		return 2
	}
	var req customerCreateRequest
	if err := msgpack.Unmarshal(data, &req); err != nil {
		return 3
	}
	if err := ensureConfigured(); err != nil {
		return 10
	}
	params := &stripe.CustomerParams{}
	if req.Email != "" {
		params.Email = stripe.String(req.Email)
	}
	if req.Name != "" {
		params.Name = stripe.String(req.Name)
	}
	if req.Description != "" {
		params.Description = stripe.String(req.Description)
	}
	for k, v := range req.Metadata {
		params.AddMetadata(k, v)
	}
	cust, err := customer.New(params)
	if err != nil {
		return 4
	}
	return writeMsgpackResponse(ctx, m, customerResponse{
		ID:    cust.ID,
		Email: cust.Email,
	}, respPtrOut, respLenOut)
}

func invoiceCreate(ctx context.Context, m api.Module, reqPtr, reqLen, respPtrOut, respLenOut uint32) uint32 {
	if reqLen == 0 {
		return 1
	}
	data, ok := m.Memory().Read(reqPtr, reqLen)
	if !ok {
		return 2
	}
	var req invoiceCreateRequest
	if err := msgpack.Unmarshal(data, &req); err != nil {
		return 3
	}
	if err := ensureConfigured(); err != nil {
		return 10
	}
	params := &stripe.InvoiceParams{
		Customer:    stripe.String(req.Customer),
		AutoAdvance: stripe.Bool(req.AutoAdvance),
	}
	if req.Description != "" {
		params.Description = stripe.String(req.Description)
	}
	if req.CollectionMethod != "" {
		params.CollectionMethod = stripe.String(req.CollectionMethod)
	}
	for k, v := range req.Metadata {
		params.AddMetadata(k, v)
	}
	if req.PromotionCodeID != "" {
		params.Discounts = []*stripe.InvoiceDiscountParams{
			{PromotionCode: stripe.String(req.PromotionCodeID)},
		}
	}
	inv, err := invoice.New(params)
	if err != nil {
		return 4
	}
	return writeMsgpackResponse(ctx, m, encodeInvoice(inv), respPtrOut, respLenOut)
}

func invoiceFinalize(ctx context.Context, m api.Module, reqPtr, reqLen, respPtrOut, respLenOut uint32) uint32 {
	if reqLen == 0 {
		return 1
	}
	data, ok := m.Memory().Read(reqPtr, reqLen)
	if !ok {
		return 2
	}
	var req invoiceIDRequest
	if err := msgpack.Unmarshal(data, &req); err != nil {
		return 3
	}
	if err := ensureConfigured(); err != nil {
		return 10
	}
	inv, err := invoice.FinalizeInvoice(req.ID, nil)
	if err != nil {
		return 4
	}
	return writeMsgpackResponse(ctx, m, encodeInvoice(inv), respPtrOut, respLenOut)
}

func invoiceMarkPaidOutOfBand(ctx context.Context, m api.Module, reqPtr, reqLen, respPtrOut, respLenOut uint32) uint32 {
	if reqLen == 0 {
		return 1
	}
	data, ok := m.Memory().Read(reqPtr, reqLen)
	if !ok {
		return 2
	}
	var req invoiceIDRequest
	if err := msgpack.Unmarshal(data, &req); err != nil {
		return 3
	}
	if err := ensureConfigured(); err != nil {
		return 10
	}
	params := &stripe.InvoicePayParams{
		PaidOutOfBand: stripe.Bool(true),
	}
	inv, err := invoice.Pay(req.ID, params)
	if err != nil {
		return 4
	}
	return writeMsgpackResponse(ctx, m, encodeInvoice(inv), respPtrOut, respLenOut)
}

func encodeInvoice(inv *stripe.Invoice) invoiceResponse {
	resp := invoiceResponse{
		ID:            inv.ID,
		Status:        string(inv.Status),
		HostedInvoice: inv.HostedInvoiceURL,
		InvoicePDF:    inv.InvoicePDF,
		AmountDue:     inv.AmountDue,
		AmountPaid:    inv.AmountPaid,
	}
	return resp
}

func invoiceItemCreate(ctx context.Context, m api.Module, reqPtr, reqLen, respPtrOut, respLenOut uint32) uint32 {
	if reqLen == 0 {
		return 1
	}
	data, ok := m.Memory().Read(reqPtr, reqLen)
	if !ok {
		return 2
	}
	var req invoiceItemCreateRequest
	if err := msgpack.Unmarshal(data, &req); err != nil {
		return 3
	}
	if err := ensureConfigured(); err != nil {
		return 10
	}
	params := &stripe.InvoiceItemParams{
		Customer: stripe.String(req.Customer),
		Amount:   stripe.Int64(req.AmountCents),
		Currency: stripe.String(req.Currency),
	}
	if req.Invoice != "" {
		params.Invoice = stripe.String(req.Invoice)
	}
	if req.Description != "" {
		params.Description = stripe.String(req.Description)
	}
	item, err := invoiceitem.New(params)
	if err != nil {
		return 4
	}
	return writeMsgpackResponse(ctx, m, invoiceItemResponse{ID: item.ID}, respPtrOut, respLenOut)
}

func balanceGet(ctx context.Context, m api.Module, reqPtr, reqLen, respPtrOut, respLenOut uint32) uint32 {
	_ = reqPtr
	_ = reqLen
	if err := ensureConfigured(); err != nil {
		return 10
	}
	bal, err := balance.Get(nil)
	if err != nil {
		return 4
	}
	resp := balanceResponse{}
	for _, a := range bal.Available {
		resp.Available = append(resp.Available, balanceAmount{Amount: a.Amount, Currency: string(a.Currency)})
	}
	for _, a := range bal.Pending {
		resp.Pending = append(resp.Pending, balanceAmount{Amount: a.Amount, Currency: string(a.Currency)})
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
	for k, v := range req.Metadata {
		params.AddMetadata(k, v)
	}
	if req.IdempotencyKey != "" {
		params.SetIdempotencyKey(req.IdempotencyKey)
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

// ---- coupon + promotion code request/response types ---------------------
//
// Stripe-native Coupon + PromotionCode replace the local SQLite coupon /
// promo math. A Coupon defines the discount shape (amount_off or percent_off,
// duration, max redemptions). A PromotionCode is the customer-facing code
// that resolves to a Coupon — Coupons themselves are opaque IDs, so we
// always pair them.
//
// Lifecycle: createCoupon → createPromotionCode (carries the Coupon's ID +
// the customer-facing code string). At checkout the cell calls
// promotionCodeLookup(code) to validate + resolve to the Stripe ID.
// On admin-side deletion we don't delete the Coupon (Stripe disallows it
// once redemptions exist) — we set the PromotionCode's active=false via
// promotionCodeUpdate so it no longer resolves.

type couponCreateRequest struct {
	// AmountOffCents and PercentOff are mutually exclusive — exactly one
	// must be set. PercentOff is a whole-number 1..100 (Stripe rejects
	// fractional values with Decimal off).
	AmountOffCents int64             `msgpack:"amount_off_cents,omitempty"`
	PercentOff     float64           `msgpack:"percent_off,omitempty"`
	Currency       string            `msgpack:"currency,omitempty"`
	Duration       string            `msgpack:"duration"` // "once", "repeating", "forever"
	DurationMonths int               `msgpack:"duration_months,omitempty"`
	MaxRedemptions int               `msgpack:"max_redemptions,omitempty"`
	RedeemBy       int64             `msgpack:"redeem_by,omitempty"` // unix seconds
	Name           string            `msgpack:"name,omitempty"`
	Metadata       map[string]string `msgpack:"metadata,omitempty"`
	// IdempotencyKey — forwarded to Stripe's Idempotency-Key header so a
	// retried Coupon create returns the original record. Lets callers pair
	// (couponID+":stripe-coupon", couponID+":stripe-promo") across the
	// two-step Coupon+PromotionCode flow for retry-safe upserts.
	IdempotencyKey string `msgpack:"idempotency_key,omitempty"`
}

type couponResponse struct {
	ID         string `msgpack:"id"`
	Valid      bool   `msgpack:"valid"`
	AmountOff  int64  `msgpack:"amount_off,omitempty"`
	PercentOff float64 `msgpack:"percent_off,omitempty"`
	Currency   string `msgpack:"currency,omitempty"`
	Duration   string `msgpack:"duration,omitempty"`
}

type promotionCodeCreateRequest struct {
	CouponID       string            `msgpack:"coupon_id"`
	Code           string            `msgpack:"code,omitempty"`
	Active         bool              `msgpack:"active,omitempty"`
	MaxRedemptions int               `msgpack:"max_redemptions,omitempty"`
	ExpiresAt      int64             `msgpack:"expires_at,omitempty"` // unix seconds
	Customer       string            `msgpack:"customer,omitempty"`
	Metadata       map[string]string `msgpack:"metadata,omitempty"`
	// IdempotencyKey — forwarded as Stripe's Idempotency-Key header so a
	// retried PromotionCode create after a partial-failure orphan returns
	// the original record rather than minting a duplicate.
	IdempotencyKey string `msgpack:"idempotency_key,omitempty"`
}

type promotionCodeLookupRequest struct {
	Code string `msgpack:"code"`
}

type promotionCodeUpdateRequest struct {
	ID     string `msgpack:"id"`
	Active bool   `msgpack:"active"`
}

type promotionCodeResponse struct {
	ID             string `msgpack:"id"`
	Code           string `msgpack:"code"`
	CouponID       string `msgpack:"coupon_id"`
	Active         bool   `msgpack:"active"`
	MaxRedemptions int64  `msgpack:"max_redemptions,omitempty"`
	TimesRedeemed  int64  `msgpack:"times_redeemed"`
	ExpiresAt      int64  `msgpack:"expires_at,omitempty"`
	// Coupon snapshot fields (mirrored on the PromotionCode object) — saves
	// the cell from a second roundtrip when validating a redemption.
	AmountOff  int64   `msgpack:"amount_off,omitempty"`
	PercentOff float64 `msgpack:"percent_off,omitempty"`
	Currency   string  `msgpack:"currency,omitempty"`
}

// ---- coupon + promotion code handlers -----------------------------------

func couponCreate(ctx context.Context, m api.Module, reqPtr, reqLen, respPtrOut, respLenOut uint32) uint32 {
	if reqLen == 0 {
		return 1
	}
	data, ok := m.Memory().Read(reqPtr, reqLen)
	if !ok {
		return 2
	}
	var req couponCreateRequest
	if err := msgpack.Unmarshal(data, &req); err != nil {
		return 3
	}
	if err := ensureConfigured(); err != nil {
		return 10
	}
	params := &stripe.CouponParams{}
	if req.AmountOffCents > 0 {
		params.AmountOff = stripe.Int64(req.AmountOffCents)
		if req.Currency != "" {
			params.Currency = stripe.String(req.Currency)
		} else {
			params.Currency = stripe.String("usd")
		}
	} else if req.PercentOff > 0 {
		params.PercentOff = stripe.Float64(req.PercentOff)
	}
	if req.Duration != "" {
		params.Duration = stripe.String(req.Duration)
	} else {
		params.Duration = stripe.String(string(stripe.CouponDurationOnce))
	}
	if req.DurationMonths > 0 {
		params.DurationInMonths = stripe.Int64(int64(req.DurationMonths))
	}
	if req.MaxRedemptions > 0 {
		params.MaxRedemptions = stripe.Int64(int64(req.MaxRedemptions))
	}
	if req.RedeemBy > 0 {
		params.RedeemBy = stripe.Int64(req.RedeemBy)
	}
	if req.Name != "" {
		params.Name = stripe.String(req.Name)
	}
	for k, v := range req.Metadata {
		params.AddMetadata(k, v)
	}
	if req.IdempotencyKey != "" {
		params.SetIdempotencyKey(req.IdempotencyKey)
	}
	cp, err := coupon.New(params)
	if err != nil {
		return 4
	}
	resp := couponResponse{
		ID:       cp.ID,
		Valid:    cp.Valid,
		Duration: string(cp.Duration),
	}
	if cp.AmountOff > 0 {
		resp.AmountOff = cp.AmountOff
		resp.Currency = string(cp.Currency)
	}
	if cp.PercentOff > 0 {
		resp.PercentOff = cp.PercentOff
	}
	return writeMsgpackResponse(ctx, m, resp, respPtrOut, respLenOut)
}

func promotionCodeCreate(ctx context.Context, m api.Module, reqPtr, reqLen, respPtrOut, respLenOut uint32) uint32 {
	if reqLen == 0 {
		return 1
	}
	data, ok := m.Memory().Read(reqPtr, reqLen)
	if !ok {
		return 2
	}
	var req promotionCodeCreateRequest
	if err := msgpack.Unmarshal(data, &req); err != nil {
		return 3
	}
	if err := ensureConfigured(); err != nil {
		return 10
	}
	if req.CouponID == "" {
		return 3
	}
	params := &stripe.PromotionCodeParams{
		Coupon: stripe.String(req.CouponID),
	}
	if req.Code != "" {
		params.Code = stripe.String(req.Code)
	}
	// Active defaults to true on Stripe's side; honor the request only
	// when explicitly false (the request shape carries the bool, so an
	// unset value decodes to false — but the typical path is "true").
	params.Active = stripe.Bool(req.Active)
	if req.MaxRedemptions > 0 {
		params.MaxRedemptions = stripe.Int64(int64(req.MaxRedemptions))
	}
	if req.ExpiresAt > 0 {
		params.ExpiresAt = stripe.Int64(req.ExpiresAt)
	}
	if req.Customer != "" {
		params.Customer = stripe.String(req.Customer)
	}
	for k, v := range req.Metadata {
		params.AddMetadata(k, v)
	}
	if req.IdempotencyKey != "" {
		params.SetIdempotencyKey(req.IdempotencyKey)
	}
	pc, err := promotioncode.New(params)
	if err != nil {
		return 4
	}
	return writeMsgpackResponse(ctx, m, encodePromotionCode(pc), respPtrOut, respLenOut)
}

func promotionCodeLookup(ctx context.Context, m api.Module, reqPtr, reqLen, respPtrOut, respLenOut uint32) uint32 {
	if reqLen == 0 {
		return 1
	}
	data, ok := m.Memory().Read(reqPtr, reqLen)
	if !ok {
		return 2
	}
	var req promotionCodeLookupRequest
	if err := msgpack.Unmarshal(data, &req); err != nil {
		return 3
	}
	if err := ensureConfigured(); err != nil {
		return 10
	}
	if req.Code == "" {
		return 3
	}
	// PromotionCode List filtered by code — Stripe's lookup by code uses
	// the list endpoint with a code filter (there's no GET-by-code).
	params := &stripe.PromotionCodeListParams{
		Code: stripe.String(req.Code),
	}
	params.Limit = stripe.Int64(1)
	it := promotioncode.List(params)
	if !it.Next() {
		if err := it.Err(); err != nil {
			return 4
		}
		// Not found — return empty response with code 0; cell side checks
		// resp.ID == "".
		return writeMsgpackResponse(ctx, m, promotionCodeResponse{}, respPtrOut, respLenOut)
	}
	pc := it.PromotionCode()
	return writeMsgpackResponse(ctx, m, encodePromotionCode(pc), respPtrOut, respLenOut)
}

func promotionCodeUpdate(ctx context.Context, m api.Module, reqPtr, reqLen, respPtrOut, respLenOut uint32) uint32 {
	if reqLen == 0 {
		return 1
	}
	data, ok := m.Memory().Read(reqPtr, reqLen)
	if !ok {
		return 2
	}
	var req promotionCodeUpdateRequest
	if err := msgpack.Unmarshal(data, &req); err != nil {
		return 3
	}
	if err := ensureConfigured(); err != nil {
		return 10
	}
	if req.ID == "" {
		return 3
	}
	params := &stripe.PromotionCodeParams{
		Active: stripe.Bool(req.Active),
	}
	pc, err := promotioncode.Update(req.ID, params)
	if err != nil {
		return 4
	}
	return writeMsgpackResponse(ctx, m, encodePromotionCode(pc), respPtrOut, respLenOut)
}

func encodePromotionCode(pc *stripe.PromotionCode) promotionCodeResponse {
	resp := promotionCodeResponse{
		ID:             pc.ID,
		Code:           pc.Code,
		Active:         pc.Active,
		MaxRedemptions: pc.MaxRedemptions,
		TimesRedeemed:  pc.TimesRedeemed,
		ExpiresAt:      pc.ExpiresAt,
	}
	if pc.Coupon != nil {
		resp.CouponID = pc.Coupon.ID
		if pc.Coupon.AmountOff > 0 {
			resp.AmountOff = pc.Coupon.AmountOff
			resp.Currency = string(pc.Coupon.Currency)
		}
		if pc.Coupon.PercentOff > 0 {
			resp.PercentOff = pc.Coupon.PercentOff
		}
	}
	return resp
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
