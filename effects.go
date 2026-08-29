package stripeext

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/BananaLabs-OSS/Fiber/pulp/effect"
	"github.com/BananaLabs-OSS/Pulp/ext"
	"github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/checkout/session"
	"github.com/stripe/stripe-go/v82/coupon"
	"github.com/stripe/stripe-go/v82/customer"
	"github.com/stripe/stripe-go/v82/invoice"
	"github.com/stripe/stripe-go/v82/invoiceitem"
	"github.com/stripe/stripe-go/v82/paymentintent"
	"github.com/stripe/stripe-go/v82/promotioncode"
	"github.com/stripe/stripe-go/v82/refund"
	"github.com/stripe/stripe-go/v82/setupintent"
	"github.com/vmihailenco/msgpack/v5"
)

// ErrStripeHostEffectDenied is returned when a cell attempts to use the
// narrow host-effect ABI for a Stripe operation it does not own. In
// particular, application sequencing (Checkout and the compound free-invoice
// flow) never crosses this import.
var ErrStripeHostEffectDenied = errors.New("stripe effect: kind is not admitted by effect.stripe.runtime")

// EffectKind identifies a durable, host-owned Stripe action. Only these
// actions can be executed by Executor; arbitrary Stripe calls are not an
// outbox contract.
type EffectKind string

const (
	EffectPaymentIntentCreate   EffectKind = "payment_intent.create"
	EffectCheckoutSessionCreate EffectKind = "checkout_session.create"
	EffectSetupIntentCreate     EffectKind = "setup_intent.create"
	EffectRefundCreate          EffectKind = "refund.create"
)

var (
	ErrUnsupportedEffect   = errors.New("stripe effect: unsupported kind")
	ErrInvalidEffect       = errors.New("stripe effect: invalid request")
	ErrIdempotencyConflict = errors.New("stripe effect: idempotency key reused with different effect")
	ErrFreeInvoiceNotZero  = errors.New("stripe effect: free invoice amount_due is not zero")
)

// Effect is a durable commerce outbox entry. Payload is JSON, deliberately a
// string so the outbox can persist and replay it without depending on Go or
// WASM object layouts. IdempotencyKey must be the stable, globally unique key
// assigned by the outbox (for example its immutable row ID), not an attempt ID.
type Effect struct {
	Kind           EffectKind `json:"kind"`
	IdempotencyKey string     `json:"idempotency_key"`
	Payload        string     `json:"payload"`
}

// EffectResult is the serializable, stable result returned to the outbox. The
// fields intentionally cover both browser and off-session payment flows:
// PaymentIntent and ClientSecret are populated by PaymentIntent creation, and
// CheckoutSession / CheckoutURL by hosted Checkout creation.
type EffectResult struct {
	Kind            EffectKind `json:"kind" msgpack:"kind"`
	IdempotencyKey  string     `json:"idempotency_key" msgpack:"idempotency_key"`
	PaymentIntent   string     `json:"payment_intent,omitempty" msgpack:"payment_intent,omitempty"`
	ClientSecret    string     `json:"client_secret,omitempty" msgpack:"client_secret,omitempty"`
	CheckoutSession string     `json:"checkout_session,omitempty" msgpack:"checkout_session,omitempty"`
	CheckoutURL     string     `json:"checkout_url,omitempty" msgpack:"checkout_url,omitempty"`
	SetupIntent     string     `json:"setup_intent,omitempty" msgpack:"setup_intent,omitempty"`
	Refund          string     `json:"refund,omitempty" msgpack:"refund,omitempty"`
	Status          string     `json:"status,omitempty" msgpack:"status,omitempty"`
}

// PaymentIntentEffectPayload is the JSON payload for
// EffectPaymentIntentCreate.
type PaymentIntentEffectPayload struct {
	AmountCents        int64             `json:"amount_cents"`
	Currency           string            `json:"currency"`
	Description        string            `json:"description,omitempty"`
	ReceiptEmail       string            `json:"receipt_email,omitempty"`
	CaptureMethod      string            `json:"capture_method,omitempty"`
	PaymentMethodTypes []string          `json:"payment_method_types,omitempty"`
	Customer           string            `json:"customer,omitempty"`
	Metadata           map[string]string `json:"metadata,omitempty"`
	PaymentMethod      string            `json:"payment_method,omitempty"`
	OffSession         bool              `json:"off_session,omitempty"`
	Confirm            bool              `json:"confirm,omitempty"`
	PromotionCodeID    string            `json:"promotion_code_id,omitempty"`
}

// CheckoutSessionEffectPayload is the JSON payload for
// EffectCheckoutSessionCreate.
type CheckoutSessionEffectPayload struct {
	AmountCents        int64             `json:"amount_cents"`
	Currency           string            `json:"currency"`
	SuccessURL         string            `json:"success_url"`
	CancelURL          string            `json:"cancel_url"`
	ProductName        string            `json:"product_name"`
	ProductDescription string            `json:"product_description,omitempty"`
	Metadata           map[string]string `json:"metadata,omitempty"`
	AutomaticTax       bool              `json:"automatic_tax,omitempty"`
}

// SetupIntentEffectPayload is the JSON payload for
// EffectSetupIntentCreate.
type SetupIntentEffectPayload struct {
	Customer           string            `json:"customer,omitempty"`
	Usage              string            `json:"usage,omitempty"`
	PaymentMethodTypes []string          `json:"payment_method_types,omitempty"`
	Metadata           map[string]string `json:"metadata,omitempty"`
}

// RefundEffectPayload is the JSON payload for EffectRefundCreate. A nil
// AmountCents asks Stripe for its documented full refund; an explicit zero or
// negative amount is rejected.
type RefundEffectPayload struct {
	PaymentIntent string            `json:"payment_intent"`
	AmountCents   *int64            `json:"amount_cents,omitempty"`
	Reason        string            `json:"reason,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// EffectClient is the small, fakeable Stripe boundary. The executor supplies
// the exact stable IdempotencyKey to every mutating operation. Implementations
// must forward it to Stripe's Idempotency-Key request header unchanged.
type EffectClient interface {
	CreatePaymentIntent(context.Context, PaymentIntentEffectPayload, string) (EffectResult, error)
	CreateCheckoutSession(context.Context, CheckoutSessionEffectPayload, string) (EffectResult, error)
	CreateSetupIntent(context.Context, SetupIntentEffectPayload, string) (EffectResult, error)
	GetSetupIntent(context.Context, effect.StripeSetupIntentGetPayload) (effect.StripeSetupIntentGetResult, error)
	GetPaymentIntent(context.Context, effect.StripePaymentIntentGetPayload) (effect.StripePaymentIntentGetResult, error)
	CreateRefund(context.Context, RefundEffectPayload, string) (EffectResult, error)
	CapturePaymentIntent(context.Context, effect.StripePaymentIntentCapturePayload, string) (effect.StripePaymentIntentMutationResult, error)
	CancelPaymentIntent(context.Context, effect.StripePaymentIntentCancelPayload, string) (effect.StripePaymentIntentMutationResult, error)
	CreateCustomer(context.Context, effect.StripeCustomerCreatePayload, string) (effect.StripeCustomerCreateResult, error)
	CreateInvoiceItem(context.Context, effect.StripeInvoiceItemCreatePayload, string) (effect.StripeInvoiceItemCreateResult, error)
	CreateInvoice(context.Context, effect.StripeInvoiceCreatePayload, string) (effect.StripeInvoiceResult, error)
	FinalizeInvoice(context.Context, effect.StripeInvoiceFinalizePayload, string) (effect.StripeInvoiceResult, error)
	MarkInvoicePaid(context.Context, effect.StripeInvoiceMarkPaidPayload, string) (effect.StripeInvoiceResult, error)
	CreateFreeInvoiceItem(context.Context, string, effect.StripeFreeInvoiceItem, string) (string, error)
	CreateFreeInvoice(context.Context, string, effect.StripeFreeInvoice, string) (invoiceEffectResult, error)
	FinalizeFreeInvoice(context.Context, string, string) (invoiceEffectResult, error)
	MarkFreeInvoicePaid(context.Context, string, string) (invoiceEffectResult, error)
	UpsertCoupon(context.Context, effect.StripeCouponUpsertPayload, string) (effect.StripeCouponUpsertResult, error)
	DeleteCoupon(context.Context, effect.StripeCouponDeletePayload, string) (effect.StripeCouponDeleteResult, error)
	UpsertPromotionCode(context.Context, effect.StripePromotionCodeUpsertPayload, string) (effect.StripePromotionCodeUpsertResult, error)
	DeactivatePromotionCode(context.Context, effect.StripePromotionCodeDeactivatePayload, string) (effect.StripePromotionCodeDeactivateResult, error)
}

type invoiceEffectResult struct {
	ID               string
	Status           string
	HostedInvoiceURL string
	InvoicePDF       string
	AmountDue        int64
	AmountPaid       int64
}

// EffectLimits are host-side safety ceilings held by one executor instance.
// A limit of zero means no ceiling, matching the established extension policy.
type EffectLimits struct {
	MaxChargeCents int64
	MaxRefundCents int64
}

// Executor is the host-owned Stripe outbox boundary. It retains completed
// results only for the lifetime of one host instance; Stripe's stable
// Idempotency-Key remains the durable replay protection across restarts.
type Executor struct {
	client EffectClient
	limits EffectLimits

	mu      sync.Mutex
	replays map[string]replay
	closed  bool

	canonicalReplays map[string]canonicalReplay
	canonicalClaims  map[string]string
	compoundProgress map[string]*freeInvoiceProgress
}

type replay struct {
	fingerprint string
	result      EffectResult
}

type canonicalReplay struct {
	fingerprint string
	result      msgpack.RawMessage
}

type freeInvoiceProgress struct {
	fingerprint   string
	customer      *effect.StripeCustomerCreateResult
	invoiceItemID string
	invoice       *invoiceEffectResult
	finalized     *invoiceEffectResult
	paid          *invoiceEffectResult
}

// NewExecutor constructs one independently owned executor. Passing a nil
// client is permitted for wiring tests but every Execute will fail safely.
func NewExecutor(client EffectClient, limits EffectLimits) *Executor {
	return &Executor{
		client: client, limits: limits,
		replays:          make(map[string]replay),
		canonicalReplays: make(map[string]canonicalReplay),
		canonicalClaims:  make(map[string]string),
		compoundProgress: make(map[string]*freeInvoiceProgress),
	}
}

// Execute validates and runs one effect. Replaying the same kind, stable key,
// and payload returns the original result without another client call. Reusing
// a key with different content is refused locally before it reaches Stripe.
func (e *Executor) Execute(ctx context.Context, effect Effect) (EffectResult, error) {
	if err := validateEffect(effect); err != nil {
		return EffectResult{}, err
	}
	if e == nil || e.client == nil {
		return EffectResult{}, fmt.Errorf("%w: executor client is not configured", ErrInvalidEffect)
	}
	kind, err := normalizeExecutorKind(effect.Kind)
	if err != nil {
		return EffectResult{}, err
	}
	effect.Kind = kind

	// The outbox key is globally unique across effect kinds. Keeping it as the
	// sole replay key catches accidental reuse for a different Stripe endpoint
	// before it can become an ambiguous Stripe-side retry.
	key := effect.IdempotencyKey
	fingerprint := effectFingerprint(effect)

	// The lock intentionally covers the client call. It gives concurrent
	// dequeuers at-most-once execution within this host, while Stripe's
	// Idempotency-Key handles process crashes and cross-host retries.
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return EffectResult{}, errStripeRuntimeClosed
	}
	if _, ok := e.canonicalClaims[key]; ok {
		return EffectResult{}, ErrIdempotencyConflict
	}
	if prior, ok := e.replays[key]; ok {
		if prior.fingerprint != fingerprint {
			return EffectResult{}, ErrIdempotencyConflict
		}
		return prior.result, nil
	}

	result, err := e.execute(ctx, effect)
	if err != nil {
		return EffectResult{}, err
	}
	result.Kind = effect.Kind
	result.IdempotencyKey = effect.IdempotencyKey
	e.replays[key] = replay{fingerprint: fingerprint, result: result}
	return result, nil
}

func (e *Executor) close() {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.closed = true
	e.mu.Unlock()
}

// ExecuteIntent runs Fiber's canonical pulp.effect.v1 envelope and returns a
// receipt bound to the normalized intent. Supported legacy kind aliases are
// normalized before they enter the replay cache, so alias and canonical
// replays converge on one Stripe request and one result.
func (e *Executor) ExecuteIntent(ctx context.Context, intent effect.Intent) (effect.Receipt, error) {
	normalized := intent
	if err := normalized.Normalize(); err != nil {
		return effect.Receipt{}, err
	}
	switch normalized.Kind {
	case effect.KindStripePaymentIntentCapture,
		effect.KindStripePaymentIntentCancel,
		effect.KindStripePaymentIntentGet,
		effect.KindStripeSetupIntentGet,
		effect.KindStripeCustomerCreate,
		effect.KindStripeInvoiceItemCreate,
		effect.KindStripeInvoiceCreate,
		effect.KindStripeInvoiceFinalize,
		effect.KindStripeInvoiceMarkPaid,
		effect.KindStripeFreeInvoiceFinalize,
		effect.KindStripeCouponUpsert,
		effect.KindStripeCouponDelete,
		effect.KindStripePromotionCodeUpsert,
		effect.KindStripePromotionCodeDeactivate:
		return e.executeCanonicalIntent(ctx, normalized)
	}
	legacy, err := executorEffectFromIntent(normalized)
	if err != nil {
		return effect.Receipt{}, err
	}
	result, err := e.Execute(ctx, legacy)
	if err != nil {
		return effect.Receipt{}, err
	}
	result.Kind = EffectKind(normalized.Kind)
	return effect.NewCompletedReceipt(normalized, result)
}

func (e *Executor) executeCanonicalIntent(ctx context.Context, intent effect.Intent) (effect.Receipt, error) {
	if e == nil || e.client == nil {
		return effect.Receipt{}, fmt.Errorf("%w: executor client is not configured", ErrInvalidEffect)
	}
	fingerprint := canonicalEffectFingerprint(intent)

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return effect.Receipt{}, errStripeRuntimeClosed
	}
	if prior, ok := e.replays[intent.IdempotencyKey]; ok {
		_ = prior
		return effect.Receipt{}, ErrIdempotencyConflict
	}
	if claim, ok := e.canonicalClaims[intent.IdempotencyKey]; ok {
		if claim != fingerprint {
			return effect.Receipt{}, ErrIdempotencyConflict
		}
	} else {
		e.canonicalClaims[intent.IdempotencyKey] = fingerprint
	}
	if prior, ok := e.canonicalReplays[intent.IdempotencyKey]; ok {
		if prior.fingerprint != fingerprint {
			return effect.Receipt{}, ErrIdempotencyConflict
		}
		return completedReceiptFromRaw(intent, prior.result)
	}
	if progress, ok := e.compoundProgress[intent.IdempotencyKey]; ok && progress.fingerprint != fingerprint {
		return effect.Receipt{}, ErrIdempotencyConflict
	}

	var result any
	switch intent.Kind {
	case effect.KindStripePaymentIntentGet:
		payload, err := effect.DecodePayload[effect.StripePaymentIntentGetPayload](intent)
		if err != nil {
			return effect.Receipt{}, err
		}
		result, err = e.client.GetPaymentIntent(ctx, payload)
		if err != nil {
			return effect.Receipt{}, err
		}
	case effect.KindStripeSetupIntentGet:
		payload, err := effect.DecodePayload[effect.StripeSetupIntentGetPayload](intent)
		if err != nil {
			return effect.Receipt{}, err
		}
		result, err = e.client.GetSetupIntent(ctx, payload)
		if err != nil {
			return effect.Receipt{}, err
		}
	case effect.KindStripePaymentIntentCapture:
		payload, err := effect.DecodePayload[effect.StripePaymentIntentCapturePayload](intent)
		if err != nil {
			return effect.Receipt{}, err
		}
		result, err = e.client.CapturePaymentIntent(ctx, payload, intent.IdempotencyKey)
		if err != nil {
			return effect.Receipt{}, err
		}
	case effect.KindStripePaymentIntentCancel:
		payload, err := effect.DecodePayload[effect.StripePaymentIntentCancelPayload](intent)
		if err != nil {
			return effect.Receipt{}, err
		}
		result, err = e.client.CancelPaymentIntent(ctx, payload, intent.IdempotencyKey)
		if err != nil {
			return effect.Receipt{}, err
		}
	case effect.KindStripeCustomerCreate:
		payload, err := effect.DecodePayload[effect.StripeCustomerCreatePayload](intent)
		if err != nil {
			return effect.Receipt{}, err
		}
		result, err = e.client.CreateCustomer(ctx, payload, intent.IdempotencyKey)
		if err != nil {
			return effect.Receipt{}, err
		}
	case effect.KindStripeInvoiceItemCreate:
		payload, err := effect.DecodePayload[effect.StripeInvoiceItemCreatePayload](intent)
		if err != nil {
			return effect.Receipt{}, err
		}
		result, err = e.client.CreateInvoiceItem(ctx, payload, intent.IdempotencyKey)
		if err != nil {
			return effect.Receipt{}, err
		}
	case effect.KindStripeInvoiceCreate:
		payload, err := effect.DecodePayload[effect.StripeInvoiceCreatePayload](intent)
		if err != nil {
			return effect.Receipt{}, err
		}
		result, err = e.client.CreateInvoice(ctx, payload, intent.IdempotencyKey)
		if err != nil {
			return effect.Receipt{}, err
		}
	case effect.KindStripeInvoiceFinalize:
		payload, err := effect.DecodePayload[effect.StripeInvoiceFinalizePayload](intent)
		if err != nil {
			return effect.Receipt{}, err
		}
		result, err = e.client.FinalizeInvoice(ctx, payload, intent.IdempotencyKey)
		if err != nil {
			return effect.Receipt{}, err
		}
	case effect.KindStripeInvoiceMarkPaid:
		payload, err := effect.DecodePayload[effect.StripeInvoiceMarkPaidPayload](intent)
		if err != nil {
			return effect.Receipt{}, err
		}
		result, err = e.client.MarkInvoicePaid(ctx, payload, intent.IdempotencyKey)
		if err != nil {
			return effect.Receipt{}, err
		}
	case effect.KindStripeFreeInvoiceFinalize:
		payload, err := effect.DecodePayload[effect.StripeFreeInvoiceFinalizePayload](intent)
		if err != nil {
			return effect.Receipt{}, err
		}
		result, err = e.executeFreeInvoice(ctx, intent.IdempotencyKey, fingerprint, payload)
		if err != nil {
			return effect.Receipt{}, err
		}
	case effect.KindStripeCouponUpsert:
		payload, err := effect.DecodePayload[effect.StripeCouponUpsertPayload](intent)
		if err != nil {
			return effect.Receipt{}, err
		}
		result, err = e.client.UpsertCoupon(ctx, payload, intent.IdempotencyKey)
		if err != nil {
			return effect.Receipt{}, err
		}
	case effect.KindStripeCouponDelete:
		payload, err := effect.DecodePayload[effect.StripeCouponDeletePayload](intent)
		if err != nil {
			return effect.Receipt{}, err
		}
		result, err = e.client.DeleteCoupon(ctx, payload, intent.IdempotencyKey)
		if err != nil {
			return effect.Receipt{}, err
		}
	case effect.KindStripePromotionCodeUpsert:
		payload, err := effect.DecodePayload[effect.StripePromotionCodeUpsertPayload](intent)
		if err != nil {
			return effect.Receipt{}, err
		}
		result, err = e.client.UpsertPromotionCode(ctx, payload, intent.IdempotencyKey)
		if err != nil {
			return effect.Receipt{}, err
		}
	case effect.KindStripePromotionCodeDeactivate:
		payload, err := effect.DecodePayload[effect.StripePromotionCodeDeactivatePayload](intent)
		if err != nil {
			return effect.Receipt{}, err
		}
		result, err = e.client.DeactivatePromotionCode(ctx, payload, intent.IdempotencyKey)
		if err != nil {
			return effect.Receipt{}, err
		}
	default:
		return effect.Receipt{}, fmt.Errorf("%w: %q", ErrUnsupportedEffect, intent.Kind)
	}

	receipt, err := effect.NewCompletedReceipt(intent, result)
	if err != nil {
		return effect.Receipt{}, err
	}
	e.canonicalReplays[intent.IdempotencyKey] = canonicalReplay{
		fingerprint: fingerprint,
		result:      append(msgpack.RawMessage(nil), receipt.Result...),
	}
	if intent.Kind == effect.KindStripeFreeInvoiceFinalize {
		delete(e.compoundProgress, intent.IdempotencyKey)
	}
	return receipt, nil
}

func (e *Executor) executeFreeInvoice(
	ctx context.Context,
	parentKey string,
	fingerprint string,
	payload effect.StripeFreeInvoiceFinalizePayload,
) (effect.StripeFreeInvoiceFinalizeResult, error) {
	progress := e.compoundProgress[parentKey]
	if progress == nil {
		progress = &freeInvoiceProgress{fingerprint: fingerprint}
		e.compoundProgress[parentKey] = progress
	}

	if progress.customer == nil {
		customerResult, err := e.client.CreateCustomer(ctx, payload.Customer, derivedStripeKey(parentKey, ":customer"))
		if err != nil {
			return effect.StripeFreeInvoiceFinalizeResult{}, err
		}
		progress.customer = &customerResult
	}
	if progress.invoiceItemID == "" {
		itemID, err := e.client.CreateFreeInvoiceItem(
			ctx, progress.customer.CustomerID, payload.InvoiceItem, derivedStripeKey(parentKey, ":item"),
		)
		if err != nil {
			return effect.StripeFreeInvoiceFinalizeResult{}, err
		}
		progress.invoiceItemID = itemID
	}
	if progress.invoice == nil {
		invoiceResult, err := e.client.CreateFreeInvoice(
			ctx, progress.customer.CustomerID, payload.Invoice, derivedStripeKey(parentKey, ":invoice"),
		)
		if err != nil {
			return effect.StripeFreeInvoiceFinalizeResult{}, err
		}
		progress.invoice = &invoiceResult
	}
	if progress.finalized == nil {
		finalized, err := e.client.FinalizeFreeInvoice(
			ctx, progress.invoice.ID, derivedStripeKey(parentKey, ":finalize"),
		)
		if err != nil {
			return effect.StripeFreeInvoiceFinalizeResult{}, err
		}
		progress.finalized = &finalized
	}
	if progress.finalized.AmountDue != 0 {
		return effect.StripeFreeInvoiceFinalizeResult{}, fmt.Errorf(
			"%w: invoice %s amount_due=%d", ErrFreeInvoiceNotZero,
			progress.finalized.ID, progress.finalized.AmountDue,
		)
	}
	if progress.paid == nil {
		paid, err := e.client.MarkFreeInvoicePaid(
			ctx, progress.finalized.ID, derivedStripeKey(parentKey, ":paid"),
		)
		if err != nil {
			return effect.StripeFreeInvoiceFinalizeResult{}, err
		}
		progress.paid = &paid
	}
	if progress.paid.AmountDue != 0 {
		return effect.StripeFreeInvoiceFinalizeResult{}, fmt.Errorf(
			"%w: invoice %s amount_due=%d", ErrFreeInvoiceNotZero,
			progress.paid.ID, progress.paid.AmountDue,
		)
	}
	return effect.StripeFreeInvoiceFinalizeResult{
		CustomerID:       progress.customer.CustomerID,
		InvoiceItemID:    progress.invoiceItemID,
		InvoiceID:        progress.paid.ID,
		Status:           progress.paid.Status,
		HostedInvoiceURL: progress.paid.HostedInvoiceURL,
		InvoicePDF:       progress.paid.InvoicePDF,
		AmountDue:        progress.paid.AmountDue,
		AmountPaid:       progress.paid.AmountPaid,
	}, nil
}

func completedReceiptFromRaw(intent effect.Intent, result msgpack.RawMessage) (effect.Receipt, error) {
	receipt := effect.Receipt{
		Version: effect.VersionV1, IntentID: intent.ID, Kind: intent.Kind,
		IdempotencyKey: intent.IdempotencyKey, Status: effect.Completed,
		Result: append(msgpack.RawMessage(nil), result...),
	}
	if err := receipt.ValidateFor(intent); err != nil {
		return effect.Receipt{}, err
	}
	return receipt, nil
}

func canonicalEffectFingerprint(intent effect.Intent) string {
	sum := sha256.Sum256(append([]byte(intent.Kind+"\x00"), intent.Payload...))
	return hex.EncodeToString(sum[:])
}

func derivedStripeKey(parent, suffix string) string {
	candidate := parent + suffix
	if len(candidate) <= 255 {
		return candidate
	}
	sum := sha256.Sum256([]byte(parent))
	return "pulp:" + hex.EncodeToString(sum[:]) + suffix
}

// ExecuteIntentWire is the canonical MessagePack host boundary. It accepts
// Fiber's supported kind aliases on input and always emits a canonical v1
// Receipt wire.
func (e *Executor) ExecuteIntentWire(ctx context.Context, wire []byte) ([]byte, error) {
	intent, err := effect.UnmarshalIntent(wire)
	if err != nil {
		return nil, err
	}
	receipt, err := e.ExecuteIntent(ctx, intent)
	if err != nil {
		return nil, err
	}
	return effect.MarshalReceipt(receipt)
}

// ExecuteStripeIntentWire is the app-agnostic effect.stripe.runtime ABI. It
// rejects envelope riders, legacy aliases, and every non-unit Stripe effect
// before the executor can contact Stripe. The returned receipt is canonical
// and can be persisted verbatim by any state-owning application.
func (e *Executor) ExecuteStripeIntentWire(ctx context.Context, wire []byte) ([]byte, error) {
	intent, err := decodeStripeHostIntent(wire)
	if err != nil {
		return nil, err
	}
	receipt, err := e.ExecuteIntent(ctx, intent)
	if err != nil {
		return nil, err
	}
	if err := receipt.ValidateFor(intent); err != nil {
		return nil, fmt.Errorf("stripe host effect receipt: %w", err)
	}
	return effect.MarshalReceipt(receipt)
}

func decodeStripeHostIntent(wire []byte) (effect.Intent, error) {
	if len(wire) == 0 {
		return effect.Intent{}, fmt.Errorf("stripe host effect: empty intent")
	}
	var intent effect.Intent
	decoder := msgpack.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields(true)
	if err := decoder.Decode(&intent); err != nil {
		return effect.Intent{}, fmt.Errorf("stripe host effect: decode intent: %w", err)
	}
	// The host ABI deliberately does not normalize aliases: persisted effects
	// must be canonical before they leave a state owner.
	if err := intent.Validate(); err != nil {
		return effect.Intent{}, fmt.Errorf("stripe host effect: invalid intent: %w", err)
	}
	if !isStripeHostEffectKind(intent.Kind) {
		return effect.Intent{}, fmt.Errorf("%w: %q", ErrStripeHostEffectDenied, intent.Kind)
	}
	if err := validateStripeHostEffectPayload(intent); err != nil {
		return effect.Intent{}, err
	}
	return intent, nil
}

func validateStripeHostEffectPayload(intent effect.Intent) error {
	decode := func(value any) error {
		decoder := msgpack.NewDecoder(bytes.NewReader(intent.Payload))
		decoder.DisallowUnknownFields(true)
		if err := decoder.Decode(value); err != nil {
			return fmt.Errorf("stripe host effect: decode %s payload: %w", intent.Kind, err)
		}
		return nil
	}
	switch intent.Kind {
	case effect.KindStripePaymentIntentCreate:
		var payload paymentIntentCreateRequest
		if err := decode(&payload); err != nil {
			return err
		}
		if payload.IdempotencyKey != "" {
			return fmt.Errorf("stripe host effect: payment-intent payload must not carry idempotency_key")
		}
	case effect.KindStripeSetupIntentCreate:
		var payload setupIntentCreateRequest
		if err := decode(&payload); err != nil {
			return err
		}
		if payload.IdempotencyKey != "" {
			return fmt.Errorf("stripe host effect: setup-intent payload must not carry idempotency_key")
		}
	case effect.KindStripeRefundCreate:
		var payload refundCreateRequest
		if err := decode(&payload); err != nil {
			return err
		}
		if payload.IdempotencyKey != "" {
			return fmt.Errorf("stripe host effect: refund payload must not carry idempotency_key")
		}
	case effect.KindStripePaymentIntentGet:
		var payload effect.StripePaymentIntentGetPayload
		if err := decode(&payload); err != nil {
			return err
		}
	case effect.KindStripePaymentIntentCapture:
		var payload effect.StripePaymentIntentCapturePayload
		if err := decode(&payload); err != nil {
			return err
		}
	case effect.KindStripePaymentIntentCancel:
		var payload effect.StripePaymentIntentCancelPayload
		if err := decode(&payload); err != nil {
			return err
		}
	case effect.KindStripeSetupIntentGet:
		var payload effect.StripeSetupIntentGetPayload
		if err := decode(&payload); err != nil {
			return err
		}
	case effect.KindStripeCustomerCreate:
		var payload effect.StripeCustomerCreatePayload
		if err := decode(&payload); err != nil {
			return err
		}
	case effect.KindStripeInvoiceItemCreate:
		var payload effect.StripeInvoiceItemCreatePayload
		if err := decode(&payload); err != nil {
			return err
		}
	case effect.KindStripeInvoiceCreate:
		var payload effect.StripeInvoiceCreatePayload
		if err := decode(&payload); err != nil {
			return err
		}
	case effect.KindStripeInvoiceFinalize:
		var payload effect.StripeInvoiceFinalizePayload
		if err := decode(&payload); err != nil {
			return err
		}
	case effect.KindStripeInvoiceMarkPaid:
		var payload effect.StripeInvoiceMarkPaidPayload
		if err := decode(&payload); err != nil {
			return err
		}
	case effect.KindStripeCouponUpsert:
		var payload effect.StripeCouponUpsertPayload
		if err := decode(&payload); err != nil {
			return err
		}
	case effect.KindStripeCouponDelete:
		var payload effect.StripeCouponDeletePayload
		if err := decode(&payload); err != nil {
			return err
		}
	case effect.KindStripePromotionCodeUpsert:
		var payload effect.StripePromotionCodeUpsertPayload
		if err := decode(&payload); err != nil {
			return err
		}
	case effect.KindStripePromotionCodeDeactivate:
		var payload effect.StripePromotionCodeDeactivatePayload
		if err := decode(&payload); err != nil {
			return err
		}
	}
	return nil
}

func isStripeHostEffectKind(kind string) bool {
	switch kind {
	case effect.KindStripePaymentIntentCreate,
		effect.KindStripePaymentIntentGet,
		effect.KindStripePaymentIntentCapture,
		effect.KindStripePaymentIntentCancel,
		effect.KindStripeSetupIntentCreate,
		effect.KindStripeSetupIntentGet,
		effect.KindStripeRefundCreate,
		effect.KindStripeCustomerCreate,
		effect.KindStripeInvoiceItemCreate,
		effect.KindStripeInvoiceCreate,
		effect.KindStripeInvoiceFinalize,
		effect.KindStripeInvoiceMarkPaid,
		effect.KindStripeCouponUpsert,
		effect.KindStripeCouponDelete,
		effect.KindStripePromotionCodeUpsert,
		effect.KindStripePromotionCodeDeactivate:
		return true
	default:
		return false
	}
}

func executorEffectFromIntent(intent effect.Intent) (Effect, error) {
	var kind EffectKind
	var payload any
	switch intent.Kind {
	case effect.KindStripePaymentIntentCreate:
		var req paymentIntentCreateRequest
		if err := msgpack.Unmarshal(intent.Payload, &req); err != nil {
			return Effect{}, fmt.Errorf("%w: payment intent payload: %v", ErrInvalidEffect, err)
		}
		if err := validateEmbeddedIdempotencyKey(req.IdempotencyKey, intent.IdempotencyKey); err != nil {
			return Effect{}, err
		}
		kind = EffectPaymentIntentCreate
		payload = PaymentIntentEffectPayload{
			AmountCents: req.AmountCents, Currency: req.Currency,
			Description: req.Description, ReceiptEmail: req.ReceiptEmail,
			CaptureMethod: req.CaptureMethod, PaymentMethodTypes: req.PaymentMethodTypes,
			Customer: req.Customer, Metadata: req.Metadata,
			PaymentMethod: req.PaymentMethod, OffSession: req.OffSession,
			Confirm: req.Confirm, PromotionCodeID: req.PromotionCodeID,
		}
	case effect.KindStripeCheckoutSessionCreate:
		var req checkoutSessionCreateRequest
		if err := msgpack.Unmarshal(intent.Payload, &req); err != nil {
			return Effect{}, fmt.Errorf("%w: checkout session payload: %v", ErrInvalidEffect, err)
		}
		if err := validateEmbeddedIdempotencyKey(req.IdempotencyKey, intent.IdempotencyKey); err != nil {
			return Effect{}, err
		}
		kind = EffectCheckoutSessionCreate
		payload = CheckoutSessionEffectPayload{
			AmountCents: req.AmountCents, Currency: req.Currency,
			SuccessURL: req.SuccessURL, CancelURL: req.CancelURL,
			ProductName: req.ProductName, ProductDescription: req.ProductDescription,
			Metadata: req.Metadata, AutomaticTax: req.AutomaticTax,
		}
	case effect.KindStripeSetupIntentCreate:
		var req setupIntentCreateRequest
		if err := msgpack.Unmarshal(intent.Payload, &req); err != nil {
			return Effect{}, fmt.Errorf("%w: setup intent payload: %v", ErrInvalidEffect, err)
		}
		if err := validateEmbeddedIdempotencyKey(req.IdempotencyKey, intent.IdempotencyKey); err != nil {
			return Effect{}, err
		}
		kind = EffectSetupIntentCreate
		payload = SetupIntentEffectPayload{
			Customer: req.Customer, Usage: req.Usage,
			PaymentMethodTypes: req.PaymentMethodTypes, Metadata: req.Metadata,
		}
	case effect.KindStripeRefundCreate:
		var req refundCreateRequest
		if err := msgpack.Unmarshal(intent.Payload, &req); err != nil {
			return Effect{}, fmt.Errorf("%w: refund payload: %v", ErrInvalidEffect, err)
		}
		if err := validateEmbeddedIdempotencyKey(req.IdempotencyKey, intent.IdempotencyKey); err != nil {
			return Effect{}, err
		}
		kind = EffectRefundCreate
		payload = RefundEffectPayload{
			PaymentIntent: req.PaymentIntentID, AmountCents: req.AmountCents,
			Reason: req.Reason, Metadata: req.Metadata,
		}
	default:
		return Effect{}, fmt.Errorf("%w: %q", ErrUnsupportedEffect, intent.Kind)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return Effect{}, fmt.Errorf("%w: encode canonical payload: %v", ErrInvalidEffect, err)
	}
	return Effect{Kind: kind, IdempotencyKey: intent.IdempotencyKey, Payload: string(encoded)}, nil
}

func validateEmbeddedIdempotencyKey(embedded, envelope string) error {
	if embedded != "" && embedded != envelope {
		return fmt.Errorf("%w: payload idempotency key does not match envelope", ErrIdempotencyConflict)
	}
	return nil
}

func (e *Executor) execute(ctx context.Context, effect Effect) (EffectResult, error) {
	switch effect.Kind {
	case EffectPaymentIntentCreate:
		var payload PaymentIntentEffectPayload
		if err := json.Unmarshal([]byte(effect.Payload), &payload); err != nil {
			return EffectResult{}, fmt.Errorf("%w: payment intent payload: %v", ErrInvalidEffect, err)
		}
		if payload.AmountCents <= 0 || (e.limits.MaxChargeCents > 0 && payload.AmountCents > e.limits.MaxChargeCents) || strings.TrimSpace(payload.Currency) == "" {
			return EffectResult{}, fmt.Errorf("%w: invalid payment intent amount or currency", ErrInvalidEffect)
		}
		return e.client.CreatePaymentIntent(ctx, payload, effect.IdempotencyKey)
	case EffectCheckoutSessionCreate:
		var payload CheckoutSessionEffectPayload
		if err := json.Unmarshal([]byte(effect.Payload), &payload); err != nil {
			return EffectResult{}, fmt.Errorf("%w: checkout session payload: %v", ErrInvalidEffect, err)
		}
		if payload.AmountCents <= 0 || (e.limits.MaxChargeCents > 0 && payload.AmountCents > e.limits.MaxChargeCents) || strings.TrimSpace(payload.Currency) == "" || strings.TrimSpace(payload.SuccessURL) == "" || strings.TrimSpace(payload.CancelURL) == "" || strings.TrimSpace(payload.ProductName) == "" {
			return EffectResult{}, fmt.Errorf("%w: incomplete checkout session payload", ErrInvalidEffect)
		}
		return e.client.CreateCheckoutSession(ctx, payload, effect.IdempotencyKey)
	case EffectSetupIntentCreate:
		var payload SetupIntentEffectPayload
		if err := json.Unmarshal([]byte(effect.Payload), &payload); err != nil {
			return EffectResult{}, fmt.Errorf("%w: setup intent payload: %v", ErrInvalidEffect, err)
		}
		return e.client.CreateSetupIntent(ctx, payload, effect.IdempotencyKey)
	case EffectRefundCreate:
		var payload RefundEffectPayload
		if err := json.Unmarshal([]byte(effect.Payload), &payload); err != nil {
			return EffectResult{}, fmt.Errorf("%w: refund payload: %v", ErrInvalidEffect, err)
		}
		if strings.TrimSpace(payload.PaymentIntent) == "" || (payload.AmountCents != nil && (*payload.AmountCents <= 0 || (e.limits.MaxRefundCents > 0 && *payload.AmountCents > e.limits.MaxRefundCents))) {
			return EffectResult{}, fmt.Errorf("%w: invalid refund payload", ErrInvalidEffect)
		}
		return e.client.CreateRefund(ctx, payload, effect.IdempotencyKey)
	default:
		return EffectResult{}, fmt.Errorf("%w: %q", ErrUnsupportedEffect, effect.Kind)
	}
}

func validateEffect(effect Effect) error {
	if strings.TrimSpace(string(effect.Kind)) == "" || strings.TrimSpace(effect.IdempotencyKey) == "" || strings.TrimSpace(effect.Payload) == "" {
		return fmt.Errorf("%w: kind, idempotency_key, and payload are required", ErrInvalidEffect)
	}
	if len(effect.IdempotencyKey) > 255 {
		return fmt.Errorf("%w: idempotency_key exceeds Stripe's 255-character limit", ErrInvalidEffect)
	}
	return nil
}

func normalizeExecutorKind(kind EffectKind) (EffectKind, error) {
	canonical, err := effect.NormalizeKind(string(kind))
	if err != nil {
		return "", fmt.Errorf("%w: %q", ErrUnsupportedEffect, kind)
	}
	switch canonical {
	case effect.KindStripePaymentIntentCreate:
		return EffectPaymentIntentCreate, nil
	case effect.KindStripeCheckoutSessionCreate:
		return EffectCheckoutSessionCreate, nil
	case effect.KindStripeSetupIntentCreate:
		return EffectSetupIntentCreate, nil
	case effect.KindStripeRefundCreate:
		return EffectRefundCreate, nil
	default:
		return "", fmt.Errorf("%w: %q", ErrUnsupportedEffect, kind)
	}
}

func effectFingerprint(effect Effect) string {
	sum := sha256.Sum256([]byte(string(effect.Kind) + "\x00" + effect.Payload))
	return hex.EncodeToString(sum[:])
}

// ScopedExecutorFactory retains a separate executor, configuration, replay
// cache, and Stripe client for each Pulp application/cell instance. It uses
// ext.ScopeOf so old cells receive the stable legacy scope automatically.
type ScopedExecutorFactory struct {
	executors *ext.ScopedFactory[*Executor]
}

// NewScopedExecutorFactory builds a scope-aware executor registry. The
// callback is invoked once per application/cell instance, never globally.
func NewScopedExecutorFactory(newExecutor func(ext.ResourceKey) (*Executor, error)) *ScopedExecutorFactory {
	return &ScopedExecutorFactory{executors: ext.NewScopedFactory(newExecutor)}
}

// ForCell returns the executor owned by this cell placement. Legacy cells are
// automatically assigned ext.LegacyScope(cell.Name()); a malformed explicit
// scope is rejected rather than silently collapsing into a legacy namespace.
func (f *ScopedExecutorFactory) ForCell(cell ext.Cell) (*Executor, error) {
	scope, err := ext.ValidatedScopeOf(cell)
	if err != nil {
		return nil, err
	}
	return f.ForScope(scope)
}

// ForScope returns the executor for a validated scope.
func (f *ScopedExecutorFactory) ForScope(scope ext.Scope) (*Executor, error) {
	if f == nil || f.executors == nil {
		return nil, fmt.Errorf("%w: scoped executor factory is not configured", ErrInvalidEffect)
	}
	key, err := scope.ResourceKey("payment.stripe", "effects")
	if err != nil {
		return nil, err
	}
	executor, _, err := f.executors.GetOrCreate(key)
	return executor, err
}

// Count reports how many independent mutable Stripe effect executors exist.
func (f *ScopedExecutorFactory) Count() int {
	if f == nil || f.executors == nil {
		return 0
	}
	return f.executors.Count()
}

// EffectExecutorForCell is the host API used by durable Evolution/commerce
// outbox workers. It does not add or alter any WASM imports.
func EffectExecutorForCell(cell ext.Cell) (*Executor, error) {
	runtime, err := extensionRuntimes.forCell(cell)
	if err != nil {
		return nil, err
	}
	return runtime.executor()
}

// stripeEffectClient is the production client adapter. Its Stripe API key and
// endpoint clients belong to one executor instance rather than the extension's
// old process-global state.
type stripeEffectClient struct {
	paymentIntent paymentintent.Client
	checkout      session.Client
	setupIntent   setupintent.Client
	refund        refund.Client
	customer      customer.Client
	invoice       invoice.Client
	invoiceItem   invoiceitem.Client
	coupon        coupon.Client
	promotionCode promotioncode.Client
}

func newStripeEffectClient(apiKey string) EffectClient {
	backend := stripe.GetBackend(stripe.APIBackend)
	return &stripeEffectClient{
		paymentIntent: paymentintent.Client{B: backend, Key: apiKey},
		checkout:      session.Client{B: backend, Key: apiKey},
		setupIntent:   setupintent.Client{B: backend, Key: apiKey},
		refund:        refund.Client{B: backend, Key: apiKey},
		customer:      customer.Client{B: backend, Key: apiKey},
		invoice:       invoice.Client{B: backend, Key: apiKey},
		invoiceItem:   invoiceitem.Client{B: backend, Key: apiKey},
		coupon:        coupon.Client{B: backend, Key: apiKey},
		promotionCode: promotioncode.Client{B: backend, Key: apiKey},
	}
}

func (c *stripeEffectClient) CreatePaymentIntent(ctx context.Context, payload PaymentIntentEffectPayload, key string) (EffectResult, error) {
	params := &stripe.PaymentIntentParams{Amount: stripe.Int64(payload.AmountCents), Currency: stripe.String(payload.Currency)}
	if payload.Description != "" {
		params.Description = stripe.String(payload.Description)
	}
	if payload.ReceiptEmail != "" {
		params.ReceiptEmail = stripe.String(payload.ReceiptEmail)
	}
	if payload.CaptureMethod != "" {
		params.CaptureMethod = stripe.String(payload.CaptureMethod)
	}
	if len(payload.PaymentMethodTypes) > 0 {
		params.PaymentMethodTypes = stripe.StringSlice(payload.PaymentMethodTypes)
	}
	if payload.Customer != "" {
		params.Customer = stripe.String(payload.Customer)
	}
	if payload.PaymentMethod != "" {
		params.PaymentMethod = stripe.String(payload.PaymentMethod)
	}
	if payload.OffSession {
		params.OffSession = stripe.Bool(true)
	}
	if payload.Confirm {
		params.Confirm = stripe.Bool(true)
	}
	for k, v := range payload.Metadata {
		params.AddMetadata(k, v)
	}
	if payload.PromotionCodeID != "" {
		params.AddMetadata("stripe_promotion_code_id", payload.PromotionCodeID)
	}
	params.SetIdempotencyKey(key)
	pi, err := retryStripeIdempotencyInUse(ctx, []time.Duration{250 * time.Millisecond, 500 * time.Millisecond, time.Second}, func() (*stripe.PaymentIntent, error) {
		return c.paymentIntent.New(params)
	})
	if err != nil {
		return EffectResult{}, err
	}
	return EffectResult{PaymentIntent: pi.ID, ClientSecret: pi.ClientSecret, Status: string(pi.Status)}, nil
}

func retryStripeIdempotencyInUse[T any](ctx context.Context, delays []time.Duration, call func() (T, error)) (T, error) {
	var zero T
	for attempt := 0; ; attempt++ {
		value, err := call()
		if err == nil {
			return value, nil
		}
		var stripeErr *stripe.Error
		if !errors.As(err, &stripeErr) || stripeErr.Code != stripe.ErrorCodeIdempotencyKeyInUse || attempt >= len(delays) {
			return zero, err
		}
		timer := time.NewTimer(delays[attempt])
		select {
		case <-ctx.Done():
			timer.Stop()
			return zero, ctx.Err()
		case <-timer.C:
		}
	}
}

func (c *stripeEffectClient) CreateCheckoutSession(_ context.Context, payload CheckoutSessionEffectPayload, key string) (EffectResult, error) {
	params := checkoutSessionParams(checkoutSessionCreateRequest{
		AmountCents:        payload.AmountCents,
		Currency:           payload.Currency,
		SuccessURL:         payload.SuccessURL,
		CancelURL:          payload.CancelURL,
		ProductName:        payload.ProductName,
		ProductDescription: payload.ProductDescription,
		Metadata:           payload.Metadata,
		AutomaticTax:       payload.AutomaticTax,
		IdempotencyKey:     key,
	})
	s, err := c.checkout.New(params)
	if err != nil {
		return EffectResult{}, err
	}
	result := EffectResult{CheckoutSession: s.ID, CheckoutURL: s.URL, Status: string(s.Status)}
	if s.PaymentIntent != nil {
		result.PaymentIntent = s.PaymentIntent.ID
	}
	return result, nil
}

func (c *stripeEffectClient) CreateSetupIntent(_ context.Context, payload SetupIntentEffectPayload, key string) (EffectResult, error) {
	params := &stripe.SetupIntentParams{}
	if payload.Customer != "" {
		params.Customer = stripe.String(payload.Customer)
	}
	usage := payload.Usage
	if usage == "" {
		usage = "off_session"
	}
	params.Usage = stripe.String(usage)
	if len(payload.PaymentMethodTypes) == 0 {
		payload.PaymentMethodTypes = []string{"card"}
	}
	params.PaymentMethodTypes = stripe.StringSlice(payload.PaymentMethodTypes)
	for k, v := range payload.Metadata {
		params.AddMetadata(k, v)
	}
	params.SetIdempotencyKey(key)
	si, err := c.setupIntent.New(params)
	if err != nil {
		return EffectResult{}, err
	}
	return EffectResult{SetupIntent: si.ID, ClientSecret: si.ClientSecret, Status: string(si.Status)}, nil
}

func (c *stripeEffectClient) GetSetupIntent(_ context.Context, payload effect.StripeSetupIntentGetPayload) (effect.StripeSetupIntentGetResult, error) {
	si, err := c.setupIntent.Get(payload.SetupIntentID, nil)
	if err != nil {
		return effect.StripeSetupIntentGetResult{}, err
	}
	result := effect.StripeSetupIntentGetResult{
		SetupIntentID: si.ID, Status: string(si.Status),
	}
	if si.Customer != nil {
		result.Customer = si.Customer.ID
	}
	if si.PaymentMethod != nil {
		result.PaymentMethod = si.PaymentMethod.ID
	}
	return result, nil
}

// GetPaymentIntent returns only the canonical confirmation surface. In
// particular, a durable host-effect receipt must never contain a client
// secret, customer data, payment method, metadata, or Stripe diagnostics.
func (c *stripeEffectClient) GetPaymentIntent(
	_ context.Context, payload effect.StripePaymentIntentGetPayload,
) (effect.StripePaymentIntentGetResult, error) {
	pi, err := c.paymentIntent.Get(payload.PaymentIntentID, nil)
	if err != nil {
		return effect.StripePaymentIntentGetResult{}, err
	}
	return effect.StripePaymentIntentGetResult{
		PaymentIntentID: pi.ID,
		Status:          string(pi.Status),
		AmountCents:     pi.Amount,
		Currency:        string(pi.Currency),
		CaptureMethod:   string(pi.CaptureMethod),
	}, nil
}

func (c *stripeEffectClient) CreateRefund(_ context.Context, payload RefundEffectPayload, key string) (EffectResult, error) {
	params := &stripe.RefundParams{PaymentIntent: stripe.String(payload.PaymentIntent)}
	if payload.AmountCents != nil {
		params.Amount = stripe.Int64(*payload.AmountCents)
	}
	if payload.Reason != "" {
		params.Reason = stripe.String(payload.Reason)
	}
	for k, v := range payload.Metadata {
		params.AddMetadata(k, v)
	}
	params.SetIdempotencyKey(key)
	r, err := c.refund.New(params)
	if err != nil {
		return EffectResult{}, err
	}
	return EffectResult{Refund: r.ID, Status: string(r.Status)}, nil
}

func (c *stripeEffectClient) CapturePaymentIntent(
	_ context.Context, payload effect.StripePaymentIntentCapturePayload, key string,
) (effect.StripePaymentIntentMutationResult, error) {
	params := &stripe.PaymentIntentCaptureParams{}
	params.SetIdempotencyKey(key)
	pi, err := c.paymentIntent.Capture(payload.PaymentIntentID, params)
	if err != nil {
		return effect.StripePaymentIntentMutationResult{}, err
	}
	return encodePaymentIntentEffectResult(pi), nil
}

func (c *stripeEffectClient) CancelPaymentIntent(
	_ context.Context, payload effect.StripePaymentIntentCancelPayload, key string,
) (effect.StripePaymentIntentMutationResult, error) {
	// Cancellation is cleanup, not a reversal of a completed payment. Avoid
	// calling Stripe's cancel endpoint for terminal intents: it rejects a
	// succeeded intent and turns an otherwise idempotent cleanup effect into a
	// noisy retry.
	current, err := c.paymentIntent.Get(payload.PaymentIntentID, nil)
	if err != nil {
		return effect.StripePaymentIntentMutationResult{}, err
	}
	if paymentIntentCancelTerminal(string(current.Status)) {
		return encodePaymentIntentEffectResult(current), nil
	}
	params := &stripe.PaymentIntentCancelParams{}
	params.SetIdempotencyKey(key)
	pi, err := c.paymentIntent.Cancel(payload.PaymentIntentID, params)
	if err != nil {
		return effect.StripePaymentIntentMutationResult{}, err
	}
	return encodePaymentIntentEffectResult(pi), nil
}

func paymentIntentCancelTerminal(status string) bool {
	return status == "succeeded" || status == "canceled"
}

func encodePaymentIntentEffectResult(pi *stripe.PaymentIntent) effect.StripePaymentIntentMutationResult {
	result := effect.StripePaymentIntentMutationResult{
		PaymentIntentID: pi.ID,
		Status:          string(pi.Status),
		Amount:          pi.Amount,
		Currency:        string(pi.Currency),
	}
	if pi.LatestCharge != nil {
		result.LatestCharge = pi.LatestCharge.ID
	}
	if pi.LastPaymentError != nil {
		result.LastErrorCode = string(pi.LastPaymentError.Code)
		result.LastError = pi.LastPaymentError.Msg
	}
	return result
}

func (c *stripeEffectClient) CreateCustomer(
	_ context.Context, payload effect.StripeCustomerCreatePayload, key string,
) (effect.StripeCustomerCreateResult, error) {
	params := customerParams(customerCreateRequest{
		Email: payload.Email, Name: payload.Name, Description: payload.Description,
		Metadata: payload.Metadata, IdempotencyKey: key,
	})
	created, err := c.customer.New(params)
	if err != nil {
		return effect.StripeCustomerCreateResult{}, err
	}
	return effect.StripeCustomerCreateResult{CustomerID: created.ID, Email: created.Email}, nil
}

func (c *stripeEffectClient) CreateInvoiceItem(
	_ context.Context, payload effect.StripeInvoiceItemCreatePayload, key string,
) (effect.StripeInvoiceItemCreateResult, error) {
	item, err := c.invoiceItem.New(invoiceItemParams(invoiceItemCreateRequest{
		Customer: payload.CustomerID, Invoice: payload.InvoiceID, AmountCents: payload.AmountCents,
		Currency: payload.Currency, Description: payload.Description, IdempotencyKey: key,
	}))
	if err != nil {
		return effect.StripeInvoiceItemCreateResult{}, err
	}
	return effect.StripeInvoiceItemCreateResult{InvoiceItemID: item.ID}, nil
}

func (c *stripeEffectClient) CreateInvoice(
	_ context.Context, payload effect.StripeInvoiceCreatePayload, key string,
) (effect.StripeInvoiceResult, error) {
	created, err := c.invoice.New(invoiceParams(invoiceCreateRequest{
		Customer: payload.CustomerID, Description: payload.Description, AutoAdvance: payload.AutoAdvance,
		CollectionMethod: payload.CollectionMethod, Metadata: payload.Metadata, PromotionCodeID: payload.PromotionCodeID,
		IdempotencyKey: key,
	}))
	if err != nil {
		return effect.StripeInvoiceResult{}, err
	}
	return encodeCanonicalInvoiceResult(created), nil
}

func (c *stripeEffectClient) FinalizeInvoice(
	_ context.Context, payload effect.StripeInvoiceFinalizePayload, key string,
) (effect.StripeInvoiceResult, error) {
	finalized, err := c.invoice.FinalizeInvoice(payload.InvoiceID, invoiceFinalizeParams(invoiceIDRequest{
		ID: payload.InvoiceID, IdempotencyKey: key,
	}))
	if err != nil {
		return effect.StripeInvoiceResult{}, err
	}
	return encodeCanonicalInvoiceResult(finalized), nil
}

func (c *stripeEffectClient) MarkInvoicePaid(
	_ context.Context, payload effect.StripeInvoiceMarkPaidPayload, key string,
) (effect.StripeInvoiceResult, error) {
	paid, err := c.invoice.Pay(payload.InvoiceID, invoicePayParams(invoiceIDRequest{
		ID: payload.InvoiceID, IdempotencyKey: key,
	}))
	if err != nil {
		return effect.StripeInvoiceResult{}, err
	}
	return encodeCanonicalInvoiceResult(paid), nil
}

func encodeCanonicalInvoiceResult(inv *stripe.Invoice) effect.StripeInvoiceResult {
	return effect.StripeInvoiceResult{
		InvoiceID: inv.ID, Status: string(inv.Status), HostedInvoiceURL: inv.HostedInvoiceURL,
		InvoicePDF: inv.InvoicePDF, AmountDue: inv.AmountDue, AmountPaid: inv.AmountPaid,
	}
}

func (c *stripeEffectClient) CreateFreeInvoiceItem(
	_ context.Context, customerID string, payload effect.StripeFreeInvoiceItem, key string,
) (string, error) {
	params := invoiceItemParams(invoiceItemCreateRequest{
		Customer: customerID, AmountCents: payload.AmountCents, Currency: payload.Currency,
		Description: payload.Description, IdempotencyKey: key,
	})
	item, err := c.invoiceItem.New(params)
	if err != nil {
		return "", err
	}
	return item.ID, nil
}

func (c *stripeEffectClient) CreateFreeInvoice(
	_ context.Context, customerID string, payload effect.StripeFreeInvoice, key string,
) (invoiceEffectResult, error) {
	collectionMethod := payload.CollectionMethod
	if collectionMethod == "" {
		collectionMethod = "charge_automatically"
	}
	params := invoiceParams(invoiceCreateRequest{
		Customer: customerID, Description: payload.Description, AutoAdvance: false,
		CollectionMethod: collectionMethod, Metadata: payload.Metadata,
		PromotionCodeID: payload.PromotionCodeID, IdempotencyKey: key,
	})
	created, err := c.invoice.New(params)
	if err != nil {
		return invoiceEffectResult{}, err
	}
	return encodeInvoiceEffectResult(created), nil
}

func (c *stripeEffectClient) FinalizeFreeInvoice(
	_ context.Context, invoiceID string, key string,
) (invoiceEffectResult, error) {
	finalized, err := c.invoice.FinalizeInvoice(invoiceID, invoiceFinalizeParams(invoiceIDRequest{
		ID: invoiceID, IdempotencyKey: key,
	}))
	if err != nil {
		return invoiceEffectResult{}, err
	}
	return encodeInvoiceEffectResult(finalized), nil
}

func (c *stripeEffectClient) MarkFreeInvoicePaid(
	_ context.Context, invoiceID string, key string,
) (invoiceEffectResult, error) {
	paid, err := c.invoice.Pay(invoiceID, invoicePayParams(invoiceIDRequest{
		ID: invoiceID, IdempotencyKey: key,
	}))
	if err != nil {
		return invoiceEffectResult{}, err
	}
	return encodeInvoiceEffectResult(paid), nil
}

func encodeInvoiceEffectResult(invoice *stripe.Invoice) invoiceEffectResult {
	return invoiceEffectResult{
		ID: invoice.ID, Status: string(invoice.Status),
		HostedInvoiceURL: invoice.HostedInvoiceURL, InvoicePDF: invoice.InvoicePDF,
		AmountDue: invoice.AmountDue, AmountPaid: invoice.AmountPaid,
	}
}

func (c *stripeEffectClient) UpsertCoupon(
	_ context.Context, payload effect.StripeCouponUpsertPayload, key string,
) (effect.StripeCouponUpsertResult, error) {
	params := couponParams(couponCreateRequest{
		AmountOffCents: payload.AmountOffCents, PercentOff: payload.PercentOff,
		Currency: payload.Currency, Duration: payload.Duration,
		DurationMonths: payload.DurationMonths, MaxRedemptions: payload.MaxRedemptions,
		RedeemBy: payload.RedeemByUnix, Name: payload.Name, Metadata: payload.Metadata,
		IdempotencyKey: key,
	})
	created, err := c.coupon.New(params)
	if err != nil {
		return effect.StripeCouponUpsertResult{}, err
	}
	durationMonths := created.DurationInMonths
	if durationMonths == 0 {
		durationMonths = payload.DurationMonths
	}
	return effect.StripeCouponUpsertResult{
		ExternalKey: payload.ExternalKey, CouponID: created.ID, Valid: created.Valid,
		AmountOff: created.AmountOff, PercentOff: created.PercentOff,
		Currency: string(created.Currency), Duration: string(created.Duration),
		DurationMonths: durationMonths,
	}, nil
}

func (c *stripeEffectClient) DeleteCoupon(
	_ context.Context, payload effect.StripeCouponDeletePayload, key string,
) (effect.StripeCouponDeleteResult, error) {
	params := couponDeleteParams(key)
	deleted, err := c.coupon.Del(payload.CouponID, params)
	if err != nil {
		return effect.StripeCouponDeleteResult{}, err
	}
	return effect.StripeCouponDeleteResult{
		ExternalKey: payload.ExternalKey, CouponID: payload.CouponID, Deleted: deleted.Deleted,
	}, nil
}

func couponDeleteParams(key string) *stripe.CouponParams {
	params := &stripe.CouponParams{}
	if key != "" {
		params.SetIdempotencyKey(key)
	}
	return params
}

func (c *stripeEffectClient) UpsertPromotionCode(
	_ context.Context, payload effect.StripePromotionCodeUpsertPayload, key string,
) (effect.StripePromotionCodeUpsertResult, error) {
	params := promotionCodeParams(promotionCodeCreateRequest{
		CouponID: payload.CouponID, Code: payload.Code, Active: payload.Active,
		MaxRedemptions: payload.MaxRedemptions, ExpiresAt: payload.ExpiresAtUnix,
		Customer: payload.CustomerID, Metadata: payload.Metadata, IdempotencyKey: key,
	})
	created, err := c.promotionCode.New(params)
	if err != nil {
		return effect.StripePromotionCodeUpsertResult{}, err
	}
	result := effect.StripePromotionCodeUpsertResult{
		ExternalKey: payload.ExternalKey, PromotionCodeID: created.ID,
		CouponID: payload.CouponID, Code: created.Code, Active: created.Active,
		MaxRedemptions: created.MaxRedemptions, TimesRedeemed: created.TimesRedeemed,
		ExpiresAtUnix: created.ExpiresAt,
	}
	if created.Coupon != nil {
		result.CouponID = created.Coupon.ID
		result.AmountOff = created.Coupon.AmountOff
		result.PercentOff = created.Coupon.PercentOff
		result.Currency = string(created.Coupon.Currency)
	}
	return result, nil
}

func (c *stripeEffectClient) DeactivatePromotionCode(
	_ context.Context, payload effect.StripePromotionCodeDeactivatePayload, key string,
) (effect.StripePromotionCodeDeactivateResult, error) {
	params := promotionCodeUpdateParams(promotionCodeUpdateRequest{
		ID: payload.PromotionCodeID, Active: false, IdempotencyKey: key,
	})
	updated, err := c.promotionCode.Update(payload.PromotionCodeID, params)
	if err != nil {
		return effect.StripePromotionCodeDeactivateResult{}, err
	}
	return effect.StripePromotionCodeDeactivateResult{
		ExternalKey: payload.ExternalKey, PromotionCodeID: payload.PromotionCodeID,
		Active: updated.Active,
	}, nil
}
