package stripeext

import (
	"context"
	"errors"
	"log/slog"
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
	"github.com/stripe/stripe-go/v82/setupintent"
)

var errStripeRuntimeClosed = errors.New("stripe: application runtime is closed")

type stripeClients struct {
	balance       balance.Client
	checkout      session.Client
	coupon        coupon.Client
	customer      customer.Client
	invoice       invoice.Client
	invoiceItem   invoiceitem.Client
	paymentIntent paymentintent.Client
	promotionCode promotioncode.Client
	refund        refund.Client
	setupIntent   setupintent.Client
}

func newStripeClients(apiKey string) stripeClients {
	backend := stripe.GetBackend(stripe.APIBackend)
	return stripeClients{
		balance:       balance.Client{B: backend, Key: apiKey},
		checkout:      session.Client{B: backend, Key: apiKey},
		coupon:        coupon.Client{B: backend, Key: apiKey},
		customer:      customer.Client{B: backend, Key: apiKey},
		invoice:       invoice.Client{B: backend, Key: apiKey},
		invoiceItem:   invoiceitem.Client{B: backend, Key: apiKey},
		paymentIntent: paymentintent.Client{B: backend, Key: apiKey},
		promotionCode: promotioncode.Client{B: backend, Key: apiKey},
		refund:        refund.Client{B: backend, Key: apiKey},
		setupIntent:   setupintent.Client{B: backend, Key: apiKey},
	}
}

// stripeRuntime owns every mutable Stripe resource for one Pulp cell
// placement. Package code is shared; clients, configuration, logger, replay
// cache, and lifecycle are not.
type stripeRuntime struct {
	mu sync.Mutex

	scope   ext.Scope
	logger  *slog.Logger
	closed  bool
	ready   bool
	initErr error

	apiKey         string
	webhookSecret  string
	maxRefundCents int64
	maxChargeCents int64
	clients        stripeClients
	effectExecutor *Executor
}

func newStripeRuntime(scope ext.Scope, logger *slog.Logger) *stripeRuntime {
	if logger == nil {
		logger = slog.Default()
	}
	return &stripeRuntime{scope: scope, logger: logger}
}

func (r *stripeRuntime) configureLogger(logger *slog.Logger) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errStripeRuntimeClosed
	}
	if logger != nil {
		r.logger = logger
	}
	return nil
}

func (r *stripeRuntime) ensureConfigured() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ensureConfiguredLocked()
}

func (r *stripeRuntime) ensureConfiguredLocked() error {
	if r.closed {
		return errStripeRuntimeClosed
	}
	if r.ready {
		return r.initErr
	}
	key := os.Getenv("STRIPE_SECRET_KEY")
	if key == "" {
		// Preserve the legacy retry behavior: a transient missing value does
		// not wedge this application instance permanently.
		r.initErr = errors.New("stripe: STRIPE_SECRET_KEY required")
		return r.initErr
	}
	r.apiKey = key
	r.webhookSecret = os.Getenv("STRIPE_WEBHOOK_SECRET")
	r.maxRefundCents = envCents("STRIPE_MAX_REFUND_CENTS")
	r.maxChargeCents = envCents("STRIPE_MAX_CHARGE_CENTS")
	r.clients = newStripeClients(key)
	r.initErr = nil
	r.ready = true
	return nil
}

func (r *stripeRuntime) executor() (*Executor, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.ensureConfiguredLocked(); err != nil {
		return nil, err
	}
	if r.effectExecutor == nil {
		r.effectExecutor = NewExecutor(newStripeEffectClient(r.apiKey), EffectLimits{
			MaxChargeCents: r.maxChargeCents,
			MaxRefundCents: r.maxRefundCents,
		})
	}
	return r.effectExecutor, nil
}

func (r *stripeRuntime) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	if r.effectExecutor != nil {
		r.effectExecutor.close()
	}
}

func (r *stripeRuntime) log() *slog.Logger {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.logger != nil {
		return r.logger
	}
	return slog.Default()
}

func (r *stripeRuntime) chargeExceedsCap(amount int64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.maxChargeCents > 0 && amount > r.maxChargeCents
}

func (r *stripeRuntime) refundExceedsCap(amount int64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.maxRefundCents > 0 && amount > r.maxRefundCents
}

func (r *stripeRuntime) chargeCap() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.maxChargeCents
}

func (r *stripeRuntime) refundCap() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.maxRefundCents
}

type stripeRuntimeRegistry struct {
	mu      sync.Mutex
	byKey   map[ext.ResourceKey]*stripeRuntime
	routing map[string]ext.ResourceKey
}

func newStripeRuntimeRegistry() *stripeRuntimeRegistry {
	return &stripeRuntimeRegistry{
		byKey:   make(map[ext.ResourceKey]*stripeRuntime),
		routing: make(map[string]ext.ResourceKey),
	}
}

func stripeRuntimeKey(scope ext.Scope) (ext.ResourceKey, error) {
	return scope.ResourceKey("payment.stripe", "runtime")
}

func (r *stripeRuntimeRegistry) setup(env ext.SetupEnv) error {
	scope := env.EffectiveScope()
	key, err := stripeRuntimeKey(scope)
	if err != nil {
		return err
	}
	r.mu.Lock()
	runtime := r.byKey[key]
	if runtime == nil {
		runtime = newStripeRuntime(scope, env.Logger)
		r.byKey[key] = runtime
	}
	r.routing[scope.RoutingID()] = key
	if env.Scope.Validate() != nil && env.CellName != "" {
		r.routing[env.CellName] = key
	}
	r.mu.Unlock()
	return runtime.configureLogger(env.Logger)
}

func (r *stripeRuntimeRegistry) forCell(cell ext.Cell) (*stripeRuntime, error) {
	scope, err := ext.ValidatedScopeOf(cell)
	if err != nil {
		return nil, err
	}
	key, err := stripeRuntimeKey(scope)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	runtime := r.byKey[key]
	if runtime == nil {
		runtime = newStripeRuntime(scope, nil)
		r.byKey[key] = runtime
	}
	r.routing[scope.RoutingID()] = key
	r.routing[ext.CellIDOf(cell)] = key
	return runtime, nil
}

func (r *stripeRuntimeRegistry) teardownCell(_ context.Context, cellID string) error {
	r.mu.Lock()
	key, ok := r.routing[cellID]
	if !ok {
		r.mu.Unlock()
		return nil
	}
	runtime := r.byKey[key]
	delete(r.byKey, key)
	for route, candidate := range r.routing {
		if candidate == key {
			delete(r.routing, route)
		}
	}
	r.mu.Unlock()
	if runtime != nil {
		runtime.close()
	}
	return nil
}

func (r *stripeRuntimeRegistry) teardownScope(_ context.Context, scope ext.Scope) error {
	key, err := stripeRuntimeKey(scope)
	if err != nil {
		return err
	}
	r.mu.Lock()
	runtime := r.byKey[key]
	delete(r.byKey, key)
	for route, candidate := range r.routing {
		if candidate == key {
			delete(r.routing, route)
		}
	}
	r.mu.Unlock()
	if runtime != nil {
		runtime.close()
	}
	return nil
}

func (r *stripeRuntimeRegistry) teardownAll(context.Context) error {
	r.mu.Lock()
	runtimes := make([]*stripeRuntime, 0, len(r.byKey))
	for _, runtime := range r.byKey {
		runtimes = append(runtimes, runtime)
	}
	r.byKey = make(map[ext.ResourceKey]*stripeRuntime)
	r.routing = make(map[string]ext.ResourceKey)
	r.mu.Unlock()
	for _, runtime := range runtimes {
		runtime.close()
	}
	return nil
}

func (r *stripeRuntimeRegistry) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.byKey)
}

var extensionRuntimes = newStripeRuntimeRegistry()

type stripeRuntimeContextKey struct{}

func withStripeRuntime(ctx context.Context, runtime *stripeRuntime) context.Context {
	return context.WithValue(ctx, stripeRuntimeContextKey{}, runtime)
}

func stripeRuntimeFromContext(ctx context.Context) *stripeRuntime {
	if runtime, ok := ctx.Value(stripeRuntimeContextKey{}).(*stripeRuntime); ok && runtime != nil {
		return runtime
	}
	// Direct legacy handler tests did not bind through a scoped cell. Keep
	// their single-application behavior without sharing with modern scopes.
	scope := ext.LegacyScope("default")
	key, _ := stripeRuntimeKey(scope)
	extensionRuntimes.mu.Lock()
	defer extensionRuntimes.mu.Unlock()
	runtime := extensionRuntimes.byKey[key]
	if runtime == nil {
		runtime = newStripeRuntime(scope, nil)
		extensionRuntimes.byKey[key] = runtime
		extensionRuntimes.routing["default"] = key
	}
	return runtime
}
