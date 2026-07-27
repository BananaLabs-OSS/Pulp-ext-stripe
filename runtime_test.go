package stripeext

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/BananaLabs-OSS/Pulp/ext"
)

func TestStripeRuntimeTeardownScopeIsolatedAcrossApplications(t *testing.T) {
	registry := newStripeRuntimeRegistry()
	scopeA := mustStripeScope(t, "evolution", "app-a", "sessions-effects", "cell-a")
	scopeB := mustStripeScope(t, "sessions", "app-b", "sessions-effects", "cell-b")
	loggerA := slog.New(slog.NewTextHandler(io.Discard, nil))
	loggerB := slog.New(slog.NewJSONHandler(io.Discard, nil))
	if err := registry.setup(ext.SetupEnv{Scope: scopeA, CellName: "sessions-effects", Logger: loggerA}); err != nil {
		t.Fatal(err)
	}
	if err := registry.setup(ext.SetupEnv{Scope: scopeB, CellName: "sessions-effects", Logger: loggerB}); err != nil {
		t.Fatal(err)
	}
	runtimeA, err := registry.forCell(scopedTestCell{name: "sessions-effects", scope: scopeA})
	if err != nil {
		t.Fatal(err)
	}
	runtimeB, err := registry.forCell(scopedTestCell{name: "sessions-effects", scope: scopeB})
	if err != nil {
		t.Fatal(err)
	}
	if runtimeA == runtimeB {
		t.Fatal("two applications shared one mutable Stripe runtime")
	}
	clientA := &fakeEffectClient{}
	clientB := &fakeEffectClient{}
	executorA := seedRuntimeForLifecycleTest(runtimeA, "key-a", 100, clientA)
	executorB := seedRuntimeForLifecycleTest(runtimeB, "key-b", 200, clientB)

	if err := registry.teardownScope(context.Background(), scopeA); err != nil {
		t.Fatal(err)
	}
	if got, want := registry.count(), 1; got != want {
		t.Fatalf("runtime count after app A teardown = %d, want %d", got, want)
	}
	if _, err := executorA.Execute(context.Background(), lifecycleTestEffect("app-a-effect")); !errors.Is(err, errStripeRuntimeClosed) {
		t.Fatalf("app A executor error = %v, want runtime closed", err)
	}
	result, err := executorB.Execute(context.Background(), lifecycleTestEffect("app-b-effect"))
	if err != nil {
		t.Fatalf("app B executor was broken by app A teardown: %v", err)
	}
	if result.PaymentIntent != "pi_123" || len(clientB.calls) != 1 {
		t.Fatalf("app B result/calls = %#v / %#v", result, clientB.calls)
	}
	if runtimeB.log() != loggerB {
		t.Fatal("app B logger was replaced by app A lifecycle")
	}
	if runtimeB.chargeCap() != 200 {
		t.Fatalf("app B charge cap = %d, want 200", runtimeB.chargeCap())
	}
}

func TestStripeCapabilityRegistersScopedLifecycleHooks(t *testing.T) {
	var stripeCapability *ext.Capability
	for _, capability := range ext.All() {
		if capability.Name == "payment.stripe" {
			candidate := capability
			stripeCapability = &candidate
			break
		}
	}
	if stripeCapability == nil {
		t.Fatal("payment.stripe capability is not registered")
	}
	if got, want := stripeCapability.Provider, "github.com/BananaLabs-OSS/Pulp-ext-stripe"; got != want {
		t.Fatalf("payment.stripe provider = %q, want %q", got, want)
	}
	if stripeCapability.Setup == nil || stripeCapability.TeardownScope == nil || stripeCapability.Teardown == nil {
		t.Fatalf("payment.stripe lifecycle hooks are incomplete: %#v", stripeCapability)
	}
}

func TestStripeRuntimeLegacyCellTeardownPreservesOtherLegacyCell(t *testing.T) {
	registry := newStripeRuntimeRegistry()
	if err := registry.setup(ext.SetupEnv{CellName: "evolution"}); err != nil {
		t.Fatal(err)
	}
	if err := registry.setup(ext.SetupEnv{CellName: "sessions"}); err != nil {
		t.Fatal(err)
	}
	evolution, err := registry.forCell(legacyTestCell("evolution"))
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := registry.forCell(legacyTestCell("sessions"))
	if err != nil {
		t.Fatal(err)
	}
	seedRuntimeForLifecycleTest(evolution, "legacy-a", 100, &fakeEffectClient{})
	sessionsClient := &fakeEffectClient{}
	sessionsExecutor := seedRuntimeForLifecycleTest(sessions, "legacy-b", 100, sessionsClient)

	if err := registry.teardownCell(context.Background(), "evolution"); err != nil {
		t.Fatal(err)
	}
	if _, err := sessionsExecutor.Execute(context.Background(), lifecycleTestEffect("legacy-b-effect")); err != nil {
		t.Fatalf("other legacy cell stopped after teardown: %v", err)
	}
	if got, want := registry.count(), 1; got != want {
		t.Fatalf("legacy runtime count = %d, want %d", got, want)
	}
}

func TestStripeRuntimeConcurrentTwoAppTeardown(t *testing.T) {
	registry := newStripeRuntimeRegistry()
	scopeA := mustStripeScope(t, "evolution", "app-a", "sessions-effects", "cell-a")
	scopeB := mustStripeScope(t, "sessions", "app-b", "sessions-effects", "cell-b")
	if err := registry.setup(ext.SetupEnv{Scope: scopeA}); err != nil {
		t.Fatal(err)
	}
	if err := registry.setup(ext.SetupEnv{Scope: scopeB}); err != nil {
		t.Fatal(err)
	}
	runtimeA, _ := registry.forCell(scopedTestCell{name: "sessions-effects", scope: scopeA})
	runtimeB, _ := registry.forCell(scopedTestCell{name: "sessions-effects", scope: scopeB})
	executorA := seedRuntimeForLifecycleTest(runtimeA, "key-a", 100, &fakeEffectClient{})
	executorB := seedRuntimeForLifecycleTest(runtimeB, "key-b", 100, &fakeEffectClient{})

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		_ = registry.teardownScope(context.Background(), scopeA)
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			_, _ = executorA.Execute(context.Background(), lifecycleTestEffect("app-a-race"))
		}
	}()
	var appBErr error
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			if _, err := executorB.Execute(context.Background(), lifecycleTestEffect("app-b-race")); err != nil {
				appBErr = err
				return
			}
		}
	}()
	wg.Wait()
	if appBErr != nil {
		t.Fatalf("app B failed during app A teardown: %v", appBErr)
	}
	if _, err := executorB.Execute(context.Background(), lifecycleTestEffect("app-b-race")); err != nil {
		t.Fatalf("app B failed after app A teardown: %v", err)
	}
}

func mustStripeScope(t *testing.T, app, appInstance, cell, cellInstance string) ext.Scope {
	t.Helper()
	scope, err := ext.NewScope(app, appInstance, cell, cellInstance)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func seedRuntimeForLifecycleTest(runtime *stripeRuntime, apiKey string, chargeCap int64, client EffectClient) *Executor {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.ready = true
	runtime.apiKey = apiKey
	runtime.maxChargeCents = chargeCap
	runtime.clients = newStripeClients(apiKey)
	runtime.effectExecutor = NewExecutor(client, EffectLimits{MaxChargeCents: chargeCap})
	return runtime.effectExecutor
}

func lifecycleTestEffect(key string) Effect {
	return Effect{
		Kind: EffectPaymentIntentCreate, IdempotencyKey: key,
		Payload: `{"amount_cents":50,"currency":"usd"}`,
	}
}
