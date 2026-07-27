package stripeext

import (
	"context"

	"github.com/BananaLabs-OSS/Pulp/ext"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

const stripeHostEffectCapability = "effect.stripe.runtime"

// bindStripeHostEffectActive exposes exactly one intent-to-receipt operation.
// Its capability is intentionally separate from payment.stripe: state-owning
// cells need no raw Stripe method imports to dispatch a durable effect.
func bindStripeHostEffectActive(b wazero.HostModuleBuilder, cell ext.Cell) error {
	runtime, err := extensionRuntimes.forCell(cell)
	if err != nil {
		return err
	}
	h := func(ctx context.Context, m api.Module, reqPtr, reqLen, respPtrOut, respLenOut uint32) uint32 {
		return stripeHostEffectExecute(withStripeRuntime(ctx, runtime), m, reqPtr, reqLen, respPtrOut, respLenOut)
	}
	b.NewFunctionBuilder().WithFunc(h).Export("stripe_effect_execute")
	return nil
}

func bindStripeHostEffectStub(b wazero.HostModuleBuilder, _ ext.Cell) error {
	nop := func(_ context.Context, _ api.Module, _, _, _, _ uint32) uint32 { return 99 }
	b.NewFunctionBuilder().WithFunc(nop).Export("stripe_effect_execute")
	return nil
}

// stripeHostEffectExecute implements the four-pointer MessagePack ABI:
// request is one canonical pulp.effect.v1 Intent; response is its completed
// canonical Receipt. State transitions, receipt acknowledgement, and any
// multi-step invoice composition remain application responsibilities.
//
// Codes: 1 empty request, 2 unreadable request, 3 invalid/denied intent,
// 4 Stripe execution/configuration failure, 5-8 response write failure.
func stripeHostEffectExecute(ctx context.Context, m api.Module, reqPtr, reqLen, respPtrOut, respLenOut uint32) uint32 {
	if reqLen == 0 {
		return 1
	}
	wire, ok := m.Memory().Read(reqPtr, reqLen)
	if !ok {
		return 2
	}
	// Validate before initializing credentials or acquiring a provider client.
	if _, err := decodeStripeHostIntent(wire); err != nil {
		return 3
	}
	executor, err := stripeRuntimeFromContext(ctx).executor()
	if err != nil {
		return 4
	}
	receipt, err := executor.ExecuteStripeIntentWire(ctx, wire)
	if err != nil {
		return 4
	}
	return writeStripeHostEffectWire(ctx, m, receipt, respPtrOut, respLenOut)
}

func writeStripeHostEffectWire(ctx context.Context, m api.Module, wire []byte, respPtrOut, respLenOut uint32) uint32 {
	allocFn := m.ExportedFunction("pulp_alloc")
	if allocFn == nil {
		return 7
	}
	result, err := allocFn.Call(ctx, uint64(len(wire)))
	if err != nil || len(result) == 0 || result[0] == 0 {
		return 7
	}
	ptr := uint32(result[0])
	if !m.Memory().Write(ptr, wire) || !m.Memory().WriteUint32Le(respPtrOut, ptr) || !m.Memory().WriteUint32Le(respLenOut, uint32(len(wire))) {
		return 8
	}
	return 0
}
