# Pulp-ext-stripe

Stripe payment capability for Pulp cells, backed by [stripe-go/v82](https://github.com/stripe/stripe-go). Covers Checkout Sessions, webhook signature verification, PaymentIntent lookups, and Refunds.

From [BananaLabs OSS](https://github.com/BananaLabs-OSS).

## Deployment

```go
import _ "github.com/BananaLabs-OSS/Pulp-ext-stripe"
```

## Capability

- `payment.stripe` — Checkout, webhooks, PaymentIntents, Refunds

## Environment

- `STRIPE_SECRET_KEY` — required, `sk_test_...` or `sk_live_...`
- `STRIPE_WEBHOOK_SECRET` — required only if the cell verifies inbound webhook signatures
