# Pulp-ext-stripe

Stripe payment capability for Pulp cells, backed by [stripe-go/v82](https://github.com/stripe/stripe-go). Covers Checkout Sessions, webhook signature verification, PaymentIntent lookups, and Refunds.

From [BananaLabs OSS](https://github.com/BananaLabs-OSS).

## Deployment

```go
import _ "github.com/BananaLabs-OSS/Pulp-ext-stripe"
```

## Capability

- `payment.stripe` — Checkout Sessions, Webhook verification, PaymentIntents
  (create/get/capture/cancel), Refunds, Customers, Invoices + InvoiceItems,
  Balance reads, Coupons, and PromotionCodes

## Environment

- `STRIPE_SECRET_KEY` — required, `sk_test_...` or `sk_live_...`
- `STRIPE_WEBHOOK_SECRET` — required only if the cell verifies inbound webhook signatures
- `STRIPE_MAX_REFUND_CENTS` — optional host ceiling; refunds above this many cents are rejected (code 12). Unset/`0` = no cap.
- `STRIPE_MAX_CHARGE_CENTS` — optional host ceiling; PaymentIntents / Checkout line items above this are rejected (code 12). Unset/`0` = no cap.

## Trust boundary

`payment.stripe` is a **trusted, single-account** capability. Every cell that
declares it transacts under the one process-global `STRIPE_SECRET_KEY` and can
act on the whole Stripe account — there is no per-cell ownership check on
individual Stripe objects (stripe-go has no host-side notion of "which cell
created this charge"). **Grant it only to first-party cells.**

Host-side guards that reduce the blast radius of a buggy or compromised holder:

- **Explicit zero/negative `amount_cents` is rejected (code 12).** An *omitted*
  `amount_cents` is the supported full-refund path — Stripe treats an absent
  amount as a full refund of the PaymentIntent, and that is intentional.
  Sending `amount_cents=0` explicitly is rejected because it would otherwise
  silently produce an uncapped full refund from what looks like a no-op value.
  A genuine partial refund must name a positive amount; a genuine full refund
  omits the field.
- **Optional amount ceilings** (`STRIPE_MAX_REFUND_CENTS` /
  `STRIPE_MAX_CHARGE_CENTS`) cap the largest amount any single request may name.
- **Cell attribution** — every refund / charge / balance read is logged with
  the calling cell's name; Stripe API errors are logged host-side with the
  Stripe error code + request ID (never returned to the cell).

Splitting `payment.stripe` into read / charge / refund sub-capabilities is a
platform-level decision left to the deployment owner and is not done here.
