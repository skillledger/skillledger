"""Stripe SDK initialization helper."""

import stripe

from skillledger_service.db import get_settings


def get_stripe_client() -> stripe.StripeClient:
    """Return a configured Stripe client using the secret key from settings."""
    settings = get_settings()
    return stripe.StripeClient(settings.stripe_secret_key)
