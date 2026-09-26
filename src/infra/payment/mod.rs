//! Payment-processor seam for the optional pay-to-register registration gate.
//!
//! A pluggable [`PaymentProvider`] the operator wires per instance. It mirrors
//! the chain-provider seam: one NEUTRAL interface, swappable adapters. The gate
//! logic ([`crate::api::auth`]) is processor-agnostic — it only creates an
//! invoice and reads its status; nothing in the auth path knows about BTCPay.
//!
//! The first adapter ([`btcpay`]) speaks the BTCPay-compatible invoice + status
//! API, which covers this project's own non-custodial checkout apps
//! (xmrcheckout / wowcheckout), BTCPay Server, and its Monero plugin — so
//! "operator picks any coin" costs one adapter. A future ETH or native adapter
//! (BTCPay serves neither) implements the SAME trait; the seam is not
//! BTCPay-shaped.
//!
//! ## Trust model
//! The processor is the OPERATOR's own self-hosted, view-only service; the payer
//! pays the operator's wallet directly. The backend never holds funds or a spend
//! key — identical to every other chain path here. Self-hosting a backend
//! bypasses the gate outright.
//!
//! ## Pull, not push (v1)
//! The grant decision READS the processor's authenticated API
//! ([`PaymentProvider::get_invoice`]) as the source of truth, rather than
//! trusting an inbound webhook. There is no public webhook endpoint to secure,
//! and a settled invoice cannot be forged over HTTP. A push (webhook) adapter
//! can be added behind this same trait later without touching the gate.

mod btcpay;

pub use btcpay::BtcPayProvider;

use std::sync::Arc;

use async_trait::async_trait;

use crate::config::Config;
use crate::error::AppError;

/// A processor-neutral invoice status. Adapters map their processor's status
/// vocabulary onto this; the gate only grants on [`InvoiceStatus::Settled`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvoiceStatus {
    /// Created; no sufficient payment detected yet (never grants).
    Pending,
    /// Payment seen, but not yet at the operator's required finality (never grants).
    Detected,
    /// Paid IN FULL and finalized to the operator's confirmation policy — the
    /// ONLY status that grants a registration.
    ///
    /// ADAPTER CONTRACT: map a processor status to `Settled` **only** when the
    /// invoice is paid in full (never on a partial / tolerance / underpayment).
    /// The gate does not re-verify the paid amount — it trusts this invariant,
    /// because the amount is server-set at mint and the invoice row is the
    /// binding anchor. (BTCPay upholds it: it reports `Settled` only on full
    /// payment.) A future underpayment-settling processor MUST enforce the amount
    /// in its adapter before returning `Settled`.
    Settled,
    /// Expired unpaid, paid too late, or voided (never grants).
    Expired,
    /// Marked invalid by the processor/operator (never grants).
    Invalid,
}

/// A request to create a registration-payment invoice.
pub struct InvoiceRequest {
    /// Price to charge, as a decimal string (no float math end-to-end).
    pub amount: String,
    /// Currency of `amount` (e.g. `"XMR"`, or a fiat code the processor converts).
    pub currency: String,
    /// The operator's confirmations-to-finalize. The adapter maps it onto the
    /// processor's own finality control (BTCPay `speedPolicy`, etc.); a future
    /// zero-conf rail (Lightning) simply ignores it.
    pub confirmations: u32,
    /// The registrant identity this invoice binds to (hex `pubkey_hash`). Set as
    /// processor-side metadata for traceability; the binding OF RECORD is the
    /// `payment_invoices` row the caller writes.
    pub bind: String,
    /// Invoice lifetime (minutes) before it expires unpaid.
    pub expires_minutes: u32,
}

/// A processor-neutral invoice.
#[derive(Debug, Clone)]
pub struct Invoice {
    /// The processor's opaque invoice id — the binding key the caller persists.
    pub id: String,
    /// Where the payer sends funds (a hosted checkout URL, or an address).
    pub pay_to: String,
    pub status: InvoiceStatus,
    /// The identity echoed back from processor metadata, if present.
    /// Defense-in-depth only; the `payment_invoices` row is the binding authority.
    pub bind: Option<String>,
}

/// A pluggable, non-custodial payment processor backing the pay-to-register gate.
#[async_trait]
pub trait PaymentProvider: Send + Sync {
    /// The adapter kind, persisted on the invoice row (e.g. `"btcpay"`).
    fn kind(&self) -> &'static str;

    /// Create an invoice for `req`. The returned [`Invoice::id`] is the binding
    /// key the caller must persist.
    async fn create_invoice(&self, req: &InvoiceRequest) -> Result<Invoice, AppError>;

    /// Fetch an invoice's current state from the processor — the source of truth
    /// for the grant decision.
    async fn get_invoice(&self, id: &str) -> Result<Invoice, AppError>;
}

/// Build the configured payment provider, or `None` when the pay-to-register
/// gate is off. Fail-closed: an unknown provider kind aborts startup (config
/// validation already rejects it when the gate is on, so this is defensive).
pub fn from_config(cfg: &Config) -> Result<Option<Arc<dyn PaymentProvider>>, AppError> {
    let p = &cfg.registration.payment;
    // Build the provider when the pay-to-register gate OR the premium tier needs
    // it (premium reuses the same processor for its recurring invoices).
    if !p.require_payment && !cfg.premium.enabled {
        return Ok(None);
    }
    let provider: Arc<dyn PaymentProvider> = match p.provider.as_str() {
        "btcpay" => Arc::new(BtcPayProvider::new(p)?),
        other => {
            return Err(AppError::ConfigError(format!(
                "unsupported payment provider: {other}"
            )))
        }
    };
    Ok(Some(provider))
}

/// One way to pay for premium: a processor plus the assets it takes.
#[derive(Clone)]
pub struct PaymentRail {
    pub provider: Arc<dyn PaymentProvider>,
    /// Asset codes as the wallet should label them.
    pub assets: Vec<String>,
}

impl PaymentRail {
    pub fn kind(&self) -> &'static str {
        self.provider.kind()
    }
}

/// Every processor premium may invoice through, primary first.
///
/// The primary is the same provider the registration gate uses, so an instance
/// with no checkout rails behaves exactly as before. Rails are looked up by the
/// kind persisted on the invoice row, so an invoice is always polled at the
/// processor that minted it, never at whichever one is first today.
#[derive(Clone, Default)]
pub struct PaymentRails {
    rails: Vec<PaymentRail>,
}

impl PaymentRails {
    /// The rails in advertisement order, primary first.
    pub fn all(&self) -> &[PaymentRail] {
        &self.rails
    }

    /// The rail a new invoice uses: the one named, or the primary when none is.
    /// An unknown name is refused rather than defaulted, so a client that asked
    /// for Monero is never silently handed a Bitcoin invoice.
    pub fn select(&self, kind: Option<&str>) -> Option<&PaymentRail> {
        match kind {
            None => self.rails.first(),
            Some(k) => self.rails.iter().find(|r| r.kind() == k),
        }
    }

    /// The rail that minted a stored invoice.
    pub fn for_invoice(&self, provider_kind: &str) -> Option<&PaymentRail> {
        self.rails.iter().find(|r| r.kind() == provider_kind)
    }
}

/// Build premium's rails: the primary provider (if any) followed by each
/// configured checkout rail. Empty when premium is off.
pub fn rails_from_config(
    cfg: &Config,
    primary: Option<&Arc<dyn PaymentProvider>>,
) -> Result<PaymentRails, AppError> {
    if !cfg.premium.enabled {
        return Ok(PaymentRails::default());
    }
    let mut rails = Vec::new();
    if let Some(p) = primary {
        rails.push(PaymentRail {
            provider: Arc::clone(p),
            assets: cfg.premium.primary_assets.clone(),
        });
    }
    for rail in &cfg.premium.rails {
        rails.push(PaymentRail {
            provider: Arc::new(BtcPayProvider::checkout_rail(rail)?),
            assets: vec![rail.asset.to_string()],
        });
    }
    Ok(PaymentRails { rails })
}

#[cfg(test)]
mod rail_tests {
    use super::*;

    struct Fake(&'static str);

    #[async_trait]
    impl PaymentProvider for Fake {
        fn kind(&self) -> &'static str {
            self.0
        }
        async fn create_invoice(&self, _: &InvoiceRequest) -> Result<Invoice, AppError> {
            unreachable!()
        }
        async fn get_invoice(&self, _: &str) -> Result<Invoice, AppError> {
            unreachable!()
        }
    }

    fn rails(kinds: &[&'static str]) -> PaymentRails {
        PaymentRails {
            rails: kinds
                .iter()
                .map(|k| PaymentRail {
                    provider: Arc::new(Fake(k)),
                    assets: vec![],
                })
                .collect(),
        }
    }

    #[test]
    fn no_choice_means_the_primary() {
        let r = rails(&["btcpay", "xmrcheckout"]);
        assert_eq!(r.select(None).map(|x| x.kind()), Some("btcpay"));
    }

    #[test]
    fn an_unknown_rail_is_refused_not_defaulted() {
        // Asking for a coin this instance cannot take must not quietly mint an
        // invoice in a different coin.
        let r = rails(&["btcpay", "xmrcheckout"]);
        assert!(r.select(Some("wowcheckout")).is_none());
    }

    #[test]
    fn an_invoice_is_polled_where_it_was_minted() {
        let r = rails(&["btcpay", "xmrcheckout", "wowcheckout"]);
        for k in ["btcpay", "xmrcheckout", "wowcheckout"] {
            assert_eq!(r.for_invoice(k).map(|x| x.kind()), Some(k));
        }
        assert!(r.for_invoice("retired-processor").is_none());
    }
}
