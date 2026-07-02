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
