//! Pay-to-register payment-invoice queries — one composable registration gate.
//!
//! Binds a processor invoice id to the registrant `pubkey_hash` it was created
//! for, and enforces **atomic single-use** on redemption: the grant path
//! consumes the row with a single-statement `UPDATE ... WHERE consumed_at IS
//! NULL AND pubkey_hash = $ ... RETURNING`, so two concurrent completions of the
//! same settled invoice can never both grant. Only public data lives here (the
//! opaque invoice id, the identity it binds, the price) — never funds or keys.

use chrono::{DateTime, Utc};
use tracing::instrument;

use crate::error::AppError;

use super::Database;

/// A persisted payment invoice: its binding and single-use state.
#[derive(Debug, Clone)]
pub struct PaymentInvoiceRow {
    pub invoice_id: String,
    pub pubkey_hash: String,
    pub amount: String,
    pub currency: String,
    /// `None` while unspent; set once when the invoice grants a registration.
    pub consumed_at: Option<DateTime<Utc>>,
}

impl Database {
    /// Record a freshly-created invoice, bound to `pubkey_hash`. A duplicate
    /// `invoice_id` (astronomically unlikely for a processor UUID) is a
    /// unique-violation error.
    #[instrument(skip(self))]
    pub async fn insert_payment_invoice(
        &self,
        invoice_id: &str,
        pubkey_hash: &str,
        provider: &str,
        amount: &str,
        currency: &str,
    ) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO payment_invoices (invoice_id, pubkey_hash, provider, amount, currency) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(invoice_id)
        .bind(pubkey_hash)
        .bind(provider)
        .bind(amount)
        .bind(currency)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Fetch an invoice by id (its binding + consumed state), or `None`.
    #[instrument(skip(self))]
    pub async fn get_payment_invoice(
        &self,
        invoice_id: &str,
    ) -> Result<Option<PaymentInvoiceRow>, AppError> {
        let row = sqlx::query_as::<_, (String, String, String, String, Option<DateTime<Utc>>)>(
            "SELECT invoice_id, pubkey_hash, amount, currency, consumed_at \
             FROM payment_invoices WHERE invoice_id = $1",
        )
        .bind(invoice_id)
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(
            |(invoice_id, pubkey_hash, amount, currency, consumed_at)| PaymentInvoiceRow {
                invoice_id,
                pubkey_hash,
                amount,
                currency,
                consumed_at,
            },
        ))
    }

    /// Atomically consume a single-use invoice bound to `pubkey_hash`. Returns
    /// `true` iff THIS call consumed a still-unspent, correctly-bound row. The
    /// `WHERE consumed_at IS NULL AND pubkey_hash = $` predicate + `RETURNING`
    /// make check-and-consume one statement, so concurrent completions race
    /// safely — exactly one wins, and an invoice bound to a different identity is
    /// never consumable here.
    #[instrument(skip(self))]
    pub async fn consume_payment_invoice(
        &self,
        invoice_id: &str,
        pubkey_hash: &str,
    ) -> Result<bool, AppError> {
        let consumed = sqlx::query_scalar::<_, String>(
            "UPDATE payment_invoices SET consumed_at = NOW() \
             WHERE invoice_id = $1 AND pubkey_hash = $2 AND consumed_at IS NULL \
             RETURNING invoice_id",
        )
        .bind(invoice_id)
        .bind(pubkey_hash)
        .fetch_optional(self.pool())
        .await?;
        Ok(consumed.is_some())
    }
}
