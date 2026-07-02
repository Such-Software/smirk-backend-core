//! Premium (subscription) invoice queries — the recurring counterpart to
//! `payment_invoices`. Binds a processor invoice id to the authenticated
//! `user_id` it was minted for and the plan's `period_days`, and enforces
//! **atomic single-use** on redemption (the same single-statement
//! `UPDATE ... WHERE consumed_at IS NULL ... RETURNING`, so two concurrent
//! completions can never both extend). Only public data lives here — never
//! funds or keys.

use chrono::{DateTime, Utc};
use tracing::instrument;
use uuid::Uuid;

use crate::error::AppError;

use super::Database;

/// A persisted premium invoice: its binding, plan, and single-use state.
#[derive(Debug, Clone)]
pub struct PremiumInvoiceRow {
    pub invoice_id: String,
    pub user_id: Uuid,
    pub plan_id: String,
    pub period_days: i32,
    pub amount: String,
    pub currency: String,
    /// `None` while unspent; set once when the invoice extends premium.
    pub consumed_at: Option<DateTime<Utc>>,
}

impl Database {
    /// Record a freshly-created premium invoice, bound to `user_id` + its plan.
    #[instrument(skip(self))]
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_premium_invoice(
        &self,
        invoice_id: &str,
        user_id: Uuid,
        provider: &str,
        plan_id: &str,
        period_days: i32,
        amount: &str,
        currency: &str,
    ) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO premium_invoices \
             (invoice_id, user_id, provider, plan_id, period_days, amount, currency) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(invoice_id)
        .bind(user_id)
        .bind(provider)
        .bind(plan_id)
        .bind(period_days)
        .bind(amount)
        .bind(currency)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Fetch a premium invoice by id (binding + plan + consumed state), or `None`.
    #[instrument(skip(self))]
    pub async fn get_premium_invoice(
        &self,
        invoice_id: &str,
    ) -> Result<Option<PremiumInvoiceRow>, AppError> {
        let row = sqlx::query_as::<
            _,
            (
                String,
                Uuid,
                String,
                i32,
                String,
                String,
                Option<DateTime<Utc>>,
            ),
        >(
            "SELECT invoice_id, user_id, plan_id, period_days, amount, currency, consumed_at \
             FROM premium_invoices WHERE invoice_id = $1",
        )
        .bind(invoice_id)
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(
            |(invoice_id, user_id, plan_id, period_days, amount, currency, consumed_at)| {
                PremiumInvoiceRow {
                    invoice_id,
                    user_id,
                    plan_id,
                    period_days,
                    amount,
                    currency,
                    consumed_at,
                }
            },
        ))
    }

    /// How many unconsumed premium invoices this user currently holds — bounds how
    /// many outstanding invoices one authenticated user can accrue at the processor
    /// (served by the partial `premium_invoices_unconsumed_idx`).
    #[instrument(skip(self))]
    pub async fn count_unconsumed_premium_invoices(&self, user_id: Uuid) -> Result<i64, AppError> {
        let n = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM premium_invoices WHERE user_id = $1 AND consumed_at IS NULL",
        )
        .bind(user_id)
        .fetch_one(self.pool())
        .await?;
        Ok(n)
    }

    /// Atomically consume a single-use premium invoice (bound to `user_id`) AND
    /// extend the user's premium window by `days`, in ONE transaction — so a
    /// transient failure between the two rolls the consume back and the user can
    /// retry, instead of burning a paid invoice with no grant. Returns the new
    /// expiry if THIS call consumed the invoice; `None` if it was already consumed
    /// or not bound to this user (neither side happens). Concurrent completions
    /// race safely on the `consumed_at IS NULL` predicate — exactly one wins.
    #[instrument(skip(self))]
    pub async fn activate_premium(
        &self,
        invoice_id: &str,
        user_id: Uuid,
        days: i32,
    ) -> Result<Option<DateTime<Utc>>, AppError> {
        let mut tx = self.pool().begin().await?;
        let consumed = sqlx::query_scalar::<_, String>(
            "UPDATE premium_invoices SET consumed_at = NOW() \
             WHERE invoice_id = $1 AND user_id = $2 AND consumed_at IS NULL \
             RETURNING invoice_id",
        )
        .bind(invoice_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
        if consumed.is_none() {
            tx.rollback().await?;
            return Ok(None);
        }
        let until = sqlx::query_scalar::<_, DateTime<Utc>>(
            "UPDATE users SET \
               premium_until = GREATEST(COALESCE(premium_until, NOW()), NOW()) \
                             + make_interval(days => $2), \
               updated_at = NOW() \
             WHERE id = $1 RETURNING premium_until",
        )
        .bind(user_id)
        .bind(days)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Some(until))
    }
}
