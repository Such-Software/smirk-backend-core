//! Emit the OpenAPI 3 specification to stdout.
//!
//! The spec is derived from the handlers (`utoipa` annotations) and is the
//! single source of truth for the API contract and the generated TypeScript
//! client. Regenerate the committed contract with:
//!
//!     cargo run --bin gen_openapi > openapi.json
//!
//! CI regenerates and diffs against the committed `openapi.json`; a drift is a
//! failed build, not a stale doc.

use smirk_backend_core::api::openapi::ApiDoc;
use utoipa::OpenApi;

fn main() {
    let spec = ApiDoc::openapi()
        .to_pretty_json()
        .expect("serialize OpenAPI spec");
    println!("{spec}");
}
