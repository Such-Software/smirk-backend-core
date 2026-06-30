//! Core business logic: pure logic with no inbound I/O dependencies.
//!
//! Functions take their inputs (config, decoded bytes) as parameters, keeping
//! this layer straightforward to test in isolation.

pub mod admin_session;
pub mod crypto;
pub mod invite;
pub mod pow;
pub mod restore_pow;
pub mod secret;
pub mod session;

// address and grin_confirmation are wired in as they land.
