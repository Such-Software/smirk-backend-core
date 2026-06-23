//! Core business logic: pure logic with no inbound I/O dependencies.
//!
//! Functions take their inputs (config, decoded bytes) as parameters, keeping
//! this layer straightforward to test in isolation.

pub mod crypto;
pub mod pow;
pub mod secret;
pub mod session;

// address and grin_confirmation are wired in as they land.
