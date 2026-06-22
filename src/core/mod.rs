//! Core business logic: pure logic with no inbound I/O dependencies.
//!
//! Functions take their inputs (config, decoded bytes) as parameters, keeping
//! this layer straightforward to test in isolation.

pub mod crypto;

// session, pow, address, and grin_confirmation are wired in as they land.
