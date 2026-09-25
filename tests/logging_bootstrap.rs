//! The log filter must be built AFTER the environment it reads.
//!
//! `tracing_subscriber::fmt::init()` builds its `EnvFilter` from `RUST_LOG` at
//! the moment it is called. The systemd unit deliberately sets no
//! `EnvironmentFile`, so `RUST_LOG` reaches the process only when `dotenv` has
//! loaded `.env`. Initialising the subscriber first therefore leaves the filter
//! with no directive, and its default is ERROR: every `info!` and `warn!` the
//! binary emits is dropped, silently and in production only, since a developer
//! running with `RUST_LOG` already exported never sees it.
//!
//! That happened. From the 2026-09-20 build until this guard, the deployed
//! backend logged nothing but errors, which also swallowed the boot lines an
//! operator reads to confirm a capability came up.
//!
//! This asserts the ordering property, not any particular spelling of the two
//! calls: it locates them by the crate each belongs to.

const MAIN: &str = include_str!("../src/main.rs");

/// Ignore comments, so prose naming a call cannot satisfy or break the check.
fn code_only(src: &str) -> String {
    src.lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn dotenv_runs_before_the_subscriber_is_built() {
    let code = code_only(MAIN);

    let dotenv = code
        .find("dotenvy::")
        .expect("main must load .env; without it RUST_LOG never reaches the process");
    let subscriber = code
        .find("tracing_subscriber::")
        .expect("main must install a tracing subscriber");

    assert!(
        dotenv < subscriber,
        "the tracing subscriber is built before dotenv loads .env, so EnvFilter \
         sees no RUST_LOG and falls back to ERROR, dropping every info! and \
         warn! in production. Move the dotenv call above it."
    );
}

#[test]
fn the_guard_can_actually_fail() {
    // A check that cannot fail proves nothing. Feed it the inverted order.
    let inverted = "tracing_subscriber::fmt::init();\nlet _ = dotenvy::dotenv();";
    let code = code_only(inverted);
    assert!(code.find("dotenvy::") > code.find("tracing_subscriber::"));
}

#[test]
fn comments_do_not_decide_the_ordering() {
    // The real main.rs carries a comment mentioning both names above the code.
    // Stripping comments must leave the calls themselves in the right order.
    let commented = "// dotenvy:: and tracing_subscriber:: explained here\n\
                     let _ = dotenvy::dotenv();\n\
                     tracing_subscriber::fmt::init();";
    let code = code_only(commented);
    assert!(code.find("dotenvy::") < code.find("tracing_subscriber::"));
}
