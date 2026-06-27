//! DHCP server foundation (data model, codecs, and the lease engine).
//!
//! Phase 1 is a pure, socket-free core: it parses and builds DHCPv4/DHCPv6
//! messages, encodes typed options to wire bytes, and decides address
//! allocation from in-memory data. No sockets are bound and no serving loop
//! lives here — later phases wire this into the network stack.

// Phase 1 ships the data model, codecs, and lease engine ahead of the serving
// loop that will consume them, so much of this API has no in-crate caller yet.
// The unit tests exercise every item; the allow keeps the staged foundation
// warning-free until the serving phase wires it in.
#![allow(dead_code)]

pub mod lease;
pub mod options;
pub mod server;
pub mod v4;
pub mod v6;
