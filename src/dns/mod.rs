//! DNS serving: the request handler, upstream resolution, the shared resolve
//! core, the DoH endpoint, and socket bootstrap.

pub mod axfr;
pub mod cache;
pub mod conditional;
pub mod dnssec;
pub mod doh;
pub mod handler;
pub mod homograph;
pub mod resolve;
pub mod secondary;
pub mod server;
pub mod tsig;
pub mod upstream;
