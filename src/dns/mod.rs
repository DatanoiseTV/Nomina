//! DNS serving: the request handler, upstream resolution, the shared resolve
//! core, the DoH endpoint, and socket bootstrap.

pub mod doh;
pub mod handler;
pub mod resolve;
pub mod server;
pub mod upstream;
