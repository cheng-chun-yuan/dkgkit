//! Live Nostr relay transport (feature `live`).
//!
//! Bridges the synchronous `Transport` trait to the async `nostr-sdk` client via
//! a dedicated background thread that owns a current-thread tokio runtime.

// Placeholder re-export targets; filled in by later tasks.
pub use placeholder::*;

mod placeholder {
    /// Removed in Task 4 when the real types land.
    pub struct ParticipantDirectory;
    pub struct LiveNostrTransportConfig;
    pub struct LiveNostrTransport;
}
