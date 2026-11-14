//! Fixed capacities. Every array in the engine is sized from these constants,
//! so the worst-case stack use is known at compile time.

/// Maximum signer (issuer) messages in one signature.
pub const MAX_SIGNER_MESSAGES: usize = 32;
/// Maximum messages committed by the holder for blind signing.
pub const MAX_BLIND_MESSAGES: usize = 16;
/// Maximum scalars covered by one signature: signer messages, the prover
/// blind and the committed messages.
pub const MAX_MESSAGES: usize = MAX_SIGNER_MESSAGES + 1 + MAX_BLIND_MESSAGES;
/// Generators: Q_1 plus one per message (blind: plus Q_2).
pub const MAX_GENERATORS: usize = MAX_MESSAGES + 2;
/// Random scalars for one proof: 5 + undisclosed + 2 * committed.
pub const MAX_RANDOM: usize = 5 + 3 * MAX_MESSAGES;
/// Longest header, presentation header or single message accepted.
pub const MAX_OCTETS: usize = 1 << 16;
