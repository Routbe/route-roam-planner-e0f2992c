/**
 * SHA-384 of the committed OPAQUE + Argon2id + Shamir (ABI 2) engine
 * (src/lib/crypto-enclave/wasm/rout-opaque.wasm), built deterministically by
 * wasm/rout-opaque/build.sh (official rustup rustc 1.95.0 with LLVM 22.1.2, Cargo.lock). The loader refuses any
 * other bytes before compiling; CI rebuilds from source and compares (F.2).
 */
export const ROUT_OPAQUE_WASM_SHA384 = "c9cbf4844f84f2aad704e43ad199c873955da50c2676ae781155d20650462649fb4ec34a80fdd08dca8ee291c0eee168";
