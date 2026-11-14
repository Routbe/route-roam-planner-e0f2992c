/**
 * SHA-384 of the committed anonymous booking engine (wasm/rout-zk, ABI 2).
 *
 * Deliberately null: no reproducible build of rout-zk exists yet. It must be
 * produced by the official rustup toolchain pinned in
 * wasm/rout-zk/rust-toolchain.toml (CI .github/workflows/wasm-reproducible.yml
 * or a local rustup build), committed together with its base64 copy in
 * zk-wasm-bytes.ts, and this pin set in the same change. While it is null the
 * loader refuses before reading any bytes, so there is no fallback path.
 */
export const ROUT_ZK_WASM_SHA384: string | null = null;
