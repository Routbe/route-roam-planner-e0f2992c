/**
 * FIDO Alliance Metadata Service v3 (Stap 5): download, verify and cache the
 * MDS3 BLOB, and look up one authenticator by AAGUID.
 *
 * Trust chain: the BLOB is a JWS whose x5c chain must end in a pinned FIDO
 * root (GlobalSign Root CA - R3, SHA-256 pinned below; the library's copy is
 * refused if it does not hash to the pin). Path validation, CRL checks and
 * the JWS signature use @simplewebauthn/server's verifyMDSBlob; on top of it
 * this module enforces:
 *   - alg allow-list (RS256 / ES256) before anything is parsed further;
 *   - a hard size limit and fetch time-out;
 *   - a BLOB serial `no` that never goes down within this runtime;
 *   - nextUpdate not more than MAX_STALE_DAYS in the past.
 *
 * Cache: verified metadata lives in memory for CACHE_TTL_MS, then the next
 * lookup refreshes it. A failed refresh keeps the previous verified BLOB for at
 * most FALLBACK_MS after it was verified; after that every lookup answers
 * "unavailable", never "attested". Per worker instance: a cold start refetches.
 *
 * Nothing here can block a registration: callers treat "unavailable" as
 * "not attested".
 */
import { SettingsService } from "@simplewebauthn/server";
import { verifyMDSBlob } from "@simplewebauthn/server/helpers";
import { GlobalSign_Root_CA_R3 } from "./fido-mds3-roots";
import { ROOT_PINS } from "./fido-root-pins";
import { pemSha256Hex } from "./fido-pem";

export const MDS3_URL = "https://mds3.fidoalliance.org/";
/** SHA-256 of the DER of GlobalSign Root CA - R3 (FIDO MDS3 root). */
export const FIDO_MDS_ROOT_SHA256: string = ROOT_PINS.mds[0];
export const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
export const FALLBACK_MS = 7 * 24 * 60 * 60 * 1000;
export const MAX_BLOB_BYTES = 16 * 1024 * 1024;
export const FETCH_TIMEOUT_MS = 20_000;
const MAX_STALE_DAYS = 31;
const ALLOWED_ALGS = new Set(["RS256", "ES256"]);

export type Mds3StatusReport = {
  status: string;
  effectiveDate?: string;
  authenticatorVersion?: number;
  certificationDescriptor?: string;
  certificateNumber?: string;
};

export type Mds3Statement = {
  aaguid?: string;
  description?: string;
  keyProtection?: string[];
  attestationTypes?: string[];
  attestationRootCertificates?: string[];
  authenticatorGetInfo?: { certifications?: Record<string, number> } & Record<string, unknown>;
} & Record<string, unknown>;

export type Mds3Entry = {
  aaguid: string;
  statement: Mds3Statement;
  statusReports: readonly Mds3StatusReport[];
};

export type Mds3Snapshot = {
  no: number;
  nextUpdate: string;
  verifiedAt: number;
  entries: ReadonlyMap<string, Mds3Entry>;
  /** Raw statements for MetadataService (chain roots per authenticator). */
  statements: readonly Mds3Statement[];
};

export class Mds3Error extends Error {
  constructor(public readonly code: string) {
    super(`mds3_${code}`);
    this.name = "Mds3Error";
  }
}

function b64uJson(segment: string): unknown {
  const pad = segment.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(pad + "===".slice((pad.length + 3) % 4));
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
}

/** Checks the JWS header before the library touches the token. */
export function checkBlobHeader(jwt: string): void {
  const parts = jwt.split(".");
  if (parts.length !== 3 || parts.some((p) => !/^[A-Za-z0-9_-]+$/.test(p))) throw new Mds3Error("malformed");
  let header: unknown;
  try {
    header = b64uJson(parts[0]!);
  } catch {
    throw new Mds3Error("malformed");
  }
  const h = header as { alg?: unknown; x5c?: unknown; typ?: unknown };
  if (typeof h.alg !== "string" || !ALLOWED_ALGS.has(h.alg)) throw new Mds3Error("alg_not_allowed");
  if (!Array.isArray(h.x5c) || h.x5c.length < 1 || h.x5c.length > 5 || !h.x5c.every((c) => typeof c === "string" && c.length < 8192)) {
    throw new Mds3Error("x5c_invalid");
  }
}

let pinnedRootsChecked = false;
/** Installs only the pinned FIDO root for MDS verification; refuses a swapped library root. */
export function installPinnedMdsRoot(rootPem: string = GlobalSign_Root_CA_R3, expectedSha256: string = FIDO_MDS_ROOT_SHA256): void {
  if (pemSha256Hex(rootPem) !== expectedSha256) throw new Mds3Error("root_pin_mismatch");
  SettingsService.setRootCertificates({ identifier: "mds", certificates: [rootPem] });
  pinnedRootsChecked = true;
}

type Payload = { no?: unknown; nextUpdate?: unknown; entries?: unknown };

/** Verifies a BLOB (chain to the pinned root, CRLs, signature) and builds the AAGUID index. */
export async function verifyMds3Blob(
  jwt: string,
  opts: { now?: number; lastNo?: number | null; rootPem?: string; rootSha256?: string } = {},
): Promise<Mds3Snapshot> {
  const now = opts.now ?? Date.now();
  checkBlobHeader(jwt);
  installPinnedMdsRoot(opts.rootPem, opts.rootSha256);
  let payload: Payload;
  try {
    payload = (await verifyMDSBlob(jwt)).payload as Payload;
  } catch {
    throw new Mds3Error("signature_or_chain");
  }
  if (typeof payload.no !== "number" || !Number.isSafeInteger(payload.no) || payload.no < 1) throw new Mds3Error("serial_invalid");
  if (opts.lastNo != null && payload.no < opts.lastNo) throw new Mds3Error("serial_went_down");
  if (typeof payload.nextUpdate !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(payload.nextUpdate)) throw new Mds3Error("next_update_invalid");
  const next = Date.parse(`${payload.nextUpdate}T00:00:00Z`);
  if (!Number.isFinite(next) || now - next > MAX_STALE_DAYS * 86_400_000) throw new Mds3Error("blob_stale");
  if (!Array.isArray(payload.entries)) throw new Mds3Error("entries_invalid");

  const entries = new Map<string, Mds3Entry>();
  const statements: Mds3Statement[] = [];
  for (const raw of payload.entries as unknown[]) {
    const e = raw as { aaguid?: unknown; metadataStatement?: unknown; statusReports?: unknown };
    if (typeof e.aaguid !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(e.aaguid)) continue;
    if (!e.metadataStatement || typeof e.metadataStatement !== "object") continue;
    const aaguid = e.aaguid.toLowerCase();
    const reports = Array.isArray(e.statusReports)
      ? (e.statusReports as unknown[]).filter((r): r is Mds3StatusReport => !!r && typeof (r as { status?: unknown }).status === "string")
      : [];
    const statement = e.metadataStatement as Mds3Statement;
    entries.set(aaguid, { aaguid, statement, statusReports: reports });
    statements.push(statement);
  }
  return { no: payload.no, nextUpdate: payload.nextUpdate, verifiedAt: now, entries, statements };
}

/** Bounded download: time-out, https only, no redirects to elsewhere, size cap. */
export async function fetchMds3Blob(fetchImpl: typeof fetch = fetch, url: string = MDS3_URL): Promise<string> {
  if (!url.startsWith("https://")) throw new Mds3Error("url_not_https");
  const res = await fetchImpl(url, { redirect: "error", signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  if (!res.ok || !res.body) throw new Mds3Error("download_failed");
  const declared = Number(res.headers.get("content-length") ?? "0");
  if (declared > MAX_BLOB_BYTES) throw new Mds3Error("too_large");
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_BLOB_BYTES) {
      await reader.cancel();
      throw new Mds3Error("too_large");
    }
    chunks.push(value);
  }
  const all = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    all.set(c, off);
    off += c.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(all).trim();
}

export type Mds3Deps = { fetchImpl?: typeof fetch; now?: () => number; url?: string };

/** In-memory MDS3 cache with TTL, monotonic serial and bounded fallback. */
export class Mds3Cache {
  private snapshot: Mds3Snapshot | null = null;
  private loadedAt = 0;
  private inflight: Promise<Mds3Snapshot | null> | null = null;
  constructor(private readonly deps: Mds3Deps = {}) {}

  private now(): number {
    return this.deps.now ? this.deps.now() : Date.now();
  }

  /** The verified snapshot, refreshed when older than the TTL; null when none is usable. */
  async current(): Promise<Mds3Snapshot | null> {
    const now = this.now();
    if (this.snapshot && now - this.loadedAt < CACHE_TTL_MS) return this.snapshot;
    this.inflight ??= this.refresh().finally(() => {
      this.inflight = null;
    });
    return this.inflight;
  }

  private async refresh(): Promise<Mds3Snapshot | null> {
    const now = this.now();
    try {
      const jwt = await fetchMds3Blob(this.deps.fetchImpl, this.deps.url);
      const fresh = await verifyMds3Blob(jwt, { now, lastNo: this.snapshot?.no ?? null });
      this.snapshot = fresh;
      this.loadedAt = now;
      return fresh;
    } catch (err) {
      console.warn("[mds3] refresh failed", err instanceof Mds3Error ? err.code : "error");
      if (this.snapshot && now - this.snapshot.verifiedAt <= FALLBACK_MS) return this.snapshot;
      this.snapshot = null;
      return null;
    }
  }

  /** Test seam: install an already verified snapshot. */
  prime(snapshot: Mds3Snapshot, loadedAt: number = this.now()): void {
    if (this.snapshot && snapshot.no < this.snapshot.no) throw new Mds3Error("serial_went_down");
    this.snapshot = snapshot;
    this.loadedAt = loadedAt;
  }
}

let shared: Mds3Cache | null = null;
export function mds3(): Mds3Cache {
  shared ??= new Mds3Cache();
  return shared;
}

export function lookupAaguid(snapshot: Mds3Snapshot | null, aaguid: string): Mds3Entry | null {
  if (!snapshot) return null;
  return snapshot.entries.get(aaguid.toLowerCase()) ?? null;
}

export const __pinnedRootsChecked = () => pinnedRootsChecked;
