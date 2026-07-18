// Admin login = a NIP-98 kind-27235 "signed action" over a server-issued nonce.
// The backend (admin_verify) binds SIX tags exactly once and a request-descriptor
// hash over an EMPTY body. Get any of this wrong and verify returns an opaque 401,
// so this mirrors src/core/crypto/nip98.rs precisely.

async function sha256Hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export interface Challenge {
  challenge: string;
  url: string;
  instance_id: string;
  expires_in: number;
}

/** A NIP-07 signer: `window.nostr` (Smirk / Alby / nos2x). */
export interface Nip07 {
  getPublicKey(): Promise<string>;
  signEvent(event: {
    kind: number;
    created_at: number;
    content: string;
    tags: string[][];
  }): Promise<{ id: string; pubkey: string; sig: string; [k: string]: unknown }>;
}

/**
 * Build + sign the admin_login event for a challenge and return the
 * `Nostr <base64(event)>` token the backend's `admin_token` field expects.
 */
export async function buildAdminToken(c: Challenge, signer: Nip07): Promise<string> {
  // request_descriptor("POST", "/admin/auth/verify", "", b"") then its sha256.
  const emptyBodyHash = await sha256Hex('');
  const descriptor = `POST\n/admin/auth/verify\n\n${emptyBodyHash}`;
  const payload = await sha256Hex(descriptor);

  const signed = await signer.signEvent({
    kind: 27235,
    created_at: Math.floor(Date.now() / 1000),
    content: '',
    tags: [
      ['u', c.url],
      ['method', 'POST'],
      ['purpose', 'admin_login'],
      ['challenge', c.challenge],
      ['payload', payload],
      ['instance_id', c.instance_id],
    ],
  });

  return `Nostr ${btoa(JSON.stringify(signed))}`;
}

/** The page-injected NIP-07 provider, or null. Smirk installs `window.nostr`. */
export function nip07(): Nip07 | null {
  const n = (window as unknown as { nostr?: Nip07 }).nostr;
  return n && typeof n.signEvent === 'function' ? n : null;
}
