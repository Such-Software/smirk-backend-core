// Fetch layer for the /admin JSON API. Same-origin (the SPA is served from the admin
// plane), bearer access token held in memory only (never localStorage). Admin routes
// are outside the public OpenAPI, so this is hand-written.

let accessToken: string | null = null;

export function setToken(t: string | null): void {
  accessToken = t;
}
export function hasToken(): boolean {
  return accessToken !== null;
}

async function req(method: string, path: string, body?: unknown): Promise<unknown> {
  const headers: Record<string, string> = {};
  if (accessToken) headers['Authorization'] = `Bearer ${accessToken}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(path, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  const data: unknown = text ? JSON.parse(text) : null;
  if (!res.ok) {
    const msg =
      (data as { error?: string; message?: string })?.error ??
      (data as { message?: string })?.message ??
      `${res.status} ${res.statusText}`;
    throw new Error(msg);
  }
  return data;
}

export interface ChallengeResp {
  challenge: string;
  url: string;
  instance_id: string;
  expires_in: number;
}
export interface TokenResp {
  access_token: string;
  refresh_token?: string;
  expires_in: number;
}
export interface KeyRow {
  id: string;
  pubkey: string;
  status: string;
}
export interface InviteView {
  code_prefix: string;
  label: string | null;
  created_at: string;
  status: string;
}

export const api = {
  // POST (not GET): issuing a single-use nonce is a write, and must never be
  // cached or prefetched. Matches the route wired in src/api/admin.rs.
  challenge: () => req('POST', '/admin/auth/challenge', {}) as Promise<ChallengeResp>,
  verify: (admin_token: string, challenge: string) =>
    req('POST', '/admin/auth/verify', { admin_token, challenge }) as Promise<TokenResp>,
  logout: () => req('POST', '/admin/auth/logout', {}),
  me: () => req('GET', '/admin/me'),
  features: () => req('GET', '/admin/features'),
  // The backend wraps the list as {keys:[...]} (KeysListResponse); unwrap here so
  // callers get the array they expect (KeysTab maps over it directly).
  keys: () => req('GET', '/admin/keys').then((r) => (r as { keys: KeyRow[] }).keys),
  addKey: (pubkey: string, label?: string) =>
    req('POST', '/admin/keys', label ? { pubkey, label } : { pubkey }),
  revokeKey: (id: string) => req('DELETE', `/admin/keys/${id}`),
  config: () => req('GET', '/admin/config'),
  putConfig: (patch: unknown, expected_versions: Record<string, number>) =>
    req('PUT', '/admin/config', { patch, expected_versions }),
  invites: () =>
    req('GET', '/admin/invites') as Promise<{ invites: InviteView[]; unused_count: number }>,
  mintInvites: (count: number, label?: string) =>
    req('POST', '/admin/invites', label ? { count, label } : { count }) as Promise<{
      codes: string[];
    }>,
};
