import { render } from 'preact';
import { useEffect, useState } from 'preact/hooks';
import './tokens.css';
import { api, setToken, type KeyRow, type InviteView } from './api';
import { buildAdminToken, nip07 } from './nip98';

// ── login ─────────────────────────────────────────────────────────────────────

function Login({ onDone }: { onDone: () => void }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const signIn = async () => {
    setBusy(true);
    setErr(null);
    try {
      const signer = nip07();
      if (!signer) {
        throw new Error(
          'No NIP-07 signer found. Enable your Smirk wallet (or nos2x/Alby) on this origin, then reload.',
        );
      }
      const c = await api.challenge();
      const token = await buildAdminToken(c, signer);
      const { access_token } = await api.verify(token, c.challenge);
      setToken(access_token);
      onDone();
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Sign-in failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div style={{ maxWidth: 420, margin: '12vh auto', padding: 24, textAlign: 'center' }}>
      <div style={{ fontSize: 40 }}>🐸</div>
      <h1>Smirk Operator Console</h1>
      <p style={{ color: 'var(--smirk-fg-muted)' }}>
        Sign in with an admin Nostr key on your instance's allowlist.
      </p>
      <button class="primary" style={{ padding: '12px 20px', fontSize: 16 }} disabled={busy} onClick={signIn}>
        {busy ? 'Signing in…' : 'Sign in with Smirk'}
      </button>
      {err && <p style={{ color: 'var(--smirk-danger)', marginTop: 16 }}>{err}</p>}
    </div>
  );
}

// ── shared ────────────────────────────────────────────────────────────────────

function Section({ title, children }: { title: string; children: unknown }) {
  return (
    <div
      style={{
        background: 'var(--smirk-bg-elevated)',
        border: '1px solid var(--smirk-border)',
        borderRadius: 'var(--smirk-radius)',
        padding: 16,
        marginBottom: 16,
      }}
    >
      <h3 style={{ marginTop: 0 }}>{title}</h3>
      {children}
    </div>
  );
}

function useAsync<T>(fn: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const reload = () => {
    setErr(null);
    fn()
      .then(setData)
      .catch((e) => setErr(e instanceof Error ? e.message : String(e)));
  };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(reload, deps);
  return { data, err, reload };
}

// ── status ────────────────────────────────────────────────────────────────────

function StatusTab() {
  const { data, err } = useAsync(() => api.features());
  return (
    <Section title="Instance features">
      {err && <p style={{ color: 'var(--smirk-danger)' }}>{err}</p>}
      <pre style={{ overflow: 'auto', fontSize: 12 }}>{JSON.stringify(data, null, 2)}</pre>
    </Section>
  );
}

// ── admin keys ────────────────────────────────────────────────────────────────

function KeysTab() {
  const { data, err, reload } = useAsync(() => api.keys());
  const [pubkey, setPubkey] = useState('');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  const add = async () => {
    setBusy(true);
    setMsg(null);
    try {
      await api.addKey(pubkey.trim().toLowerCase());
      setPubkey('');
      reload();
    } catch (e) {
      setMsg(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };
  const revoke = async (id: string) => {
    if (!confirm('Revoke this admin key?')) return;
    setMsg(null);
    try {
      await api.revokeKey(id);
      reload();
    } catch (e) {
      setMsg(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <Section title="Admin keys">
      {err && <p style={{ color: 'var(--smirk-danger)' }}>{err}</p>}
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
        <tbody>
          {(data ?? []).map((k: KeyRow) => (
            <tr style={{ borderTop: '1px solid var(--smirk-border)' }}>
              <td style={{ fontFamily: 'monospace', padding: '6px 4px' }}>{k.pubkey.slice(0, 16)}…</td>
              <td style={{ padding: '6px 4px' }}>{k.status}</td>
              <td style={{ padding: '6px 4px', textAlign: 'right' }}>
                {k.status !== 'revoked' && (
                  <button class="danger" onClick={() => revoke(k.id)}>
                    Revoke
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
        <input
          style={{ flex: 1 }}
          placeholder="new admin pubkey (64 hex)"
          value={pubkey}
          onInput={(e) => setPubkey((e.target as HTMLInputElement).value)}
        />
        <button class="primary" disabled={busy || pubkey.trim().length !== 64} onClick={add}>
          Add key
        </button>
      </div>
      {msg && <p style={{ color: 'var(--smirk-danger)' }}>{msg}</p>}
    </Section>
  );
}

// ── invites ───────────────────────────────────────────────────────────────────

function InvitesTab() {
  const { data, err, reload } = useAsync(() => api.invites());
  const [count, setCount] = useState(5);
  const [label, setLabel] = useState('');
  const [minted, setMinted] = useState<string[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  const mint = async () => {
    setBusy(true);
    setMsg(null);
    try {
      const r = await api.mintInvites(count, label.trim() || undefined);
      setMinted(r.codes);
      reload();
    } catch (e) {
      setMsg(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Section title={`Invite codes${data ? ` — ${data.unused_count} unused` : ''}`}>
      {err && <p style={{ color: 'var(--smirk-danger)' }}>{err}</p>}
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 12 }}>
        <input
          type="number"
          min={1}
          max={1000}
          style={{ width: 80 }}
          value={count}
          onInput={(e) => setCount(Number((e.target as HTMLInputElement).value))}
        />
        <input
          style={{ flex: 1 }}
          placeholder="label (optional)"
          value={label}
          onInput={(e) => setLabel((e.target as HTMLInputElement).value)}
        />
        <button class="primary" disabled={busy || count < 1} onClick={mint}>
          Mint
        </button>
      </div>
      {msg && <p style={{ color: 'var(--smirk-danger)' }}>{msg}</p>}
      {minted && (
        <div style={{ background: 'var(--smirk-bg-sunken)', padding: 12, borderRadius: 8, marginBottom: 12 }}>
          <b>New codes — copy now, they are shown once:</b>
          <pre style={{ margin: '6px 0 0', whiteSpace: 'pre-wrap' }}>{minted.join('\n')}</pre>
        </div>
      )}
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
        <tbody>
          {(data?.invites ?? []).map((i: InviteView) => (
            <tr style={{ borderTop: '1px solid var(--smirk-border)' }}>
              <td style={{ fontFamily: 'monospace', padding: '6px 4px' }}>{i.code_prefix}…</td>
              <td style={{ padding: '6px 4px' }}>{i.label ?? ''}</td>
              <td style={{ padding: '6px 4px', color: 'var(--smirk-fg-muted)' }}>{i.created_at.slice(0, 10)}</td>
              <td style={{ padding: '6px 4px' }}>{i.status}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Section>
  );
}

// ── config ────────────────────────────────────────────────────────────────────

type Overlay = Record<string, Record<string, unknown>>;
interface ConfigResp {
  effective: Overlay;
  overlay: Overlay;
  versions: Record<string, number>;
  runtime_class: Record<string, string>;
  restart_pending: boolean;
}

function ConfigTab() {
  const { data, err, reload } = useAsync(() => api.config() as Promise<ConfigResp>);
  const [edit, setEdit] = useState<Overlay>({});
  const [msg, setMsg] = useState<string | null>(null);

  useEffect(() => {
    if (!data) return;
    // Seed edit state for sections we are NOT already editing, and preserve
    // in-progress edits — a reload after saving one section must not discard
    // unsaved edits in the others.
    setEdit((prev) => {
      const next = { ...prev };
      for (const section of Object.keys(data.effective)) {
        if (!(section in next)) next[section] = structuredClone(data.effective[section]);
      }
      return next;
    });
  }, [data]);

  if (err) return <Section title="Config">{<p style={{ color: 'var(--smirk-danger)' }}>{err}</p>}</Section>;
  if (!data) return <Section title="Config">Loading…</Section>;

  const setField = (section: string, field: string, value: unknown) =>
    setEdit((e) => ({ ...e, [section]: { ...(e[section] ?? {}), [field]: value } }));

  const save = async (section: string) => {
    setMsg(null);
    // Send ONLY the fields that actually changed. Sending the whole section makes the
    // backend count every populated field as "touched" — spuriously flagging a restart
    // and pinning env-sourced values into the DB overlay.
    const orig = (data.effective[section] ?? {}) as Record<string, unknown>;
    const cur = (edit[section] ?? {}) as Record<string, unknown>;
    const patch: Record<string, unknown> = {};
    for (const k of Object.keys(cur)) {
      if (JSON.stringify(cur[k]) !== JSON.stringify(orig[k])) patch[k] = cur[k];
    }
    if (Object.keys(patch).length === 0) {
      setMsg(`No changes in ${section}.`);
      return;
    }
    try {
      await api.putConfig({ [section]: patch }, { [section]: data.versions[section] ?? 0 });
      setMsg(`Saved ${section}.`);
      reload();
    } catch (e) {
      setMsg(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <div>
      {data.restart_pending && (
        <div
          style={{
            background: 'rgba(245,158,11,0.12)',
            border: '1px solid var(--smirk-warn)',
            borderRadius: 8,
            padding: 10,
            marginBottom: 16,
          }}
        >
          ⚠ A saved change needs a restart to take effect (systemctl restart, or auto mode).
        </div>
      )}
      {msg && <p style={{ color: 'var(--smirk-accent)' }}>{msg}</p>}
      {Object.keys(edit)
        .sort()
        .map((section) => (
          <Section title={section}>
            {Object.entries(edit[section] ?? {}).map(([field, value]) => {
              const cls = data.runtime_class[`${section}.${field}`] ?? 'restart-required';
              const overridden = data.overlay[section]?.[field] !== undefined;
              return (
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 0' }}>
                  <label style={{ flex: 1, minWidth: 0 }}>
                    {field}{' '}
                    <span style={{ fontSize: 11, color: 'var(--smirk-fg-muted)' }}>
                      · {cls === 'restart-required' ? 'restart' : 'live'}
                      {overridden ? ' · db' : ''}
                    </span>
                  </label>
                  {typeof value === 'boolean' ? (
                    <input
                      type="checkbox"
                      checked={value}
                      onChange={(e) => setField(section, field, (e.target as HTMLInputElement).checked)}
                    />
                  ) : (
                    <input
                      style={{ width: 220 }}
                      value={String(value ?? '')}
                      onInput={(e) => {
                        const v = (e.target as HTMLInputElement).value;
                        if (typeof value === 'number') {
                          // Ignore empty / non-numeric input instead of coercing to 0.
                          if (v === '') return;
                          const n = Number(v);
                          if (!Number.isNaN(n)) setField(section, field, n);
                        } else {
                          setField(section, field, v);
                        }
                      }}
                    />
                  )}
                </div>
              );
            })}
            <button class="primary" style={{ marginTop: 8 }} onClick={() => save(section)}>
              Save {section}
            </button>
          </Section>
        ))}
    </div>
  );
}

// ── shell ─────────────────────────────────────────────────────────────────────

const TABS = ['Status', 'Keys', 'Invites', 'Config'] as const;
type Tab = (typeof TABS)[number];

function Console({ onLogout }: { onLogout: () => void }) {
  const [tab, setTab] = useState<Tab>('Status');
  return (
    <div style={{ maxWidth: 760, margin: '0 auto', padding: 20 }}>
      <header style={{ display: 'flex', alignItems: 'center', marginBottom: 16 }}>
        <h2 style={{ margin: 0, flex: 1 }}>🐸 Smirk Operator Console</h2>
        <button
          onClick={() => {
            api.logout().catch(() => {});
            setToken(null);
            onLogout();
          }}
        >
          Sign out
        </button>
      </header>
      <nav style={{ display: 'flex', gap: 6, marginBottom: 16 }}>
        {TABS.map((t) => (
          <button class={t === tab ? 'primary' : ''} onClick={() => setTab(t)}>
            {t}
          </button>
        ))}
      </nav>
      {tab === 'Status' && <StatusTab />}
      {tab === 'Keys' && <KeysTab />}
      {tab === 'Invites' && <InvitesTab />}
      {tab === 'Config' && <ConfigTab />}
    </div>
  );
}

function App() {
  const [authed, setAuthed] = useState(false);
  return authed ? <Console onLogout={() => setAuthed(false)} /> : <Login onDone={() => setAuthed(true)} />;
}

render(<App />, document.getElementById('app')!);
