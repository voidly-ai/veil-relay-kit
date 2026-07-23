import { getDb, findAgentByDid, registerAgent, getLocalAgents } from './db.js';

const PRIMARY_RELAY = process.env.PRIMARY_RELAY || 'https://api.voidly.ai';
const PEER_SECRET = process.env.RELAY_PEER_SECRET || '';
const RELAY_URL = process.env.RELAY_URL || '';
const REGION = process.env.RELAY_REGION || 'unknown';

let registered = false;

/** Register this relay node with the primary relay */
export async function registerWithPrimary(): Promise<boolean> {
  if (!PEER_SECRET || !RELAY_URL) {
    console.log('[FEDERATION] Skipping registration: RELAY_PEER_SECRET or RELAY_URL not set');
    return false;
  }

  try {
    const res = await fetch(`${PRIMARY_RELAY}/v1/relay/peers`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        relay_url: RELAY_URL,
        name: `relay-${REGION}`,
        region: REGION,
        features: ['sse', 'websocket', 'federation'],
        peer_secret: PEER_SECRET,
      }),
    });

    if (res.ok) {
      registered = true;
      console.log(`[FEDERATION] Registered with primary relay as relay-${REGION}`);
      return true;
    }

    const err = await res.text();
    console.error(`[FEDERATION] Registration failed: ${res.status} ${err}`);
    return false;
  } catch (err) {
    console.error('[FEDERATION] Registration error:', err);
    return false;
  }
}

/**
 * Push local agent identities to the primary relay.
 * The primary stores them as federated stubs so it can route messages here.
 */
export async function pushLocalIdentities(): Promise<number> {
  if (!registered || !PEER_SECRET) return 0;

  try {
    const locals = getLocalAgents();
    if (locals.length === 0) return 0;

    const agents = locals.map((a: any) => ({
      did: a.did,
      name: a.display_name,
      signing_public_key: a.signing_public_key,
      encryption_public_key: a.encryption_public_key,
      capabilities: a.capabilities ? JSON.parse(a.capabilities) : [],
    }));

    const res = await fetch(`${PRIMARY_RELAY}/v1/relay/sync/identities`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        relay_url: RELAY_URL,
        peer_secret: PEER_SECRET,
        agents,
      }),
    });

    if (!res.ok) {
      const err = await res.text();
      console.error(`[FEDERATION] Push identities failed: ${res.status} ${err}`);
      return 0;
    }

    const data = await res.json() as { synced?: number; skipped?: number };
    if ((data.synced || 0) > 0) {
      console.log(`[FEDERATION] Pushed ${data.synced} identities to primary`);
    }
    return data.synced || 0;
  } catch (err) {
    console.error('[FEDERATION] Push identities error:', err);
    return 0;
  }
}

/** Route a message to the primary relay if recipient is not local */
export async function routeToRelay(msg: {
  from_did: string;
  to: string;
  ciphertext: string;
  nonce: string;
  signature: string;
  envelope?: string;
}): Promise<{ success: boolean; error?: string }> {
  try {
    const res = await fetch(`${PRIMARY_RELAY}/v1/relay/deliver`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from_relay: RELAY_URL,
        from_did: msg.from_did,
        to_did: msg.to,
        ciphertext: msg.ciphertext,
        nonce: msg.nonce,
        signature: msg.signature,
        envelope: msg.envelope,
        peer_secret: PEER_SECRET,
      }),
    });

    if (res.ok) return { success: true };
    const err = await res.json().catch(() => ({}));
    return { success: false, error: (err as any).error?.message || `Route failed (${res.status})` };
  } catch (err) {
    return { success: false, error: String(err) };
  }
}

/** Periodic federation tasks — returns interval IDs for cleanup on shutdown */
export function startFederationLoop(): ReturnType<typeof setInterval>[] {
  // Register on startup
  registerWithPrimary();

  // Re-register every 5 minutes (heartbeat)
  const heartbeat = setInterval(() => registerWithPrimary(), 5 * 60 * 1000);

  // Push local identities every 2 minutes
  const syncPush = setInterval(() => pushLocalIdentities(), 2 * 60 * 1000);

  return [heartbeat, syncPush];
}
