import { createServer, IncomingMessage, ServerResponse } from 'http';
import { createHash, randomBytes } from 'crypto';
import { WebSocketServer, WebSocket } from 'ws';
import {
  getDb, findAgentByApiKey, findAgentByDid, registerAgent,
  storeMessage, getMessages, updateLastSeen, cleanExpired, getStats, closeDb,
} from './db.js';
import { startFederationLoop, routeToRelay } from './federation.js';

const PORT = parseInt(process.env.PORT || '8080', 10);
const REGION = process.env.RELAY_REGION || 'unknown';
const VERSION = '1.0.0';
const PEER_SECRET = process.env.RELAY_PEER_SECRET || '';
const MAX_BODY_BYTES = 1024 * 1024; // 1MB max request body

// ── WebSocket connections per agent DID ──
const wsClients = new Map<string, Set<WebSocket>>();

// ── Rate limiting ──
const rateLimits = new Map<string, { count: number; resetAt: number }>();
function rateLimit(key: string, maxPerMin: number): boolean {
  const now = Date.now();
  const entry = rateLimits.get(key);
  if (!entry || now > entry.resetAt) {
    rateLimits.set(key, { count: 1, resetAt: now + 60000 });
    return false; // not limited
  }
  entry.count++;
  return entry.count > maxPerMin; // true = rate limited
}
// Clean rate limit entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimits) {
    if (now > entry.resetAt) rateLimits.delete(key);
  }
}, 5 * 60 * 1000);

// ── Base58 encoding (matches SDK DID format) ──
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58Encode(bytes: Uint8Array): string {
  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let str = '';
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) str += '1';
  for (let i = digits.length - 1; i >= 0; i--) str += BASE58_ALPHABET[digits[i]];
  return str;
}

function sha256(input: string): string {
  return createHash('sha256').update(input).digest('hex');
}

function json(res: ServerResponse, status: number, data: unknown) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
  res.end(JSON.stringify(data));
}

function parseBody(req: IncomingMessage): Promise<any> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let totalSize = 0;
    const timeout = setTimeout(() => {
      req.destroy();
      reject(new Error('Request body timeout'));
    }, 10000); // 10s body timeout

    req.on('data', (c: Buffer) => {
      totalSize += c.length;
      if (totalSize > MAX_BODY_BYTES) {
        clearTimeout(timeout);
        req.destroy();
        reject(new Error('Request body too large'));
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      clearTimeout(timeout);
      try { resolve(JSON.parse(Buffer.concat(chunks).toString())); }
      catch { reject(new Error('Invalid JSON')); }
    });
    req.on('error', (err) => { clearTimeout(timeout); reject(err); });
  });
}

async function authenticate(req: IncomingMessage): Promise<{ did: string } | null> {
  const apiKey = req.headers['x-agent-key'] as string;
  if (!apiKey) return null;
  const hash = sha256(apiKey);
  const agent = findAgentByApiKey(hash);
  if (!agent) return null;
  updateLastSeen(agent.did);
  return { did: agent.did };
}

// ── Push message to connected WebSocket clients ──
function pushToWebSocket(toDid: string, messageData: any) {
  const clients = wsClients.get(toDid);
  if (!clients) return;
  const payload = JSON.stringify(messageData);
  for (const ws of clients) {
    if (ws.readyState === WebSocket.OPEN) {
      try { ws.send(payload); } catch { /* socket closing */ }
    }
  }
}

// ── Route handlers ──

async function handleRelayInfo(_req: IncomingMessage, res: ServerResponse) {
  json(res, 200, {
    name: `voidly-relay-${REGION}`,
    version: VERSION,
    region: REGION,
    features: ['sse', 'websocket', 'federation', 'encrypted-messages'],
    uptime: process.uptime(),
    stats: getStats(),
  });
}

async function handleRegister(req: IncomingMessage, res: ServerResponse) {
  const clientIp = (req.headers['x-forwarded-for'] as string || req.socket.remoteAddress || '').split(',')[0].trim();
  if (rateLimit(`register:${clientIp}`, 20)) {
    return json(res, 429, { error: 'Rate limit exceeded' });
  }

  let body: any;
  try { body = await parseBody(req); }
  catch (e: any) { return json(res, 400, { error: e.message }); }

  if (!body.signing_public_key || !body.encryption_public_key) {
    return json(res, 400, { error: 'Missing required keys' });
  }
  if (body.signing_public_key.length > 200 || body.encryption_public_key.length > 200) {
    return json(res, 400, { error: 'Key too large' });
  }
  if (body.name && body.name.length > 200) {
    return json(res, 400, { error: 'Name too long' });
  }

  // Cryptographically secure API key
  const apiKey = randomBytes(32).toString('hex');
  const apiKeyHash = sha256(apiKey);

  // Generate DID from signing key — base58 encoding (matches SDK)
  const keyBytes = Buffer.from(body.signing_public_key, 'base64');
  const didSuffix = base58Encode(keyBytes.subarray(0, 16));
  const did = `did:voidly:${didSuffix}`;

  try {
    registerAgent({
      did,
      display_name: body.name || body.display_name,
      signing_public_key: body.signing_public_key,
      encryption_public_key: body.encryption_public_key,
      api_key_hash: apiKeyHash,
    });
  } catch (err: any) {
    if (err.message?.includes('UNIQUE')) {
      return json(res, 409, { error: 'Agent already registered' });
    }
    throw err;
  }

  json(res, 200, {
    did,
    api_key: apiKey,
    relay: process.env.RELAY_URL || `http://localhost:8080`,
    region: REGION,
  });
}

async function handleSendEncrypted(req: IncomingMessage, res: ServerResponse) {
  const auth = await authenticate(req);
  if (!auth) return json(res, 401, { error: 'Invalid API key' });
  if (rateLimit(`send:${auth.did}`, 100)) {
    return json(res, 429, { error: 'Rate limit exceeded' });
  }

  let body: any;
  try { body = await parseBody(req); }
  catch (e: any) { return json(res, 400, { error: e.message }); }

  if (!body.to || !body.ciphertext || !body.nonce || !body.signature) {
    return json(res, 400, { error: 'Missing required fields' });
  }

  // Check if recipient is local
  const recipient = findAgentByDid(body.to);
  if (!recipient || recipient.api_key_hash === 'federated') {
    // Route to primary relay
    const result = await routeToRelay({
      from_did: auth.did,
      to: body.to,
      ciphertext: body.ciphertext,
      nonce: body.nonce,
      signature: body.signature,
      envelope: body.envelope,
    });
    if (!result.success) {
      return json(res, 404, { error: result.error || 'Recipient not found' });
    }
    return json(res, 200, { id: 'routed', from: auth.did, to: body.to, routed: true });
  }

  const id = storeMessage({
    from_did: auth.did,
    to_did: body.to,
    encrypted_payload: body.ciphertext,
    nonce: body.nonce,
    signature: body.signature,
    envelope: body.envelope,
    content_type: body.content_type,
    message_type: body.message_type,
    thread_id: body.thread_id,
    reply_to: body.reply_to,
    ttl: body.ttl,
  });

  // Push to WebSocket clients
  const msgData = {
    id, from: auth.did, to: body.to,
    ciphertext: body.ciphertext, nonce: body.nonce, signature: body.signature,
    envelope: body.envelope, content_type: body.content_type,
    message_type: body.message_type, thread_id: body.thread_id,
    timestamp: new Date().toISOString(),
  };
  pushToWebSocket(body.to, msgData);

  json(res, 200, {
    id, from: auth.did, to: body.to,
    timestamp: new Date().toISOString(),
    encrypted: true, client_side: true,
  });
}

async function handleReceiveRaw(req: IncomingMessage, res: ServerResponse) {
  const auth = await authenticate(req);
  if (!auth) return json(res, 401, { error: 'Invalid API key' });
  if (rateLimit(`recv:${auth.did}`, 200)) {
    return json(res, 429, { error: 'Rate limit exceeded' });
  }

  const url = new URL(req.url || '/', `http://localhost`);
  const messages = getMessages(auth.did, {
    since: url.searchParams.get('since') || undefined,
    from: url.searchParams.get('from') || undefined,
    limit: parseInt(url.searchParams.get('limit') || '50', 10),
    unreadOnly: url.searchParams.get('unread') === 'true',
  });

  const formatted = messages.map((m: any) => ({
    id: m.id, from: m.from_did, to: m.to_did,
    ciphertext: m.encrypted_payload, nonce: m.nonce, signature: m.signature,
    sender_signing_key: m.sender_signing_key,
    sender_encryption_key: m.sender_encryption_key,
    envelope: m.envelope, content_type: m.content_type,
    message_type: m.message_type, thread_id: m.thread_id,
    reply_to: m.reply_to, timestamp: m.created_at, expires_at: m.expires_at,
  }));

  json(res, 200, { messages: formatted });
}

async function handleReceiveSSE(req: IncomingMessage, res: ServerResponse) {
  const apiKey = req.headers['x-agent-key'] as string;
  if (!apiKey) return json(res, 401, { error: 'Missing X-Agent-Key' });
  const hash = sha256(apiKey);
  const agent = findAgentByApiKey(hash);
  if (!agent) return json(res, 401, { error: 'Invalid API key' });
  const agentDid = agent.did;
  updateLastSeen(agentDid);

  if (rateLimit(`sse:${agentDid}`, 30)) {
    return json(res, 429, { error: 'Rate limit exceeded' });
  }

  const url = new URL(req.url || '/', 'http://localhost');
  const from = url.searchParams.get('from');
  // Use since param as timestamp cursor (Last-Event-ID is a message UUID, not a timestamp)
  let since = url.searchParams.get('since') || '1970-01-01T00:00:00Z';

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-store',
    'Connection': 'keep-alive',
    'Access-Control-Allow-Origin': '*',
    'X-Accel-Buffering': 'no', // Disable nginx/proxy buffering
  });
  res.write(`retry: 1000\n: connected\n\n`);

  let cancelled = false;
  req.on('close', () => { cancelled = true; });

  for (let i = 0; i < 30 && !cancelled; i++) {
    const messages = getMessages(agentDid, {
      since, from: from || undefined, limit: 50, unreadOnly: true,
    });

    for (const m of messages) {
      if (cancelled) break;
      const data = JSON.stringify({
        id: m.id, from: m.from_did, to: m.to_did,
        ciphertext: m.encrypted_payload, nonce: m.nonce, signature: m.signature,
        sender_signing_key: m.sender_signing_key,
        sender_encryption_key: m.sender_encryption_key,
        envelope: m.envelope, content_type: m.content_type,
        message_type: m.message_type, thread_id: m.thread_id,
        reply_to: m.reply_to, timestamp: m.created_at, expires_at: m.expires_at,
      });
      try {
        res.write(`id: ${m.created_at}\nevent: message\ndata: ${data}\n\n`);
      } catch { cancelled = true; break; }
      since = m.created_at;
    }

    if (!cancelled) {
      try { res.write(': heartbeat\n\n'); } catch { cancelled = true; }
    }
    if (!cancelled) await new Promise(r => setTimeout(r, 1000));
  }

  if (!cancelled) {
    try { res.write('event: reconnect\ndata: {"reason":"timeout"}\n\n'); } catch {}
  }
  res.end();
}

async function handleDeliver(req: IncomingMessage, res: ServerResponse) {
  // Authenticate peer relay via shared secret
  let body: any;
  try { body = await parseBody(req); }
  catch (e: any) { return json(res, 400, { error: e.message }); }

  // Federation delivery requires a configured peer secret. In standalone
  // mode (no RELAY_PEER_SECRET set) this route is closed — otherwise any
  // unauthenticated caller could inject spoofed messages into local
  // mailboxes. Federated deployments set the secret and are checked below.
  if (!PEER_SECRET) {
    return json(res, 403, { error: 'Federation not enabled on this relay' });
  }
  if (body.peer_secret !== PEER_SECRET) {
    return json(res, 403, { error: 'Invalid peer credentials' });
  }

  if (!body.to_did || !body.encrypted_payload || !body.nonce || !body.signature) {
    return json(res, 400, { error: 'Missing required fields' });
  }
  if (!body.from_did) {
    return json(res, 400, { error: 'Missing from_did' });
  }

  const recipient = findAgentByDid(body.to_did);
  if (!recipient) {
    return json(res, 404, { error: 'Recipient not found on this relay' });
  }

  const id = storeMessage({
    from_did: body.from_did,
    to_did: body.to_did,
    encrypted_payload: body.encrypted_payload,
    nonce: body.nonce,
    signature: body.signature,
    envelope: body.envelope,
  });

  pushToWebSocket(body.to_did, {
    id, from: body.from_did, to: body.to_did,
    ciphertext: body.encrypted_payload, nonce: body.nonce,
    signature: body.signature, envelope: body.envelope,
    timestamp: new Date().toISOString(),
  });

  json(res, 200, { id, delivered: true });
}

async function handlePing(req: IncomingMessage, res: ServerResponse) {
  const auth = await authenticate(req);
  if (!auth) return json(res, 401, { error: 'Invalid API key' });
  json(res, 200, { status: 'online', did: auth.did, region: REGION, timestamp: new Date().toISOString() });
}

async function handleIdentity(_req: IncomingMessage, res: ServerResponse, did: string) {
  const agent = findAgentByDid(did);
  if (!agent) return json(res, 404, { error: 'Agent not found' });
  // Only expose public fields
  json(res, 200, {
    agent: {
      did: agent.did,
      display_name: agent.display_name,
      signing_public_key: agent.signing_public_key,
      encryption_public_key: agent.encryption_public_key,
      status: agent.status,
      capabilities: agent.capabilities,
      home_relay: agent.home_relay,
      last_seen: agent.last_seen,
    },
  });
}

// ── HTTP Server ──

const server = createServer(async (req, res) => {
  const url = new URL(req.url || '/', 'http://localhost');
  const path = url.pathname;
  const method = req.method || 'GET';

  // CORS preflight
  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-Agent-Key',
      'Access-Control-Max-Age': '86400',
    });
    return res.end();
  }

  try {
    // Routes
    if (path === '/v1/relay/info' && method === 'GET') {
      return handleRelayInfo(req, res);
    }
    if (path === '/v1/agent/register' && method === 'POST') {
      return handleRegister(req, res);
    }
    if (path === '/v1/agent/send/encrypted' && method === 'POST') {
      return handleSendEncrypted(req, res);
    }
    if (path === '/v1/agent/receive/raw' && method === 'GET') {
      return handleReceiveRaw(req, res);
    }
    if (path === '/v1/agent/receive/sse' && method === 'GET') {
      return handleReceiveSSE(req, res);
    }
    if (path === '/v1/relay/deliver' && method === 'POST') {
      return handleDeliver(req, res);
    }
    if (path === '/v1/agent/ping' && method === 'POST') {
      return handlePing(req, res);
    }
    if (path.startsWith('/v1/agent/identity/') && method === 'GET') {
      const did = decodeURIComponent(path.slice('/v1/agent/identity/'.length));
      return handleIdentity(req, res, did);
    }
    if (path === '/health' && method === 'GET') {
      return json(res, 200, { status: 'ok', region: REGION, version: VERSION });
    }

    json(res, 404, { error: 'Not found' });
  } catch (err: any) {
    console.error('[SERVER]', err);
    if (err.message === 'Request body too large') {
      json(res, 413, { error: 'Request body too large' });
    } else if (err.message === 'Invalid JSON') {
      json(res, 400, { error: 'Invalid JSON' });
    } else {
      json(res, 500, { error: 'Internal server error' });
    }
  }
});

// ── WebSocket Server ──

const wss = new WebSocketServer({ server, path: '/ws' });

wss.on('connection', (ws, req) => {
  // Authenticate via first message instead of URL query param (prevents key in logs)
  let authenticated = false;
  let did = '';

  // Message-based auth: client sends { type: 'auth', key: '...' }
  ws.on('message', (data) => {
    if (authenticated) return; // Already authed
    try {
      const msg = JSON.parse(data.toString());
      if (msg.type === 'auth' && msg.key) {
        const hash = sha256(msg.key);
        const agent = findAgentByApiKey(hash);
        if (!agent) {
          ws.close(4001, 'Invalid API key');
          return;
        }
        did = agent.did;
        authenticated = true;
        if (!wsClients.has(did)) wsClients.set(did, new Set());
        wsClients.get(did)!.add(ws);
        ws.send(JSON.stringify({ type: 'connected', did, region: REGION }));
      }
    } catch { /* ignore malformed */ }
  });

  // Auth timeout — close if not authenticated within 5s
  const authTimeout = setTimeout(() => {
    if (!authenticated) ws.close(4001, 'Authentication timeout');
  }, 5000);

  const cleanup = () => {
    clearTimeout(authTimeout);
    if (did) {
      const clients = wsClients.get(did);
      if (clients) {
        clients.delete(ws);
        if (clients.size === 0) wsClients.delete(did);
      }
    }
  };

  ws.on('close', cleanup);
  ws.on('error', cleanup);
});

// ── WebSocket ping/pong keepalive ──
const pingInterval = setInterval(() => {
  for (const [, clients] of wsClients) {
    for (const ws of clients) {
      if (ws.readyState === WebSocket.OPEN) {
        ws.ping();
      }
    }
  }
}, 30000);

// ── Dead WebSocket cleanup ──
const wsCleanupInterval = setInterval(() => {
  for (const [did, clients] of wsClients) {
    for (const ws of clients) {
      if (ws.readyState !== WebSocket.OPEN && ws.readyState !== WebSocket.CONNECTING) {
        clients.delete(ws);
      }
    }
    if (clients.size === 0) wsClients.delete(did);
  }
}, 60000);

// ── Startup ──

// Cleanup expired messages every 10 minutes
const cleanupInterval = setInterval(() => {
  const cleaned = cleanExpired();
  if (cleaned > 0) console.log(`[CLEANUP] Removed ${cleaned} expired messages`);
}, 10 * 60 * 1000);

// Start federation
const federationIntervals = startFederationLoop();

// ── Graceful shutdown ──
function shutdown(signal: string) {
  console.log(`[RELAY] ${signal} received — shutting down...`);
  clearInterval(pingInterval);
  clearInterval(wsCleanupInterval);
  clearInterval(cleanupInterval);
  if (federationIntervals) {
    for (const id of federationIntervals) clearInterval(id);
  }

  // Close all WebSocket connections
  for (const [, clients] of wsClients) {
    for (const ws of clients) {
      try { ws.close(1001, 'Server shutting down'); } catch {}
    }
  }
  wsClients.clear();

  wss.close();
  closeDb();
  server.close(() => {
    console.log('[RELAY] Shutdown complete');
    process.exit(0);
  });

  // Force exit after 5s
  setTimeout(() => process.exit(1), 5000);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

server.listen(PORT, () => {
  console.log(`[RELAY] Voidly Relay Node v${VERSION} — region: ${REGION} — port: ${PORT}`);
});
