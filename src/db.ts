import Database from 'better-sqlite3';
import { randomUUID } from 'crypto';
import path from 'path';

const DATA_DIR = process.env.DATA_DIR || '/data';
const DB_PATH = path.join(DATA_DIR, 'relay.db');

let db: Database.Database;

export function getDb(): Database.Database {
  if (!db) {
    db = new Database(DB_PATH);
    db.pragma('journal_mode = WAL');
    // FK OFF — federated messages have from_did not in local agent_identities
    db.pragma('foreign_keys = OFF');
    initSchema();
  }
  return db;
}

function initSchema() {
  const d = getDb();

  d.exec(`
    CREATE TABLE IF NOT EXISTS agent_identities (
      did TEXT PRIMARY KEY,
      display_name TEXT,
      signing_public_key TEXT NOT NULL,
      encryption_public_key TEXT NOT NULL,
      api_key_hash TEXT NOT NULL,
      capabilities TEXT DEFAULT '[]',
      metadata TEXT DEFAULT '{}',
      status TEXT DEFAULT 'active',
      home_relay TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      last_seen TEXT DEFAULT (datetime('now')),
      message_count INTEGER DEFAULT 0
    );

    CREATE INDEX IF NOT EXISTS idx_agent_status ON agent_identities(status);
    CREATE INDEX IF NOT EXISTS idx_agent_api_key ON agent_identities(api_key_hash);

    CREATE TABLE IF NOT EXISTS agent_messages (
      id TEXT PRIMARY KEY,
      from_did TEXT NOT NULL,
      to_did TEXT NOT NULL,
      encrypted_payload TEXT NOT NULL,
      nonce TEXT NOT NULL,
      signature TEXT NOT NULL,
      envelope TEXT,
      content_type TEXT DEFAULT 'text/plain',
      message_type TEXT DEFAULT 'text',
      thread_id TEXT,
      reply_to TEXT,
      ttl_seconds INTEGER DEFAULT 86400,
      expires_at TEXT NOT NULL,
      delivered INTEGER DEFAULT 0,
      delivered_at TEXT,
      read_at TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_msg_to ON agent_messages(to_did, read_at, expires_at);
    CREATE INDEX IF NOT EXISTS idx_msg_from ON agent_messages(from_did, created_at);
    CREATE INDEX IF NOT EXISTS idx_msg_thread ON agent_messages(thread_id);
    CREATE INDEX IF NOT EXISTS idx_msg_expires ON agent_messages(expires_at);
  `);
}

// ── Queries ──

export function findAgentByApiKey(apiKeyHash: string) {
  return getDb().prepare(
    'SELECT * FROM agent_identities WHERE api_key_hash = ? AND status = ?'
  ).get(apiKeyHash, 'active') as any | undefined;
}

export function findAgentByDid(did: string) {
  return getDb().prepare(
    'SELECT did, display_name, signing_public_key, encryption_public_key, capabilities, status, home_relay, created_at, last_seen FROM agent_identities WHERE did = ?'
  ).get(did) as any | undefined;
}

export function registerAgent(agent: {
  did: string;
  display_name?: string;
  signing_public_key: string;
  encryption_public_key: string;
  api_key_hash: string;
  home_relay?: string;
}) {
  return getDb().prepare(`
    INSERT INTO agent_identities (did, display_name, signing_public_key, encryption_public_key, api_key_hash, home_relay)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(agent.did, agent.display_name || null, agent.signing_public_key, agent.encryption_public_key, agent.api_key_hash, agent.home_relay || null);
}

export function storeMessage(msg: {
  from_did: string;
  to_did: string;
  encrypted_payload: string;
  nonce: string;
  signature: string;
  envelope?: string;
  content_type?: string;
  message_type?: string;
  thread_id?: string;
  reply_to?: string;
  ttl?: number;
}) {
  const id = randomUUID();
  const ttl = msg.ttl || 86400;
  const expiresAt = new Date(Date.now() + ttl * 1000).toISOString();

  getDb().prepare(`
    INSERT INTO agent_messages (id, from_did, to_did, encrypted_payload, nonce, signature, envelope,
      content_type, message_type, thread_id, reply_to, ttl_seconds, expires_at, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
  `).run(id, msg.from_did, msg.to_did, msg.encrypted_payload, msg.nonce, msg.signature,
    msg.envelope || null, msg.content_type || 'text/plain', msg.message_type || 'text',
    msg.thread_id || null, msg.reply_to || null, ttl, expiresAt);

  return id;
}

export function getMessages(toDid: string, options: {
  since?: string;
  from?: string;
  limit?: number;
  unreadOnly?: boolean;
}) {
  let sql = `
    SELECT m.*, i.signing_public_key AS sender_signing_key, i.encryption_public_key AS sender_encryption_key
    FROM agent_messages m
    LEFT JOIN agent_identities i ON i.did = m.from_did
    WHERE m.to_did = ?
    AND (m.expires_at IS NULL OR m.expires_at > datetime('now'))
  `;
  const params: any[] = [toDid];

  if (options.since) { sql += ' AND m.created_at > ?'; params.push(options.since); }
  if (options.from) { sql += ' AND m.from_did = ?'; params.push(options.from); }
  if (options.unreadOnly) { sql += ' AND m.read_at IS NULL'; }

  sql += ' ORDER BY m.created_at ASC LIMIT ?';
  params.push(options.limit || 50);

  return getDb().prepare(sql).all(...params) as any[];
}

export function updateLastSeen(did: string) {
  getDb().prepare('UPDATE agent_identities SET last_seen = datetime(\'now\') WHERE did = ?').run(did);
}

export function cleanExpired() {
  const result = getDb().prepare("DELETE FROM agent_messages WHERE expires_at < datetime('now')").run();
  return result.changes;
}

export function getStats() {
  const d = getDb();
  const agents = d.prepare('SELECT COUNT(*) as count FROM agent_identities WHERE status = ?').get('active') as any;
  const messages = d.prepare('SELECT COUNT(*) as count FROM agent_messages').get() as any;
  return {
    agents: agents?.count || 0,
    messages: messages?.count || 0,
  };
}

/** Get all local (non-federated) agents for pushing to primary relay */
export function getLocalAgents() {
  return getDb().prepare(
    `SELECT did, display_name, signing_public_key, encryption_public_key, capabilities
     FROM agent_identities WHERE api_key_hash != 'federated' AND status = 'active'`
  ).all() as any[];
}

/** Close DB for graceful shutdown */
export function closeDb() {
  if (db) {
    try { db.close(); } catch { /* already closed */ }
  }
}
