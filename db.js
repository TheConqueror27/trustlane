/**
 * db.js
 * TimescaleDB & PostgreSQL Persistence Layer for TrustLane
 * Stores all audits, trials, transactions, and consent mandates permanently across restarts.
 */

const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// TimescaleDB configuration with fallback defaults
const poolConfig = {
  connectionString: process.env.DATABASE_URL || undefined,
  host: process.env.PGHOST || 'localhost',
  port: parseInt(process.env.PGPORT || '5432', 10),
  user: process.env.PGUSER || 'postgres',
  password: process.env.PGPASSWORD || 'postgres',
  database: process.env.PGDATABASE || 'trustlane',
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 3000,
};

let pool = null;
let isConnected = false;
let isTimescaleActive = false;
let lastGenesisHash = '0000000000000000000000000000000000000000000000000000000000000000';
let lastBlockHash = lastGenesisHash;

// Local JSON backup store directory for resilient offline dev fallback
const DATA_DIR = path.join(__dirname, '.data');
const BACKUP_FILE = path.join(DATA_DIR, 'persisted_db.json');

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// In-memory cache synced with DB
const memoryStore = {
  auditLogs: [],
  transactions: {},
  intents: {},
  catalog: []
};

// Load initial offline state if exists
try {
  if (fs.existsSync(BACKUP_FILE)) {
    const saved = JSON.parse(fs.readFileSync(BACKUP_FILE, 'utf8'));
    if (saved.auditLogs) memoryStore.auditLogs = saved.auditLogs;
    if (saved.transactions) memoryStore.transactions = saved.transactions;
    if (saved.intents) memoryStore.intents = saved.intents;
    if (saved.catalog) memoryStore.catalog = saved.catalog;
    if (memoryStore.auditLogs.length > 0) {
      lastBlockHash = memoryStore.auditLogs[0].block_hash || memoryStore.auditLogs[0].blockHash || lastGenesisHash;
    }
  }
} catch (e) {
  console.warn('[DB] Could not load backup json:', e.message);
}

function persistToLocalDisk() {
  try {
    fs.writeFileSync(BACKUP_FILE, JSON.stringify(memoryStore, null, 2), 'utf8');
  } catch (e) {
    console.error('[DB] Disk persist error:', e.message);
  }
}

/**
 * Initialize TimescaleDB connection and run migrations
 */
async function initDB() {
  try {
    pool = new Pool(poolConfig);
    const client = await pool.connect();
    isConnected = true;
    console.log('✅ [TimescaleDB] Successfully connected to PostgreSQL/TimescaleDB on port', poolConfig.port);

    // 1. Try enabling TimescaleDB extension
    try {
      await client.query('CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;');
      isTimescaleActive = true;
      console.log('⚡ [TimescaleDB] TimescaleDB extension enabled with Time-Series partitioning.');
    } catch (extErr) {
      console.warn('ℹ️ [TimescaleDB] Standard PostgreSQL mode (TimescaleDB extension optional):', extErr.message);
      isTimescaleActive = false;
    }

    // 2. Migration: audit_logs table (Hypertable)
    await client.query(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id VARCHAR(64) NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        event_type VARCHAR(64) NOT NULL,
        session_id VARCHAR(64) NOT NULL,
        order_ref VARCHAR(64),
        detail TEXT NOT NULL,
        user_role VARCHAR(32) DEFAULT 'buyer',
        prev_hash VARCHAR(64) NOT NULL,
        block_hash VARCHAR(64) NOT NULL,
        signature VARCHAR(128) NOT NULL,
        extra_metadata JSONB DEFAULT '{}'::jsonb,
        PRIMARY KEY (id, created_at)
      );
    `);

    // Convert to hypertable if timescale is available
    if (isTimescaleActive) {
      try {
        await client.query(`
          SELECT create_hypertable('audit_logs', 'created_at', if_not_exists => TRUE);
        `);
        console.log('📊 [TimescaleDB] Hypertable created on audit_logs(created_at).');
      } catch (htErr) {
        // already hypertable or ignore
      }
    }

    // 3. Migration: transactions table
    await client.query(`
      CREATE TABLE IF NOT EXISTS transactions (
        order_ref VARCHAR(64) PRIMARY KEY,
        session_id VARCHAR(64) NOT NULL,
        product_id VARCHAR(64),
        product_name VARCHAR(128),
        category VARCHAR(64),
        amount NUMERIC(10,2) NOT NULL,
        status VARCHAR(64) NOT NULL,
        input_mode VARCHAR(32) DEFAULT 'text',
        rzp_order_id VARCHAR(64),
        payment_id VARCHAR(64),
        gate_ticket VARCHAR(256),
        anomaly_score NUMERIC(6,2),
        anomaly_flag JSONB,
        dispute JSONB,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);

    // 4. Migration: consent_mandates table
    await client.query(`
      CREATE TABLE IF NOT EXISTS consent_mandates (
        session_id VARCHAR(64) PRIMARY KEY,
        spend_cap NUMERIC(10,2) NOT NULL,
        spent NUMERIC(10,2) DEFAULT 0,
        merchant VARCHAR(128) NOT NULL,
        nonce VARCHAR(64) NOT NULL,
        mandate_signature VARCHAR(128) NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);

    // 5. Migration: menu_items table
    await client.query(`
      CREATE TABLE IF NOT EXISTS menu_items (
        id VARCHAR(64) PRIMARY KEY,
        name VARCHAR(128) NOT NULL,
        price NUMERIC(10,2) NOT NULL,
        base_price NUMERIC(10,2) NOT NULL,
        stock INT NOT NULL,
        category VARCHAR(64) NOT NULL,
        merchant VARCHAR(128) NOT NULL,
        description TEXT,
        image VARCHAR(16),
        surge_multiplier NUMERIC(4,2) DEFAULT 1.0,
        is_simulated BOOLEAN DEFAULT FALSE,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);

    client.release();

    // 6. Sync memory records to DB and load existing DB rows into memory
    await loadInitialRecordsFromDB();

  } catch (err) {
    isConnected = false;
    console.warn(`⚠️ [TimescaleDB] Could not connect to database (${err.message}). Running in Resilient Hybrid Mode with Local Persistent Storage.`);
    // Reconnect scheduler in background
    setTimeout(reconnectDB, 5000);
  }
}

async function reconnectDB() {
  if (isConnected) return;
  try {
    pool = new Pool(poolConfig);
    const client = await pool.connect();
    client.release();
    isConnected = true;
    console.log('🔄 [TimescaleDB] Reconnection successful! Running schema migration & syncing data...');
    await initDB();
  } catch (err) {
    setTimeout(reconnectDB, 8000);
  }
}

/**
 * Syncs DB records into memory and syncs offline memory records to DB
 */
async function loadInitialRecordsFromDB() {
  if (!isConnected || !pool) return;
  try {
    // 1. Load audit logs
    const auditRes = await pool.query(`SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 500`);
    if (auditRes.rows.length > 0) {
      memoryStore.auditLogs = auditRes.rows.map(r => ({
        id: r.id,
        ts: r.created_at.toISOString(),
        type: r.event_type,
        sessionId: r.session_id,
        orderRef: r.order_ref,
        detail: r.detail,
        userRole: r.user_role,
        prevHash: r.prev_hash,
        blockHash: r.block_hash,
        signature: r.signature,
        extra: r.extra_metadata || {}
      }));
      lastBlockHash = auditRes.rows[0].block_hash;
      console.log(`📦 [TimescaleDB] Loaded ${auditRes.rows.length} immutable audit logs from database.`);
    }

    // 2. Load transactions
    const txnRes = await pool.query(`SELECT * FROM transactions ORDER BY created_at DESC LIMIT 200`);
    for (const r of txnRes.rows) {
      memoryStore.transactions[r.order_ref] = {
        orderRef: r.order_ref,
        sessionId: r.session_id,
        item: {
          id: r.product_id,
          name: r.product_name,
          category: r.category,
          price: Number(r.amount)
        },
        amount: Number(r.amount),
        status: r.status,
        inputMode: r.input_mode,
        rzpOrderId: r.rzp_order_id,
        paymentId: r.payment_id,
        gateTicket: r.gate_ticket,
        anomalyScore: r.anomaly_score ? Number(r.anomaly_score) : null,
        anomalyFlag: r.anomaly_flag,
        dispute: r.dispute,
        createdAt: r.created_at.toISOString(),
        updatedAt: r.updated_at.toISOString()
      };
    }

    // 3. Load consent intents
    const consentRes = await pool.query(`SELECT * FROM consent_mandates WHERE expires_at > NOW()`);
    for (const r of consentRes.rows) {
      memoryStore.intents[r.session_id] = {
        cap: Number(r.spend_cap),
        spent: Number(r.spent),
        merchant: r.merchant,
        nonce: r.nonce,
        signature: r.mandate_signature,
        expiresAt: r.expires_at.toISOString(),
        createdAt: r.created_at.toISOString()
      };
    }

    persistToLocalDisk();
  } catch (err) {
    console.error('[DB] Error loading initial records:', err.message);
  }
}

/**
 * Save an immutable audit log entry into TimescaleDB with cryptographic hash chaining
 */
async function saveAuditLog(entry) {
  // Ensure hash chaining
  const prevHash = entry.prevHash || lastBlockHash;
  const canonicalPayload = JSON.stringify({
    id: entry.id,
    type: entry.type,
    sessionId: entry.sessionId,
    orderRef: entry.orderRef,
    detail: entry.detail
  });
  
  const blockHash = entry.blockHash || crypto.createHash('sha256').update(`${prevHash}:${entry.ts}:${canonicalPayload}`).digest('hex');
  const signature = entry.signature || crypto.createHmac('sha256', process.env.TRUSTLANE_SECRET || 'trustlane_sec_2026').update(blockHash).digest('hex');

  const normalized = {
    ...entry,
    prevHash,
    blockHash,
    signature
  };

  lastBlockHash = blockHash;
  memoryStore.auditLogs.unshift(normalized);
  persistToLocalDisk();

  if (isConnected && pool) {
    try {
      await pool.query(
        `INSERT INTO audit_logs (id, created_at, event_type, session_id, order_ref, detail, user_role, prev_hash, block_hash, signature, extra_metadata)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         ON CONFLICT (id, created_at) DO NOTHING`,
        [
          normalized.id,
          new Date(normalized.ts),
          normalized.type,
          normalized.sessionId || 'system',
          normalized.orderRef || null,
          normalized.detail,
          normalized.userRole || 'buyer',
          normalized.prevHash,
          normalized.blockHash,
          normalized.signature,
          JSON.stringify(normalized.extra || {})
        ]
      );
    } catch (err) {
      console.error('[DB] TimescaleDB insert audit failed:', err.message);
    }
  }

  return normalized;
}

/**
 * Save or update a transaction
 */
async function saveTransaction(order) {
  memoryStore.transactions[order.orderRef] = order;
  persistToLocalDisk();

  if (isConnected && pool) {
    try {
      await pool.query(
        `INSERT INTO transactions (order_ref, session_id, product_id, product_name, category, amount, status, input_mode, rzp_order_id, payment_id, gate_ticket, anomaly_score, anomaly_flag, dispute, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, NOW())
         ON CONFLICT (order_ref) DO UPDATE SET
           status = EXCLUDED.status,
           rzp_order_id = EXCLUDED.rzp_order_id,
           payment_id = EXCLUDED.payment_id,
           gate_ticket = EXCLUDED.gate_ticket,
           anomaly_score = EXCLUDED.anomaly_score,
           anomaly_flag = EXCLUDED.anomaly_flag,
           dispute = EXCLUDED.dispute,
           updated_at = NOW()`,
        [
          order.orderRef,
          order.sessionId,
          order.item?.id || null,
          order.item?.name || 'Item',
          order.item?.category || 'food',
          order.amount,
          order.status,
          order.inputMode || 'text',
          order.rzpOrderId || null,
          order.paymentId || null,
          order.gateTicket || null,
          order.anomalyScore || null,
          JSON.stringify(order.anomalyFlag || null),
          JSON.stringify(order.dispute || null),
          new Date(order.createdAt || Date.now())
        ]
      );
    } catch (err) {
      console.error('[DB] TimescaleDB transaction save failed:', err.message);
    }
  }
}

/**
 * Save consent mandate
 */
async function saveConsentMandate(mandate) {
  memoryStore.intents[mandate.sessionId] = mandate;
  persistToLocalDisk();

  if (isConnected && pool) {
    try {
      await pool.query(
        `INSERT INTO consent_mandates (session_id, spend_cap, spent, merchant, nonce, mandate_signature, expires_at, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (session_id) DO UPDATE SET
           spend_cap = EXCLUDED.spend_cap,
           spent = EXCLUDED.spent,
           merchant = EXCLUDED.merchant,
           nonce = EXCLUDED.nonce,
           mandate_signature = EXCLUDED.mandate_signature,
           expires_at = EXCLUDED.expires_at`,
        [
          mandate.sessionId,
          mandate.cap,
          mandate.spent || 0,
          mandate.merchant,
          mandate.nonce || 'nonce_0',
          mandate.signature || 'sig_0',
          new Date(mandate.expiresAt),
          new Date(mandate.createdAt || Date.now())
        ]
      );
    } catch (err) {
      console.error('[DB] TimescaleDB mandate save failed:', err.message);
    }
  }
}

/**
 * Get audit logs with optional filters
 */
async function getAuditLogs(filter = {}) {
  let logs = [...memoryStore.auditLogs];

  if (filter.sessionId) {
    logs = logs.filter(l => l.sessionId === filter.sessionId);
  }
  if (filter.eventType && filter.eventType !== 'all') {
    logs = logs.filter(l => l.type === filter.eventType);
  }

  return logs;
}

/**
 * Get system and database health statistics
 */
async function getDbStatus() {
  let hypertableChunks = 0;
  let totalDbAuditRows = memoryStore.auditLogs.length;

  if (isConnected && pool) {
    try {
      const countRes = await pool.query('SELECT COUNT(*) as count FROM audit_logs');
      totalDbAuditRows = parseInt(countRes.rows[0].count, 10);

      if (isTimescaleActive) {
        const chunkRes = await pool.query("SELECT count(*) FROM timescaledb_information.chunks WHERE hypertable_name = 'audit_logs'");
        hypertableChunks = parseInt(chunkRes.rows[0].count, 10);
      }
    } catch (e) {
      // ignore
    }
  }

  return {
    connected: isConnected,
    isTimescaleActive,
    storageType: isConnected ? (isTimescaleActive ? 'TimescaleDB Hypertable (Time-Series)' : 'PostgreSQL Relational') : 'Hybrid Persistent File + In-Memory Ledger',
    totalAuditRecords: totalDbAuditRows,
    totalTransactions: Object.keys(memoryStore.transactions).length,
    activeMandates: Object.keys(memoryStore.intents).length,
    hypertableChunks,
    lastBlockHash: lastBlockHash.substr(0, 16) + '...'
  };
}

module.exports = {
  initDB,
  saveAuditLog,
  getAuditLogs,
  saveTransaction,
  saveConsentMandate,
  getDbStatus,
  memoryStore,
  getLastBlockHash: () => lastBlockHash
};
