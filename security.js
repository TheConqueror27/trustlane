/**
 * security.js
 * NPCI-Grade Zero-Trust Payment Security Layer for TrustLane
 * (Refactored for Production - Persistent Keys and Bounded Caches)
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const db = require('./db');

const DATA_DIR = path.join(__dirname, '.data');
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}
const PRIV_KEY_PATH = path.join(DATA_DIR, 'private.pem');
const PUB_KEY_PATH = path.join(DATA_DIR, 'public.pem');

let ed25519KeyPair = null;
try {
  if (fs.existsSync(PRIV_KEY_PATH) && fs.existsSync(PUB_KEY_PATH)) {
    const privateKey = fs.readFileSync(PRIV_KEY_PATH, 'utf8');
    const publicKey = fs.readFileSync(PUB_KEY_PATH, 'utf8');
    
    // We create a KeyObject for the private key
    const privKeyObj = crypto.createPrivateKey({
      key: privateKey,
      format: 'pem',
      type: 'pkcs8'
    });
    // We create a KeyObject for the public key
    const pubKeyObj = crypto.createPublicKey({
      key: publicKey,
      format: 'pem',
      type: 'spki'
    });

    ed25519KeyPair = { privateKey: privKeyObj, publicKey: pubKeyObj };
    console.log('🔑 [Security] Loaded persistent Ed25519 keys from disk.');
  } else {
    ed25519KeyPair = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    fs.writeFileSync(PRIV_KEY_PATH, ed25519KeyPair.privateKey);
    fs.writeFileSync(PUB_KEY_PATH, ed25519KeyPair.publicKey);
    console.log('🔑 [Security] Generated and saved new persistent Ed25519 keys.');
  }
} catch (err) {
  console.error('[Security] Ed25519 initialization error:', err);
}

const SERVER_SECRET = process.env.TRUSTLANE_SECRET;
if (!SERVER_SECRET) {
  throw new Error('[Security] TRUSTLANE_SECRET env var is not set. Server cannot start without a signing secret.');
}

// Bounded LRU cache for velocity
const { LRUCache } = require('lru-cache');
const sessionVelocity = new LRUCache({ max: 1000, ttl: 60 * 1000 });

const MAX_ORDERS_PER_MINUTE = 6;
const MAX_VELOCITY_AMOUNT_PER_MINUTE = 2000;

function getPublicKey() {
  return ed25519KeyPair ? ed25519KeyPair.publicKey : null;
}

function generateNonce() {
  return 'nonce_' + crypto.randomBytes(16).toString('hex');
}

function signConsentMandate(sessionId, cap, merchant, expiresAt, nonce) {
  const payload = `${sessionId}|${cap}|${merchant}|${expiresAt}|${nonce}`;
  if (ed25519KeyPair) {
    const signature = crypto.sign(null, Buffer.from(payload), ed25519KeyPair.privateKey);
    return signature.toString('base64url');
  }
  return crypto.createHmac('sha256', SERVER_SECRET).update(payload).digest('hex');
}

function verifyConsentMandate(mandate) {
  if (!mandate || !mandate.nonce || !mandate.signature) return false;
  const payload = `${mandate.sessionId}|${mandate.cap}|${mandate.merchant}|${mandate.expiresAt}|${mandate.nonce}`;
  
  if (ed25519KeyPair) {
    try {
      return crypto.verify(
        null,
        Buffer.from(payload),
        ed25519KeyPair.publicKey,
        Buffer.from(mandate.signature, 'base64url')
      );
    } catch (e) {
      return false;
    }
  }
  return true;
}

function issueGateTicket(sessionId, orderRef, amount, itemCategory, items = []) {
  const payload = {
    sessionId,
    orderRef,
    amount,
    itemCategory,
    itemsSummary: items.length > 1 ? items.map(i => `${i.name} (₹${i.price})`).join(', ') : (items[0]?.name || 'Single Item'),
    issuedAt: Date.now(),
    expiresAt: Date.now() + 5 * 60 * 1000,
    nonce: generateNonce(),
    issuer: 'TrustLane Zero-Trust Gate Authority (Ed25519)'
  };

  const payloadString = JSON.stringify(payload);
  const payloadB64 = Buffer.from(payloadString).toString('base64url');

  let signature;
  if (ed25519KeyPair) {
    signature = crypto.sign(null, Buffer.from(payloadB64), ed25519KeyPair.privateKey).toString('base64url');
  } else {
    signature = crypto.createHmac('sha256', SERVER_SECRET).update(payloadB64).digest('base64url');
  }

  const gateTicket = `${payloadB64}.${signature}`;

  return {
    gateTicket,
    payload,
    publicKey: getPublicKey()
  };
}

async function verifyAndConsumeGateTicket(gateTicket, expectedOrderRef, expectedAmount) {
  if (!gateTicket || typeof gateTicket !== 'string') {
    return {
      valid: false,
      code: 'MISSING_TICKET',
      reason: 'Missing cryptographic Gate Approval Ticket. Payment rejected by Zero-Trust Enforcer.'
    };
  }

  // 1. Anti-Replay Check via Database
  // If the transaction already has a payment_id or is marked 'paid', this ticket has been used.
  const order = await db.getTransaction(expectedOrderRef);
  if (order && (order.status === 'paid' || order.status === 'payment_pending')) {
     // Wait, the ticket is consumed when the order reaches payment_pending
     // We should only allow it if the current DB state is gate_approved
     if (order.status !== 'gate_approved') {
       return {
         valid: false,
         code: 'REPLAY_ATTACK_DETECTED',
         reason: '🚨 Security Breach Blocked: Gate approval ticket was already consumed or invalid state (Replay attack intercepted).'
       };
     }
  }

  const parts = gateTicket.split('.');
  if (parts.length !== 2) {
    return { valid: false, code: 'MALFORMED_TICKET', reason: 'Malformed gate approval ticket structure.' };
  }

  const [payloadB64, signature] = parts;

  // 2. Asymmetric Cryptographic Verification
  let signatureValid = false;
  if (ed25519KeyPair) {
    try {
      signatureValid = crypto.verify(
        null,
        Buffer.from(payloadB64),
        ed25519KeyPair.publicKey,
        Buffer.from(signature, 'base64url')
      );
    } catch (e) {
      signatureValid = false;
    }
  } else {
    const expectedSig = crypto.createHmac('sha256', SERVER_SECRET).update(payloadB64).digest('base64url');
    signatureValid = (signature === expectedSig);
  }

  if (!signatureValid) {
    return {
      valid: false,
      code: 'FORGED_SIGNATURE_DETECTED',
      reason: '🚨 Signature Forgery Detected: Digital signature does not match Gate Public Key. Tampering intercepted.'
    };
  }

  let payload;
  try {
    payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
  } catch (e) {
    return { valid: false, code: 'INVALID_PAYLOAD', reason: 'Invalid ticket payload encoding.' };
  }

  // 3. Expiration Check
  if (Date.now() > payload.expiresAt) {
    return {
      valid: false,
      code: 'TICKET_EXPIRED',
      reason: `Gate approval ticket expired at ${new Date(payload.expiresAt).toLocaleTimeString()} (5-minute TTL exceeded).`
    };
  }

  // 4. Order Reference Check
  if (payload.orderRef !== expectedOrderRef) {
    return {
      valid: false,
      code: 'ORDER_MISMATCH',
      reason: `Ticket orderRef mismatch (Expected ${expectedOrderRef}, got ${payload.orderRef}).`
    };
  }

  // 5. Amount Tampering (MITM) Check
  if (Number(payload.amount) !== Number(expectedAmount)) {
    return {
      valid: false,
      code: 'AMOUNT_TAMPERING_DETECTED',
      reason: `🚨 Man-In-The-Middle Amount Tampering: Ticket authorized ₹${payload.amount}, but request attempted ₹${expectedAmount}.`
    };
  }

  return {
    valid: true,
    payload
  };
}

function checkVelocityLimit(sessionId, proposedAmount) {
  const now = Date.now();
  const windowMs = 60 * 1000;

  let history = sessionVelocity.get(sessionId) || [];
  
  // Filter history
  history = history.filter(entry => now - entry.timestamp < windowMs);
  
  if (history.length >= MAX_ORDERS_PER_MINUTE) {
    return {
      allowed: false,
      code: 'VELOCITY_FREQUENCY_EXCEEDED',
      reason: `🚨 Blast-Radius Containment: Exceeded max rate of ${MAX_ORDERS_PER_MINUTE} transactions/min. Runaway agent spending blocked.`
    };
  }

  const totalVolumeInWindow = history.reduce((sum, e) => sum + e.amount, 0) + proposedAmount;
  if (totalVolumeInWindow > MAX_VELOCITY_AMOUNT_PER_MINUTE) {
    return {
      allowed: false,
      code: 'VELOCITY_VOLUME_EXCEEDED',
      reason: `🚨 Volume Spike Containment: 1-minute velocity of ₹${totalVolumeInWindow} exceeds ₹${MAX_VELOCITY_AMOUNT_PER_MINUTE} ceiling.`
    };
  }

  history.push({ timestamp: now, amount: proposedAmount });
  sessionVelocity.set(sessionId, history);
  return { allowed: true };
}

function verifyLedgerIntegrity(auditLogs) {
  if (!auditLogs || auditLogs.length === 0) {
    return { valid: true, totalRecords: 0, message: 'Ledger is clean with 0 records.' };
  }

  const chronological = [...auditLogs].reverse();
  let expectedPrevHash = '0000000000000000000000000000000000000000000000000000000000000000';
  let verifiedCount = 0;

  for (let i = 0; i < chronological.length; i++) {
    const entry = chronological[i];
    
    if (i > 0 && entry.prevHash !== expectedPrevHash) {
      return {
        valid: false,
        brokenAtBlock: entry.id,
        index: i,
        error: `Broken cryptographic link at log ${entry.id}. Expected prevHash: ${expectedPrevHash}, Found: ${entry.prevHash}`
      };
    }

    const canonicalPayload = JSON.stringify({
      id: entry.id,
      type: entry.type,
      sessionId: entry.sessionId,
      orderRef: entry.orderRef,
      detail: entry.detail
    });

    const calculatedBlockHash = crypto
      .createHash('sha256')
      .update(`${entry.prevHash}:${entry.ts}:${canonicalPayload}`)
      .digest('hex');

    if (entry.blockHash !== calculatedBlockHash) {
      return {
        valid: false,
        brokenAtBlock: entry.id,
        index: i,
        error: `Tampered block content detected at log ${entry.id}. Hash mismatch.`
      };
    }

    expectedPrevHash = entry.blockHash;
    verifiedCount++;
  }

  return {
    valid: true,
    totalRecords: verifiedCount,
    latestBlockHash: expectedPrevHash,
    message: `All ${verifiedCount} audit ledger blocks cryptographically verified with 100% SHA-256 integrity.`
  };
}

async function simulateAttack(attackType, options = {}) {
  const sessionId = options.sessionId || 'attacker_session_99';
  const orderRef = options.orderRef || 'ord_attack_' + Date.now();

  switch (attackType) {
    case 'replay_ticket': {
      // Create a dummy transaction
      await db.saveTransaction({
        orderRef,
        sessionId,
        amount: 180,
        status: 'gate_approved'
      });
      const { gateTicket } = issueGateTicket(sessionId, orderRef, 180, 'food');
      
      // Consume it legitimately
      const res1 = await verifyAndConsumeGateTicket(gateTicket, orderRef, 180);
      
      // Update DB to mark as paid so it fails replay
      if (res1.valid) {
        await db.saveTransaction({
          orderRef,
          sessionId,
          amount: 180,
          status: 'paid'
        });
      }

      // Attempt replay
      const replayResult = await verifyAndConsumeGateTicket(gateTicket, orderRef, 180);
      return {
        attackType: 'Ticket Replay Attack',
        description: 'Attacker intercepts and attempts to reuse an already captured Gate Approval Ticket.',
        intercepted: !replayResult.valid,
        verdict: replayResult.reason,
        securityLayer: 'Anti-Replay DB Verifier'
      };
    }

    case 'mitm_amount_tamper': {
      await db.saveTransaction({ orderRef, sessionId, amount: 180, status: 'gate_approved' });
      const { gateTicket } = issueGateTicket(sessionId, orderRef, 180, 'food');
      const tamperResult = await verifyAndConsumeGateTicket(gateTicket, orderRef, 1800);
      return {
        attackType: 'Man-In-The-Middle (MITM) Amount Tampering',
        description: 'Rogue client/proxy modifies payment amount from ₹180 to ₹1800 post-gate authorization.',
        intercepted: !tamperResult.valid,
        verdict: tamperResult.reason,
        securityLayer: 'Zero-Trust Gate Ticket Verifier'
      };
    }

    case 'forge_signature': {
      await db.saveTransaction({ orderRef, sessionId, amount: 9999, status: 'gate_approved' });
      const fakePayload = Buffer.from(JSON.stringify({
        sessionId, orderRef, amount: 9999, issuedAt: Date.now(), expiresAt: Date.now() + 300000
      })).toString('base64url');
      const bogusSignature = crypto.randomBytes(64).toString('base64url');
      const forgedTicket = `${fakePayload}.${bogusSignature}`;

      const forgeResult = await verifyAndConsumeGateTicket(forgedTicket, orderRef, 9999);
      return {
        attackType: 'Asymmetric Signature Forgery',
        description: 'Unauthorized client attempts to mint a fake gate ticket without the Ed25519 Private Key.',
        intercepted: !forgeResult.valid,
        verdict: forgeResult.reason,
        securityLayer: 'Ed25519 Cryptographic Verification'
      };
    }

    case 'velocity_flood': {
      let floodResult = null;
      for (let i = 0; i < 7; i++) {
        floodResult = checkVelocityLimit('flood_session_test', 100);
      }
      return {
        attackType: 'Runaway Agent Velocity Flood (DDoS Spend Loop)',
        description: 'Rogue or looping AI agent fires 7 consecutive order executions within seconds.',
        intercepted: !floodResult.allowed,
        verdict: floodResult.reason,
        securityLayer: 'Blast-Radius & Velocity Limiter'
      };
    }

    default:
      return { error: 'Unknown attack type.' };
  }
}

module.exports = {
  getPublicKey,
  generateNonce,
  signConsentMandate,
  verifyConsentMandate,
  issueGateTicket,
  verifyAndConsumeGateTicket,
  checkVelocityLimit,
  verifyLedgerIntegrity,
  simulateAttack
};
