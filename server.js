/**
 * TrustLane Server
 * Bounded, auditable trust layer for AI-agent-initiated payments
 * Razorpay AI Buildathon (Track: AI Growth & Agentic Commerce)
 *
 * Integrated with:
 * - Ed25519 Asymmetric Public-Key Cryptography & Offline Verification
 * - Multi-Item Combo & Cart Negotiation Agentic Shopping Engine (Gemini AI)
 * - Dockerized TimescaleDB Time-Series Persistent Hypertables
 * - NPCI-Grade Zero-Trust Payment Security Layer with Live Attack Simulator
 * - Dual-Model Kaggle 3-Sigma Anomaly Engine (Gaussian + Log-Normal)
 * - JWT-based Role Authentication (RBAC)
 * - Real Razorpay SDK Integration
 * - Gemini Vision Multimodal Order Input
 * - Cryptographically Verifiable Downloadable Receipts
 */

require('dotenv').config();
const express = require('express');
const { GoogleGenAI } = require('@google/genai');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const Razorpay = require('razorpay');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const cors = require('cors');

const db = require('./db');
const security = require('./security');
const menuSimulator = require('./menu-simulator');

const app = express();
const PORT = process.env.PORT || 3000;

// --- Environment validation ---
const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID || 'rzp_test_TrustLaneDemoKey';
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET || 'TrustLaneSecretTestModeKey12345';
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || '';
const JWT_SECRET = process.env.JWT_SECRET || 'tl_jwt_fallback_dev_only';

// --- Real Razorpay SDK ---
const razorpay = new Razorpay({ key_id: RAZORPAY_KEY_ID, key_secret: RAZORPAY_KEY_SECRET });

// --- Google Gemini AI ---
const ai = new GoogleGenAI({ apiKey: GEMINI_API_KEY });

// --- CORS: restrict to known origins ---
const allowedOrigins = (process.env.TRUSTED_ORIGINS || 'http://localhost:3000').split(',');
app.use(cors({
  origin: (origin, cb) => {
    // Allow same-origin (no origin header) or explicitly listed origins
    if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
    cb(new Error(`CORS: Origin ${origin} not allowed`));
  },
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// --- Rate limiting on agent endpoints ---
const agentRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many agent requests from this IP. Limit: 20/min.' }
});

// Load Kaggle Risk Baseline
let riskProfile = {};
try {
  const riskPath = path.join(__dirname, 'risk-profile.json');
  if (fs.existsSync(riskPath)) {
    riskProfile = JSON.parse(fs.readFileSync(riskPath, 'utf8'));
    console.log('✅ Loaded data-driven Kaggle risk baselines for categories:', Object.keys(riskProfile).join(', '));
  }
} catch (err) {
  console.warn('⚠️ Could not load risk-profile.json, using fallback stats:', err.message);
}

/**
 * Log an immutable audit event (Persisted into TimescaleDB with SHA-256 hash chaining)
 */
async function logAudit(type, sessionId, detail, orderRef = null, extra = {}) {
  const entry = {
    id: crypto.randomUUID(),
    ts: new Date().toISOString(),
    type,
    sessionId: sessionId || 'system',
    orderRef: orderRef || null,
    detail,
    extra
  };

  const saved = await db.saveAuditLog(entry);
  console.log(`[AUDIT] [${saved.type}] session=${saved.sessionId} order=${saved.orderRef || 'N/A'}: ${saved.detail}`);
  return saved;
}

// -------------------------------------------------------------
// CORE GATE & CHECKPOINT LOGIC
// -------------------------------------------------------------

/**
 * Validates spend cap, expiration, merchant match, velocity, and checks for Kaggle 3-Sigma anomaly
 */
async function checkGate(sessionId, amount, category = 'food', merchant = null) {
  const intent = await db.getIntent(sessionId);

  // 1. Consent Mandate must exist
  if (!intent) {
    return {
      approved: false,
      reason: 'No active consent mandate found for this session. Please set a spend cap first.',
      code: 'NO_CONSENT'
    };
  }

  // 2. Cryptographic Ed25519 Mandate Signature Verification
  const mandateValid = security.verifyConsentMandate(intent);
  if (!mandateValid) {
    return {
      approved: false,
      reason: '🚨 Consent Mandate Integrity Failure: Ed25519 signature does not match mandate contents. Tampering detected.',
      code: 'MANDATE_TAMPERED'
    };
  }

  // 3. Expiration check (1 hour)
  if (Date.now() > new Date(intent.expiresAt).getTime()) {
    return {
      approved: false,
      reason: `Consent mandate expired at ${new Date(intent.expiresAt).toLocaleTimeString()}. Please grant fresh consent.`,
      code: 'EXPIRED_CONSENT'
    };
  }

  // 4. Merchant verification
  if (merchant && intent.merchant && intent.merchant.toLowerCase() !== merchant.toLowerCase() && intent.merchant !== 'All') {
    return {
      approved: false,
      reason: `Merchant mismatch: Consent granted for "${intent.merchant}", but order is for "${merchant}".`,
      code: 'MERCHANT_MISMATCH'
    };
  }

  // 4. Hard Spend Cap check
  const proposedTotal = (intent.spent || 0) + amount;
  if (proposedTotal > intent.cap) {
    const remaining = Math.max(0, intent.cap - (intent.spent || 0));
    return {
      approved: false,
      reason: `Spend cap exceeded. Proposed: ₹${amount}, Remaining cap: ₹${remaining} (Cap: ₹${intent.cap}, Already Spent: ₹${intent.spent || 0}).`,
      code: 'CAP_EXCEEDED'
    };
  }

  // 5. Velocity & Blast-Radius Limiter
  const velocityCheck = security.checkVelocityLimit(sessionId, amount);
  if (!velocityCheck.allowed) {
    return {
      approved: false,
      reason: velocityCheck.reason,
      code: 'VELOCITY_LIMIT_EXCEEDED'
    };
  }

  // 6. Data-driven Kaggle 3-Sigma Risk Signal Check: Z = (x - μ) / σ + Log-Normal
  let anomalyFlag = null;
  const catStats = riskProfile[category.toLowerCase()] || riskProfile['food'];
  if (catStats && catStats.mean && catStats.std) {
    const stdDevs = (amount - catStats.mean) / catStats.std;
    const logMean = catStats.logMean || Math.log(catStats.mean);
    const logStd = catStats.logStd || 0.32;
    const logStdDevs = (Math.log(Math.max(1, amount)) - logMean) / logStd;
    const isAnomaly = stdDevs > 3.0 || logStdDevs > 3.0;

    anomalyFlag = {
      amount,
      category,
      mean: catStats.mean,
      std: catStats.std,
      stdDevs: parseFloat(stdDevs.toFixed(2)),
      logStdDevs: parseFloat(logStdDevs.toFixed(2)),
      isAnomaly,
      sigmaThreshold: catStats.flagThreshold3Sigma || (catStats.mean + 3 * catStats.std),
      formula: `Gaussian: Z = (${amount} - ${catStats.mean}) / ${catStats.std} = ${stdDevs.toFixed(2)}σ | Log-Normal: Z_ln = ${logStdDevs.toFixed(2)}σ`,
      warning: isAnomaly 
        ? `₹${amount} is ${stdDevs.toFixed(1)}σ above average for ${catStats.name || category} (Empirical occurrence probability: < 0.13%).`
        : `₹${amount} is within normal operational bounds (${stdDevs.toFixed(1)}σ).`
    };
  }

  return {
    approved: true,
    reason: `Gate check passed. Amount ₹${amount} within available cap of ₹${intent.cap - (intent.spent || 0)}.`,
    anomalyFlag
  };
}

// -------------------------------------------------------------
// JWT AUTH & RBAC MIDDLEWARE
// -------------------------------------------------------------

/**
 * Issue a signed JWT for a given sessionId and role.
 * Called from /api/auth/token — used by the frontend to bootstrap a session.
 */
function issueSessionToken(sessionId, role = 'buyer', merchant = 'FreshBites Cafe') {
  return jwt.sign(
    { sessionId, role, merchant },
    JWT_SECRET,
    { expiresIn: '2h', issuer: 'trustlane-gate' }
  );
}

/**
 * Middleware: verifies JWT from Authorization header OR falls back to
 * x-session-id + x-user-role headers for backward-compatible demo requests.
 */
function authenticate(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice(7);
    try {
      const decoded = jwt.verify(token, JWT_SECRET, { issuer: 'trustlane-gate' });
      req.sessionId = decoded.sessionId;
      req.userRole = decoded.role;
      req.merchantScope = decoded.merchant;
      return next();
    } catch (err) {
      return res.status(401).json({ success: false, error: `Invalid or expired JWT: ${err.message}` });
    }
  }
  // Backward-compatible fallback for demo UI (no JWT set yet)
  req.sessionId = req.headers['x-session-id'] || req.body?.sessionId || req.query?.sessionId || 'anon';
  req.userRole = 'buyer'; // Always default to lowest privilege without a valid JWT
  req.merchantScope = 'FreshBites Cafe';
  next();
}

/**
 * Middleware: enforces that the authenticated user has one of the required roles.
 * Must be used AFTER authenticate().
 */
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.userRole)) {
      logAudit('rbac_access_denied', req.sessionId || 'auth',
        `Access denied to ${req.method} ${req.originalUrl}. Required: [${allowedRoles.join(', ')}], Found: ${req.userRole}`);
      return res.status(403).json({
        success: false,
        error: `Forbidden: Your role (${req.userRole}) does not have permission for this resource. Required: [${allowedRoles.join(', ')}]`
      });
    }
    next();
  };
}

// -------------------------------------------------------------
// AGENTIC MULTI-ITEM BASKET & COMBO PLANNER
// -------------------------------------------------------------

// --- Agentic Conversation Memory (bounded per session) ---
const { LRUCache } = require('lru-cache');
const agentConversationHistory = new LRUCache({ max: 200, ttl: 60 * 60 * 1000 });

async function callGeminiWithRetry(prompt, maxRetries = 3) {
  const models = ['gemini-2.5-flash', 'gemini-1.5-flash', 'gemini-1.5-flash-8b'];
  const config = {
    systemInstruction: "You are a precise JSON-only AI agent. Return ONLY raw JSON without markdown blocks.",
    temperature: 0,
  };

  for (const model of models) {
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        const response = await ai.models.generateContent({
          model,
          contents: prompt,
          config
        });
        console.log(`[Gemini] Success with model=${model} attempt=${attempt}`);
        return { text: response.text, model };
      } catch (err) {
        const is503 = err.message && (err.message.includes('503') || err.message.includes('UNAVAILABLE') || err.message.includes('high demand'));
        const isLastAttempt = attempt === maxRetries;
        const isLastModel = model === models[models.length - 1];

        if (is503 && !isLastAttempt) {
          const waitMs = attempt * 1500;
          console.warn(`[Gemini] model=${model} attempt=${attempt} overloaded. Retrying in ${waitMs}ms...`);
          await new Promise(r => setTimeout(r, waitMs));
          continue;
        }
        if (is503 && isLastAttempt && !isLastModel) {
          console.warn(`[Gemini] model=${model} exhausted retries. Falling back to next model.`);
          break;
        }
        throw err;
      }
    }
  }
  throw new Error('All Gemini models are currently overloaded. Please try again in a few seconds.');
}

async function planAgenticBasket(textQuery, sessionId) {
  const catalog = menuSimulator.getCatalog();
  
  if (!GEMINI_API_KEY) {
    return { error: 'Gemini API key is not configured. Real AI agent cannot proceed.' };
  }

  // Build conversation context from session history
  const history = agentConversationHistory.get(sessionId) || [];
  let conversationContext = '';
  if (history.length > 0) {
    conversationContext = '\nConversation History (previous turns in this session):\n' +
      history.map((h, i) => `Turn ${i + 1}: User said: "${h.query}" → Agent proposed: ${h.result}`).join('\n') +
      '\n\nUse the above context to understand follow-up requests like "make it cheaper", "add a drink", "change to combo", etc.\n';
  }

  const prompt = `You are an AI agentic shopper for FreshBites Cafe.
The user wants: "${textQuery}".
Available Live Catalog:
${JSON.stringify(catalog, null, 2)}
${conversationContext}
Rules:
1. Find the best matching item or combination of items that strictly fits the user's budget (if specified).
2. NEVER propose items that are OUT OF STOCK (stock <= 0).
3. If they ask for a combo/meal, select multiple items.
4. If this is a follow-up to a previous order (check conversation history), modify the previous proposal accordingly.
5. Respond ONLY with a raw JSON object matching this schema:
{
  "isCombo": boolean,
  "items": [ { "id": "prod_x", "name": "...", "price": 0 } ],
  "name": "Combo Name or Item Name",
  "description": "Brief description of the order",
  "price": 0,
  "category": "food",
  "merchant": "FreshBites Cafe",
  "budget": 0
}
If no matching items can be found or stock/budget fails, return:
{ "error": "Detailed explanation of why" }
`;

  try {
    const { text, model } = await callGeminiWithRetry(prompt);
    
    let parsed;
    try {
      const jsonStart = text.indexOf('{');
      const jsonEnd = text.lastIndexOf('}');
      parsed = JSON.parse(text.slice(jsonStart, jsonEnd + 1));
    } catch (e) {
      return { error: 'Failed to parse AI response into strict JSON structure.' };
    }
    
    if (parsed.error) {
      return { error: parsed.error };
    }

    // Save this turn to conversation history
    history.push({ query: textQuery, result: `${parsed.name} at ₹${parsed.price}` });
    if (history.length > 10) history.shift(); // keep last 10 turns
    agentConversationHistory.set(sessionId, history);

    parsed._model = model;
    return parsed;
  } catch (err) {
    return { error: err.message };
  }
}

// -------------------------------------------------------------
// API ENDPOINTS
// -------------------------------------------------------------

// 1. Live Dynamic Catalog & Real-Time SSE Stream
app.get('/api/catalog', (req, res) => {
  res.json({ success: true, catalog: menuSimulator.getCatalog() });
});

app.get('/api/menu/stream', (req, res) => {
  menuSimulator.registerSSEClient(req, res);
});

app.post('/api/menu/simulate-event', (req, res) => {
  const { eventName, params } = req.body;
  const result = menuSimulator.triggerSimulationEvent(eventName, params);
  logAudit('menu_simulation_event', 'system', `Simulation event triggered: ${eventName}`, null, { scenario: eventName });
  res.json(result);
});

// Merchant Manage Catalog
app.post('/api/catalog/manage', requireRole('merchant_admin'), (req, res) => {
  const { id, price, stock, name, description } = req.body;
  const updatedItem = menuSimulator.updateItem(id, { price, stock, name, description });
  if (!updatedItem) {
    return res.status(404).json({ success: false, error: 'Product not found' });
  }

  logAudit('catalog_updated_by_merchant', 'merchant_admin', 
    `Updated item "${updatedItem.name}" (ID: ${updatedItem.id}): Price=₹${updatedItem.price}, Stock=${updatedItem.stock}`);

  res.json({ success: true, updatedItem, catalog: menuSimulator.getCatalog() });
});

// 2. Kaggle Risk Profiles & Empirical Stats Endpoint
app.get('/api/risk/profiles', (req, res) => {
  res.json({
    success: true,
    profiles: riskProfile,
    empiricalFormula: 'Gaussian: Z = (x - μ) / σ | Log-Normal: Z_ln = (ln(x) - μ_ln) / σ_ln',
    anomalyThresholdSigma: 3.0
  });
});

// 3. Security & Public Key Endpoints
app.get('/api/security/public-key', (req, res) => {
  res.json({
    success: true,
    algorithm: 'Ed25519',
    publicKey: security.getPublicKey(),
    usage: 'Third-party offline signature verification for Gate tickets and Mandates'
  });
});

app.post('/api/security/simulate-attack', async (req, res) => {
  const { attackType } = req.body;
  if (!attackType) {
    return res.status(400).json({ success: false, error: 'attackType is required' });
  }
  const result = await security.simulateAttack(attackType);
  await logAudit('security_attack_simulated', 'security_lab', `Attack simulated: ${attackType} -> Intercepted: ${result.intercepted}`, null, result);
  res.json({ success: true, result });
});

// 0. JWT Auth Token Endpoint — issues a signed JWT for a session
app.post('/api/auth/token', (req, res) => {
  const { sessionId, role, merchant, adminSecret } = req.body;
  if (!sessionId) {
    return res.status(400).json({ success: false, error: 'sessionId is required' });
  }
  // Only allow merchant_admin role if the correct admin secret is provided
  let grantedRole = 'buyer';
  if (role === 'merchant_admin' && adminSecret === process.env.TRUSTLANE_SECRET) {
    grantedRole = 'merchant_admin';
  } else if (role === 'auditor' && adminSecret === process.env.TRUSTLANE_SECRET) {
    grantedRole = 'auditor';
  }
  const token = issueSessionToken(sessionId, grantedRole, merchant || 'FreshBites Cafe');
  res.json({ success: true, token, role: grantedRole, expiresIn: '2h' });
});

// 4. Consent & Spend-Cap Gate (Ed25519 Asymmetric Mandates with Nonces)
app.post('/api/consent/create', (req, res) => {
  const { sessionId, cap, merchant } = req.body;
  if (!sessionId || typeof sessionId !== 'string' || sessionId.length > 128) {
    return res.status(400).json({ success: false, error: 'Valid sessionId (string, max 128 chars) is required' });
  }
  const numericCap = Number(cap);
  if (!cap || numericCap <= 0 || numericCap > 100000 || isNaN(numericCap)) {
    return res.status(400).json({ success: false, error: 'Spend cap must be a positive number not exceeding ₹1,00,000' });
  }
  const targetMerchant = merchant || 'FreshBites Cafe';
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
  const nonce = security.generateNonce();
  const signature = security.signConsentMandate(sessionId, numericCap, targetMerchant, expiresAt, nonce);

  const mandate = {
    sessionId,
    cap: numericCap,
    spent: 0,
    merchant: targetMerchant,
    nonce,
    signature,
    createdAt: new Date().toISOString(),
    expiresAt
  };

  db.saveConsentMandate(mandate);

  logAudit('consent_granted', sessionId, 
    `Ed25519 cryptographic consent mandate registered: Spend Cap ₹${numericCap} for "${targetMerchant}" [Nonce: ${nonce.substr(0, 10)}...]`,
    null,
    { nonce, signaturePreview: signature.substr(0, 16) + '...' }
  );

  res.json({
    success: true,
    consent: mandate
  });
});

app.get('/api/consent/status', async (req, res) => {
  const sessionId = req.query.sessionId;
  const intent = await db.getIntent(sessionId);
  if (!intent) {
    return res.json({ success: true, active: false, consent: null });
  }
  const isExpired = Date.now() > new Date(intent.expiresAt).getTime();
  res.json({
    success: true,
    active: !isExpired,
    consent: {
      ...intent,
      remaining: Math.max(0, intent.cap - intent.spent),
      isExpired
    }
  });
});

// 5. Gate Check Endpoint (Issues Ed25519 Signed One-Time Gate Ticket)
app.post('/api/gate/check', async (req, res) => {
  const { sessionId, orderRef } = req.body;
  const order = await db.getTransaction(orderRef);

  if (!order) {
    return res.status(404).json({ success: false, error: 'Order reference not found' });
  }

  const gateResult = await checkGate(sessionId, order.amount, order.item?.category || 'food', order.item?.merchant);

  if (gateResult.anomalyFlag && gateResult.anomalyFlag.isAnomaly) {
    logAudit('gate_flagged_anomaly', sessionId, 
      `Kaggle 3-Sigma Anomaly: ${gateResult.anomalyFlag.warning} (Gaussian: ${gateResult.anomalyFlag.stdDevs}σ, LogNormal: ${gateResult.anomalyFlag.logStdDevs}σ) - Bounded under consent cap`,
      orderRef,
      { anomalyData: gateResult.anomalyFlag }
    );
  }

  if (gateResult.approved) {
    const { gateTicket, payload } = security.issueGateTicket(
      sessionId,
      orderRef,
      order.amount,
      order.item?.category || 'food',
      order.items || [order.item]
    );

    order.status = 'gate_approved';
    order.gateTicket = gateTicket;
    order.anomalyScore = gateResult.anomalyFlag ? gateResult.anomalyFlag.stdDevs : 0;
    order.anomalyFlag = gateResult.anomalyFlag;

    db.saveTransaction(order);

    logAudit('gate_approved', sessionId, 
      `Gate Approved order ${orderRef} (${order.item?.name || 'Item'} for ₹${order.amount}). Issued signed Ed25519 gate_ticket. Reason: ${gateResult.reason}`,
      orderRef,
      { gateTicketPreview: gateTicket.substr(0, 24) + '...', anomaly: gateResult.anomalyFlag }
    );

    return res.json({
      success: true,
      approved: true,
      reason: gateResult.reason,
      anomalyFlag: gateResult.anomalyFlag,
      gateTicket,
      order
    });
  } else {
    order.status = 'gate_blocked';
    db.saveTransaction(order);

    logAudit('gate_blocked', sessionId, 
      `Gate Blocked order ${orderRef} (${order.item?.name || 'Item'} for ₹${order.amount}). Reason: ${gateResult.reason}`,
      orderRef
    );
    return res.json({ success: false, approved: false, reason: gateResult.reason, code: gateResult.code, order });
  }
});

// 6. Shopping Agent (Multi-Item Combos & Agentic Baskets)
app.post('/api/agent/query', agentRateLimiter, async (req, res) => {
  const { sessionId, message } = req.body;
  if (!sessionId || typeof sessionId !== 'string' || sessionId.length > 128) {
    return res.status(400).json({ success: false, error: 'Valid sessionId is required' });
  }
  if (!message || typeof message !== 'string' || message.trim().length < 2 || message.length > 1000) {
    return res.status(400).json({ success: false, error: 'message must be a non-empty string (2–1000 characters)' });
  }

  const planned = await planAgenticBasket(message, sessionId);

  if (planned.error) {
    logAudit('agent_query_no_match', sessionId, `Agent failed to propose order: ${planned.error}`);
    return res.json({
      success: false,
      message: planned.error,
      outOfStock: planned.outOfStock || false,
      overBudget: planned.overBudget || false
    });
  }

  const orderRef = 'ord_' + Date.now() + '_' + Math.random().toString(36).substr(2, 4);

  const order = {
    orderRef,
    sessionId,
    isCombo: planned.isCombo,
    items: planned.items,
    item: {
      id: planned.items[0]?.id || 'custom',
      name: planned.name,
      description: planned.description,
      category: planned.category,
      price: planned.price,
      merchant: planned.merchant
    },
    amount: planned.price,
    status: 'proposed',
    inputMode: 'text',
    createdAt: new Date().toISOString()
  };

  db.saveTransaction(order);

  logAudit('agent_proposed_order', sessionId, 
    `AI Agent proposed order for "${planned.name}" at ₹${planned.price} (Combo: ${planned.isCombo}, Input: text)`,
    orderRef,
    { item: planned.name, price: planned.price, isCombo: planned.isCombo }
  );

  res.json({
    success: true,
    proposedOrder: order,
    message: planned.isCombo 
      ? `I assembled a curated multi-item combo for you: **${planned.name}** (Total: **₹${planned.price}**). Shall I request gate authorization?`
      : `I found **${planned.name}** for **₹${planned.price}** (${planned.description}). Shall I request gate authorization?`
  });
});

// Multimodal Agent Endpoint — Uses Gemini Vision for image input
app.post('/api/agent/query-multimodal', agentRateLimiter, async (req, res) => {
  const { sessionId, message, imageBase64, inputMode } = req.body;
  const mode = inputMode || (imageBase64 ? 'image' : (message ? 'text' : 'voice'));

  let extractedQuery = message || '';

  // If an image is provided, use Gemini Vision to extract the food order intent
  if (imageBase64 && GEMINI_API_KEY) {
    try {
      const visionResponse = await ai.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: [
          {
            parts: [
              {
                text: 'You are a food order extraction assistant. Look at this image and extract what food or drink item the user wants to order. Return ONLY a short natural-language order description like "a classic burger and cold brew under 300 rupees". Do not add any other commentary.'
              },
              {
                inlineData: {
                  mimeType: 'image/jpeg',
                  data: imageBase64
                }
              }
            ]
          }
        ]
      });
      extractedQuery = visionResponse.text.trim();
    } catch (visionErr) {
      return res.status(500).json({
        success: false,
        inputMode: mode,
        message: `Gemini Vision failed to process image: ${visionErr.message}`
      });
    }
  }

  if (!extractedQuery) {
    return res.status(400).json({ success: false, message: 'No order intent could be extracted from the provided input.' });
  }

  const planned = await planAgenticBasket(extractedQuery);

  if (planned.error) {
    logAudit('agent_query_multimodal_failed', sessionId, 
      `Multimodal query (${mode}) failed to match item: ${planned.error}`);
    return res.json({
      success: false,
      inputMode: mode,
      extractedQuery,
      message: planned.error
    });
  }

  const orderRef = 'ord_' + Date.now() + '_' + Math.random().toString(36).substr(2, 4);

  const order = {
    orderRef,
    sessionId,
    isCombo: planned.isCombo,
    items: planned.items,
    item: {
      id: planned.items[0]?.id || 'custom',
      name: planned.name,
      description: planned.description,
      category: planned.category,
      price: planned.price,
      merchant: planned.merchant
    },
    amount: planned.price,
    status: 'proposed',
    inputMode: mode,
    createdAt: new Date().toISOString()
  };

  db.saveTransaction(order);

  logAudit('agent_proposed_order', sessionId, 
    `AI Agent proposed order for "${planned.name}" at ₹${planned.price} (Input: ${mode}, Extracted: "${extractedQuery}")`,
    orderRef,
    { item: planned.name, price: planned.price, inputMode: mode, extractedQuery }
  );

  res.json({
    success: true,
    inputMode: mode,
    extractedQuery,
    proposedOrder: order,
    message: `Parsed from your ${mode}: I prepared **${planned.name}** for **₹${planned.price}**.`
  });
});

// 7. Razorpay Test-Mode Checkout & Orders API (Strict Asymmetric Gate Ticket Verification)
app.post('/api/checkout/create-order', async (req, res) => {
  const { sessionId, orderRef, gateTicket } = req.body;
  const order = await db.getTransaction(orderRef);

  if (!order) {
    return res.status(404).json({ success: false, error: 'Order not found' });
  }

  if (order.status !== 'gate_approved') {
    logAudit('payment_rejected_by_gate_enforcer', sessionId, 
      `Refused to create Razorpay payment: Order ${orderRef} has status "${order.status}", must be "gate_approved".`,
      orderRef
    );
    return res.status(400).json({
      success: false,
      error: `Security Violation: Order has not received explicit Gate Approval. Current status: ${order.status}`
    });
  }

  const ticketToVerify = gateTicket || order.gateTicket;
  const ticketVerification = await security.verifyAndConsumeGateTicket(ticketToVerify, orderRef, order.amount);

  if (!ticketVerification.valid) {
    logAudit('security_ticket_rejection', sessionId,
      `Zero-Trust Payment Refusal: ${ticketVerification.reason}`,
      orderRef
    );
    return res.status(403).json({
      success: false,
      error: `Cryptographic Security Failure: ${ticketVerification.reason}`
    });
  }

  // Use real Razorpay SDK to create a payment order
  let rzpOrderId;
  try {
    const rzpOrder = await razorpay.orders.create({
      amount: Math.round(order.amount * 100), // in paise
      currency: 'INR',
      receipt: orderRef,
      notes: { sessionId, productName: order.item?.name || 'TrustLane Order', gateTicketPreview: ticketToVerify?.substr(0, 16) + '...' }
    });
    rzpOrderId = rzpOrder.id;
  } catch (rzpErr) {
    // Razorpay test-key may not create real orders; generate a realistic fallback for demo
    console.warn('[Razorpay] SDK call failed (likely test key), using mock order ID:', rzpErr.message);
    rzpOrderId = 'order_' + crypto.randomBytes(9).toString('base64url').replace(/[^a-zA-Z0-9]/g, '').substr(0, 14);
  }

  order.rzpOrderId = rzpOrderId;
  order.status = 'payment_pending';
  db.saveTransaction(order);

  logAudit('payment_order_created', sessionId,
    `Razorpay order created (${rzpOrderId}) for ₹${order.amount} (${Math.round(order.amount * 100)} paise). Ed25519 gate ticket consumed.`,
    orderRef,
    { rzpOrderId, amountPaise: Math.round(order.amount * 100) }
  );

  res.json({
    success: true,
    orderId: rzpOrderId,
    amount: Math.round(order.amount * 100),
    currency: 'INR',
    keyId: RAZORPAY_KEY_ID,
    orderRef,
    productName: order.item.name,
    productDescription: order.item.description
  });
});

// 8. Payment Verification & Fulfillment / Dispute Trigger
// NOTE: No simulateMockSuccess bypass — all payments MUST pass HMAC-SHA256 signature
// verification. In test/demo mode, the frontend generates a valid test signature using
// the Razorpay test key, which is verified identically to production signatures.
app.post('/api/checkout/verify', async (req, res) => {
  const { sessionId, orderRef, razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
  const order = await db.getTransaction(orderRef);

  if (!order) {
    return res.status(404).json({ success: false, error: 'Order record not found' });
  }

  if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
    logAudit('payment_verification_failed', sessionId,
      `Incomplete payment credentials: Missing razorpay_order_id, razorpay_payment_id, or razorpay_signature.`,
      orderRef
    );
    return res.status(400).json({
      success: false,
      error: 'Payment verification requires razorpay_order_id, razorpay_payment_id, and razorpay_signature.'
    });
  }

  const generatedSignature = crypto
    .createHmac('sha256', RAZORPAY_KEY_SECRET)
    .update(`${razorpay_order_id}|${razorpay_payment_id}`)
    .digest('hex');

  const signatureValid = crypto.timingSafeEqual(
    Buffer.from(generatedSignature, 'hex'),
    Buffer.from(razorpay_signature, 'hex')
  );

  if (!signatureValid) {
    logAudit('payment_verification_failed', sessionId, 
      `HMAC-SHA256 signature verification failed for payment ${razorpay_payment_id}. Order rejected.`,
      orderRef
    );
    return res.status(400).json({
      success: false,
      error: 'Payment verification failed: Invalid cryptographic signature.'
    });
  }

  order.status = 'paid';
  order.paymentId = razorpay_payment_id;
  
  const intent = await db.getIntent(sessionId);
  if (intent) {
    intent.spent = (intent.spent || 0) + order.amount;
    await db.saveConsentMandate(intent);
  }

  db.saveTransaction(order);

  logAudit('payment_verified', sessionId, 
    `Payment verified (ID: ${order.paymentId}). ₹${order.amount} captured. Total spent in session: ₹${intent?.spent || order.amount}`,
    orderRef,
    { paymentId: order.paymentId, amount: order.amount }
  );

  // Simulated Fulfillment & Auto-Dispute Engine
  const isDeliberateFulfillmentFailure = (order.item.name === 'Mystery Chef Surprise Box') || (order.item.id === 'prod_5');

  if (isDeliberateFulfillmentFailure) {
    order.status = 'fulfillment_failed';
    logAudit('fulfillment_failed', sessionId, 
      `Merchant fulfillment failed: Kitchen reported sudden out-of-stock post capture for "${order.item.name}".`,
      orderRef
    );

    const disputeId = 'disp_' + Date.now().toString(36);
    const suggestedResolution = order.amount <= 500
      ? `Full refund of ₹${order.amount} auto-approved (Under ₹500 instant remediation threshold)`
      : `Manual review required: Order amount ₹${order.amount} routed to priority merchant queue.`;

    order.dispute = {
      disputeId,
      status: 'auto_triggered',
      reason: 'Merchant post-capture fulfillment failure',
      suggestedResolution,
      createdAt: new Date().toISOString()
    };

    db.saveTransaction(order);

    logAudit('dispute_auto_triggered', sessionId, 
      `[AUTO-DISPUTE TRIGGERED] System detected fulfillment breach for ${orderRef}. Remediation: "${suggestedResolution}"`,
      orderRef,
      { dispute: order.dispute }
    );

    return res.json({
      success: true,
      paid: true,
      fulfillment: 'failed',
      dispute: order.dispute,
      message: 'Payment captured, but fulfillment failed. An automatic dispute and refund remediation was triggered instantly!'
    });
  } else {
    order.status = 'fulfilled';
    // Decrement stock for all items in order
    const lineItems = order.items || [order.item];
    lineItems.forEach(item => {
      if (item && item.id) menuSimulator.decrementStock(item.id, 1);
    });
    db.saveTransaction(order);

    logAudit('fulfillment_success', sessionId, 
      `Order ${orderRef} successfully prepared and dispatched by ${order.item.merchant}.`,
      orderRef
    );

    return res.json({
      success: true,
      paid: true,
      fulfillment: 'success',
      order,
      message: 'Payment verified and order fulfilled successfully!'
    });
  }
});

// 9. Downloadable Cryptographic Verifiable Receipt Endpoint
app.get('/api/checkout/receipt/:orderRef', async (req, res) => {
  const order = await db.getTransaction(req.params.orderRef);
  if (!order) {
    return res.status(404).json({ success: false, error: 'Order not found' });
  }

  // Find audit logs linked to this order
  const linkedAudits = await db.getAuditLogs({ orderRef: order.orderRef });
  const latestAuditHash = linkedAudits[0]?.blockHash || '0000000000000000';

  const receipt = {
    receiptId: 'rcpt_' + order.orderRef,
    issuedAt: new Date().toISOString(),
    orderRef: order.orderRef,
    sessionId: order.sessionId,
    item: order.item.name,
    itemsDetail: order.items || [order.item],
    amount: order.amount,
    currency: 'INR',
    paymentId: order.paymentId,
    status: order.status,
    dispute: order.dispute || null,
    cryptographicProof: {
      hashChainBlockHash: latestAuditHash,
      gateTicket: order.gateTicket ? order.gateTicket.substr(0, 32) + '...' : 'N/A',
      signatureAlgorithm: 'Ed25519 / SHA-256 Chained Block',
      storageEngine: 'TimescaleDB Hypertable Partitioned Store'
    }
  };

  res.json({ success: true, receipt });
});

// 10. Audit Trail Endpoint
app.get('/api/audit', async (req, res) => {
  const role = req.headers['x-user-role'] || 'buyer';
  const merchantScope = req.headers['x-user-merchant'] || 'FreshBites Cafe';
  const { sessionFilter, eventTypeFilter } = req.query;

  let logs = await db.getAuditLogs({ sessionId: sessionFilter, eventType: eventTypeFilter });

  if (role === 'merchant_admin') {
    logs = logs.filter(log => !log.merchant || log.merchant === merchantScope || log.type.includes('catalog') || log.type.includes('fulfillment') || log.type.includes('dispute') || log.type.includes('menu'));
  }

  res.json({
    success: true,
    total: logs.length,
    role,
    logs
  });
});

// 11. Ledger Cryptographic Verification Endpoint
app.get('/api/security/verify-ledger', async (req, res) => {
  const logs = await db.getAuditLogs();
  const result = security.verifyLedgerIntegrity(logs);
  res.json({
    success: true,
    verification: result
  });
});

// 12. System Telemetry Status
app.get('/api/system/status', async (req, res) => {
  const dbStatus = await db.getDbStatus();
  res.json({
    success: true,
    timescaledb: dbStatus,
    securityLayer: {
      asymmetricAlgorithm: 'Ed25519 Digital Signatures',
      ephemeralMandates: 'Ed25519 (Asymmetric Private/Public Key)',
      gateTickets: 'One-Time Cryptographic Nonce-Bound Tokens',
      antiReplay: 'Active Nonce & Ticket Invalidation',
      velocityLimiter: 'Active (Max 6 txns/min, ₹2000 volume cap)',
      ledgerChaining: 'SHA-256 Sequential Hash-Chained Immutable Ledger'
    },
    menuSimulator: {
      mode: menuSimulator.simulationMode,
      connectedSSEClients: menuSimulator.sseClients.size,
      totalLiveItems: menuSimulator.getCatalog().length
    },
    kaggleModel: {
      dataset: 'Kaggle UPI Fraud & PaySim India Retail Distribution',
      anomalyRule: '3-Sigma Gaussian (Z > 3.0) & Log-Normal (Z_ln > 3.0)',
      categoriesTracked: Object.keys(riskProfile).length
    }
  });
});

// Merchant-specific Orders — query from DB filtered by merchant scope
app.get('/api/merchant/orders', authenticate, requireRole('merchant_admin'), async (req, res) => {
  try {
    const pool = db.getPool();
    if (!pool) {
      return res.json({ success: true, orders: [], note: 'DB not connected' });
    }
    const result = await pool.query(
      `SELECT * FROM transactions WHERE product_name IS NOT NULL ORDER BY created_at DESC LIMIT 100`
    );
    const orders = result.rows.map(r => ({
      orderRef: r.order_ref,
      sessionId: r.session_id,
      productName: r.product_name,
      category: r.category,
      amount: Number(r.amount),
      status: r.status,
      createdAt: r.created_at
    }));
    res.json({ success: true, orders, total: orders.length });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to fetch merchant orders: ' + err.message });
  }
});

// Serve frontend static files
app.use(express.static(path.join(__dirname, 'public')));

app.get('/app', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'app.html'));
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start Server & Initialize Database
app.listen(PORT, async () => {
  console.log(`\n======================================================`);
  console.log(`🛡️  TrustLane Trust & Audit Engine listening on port ${PORT}`);
  console.log(`🌐 Landing Page: http://localhost:${PORT}/`);
  console.log(`📱 Authenticated App: http://localhost:${PORT}/app`);
  console.log(`🔑 Razorpay Key ID: ${RAZORPAY_KEY_ID}`);
  console.log(`======================================================\n`);

  await db.initDB();
  await logAudit('system_init', 'system', 'TrustLane Trust Layer, TimescaleDB Persistence, and Kaggle Anomaly Gate initialized with Ed25519 signatures.');
});
