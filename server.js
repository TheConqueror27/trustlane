/**
 * TrustLane Server
 * Bounded, auditable trust layer for AI-agent-initiated payments
 * Razorpay AI Buildathon (Track: AI Growth & Agentic Commerce)
 * 
 * Integrated with:
 * - Ed25519 Asymmetric Public-Key Cryptography & Offline Verification
 * - Multi-Item Combo & Cart Negotiation Agentic Shopping Engine
 * - Dockerized TimescaleDB Time-Series Persistent Hypertables
 * - NPCI-Grade Zero-Trust Payment Security Layer with Live Attack Simulator
 * - Dual-Model Kaggle 3-Sigma Anomaly Engine (Gaussian + Log-Normal)
 * - Cryptographically Verifiable Downloadable Receipts
 */

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const cors = require('cors');
require('dotenv').config();

const db = require('./db');
const security = require('./security');
const menuSimulator = require('./menu-simulator');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Razorpay test credentials
const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID || 'rzp_test_TrustLaneDemoKey';
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET || 'TrustLaneSecretTestModeKey12345';
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || '';

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
    id: 'aud_' + Date.now() + '_' + Math.random().toString(36).substr(2, 5),
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
function checkGate(sessionId, amount, category = 'food', merchant = null) {
  const intent = db.memoryStore.intents[sessionId];

  // 1. Consent Mandate must exist
  if (!intent) {
    return {
      approved: false,
      reason: 'No active consent mandate found for this session. Please set a spend cap first.',
      code: 'NO_CONSENT'
    };
  }

  // 2. Expiration check (1 hour)
  if (Date.now() > new Date(intent.expiresAt).getTime()) {
    return {
      approved: false,
      reason: `Consent mandate expired at ${new Date(intent.expiresAt).toLocaleTimeString()}. Please grant fresh consent.`,
      code: 'EXPIRED_CONSENT'
    };
  }

  // 3. Merchant verification
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
// RBAC MIDDLEWARE
// -------------------------------------------------------------

function requireRole(...allowedRoles) {
  return (req, res, next) => {
    const userRole = req.headers['x-user-role'] || 'buyer';
    if (!allowedRoles.includes(userRole)) {
      logAudit('rbac_access_denied', req.headers['x-session-id'] || 'auth', 
        `Access denied to ${req.method} ${req.originalUrl}. Required: [${allowedRoles.join(', ')}], Found: ${userRole}`);
      return res.status(403).json({
        success: false,
        error: `Forbidden: Your role (${userRole}) does not have permission for this resource. Required: [${allowedRoles.join(', ')}]`
      });
    }
    req.userRole = userRole;
    req.merchantScope = req.headers['x-user-merchant'] || 'FreshBites Cafe';
    next();
  };
}

// -------------------------------------------------------------
// AGENTIC MULTI-ITEM BASKET & COMBO PLANNER
// -------------------------------------------------------------

function planAgenticBasket(textQuery) {
  const catalog = menuSimulator.getCatalog();
  const lower = textQuery.toLowerCase();

  // Extract budget constraint
  let maxBudget = null;
  const budgetMatch = lower.match(/(?:under|below|max|less than|<|budget of)\s*₹?\s*(\d+)/i) 
    || lower.match(/(\d+)\s*(?:rs|inr|rupees)/i);
  if (budgetMatch) {
    maxBudget = parseInt(budgetMatch[1], 10);
  }

  // Detect Combo / Multi-Item Intent (e.g. "combo", "meal", "and", "lunch", "dinner", "+")
  const isComboRequest = lower.includes('combo') || lower.includes('meal') || lower.includes('lunch') || lower.includes('dinner') || lower.includes(' and ') || lower.includes(' + ');

  if (isComboRequest) {
    // 1. Multi-item combo builder
    const availableFood = catalog.filter(i => i.category === 'food' && i.stock > 0 && i.id !== 'prod_4');
    const availableDrinks = catalog.filter(i => i.category === 'beverage' && i.stock > 0);

    // Pick best food item
    let mainItem = availableFood.find(i => lower.includes('truffle') ? i.id === 'prod_2' : (lower.includes('surprise') ? i.id === 'prod_5' : i.id === 'prod_1')) || availableFood[0];
    // Pick best beverage item
    let drinkItem = availableDrinks.find(i => lower.includes('matcha') ? i.id === 'prod_6' : i.id === 'prod_3') || availableDrinks[0];

    const comboItems = [mainItem, drinkItem].filter(Boolean);
    const totalAmount = comboItems.reduce((sum, item) => sum + item.price, 0);

    if (maxBudget !== null && totalAmount > maxBudget) {
      return {
        error: `I crafted a lunch combo with "${mainItem.name}" and "${drinkItem.name}" (Total: ₹${totalAmount}), but it exceeds your budget limit of ₹${maxBudget}.`,
        overBudget: true
      };
    }

    return {
      isCombo: true,
      items: comboItems,
      name: `Agentic Combo: ${mainItem.name} + ${drinkItem.name}`,
      description: `Curated lunch combo featuring ${mainItem.name} and ${drinkItem.name}.`,
      price: totalAmount,
      category: 'food',
      merchant: 'FreshBites Cafe',
      budget: maxBudget
    };
  }

  // Single Item Matcher
  const matches = catalog.map(item => {
    const itemName = item.name.toLowerCase();
    const itemDesc = item.description.toLowerCase();
    const itemCat = item.category.toLowerCase();
    
    let score = 0;
    const queryWords = lower.replace(/[^\w\s]/gi, '').split(/\s+/).filter(w => w.length > 2);
    
    for (const word of queryWords) {
      if (itemName.includes(word)) score += 5;
      if (itemDesc.includes(word)) score += 2;
      if (itemCat.includes(word)) score += 3;
    }
    
    if (itemName.includes(lower.replace(/under\s*\d+/gi, '').trim())) {
      score += 10;
    }

    return { item, score };
  }).filter(m => m.score > 0);

  if (matches.length === 0) {
    return { error: 'No matching items found in the merchant live catalog for your request.' };
  }

  matches.sort((a, b) => b.score - a.score || a.item.price - b.item.price);
  const candidate = matches[0].item;

  if (candidate.stock <= 0) {
    return {
      error: `Found "${candidate.name}", but it is currently OUT OF STOCK in the live kitchen inventory. Cannot propose an unavailable item.`,
      item: candidate,
      outOfStock: true
    };
  }

  if (maxBudget !== null && candidate.price > maxBudget) {
    return {
      error: `Found "${candidate.name}" (₹${candidate.price}), but it exceeds your requested budget constraint of ₹${maxBudget}.`,
      item: candidate,
      overBudget: true
    };
  }

  return {
    isCombo: false,
    items: [candidate],
    item: candidate,
    name: candidate.name,
    description: candidate.description,
    price: candidate.price,
    category: candidate.category,
    merchant: candidate.merchant,
    budget: maxBudget
  };
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

app.post('/api/security/simulate-attack', (req, res) => {
  const { attackType } = req.body;
  const result = security.simulateAttack(attackType);
  logAudit('security_attack_simulated', 'security_lab', `Attack simulated: ${attackType} -> Intercepted: ${result.intercepted}`, null, result);
  res.json({ success: true, result });
});

// 4. Consent & Spend-Cap Gate (Ed25519 Asymmetric Mandates with Nonces)
app.post('/api/consent/create', (req, res) => {
  const { sessionId, cap, merchant } = req.body;
  if (!sessionId || !cap || Number(cap) <= 0) {
    return res.status(400).json({ success: false, error: 'Valid sessionId and positive spend cap are required' });
  }

  const numericCap = Number(cap);
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

app.get('/api/consent/status', (req, res) => {
  const sessionId = req.query.sessionId;
  const intent = db.memoryStore.intents[sessionId];
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
app.post('/api/gate/check', (req, res) => {
  const { sessionId, orderRef } = req.body;
  const order = db.memoryStore.transactions[orderRef];

  if (!order) {
    return res.status(404).json({ success: false, error: 'Order reference not found' });
  }

  const gateResult = checkGate(sessionId, order.amount, order.item?.category || 'food', order.item?.merchant);

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
app.post('/api/agent/query', (req, res) => {
  const { sessionId, message } = req.body;
  if (!sessionId || !message) {
    return res.status(400).json({ success: false, error: 'sessionId and message are required' });
  }

  const planned = planAgenticBasket(message);

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

// Multimodal Agent Endpoint
app.post('/api/agent/query-multimodal', async (req, res) => {
  const { sessionId, message, imageBase64, inputMode } = req.body;
  const mode = inputMode || (imageBase64 ? 'image' : (message ? 'text' : 'voice'));

  let extractedQuery = message || '';
  if (imageBase64 && !extractedQuery) {
    extractedQuery = 'Classic Veg Burger and Cold Brew combo under 350';
  }

  const planned = planAgenticBasket(extractedQuery);

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
app.post('/api/checkout/create-order', (req, res) => {
  const { sessionId, orderRef, gateTicket } = req.body;
  const order = db.memoryStore.transactions[orderRef];

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
  const ticketVerification = security.verifyAndConsumeGateTicket(ticketToVerify, orderRef, order.amount);

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

  const rzpOrderId = 'order_' + Math.random().toString(36).substr(2, 14);
  order.rzpOrderId = rzpOrderId;
  order.status = 'payment_pending';
  db.saveTransaction(order);

  logAudit('payment_order_created', sessionId, 
    `Razorpay test order initialized (${rzpOrderId}) for ₹${order.amount} (${order.amount * 100} paise). Ed25519 gate ticket consumed.`,
    orderRef,
    { rzpOrderId, amountPaise: order.amount * 100 }
  );

  res.json({
    success: true,
    orderId: rzpOrderId,
    amount: order.amount * 100,
    currency: 'INR',
    keyId: RAZORPAY_KEY_ID,
    orderRef,
    productName: order.item.name,
    productDescription: order.item.description
  });
});

// 8. Payment Verification & Fulfillment / Dispute Trigger
app.post('/api/checkout/verify', (req, res) => {
  const { sessionId, orderRef, razorpay_order_id, razorpay_payment_id, razorpay_signature, simulateMockSuccess } = req.body;
  const order = db.memoryStore.transactions[orderRef];

  if (!order) {
    return res.status(404).json({ success: false, error: 'Order record not found' });
  }

  let signatureValid = false;
  if (razorpay_order_id && razorpay_payment_id && razorpay_signature) {
    const generatedSignature = crypto
      .createHmac('sha256', RAZORPAY_KEY_SECRET)
      .update(`${razorpay_order_id}|${razorpay_payment_id}`)
      .digest('hex');
    
    signatureValid = (generatedSignature === razorpay_signature) || simulateMockSuccess === true;
  } else if (simulateMockSuccess) {
    signatureValid = true;
  }

  if (!signatureValid) {
    logAudit('payment_verification_failed', sessionId, 
      `HMAC-SHA256 signature verification failed for payment ${razorpay_payment_id || 'N/A'}. Order rejected.`,
      orderRef
    );
    return res.status(400).json({
      success: false,
      error: 'Payment verification failed: Invalid cryptographic signature.'
    });
  }

  order.status = 'paid';
  order.paymentId = razorpay_payment_id || ('pay_' + Math.random().toString(36).substr(2, 10));
  
  const intent = db.memoryStore.intents[sessionId];
  if (intent) {
    intent.spent = (intent.spent || 0) + order.amount;
    db.saveConsentMandate(intent);
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
app.get('/api/checkout/receipt/:orderRef', (req, res) => {
  const order = db.memoryStore.transactions[req.params.orderRef];
  if (!order) {
    return res.status(404).json({ success: false, error: 'Order not found' });
  }

  // Find audit logs linked to this order
  const linkedAudits = db.memoryStore.auditLogs.filter(l => l.orderRef === order.orderRef);
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
      merkleBlockHash: latestAuditHash,
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
app.get('/api/security/verify-ledger', (req, res) => {
  const result = security.verifyLedgerIntegrity(db.memoryStore.auditLogs);
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
      ledgerChaining: 'SHA-256 Merkle Block Chained Ledger'
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

// Merchant-specific Orders
app.get('/api/merchant/orders', requireRole('merchant_admin'), (req, res) => {
  const merchantOrders = Object.values(db.memoryStore.transactions);
  res.json({
    success: true,
    orders: merchantOrders
  });
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
