/**
 * app.js
 * Frontend logic for TrustLane authenticated app
 * Integrated with Real-Time SSE Menu Stream, TimescaleDB Persistence,
 * NPCI Trust & Security Layer, Live Attack Simulator, and Kaggle 3-Sigma Anomaly Visualizer
 */

// Persistent Session ID for gate checks and audit logging
let currentSessionId = localStorage.getItem('trustlane_session_id');
if (!currentSessionId) {
  currentSessionId = 'sess_' + Math.random().toString(36).substr(2, 9);
  localStorage.setItem('trustlane_session_id', currentSessionId);
}

let activeProposal = null;
let currentCatalog = [];
let speechRecognition = null;
let isRecording = false;
let sseSource = null;
let sandboxCategory = 'food';
let sandboxAmount = 490;

// -------------------------------------------------------------
// INITIALIZATION & TAB ROUTING
// -------------------------------------------------------------
document.addEventListener('DOMContentLoaded', async () => {
  setupTabs();
  initAuthObserver();
  initSpeechRecognition();
  initSSEMenuStream();
  await window.KaggleAnomalyVisualizer.loadRiskProfiles();
  window.KaggleAnomalyVisualizer.initCanvas('gateGaussianCanvas');
  window.KaggleAnomalyVisualizer.initCanvas('labGaussianCanvas');
  
  loadCatalog();
  loadConsentStatus();
  loadAuditTrail();
  loadSystemTelemetry();
  updateSandboxScore();

  const urlParams = new URLSearchParams(window.location.search);
  const targetTab = urlParams.get('tab');
  if (targetTab) {
    switchTab(targetTab);
  }
});

function setupTabs() {
  const tabs = document.querySelectorAll('.tab-btn');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const targetId = tab.getAttribute('data-tab');
      switchTab(targetId);
    });
  });
}

function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

  const btn = document.querySelector(`.tab-btn[data-tab="${tabId}"]`);
  const content = document.getElementById(tabId);
  if (btn) btn.classList.add('active');
  if (content) content.classList.add('active');

  if (tabId === 'audit-tab') {
    loadAuditTrail();
    loadSystemTelemetry();
  }
  if (tabId === 'merchant-tab') loadMerchantOrders();
  if (tabId === 'catalog-tab') loadCatalog();
  if (tabId === 'anomaly-tab') {
    setTimeout(() => {
      window.KaggleAnomalyVisualizer.setTransaction(sandboxCategory, sandboxAmount);
      updateSandboxScore();
    }, 100);
  }
}

// -------------------------------------------------------------
// REAL-TIME SSE MENU STREAM & SIMULATION CONTROLS
// -------------------------------------------------------------
function initSSEMenuStream() {
  if (typeof EventSource === 'undefined') return;

  try {
    if (sseSource) sseSource.close();
    sseSource = new EventSource('/api/menu/stream');

    sseSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.catalog) {
          currentCatalog = data.catalog;
          renderCatalog();
        }

        const headlineEl = document.getElementById('liveTickerHeadline');
        if (headlineEl && data.message) {
          headlineEl.textContent = `[${new Date().toLocaleTimeString()}] ${data.message}`;
          headlineEl.style.color = data.type?.includes('rush') ? '#f59e0b' : (data.type?.includes('flash') ? '#38bdf8' : '#94a3b8');
        }
      } catch (e) {
        console.warn('SSE parse error:', e);
      }
    };
  } catch (err) {
    console.error('SSE initialization failed:', err);
  }
}

async function triggerMenuSimulation(eventName) {
  try {
    const res = await fetch('/api/menu/simulate-event', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ eventName })
    });
    const data = await res.json();
    if (data.success && data.catalog) {
      currentCatalog = data.catalog;
      renderCatalog();
    }
  } catch (err) {
    alert('Simulation trigger error: ' + err.message);
  }
}

// -------------------------------------------------------------
// AUTH & RBAC CONTROLS
// -------------------------------------------------------------
function initAuthObserver() {
  window.TrustLaneAuth.onAuthStateChanged((user, role) => {
    const roleSelector = document.getElementById('roleSelector');
    const userEmailDisplay = document.getElementById('userEmailDisplay');
    const userAvatar = document.getElementById('userAvatar');
    const tabNavMerchant = document.getElementById('tabNavMerchant');
    const catalogAdminIndicator = document.getElementById('catalogAdminIndicator');

    if (roleSelector) roleSelector.value = role;
    if (userEmailDisplay) userEmailDisplay.textContent = `${role}@trustlane.ai`;
    if (userAvatar) userAvatar.textContent = role.charAt(0).toUpperCase();

    if (tabNavMerchant) {
      tabNavMerchant.style.display = (role === 'merchant_admin') ? 'inline-flex' : 'none';
    }

    if (catalogAdminIndicator) {
      catalogAdminIndicator.textContent = (role === 'merchant_admin') 
        ? '⚡ (Merchant Admin Mode: Click item price/stock to edit)'
        : '(Viewing as Buyer: Read Only)';
    }

    const activeTab = document.querySelector('.tab-btn.active')?.getAttribute('data-tab');
    if (role === 'merchant_admin' && activeTab !== 'merchant-tab' && activeTab !== 'catalog-tab') {
      switchTab('merchant-tab');
    } else if (role === 'auditor' && activeTab !== 'audit-tab') {
      switchTab('audit-tab');
    } else if (role === 'buyer' && activeTab === 'merchant-tab') {
      switchTab('agent-tab');
    }

    renderCatalog();
  });
}

function handleRoleSwitch(newRole) {
  window.TrustLaneAuth.switchRole(newRole);
}

// -------------------------------------------------------------
// 1. CONSENT & SPEND-CAP (Ed25519)
// -------------------------------------------------------------
async function createConsentRecord() {
  const cap = document.getElementById('consentCapInput').value;
  const merchant = document.getElementById('consentMerchantInput').value;
  const feedback = document.getElementById('consentFeedbackBox');

  try {
    const res = await fetch('/api/consent/create', {
      method: 'POST',
      headers: window.TrustLaneAuth.getAuthHeaders(currentSessionId),
      body: JSON.stringify({
        sessionId: currentSessionId,
        cap: Number(cap),
        merchant
      })
    });

    const data = await res.json();
    if (data.success) {
      feedback.style.display = 'block';
      feedback.className = 'status-tag status-success';
      feedback.style.width = '100%';
      feedback.style.padding = '0.75rem';
      feedback.innerHTML = `✅ Ed25519 Mandate Granted: ₹${data.consent.cap} cap signed with nonce [${data.consent.nonce.substr(0, 10)}...]. Valid for 1 hr.`;
      loadConsentStatus();
      loadAuditTrail();
    } else {
      alert('Error: ' + data.error);
    }
  } catch (err) {
    alert('Failed to register consent: ' + err.message);
  }
}

async function loadConsentStatus() {
  try {
    const res = await fetch(`/api/consent/status?sessionId=${currentSessionId}`);
    const data = await res.json();
    const summary = document.getElementById('activeConsentSummary');

    if (data.success && data.consent && data.active) {
      summary.innerHTML = `
        <span style="color: #10b981;">Active</span> — Cap: ₹${data.consent.cap} | Spent: ₹${data.consent.spent} | <strong style="color: #93c5fd;">Remaining: ₹${data.consent.remaining}</strong>
      `;
    } else {
      summary.innerHTML = `
        <span style="color: #ef4444;">No Active Mandate</span> — Agent cannot execute payments until you grant a spend cap.
      `;
    }
  } catch (err) {
    console.error('Failed to load consent status:', err);
  }
}

// -------------------------------------------------------------
// 2. MULTIMODAL AGENT INPUTS & COMBO PLANNING
// -------------------------------------------------------------
function quickSuggest(text) {
  document.getElementById('agentTextInput').value = text;
  sendAgentQuery('text', text);
}

function initSpeechRecognition() {
  const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (SpeechRecognition) {
    speechRecognition = new SpeechRecognition();
    speechRecognition.continuous = false;
    speechRecognition.interimResults = false;
    speechRecognition.lang = 'en-US';

    speechRecognition.onresult = (event) => {
      const transcript = event.results[0][0].transcript;
      document.getElementById('agentTextInput').value = transcript;
      sendAgentQuery('voice', transcript);
    };

    speechRecognition.onerror = (event) => {
      console.warn('Speech recognition error:', event.error);
      stopVoiceRecording();
    };

    speechRecognition.onend = () => {
      stopVoiceRecording();
    };
  }
}

function toggleVoiceInput() {
  if (!speechRecognition) {
    const simulatedVoice = prompt("Speech-to-Text: Enter your spoken query:", "Order me a classic veg burger under 300");
    if (simulatedVoice) {
      document.getElementById('agentTextInput').value = simulatedVoice;
      sendAgentQuery('voice', simulatedVoice);
    }
    return;
  }

  if (isRecording) {
    speechRecognition.stop();
    stopVoiceRecording();
  } else {
    try {
      speechRecognition.start();
      isRecording = true;
      const btn = document.getElementById('btnVoiceInput');
      btn.classList.add('recording');
      btn.innerHTML = '🔴';
    } catch (e) {
      console.error(e);
    }
  }
}

function stopVoiceRecording() {
  isRecording = false;
  const btn = document.getElementById('btnVoiceInput');
  if (btn) {
    btn.classList.remove('recording');
    btn.innerHTML = '🎙️';
  }
}

function handleImageUpload(event) {
  const file = event.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = (e) => {
    const base64 = e.target.result;
    appendUserMessage(`[Uploaded photo: ${file.name}]`, 'image');
    sendAgentQueryMultimodal('image', base64, 'Classic Veg Burger and Cold Brew combo under 350');
  };
  reader.readAsDataURL(file);
}

function appendUserMessage(text, mode = 'text') {
  const feed = document.getElementById('agentMessageFeed');
  const div = document.createElement('div');
  div.className = 'msg msg-user';
  div.innerHTML = `<span class="msg-mode-tag">Input via ${mode}</span>${text}`;
  feed.appendChild(div);
  feed.scrollTop = feed.scrollHeight;
}

function appendAgentMessage(text, modeTag = 'Agent Response') {
  const feed = document.getElementById('agentMessageFeed');
  const div = document.createElement('div');
  div.className = 'msg msg-agent';
  div.innerHTML = `<span class="msg-mode-tag">🤖 ${modeTag}</span>${text}`;
  feed.appendChild(div);
  feed.scrollTop = feed.scrollHeight;
}

async function sendAgentQuery(mode = 'text', customText = null, autoCheckout = false) {
  const inputEl = document.getElementById('agentTextInput');
  const query = customText || inputEl.value.trim();
  if (!query) return;

  if (mode === 'text' && !customText) appendUserMessage(query, 'text');
  else if (mode === 'voice' && !customText) appendUserMessage(query, 'voice');
  else if (customText) appendUserMessage(customText, mode);

  inputEl.value = '';

  try {
    const res = await fetch('/api/agent/query', {
      method: 'POST',
      headers: window.TrustLaneAuth.getAuthHeaders(currentSessionId),
      body: JSON.stringify({
        sessionId: currentSessionId,
        message: query
      })
    });

    const data = await res.json();
    handleAgentResponse(data, mode, autoCheckout);
  } catch (err) {
    appendAgentMessage(`❌ Error querying agent: ${err.message}`);
  }
}

async function sendAgentQueryMultimodal(mode, imageBase64, fallbackText) {
  try {
    const res = await fetch('/api/agent/query-multimodal', {
      method: 'POST',
      headers: window.TrustLaneAuth.getAuthHeaders(currentSessionId),
      body: JSON.stringify({
        sessionId: currentSessionId,
        imageBase64,
        message: fallbackText,
        inputMode: mode
      })
    });

    const data = await res.json();
    handleAgentResponse(data, mode, false);
  } catch (err) {
    appendAgentMessage(`❌ Error processing photo: ${err.message}`);
  }
}

function handleAgentResponse(data, inputMode, autoCheckout = false) {
  if (data.success && data.proposedOrder) {
    activeProposal = data.proposedOrder;
    appendAgentMessage(`Parsed from ${inputMode}: ${data.message} Verifying Gate Checkpoint...`, `Agent Plan`);
    renderProposalCheckpoint(data.proposedOrder);
    triggerGateCheck(data.proposedOrder.orderRef, autoCheckout);
  } else {
    activeProposal = null;
    appendAgentMessage(`⚠️ ${data.message || 'Could not fulfill request.'}`, 'Catalog Matcher');
    document.getElementById('orderStatusTag').className = 'status-tag status-danger';
    document.getElementById('orderStatusTag').textContent = 'Match Failed';
    document.getElementById('checkpointCanvasWrapper').style.display = 'none';
    document.getElementById('checkpointBody').innerHTML = `
      <div style="padding: 1rem; border-radius: 8px; background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.3); color: #fca5a5;">
        <strong>Agent Proposal Refused:</strong><br>${data.message}
      </div>
    `;
  }
  loadAuditTrail();
}

// -------------------------------------------------------------
// 3. GATE CHECKPOINT & AUTONOMOUS CHECKOUT
// -------------------------------------------------------------
function renderProposalCheckpoint(order) {
  const container = document.getElementById('checkpointBody');
  document.getElementById('orderStatusTag').className = 'status-tag status-neutral';
  document.getElementById('orderStatusTag').textContent = 'Evaluating Gate';

  let itemsHtml = '';
  if (order.isCombo && order.items && order.items.length > 1) {
    itemsHtml = `
      <div style="margin-top: 0.6rem; padding-top: 0.5rem; border-top: 1px solid rgba(255,255,255,0.08);">
        <span style="font-size: 0.72rem; color: #93c5fd; font-weight: 700; text-transform: uppercase;">Combo Items Breakdown:</span>
        ${order.items.map(i => `
          <div class="combo-line-item">
            <span>${i.image || '•'} ${i.name}</span>
            <span style="font-family: monospace; font-weight: 600;">₹${i.price}</span>
          </div>
        `).join('')}
      </div>
    `;
  }

  container.innerHTML = `
    <div class="order-preview-card">
      <div class="order-info" style="width: 100%;">
        <div style="display: flex; justify-content: space-between; align-items: flex-start;">
          <div>
            <h3>${order.item.name}</h3>
            <p>${order.item.description}</p>
          </div>
          <div class="order-price">
            ₹${order.amount}
          </div>
        </div>
        ${itemsHtml}
        <p style="margin-top: 0.4rem; font-family: monospace; font-size: 0.72rem; color: #64748b;">
          Ref: ${order.orderRef} | Mode: ${order.inputMode} | Type: ${order.isCombo ? 'Multi-Item Basket' : 'Single'}
        </p>
      </div>
    </div>
    <div id="gateDecisionBox" style="font-size: 0.85rem; color: var(--text-muted); margin-top: 1rem;">
      ⏳ Evaluating Ephemeral Mandate, Velocity & Kaggle 3-Sigma Anomaly...
    </div>
  `;

  const canvasWrapper = document.getElementById('checkpointCanvasWrapper');
  if (canvasWrapper) {
    canvasWrapper.style.display = 'block';
    window.KaggleAnomalyVisualizer.setTransaction(order.item.category || 'food', order.amount);
  }
}

async function triggerGateCheck(orderRef, autoCheckout = false) {
  const decisionBox = document.getElementById('gateDecisionBox');
  const statusTag = document.getElementById('orderStatusTag');

  try {
    const res = await fetch('/api/gate/check', {
      method: 'POST',
      headers: window.TrustLaneAuth.getAuthHeaders(currentSessionId),
      body: JSON.stringify({
        sessionId: currentSessionId,
        orderRef
      })
    });

    const data = await res.json();
    loadAuditTrail();

    if (data.approved) {
      statusTag.className = 'status-tag status-success';
      statusTag.textContent = 'Gate Approved';

      const ticketPreview = data.gateTicket ? data.gateTicket.substr(0, 24) + '...' : 'Signed (Ed25519)';

      decisionBox.innerHTML = `
        <div class="gate-decision-box approved">
          <div class="gate-decision-title" style="color: #6ee7b7;">
            <span>✅</span> Gate Approved & Ed25519 Ticket Issued
          </div>
          <div class="gate-decision-reason">
            ${data.reason}
          </div>
          <div style="margin-top: 0.5rem; font-family: monospace; font-size: 0.72rem; color: #93c5fd;">
            🎟️ Ed25519 Ticket: <strong>${ticketPreview}</strong> (One-time, 5-min TTL)
          </div>
        </div>
        <button class="btn btn-primary" style="width: 100%; margin-top: 1rem;" onclick="launchAutonomousRazorpayFlow('${orderRef}', '${data.gateTicket || ''}')">
          💳 Execute Razorpay Autonomous Checkout →
        </button>
      `;

      if (autoCheckout) {
        setTimeout(() => {
          launchAutonomousRazorpayFlow(orderRef, data.gateTicket || '');
        }, 800);
      }
    } else {
      statusTag.className = 'status-tag status-danger';
      statusTag.textContent = 'Gate Blocked';

      decisionBox.innerHTML = `
        <div class="gate-decision-box blocked">
          <div class="gate-decision-title" style="color: #fca5a5;">
            <span>🛑</span> Gate Refused Payment
          </div>
          <div class="gate-decision-reason">
            ${data.reason}
          </div>
        </div>
      `;
    }
  } catch (err) {
    decisionBox.innerHTML = `<span style="color: #ef4444;">Gate Check Error: ${err.message}</span>`;
  }
}

async function launchAutonomousRazorpayFlow(orderRef, gateTicket = '') {
  if (window.TrustLaneAuth.role === 'auditor') {
    alert('RBAC Violation: Auditor role is Read-Only and cannot initiate payments.');
    return;
  }

  try {
    const res = await fetch('/api/checkout/create-order', {
      method: 'POST',
      headers: window.TrustLaneAuth.getAuthHeaders(currentSessionId),
      body: JSON.stringify({
        sessionId: currentSessionId,
        orderRef,
        gateTicket
      })
    });

    const orderData = await res.json();
    if (!orderData.success) {
      alert('Security Refusal: ' + orderData.error);
      loadAuditTrail();
      return;
    }

    loadAuditTrail();
    renderRazorpayAutonomousScreen(orderData);
  } catch (err) {
    alert('Payment initialization failed: ' + err.message);
  }
}

function renderRazorpayAutonomousScreen(orderData) {
  const modalContent = document.getElementById('modalContent');
  modalContent.innerHTML = `
    <div class="rzp-modal-header">
      <div class="rzp-brand-badge">
        <svg width="28" height="28" viewBox="0 0 48 48" fill="none">
          <path d="M14 8L8 40H22L28 8H14Z" fill="#38BDF8"/>
          <path d="M28 8L20 40H34L40 8H28Z" fill="#0284C7"/>
        </svg>
        <div class="rzp-logo-text">Razorpay <span>Checkout</span></div>
      </div>
      <span class="status-tag status-info" style="font-size: 0.68rem; background: rgba(56, 189, 248, 0.2); color: #38bdf8; border: 1px solid #0284c7;">
        Ed25519 Ticket Verified
      </span>
    </div>

    <div class="rzp-modal-body">
      <div style="display: flex; justify-content: space-between; align-items: baseline; border-bottom: 1px solid rgba(255,255,255,0.08); padding-bottom: 0.75rem;">
        <div>
          <h3 style="font-size: 1.1rem; color: #ffffff;">${orderData.productName}</h3>
          <p style="font-size: 0.78rem; color: var(--text-dim);">${orderData.productDescription}</p>
        </div>
        <div style="font-size: 1.35rem; font-weight: 800; color: #38bdf8; font-family: monospace;">
          ₹${orderData.amount / 100}
        </div>
      </div>

      <div class="agent-auto-stepper">
        <div class="auto-step-item" id="step1">
          <div class="auto-step-icon">1</div>
          <span>Verifying Signed Ed25519 Gate Ticket & Nonce...</span>
        </div>
        <div class="auto-step-item" id="step2">
          <div class="auto-step-icon">2</div>
          <span>Creating Razorpay Payment Session (${orderData.orderId})...</span>
        </div>
        <div class="auto-step-item" id="step3">
          <div class="auto-step-icon">3</div>
          <span>Generating HMAC-SHA256 Cryptographic Signature...</span>
        </div>
        <div class="auto-step-item" id="step4">
          <div class="auto-step-icon">4</div>
          <span>Triggering Merchant Fulfillment & Writing to TimescaleDB...</span>
        </div>
      </div>

      <div class="rzp-progress-bar-wrap">
        <div class="rzp-progress-bar-fill" id="rzpProgressBar"></div>
      </div>

      <div id="paymentResultHUD" style="display: none; padding: 0.85rem; border-radius: 8px; font-size: 0.82rem;"></div>
    </div>
  `;

  openModal();
  executeAutonomousPaymentSteps(orderData);
}

async function executeAutonomousPaymentSteps(orderData) {
  const step1 = document.getElementById('step1');
  const step2 = document.getElementById('step2');
  const step3 = document.getElementById('step3');
  const step4 = document.getElementById('step4');
  const bar = document.getElementById('rzpProgressBar');
  const resultHUD = document.getElementById('paymentResultHUD');

  step1.classList.add('active');
  bar.style.width = '25%';

  await new Promise(r => setTimeout(r, 600));
  step1.classList.remove('active');
  step1.classList.add('completed');
  step2.classList.add('active');
  bar.style.width = '50%';

  await new Promise(r => setTimeout(r, 600));
  step2.classList.remove('active');
  step2.classList.add('completed');
  step3.classList.add('active');
  bar.style.width = '75%';

  await new Promise(r => setTimeout(r, 600));
  step3.classList.remove('active');
  step3.classList.add('completed');
  step4.classList.add('active');
  bar.style.width = '90%';

  try {
    const res = await fetch('/api/checkout/verify', {
      method: 'POST',
      headers: window.TrustLaneAuth.getAuthHeaders(currentSessionId),
      body: JSON.stringify({
        sessionId: currentSessionId,
        orderRef: orderData.orderRef,
        razorpay_order_id: orderData.orderId,
        simulateMockSuccess: true
      })
    });

    const verifyData = await res.json();
    step4.classList.remove('active');
    step4.classList.add('completed');
    bar.style.width = '100%';

    resultHUD.style.display = 'block';

    if (verifyData.fulfillment === 'failed' && verifyData.dispute) {
      resultHUD.className = 'status-tag status-warning';
      resultHUD.style.display = 'block';
      resultHUD.style.padding = '1rem';
      resultHUD.innerHTML = `
        <strong style="color: #fde68a;">⚠️ Auto-Dispute Engine Triggered:</strong><br>
        Payment of ₹${orderData.amount / 100} captured, but merchant kitchen reported an out-of-stock breach post-capture.<br>
        <strong>Automated Remediation:</strong> ${verifyData.dispute.suggestedResolution}<br>
        <div style="margin-top: 10px; display: flex; gap: 8px;">
          <button class="btn btn-secondary" style="font-size: 0.75rem;" onclick="showCryptographicReceipt('${orderData.orderRef}')">📄 View Cryptographic Proof</button>
        </div>
      `;
    } else {
      resultHUD.className = 'status-tag status-success';
      resultHUD.style.display = 'block';
      resultHUD.style.padding = '1rem';
      resultHUD.innerHTML = `
        <strong>🎉 Payment Captured & Order Dispatched!</strong><br>
        Amount ₹${orderData.amount / 100} verified with cryptographic signature.<br>
        <span style="font-size: 0.75rem; opacity: 0.85;">Immutable trial recorded into TimescaleDB Hypertable.</span>
        <div style="margin-top: 10px; display: flex; gap: 8px;">
          <button class="btn btn-secondary" style="font-size: 0.75rem;" onclick="showCryptographicReceipt('${orderData.orderRef}')">📄 Download Cryptographic Proof</button>
        </div>
      `;
    }

    loadConsentStatus();
    loadAuditTrail();
    loadCatalog();
  } catch (err) {
    resultHUD.className = 'status-tag status-danger';
    resultHUD.style.display = 'block';
    resultHUD.textContent = 'Payment execution error: ' + err.message;
  }
}

// -------------------------------------------------------------
// 4. KILLER FEATURE 1: LIVE ATTACK & EXPLOIT SIMULATOR
// -------------------------------------------------------------
async function runSimulatedAttack(attackType) {
  const resultBox = document.getElementById('attackResultBox');
  resultBox.style.display = 'block';
  resultBox.innerHTML = `
    <div style="padding: 1rem; background: rgba(0,0,0,0.5); border-radius: 8px; font-size: 0.82rem; color: #94a3b8;">
      ⏳ Launching exploit simulation: <strong>${attackType}</strong>...
    </div>
  `;

  try {
    const res = await fetch('/api/security/simulate-attack', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ attackType })
    });

    const data = await res.json();
    if (data.success && data.result) {
      const r = data.result;
      resultBox.innerHTML = `
        <div class="attack-intercept-card blocked">
          <div class="attack-intercept-title">
            <span>🛡️</span> Zero-Trust Defense Triggered: ${r.attackType} Intercepted!
          </div>
          <p style="font-size: 0.8rem; color: #e2e8f0; margin-bottom: 0.4rem;">
            <strong>Scenario:</strong> ${r.description}
          </p>
          <div style="background: rgba(0,0,0,0.4); border: 1px solid rgba(239,68,68,0.3); border-radius: 6px; padding: 0.6rem; color: #fca5a5; font-size: 0.78rem;">
            <strong>Security Refusal:</strong> ${r.verdict}
          </div>
          <div style="margin-top: 0.5rem; font-size: 0.72rem; color: #6ee7b7; font-weight: 600;">
            Enforced by: ${r.securityLayer}
          </div>
        </div>
      `;
      loadAuditTrail();
    }
  } catch (err) {
    resultBox.innerHTML = `<span style="color: #ef4444;">Simulation failed: ${err.message}</span>`;
  }
}

// -------------------------------------------------------------
// 5. KILLER FEATURE 3: DOWNLOADABLE CRYPTOGRAPHIC RECEIPTS
// -------------------------------------------------------------
async function showCryptographicReceipt(orderRef) {
  try {
    const res = await fetch(`/api/checkout/receipt/${orderRef}`);
    const data = await res.json();

    if (!data.success || !data.receipt) {
      alert('Could not find cryptographic receipt for ' + orderRef);
      return;
    }

    const r = data.receipt;
    const modalContent = document.getElementById('modalContent');
    modalContent.innerHTML = `
      <div class="receipt-card">
        <div class="receipt-header">
          <div>
            <h3 style="color: #ffffff; font-size: 1.15rem;">🛡️ TrustLane Cryptographic Receipt</h3>
            <span style="font-size: 0.72rem; color: #94a3b8;">Verifiable Digital Payment Proof</span>
          </div>
          <span class="status-tag status-success">Verified</span>
        </div>

        <div class="receipt-row">
          <span style="color: var(--text-dim);">Order Reference:</span>
          <strong style="font-family: monospace; color: #93c5fd;">${r.orderRef}</strong>
        </div>
        <div class="receipt-row">
          <span style="color: var(--text-dim);">Session ID:</span>
          <strong style="font-family: monospace;">${r.sessionId}</strong>
        </div>
        <div class="receipt-row">
          <span style="color: var(--text-dim);">Item / Basket:</span>
          <span>${r.item}</span>
        </div>
        <div class="receipt-row">
          <span style="color: var(--text-dim);">Amount Captured:</span>
          <strong style="font-size: 1rem; color: #38bdf8; font-family: monospace;">₹${r.amount}</strong>
        </div>
        <div class="receipt-row">
          <span style="color: var(--text-dim);">Payment ID:</span>
          <span style="font-family: monospace;">${r.paymentId || 'pay_simulated'}</span>
        </div>

        <div>
          <span style="font-size: 0.75rem; color: var(--text-dim); display: block; margin-bottom: 0.25rem;">Cryptographic Proof (SHA-256 Block Hash):</span>
          <div class="receipt-proof-box">
            ${r.cryptographicProof.merkleBlockHash}
          </div>
        </div>

        <div style="display: flex; gap: 8px; margin-top: 0.5rem;">
          <button class="btn btn-primary" style="flex: 1;" onclick="downloadReceiptJSON('${orderRef}')">📥 Download Signed JSON-LD</button>
          <button class="btn btn-secondary" style="flex: 1;" onclick="closeModal()">Close</button>
        </div>
      </div>
    `;

    openModal();
  } catch (err) {
    alert('Error loading receipt: ' + err.message);
  }
}

function downloadReceiptJSON(orderRef) {
  fetch(`/api/checkout/receipt/${orderRef}`)
    .then(res => res.json())
    .then(data => {
      const blob = new Blob([JSON.stringify(data.receipt, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `TrustLane_Proof_${orderRef}.json`;
      a.click();
      URL.revokeObjectURL(url);
    });
}

// -------------------------------------------------------------
// 6. KAGGLE ANOMALY LAB & DISTRIBUTION TOGGLE
// -------------------------------------------------------------
function setVisualizerModel(model) {
  window.KaggleAnomalyVisualizer.setDistributionModel(model);
}

function handleSandboxCategoryChange(val) {
  sandboxCategory = val;
  window.KaggleAnomalyVisualizer.setTransaction(sandboxCategory, sandboxAmount);
  updateSandboxScore();
}

function handleSandboxAmountChange(val) {
  sandboxAmount = Number(val);
  document.getElementById('sandboxAmountDisplay').textContent = `₹${sandboxAmount}`;
  window.KaggleAnomalyVisualizer.setTransaction(sandboxCategory, sandboxAmount);
  updateSandboxScore();
}

function setSandboxPreset(cat, amt) {
  sandboxCategory = cat;
  sandboxAmount = amt;
  const catSel = document.getElementById('sandboxCategorySelect');
  const amtSlide = document.getElementById('sandboxAmountSlider');
  if (catSel) catSel.value = cat;
  if (amtSlide) amtSlide.value = amt;
  document.getElementById('sandboxAmountDisplay').textContent = `₹${amt}`;
  window.KaggleAnomalyVisualizer.setTransaction(cat, amt);
  updateSandboxScore();
}

function updateSandboxScore() {
  const hud = document.getElementById('sandboxScoreHud');
  const mathHud = document.getElementById('labMathHud');
  if (!hud) return;

  const res = window.KaggleAnomalyVisualizer.calculateZScore(sandboxAmount, sandboxCategory);
  if (!res || !res.profile) return;

  const isAnomaly = res.isAnomaly;
  const zScore = res.zScore;
  const zLogNormal = res.zScoreLogNormal;

  hud.innerHTML = `
    <div style="background: rgba(255,255,255,0.03); border: 1px solid var(--border-medium); border-radius: 8px; padding: 0.85rem;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.4rem;">
        <span style="font-size: 0.78rem; font-weight: 700; color: #94a3b8;">Dual-Model Score:</span>
        <span class="status-tag ${isAnomaly ? 'status-danger' : (zScore > 2.0 ? 'status-warning' : 'status-success')}">
          ${zScore}σ (Gaussian) | ${zLogNormal}σ (Log-Normal)
        </span>
      </div>
      <div class="anomaly-meter-bar">
        <div class="anomaly-meter-fill" style="width: ${Math.min(100, Math.max(10, (zScore / 5) * 100))}%;"></div>
      </div>
      <div style="font-size: 0.78rem; color: var(--text-muted); margin-top: 0.5rem; line-height: 1.4;">
        ${isAnomaly 
          ? `<strong style="color: #fca5a5;">🚨 3-Sigma Anomaly Triggered!</strong> Exceeds ₹${res.threshold3Sigma} threshold (Occurrence: < 0.13%).`
          : `✅ Within expected statistical bounds (Threshold: > ₹${res.threshold3Sigma}).`}
      </div>
    </div>
  `;

  if (mathHud) {
    mathHud.innerHTML = `
      <div class="math-step-card">
        <div class="math-header">
          <span class="math-badge">Empirical Distribution Check</span>
          <span class="math-source">Dataset: ${res.profile.source}</span>
        </div>
        <div class="math-formula">
          Gaussian: Z = \\frac{₹${sandboxAmount} - ₹${res.mean}}{₹${res.std}} = \\mathbf{${zScore}\\sigma} \\quad | \\quad Log-Normal: Z_{\\ln} = \\mathbf{${zLogNormal}\\sigma}
        </div>
        <div class="math-verdict ${isAnomaly ? 'verdict-anomaly' : 'verdict-pass'}">
          ${isAnomaly 
            ? `🚨 <strong>Kaggle Anomaly Detected:</strong> Proposed transaction ₹${sandboxAmount} is <strong>${zScore}σ / ${zLogNormal}σ</strong> above baseline.` 
            : `✅ <strong>Normal Band:</strong> Transaction is within expected operational range.`}
        </div>
      </div>
    `;
  }
}

// -------------------------------------------------------------
// 7. TIMESCALEDB TELEMETRY & AUDIT LEDGER
// -------------------------------------------------------------
async function loadSystemTelemetry() {
  try {
    const res = await fetch('/api/system/status');
    const data = await res.json();
    if (data.success && data.timescaledb) {
      const dbInfo = data.timescaledb;
      const pill = document.getElementById('dbStatusPill');
      const typeEl = document.getElementById('telemetryStorageType');
      const chunksEl = document.getElementById('telemetryChunks');
      const rowsEl = document.getElementById('telemetryTotalRows');
      const hashEl = document.getElementById('telemetryLastHash');

      if (pill) {
        pill.innerHTML = `<span class="pulse-dot"></span> ${dbInfo.connected ? (dbInfo.isTimescaleActive ? 'TimescaleDB Partitioned' : 'PostgreSQL Connected') : 'Hybrid Persistent File Store'}`;
      }
      if (typeEl) typeEl.textContent = dbInfo.storageType;
      if (chunksEl) chunksEl.textContent = dbInfo.hypertableChunks > 0 ? `${dbInfo.hypertableChunks} Active Chunks` : 'Partitioned Table';
      if (rowsEl) rowsEl.textContent = dbInfo.totalAuditRecords;
      if (hashEl) hashEl.textContent = dbInfo.lastBlockHash;
    }
  } catch (e) {
    console.warn('Telemetry load failed:', e);
  }
}

async function loadAuditTrail() {
  const filter = document.getElementById('auditEventFilter')?.value || 'all';
  try {
    const res = await fetch(`/api/audit?eventTypeFilter=${filter}`, {
      headers: window.TrustLaneAuth.getAuthHeaders(currentSessionId)
    });
    const data = await res.json();

    const tbody = document.getElementById('auditTableBody');
    if (!tbody) return;

    if (!data.logs || data.logs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-dim);">No audit logs recorded yet.</td></tr>`;
      return;
    }

    tbody.innerHTML = data.logs.map(log => {
      const hashPreview = (log.blockHash || log.block_hash || '0000').substr(0, 10) + '...';
      return `
        <tr>
          <td style="white-space: nowrap; font-family: monospace; font-size: 0.72rem; color: #94a3b8;">
            ${new Date(log.ts).toLocaleTimeString()}
          </td>
          <td>
            <span class="audit-tag" style="${getAuditBadgeStyle(log.type)}">
              ${log.type}
            </span>
          </td>
          <td style="font-family: monospace; font-size: 0.72rem; color: #94a3b8;">
            ${log.sessionId || 'system'}
          </td>
          <td style="font-family: monospace; font-size: 0.72rem; color: #93c5fd;">
            ${log.orderRef ? `<a href="javascript:void(0)" onclick="showCryptographicReceipt('${log.orderRef}')" style="color: #93c5fd; text-decoration: underline;">${log.orderRef}</a>` : '—'}
          </td>
          <td style="font-family: monospace; font-size: 0.72rem; color: #a78bfa;" title="${log.blockHash || ''}">
            ${hashPreview}
          </td>
          <td style="font-size: 0.78rem; color: #e2e8f0;">
            ${log.detail}
          </td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    console.error('Failed to load audit trail:', err);
  }
}

function getAuditBadgeStyle(type) {
  if (type.includes('blocked') || type.includes('denied') || type.includes('failed') || type.includes('attack')) {
    return 'background: rgba(239, 68, 68, 0.15); color: #fca5a5; border-color: rgba(239,68,68,0.3);';
  }
  if (type.includes('approved') || type.includes('verified') || type.includes('success')) {
    return 'background: rgba(16, 185, 129, 0.15); color: #6ee7b7; border-color: rgba(16,185,129,0.3);';
  }
  if (type.includes('anomaly') || type.includes('dispute')) {
    return 'background: rgba(245, 158, 11, 0.15); color: #fde68a; border-color: rgba(245,158,11,0.3);';
  }
  return 'background: rgba(255, 255, 255, 0.06); color: #93c5fd;';
}

async function verifyLedgerIntegrity() {
  const resultBox = document.getElementById('ledgerVerificationResult');
  try {
    const res = await fetch('/api/security/verify-ledger');
    const data = await res.json();

    if (data.success && data.verification) {
      const v = data.verification;
      const html = `
        <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.35); border-radius: 8px; padding: 1rem; color: #6ee7b7;">
          <div style="display: flex; align-items: center; gap: 8px; font-weight: 700; font-size: 0.95rem; margin-bottom: 0.35rem;">
            <span>🛡️</span> Cryptographic Hash Chain Verified (100% Integrity)
          </div>
          <p style="font-size: 0.82rem; color: #e2e8f0; margin-bottom: 0.5rem;">
            ${v.message}
          </p>
          <div style="font-family: monospace; font-size: 0.72rem; color: #93c5fd;">
            Latest Chain Hash: ${v.latestBlockHash}
          </div>
        </div>
      `;

      if (resultBox) resultBox.innerHTML = html;
      else alert(v.message);
    }
  } catch (err) {
    alert('Verification failed: ' + err.message);
  }
}

// -------------------------------------------------------------
// 8. CATALOG RENDERING & EDITING
// -------------------------------------------------------------
async function loadCatalog() {
  try {
    const res = await fetch('/api/catalog');
    const data = await res.json();
    if (data.success) {
      currentCatalog = data.catalog;
      renderCatalog();
    }
  } catch (err) {
    console.error('Failed to load catalog:', err);
  }
}

function renderCatalog() {
  const grid = document.getElementById('catalogGrid');
  if (!grid) return;

  const isMerchant = window.TrustLaneAuth.role === 'merchant_admin';

  grid.innerHTML = currentCatalog.map(item => {
    const isOut = item.stock <= 0;
    const isAnomalyDemo = item.id === 'prod_2';
    const isDisputeDemo = item.id === 'prod_5';
    const surgeMultiplier = item.surgeMultiplier || 1.0;

    return `
      <div class="catalog-item-card" style="${isOut ? 'opacity: 0.7;' : ''}">
        <div class="catalog-item-header">
          <div class="catalog-emoji">${item.image || '🍽️'}</div>
          <div style="display: flex; flex-direction: column; align-items: flex-end; gap: 4px;">
            <span class="stock-tag ${isOut ? 'status-danger' : (item.stock < 5 ? 'status-warning' : 'status-success')}">
              ${isOut ? 'Out of Stock' : `${item.stock} left in kitchen`}
            </span>
            ${surgeMultiplier > 1.0 ? `<span class="status-tag status-warning" style="font-size: 0.65rem;">🔥 +${Math.round((surgeMultiplier - 1) * 100)}% Surge</span>` : ''}
            ${surgeMultiplier < 1.0 ? `<span class="status-tag status-info" style="font-size: 0.65rem; color: #38bdf8;">⚡ -${Math.round((1 - surgeMultiplier) * 100)}% Sale</span>` : ''}
          </div>
        </div>

        <div>
          <div class="catalog-item-name">${item.name}</div>
          <div class="catalog-item-desc">${item.description}</div>
          ${isAnomalyDemo ? '<div style="margin-top: 4px; font-size: 0.72rem; color: #f59e0b; font-weight: 600;">📊 Kaggle 3-Sigma Anomaly Trigger Item</div>' : ''}
          ${isDisputeDemo ? '<div style="margin-top: 4px; font-size: 0.72rem; color: #ef4444; font-weight: 600;">🎁 Auto-Dispute Trigger Item</div>' : ''}
        </div>

        <div class="catalog-item-footer">
          <div class="catalog-price">₹${item.price}</div>
          ${isMerchant 
            ? `<button class="btn btn-secondary" style="font-size: 0.75rem; padding: 0.3rem 0.65rem;" onclick="editCatalogItemPrompt('${item.id}', ${item.price}, ${item.stock})">✏️ Edit</button>`
            : `<button class="btn btn-secondary" style="font-size: 0.75rem; padding: 0.3rem 0.65rem;" onclick="orderThisItem('${item.name}')" ${isOut ? 'disabled style="opacity: 0.5;"' : ''}>🤖 Order</button>`
          }
        </div>
      </div>
    `;
  }).join('');
}

function orderThisItem(itemName) {
  switchTab('agent-tab');
  quickSuggest(`Order me ${itemName}`);
}

async function editCatalogItemPrompt(id, currentPrice, currentStock) {
  const newPrice = prompt(`Enter new price for item:`, currentPrice);
  if (newPrice === null) return;
  const newStock = prompt(`Enter new kitchen stock count:`, currentStock);
  if (newStock === null) return;

  try {
    const res = await fetch('/api/catalog/manage', {
      method: 'POST',
      headers: window.TrustLaneAuth.getAuthHeaders(currentSessionId),
      body: JSON.stringify({
        id,
        price: Number(newPrice),
        stock: Number(newStock)
      })
    });

    const data = await res.json();
    if (data.success) {
      currentCatalog = data.catalog;
      renderCatalog();
      loadAuditTrail();
    } else {
      alert('Error updating catalog: ' + data.error);
    }
  } catch (err) {
    alert('Failed to update catalog: ' + err.message);
  }
}

// -------------------------------------------------------------
// 9. MERCHANT ORDERS & DISPUTES
// -------------------------------------------------------------
async function loadMerchantOrders() {
  try {
    const res = await fetch('/api/merchant/orders', {
      headers: window.TrustLaneAuth.getAuthHeaders(currentSessionId)
    });
    const data = await res.json();

    const tbody = document.getElementById('merchantOrdersTableBody');
    if (!tbody) return;

    if (!data.orders || data.orders.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-dim);">No orders received by FreshBites Cafe yet.</td></tr>`;
      return;
    }

    tbody.innerHTML = data.orders.map(order => `
      <tr>
        <td style="font-family: monospace; font-size: 0.72rem; color: #93c5fd;">
          <a href="javascript:void(0)" onclick="showCryptographicReceipt('${order.orderRef}')" style="color: #93c5fd; text-decoration: underline;">
            ${order.orderRef}
          </a>
        </td>
        <td><strong>${order.item?.name || 'Item'}</strong><br><span style="font-size: 0.72rem; color: var(--text-dim);">${order.item?.description || ''}</span></td>
        <td style="font-family: monospace; font-size: 0.88rem; font-weight: 700;">₹${order.amount}</td>
        <td><span class="status-tag ${order.status === 'gate_approved' || order.status === 'paid' || order.status === 'fulfilled' ? 'status-success' : 'status-danger'}">${order.status}</span></td>
        <td><span class="status-tag ${order.status === 'fulfilled' ? 'status-success' : (order.status === 'fulfillment_failed' ? 'status-danger' : 'status-neutral')}">${order.status === 'fulfilled' ? 'Dispatched' : (order.status === 'fulfillment_failed' ? 'Stock Out Breach' : 'Pending')}</span></td>
        <td>${order.dispute ? `<span class="status-tag status-warning">Auto-Remediated (${order.dispute.status})</span>` : '—'}</td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Failed to load merchant orders:', err);
  }
}

// -------------------------------------------------------------
// 10. FAST DEMO PRESET SCENARIOS
// -------------------------------------------------------------
async function runPresetScenario(scenario) {
  switchTab('agent-tab');

  switch (scenario) {
    case 'happy_path':
      document.getElementById('consentCapInput').value = '300';
      await createConsentRecord();
      sendAgentQuery('text', 'Order me a classic veg burger', false);
      break;

    case 'combo_basket':
      // 🔥 Killer Feature 2: Multi-Item Combo
      document.getElementById('consentCapInput').value = '350';
      await createConsentRecord();
      sendAgentQuery('text', 'Build me a lunch combo with a burger and cold brew under 350', false);
      break;

    case 'gate_blocked':
      document.getElementById('consentCapInput').value = '50';
      await createConsentRecord();
      sendAgentQuery('text', 'Order me a classic veg burger', false);
      break;

    case 'auto_dispute':
      document.getElementById('consentCapInput').value = '500';
      await createConsentRecord();
      sendAgentQuery('text', 'Order me the mystery chef surprise box', false);
      break;

    case 'anomaly_flag':
      document.getElementById('consentCapInput').value = '1000';
      await createConsentRecord();
      sendAgentQuery('text', 'Order me a gourmet truffle burger', false);
      break;

    case 'out_of_stock':
      sendAgentQuery('text', 'Order me avocado toast', false);
      break;
  }
}

// Modal helpers
function openModal() {
  document.getElementById('genericModal').classList.add('active');
}
function closeModal() {
  document.getElementById('genericModal').classList.remove('active');
}
