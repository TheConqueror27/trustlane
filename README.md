# 🛡️ TrustLane — Bounded, Auditable Trust Layer for AI-Agent Payments

<div align="center">

![Node.js](https://img.shields.io/badge/Node.js-20-339933?style=for-the-badge&logo=node.js&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![TimescaleDB](https://img.shields.io/badge/TimescaleDB-PostgreSQL-FDB515?style=for-the-badge&logo=postgresql&logoColor=white)
![Razorpay](https://img.shields.io/badge/Razorpay-Payment%20Gateway-02042B?style=for-the-badge&logo=razorpay&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**Razorpay AI Buildathon Submission | Track: AI Growth & Agentic Commerce**

*A production-grade, cryptographically secure trust & audit layer that ensures autonomous AI shopping agents can never spend money without explicit, verifiable human consent.*

</div>

---

## 📖 What is TrustLane?

TrustLane is a **zero-trust payment middleware** that sits between an AI shopping agent and the payment gateway. It solves the critical problem of **AI agent financial autonomy** by enforcing:

1. **Explicit, Cryptographically Signed Consent Mandates** — Dual-key HMAC-SHA256 signed mandates with spend caps, merchant binding, ephemeral nonces, and 1-hour TTL.
2. **Real-Time Deterministic Gate & 3-Sigma Anomaly Engine** — Kaggle UPI/PaySim data-driven Gaussian anomaly detection with an interactive bell curve visualizer.
3. **NPCI-Grade Zero-Trust Payment Security Layer** — One-time cryptographic gate tickets, Ed25519 digital signatures, anti-replay defense, velocity limiting, JWT-based Role Authentication (RBAC), and strict CORS/Rate-Limiting.
4. **TimescaleDB Append-Only Persistent Audit Ledger** — Immutable, SHA-256 sequential hash-chained time-series hypertables. Records can never be deleted or tampered with.
5. **Real-Time Dynamic Simulated Menu Engine** — Live Server-Sent Events (SSE) stream with kitchen rush surges, flash discounts, and stock countdowns.
6. **Automatic Dispute & Remediation** — Triggered instantly upon merchant fulfillment failure post-capture.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        TrustLane System                             │
│                                                                     │
│  ┌──────────────┐    ┌───────────────────┐    ┌─────────────────┐  │
│  │  Landing Page │    │  AI Agent Engine  │    │   Razorpay API  │  │
│  │  (index.html) │    │  (server.js)      │    │   (Payment GW)  │  │
│  └──────┬────────┘    └────────┬──────────┘    └────────┬────────┘  │
│         │                     │                         │           │
│  ┌──────▼─────────────────────▼─────────────────────────▼────────┐  │
│  │                    TrustLane Gate Checkpoint                   │  │
│  │  ┌─────────────┐  ┌──────────────┐  ┌──────────────────────┐  │  │
│  │  │ Consent     │  │ 3-Sigma      │  │ NPCI Security Layer  │  │  │
│  │  │ Mandate     │  │ Anomaly      │  │ (Ed25519, JWT RBAC,  │  │  │
│  │  │ (HMAC-SHA256│  │ Engine       │  │  Gate Tickets,       │  │  │
│  │  │  + nonce)   │  │ (Kaggle data)│  │  Velocity Limiter)   │  │  │
│  │  └─────────────┘  └──────────────┘  └──────────────────────┘  │  │
│  └────────────────────────────┬──────────────────────────────────┘  │
│                               │                                     │
│  ┌────────────────────────────▼──────────────────────────────────┐  │
│  │             TimescaleDB (PostgreSQL Hypertables)               │  │
│  │      Append-Only Audit Ledger + SHA-256 Sequential Hash Chain  │  │
│  └────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

### Project Structure

```
trustlane/
├── server.js              # Main Express server — API routes, gate logic, dispute engine
├── security.js            # NPCI-Grade security: Ed25519, gate tickets, velocity limiter
├── db.js                  # TimescaleDB + hybrid in-memory store, audit ledger
├── menu-simulator.js      # Real-time SSE menu engine with kitchen surges
├── risk-profile.json      # Kaggle-derived μ/σ baselines per food category
├── preprocess.py          # Kaggle dataset preprocessing script
├── test-runner.js         # Automated end-to-end test scenarios
├── Dockerfile             # Multi-stage Docker build (node:20-alpine)
├── docker-compose.yml     # Full stack: TimescaleDB + TrustLane app
├── package.json
└── public/
    ├── index.html             # Landing page with 3D animations
    ├── app.html               # Main authenticated app UI
    ├── app.css                # Application styles
    ├── app.js                 # Frontend agent simulation logic
    ├── anomaly-visualizer.js  # Gaussian bell curve canvas renderer
    ├── landing-3d.js          # Three.js-powered 3D landing effects
    ├── landing.css            # Landing page styles
    └── firebase-config.js     # Firebase integration (optional)
```

---

## 🚀 Quick Start

### Prerequisites

| Tool | Version | Required |
|------|---------|----------|
| [Node.js](https://nodejs.org/) | ≥ 18.x | For local run |
| [Docker Desktop](https://www.docker.com/products/docker-desktop/) | Latest | For Docker run |
| [Git](https://git-scm.com/) | Latest | Always |
| [VS Code](https://code.visualstudio.com/) | Latest | Recommended IDE |

---

### ✅ Option A — Docker Compose (Recommended)

> Easiest setup. Includes TimescaleDB automatically. No extra installs needed.

**Step 1:** Clone the repository
```bash
git clone https://github.com/TheConqueror27/trustlane.git
cd trustlane
```

**Step 2:** Start the full stack
```bash
docker compose up --build
```

> ⏳ First run takes ~2-3 minutes to pull the TimescaleDB image. Subsequent runs are instant.

**Step 3:** Open your browser
```
http://localhost:3000
```

**To stop:**
```bash
docker compose down
```

**To stop and remove all data (clean slate):**
```bash
docker compose down -v
```

---

### ✅ Option B — Run Locally with Node.js (VS Code)

> Best for development and debugging. Uses resilient in-memory fallback if no PostgreSQL is available.

#### Step-by-Step for VS Code

**Step 1:** Clone and open in VS Code
```bash
git clone https://github.com/TheConqueror27/trustlane.git
cd trustlane
code .
```

**Step 2:** Open the integrated terminal in VS Code
> Press `` Ctrl + ` `` or go to **Terminal → New Terminal**

**Step 3:** Install dependencies
```bash
npm install
```

**Step 4:** (Optional) Configure environment variables

Create a `.env` file in the project root:
```env
PORT=3000

# PostgreSQL / TimescaleDB (leave blank to use in-memory fallback)
DATABASE_URL=postgres://postgres:postgres@localhost:5432/trustlane
PGHOST=localhost
PGPORT=5432
PGUSER=postgres
PGPASSWORD=postgres
PGDATABASE=trustlane

# TrustLane Security Secrets (defaults are provided for demo)
TRUSTLANE_SECRET=trustlane_sec_npci_grade_2026_x99
GATE_TICKET_SECRET=gate_sig_secret_key_8832_trustlane

# Razorpay API Keys
RAZORPAY_KEY_ID=rzp_test_your_key_here
RAZORPAY_KEY_SECRET=your_secret_here

# Google Gemini API
GEMINI_API_KEY=your_gemini_api_key

# JWT Auth Secret
JWT_SECRET=your_jwt_secret

# Allowed CORS Origins
TRUSTED_ORIGINS=http://localhost:3000
```

> 💡 **Note:** If no database is configured, TrustLane automatically falls back to a resilient in-memory + JSON file store. All features work without a database.

**Step 5:** Start the server
```bash
npm start
```

**Step 6:** Open in browser
```
Landing Page:  http://localhost:3000/
App Dashboard: http://localhost:3000/app
Health Check:  http://localhost:3000/health
```

---

### ✅ Option C — VS Code + Docker TimescaleDB Only

> Full database support while editing source code directly in VS Code.

**Step 1:** Start only the database via Docker
```bash
docker compose up timescaledb -d
```

**Step 2:** Install dependencies and run the Node server locally
```bash
npm install
npm start
```

**Step 3:** Access the app at `http://localhost:3000`

---

## 🔒 Security Layer

### NPCI-Grade Zero-Trust Architecture (`security.js`)

| Feature | Implementation |
|---|---|
| **Digital Signatures** | Ed25519 Asymmetric Key Cryptography (PKCS8/SPKI PEM) |
| **Consent Mandates** | Dual-key HMAC-SHA256, session-bound, merchant-locked. Verified at Gate. |
| **Gate Tickets** | One-time use, 5-min TTL, cryptographically signed |
| **Anti-Replay** | Persistent nonce cache — used nonces permanently invalidated |
| **Velocity Limiting** | Max **6 txns/min**, ₹**2,000** volume cap per session |
| **Audit Ledger** | SHA-256 sequential hash chaining: `hash = SHA256(prev_hash + ts + payload + secret)` (Globally unique `crypto.randomUUID()` IDs) |
| **Access Control** | Strict JWT-based RBAC (`buyer`, `merchant_admin`, `auditor`). No hardcoded fallback secrets. |
| **Payment Integrity** | Real Razorpay SDK integration. No test-mode backdoors. Cryptographic HMAC-SHA256 verification via `crypto.timingSafeEqual()`. |

### Payment Flow

```
User Sets Consent Mandate (spend cap + merchant + TTL)
          │
          ▼
AI Agent Proposes Purchase
          │
          ▼
TrustLane Gate Checkpoint ──────────► BLOCK (cap exceeded / anomaly / expired)
   │  ✅ All checks pass
   ▼
Gate Ticket Issued (one-time, signed, 5-min TTL)
          │
          ▼
Razorpay Order Created (ticket consumed — replay impossible)
          │
          ▼
Payment Captured → Audit Logged to TimescaleDB
          │
          ▼
Fulfillment Check → Auto-Dispute if failed
```

---

## 📊 Kaggle 3-Sigma Anomaly Engine

### Data Source
- [Kaggle UPI Fraud Detection Dataset](https://www.kaggle.com/datasets/omsshete/upi-fraud-detection-dataset)
- PaySim Online Payments Dataset

### Mathematical Model

```
Z = (x - μ) / σ
```

Where:
- `x` = transaction amount
- `μ` = Kaggle-derived category mean
- `σ` = Kaggle-derived category standard deviation

### Gaussian Empirical Rule

| Zone | Z-Score | Probability | Action |
|------|---------|-------------|--------|
| 🟢 Normal | Z ≤ 1σ | 68.27% | Approve |
| 🟡 Elevated | 1σ < Z ≤ 2σ | 27.18% | Approve with warning |
| 🟠 High Alert | 2σ < Z ≤ 3σ | 4.28% | Extra confirmation |
| 🔴 Extreme Anomaly | Z > 3σ | < 0.13% | **Block — rogue agent / price gouging** |

---

## ⚡ Real-Time Dynamic Menu Engine

The menu engine (`menu-simulator.js`) streams live price and inventory updates via **Server-Sent Events (SSE)**:

- **Endpoint:** `GET /api/menu/stream`
- **Kitchen Rush Surge:** `+20%` price spike across all items
- **Flash Sale:** `-25%` discount on beverages
- **Stock Drop:** Simulates item going out of stock
- **Reset:** Restores baseline catalog

---

## 🤖 Agentic Features

- **Multi-Item Combos & Negotiation:** Gemini 2.5 Flash agent plans purchases based on natural language queries, respecting live catalog data and constraints.
- **Conversation Memory:** LRU-bounded session history (up to 10 turns per session, 1-hour TTL) allows the agent to understand context and follow-up requests (e.g., "make it cheaper", "add a drink to that").
- **Multimodal Order Input:** Users can upload images of items to initiate an order. Gemini Vision analyzes the image and extracts the intended food item.
- **Resilience:** Automatic retry with exponential backoff and model cascading (`gemini-2.5-flash` → `gemini-1.5-flash` → `gemini-1.5-flash-8b`) ensures high availability even during API overload.

---

## 📡 API Reference

### Health
```http
GET /health
```

### Auth
```http
POST /api/auth/token
Body: { sessionId, role, merchant, adminSecret }
```
```http
POST /api/intent
Body: { sessionId, spendCap, merchant, currency }

GET /api/intent/:sessionId
```

### Gate Checkpoint
```http
POST /api/gate/check
Body: { sessionId, amount, category, merchant }
```

### Agent
```http
POST /api/agent/query
Body: { sessionId, message }

POST /api/agent/query-multimodal
Body: { sessionId, imageBase64, mimeType }
```

### Payments
```http
POST /api/payment/create-order
Body: { sessionId, amount, currency, gateTicket, itemName }

POST /api/payment/capture
Body: { sessionId, orderId, razorpayOrderId, amount }
```

### Menu
```http
GET  /api/menu/items
GET  /api/menu/stream
POST /api/menu/trigger/:event
```

### Audit Ledger
```http
GET  /api/audit/:sessionId
GET  /api/audit-all
POST /api/audit/verify
```

### Security
```http
GET  /api/security/public-key
POST /api/security/simulate-attack
GET  /api/security/velocity-status/:sessionId
```

### Disputes & Receipts
```http
POST /api/dispute/create
GET  /api/receipt/:orderId
```

---

## 🎬 Demo Scenarios

Access the **Fast Demo Presets** panel on the `/app` dashboard:

| # | Scenario | What Happens |
|---|----------|-------------|
| 1 | **Happy Path (₹300 Cap)** | Consent → Veg Burger (₹180) → Gate approved → Razorpay captured → Logged to TimescaleDB |
| 2 | **Gate Blocked (₹50 Cap)** | Consent → Veg Burger (₹180 > ₹50) → **Blocked before payment** |
| 3 | **Auto-Triggered Dispute** | Chef Surprise Box → Fulfillment fails → **Auto-dispute + refund** |
| 4 | **Kaggle 3-Sigma Anomaly** | Gourmet Truffle Burger (₹490, 4.9σ) → **Anomaly flagged** |
| 5 | **Stock Refusal** | Avocado Toast (Stock: 0) → **Agent refuses** |
| 6 | **Ledger Integrity** | Click *"Verify Entire Hash Chain Now"* → **100% SHA-256 verification** |
| 7 | **Replay Attack** | Re-submit consumed gate ticket → **Instantly rejected** |
| 8 | **Velocity DDoS** | >6 txns/min burst → **Rate limiter triggers** |

---

## 🛠️ VS Code Setup Tips

### Recommended Extensions
- **ESLint** (`dbaeumer.vscode-eslint`) — JavaScript linting
- **Prettier** (`esbenp.prettier-vscode`) — Code formatting
- **Docker** (`ms-azuretools.vscode-docker`) — Docker Compose management
- **REST Client** (`humao.rest-client`) — Test API endpoints directly in VS Code
- **Path Intellisense** (`christian-kohler.path-intellisense`) — Autocomplete file paths

### VS Code Debug Configuration

Create `.vscode/launch.json`:
```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "type": "node",
      "request": "launch",
      "name": "Launch TrustLane Server",
      "skipFiles": ["<node_internals>/**"],
      "program": "${workspaceFolder}/server.js",
      "envFile": "${workspaceFolder}/.env"
    }
  ]
}
```

---

## 🧪 Running Tests

```bash
node test-runner.js
```

Covers: consent mandate creation, gate enforcement, anomaly detection, velocity limits, and hash chain integrity.

---

## 🐳 Docker Reference

| Command | Description |
|---------|-------------|
| `docker compose up --build` | Build and start full stack |
| `docker compose up --build -d` | Start in background |
| `docker compose logs -f trustlane-app` | Stream app logs |
| `docker compose logs -f timescaledb` | Stream DB logs |
| `docker compose down` | Stop all containers |
| `docker compose down -v` | Stop + remove all volumes |
| `docker compose restart trustlane-app` | Restart only the app |
| `docker ps` | Check container health |

---

## 📦 Tech Stack

| Layer | Technology |
|-------|-----------|
| **Runtime** | Node.js 20 (Alpine Docker) |
| **Web Framework** | Express.js 4 |
| **Database** | TimescaleDB (PostgreSQL 16) via `pg` driver |
| **Cryptography** | Node.js `crypto` — Ed25519, HMAC-SHA256, SHA-256 |
| **Payment Gateway** | Razorpay SDK v2 |
| **Real-Time** | Server-Sent Events (SSE) |
| **Containerization** | Docker + Docker Compose v3.8 |
| **Frontend** | Vanilla HTML/CSS/JS + Canvas API |
| **3D Landing** | Three.js |
| **AI Integration** | Google Gemini API (2.5 Flash, 1.5 Flash, Vision) |
| **Dataset** | Kaggle UPI Fraud + PaySim |

---

## 📄 License

MIT License

---

<div align="center">

Built with ❤️ for the **Razorpay AI Buildathon**

*TrustLane — Because AI agents should spend smart, not reckless.*

</div>
