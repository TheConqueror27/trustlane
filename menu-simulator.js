/**
 * menu-simulator.js
 * Real-Time Dynamic Simulated Menu Engine for TrustLane
 * 
 * Features:
 * - Live Server-Sent Events (SSE) broadcast for instant real-time client UI sync
 * - Dynamic price fluctuation & surge simulator (e.g. rush hour, supply/demand)
 * - Dynamic kitchen stock countdown & out-of-stock triggers
 * - Interactive simulation controls for live buildathon judging demonstrations
 */

const EventEmitter = require('events');

class MenuSimulator extends EventEmitter {
  constructor() {
    super();

    this.defaultCatalog = [
      {
        id: 'prod_1',
        name: 'Classic Veg Burger',
        price: 180,
        basePrice: 180,
        stock: 15,
        category: 'food',
        merchant: 'FreshBites Cafe',
        description: 'Crispy vegetable patty with fresh lettuce, mayo & tomatoes',
        image: '🍔',
        surgeMultiplier: 1.0
      },
      {
        id: 'prod_2',
        name: 'Gourmet Truffle Burger',
        price: 490,
        basePrice: 490,
        stock: 8,
        category: 'food',
        merchant: 'FreshBites Cafe',
        description: 'Black truffle glazed patty with aged cheddar and brioche bun (Kaggle 3-Sigma Anomaly)',
        image: '👑',
        surgeMultiplier: 1.0
      },
      {
        id: 'prod_3',
        name: 'Artisan Cold Brew Coffee',
        price: 140,
        basePrice: 140,
        stock: 20,
        category: 'beverage',
        merchant: 'FreshBites Cafe',
        description: 'Single-origin Ethiopian slow steep cold brew 300ml',
        image: '☕',
        surgeMultiplier: 1.0
      },
      {
        id: 'prod_4',
        name: 'Avocado Toast Deluxe',
        price: 240,
        basePrice: 240,
        stock: 0,
        category: 'food',
        merchant: 'FreshBites Cafe',
        description: 'Sourdough bread, smashed Hass avocado, feta & seeds (OUT OF STOCK refusal test)',
        image: '🥑',
        surgeMultiplier: 1.0
      },
      {
        id: 'prod_5',
        name: 'Mystery Chef Surprise Box',
        price: 280,
        basePrice: 280,
        stock: 5,
        category: 'food',
        merchant: 'FreshBites Cafe',
        description: 'Curated daily chef special (Auto-dispute & instant refund demo upon capture)',
        image: '🎁',
        surgeMultiplier: 1.0
      },
      {
        id: 'prod_6',
        name: 'Organic Sparkling Matcha',
        price: 210,
        basePrice: 210,
        stock: 12,
        category: 'beverage',
        merchant: 'FreshBites Cafe',
        description: 'Japanese ceremonial grade matcha lightly carbonated',
        image: '🍵',
        surgeMultiplier: 1.0
      },
      {
        id: 'prod_7',
        name: 'Signature Chocolate Lava Cake',
        price: 190,
        basePrice: 190,
        stock: 10,
        category: 'food',
        merchant: 'FreshBites Cafe',
        description: 'Warm molten Belgian chocolate cake with vanilla cream',
        image: '🍰',
        surgeMultiplier: 1.0
      }
    ];

    this.catalog = JSON.parse(JSON.stringify(this.defaultCatalog));
    this.sseClients = new Set();
    this.simulationMode = 'active'; // 'active' | 'paused'
    this.lastSimulationEvent = { type: 'system_boot', message: 'Real-time menu simulator initialized.', timestamp: new Date().toISOString() };

    // Start background gentle simulation timer (every 12 seconds gentle fluctuation)
    this.startAutoSimulation();
  }

  getCatalog() {
    return this.catalog;
  }

  getItem(id) {
    return this.catalog.find(item => item.id === id);
  }

  updateItem(id, updates) {
    const item = this.getItem(id);
    if (!item) return null;

    if (updates.price !== undefined) item.price = Number(updates.price);
    if (updates.stock !== undefined) item.stock = Math.max(0, Number(updates.stock));
    if (updates.name !== undefined) item.name = updates.name;
    if (updates.description !== undefined) item.description = updates.description;

    this.broadcastUpdate({
      type: 'item_updated',
      itemId: id,
      item,
      message: `Menu item "${item.name}" updated (Price: ₹${item.price}, Stock: ${item.stock})`
    });

    return item;
  }

  decrementStock(id, qty = 1) {
    const item = this.getItem(id);
    if (item && item.stock > 0) {
      item.stock = Math.max(0, item.stock - qty);
      this.broadcastUpdate({
        type: 'stock_depleted',
        itemId: id,
        newStock: item.stock,
        message: `Stock updated for "${item.name}": ${item.stock} left in kitchen.`
      });
    }
  }

  /**
   * Handle Server-Sent Events (SSE) Client registration
   */
  registerSSEClient(req, res) {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders?.();

    const client = { id: Date.now() + Math.random(), res };
    this.sseClients.add(client);

    // Send initial snapshot
    const initialPayload = JSON.stringify({
      type: 'initial_catalog',
      catalog: this.catalog,
      lastEvent: this.lastSimulationEvent,
      timestamp: new Date().toISOString()
    });
    res.write(`data: ${initialPayload}\n\n`);

    req.on('close', () => {
      this.sseClients.delete(client);
    });
  }

  /**
   * Broadcast message to all connected SSE clients
   */
  broadcastUpdate(eventData) {
    this.lastSimulationEvent = {
      ...eventData,
      timestamp: new Date().toISOString()
    };

    const payload = JSON.stringify({
      ...eventData,
      catalog: this.catalog,
      timestamp: new Date().toISOString()
    });

    for (const client of this.sseClients) {
      try {
        client.res.write(`data: ${payload}\n\n`);
      } catch (e) {
        this.sseClients.delete(client);
      }
    }

    this.emit('menu_changed', eventData);
  }

  /**
   * Simulation Scenarios
   */
  triggerSimulationEvent(eventName, params = {}) {
    switch (eventName) {
      case 'rush_hour_surge': {
        // Surge food prices by 15-20% and cold brew by 10%
        this.catalog.forEach(item => {
          if (item.category === 'food' && item.stock > 0) {
            const surge = Math.round(item.basePrice * 1.2);
            item.price = surge;
            item.surgeMultiplier = 1.2;
          }
        });
        this.broadcastUpdate({
          type: 'simulation_rush_hour',
          message: '🔥 Rush Hour Surge Activated: Kitchen high-demand surge pricing (+20%) applied.',
          scenario: 'rush_hour'
        });
        break;
      }

      case 'flash_sale': {
        // Flash sale on Cold brew and Matcha
        this.catalog.forEach(item => {
          if (item.category === 'beverage') {
            item.price = Math.round(item.basePrice * 0.75);
            item.surgeMultiplier = 0.75;
          }
        });
        this.broadcastUpdate({
          type: 'simulation_flash_sale',
          message: '⚡ Flash Sale Event: 25% discount on all Artisan Beverages for the next 15 minutes!',
          scenario: 'flash_sale'
        });
        break;
      }

      case 'kitchen_stock_drop': {
        // Drop stock of 2 items
        const item1 = this.catalog.find(i => i.id === 'prod_1');
        const item2 = this.catalog.find(i => i.id === 'prod_3');
        if (item1) item1.stock = Math.max(1, item1.stock - 3);
        if (item2) item2.stock = Math.max(1, item2.stock - 4);

        this.broadcastUpdate({
          type: 'simulation_stock_drop',
          message: '📉 Live Kitchen Inventory Update: Heavy order rush reduced Veg Burger and Cold Brew stock.',
          scenario: 'stock_drop'
        });
        break;
      }

      case 'reset_defaults': {
        this.catalog = JSON.parse(JSON.stringify(this.defaultCatalog));
        this.broadcastUpdate({
          type: 'simulation_reset',
          message: '🔄 Menu reset to standard baseline catalog prices and initial kitchen stock.',
          scenario: 'reset'
        });
        break;
      }

      default:
        break;
    }

    return {
      success: true,
      scenario: eventName,
      catalog: this.catalog
    };
  }

  /**
   * Background gentle live tick (Simulates realistic live restaurant changes)
   */
  startAutoSimulation() {
    setInterval(() => {
      if (this.sseClients.size > 0 && this.simulationMode === 'active') {
        // Random subtle fluctuation on 1 item
        const randIndex = Math.floor(Math.random() * this.catalog.length);
        const item = this.catalog[randIndex];
        if (item && item.id !== 'prod_2' && item.id !== 'prod_4' && item.id !== 'prod_5') {
          // Subtle price delta ± ₹5
          const delta = (Math.random() > 0.5 ? 5 : -5);
          const newPrice = Math.max(item.basePrice - 15, Math.min(item.basePrice + 25, item.price + delta));
          if (newPrice !== item.price) {
            item.price = newPrice;
            item.surgeMultiplier = parseFloat((item.price / item.basePrice).toFixed(2));
            this.broadcastUpdate({
              type: 'live_price_tick',
              itemId: item.id,
              newPrice: item.price,
              message: `Dynamic Ticker: ${item.name} price adjusted to ₹${item.price} based on real-time kitchen demand.`
            });
          }
        }
      }
    }, 15000);
  }
}

const menuSimulator = new MenuSimulator();
module.exports = menuSimulator;
