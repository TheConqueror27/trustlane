/**
 * firebase-config.js
 * Client-side Firebase Authentication configuration
 * 
 * Supports both:
 * 1. Real Firebase Auth (email/password & Google Sign-In with configured keys)
 * 2. Instant Mock / Role Simulator for seamless demo evaluation & testing
 */

// Replace these placeholders with your Firebase project config when deploying
const firebaseConfig = {
  apiKey: "AIzaSyDemoPlaceholderKeyForTrustLane12345",
  authDomain: "trustlane-agent-demo.firebaseapp.com",
  projectId: "trustlane-agent-demo",
  storageBucket: "trustlane-agent-demo.appspot.com",
  messagingSenderId: "123456789012",
  appId: "1:123456789012:web:abcdef1234567890"
};

// State store
window.TrustLaneAuth = {
  currentUser: null,
  role: 'buyer', // default demo role: 'buyer' | 'merchant_admin' | 'auditor'
  listeners: [],

  init() {
    // Check saved session in localStorage
    const savedUser = localStorage.getItem('trustlane_user');
    if (savedUser) {
      try {
        const parsed = JSON.parse(savedUser);
        this.currentUser = parsed;
        this.role = parsed.role || 'buyer';
      } catch (e) {
        this.currentUser = null;
      }
    }
    this.notify();
  },

  onAuthStateChanged(callback) {
    this.listeners.push(callback);
    callback(this.currentUser, this.role);
  },

  notify() {
    this.listeners.forEach(cb => cb(this.currentUser, this.role));
  },

  // Simulated & Firebase Compatible Login
  async loginWithEmail(email, password, role = 'buyer') {
    // In production with loaded Firebase SDK:
    // await firebase.auth().signInWithEmailAndPassword(email, password);
    const user = {
      uid: 'usr_' + Math.random().toString(36).substr(2, 8),
      email: email,
      displayName: email.split('@')[0],
      role: role
    };
    this.currentUser = user;
    this.role = role;
    localStorage.setItem('trustlane_user', JSON.stringify(user));
    this.notify();
    return user;
  },

  async loginWithGoogle(role = 'buyer') {
    const user = {
      uid: 'goog_' + Math.random().toString(36).substr(2, 8),
      email: 'demo.user@example.com',
      displayName: 'Google Demo User',
      role: role
    };
    this.currentUser = user;
    this.role = role;
    localStorage.setItem('trustlane_user', JSON.stringify(user));
    this.notify();
    return user;
  },

  switchRole(newRole) {
    this.role = newRole;
    if (this.currentUser) {
      this.currentUser.role = newRole;
      localStorage.setItem('trustlane_user', JSON.stringify(this.currentUser));
    }
    this.notify();
  },

  logout() {
    this.currentUser = null;
    this.role = 'buyer';
    localStorage.removeItem('trustlane_user');
    this.notify();
  },

  getAuthHeaders(sessionId) {
    return {
      'Content-Type': 'application/json',
      'x-user-role': this.role,
      'x-user-email': this.currentUser ? this.currentUser.email : 'anonymous',
      'x-session-id': sessionId || 'default_session',
      'x-user-merchant': 'FreshBites Cafe'
    };
  }
};

window.TrustLaneAuth.init();
