/**
 * auth.js — SecurePulse
 * Central auth helpers: apiFetch, logout, user info population.
 * Loaded on every page (via base.html).
 */

(function () {
  'use strict';

  /* ── Token helpers ─────────────────────────────────────── */
  function getToken() {
    return localStorage.getItem('sp_token');
  }

  function getUser() {
    try {
      return JSON.parse(localStorage.getItem('sp_user')) || {};
    } catch {
      return {};
    }
  }

  function clearAuth() {
    localStorage.removeItem('sp_token');
    localStorage.removeItem('sp_user');
  }

  /* ── Server handles routing redirects ────────────────────── */
  // Removed guardPage() to prevent infinite loops. The backend's @login_required decorator
  // properly handles redirecting unauthenticated users to /login.

  /* ── Populate sidebar user info ────────────────────────── */
  document.addEventListener('DOMContentLoaded', function () {
    const user = getUser();
    if (!user.email) return;

    const nameEl   = document.getElementById('user-name');
    const emailEl  = document.getElementById('user-email');
    const avatarEl = document.getElementById('user-avatar');

    if (nameEl)   nameEl.textContent  = user.full_name || 'Admin';
    if (emailEl)  emailEl.textContent = user.email;
    if (avatarEl) avatarEl.textContent = (user.full_name || user.email || 'A')[0].toUpperCase();
  });

  /* ── Central API fetch ──────────────────────────────────── */
  /**
   * apiFetch(path, options)
   * - Automatically attaches Bearer token
   * - Returns parsed JSON
   * - Redirects to /login on 401
   * - Throws on non-OK
   */
  window.apiFetch = async function (path, options = {}) {
    const token = getToken();
    const headers = {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    };
    if (token) headers['Authorization'] = 'Bearer ' + token;

    const res = await fetch(path, { ...options, headers });

    if (res.status === 401) {
      clearAuth();
      window.location.href = '/login';
      throw new Error('Session expired');
    }

    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      throw new Error(data.error || data.message || `HTTP ${res.status}`);
    }

    return data;
  };

  /* ── Logout ─────────────────────────────────────────────── */
  window.logout = function () {
    clearAuth();
    window.location.href = '/login';
  };

  /* ── Toast notifications ────────────────────────────────── */
  window.showToast = function (message, type = 'info') {
    let container = document.getElementById('toast-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'toast-container';
      document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `toast toast--${type}`;
    toast.textContent = message;
    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transition = 'opacity .3s';
      setTimeout(() => toast.remove(), 300);
    }, 3500);
  };

})();
