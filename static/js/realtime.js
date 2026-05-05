/**
 * realtime.js — SecurePulse
 * SocketIO connection setup. Exposes window._socket.
 * Loaded on all authenticated pages (via base.html).
 */

(function () {
  'use strict';

  var token = localStorage.getItem('sp_token');
  if (!token) return;  // Not authenticated — skip

  // Connect with token as query param (SocketIO doesn't support custom headers)
  var socket = io({
    transports: ['websocket', 'polling'],
    query: { token: token },
    reconnection: true,
    reconnectionAttempts: 10,
    reconnectionDelay: 2000,
  });

  socket.on('connect', function () {
    // Join the dashboard broadcast room
    socket.emit('join_dashboard');
    updateConnectionBadge(true);
  });

  socket.on('joined', function (data) {
    console.log('[SecurePulse WS] Joined room:', data.room);
  });

  socket.on('disconnect', function () {
    updateConnectionBadge(false);
  });

  socket.on('connect_error', function (err) {
    console.warn('[SecurePulse WS] Connection error:', err.message);
    updateConnectionBadge(false);
  });

  /* ── Expose globally so page scripts can listen ────────── */
  window._socket = socket;

  /* ── Optional visual indicator ──────────────────────────── */
  function updateConnectionBadge(connected) {
    var badge = document.getElementById('live-badge');
    if (!badge) return;
    if (connected) {
      badge.textContent = 'LIVE';
      badge.className = 'badge badge-blue';
    } else {
      badge.textContent = 'OFFLINE';
      badge.className = 'badge badge-gray';
    }
  }

})();
