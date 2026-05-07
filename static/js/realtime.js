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

  /* ── Critical Alert Notifications ──────────────────────── */
  var originalTitle = document.title;
  var flashInterval = null;

  socket.on('new_event', function (ev) {
    if (typeof showToast === 'function') {
      showToast(`${ev.severity.toUpperCase()}: ${ev.description}`, ev.severity);
    }
    if (ev.severity === 'critical') {
      playAlertSound();
      startTitleFlash();
    }
  });

  socket.on('new_alert', function (alert) {
    if (typeof showToast === 'function') {
      showToast(`NEW ALERT: ${alert.title}`, 'error');
    }
    playAlertSound();
  });

  function playAlertSound() {
    // Basic browser beep using AudioContext
    try {
      var ctx = new (window.AudioContext || window.webkitAudioContext)();
      var osc = ctx.createOscillator();
      var gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.type = 'sine';
      osc.frequency.value = 523.25; // C5
      gain.gain.setValueAtTime(0.1, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.5);
      osc.start();
      osc.stop(ctx.currentTime + 0.5);
    } catch (e) { console.warn('Audio alert failed:', e); }
  }

  function startTitleFlash() {
    if (flashInterval) return;
    var isFlash = false;
    flashInterval = setInterval(function () {
      document.title = isFlash ? originalTitle : '🔴 CRITICAL ALERT';
      isFlash = !isFlash;
    }, 1000);

    // Stop flashing when user clicks anywhere or refocuses
    var stopFlash = function () {
      clearInterval(flashInterval);
      flashInterval = null;
      document.title = originalTitle;
      window.removeEventListener('click', stopFlash);
      window.removeEventListener('focus', stopFlash);
    };
    window.addEventListener('click', stopFlash);
    window.addEventListener('focus', stopFlash);
  }

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
