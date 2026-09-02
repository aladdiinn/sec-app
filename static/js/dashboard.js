/**
 * EC2 Security Monitor — Real-Time Dashboard Controller
 * Updates server cards, last_sudo metrics, and stats without full page reload.
 */

async function refreshData() {
    try {
        // Fetch server list and stats in parallel
        const [serversRes, statsRes] = await Promise.all([
            fetch('/api/servers'),
            fetch('/api/servers/stats')
        ]);

        if (serversRes.ok) {
            const servers = await serversRes.json();
            updateServerCards(servers);
        }

        if (statsRes.ok) {
            const stats = await statsRes.json();
            updateStatsCounters(stats);
        }
    } catch (err) {
        console.error("Dashboard refresh error:", err);
    }
}

function updateServerCards(servers) {
    if (!Array.isArray(servers)) return;

    servers.forEach(srv => {
        const card = document.getElementById(`server-card-${srv.id}`);
        if (!card) return;

        // 1. Update Status Badge
        const statusEl = card.querySelector('.server-status-badge');
        if (statusEl) {
            statusEl.textContent = srv.status ? srv.status.toUpperCase() : 'OFFLINE';
            if (srv.status === 'online') {
                statusEl.className = 'server-status-badge px-2.5 py-1 rounded-full text-xs font-mono font-bold bg-green-500/20 text-green-400 border border-green-500/30';
            } else {
                statusEl.className = 'server-status-badge px-2.5 py-1 rounded-full text-xs font-mono font-bold bg-slate-800 text-slate-400 border border-slate-700';
            }
        }

        // 2. Update Severity Badge
        const sevEl = card.querySelector('.server-severity-badge');
        if (sevEl) {
            sevEl.textContent = srv.severity ? srv.severity.toUpperCase() : 'INFO';
            if (srv.severity === 'critical') {
                sevEl.className = 'server-severity-badge px-2.5 py-1 rounded-full text-xs font-mono font-bold bg-red-500/20 text-red-400 border border-red-500/30 glow-red';
            } else if (srv.severity === 'warning') {
                sevEl.className = 'server-severity-badge px-2.5 py-1 rounded-full text-xs font-mono font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30';
            } else {
                sevEl.className = 'server-severity-badge px-2.5 py-1 rounded-full text-xs font-mono font-bold bg-blue-500/20 text-blue-400 border border-blue-500/30';
            }
        }

        // 3. Update Last Sudo Execution and Time Ago
        const lastSudoEl = card.querySelector('.server-last-sudo');
        if (lastSudoEl) {
            lastSudoEl.textContent = srv.last_sudo || 'None';
        }

        const lastSudoAgoEl = card.querySelector('.server-last-sudo-ago');
        if (lastSudoAgoEl) {
            lastSudoAgoEl.textContent = srv.last_sudo_ago || 'never';
        }

        // 4. Update Alert Count Badge
        const alertCountEl = card.querySelector('.server-alert-count');
        if (alertCountEl) {
            alertCountEl.textContent = srv.alert_count || '0';
        }
    });
}

function updateStatsCounters(stats) {
    if (!stats) return;

    const totalEl = document.getElementById('stat-total-servers');
    if (totalEl && stats.total_servers !== undefined) totalEl.textContent = stats.total_servers;

    const onlineEl = document.getElementById('stat-online-servers');
    if (onlineEl && stats.online_servers !== undefined) onlineEl.textContent = stats.online_servers;

    const criticalEl = document.getElementById('stat-critical-alerts');
    if (criticalEl && stats.critical_alerts !== undefined) criticalEl.textContent = stats.critical_alerts;

    const threatsEl = document.getElementById('stat-active-threats');
    if (threatsEl && stats.active_threats !== undefined) threatsEl.textContent = stats.active_threats;
}

// Auto-refresh every 10 seconds
document.addEventListener('DOMContentLoaded', () => {
    refreshData();
    setInterval(refreshData, 10000);
});
