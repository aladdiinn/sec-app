/**
 * BSmart SOC — Unified Asset & App Node Status Rule
 * Single Source of Truth for:
 * 1. Card badge
 * 2. Card border colour
 * 3. Status strip counts (DOWN, CRITICAL, TROUBLE, MAINT, UP)
 * 4. Grid filtering
 */

function getUnifiedAssetStatus(item) {
    if (!item) return 'UP';

    // =========================================================
    // 1. APPLICATION NODES (_type === 'app')
    // =========================================================
    if (item._type === 'app') {
        const a = item.raw || item;
        const totalComp = a.total_components ?? (a.components ? a.components.length : 0);
        const repComp = a.reporting_components ?? 0;
        const critInc = Number(a.critical_incidents || 0);
        const critEv = Number(a.critical_events || 0);
        const openInc = Number(a.open_incidents || 0);
        const highInc = Number(a.high_incidents || 0);
        const openSecEv = Number(a.open_security_events || 0);
        const settings = a.settings || {};
        const isMaint = settings.maintenance_mode || a.status === 'MAINT' || a.computed_status === 'MAINT';

        // 1a. DOWN: all reporting components dead or explicit DOWN status
        if (a.status === 'DOWN' || a.computed_status === 'DOWN' || (totalComp > 0 && repComp === 0 && a.last_event_at)) {
            return 'DOWN';
        }

        // 1b. CRITICAL: open critical incident or critical exploit event
        if (critInc > 0 || critEv > 0 || (a.status === 'CRITICAL' && (critInc > 0 || openInc > 0))) {
            return 'CRITICAL';
        }

        // 1c. TROUBLE: open incidents, high/medium attacks, open security events
        if (openInc > 0 || highInc > 0 || openSecEv > 0 || (a.status === 'TROUBLE' && openInc > 0)) {
            return 'TROUBLE';
        }

        // 1d. Stale telemetry check (> 5 mins since last event)
        if (a.last_event_at) {
            const dt = new Date(a.last_event_at);
            if (!isNaN(dt.getTime()) && (Date.now() - dt.getTime()) > 5 * 60 * 1000) {
                return 'TROUBLE';
            }
        }

        // 1e. Component ratio trouble (some components down)
        if (totalComp > 0 && repComp < totalComp) {
            return 'TROUBLE';
        }

        // 1f. MAINT: scheduled maintenance window (only if no threats)
        if (isMaint) {
            return 'MAINT';
        }

        // 1g. Healthy UP
        return 'UP';
    }

    // =========================================================
    // 2. INFRASTRUCTURE SERVERS (_type === 'server')
    // =========================================================
    const s = item.raw || item;
    const st = (s.status || 'online').toLowerCase();
    const isMaint = s.is_maintenance || st === 'maintenance' || st === 'isolated';

    // 2a. DOWN: offline/down
    if (st === 'offline' || st === 'down') {
        return 'DOWN';
    }

    // 2b. CRITICAL: open critical alerts/incidents
    const critAlerts = Number(s.critical_alert_count || 0);
    if (critAlerts > 0) {
        return 'CRITICAL';
    }

    // 2c. TROUBLE: warnings, high resources, open trouble alerts
    const cpu = Number(s.cpu_percent || 0);
    const ram = Number(s.memory_percent || 0);
    const disk = Number(s.disk_percent || 0);
    const sev = (s.severity || s.computed_severity || 'info').toLowerCase();
    const troubleAlerts = Number(s.trouble_alert_count || 0);
    const alertCount = Number(s.alert_count || 0);

    const degCount = (s.degraded_collectors && typeof s.degraded_collectors === 'object')
        ? Object.entries(s.degraded_collectors).filter(([k, v]) => {
            const kl = k.toLowerCase();
            if (kl.includes('heartbeat') || kl.includes('telemetry_loop') || kl.includes('network') || kl.includes('socket')) return false;
            const msg = String((v && v.message) || v || '').toLowerCase();
            if (msg.includes('connection refused') || msg.includes('errno 111') || msg.includes('timed out') || msg.includes('unreachable')) return false;
            return true;
        }).length
        : 0;
    if (troubleAlerts > 0 || alertCount > 0 || (sev !== 'info' && sev !== 'normal') || cpu > 85 || ram > 85 || disk > 85 || degCount > 0) {
        return 'TROUBLE';
    }

    // 2d. MAINT: maintenance mode
    if (isMaint) {
        return 'MAINT';
    }

    // 2e. Healthy UP
    return 'UP';
}

function getAssetBorderColor(status) {
    switch (status) {
        case 'DOWN': return 'var(--red, #ef4444)';
        case 'CRITICAL': return 'var(--red, #ef4444)';
        case 'TROUBLE': return 'var(--amber, #f59e0b)';
        case 'MAINT': return 'var(--cyan, #00d4ff)';
        case 'UP': return '';
        default: return '';
    }
}
