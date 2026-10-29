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

    // 1. MAINT: asset in maintenance window
    if (item._type === 'app') {
        const a = item.raw || item;
        const settings = a.settings || {};
        if (settings.maintenance_mode || a.status === 'MAINT' || a.computed_status === 'MAINT') {
            return 'MAINT';
        }
    } else {
        const s = item.raw || item;
        const st = (s.status || 'online').toLowerCase();
        if (s.is_maintenance || st === 'maintenance' || st === 'isolated') {
            return 'MAINT';
        }
    }

    // 2. DOWN: agent/heartbeat lost or probe failing
    if (item._type === 'app') {
        const a = item.raw || item;
        const totalComp = a.total_components ?? (a.components ? a.components.length : 0);
        const repComp = a.reporting_components ?? 0;
        if (a.status === 'DOWN' || a.computed_status === 'DOWN' || (totalComp > 0 && repComp === 0 && a.last_event_at)) {
            return 'DOWN';
        }
    } else {
        const s = item.raw || item;
        const st = (s.status || 'online').toLowerCase();
        if (st === 'offline' || st === 'down') {
            return 'DOWN';
        }
    }

    // 3. CRITICAL: at least 1 open Critical-severity alert/incident
    if (item._type === 'app') {
        const a = item.raw || item;
        const critInc = Number(a.critical_incidents || 0);
        if (critInc > 0 || (a.computed_status === 'CRITICAL' && Number(a.open_incidents || 0) > 0)) {
            return 'CRITICAL';
        }
    } else {
        const s = item.raw || item;
        const critAlerts = Number(s.critical_alert_count || s.vuln_critical || 0);
        if (critAlerts > 0) {
            return 'CRITICAL';
        }
    }

    // 4. TROUBLE: no Critical, but High/Medium alerts, resource threshold breach (>85%), or stale telemetry
    if (item._type === 'app') {
        const a = item.raw || item;
        const openInc = Number(a.open_incidents || 0);
        const highInc = Number(a.high_incidents || 0);
        const repComp = a.reporting_components ?? 0;
        const totalComp = a.total_components ?? (a.components ? a.components.length : 0);
        
        // Stale telemetry check (> 5 mins since last event)
        let isStale = false;
        if (a.last_event_at) {
            const dt = new Date(a.last_event_at);
            if (!isNaN(dt.getTime())) {
                isStale = (Date.now() - dt.getTime()) > 5 * 60 * 1000;
            }
        }
        
        if (openInc > 0 || highInc > 0 || isStale || (totalComp > 0 && repComp < totalComp) || a.computed_status === 'TROUBLE') {
            return 'TROUBLE';
        }
    } else {
        const s = item.raw || item;
        const cpu = Number(s.cpu_percent || 0);
        const ram = Number(s.memory_percent || 0);
        const disk = Number(s.disk_percent || 0);
        const sev = (s.severity || s.computed_severity || 'info').toLowerCase();
        const troubleAlerts = Number(s.trouble_alert_count || 0);
        const alertCount = Number(s.alert_count || 0);
        
        if (troubleAlerts > 0 || alertCount > 0 || sev === 'warning' || sev === 'high' || cpu > 85 || ram > 85 || disk > 85) {
            return 'TROUBLE';
        }
    }

    // 5. UP: none of the above (healthy!)
    return 'UP';
}

function getAssetBorderColor(status) {
    switch (status) {
        case 'DOWN': return 'var(--red, #ef4444)';
        case 'CRITICAL': return 'var(--red, #ef4444)';
        case 'TROUBLE': return 'var(--amber, #f59e0b)';
        case 'MAINT': return 'var(--cyan, #00d4ff)';
        case 'UP': return ''; // Default card border
        default: return '';
    }
}
