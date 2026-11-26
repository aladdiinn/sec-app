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

/* ============================================================================
 * Shared Compact Website & Asset Card Renderers (apps.html, servers.html, dashboard.html)
 * ============================================================================ */

function _spEsc(val) {
    if (typeof escapeHtml === 'function') return escapeHtml(val);
    return String(val ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function _spParseVerArr(v) {
    const m = String(v || '').match(/\d+/g);
    return m ? m.map(Number) : [0];
}

function _spIsVerAtLeast(curr, target) {
    const c = _spParseVerArr(curr), t = _spParseVerArr(target);
    for (let i = 0; i < Math.max(c.length, t.length); i++) {
        const cv = c[i] || 0, tv = t[i] || 0;
        if (cv > tv) return true;
        if (cv < tv) return false;
    }
    return true;
}

function renderSpWebsiteIcon(color) {
    const c = color || '#d97706';
    return `<svg viewBox="0 0 24 24" width="15" height="15" fill="none" xmlns="http://www.w3.org/2000/svg" style="vertical-align:middle; flex-shrink:0;">
        <path d="M12 2L2 7L12 12L22 7L12 2Z" fill="${c}" fill-opacity="0.85" stroke="${c}" stroke-width="1.2" stroke-linejoin="round"/>
        <path d="M2 12L12 17L22 12" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
        <path d="M2 17L12 22L22 17" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>`;
}

function renderSpAssetChassisIcon(color) {
    const c = color || '#60a5fa';
    return `<svg viewBox="0 0 24 24" width="15" height="15" fill="none" xmlns="http://www.w3.org/2000/svg" style="vertical-align:middle; flex-shrink:0;">
        <rect x="2" y="3.5" width="20" height="7.5" rx="3" fill="${c}" fill-opacity="0.88" />
        <circle cx="15.5" cy="7.25" r="1.1" fill="#0f172a" />
        <circle cx="18.5" cy="7.25" r="1.1" fill="#0f172a" />
        <rect x="2" y="13" width="20" height="7.5" rx="3" fill="${c}" fill-opacity="0.88" />
        <circle cx="15.5" cy="16.75" r="1.1" fill="#0f172a" />
        <circle cx="18.5" cy="16.75" r="1.1" fill="#0f172a" />
    </svg>`;
}

function renderSpDatabaseIcon(color) {
    const c = color || '#a78bfa';
    return `<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="${c}" stroke-width="2" style="vertical-align:middle; flex-shrink:0;">
        <ellipse cx="12" cy="5" rx="9" ry="3"/>
        <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/>
        <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
    </svg>`;
}

function closeAllSpCardMenus() {
    document.querySelectorAll('.sp-kebab-menu.open').forEach(m => {
        m.classList.remove('open');
        const card = m.closest('.sp-card');
        if (card) card.classList.remove('menu-open');
    });
}

function toggleSpCardMenu(menuId, ev) {
    if (ev) ev.stopPropagation();
    const menu = document.getElementById(menuId);
    if (!menu) return;
    const willOpen = !menu.classList.contains('open');
    closeAllSpCardMenus();
    if (willOpen) {
        menu.classList.add('open');
        const card = menu.closest('.sp-card');
        if (card) card.classList.add('menu-open');
    }
}

document.addEventListener('click', function (e) {
    if (!e.target.closest('.sp-kebab-wrap')) {
        closeAllSpCardMenus();
    }
});
document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') closeAllSpCardMenus();
});

async function spToggleServerMaintenance(id, isMaint, ctx) {
    closeAllSpCardMenus();
    try {
        await apiFetch(`/api/servers/${id}/maintenance`, { method: 'POST' });
        if (typeof showToast === 'function') {
            showToast(`Maintenance mode ${isMaint ? 'disabled' : 'enabled'}`, 'success');
        }
        if (ctx === 'dashboard' && typeof loadDashboardData === 'function') {
            loadDashboardData();
        } else if (typeof loadServers === 'function') {
            loadServers();
        }
    } catch (e) {
        if (typeof showToast === 'function') showToast('Maintenance toggle failed', 'error');
    }
}

async function spDeleteServer(id, ctx) {
    closeAllSpCardMenus();
    if (!confirm('Are you sure you want to permanently delete this asset?')) return;
    try {
        await apiFetch(`/api/servers/${id}`, { method: 'DELETE' });
        const card = document.getElementById(`srv-card-${id}`) || document.getElementById(`dash-srv-card-${id}`);
        if (card) card.remove();
        if (typeof showToast === 'function') showToast('Asset deleted', 'success');
        if (ctx === 'dashboard' && typeof loadDashboardData === 'function') {
            loadDashboardData();
        }
    } catch (e) {
        if (typeof showToast === 'function') showToast(e.message || 'Delete failed', 'error');
    }
}

async function spViewAgentCrashLogs(id, name) {
    closeAllSpCardMenus();
    if (typeof viewAgentCrashLogs === 'function') {
        return viewAgentCrashLogs(id, name);
    }
    try {
        const res = await apiFetch(`/api/servers/${id}/recent-logs`);
        const logs = res.logs || [];
        const bodyText = logs.length ? logs.join('\n') : 'No recent agent log lines collected yet.';
        alert(`Last 20 Agent Logs — ${name}:\n\n${bodyText}`);
    } catch (e) {
        if (typeof showToast === 'function') showToast('Failed to load agent logs', 'error');
    }
}

function renderCompactWebsiteCard(a, opts = {}) {
    const id = a.id;
    const name = _spEsc(a.name || 'Unnamed Application');
    const url = _spEsc(a.primary_url || '');
    const status = opts.computedStatus || a.computed_status || a.status || 'WAITING';
    const compRatio = _spEsc(a.components_ratio || '0/0');
    const epm = Number(a.events_per_min || 0);
    const inc = Number(a.open_incidents ?? a.open_security_events ?? 0);
    const lastEv = _spEsc(a.last_event_formatted || (a.last_event_at ? 'Recent' : 'never'));
    const proj = _spEsc(a.project_name || 'No project');
    const isRead = a.is_read === true || a.is_read === 'true';
    const readBadgeHtml = opts.readBadgeHtml !== undefined ? opts.readBadgeHtml : (isRead ? '<span class="badge-read-tag">✓ Read</span>' : '');
    const onClickFn = opts.onClick || `openAppDetailsModal(${id})`;

    let pillCls = 'sp-pill-muted';
    let pillText = status === 'WAITING' ? 'WAITING DATA' : status;
    let stateClass = '';

    if (status === 'CRITICAL') {
        pillCls = 'sp-pill-crit';
        stateClass = 'sp-card-crit';
    } else if (status === 'TROUBLE') {
        pillCls = 'sp-pill-warn';
        stateClass = 'sp-card-warn';
    } else if (status === 'NORMAL' || status === 'UP') {
        pillCls = 'sp-pill-ok';
        pillText = 'UP';
    } else if (status === 'MAINT') {
        pillCls = 'sp-pill-info';
        stateClass = 'sp-card-maint';
    } else if (status === 'DOWN') {
        pillCls = 'sp-pill-crit';
        stateClass = 'sp-card-crit';
        pillText = 'DOWN';
    } else if (status === 'PENDING_APPROVAL' || status === 'WAITING') {
        pillCls = 'sp-pill-warn';
    }

    return `
    <div class="sp-card sp-website-card ${stateClass} fade-in" onclick="${onClickFn}">
        <div class="sp-card-head">
            <div class="sp-card-title-wrap">
                ${renderSpWebsiteIcon('#d97706')}
                <span class="sp-card-title" title="${name}">${name}</span>
            </div>
            <div class="sp-card-head-right">
                ${readBadgeHtml}
                <span class="sp-status-pill ${pillCls}">${_spEsc(pillText)}</span>
            </div>
        </div>

        <div class="sp-card-sub" title="${url}">${url || '&mdash;'}</div>

        <div class="sp-metric-box sp-metric-3">
            <div class="sp-metric-col">
                <span class="sp-metric-lbl">COMPONENTS</span>
                <span class="sp-metric-val">${compRatio}</span>
            </div>
            <div class="sp-metric-col">
                <span class="sp-metric-lbl">EVENTS/MIN</span>
                <span class="sp-metric-val">${epm}</span>
            </div>
            <div class="sp-metric-col">
                <span class="sp-metric-lbl">OPEN INCIDENTS</span>
                <span class="sp-metric-val ${inc > 0 ? 'sp-val-crit' : ''}">${inc}</span>
            </div>
        </div>

        <div class="sp-card-foot-links">
            <span class="sp-foot-proj" title="${proj}">
                <span style="opacity:0.75">📁</span>
                <span class="sp-foot-proj-name">${proj}</span>
            </span>
            <span class="sp-foot-time">Last event: <strong>${lastEv}</strong></span>
        </div>
    </div>`;
}

function renderCompactAssetCard(s, opts = {}) {
    const id = s.id;
    const rawName = String(s.hostname || s.name || s.ip || 'server-node');
    const nameEsc = _spEsc(rawName);
    const nameJs = rawName.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
    const ip = _spEsc(s.ip_address || s.ip || '127.0.0.1');
    const fromPage = opts.from || 'assets';
    const ctx = opts.ctx || (fromPage === 'dashboard' ? 'dashboard' : 'assets');
    const cardDomId = ctx === 'dashboard' ? `dash-srv-card-${id}` : `srv-card-${id}`;
    const menuDomId = `sp-menu-${ctx}-${id}`;
    const manageUrl = opts.manageUrl || `/servers/${id}?from=${fromPage}`;

    const unifiedStatus = opts.computedStatus || getUnifiedAssetStatus({ _type: 'server', raw: s });
    const isDown = unifiedStatus === 'DOWN';
    const isMaint = unifiedStatus === 'MAINT';
    const isCrit = unifiedStatus === 'CRITICAL';
    const isTrouble = unifiedStatus === 'TROUBLE';

    const cpu = Math.round(Number(s.cpu_percent || 0));
    const ram = Math.round(Number(s.memory_percent || 0));
    const disk = Math.round(Number(s.disk_percent || 0));
    const openAlerts = Number(s.alert_count || 0);
    const critAlerts = Number(s.critical_alert_count || 0);
    const isSrvRead = s.is_read === true || s.is_read === 'true';
    const readBadgeHtml = opts.readBadgeHtml !== undefined ? opts.readBadgeHtml : (isSrvRead ? '<span class="badge-read-tag">✓ Read</span>' : '');
    const manageLabel = _spEsc(opts.manageLabel || 'MANAGE ASSET');

    const nameLow = rawName.toLowerCase();
    const osLow = (s.os_info || '').toLowerCase();
    const isDb = nameLow.includes('db') || osLow.includes('postgres') || osLow.includes('mysql');
    const isWin = osLow.includes('windows');

    let typeLabel = 'LINUX SERVER';
    let nodeIcon = renderSpAssetChassisIcon('#60a5fa');
    if (isDb) {
        typeLabel = 'DATABASE';
        nodeIcon = renderSpDatabaseIcon('#a78bfa');
    } else if (isWin) {
        typeLabel = 'WINDOWS SERVER';
    }

    let rawAgentV = String(s.agent_version || '1.6.2');
    if (rawAgentV.includes('{') || rawAgentV.includes('version')) rawAgentV = '2.1.7';
    const targetV = opts.targetVersion || '2.1.9';
    let upStat = s.update_status || (_spIsVerAtLeast(rawAgentV, targetV) ? 'up_to_date' : 'update_available');
    if (_spIsVerAtLeast(rawAgentV, targetV)) {
        upStat = 'up_to_date';
    } else if (upStat === 'unsupported' && (String(s.agent_version).includes('{') || String(s.agent_version).includes('version') || s.is_canary)) {
        upStat = 'update_available';
    }

    let upHtml = '';
    if (upStat === 'up_to_date') {
        upHtml = '<span class="sp-ver-ok">Up to date</span>';
    } else if (upStat === 'update_available') {
        upHtml = '<span class="sp-ver-info">Update avail</span>';
    } else if (upStat === 'updating') {
        upHtml = '<span class="sp-ver-warn">Updating...</span>';
    } else if (upStat === 'failed') {
        upHtml = `<span class="sp-ver-err" title="${_spEsc(s.update_error || 'Update failed')}">Failed</span>`;
    } else if (upStat === 'unsupported') {
        upHtml = '<span class="sp-ver-err">Unsupported</span>';
    }

    let dotClass = 'sp-dot-ok';
    let statusLabel = 'NORMAL';
    let statusDetail = `CPU: ${cpu}%`;
    let stateClass = '';
    const isRecentFail = upStat === 'failed' || s.update_error || (s.last_update_attempt && (Date.now() - new Date(s.last_update_attempt).getTime() < 1800000));

    const degEntries = s.degraded_collectors && typeof s.degraded_collectors === 'object'
        ? Object.entries(s.degraded_collectors).filter(([k, v]) => {
            const kl = k.toLowerCase();
            if (kl.includes('heartbeat') || kl.includes('telemetry_loop') || kl.includes('network') || kl.includes('socket')) return false;
            const msg = String((v && v.message) || v || '').toLowerCase();
            if (msg.includes('connection refused') || msg.includes('errno 111') || msg.includes('timed out') || msg.includes('unreachable')) return false;
            return true;
        })
        : [];

    if (isDown) {
        dotClass = 'sp-dot-crit';
        stateClass = 'sp-card-crit';
        statusLabel = isRecentFail ? 'UPDATE FAILED' : 'OFFLINE';
        statusDetail = isRecentFail ? `v${_spEsc(rawAgentV)}` : 'Connection Lost';
    } else if (degEntries.length > 0 && !isCrit) {
        dotClass = 'sp-dot-warn';
        stateClass = 'sp-card-warn';
        statusLabel = 'DEGRADED';
        statusDetail = `${_spEsc(degEntries[0][0])}`;
    } else if (isMaint) {
        dotClass = 'sp-dot-info';
        stateClass = 'sp-card-maint';
        statusLabel = 'MAINT';
        statusDetail = `CPU: ${cpu}%`;
    } else if (isCrit) {
        dotClass = 'sp-dot-crit';
        stateClass = 'sp-card-crit';
        statusLabel = 'CRITICAL';
        statusDetail = `${critAlerts || openAlerts || 1} Alert(s) • CPU: ${cpu}%`;
    } else if (isTrouble) {
        dotClass = 'sp-dot-warn';
        stateClass = 'sp-card-warn';
        if (cpu > 85 || ram > 85 || disk > 85) {
            statusLabel = 'HIGH RES';
            statusDetail = `CPU: ${cpu}% / RAM: ${ram}%`;
        } else {
            statusLabel = 'TROUBLE';
            statusDetail = `${openAlerts} Alert(s) • CPU: ${cpu}%`;
        }
    }

    const canAdmin = window.USER_ROLE !== 'normal';

    return `
    <div id="${cardDomId}" class="sp-card sp-asset-card ${stateClass} fade-in" onclick="openImage3Modal(${id})">
        <div class="sp-card-head">
            <div class="sp-card-title-wrap">
                ${nodeIcon}
                <span class="sp-card-title" title="${nameEsc}">${nameEsc}</span>
                <span class="sp-type-pill">${typeLabel}</span>
            </div>
            <div class="sp-card-head-right">
                ${readBadgeHtml}
                ${canAdmin ? `<button type="button" class="sp-del-pill" onclick="event.stopPropagation(); spDeleteServer(${id}, '${ctx}')" title="Delete asset">DEL</button>` : ''}
            </div>
        </div>

        <div class="sp-card-sub">
            <span title="${ip}">${ip}</span>
            <span class="sp-sep">|</span>
            <span>v${_spEsc(rawAgentV)}</span>
            ${upHtml}
        </div>

        <div class="sp-metric-box sp-metric-2">
            <div class="sp-metric-col">
                <span class="sp-metric-lbl">OPEN ALERTS</span>
                <span class="sp-metric-val ${openAlerts > 0 ? 'sp-val-warn' : ''}">${openAlerts > 0 ? openAlerts : '-'}</span>
            </div>
            <div class="sp-metric-col">
                <span class="sp-metric-lbl">CRITICAL ALERTS</span>
                <span class="sp-metric-val ${critAlerts > 0 ? 'sp-val-crit' : ''}">${critAlerts > 0 ? critAlerts : '-'}</span>
            </div>
        </div>

        <div class="sp-card-foot-bar">
            <div class="sp-status-strip" title="${_spEsc(statusLabel)} - ${_spEsc(statusDetail)}">
                <span class="sp-status-dot ${dotClass}"></span>
                <span class="sp-status-txt"><strong>${_spEsc(statusLabel)}</strong> &ndash; ${_spEsc(statusDetail)}</span>
            </div>

            <div class="sp-kebab-wrap" onclick="event.stopPropagation();">
                <button type="button" class="sp-kebab-btn" onclick="toggleSpCardMenu('${menuDomId}', event)" title="Asset options" aria-label="Asset options">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
                        <circle cx="12" cy="5" r="2"/>
                        <circle cx="12" cy="12" r="2"/>
                        <circle cx="12" cy="19" r="2"/>
                    </svg>
                </button>
                <div id="${menuDomId}" class="sp-kebab-menu">
                    <button type="button" class="sp-kebab-item" onclick="closeAllSpCardMenus(); window.location.href='${manageUrl}'">
                        ${manageLabel}
                    </button>
                    <button type="button" class="sp-kebab-item" onclick="closeAllSpCardMenus(); openImage3Modal(${id})">
                        View Incidents &amp; Details
                    </button>
                    ${canAdmin ? `
                    <button type="button" class="sp-kebab-item" onclick="spToggleServerMaintenance(${id}, ${isMaint}, '${ctx}')">
                        ${isMaint ? 'Disable Maintenance' : 'Enable Maintenance'}
                    </button>` : ''}
                    ${(isDown && isRecentFail) ? `
                    <button type="button" class="sp-kebab-item" onclick="spViewAgentCrashLogs(${id}, '${nameJs}')">
                        View Last 20 Agent Logs
                    </button>` : ''}
                    ${canAdmin ? `
                    <button type="button" class="sp-kebab-item sp-kebab-danger" onclick="spDeleteServer(${id}, '${ctx}')">
                        Delete Asset
                    </button>` : ''}
                </div>
            </div>
        </div>
    </div>`;
}
