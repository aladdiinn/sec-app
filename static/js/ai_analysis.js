/**
 * ai_analysis.js — Shared Reusable AI Alert Analysis Component
 * Used across:
 * 1. Asset Modal / Incidents Tab (templates/dashboard.html & templates/servers.html)
 * 2. Website Modal / Incidents Tab (templates/app_detail_modal.html)
 * 3. Main Alerts Page (templates/alerts.html)
 */

window.AiAnalysisComponent = {
    cache: {},

    renderPanelHtml(targetId, targetType, severity) {
        return `
        <div id="ai-panel-${targetType}-${targetId}" class="ai-analysis-panel" style="background:rgba(15,23,42,0.85); border:1px solid rgba(56,189,248,0.25); border-radius:6px; padding:12px; font-size:12px; margin-top:8px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                <div style="display:flex; align-items:center; gap:6px;">
                    <span style="font-size:14px;">✨</span>
                    <strong style="color:var(--cyan, #38bdf8); font-size:11.5px; letter-spacing:0.5px;">AI THREAT ANALYSIS (ADVISORY)</strong>
                </div>
                <div id="ai-status-${targetType}-${targetId}"></div>
            </div>

            <div id="ai-content-${targetType}-${targetId}">
                <p style="color:var(--text3, #94a3b8); font-size:11.5px; margin:0 0 8px 0; line-height:1.4;">
                    Get an advisory AI assessment with root-cause analysis, false-positive indicators, and recommended triage steps.
                </p>
                <button class="btn btn-glass" onclick="event.stopPropagation(); AiAnalysisComponent.load(${targetId}, '${targetType}', '${severity}', false)" style="font-size:11px; padding:5px 12px; border-color:var(--cyan); color:var(--cyan); font-weight:600;">
                    ✨ Analyze with AI
                </button>
            </div>
        </div>
        `;
    },

    async load(targetId, targetType, severity, regenerate = false) {
        const contentEl = document.getElementById(`ai-content-${targetType}-${targetId}`);
        const statusEl = document.getElementById(`ai-status-${targetType}-${targetId}`);
        if (!contentEl) return;

        contentEl.innerHTML = `
            <div style="display:flex; align-items:center; gap:8px; color:var(--cyan); font-size:11.5px; padding:10px 0;">
                <span class="spinner" style="display:inline-block; width:12px; height:12px; border:2px solid var(--cyan); border-top-color:transparent; border-radius:50%; animation:spin 1s linear infinite;"></span>
                <span>Generating grounded advisory triage (up to 20s)...</span>
            </div>
        `;

        try {
            const url = `/api/alerts/${targetId}/ai-analysis?type=${encodeURIComponent(targetType)}${regenerate ? '&regenerate=true' : ''}`;
            const res = await apiFetch(url, { method: 'POST' });
            if (!res || !res.ok || !res.analysis) {
                contentEl.innerHTML = `
                    <div style="color:#f87171; font-size:11.5px;">
                        ${this.escapeHtml(res ? res.message : 'Failed to retrieve AI analysis.')}
                        <button class="btn btn-glass" onclick="event.stopPropagation(); AiAnalysisComponent.load(${targetId}, '${targetType}', '${severity}', true)" style="font-size:10px; padding:2px 8px; margin-left:6px;">Retry</button>
                    </div>
                `;
                return;
            }

            const a = res.analysis;
            this.renderAnalysisResult(targetId, targetType, severity, a);

        } catch (e) {
            contentEl.innerHTML = `
                <div style="color:#f87171; font-size:11.5px;">
                    Connection error or timeout during analysis.
                    <button class="btn btn-glass" onclick="event.stopPropagation(); AiAnalysisComponent.load(${targetId}, '${targetType}', '${severity}', true)" style="font-size:10px; padding:2px 8px; margin-left:6px;">Retry</button>
                </div>
            `;
        }
    },

    renderAnalysisResult(targetId, targetType, severity, a) {
        const contentEl = document.getElementById(`ai-content-${targetType}-${targetId}`);
        const statusEl = document.getElementById(`ai-status-${targetType}-${targetId}`);
        if (!contentEl) return;

        let conflictHtml = '';
        if (a.has_conflict) {
            conflictHtml = `
            <div style="background:rgba(239,68,68,0.18); border:1px solid #ef4444; border-radius:4px; padding:6px 10px; margin-bottom:8px; display:flex; align-items:center; gap:8px;">
                <span style="font-size:13px;">⚠️</span>
                <span style="color:#fca5a5; font-size:11px; font-weight:700;">
                    CONFLICT DETECTED: AI Assessed ${(a.assessed_risk || 'LOW').toUpperCase()} risk (Engine: ${(severity || 'CRITICAL').toUpperCase()})
                </span>
            </div>
            `;
        }

        const confColor = a.confidence === 'High' ? 'var(--green, #22c55e)' : (a.confidence === 'Medium' ? 'var(--amber, #f59e0b)' : 'var(--cyan, #38bdf8)');

        contentEl.innerHTML = `
            ${conflictHtml}
            <div style="display:flex; flex-direction:column; gap:6px; color:var(--text, #f8fafc); font-size:12px; line-height:1.45;">
                <div><strong style="color:var(--cyan);">Summary:</strong> ${this.escapeHtml(a.summary || 'N/A')}</div>
                <div><strong style="color:#94a3b8;">Likely Cause:</strong> ${this.escapeHtml(a.likely_cause || 'N/A')}</div>
                <div><strong style="color:#94a3b8;">Risk &amp; Impact:</strong> ${this.escapeHtml(a.risk_impact || 'N/A')}</div>
                <div><strong style="color:#38bdf8;">Recommended Steps:</strong> ${this.escapeHtml(a.recommendations || 'N/A')}</div>
                ${a.possible_fp ? `<div style="color:var(--amber, #fbbf24); font-size:11.5px;"><strong>False-Positive Indicators:</strong> ${this.escapeHtml(a.possible_fp)}</div>` : ''}
            </div>

            <div style="display:flex; justify-content:space-between; align-items:center; border-top:1px solid rgba(255,255,255,0.08); padding-top:8px; margin-top:8px; flex-wrap:wrap; gap:6px;">
                <div style="display:flex; gap:8px; align-items:center; font-size:10.5px; color:var(--text3, #64748b);">
                    <span>Confidence: <strong style="color:${confColor}">${this.escapeHtml(a.confidence || 'Medium')}</strong></span>
                    <span>•</span>
                    <span>Model: <code style="color:#94a3b8">${this.escapeHtml(a.model_name || 'gemini-2.5-flash')}</code></span>
                </div>
                <button class="btn btn-glass" onclick="event.stopPropagation(); AiAnalysisComponent.load(${targetId}, '${targetType}', '${severity}', true)" style="font-size:10px; padding:2px 8px; color:var(--text2);" title="Re-run analysis">
                    ↺ Regenerate
                </button>
            </div>
            <div style="font-size:9.5px; color:#64748b; margin-top:4px;">
                Advisory analysis only. Does not alter engine severity or operational status.
            </div>
        `;
    },

    escapeHtml(str) {
        if (!str) return '';
        return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
    }
};
