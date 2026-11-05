with open("templates/app_detail_modal.html", "r", encoding="utf-8") as f:
    html = f.read()

# 1. Add Select All Incidents header bar
target_sel_bar = """        <!-- Selection Bar -->
        <div id="incidents-selection-bar" style="display:none; justify-content:space-between; align-items:center; background:rgba(2,132,199,0.15); border:1px solid var(--cyan); border-radius:6px; padding:6px 12px; margin-bottom:10px">"""

replacement_sel_bar = """        <!-- Master Select All bar for Incidents -->
        <div style="display:flex; justify-content:space-between; align-items:center; background:rgba(255,255,255,0.02); border:1px solid var(--border); border-radius:6px; padding:6px 12px; margin-bottom:8px">
            <label style="display:flex; align-items:center; gap:8px; font-size:11.5px; font-weight:600; color:var(--text); cursor:pointer">
                <input type="checkbox" id="incidents-select-all" onchange="toggleSelectAll('incidents', this.checked)">
                <span>Select All Incidents</span>
            </label>
            <span style="font-size:10.5px; color:var(--text3)">Check boxes to perform bulk triage or export multi-incident report</span>
        </div>

        <!-- Selection Bar -->
        <div id="incidents-selection-bar" style="display:none; justify-content:space-between; align-items:center; background:rgba(2,132,199,0.15); border:1px solid var(--cyan); border-radius:6px; padding:6px 12px; margin-bottom:10px">
            <span style="font-size:11.5px; font-weight:700; color:var(--cyan)"><span id="incidents-selected-count">0</span> incidents selected</span>
            <div style="display:flex; gap:6px; align-items:center">
                <button class="btn btn-glass" onclick="batchVerdictSelected('true_positive')" style="padding:4px 10px; font-size:11px; color:var(--cyan); border-color:rgba(56,189,248,0.4)">✓ True (Bulk)</button>
                <button class="btn btn-glass" onclick="batchVerdictSelected('false_positive')" style="padding:4px 10px; font-size:11px; color:var(--red); border-color:rgba(239,68,68,0.4)">✗ False Pos (Bulk)</button>
                <button class="btn btn-glass" onclick="openCloseModal('incidents')" style="padding:4px 10px; font-size:11px; color:var(--amber); border-color:rgba(245,158,11,0.4)">✓ Mark as Closed</button>
                <button class="btn btn-glass" onclick="batchReopenRows('incidents')" style="padding:4px 10px; font-size:11px; color:var(--green); border-color:rgba(16,185,129,0.4)">↺ Reopen</button>
                <button class="btn btn-primary" onclick="generateSelectedReport('incidents')" style="padding:4px 12px; font-size:11px">📄 Report for Selected</button>
                <button class="btn btn-ghost" onclick="clearTabSelection('incidents')" style="padding:4px 8px; font-size:11px; color:var(--text3)">Clear</button>
            </div>
        </div>"""

# Replace the existing incidents selection bar with the enhanced version + master select all checkbox
old_full_sel_bar = """        <!-- Selection Bar -->
        <div id="incidents-selection-bar" style="display:none; justify-content:space-between; align-items:center; background:rgba(2,132,199,0.15); border:1px solid var(--cyan); border-radius:6px; padding:6px 12px; margin-bottom:10px">
            <span style="font-size:11.5px; font-weight:700; color:var(--cyan)"><span id="incidents-selected-count">0</span> incidents selected</span>
            <div style="display:flex; gap:6px; align-items:center">
                <button class="btn btn-glass" onclick="openCloseModal('incidents')" style="padding:4px 10px; font-size:11px; color:var(--amber); border-color:rgba(245,158,11,0.4)">✓ Mark as Closed</button>
                <button class="btn btn-glass" onclick="batchReopenRows('incidents')" style="padding:4px 10px; font-size:11px; color:var(--green); border-color:rgba(16,185,129,0.4)">↺ Reopen</button>
                <button class="btn btn-primary" onclick="generateSelectedReport('incidents')" style="padding:4px 12px; font-size:11px">📄 Report for Selected</button>
                <button class="btn btn-ghost" onclick="clearTabSelection('incidents')" style="padding:4px 8px; font-size:11px; color:var(--text3)">Clear</button>
            </div>
        </div>"""

if old_full_sel_bar in html:
    html = html.replace(old_full_sel_bar, replacement_sel_bar)
    print("[+] Added master Select All and bulk triage toolbar to Incidents tab")

# 2. Fix submitVerdict reload fallback and add batchVerdictSelected
old_verdict_func = """async function submitVerdict(targetType, targetId, verdict, ruleName, reason = '') {
    try {
        const res = await apiFetch('/api/detection/verdict', {
            method: 'POST',
            body: JSON.stringify({
                target_type: targetType,
                target_id: targetId,
                verdict: verdict,
                rule_name: ruleName,
                reason: reason || (verdict === 'true_positive' ? 'Confirmed by analyst' : 'Marked false positive')
            })
        });
        if (typeof showToast === 'function') {
            showToast(verdict === 'true_positive' ? 'Confirmed True Positive' : 'Marked False Positive & Auto-Closed', 'success');
        }
        if (typeof refreshIncidentsTab === 'function') refreshIncidentsTab();
        else if (typeof refreshAppEventsView === 'function') refreshAppEventsView();
        else window.location.reload();
    } catch(e) {
        if (typeof showToast === 'function') showToast('Failed to record verdict', 'error');
    }
}"""

new_verdict_func = """async function submitVerdict(targetType, targetId, verdict, ruleName, reason = '') {
    try {
        const res = await apiFetch('/api/detection/verdict', {
            method: 'POST',
            body: JSON.stringify({
                target_type: targetType,
                target_id: targetId,
                verdict: verdict,
                rule_name: ruleName,
                reason: reason || (verdict === 'true_positive' ? 'Confirmed by analyst' : 'Marked false positive')
            })
        });
        if (typeof showToast === 'function') {
            showToast(verdict === 'true_positive' ? 'Confirmed True Positive' : 'Marked False Positive & Auto-Closed', 'success');
        }
        if (typeof loadAppIncidents === 'function' && typeof activeModalAppId !== 'undefined' && activeModalAppId) {
            loadAppIncidents(activeModalAppId);
        } else if (typeof refreshAppEventsView === 'function') {
            refreshAppEventsView();
        }
    } catch(e) {
        if (typeof showToast === 'function') showToast('Failed to record verdict: ' + (e.message || e), 'error');
    }
}

async function batchVerdictSelected(verdict) {
    const ids = Array.from(selectedTabRows.incidents);
    if (ids.length === 0) {
        alert('Please select at least one incident.');
        return;
    }
    let reason = verdict === 'true_positive' ? 'Confirmed by analyst in bulk' : '';
    if (verdict === 'false_positive') {
        reason = prompt('Reason for marking selected incidents as False Positive (REQUIRED):');
        if (reason === null) return;
        if (!reason.trim()) {
            alert('A reason is required.');
            return;
        }
    }
    try {
        for (const incId of ids) {
            await apiFetch('/api/detection/verdict', {
                method: 'POST',
                body: JSON.stringify({
                    target_type: 'incident',
                    target_id: parseInt(incId),
                    verdict: verdict,
                    rule_name: 'Bulk Triage',
                    reason: reason
                })
            });
        }
        if (typeof showToast === 'function') showToast(`Successfully triaged ${ids.length} incidents as ${verdict}`, 'success');
        clearTabSelection('incidents');
        if (typeof loadAppIncidents === 'function') loadAppIncidents(activeModalAppId);
    } catch(e) {
        alert('Error triaging incidents: ' + (e.message || e));
    }
}"""

if old_verdict_func in html:
    html = html.replace(old_verdict_func, new_verdict_func)
    print("[+] Fixed submitVerdict to prevent page reload and added batchVerdictSelected")

# 3. Prevent event bubbling on True / False Pos buttons
html = html.replace(
    'onclick="submitVerdict(\'incident\', ${i.id}, \'true_positive\', \'${escapeHtml(i.title)}\')"',
    'onclick="event.preventDefault(); event.stopPropagation(); submitVerdict(\'incident\', ${i.id}, \'true_positive\', \'${escapeHtml(i.title)}\')"'
)
html = html.replace(
    'onclick="promptFalsePositive(\'incident\', ${i.id}, \'${escapeHtml(i.title)}\')"',
    'onclick="event.preventDefault(); event.stopPropagation(); promptFalsePositive(\'incident\', ${i.id}, \'${escapeHtml(i.title)}\')"'
)

with open("templates/app_detail_modal.html", "w", encoding="utf-8") as f:
    f.write(html)

print("[+] Successfully updated templates/app_detail_modal.html")
