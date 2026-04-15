/**
 * Sentinels - Threat Logs Page JavaScript
 */

// Delete a single threat
async function deleteLog(id) {
    if (!confirm('Delete this threat record?')) return;

    try {
        const response = await fetch(`/api/threats/delete/${id}`, { method: 'POST' });
        const data = await response.json();

        if (data.success) {
            // Remove row from table
            const row = document.getElementById(`row-${id}`);
            if (row) {
                row.remove();
                updateCount(-1);
            }
        } else {
            alert('Failed to delete threat');
        }
    } catch (error) {
        console.error('Delete error:', error);
        alert('Error deleting threat');
    }
}

// Update the count display
function updateCount(delta) {
    const countEl = document.getElementById('totalCount');
    const current = parseInt(countEl.textContent) || 0;
    const newCount = Math.max(0, current + delta);
    countEl.textContent = newCount;

    // Show empty state if no threats left
    if (newCount === 0) {
        const tbody = document.getElementById('logsTableBody');
        tbody.innerHTML = `
            <tr id="emptyState">
                <td colspan="8" class="px-6 py-16 text-center text-gray-500">
                    <span class="material-symbols-outlined text-5xl mb-3 block text-primary">verified_user</span>
                    <p class="text-lg font-medium text-gray-400">No threats detected</p>
                    <p class="text-sm">Your network is secure. Threats will appear here when detected.</p>
                </td>
            </tr>
        `;
    }
}

/**
 * Escape HTML special characters to prevent XSS.
 * @param {string} str
 * @returns {string}
 */
function escapeHTML(str) {
    if (str == null) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

/**
 * Build a severity cell with appropriate colour class.
 * @param {string} severity
 * @returns {string}
 */
function buildSeverityHTML(severity) {
    const s = severity || 'LOW';
    if (s === 'CRITICAL') {
        return `<span class="text-danger font-bold">${escapeHTML(s)}</span>`;
    } else if (s === 'HIGH') {
        return `<span class="text-orange-500 font-bold">${escapeHTML(s)}</span>`;
    } else if (s === 'MEDIUM') {
        return `<span class="text-yellow-500">${escapeHTML(s)}</span>`;
    } else {
        return `<span class="text-gray-400">${escapeHTML(s)}</span>`;
    }
}

/**
 * Build the "Detected By" badge cell.
 * @param {string|null} method
 * @returns {string}
 */
function buildDetectionMethodHTML(method) {
    if (method === 'ML') {
        return `<span class="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-bold bg-purple-500/20 text-purple-400 border border-purple-500/40">
                    <span class="material-symbols-outlined text-[12px]">model_training</span>ML
                </span>`;
    }
    return `<span class="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-bold bg-blue-500/20 text-blue-400 border border-blue-500/40">
                <span class="material-symbols-outlined text-[12px]">rule</span>Heuristic
            </span>`;
}

/**
 * Build the HTML for a single threat table row, mirroring the Jinja2 template.
 * @param {Object} threat
 * @returns {string}
 */
function buildRowHTML(threat) {
    const sourceIPCell = threat.source_ip
        ? `<span class="font-mono text-primary cursor-pointer hover:text-white hover:underline transition-colors"
               onclick="window.SentinelsShowIPDetails && window.SentinelsShowIPDetails('${escapeHTML(threat.source_ip)}')"
               title="Click for Deep Dive">${escapeHTML(threat.source_ip)}</span>`
        : `<span class="text-gray-500">—</span>`;

    return `
        <tr class="hover:bg-white/5 transition-colors" id="row-${threat.id}">
            <td class="px-6 py-4 font-mono text-gray-500">#${threat.id}</td>
            <td class="px-6 py-4 font-mono text-gray-400">${escapeHTML(threat.timestamp)}</td>
            <td class="px-6 py-4">${sourceIPCell}</td>
            <td class="px-6 py-4 font-mono text-gray-300">${escapeHTML(threat.destination_ip) || '—'}</td>
            <td class="px-6 py-4">
                <span class="inline-block whitespace-nowrap px-2 py-1 rounded text-xs font-bold bg-[#333] text-gray-300 border border-gray-600">
                    ${escapeHTML(threat.protocol) || 'N/A'}
                </span>
            </td>
            <td class="px-6 py-4">
                <span class="inline-block whitespace-nowrap px-2 py-1 rounded text-xs font-bold bg-danger/20 text-danger border border-danger/40">
                    ${escapeHTML(threat.threat_type) || 'Unknown'}
                </span>
            </td>
            <td class="px-6 py-4">${buildSeverityHTML(threat.severity)}</td>
            <td class="px-6 py-4">${buildDetectionMethodHTML(threat.detection_method)}</td>
            <td class="px-6 py-4 text-center align-middle">
                <div class="flex items-center justify-center gap-2">
                    <button onclick="showThreatDetails('${threat.id}')"
                        class="p-2 text-gray-400 hover:text-white hover:bg-white/10 rounded transition-colors inline-flex items-center justify-center"
                        title="View Packet Details">
                        <span class="material-symbols-outlined text-sm">visibility</span>
                    </button>
                    <button onclick="window.SentinelsShowIPDetails && window.SentinelsShowIPDetails('${escapeHTML(threat.source_ip)}')"
                        class="p-2 text-gray-400 hover:text-primary hover:bg-primary/10 rounded transition-colors inline-flex items-center justify-center"
                        title="Inspect IP">
                        <span class="material-symbols-outlined text-sm">search</span>
                    </button>
                </div>
            </td>
        </tr>
    `;
}

/**
 * Check whether any modal is currently visible on the page.
 * @returns {boolean}
 */
function isModalOpen() {
    // Look for any element that acts as a modal overlay/container that is visible.
    // The base template modal uses SentinelsGlobal; check for a visible modal element.
    const modal = document.getElementById('globalModal') || document.querySelector('[data-modal]');
    if (modal) {
        return !modal.classList.contains('hidden') && modal.style.display !== 'none';
    }
    return false;
}

/**
 * Fetch the latest threats and re-render the table body.
 */
async function refreshLogs() {
    // Do not refresh while the user has a modal open
    if (isModalOpen()) return;

    try {
        const response = await fetch('/api/threats?limit=200');
        const data = await response.json();

        if (!data.success) return;

        const threats = data.threats || [];
        const tbody = document.getElementById('logsTableBody');
        const countEl = document.getElementById('totalCount');

        if (!tbody) return;

        // Update count badge
        if (countEl) {
            countEl.textContent = threats.length;
        }

        if (threats.length === 0) {
            tbody.innerHTML = `
                <tr id="emptyState">
                    <td colspan="9" class="px-6 py-16 text-center text-gray-500">
                        <span class="material-symbols-outlined text-5xl mb-3 block text-primary">verified_user</span>
                        <p class="text-lg font-medium text-gray-400">No threats detected</p>
                        <p class="text-sm">Your network is secure. Threats will appear here when detected.</p>
                    </td>
                </tr>
            `;
        } else {
            tbody.innerHTML = threats.map(buildRowHTML).join('');
        }
    } catch (error) {
        console.error('[Sentinels] Failed to refresh logs:', error);
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    // Clear all history button
    const clearBtn = document.getElementById('clearHistoryBtn');
    if (clearBtn) {
        clearBtn.addEventListener('click', async () => {
            if (!confirm('Are you sure you want to delete ALL threat history? This cannot be undone.')) return;

            try {
                const response = await fetch('/api/threats/clear', { method: 'POST' });
                const data = await response.json();

                if (data.success) {
                    location.reload();
                } else {
                    alert('Failed to clear history');
                }
            } catch (error) {
                console.error('Clear error:', error);
                alert('Error clearing history');
            }
        });
    }

    // Event delegation for delete buttons
    document.addEventListener('click', (e) => {
        const deleteBtn = e.target.closest('.delete-btn');
        if (deleteBtn) {
            const id = deleteBtn.dataset.id;
            if (id) {
                deleteLog(id);
            }
        }
    });

    // Auto-refresh every 5 seconds
    setInterval(refreshLogs, 5000);

    console.log('[Sentinels] Logs page initialized (auto-refresh every 5s)');
});
