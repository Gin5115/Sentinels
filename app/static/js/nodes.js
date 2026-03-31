/**
 * Sentinels - Nodes Page JavaScript
 * Auto-refreshes the node cards every 5 seconds by polling /api/nodes.
 */

/**
 * Format bytes into a human-readable string.
 * @param {number} bytes
 * @returns {string}
 */
function formatBytes(bytes) {
    if (bytes >= 1048576) {
        return (bytes / 1048576).toFixed(1) + ' MB';
    } else if (bytes >= 1024) {
        return (bytes / 1024).toFixed(1) + ' KB';
    } else {
        return bytes + ' B';
    }
}

/**
 * Build the HTML for a single node card, mirroring the Jinja2 template.
 * @param {Object} node
 * @returns {string}
 */
function buildCardHTML(node) {
    // Device name logic: hostname > vendor (if not unknown/resolving) > ip
    let deviceName;
    if (node.hostname) {
        deviceName = `<span class="text-white font-bold text-lg group-hover:text-primary transition-colors truncate">${escapeHTML(node.hostname)}</span>`;
    } else if (node.vendor && node.vendor !== 'Unknown' && node.vendor !== 'Resolving...') {
        deviceName = `<span class="text-white font-bold text-lg group-hover:text-primary transition-colors truncate">${escapeHTML(node.vendor)}</span>`;
    } else {
        deviceName = `<span class="text-gray-400 font-bold text-lg group-hover:text-primary transition-colors truncate">${escapeHTML(node.ip)}</span>`;
    }

    // Icon: devices if hostname, else computer
    const iconName = node.hostname ? 'devices' : 'computer';

    // Secondary IP (truncated to 20 chars + ellipsis)
    const secondaryIPHTML = node.secondary_ip
        ? `<p class="text-gray-500 font-mono text-xs truncate" title="${escapeHTML(node.secondary_ip)}">${escapeHTML(node.secondary_ip.substring(0, 20))}...</p>`
        : '';

    // Vendor badge: only shown when hostname also exists and vendor is meaningful
    const showVendorBadge = node.hostname && node.vendor && node.vendor !== 'Unknown' && node.vendor !== 'Resolving...';
    const vendorBadgeHTML = showVendorBadge
        ? `<div class="mb-3 px-3 py-2 bg-background rounded-lg">
                <p class="text-gray-500 text-xs uppercase tracking-wider mb-1">Manufacturer</p>
                <p class="text-white text-sm font-medium truncate">${escapeHTML(node.vendor)}</p>
            </div>`
        : '';

    // MAC address row
    const macHTML = node.mac
        ? `<div class="flex items-center justify-between">
                <span class="text-gray-500 text-xs">MAC Address</span>
                <span class="text-gray-400 font-mono text-xs">${escapeHTML(node.mac)}</span>
            </div>`
        : '';

    // Last seen: show only HH:MM:SS portion (chars 11-19)
    const lastSeenTime = node.last_seen ? escapeHTML(node.last_seen.substring(11, 19)) : '—';

    return `
        <div class="bg-surface border border-[#333] rounded-lg p-5 hover:border-primary/50 transition-all group">
            <!-- Device Name & IP -->
            <div class="flex items-center gap-3 mb-3">
                <div class="size-12 rounded-lg bg-primary/10 flex items-center justify-center">
                    <span class="material-symbols-outlined text-primary text-2xl">${iconName}</span>
                </div>
                <div class="flex-1 min-w-0">
                    <p class="text-white font-bold text-lg group-hover:text-primary transition-colors truncate">
                        ${deviceName}
                    </p>
                    <p class="text-primary font-mono text-sm">${escapeHTML(node.ip)}</p>
                    ${secondaryIPHTML}
                </div>
            </div>

            ${vendorBadgeHTML}

            <!-- Stats -->
            <div class="grid grid-cols-2 gap-3 mb-4">
                <div class="bg-background rounded-lg p-3">
                    <p class="text-gray-500 text-xs uppercase tracking-wider">Packets</p>
                    <p class="text-white text-xl font-bold">${node.packets}</p>
                </div>
                <div class="bg-background rounded-lg p-3">
                    <p class="text-gray-500 text-xs uppercase tracking-wider">Data</p>
                    <p class="text-white text-xl font-bold">${formatBytes(node.bytes)}</p>
                </div>
            </div>

            <!-- Footer: MAC & Last Seen -->
            <div class="pt-3 border-t border-[#333] space-y-2">
                ${macHTML}
                <div class="flex items-center justify-between">
                    <span class="text-gray-500 text-xs">Last Active</span>
                    <span class="text-primary font-mono text-sm">${lastSeenTime}</span>
                </div>
            </div>
        </div>
    `;
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
 * Fetch nodes from the API and re-render the grid.
 */
async function fetchAndRender() {
    try {
        const response = await fetch('/api/nodes');
        const data = await response.json();

        if (!data.success) return;

        const nodes = data.nodes || [];
        const grid = document.getElementById('nodesGrid');
        const emptyState = document.getElementById('emptyState');
        const deviceCount = document.getElementById('deviceCount');

        // Update device count
        if (deviceCount) {
            deviceCount.textContent = nodes.length;
        }

        if (nodes.length === 0) {
            // Show empty state, hide grid
            if (grid) grid.style.display = 'none';
            if (emptyState) emptyState.style.display = '';
        } else {
            // Hide empty state, show and populate grid
            if (emptyState) emptyState.style.display = 'none';
            if (grid) {
                grid.style.display = '';
                grid.innerHTML = nodes.map(buildCardHTML).join('');
            }
        }
    } catch (error) {
        console.error('[Sentinels] Failed to fetch nodes:', error);
    }
}

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => {
    fetchAndRender();
    setInterval(fetchAndRender, 5000);
    console.log('[Sentinels] Nodes page auto-refresh initialized (5s interval)');
});
