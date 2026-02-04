/**
 * Sentinels IP Deep Dive Modal
 * Shared script for displaying detailed IP information.
 */

window.SentinelsShowIPDetails = function (ip) {
    if (!ip || ip === '—' || ip === '-') return;

    // Remove existing modal if any
    const existing = document.getElementById('deep-dive-modal');
    if (existing) existing.remove();

    // Create and show modal
    const modal = document.createElement('div');
    modal.className = 'fixed inset-0 bg-black/70 flex items-center justify-center z-50 animate-in fade-in duration-200';
    modal.id = 'deep-dive-modal';
    modal.onclick = (e) => { if (e.target === modal) modal.remove(); };

    modal.innerHTML = `
        <div class="bg-surface border border-[#333] rounded-lg p-6 max-w-md w-full mx-4 shadow-xl transform transition-all scale-100">
            <div class="flex justify-between items-center mb-4">
                <h3 class="text-lg font-bold text-white flex items-center gap-2">
                    <span class="material-symbols-outlined text-primary">hub</span>
                    Deep Dive: ${ip}
                </h3>
                <button onclick="document.getElementById('deep-dive-modal').remove()" 
                    class="text-gray-400 hover:text-white transition-colors">
                    <span class="material-symbols-outlined">close</span>
                </button>
            </div>
            <div id="modal-content" class="space-y-4">
                <div class="flex flex-col items-center justify-center py-8">
                    <span class="material-symbols-outlined animate-spin text-primary text-3xl mb-2">autorenew</span>
                    <span class="text-gray-400 text-sm">Analyzing Network Traffic...</span>
                </div>
            </div>
        </div>
    `;
    document.body.appendChild(modal);

    // Fetch packet data and geo data in parallel
    // OPTIMIZATION: Use server-side filtering (ip param) + smaller limit (1000)
    // This reduces payload from ~10MB -> ~5KB
    Promise.all([
        fetch(`/api/packets?ip=${ip}&limit=1000`).then(res => res.json()),
        fetch(`/api/geo/${ip}`).then(res => res.json())
    ])
        .then(([packetData, geoData]) => {
            const content = document.getElementById('modal-content');
            if (!content) return; // Modal closed before load

            if (!packetData.success || !packetData.packets) {
                content.innerHTML = '<p class="text-gray-400 text-center">No packet history available</p>';
                return;
            }

            // packets are already filtered by server
            const ipPackets = packetData.packets;
            const protocols = {};
            ipPackets.forEach(p => {
                const proto = (p.protocol || 'OTHER').toUpperCase();
                protocols[proto] = (protocols[proto] || 0) + 1;
            });

            const total = Object.values(protocols).reduce((a, b) => a + b, 0) || 1;
            const bars = Object.entries(protocols)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 5) // Top 5 protocols
                .map(([proto, count]) => {
                    const pct = ((count / total) * 100).toFixed(1);
                    // Color mapping
                    let color = '#888';
                    if (proto === 'TCP') color = '#0df269'; // Primary
                    else if (proto === 'UDP') color = '#3b82f6'; // Blue
                    else if (proto === 'ICMP') color = '#a855f7'; // Purple
                    else if (proto === 'HTTP' || proto === 'HTTPS') color = '#f59e0b'; // Amber

                    return `
                        <div class="flex items-center gap-2 mb-1">
                            <span class="w-12 text-xs text-gray-400 font-mono">${proto}</span>
                            <div class="flex-1 bg-[#222] rounded-full h-1.5 overflow-hidden">
                                <div class="h-full rounded-full transition-all duration-500" style="width: ${pct}%; background: ${color}"></div>
                            </div>
                            <span class="w-10 text-xs text-gray-300 text-right font-mono">${pct}%</span>
                        </div>
                    `;
                }).join('');

            // Process Geo Data
            let flag = '🌐';
            let location = 'Unknown, Unknown';

            if (geoData.success && geoData.geo) {
                flag = geoData.geo.flag || '🌐';
                // If private IP (local network)
                if (geoData.geo.country === 'LAN') {
                    flag = '💻';
                    location = 'Local Network';
                } else if (geoData.geo.country !== 'Unknown') {
                    location = `${geoData.geo.city}, ${geoData.geo.country}`;
                }
            }

            content.innerHTML = `
            <div class="grid grid-cols-2 gap-3 animate-in fade-in slide-in-from-bottom-2 duration-300">
                <!-- IP Badge -->
                <div class="bg-[#111] p-3 rounded-lg border border-[#333] hover:border-primary/30 transition-colors">
                    <span class="text-[10px] text-gray-500 uppercase font-bold tracking-wider block mb-1">Target</span>
                    <div class="text-primary font-mono text-sm font-bold truncate" title="${ip}">${ip}</div>
                </div>
                
                <!-- Packet Count -->
                <div class="bg-[#111] p-3 rounded-lg border border-[#333] hover:border-primary/30 transition-colors">
                    <span class="text-[10px] text-gray-500 uppercase font-bold tracking-wider block mb-1">Activity</span>
                    <div class="text-white font-bold text-lg flex items-baseline gap-1">
                        ${ipPackets.length.toLocaleString()} <span class="text-xs text-gray-500 font-normal">pkts</span>
                    </div>
                </div>
            </div>

            <!-- Location Card -->
            <div class="bg-[#111] p-3 rounded-lg border border-[#333] hover:border-primary/30 transition-colors animate-in fade-in slide-in-from-bottom-3 duration-500">
                <span class="text-[10px] text-gray-500 uppercase font-bold tracking-wider block mb-1">Location</span>
                <div class="text-white text-sm flex items-center gap-3">
                    <span class="text-2xl">${flag}</span>
                    <span class="font-medium tracking-wide">${location}</span>
                </div>
            </div>

            <!-- Protocol Breakdown -->
            <div class="bg-[#111] p-4 rounded-lg border border-[#333] hover:border-primary/30 transition-colors animate-in fade-in slide-in-from-bottom-4 duration-700">
                <span class="text-[10px] text-gray-500 uppercase font-bold tracking-wider block mb-3">Traffic Composition</span>
                <div class="space-y-1">
                    ${bars || '<p class="text-gray-500 text-xs italic">No traffic data captured recently.</p>'}
                </div>
            </div>
            
            <div class="flex justify-end mt-4">
                <button onclick="document.getElementById('deep-dive-modal').remove()" class="px-4 py-2 bg-[#222] hover:bg-[#333] text-white text-xs font-bold uppercase tracking-wide rounded transition-colors">
                    Close
                </button>
            </div>
        `;
        })
        .catch(err => {
            console.error(err);
            const content = document.getElementById('modal-content');
            if (content) content.innerHTML = '<p class="text-danger text-center">Error loading data. Check console.</p>';
        });
};
