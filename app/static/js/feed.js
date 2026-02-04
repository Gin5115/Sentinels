/**
 * Sentinels Live Packet Feed with Virtual Scrolling
 * High-performance rendering for 50,000+ packets
 */

document.addEventListener('DOMContentLoaded', () => {
    // ===== Configuration =====
    const CONFIG = {
        ROW_HEIGHT: 36,          // Fixed row height in pixels
        BUFFER_ROWS: 10,         // Extra rows above/below viewport
        MAX_PACKETS: 50000,      // Match backend buffer size
        FETCH_BATCH: 500         // Initial fetch size
    };

    // ===== State =====
    const state = {
        packets: [],             // All packets in memory (lightweight)
        packetIds: new Set(),    // For O(1) deduplication
        packetBuffer: [],        // Holding buffer for batching
        packetCount: 0,
        lastSecondCount: 0,
        packetsPerSecond: 0,
        localPaused: false,
        globalPaused: false,
        scrollTop: 0,
        visibleStartIndex: 0,
        visibleEndIndex: 0,
        initialLoadComplete: false,
        isUserAtBottom: true,
        newPacketCount: 0
    };

    // ===== DOM Elements =====
    const elements = {
        container: document.getElementById('virtualScrollContainer'),
        viewport: document.getElementById('virtualViewport'),
        content: document.getElementById('virtualContent'),
        protocolFilter: document.getElementById('protocolFilter'),
        ipSearch: document.getElementById('ipSearch'),
        localPauseBtn: document.getElementById('localPauseBtn'),
        clearTableBtn: document.getElementById('clearTableBtn'),
        packetCount: document.getElementById('feedPacketCount'),
        packetRate: document.getElementById('feedPacketRate'),
        statusIndicator: document.getElementById('feedStatusIndicator'),
        // Modal
        modal: document.getElementById('packetDetailsModal'),
        closeModalBtn: document.getElementById('closeModalBtn'),
        modalSrcIp: document.getElementById('modalSrcIp'),
        modalDstIp: document.getElementById('modalDstIp'),
        modalProtocol: document.getElementById('modalProtocol'),
        modalLength: document.getElementById('modalLength'),
        modalTimestamp: document.getElementById('modalTimestamp'),
        modalPorts: document.getElementById('modalPorts'),
        modalPayload: document.getElementById('modalPayload')
    };

    // ===== SocketIO =====
    const socket = io();

    socket.on('connect', () => {
        // Fetch is already triggered on DOMContentLoaded
    });

    socket.on('monitoring_status', (data) => {
        state.globalPaused = !data.active;
        updateStatusIndicator();
    });

    socket.on('init_stats', (data) => {
        state.globalPaused = !data.monitoring_active;
        updateStatusIndicator();
    });

    socket.on('session_restarted', () => {
        state.packets = [];
        state.packetCount = 0;
        state.initialLoadComplete = true;
        elements.packetCount.textContent = '0';
        renderVirtualList();
    });

    // ===== New Packet Handler (Buffered) =====
    socket.on('new_packet', (packet) => {
        if (state.localPaused || state.globalPaused) return;
        if (!state.initialLoadComplete) return;

        // Deduplication check (O(1) lookup)
        if (packet.id && state.packetIds.has(packet.id)) {
            return; // Skip duplicate
        }

        // Add to holding buffer (will be flushed by interval)
        state.packetBuffer.push(packet);
        state.packetCount++;
        state.lastSecondCount++;
    });

    // ===== Batched Flush (every 200ms) =====
    setInterval(() => {
        if (state.packetBuffer.length === 0) return;

        // Flush all buffered packets at once
        const batch = state.packetBuffer.splice(0);

        for (const packet of batch) {
            // Track ID for deduplication
            if (packet.id) {
                state.packetIds.add(packet.id);
            }

            // Add to main array (oldest at 0, newest at end)
            state.packets.push(packet);
        }

        // Limit to max packets (remove oldest)
        while (state.packets.length > CONFIG.MAX_PACKETS) {
            const removed = state.packets.shift();
            if (removed?.id) {
                state.packetIds.delete(removed.id);
            }
        }

        // Update UI once per batch
        elements.packetCount.textContent = formatNumber(state.packetCount);

        if (state.isUserAtBottom) {
            renderVirtualList();
            if (elements.container) {
                elements.container.scrollTop = 0;
            }
        } else {
            state.newPacketCount += batch.length;
            updateNewPacketsBadge();
        }
    }, 100);  // 10 FPS = responsive and smooth

    // ===== Fetch Initial Packets (called immediately on page load) =====
    async function fetchInitialPackets() {
        try {
            const res = await fetch(`/api/packets?limit=${CONFIG.MAX_PACKETS}`);
            const data = await res.json();
            if (data.success && data.packets) {
                // API returns newest-first, we need oldest-first for proper numbering
                state.packets = data.packets.reverse();
                state.packetCount = data.total;

                // Build deduplication set from loaded packets
                for (const pkt of state.packets) {
                    if (pkt.id) state.packetIds.add(pkt.id);
                }

                elements.packetCount.textContent = formatNumber(state.packetCount);
                renderVirtualList();
            }
        } catch (e) {
            console.error('[Feed] Error fetching packets:', e);
        } finally {
            // Mark initial load complete - now socket can add new packets
            state.initialLoadComplete = true;
        }
    }

    // Fetch immediately on page load (before socket connects)
    fetchInitialPackets();

    // ===== Virtual Scrolling Core =====
    function renderVirtualList() {
        const container = elements.container;
        const viewport = elements.viewport;
        const content = elements.content;

        if (!container || !viewport || !content) {
            console.error('[Feed] Virtual scroll elements not found');
            return;
        }

        // Get filtered packets (oldest first in array)
        const filteredPackets = getFilteredPackets();
        const totalPackets = filteredPackets.length;
        const totalHeight = totalPackets * CONFIG.ROW_HEIGHT;

        // Set content height for scrollbar
        content.style.height = `${totalHeight}px`;

        // Calculate visible range (in visual space, where 0 = top = newest)
        const scrollTop = container.scrollTop;
        const viewportHeight = container.clientHeight;

        const visualStartIndex = Math.max(0, Math.floor(scrollTop / CONFIG.ROW_HEIGHT) - CONFIG.BUFFER_ROWS);
        const visualEndIndex = Math.min(
            totalPackets,
            Math.ceil((scrollTop + viewportHeight) / CONFIG.ROW_HEIGHT) + CONFIG.BUFFER_ROWS
        );

        state.visibleStartIndex = visualStartIndex;
        state.visibleEndIndex = visualEndIndex;

        // Render only visible rows
        const fragment = document.createDocumentFragment();

        for (let visualIndex = visualStartIndex; visualIndex < visualEndIndex; visualIndex++) {
            // Visual index 0 = newest packet = last in array
            // So we map: dataIndex = (totalPackets - 1) - visualIndex
            const dataIndex = (totalPackets - 1) - visualIndex;
            const packet = filteredPackets[dataIndex];
            if (!packet) continue;

            // Packet number is dataIndex + 1 (oldest = #1)
            const packetNumber = dataIndex + 1;

            const row = createPacketRow(packet, packetNumber);
            row.style.position = 'absolute';
            row.style.top = `${visualIndex * CONFIG.ROW_HEIGHT}px`;
            row.style.left = '0';
            row.style.right = '0';
            row.style.height = `${CONFIG.ROW_HEIGHT}px`;
            fragment.appendChild(row);
        }

        // Clear and render
        viewport.innerHTML = '';
        viewport.appendChild(fragment);

        // Show empty state if no packets
        if (filteredPackets.length === 0) {
            viewport.innerHTML = `
                <div class="flex flex-col items-center justify-center h-64 text-gray-500">
                    <span class="material-symbols-outlined text-4xl mb-2 animate-pulse">sensors</span>
                    <p>Waiting for packets... Start monitoring to see live traffic.</p>
                </div>
            `;
        }
    }

    // ===== Create Packet Row =====
    function createPacketRow(packet, packetNumber) {
        const row = document.createElement('div');
        row.className = 'flex items-center text-sm border-b border-[#222] hover:bg-surface-highlight/50 transition-colors';

        if (packet.is_threat) {
            row.classList.add('bg-red-900/30', 'text-red-200');
        }

        const time = packet.timestamp ? packet.timestamp.split('T')[1]?.slice(0, 8) : '--:--:--';

        // Status badge
        let status = packet.is_threat
            ? `<span class="px-2 py-0.5 rounded bg-red-600 text-white text-xs font-bold">THREAT</span>`
            : `<span class="text-gray-500 text-xs">Normal</span>`;

        // Protocol badge color
        const protocolColors = {
            'TCP': 'bg-blue-500/20 text-blue-400 border-blue-500/40',
            'UDP': 'bg-purple-500/20 text-purple-400 border-purple-500/40',
            'ICMP': 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40'
        };
        const protocolClass = protocolColors[packet.protocol] || 'bg-gray-500/20 text-gray-400 border-gray-500/40';

        row.innerHTML = `
            <div class="w-16 px-4 py-2 font-mono text-gray-500 text-xs">${packetNumber}</div>
            <div class="w-24 px-4 py-2 font-mono text-gray-400">${time}</div>
            <div class="flex-1 px-4 py-2 font-mono text-primary truncate">
                ${packet.src_ip && packet.src_ip !== '—' ?
                `<span class="cursor-pointer hover:text-white hover:underline transition-colors" 
                  onclick="window.SentinelsShowIPDetails && window.SentinelsShowIPDetails('${packet.src_ip}')"
                  title="Deep Dive Source IP">${packet.src_ip}</span>` : '—'}
            </div>
            <div class="flex-1 px-4 py-2 font-mono text-white truncate">
                ${packet.dst_ip && packet.dst_ip !== '—' ?
                `<span class="cursor-pointer hover:text-primary hover:underline transition-colors" 
                  onclick="window.SentinelsShowIPDetails && window.SentinelsShowIPDetails('${packet.dst_ip}')"
                  title="Deep Dive Destination IP">${packet.dst_ip}</span>` : '—'}
            </div>
            <div class="w-20 px-4 py-2">
                <span class="px-2 py-0.5 rounded text-xs font-bold border ${protocolClass}">${packet.protocol || '?'}</span>
            </div>
            <div class="w-20 px-4 py-2 font-mono text-gray-400 text-xs">${packet.len || 0}</div>
            <div class="flex-1 px-4 py-2">${status}</div>
            <div class="w-16 px-4 py-2 text-center">
                <button class="view-btn text-gray-400 hover:text-primary transition-colors" title="View Details" data-packet-id="${packet.id}">
                    <span class="material-symbols-outlined text-[18px]">visibility</span>
                </button>
            </div>
        `;

        return row;
    }

    // ===== Filtering =====
    function getFilteredPackets() {
        const protocolFilter = elements.protocolFilter?.value || 'all';
        const ipSearch = (elements.ipSearch?.value || '').trim().toLowerCase();

        return state.packets.filter(packet => {
            if (protocolFilter !== 'all' && packet.protocol !== protocolFilter) {
                return false;
            }
            if (ipSearch &&
                !packet.src_ip?.toLowerCase().includes(ipSearch) &&
                !packet.dst_ip?.toLowerCase().includes(ipSearch)) {
                return false;
            }
            return true;
        });
    }

    // Filter change handlers
    elements.protocolFilter?.addEventListener('change', renderVirtualList);
    elements.ipSearch?.addEventListener('input', debounce(renderVirtualList, 300));

    // ===== Scroll Handler with Smart Auto-Scroll Detection =====
    elements.container?.addEventListener('scroll', () => {
        const container = elements.container;
        const scrollTop = container.scrollTop;

        // User is "at bottom" (viewing newest) when scrollTop is near 0 (within 20px)
        // Because newest packets are at the TOP of the virtual list
        const wasAtBottom = state.isUserAtBottom;
        state.isUserAtBottom = scrollTop <= 20;

        // If user just scrolled back to top (newest), clear badge and re-render
        if (!wasAtBottom && state.isUserAtBottom && state.newPacketCount > 0) {
            state.newPacketCount = 0;
            updateNewPacketsBadge();
            renderVirtualList();  // Refresh to show new packets
        } else {
            requestAnimationFrame(renderVirtualList);
        }
    });

    // ===== Event Delegation for View Buttons (NO CLOSURES!) =====
    // Single listener handles ALL row clicks - no memory leak
    elements.viewport?.addEventListener('click', (e) => {
        const viewBtn = e.target.closest('.view-btn');
        if (viewBtn) {
            const packetId = parseInt(viewBtn.dataset.packetId, 10);
            // Find packet by ID from state
            const packet = state.packets.find(p => p.id === packetId);
            if (packet) {
                showPacketDetails(packet);
            }
        }
    });

    // ===== Modal Management =====
    async function showPacketDetails(packet) {
        // Show modal immediately with lightweight data
        elements.modalSrcIp.textContent = packet.src_ip || '—';
        elements.modalDstIp.textContent = packet.dst_ip || '—';
        elements.modalProtocol.textContent = packet.protocol || '—';
        elements.modalLength.textContent = `${packet.len || 0} bytes`;
        elements.modalTimestamp.textContent = packet.timestamp || '—';
        elements.modalPorts.textContent = '—';
        elements.modalPayload.textContent = 'Loading...';
        elements.modal.classList.remove('hidden');

        // Fetch full details on-demand (includes payload)
        if (packet.id) {
            try {
                const res = await fetch(`/api/packet/${packet.id}`);
                const data = await res.json();
                if (data.success && data.packet) {
                    const full = data.packet;
                    elements.modalPorts.textContent = full.src_port && full.dst_port
                        ? `${full.src_port} → ${full.dst_port}`
                        : '—';
                    elements.modalPayload.textContent = full.payload || 'No payload data';
                }
            } catch (e) {
                elements.modalPayload.textContent = 'Error loading packet details';
            }
        }
    }

    function hideModal() {
        elements.modal.classList.add('hidden');
    }

    elements.closeModalBtn?.addEventListener('click', hideModal);
    elements.modal?.addEventListener('click', (e) => {
        if (e.target === elements.modal) hideModal();
    });
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') hideModal();
    });

    // ===== Control Buttons =====
    elements.localPauseBtn?.addEventListener('click', () => {
        state.localPaused = !state.localPaused;
        elements.localPauseBtn.innerHTML = state.localPaused
            ? '<span class="material-symbols-outlined text-sm">play_arrow</span><span class="hidden sm:inline">Resume</span>'
            : '<span class="material-symbols-outlined text-sm">pause</span><span class="hidden sm:inline">Pause</span>';
        elements.localPauseBtn.classList.toggle('bg-primary', state.localPaused);
        elements.localPauseBtn.classList.toggle('text-black', state.localPaused);
        updateStatusIndicator();
    });

    elements.clearTableBtn?.addEventListener('click', () => {
        state.packets = [];
        state.packetCount = 0;
        elements.packetCount.textContent = '0';
        renderVirtualList();
    });

    // ===== Status Indicator =====
    function updateStatusIndicator() {
        const isPaused = state.localPaused || state.globalPaused;
        elements.statusIndicator.innerHTML = isPaused
            ? `<span class="h-2 w-2 rounded-full bg-danger"></span>
               <span class="text-danger text-xs font-bold">PAUSED</span>`
            : `<span class="relative flex h-2 w-2">
                   <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75"></span>
                   <span class="relative inline-flex rounded-full h-2 w-2 bg-primary"></span>
               </span>
               <span class="text-primary text-xs font-bold">LIVE</span>`;
    }

    // ===== Packets Per Second =====
    setInterval(() => {
        state.packetsPerSecond = state.lastSecondCount;
        state.lastSecondCount = 0;
        elements.packetRate.textContent = `${state.packetsPerSecond}/s`;
    }, 1000);

    // ===== Utility Functions =====
    function formatNumber(num) {
        if (num >= 1000000) return (num / 1000000).toFixed(2) + 'M';
        if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
        return num.toString();
    }

    function debounce(func, wait) {
        let timeout;
        return function (...args) {
            clearTimeout(timeout);
            timeout = setTimeout(() => func.apply(this, args), wait);
        };
    }

    // ===== New Packets Badge (Floating Button) =====
    // Create floating badge for "New Packets" notification
    const newPacketsBadge = document.createElement('button');
    newPacketsBadge.id = 'newPacketsBadge';
    newPacketsBadge.className = 'fixed bottom-24 right-8 z-40 hidden items-center gap-2 px-4 py-2 bg-primary text-black font-bold rounded-full shadow-lg hover:bg-white transition-all cursor-pointer animate-bounce';
    newPacketsBadge.innerHTML = `
        <span class="material-symbols-outlined text-sm">arrow_upward</span>
        <span id="newPacketsCount">0</span> New Packets
    `;
    document.body.appendChild(newPacketsBadge);

    // Click handler - jump back to live (top)
    newPacketsBadge.addEventListener('click', () => {
        if (elements.container) {
            elements.container.scrollTop = 0;  // Scroll to top (newest)
        }
        state.isUserAtBottom = true;
        state.newPacketCount = 0;
        updateNewPacketsBadge();
        renderVirtualList();
    });

    function updateNewPacketsBadge() {
        const badge = document.getElementById('newPacketsBadge');
        const countEl = document.getElementById('newPacketsCount');

        if (state.newPacketCount > 0 && !state.isUserAtBottom) {
            badge.classList.remove('hidden');
            badge.classList.add('flex');
            countEl.textContent = formatNumber(state.newPacketCount);
        } else {
            badge.classList.add('hidden');
            badge.classList.remove('flex');
        }
    }
});
