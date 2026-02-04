/**
 * Sentinels Network Traffic Analyzer
 * Real-time dashboard with SocketIO and Chart.js
 */

document.addEventListener('DOMContentLoaded', () => {
    // ===== State Management =====
    const state = {
        totalPackets: 0,
        threatCount: 0,
        activeIPs: new Set(),
        protocolCounts: { TCP: 0, UDP: 0, ICMP: 0, OTHER: 0 },
        packetsPerSecond: 0,
        lastSecondPackets: 0,
        isPaused: false,
        monitoringActive: false,
        // Global batching & deduplication
        packetBuffer: [],        // Holding buffer for "The Dam"
        packetIds: new Set()     // O(1) deduplication
    };

    // ===== DOM Elements =====
    const elements = {
        totalPackets: document.getElementById('total-packets'),
        threatCount: document.getElementById('threat-count'),
        threatStatus: document.getElementById('threat-status'),
        threatIcon: document.getElementById('threat-icon'),
        activeIPs: document.getElementById('active-ips'),
        topProtocol: document.getElementById('top-protocol'),
        protocolPercent: document.getElementById('protocol-percent'),
        packetsRate: document.getElementById('packets-rate'),
        connectionStatus: document.getElementById('connection-status'),
        tableBody: document.getElementById('packet-table-body'),
        emptyState: document.getElementById('empty-state'),
        tcpPercent: document.getElementById('tcp-percent'),
        udpPercent: document.getElementById('udp-percent'),
        icmpPercent: document.getElementById('icmp-percent'),
        otherPercent: document.getElementById('other-percent'),
        btnClearChart: document.getElementById('btn-clear-chart'),
        btnPauseChart: document.getElementById('btn-pause-chart'),
        liveIndicator: document.getElementById('live-indicator')
    };

    // ===== Load Dashboard History from API =====
    fetch('/api/packets?limit=20')
        .then(res => res.json())
        .then(data => {
            if (data.success && data.packets.length > 0) {
                // Render in reverse order (oldest first so newest ends up at top)
                data.packets.slice().reverse().forEach(packet => renderRow(packet));
            }
        })
        .catch(e => console.error("Error loading history:", e));

    // ===== Chart.js Setup =====
    const chartColors = {
        primary: '#0df269',
        primaryDim: 'rgba(13, 242, 105, 0.1)',
        danger: '#ff2a2a',
        blue: '#3b82f6',
        purple: '#a855f7',
        gray: '#555'
    };

    // Traffic Line Chart
    const trafficCtx = document.getElementById('trafficChart').getContext('2d');
    const trafficChart = new Chart(trafficCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Packet Size (bytes)',
                data: [],
                borderColor: chartColors.primary,
                backgroundColor: chartColors.primaryDim,
                fill: true,
                tension: 0.4,
                pointRadius: 0,
                pointHoverRadius: 6,
                pointHoverBackgroundColor: chartColors.primary,
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 0 },
            interaction: { intersect: false, mode: 'index' },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: '#1a1a1a',
                    titleColor: '#0df269',
                    bodyColor: '#fff',
                    borderColor: '#333',
                    borderWidth: 1
                }
            },
            scales: {
                x: {
                    display: true,
                    grid: { color: '#333', drawBorder: false },
                    ticks: { color: '#666', maxTicksLimit: 8, font: { family: 'Space Grotesk' } }
                },
                y: {
                    display: true,
                    grid: { color: '#333', drawBorder: false },
                    ticks: { color: '#666', font: { family: 'Space Grotesk' } },
                    beginAtZero: true
                }
            }
        }
    });

    // Protocol Doughnut Chart
    const protocolCtx = document.getElementById('protocolChart').getContext('2d');
    const protocolChart = new Chart(protocolCtx, {
        type: 'doughnut',
        data: {
            labels: ['TCP', 'UDP', 'ICMP', 'OTHER'],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: [chartColors.primary, chartColors.blue, chartColors.purple, chartColors.gray],
                borderColor: '#1a1a1a',
                borderWidth: 3,
                hoverOffset: 10
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            cutout: '70%',
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: '#1a1a1a',
                    titleColor: '#0df269',
                    bodyColor: '#fff',
                    borderColor: '#333',
                    borderWidth: 1
                }
            }
        }
    });

    // ===== Top Talkers Chart (Horizontal Bar) =====
    const topTalkersCtx = document.getElementById('topTalkersChart');
    let topTalkersChart = null;

    if (topTalkersCtx) {
        topTalkersChart = new Chart(topTalkersCtx.getContext('2d'), {
            type: 'bar',
            data: {
                labels: ['No data yet'],
                datasets: [{
                    label: 'Packets',
                    data: [0],
                    backgroundColor: [
                        chartColors.primary,
                        chartColors.blue,
                        chartColors.purple,
                        '#f59e0b',  // Amber
                        '#06b6d4'   // Cyan
                    ],
                    borderRadius: 4,
                    borderSkipped: false
                }]
            },
            options: {
                indexAxis: 'y',  // Horizontal bar
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: 300 },
                onClick: (event, elements) => {
                    if (elements.length > 0) {
                        const index = elements[0].index;
                        // Get the IP from the top 5 list
                        const entries = Object.entries(srcIpCounts);
                        entries.sort((a, b) => b[1] - a[1]);
                        const top5 = entries.slice(0, 5);
                        if (top5[index]) {
                            const ip = top5[index][0];
                            showIPDetails(ip);
                        }
                    }
                },
                onHover: (event, elements) => {
                    event.native.target.style.cursor = elements.length > 0 ? 'pointer' : 'default';
                },
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: '#1a1a1a',
                        titleColor: '#0df269',
                        bodyColor: '#fff',
                        borderColor: '#333',
                        borderWidth: 1,
                        callbacks: {
                            afterLabel: (context) => 'Click for Deep Dive'
                        }
                    }
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(255,255,255,0.05)' },
                        ticks: { color: '#888' }
                    },
                    y: {
                        grid: { display: false },
                        ticks: {
                            color: '#fff',
                            font: { family: 'monospace', size: 11 }
                        }
                    }
                }
            }
        });
    }

    // IP Resolution State
    const resolvedNames = {};  // Cache: {ip: 'name'}
    const pendingResolutions = new Set();  // IPs currently being resolved
    const srcIpCounts = {};  // Aggregated counts: {ip: count}
    let topTalkersLastUpdate = 0;

    // ===== SocketIO Connection =====
    const socket = io();

    socket.on('connect', () => {
        console.log('[Sentinels] Connected to server');
        elements.connectionStatus.innerHTML = '● Online';
        elements.connectionStatus.className = 'text-xs text-primary';
    });

    socket.on('disconnect', () => {
        console.log('[Sentinels] Disconnected from server');
        elements.connectionStatus.innerHTML = '● Offline';
        elements.connectionStatus.className = 'text-xs text-danger';
    });

    socket.on('status', (data) => {
        console.log('[Sentinels] Status:', data.message);
    });

    // Handle IP resolution responses
    socket.on('ip_resolved', (data) => {
        if (data.ip && data.name) {
            resolvedNames[data.ip] = data.name;
            pendingResolutions.delete(data.ip);
            // Trigger immediate chart refresh on resolution
            updateTopTalkers(true);
        } else if (data.ip) {
            pendingResolutions.delete(data.ip);
        }

        // Hide loading indicator when all resolved
        if (pendingResolutions.size === 0) {
            const loader = document.getElementById('topTalkersLoading');
            if (loader) loader.classList.add('hidden');
        }
    });

    // ===== Threat Alert Handler (Heuristic Detection) =====
    const geoCache = {};  // Cache for geo-location data

    socket.on('threat_alert', (threat) => {
        console.log('[Sentinels] Threat detected:', threat);

        // Update threat counter
        state.threatCount++;
        if (elements.threatCount) {
            elements.threatCount.textContent = state.threatCount;
        }

        // Flash animation on threat card
        const threatCard = document.querySelector('[data-card="threats"]');
        if (threatCard) {
            threatCard.classList.add('ring-2', 'ring-danger', 'animate-pulse');
            setTimeout(() => {
                threatCard.classList.remove('ring-2', 'ring-danger', 'animate-pulse');
            }, 1000);
        }

        // Update threat status
        if (elements.threatStatus) {
            elements.threatStatus.textContent = threat.severity || 'ALERT';
        }

        // Show toast notification for high severity threats
        if (threat.severity === 'High' || threat.severity === 'Critical') {
            window.SentinelsGlobal?.showToast(
                `${threat.type}: ${threat.ip} (${threat.location || 'Unknown'})`,
                'error'
            );
        }
    });

    // Geo-location resolution response
    socket.on('geo_resolved', (data) => {
        if (data.ip) {
            geoCache[data.ip] = {
                country: data.country,
                city: data.city,
                flag: data.flag
            };
        }
    });

    // ===== Server-pushed Top Talkers (Backend Persistence) =====
    socket.on('update_top_talkers', (data) => {
        if (!topTalkersChart || !Array.isArray(data)) return;

        if (data.length === 0) {
            topTalkersChart.data.labels = ['No data yet'];
            topTalkersChart.data.datasets[0].data = [0];
            topTalkersChart.update('none');
            return;
        }

        // Update srcIpCounts from server data (for Deep Dive)
        data.forEach(item => {
            srcIpCounts[item.ip] = item.count;
        });

        // Build labels with resolved names
        const labels = [];
        const counts = [];

        for (const item of data) {
            const name = resolvedNames[item.ip];

            // Request resolution for unresolved IPs
            if (name === undefined && !pendingResolutions.has(item.ip)) {
                pendingResolutions.add(item.ip);
                socket.emit('resolve_ip', { ip: item.ip });
            }

            let label = name
                ? `${name} (${item.ip.length > 15 ? item.ip.slice(0, 12) + '...' : item.ip})`
                : item.ip;

            labels.push(label);
            counts.push(item.count);
        }

        topTalkersChart.data.labels = labels;
        topTalkersChart.data.datasets[0].data = counts;
        topTalkersChart.update('none');
    });

    // ===== Connection Inspector Logic =====
    const inspector = document.getElementById('connectionInspector');
    const backdrop = document.getElementById('inspectorBackdrop');
    const viewIpsBtn = document.getElementById('viewIpsBtn');
    const closeInspectorBtn = document.getElementById('closeInspector');

    function isPrivateIP(ip) {
        if (!ip) return false;
        // IPv4 private ranges
        if (ip.startsWith('192.168.') || ip.startsWith('10.') ||
            ip.startsWith('172.16.') || ip.startsWith('172.17.') ||
            ip.startsWith('172.18.') || ip.startsWith('172.19.') ||
            ip.startsWith('172.2') || ip.startsWith('172.30.') ||
            ip.startsWith('172.31.')) return true;
        // IPv6 link-local
        if (ip.toLowerCase().startsWith('fe80:')) return true;
        // Loopback
        if (ip === '127.0.0.1' || ip === '::1') return true;
        return false;
    }

    function openConnectionInspector() {
        if (!inspector) return;
        inspector.classList.remove('translate-x-full');
        inspector.dataset.open = 'true';
        if (backdrop) backdrop.classList.remove('hidden');

        // Request all connections
        socket.emit('get_all_connections');
    }

    function closeConnectionInspector() {
        if (!inspector) return;
        inspector.classList.add('translate-x-full');
        inspector.dataset.open = 'false';
        if (backdrop) backdrop.classList.add('hidden');
    }

    if (viewIpsBtn) {
        viewIpsBtn.addEventListener('click', openConnectionInspector);
    }

    if (closeInspectorBtn) {
        closeInspectorBtn.addEventListener('click', closeConnectionInspector);
    }

    if (backdrop) {
        backdrop.addEventListener('click', closeConnectionInspector);
    }

    // Handle connection data from server
    socket.on('all_connections_data', (connections) => {
        const tbody = document.getElementById('connectionTableBody');
        const totalEl = document.getElementById('inspectorTotalIPs');

        if (!tbody) return;

        if (!connections || connections.length === 0) {
            tbody.innerHTML = `
                <tr class="text-center">
                    <td colspan="2" class="py-8 text-gray-500">
                        <span class="material-symbols-outlined text-2xl">cloud_off</span>
                        <p class="mt-2">No connections yet</p>
                    </td>
                </tr>
            `;
            if (totalEl) totalEl.textContent = '0';
            return;
        }

        if (totalEl) totalEl.textContent = connections.length.toLocaleString();

        tbody.innerHTML = connections.map(conn => {
            // Use server-provided geo data (cached, no API calls)
            const geo = conn.geo || {};
            const flag = geo.flag || '🌐';
            const country = geo.country || 'Unknown';
            const city = geo.city || 'Unknown';
            const isLAN = country === 'LAN';
            const typeClass = isLAN ? 'text-primary' : 'text-blue-400';
            const tooltip = isLAN ? 'Local Network' : `${city}, ${country}`;

            return `
                <tr class="border-b border-[#333] hover:bg-white/5 transition-colors cursor-pointer"
                    onclick="window.SentinelsShowIPDetails && window.SentinelsShowIPDetails('${conn.ip}')">
                    <td class="py-2 px-4">
                        <div class="flex items-center gap-2">
                            <span title="${tooltip}" class="cursor-help">${flag}</span>
                            <span class="font-mono text-sm ${typeClass}">${conn.ip}</span>
                        </div>
                    </td>
                </tr>
            `;
        }).join('');
    });

    // Handle initial stats on connect (persists counters across page refreshes)
    socket.on('init_stats', (data) => {
        console.log('[Sentinels] Init stats:', data);
        state.totalPackets = data.total_packets || 0;
        state.threatCount = data.threat_count || 0;

        // Sync active IPs count from server
        if (data.active_ips !== undefined) {
            // Clear local set and update counter directly from server
            state.activeIPs.clear();
            elements.activeIPs.textContent = data.active_ips;
        }

        // Sync monitoring status
        if (data.monitoring_active !== undefined) {
            updateMonitoringUI(data.monitoring_active);
        }

        // Sync protocol stats from server
        if (data.protocol_stats) {
            state.protocolCounts.TCP = data.protocol_stats.TCP || 0;
            state.protocolCounts.UDP = data.protocol_stats.UDP || 0;
            state.protocolCounts.ICMP = data.protocol_stats.ICMP || 0;
            state.protocolCounts.OTHER = data.protocol_stats.Other || 0;

            // Update protocol chart
            protocolChart.data.datasets[0].data = [
                state.protocolCounts.TCP,
                state.protocolCounts.UDP,
                state.protocolCounts.ICMP,
                state.protocolCounts.OTHER
            ];
            protocolChart.update();
            updateProtocolChart();
        }

        updateCounters();
    });

    // ===== Handle New Packet (Buffered - "The Dam") =====
    socket.on('new_packet', (packet) => {
        if (state.isPaused) return;

        // Deduplication check (O(1) lookup)
        if (packet.id && state.packetIds.has(packet.id)) {
            return; // Skip duplicate
        }

        // Add to holding buffer (will be flushed by interval)
        state.packetBuffer.push(packet);
    });

    // ===== Global Batch Flush (\"The Dam\" releases every 100ms) =====
    setInterval(() => {
        if (state.packetBuffer.length === 0) return;

        // Grab all buffered packets
        const batch = state.packetBuffer.splice(0);

        for (const packet of batch) {
            // Track ID for deduplication
            if (packet.id) {
                state.packetIds.add(packet.id);
            }

            // Update counters
            state.totalPackets++;
            state.lastSecondPackets++;

            // Track unique IPs
            if (packet.src_ip) state.activeIPs.add(packet.src_ip);
            if (packet.dst_ip) state.activeIPs.add(packet.dst_ip);

            // Track protocols
            const protocol = (packet.protocol || 'OTHER').toUpperCase();
            if (state.protocolCounts.hasOwnProperty(protocol)) {
                state.protocolCounts[protocol]++;
            } else {
                state.protocolCounts.OTHER++;
            }

            // Track threats
            if (packet.is_threat) {
                state.threatCount++;
            }

            // Track src_ip counts for Top Talkers
            if (packet.src_ip) {
                srcIpCounts[packet.src_ip] = (srcIpCounts[packet.src_ip] || 0) + 1;
            }

            // Add to table (newest at top)
            renderRow(packet);
        }

        // Update UI ONCE per batch (not per packet)
        if (batch.some(p => p.is_threat)) {
            flashThreatCard();
        }
        updateCounters();
        updateProtocolChart();
        updateTrafficChart(batch[batch.length - 1]); // Latest packet for chart

        // Update Top Talkers (throttled internally)
        updateTopTalkers();

        // Limit deduplication set size (memory management)
        if (state.packetIds.size > 100000) {
            const idsArray = Array.from(state.packetIds);
            state.packetIds = new Set(idsArray.slice(-50000));
        }
    }, 100);  // 10 FPS = responsive and smooth

    // ===== UI Update Functions =====
    // ===== Modal Logic =====
    async function openModal(packet) {
        if (!window.SentinelsGlobal || !window.SentinelsGlobal.showModal) {
            return;
        }

        const isThreat = packet.is_threat || false;
        const protoClass = isThreat ? 'text-danger font-bold' : 'text-white font-bold';

        // Show modal immediately with lightweight data (payload loading)
        let htmlContent = `
            <div class="grid grid-cols-2 gap-6 mb-6">
                <div class="bg-[#111] p-3 rounded border border-[#333]">
                    <span class="text-xs text-gray-500 uppercase block mb-1">Timestamp</span>
                    <div class="text-primary font-mono text-sm">${new Date(packet.timestamp || Date.now()).toLocaleTimeString('en-US')}</div>
                </div>
                <div class="bg-[#111] p-3 rounded border border-[#333]">
                    <span class="text-xs text-gray-500 uppercase block mb-1">Protocol</span>
                    <div class="${protoClass} text-sm">${packet.protocol || 'UNKNOWN'}</div>
                </div>
                <div class="bg-[#111] p-3 rounded border border-[#333]">
                    <span class="text-xs text-gray-500 uppercase block mb-1">Source IP</span>
                    <div class="font-mono text-gray-300 text-sm">${packet.src_ip || '-'}</div>
                </div>
                <div class="bg-[#111] p-3 rounded border border-[#333]">
                    <span class="text-xs text-gray-500 uppercase block mb-1">Destination IP</span>
                    <div class="font-mono text-gray-300 text-sm">${packet.dst_ip || '-'}</div>
                </div>
            </div>
            
            <div class="bg-[#111] p-4 rounded border border-[#333]">
                <span class="text-xs text-gray-500 uppercase block mb-2">Payload Content</span>
                <div id="modal-payload-content" class="text-xs text-gray-300 font-mono break-all h-32 overflow-y-auto pr-2 custom-scrollbar">Loading...</div>
            </div>
        `;

        window.SentinelsGlobal.showModal('Packet Details', htmlContent, null);

        // Fetch full details on-demand (includes payload)
        if (packet.id) {
            try {
                const res = await fetch(`/api/packet/${packet.id}`);
                const data = await res.json();
                const payloadEl = document.getElementById('modal-payload-content');
                if (data.success && data.packet && payloadEl) {
                    payloadEl.textContent = data.packet.payload || '(No payload data available)';
                }
            } catch (e) {
                const payloadEl = document.getElementById('modal-payload-content');
                if (payloadEl) payloadEl.textContent = 'Error loading payload';
            }
        }
    }

    function renderRow(packet) {
        const dbTable = document.getElementById('dashboardTableBody');
        if (dbTable) {
            const row = dbTable.insertRow(0);
            row.className = 'border-b border-[#333] hover:bg-white/5 transition-colors';

            // Time
            const c1 = row.insertCell(0);
            c1.className = "py-2 font-mono text-xs text-gray-400";
            c1.textContent = new Date(packet.timestamp || Date.now()).toLocaleTimeString('en-US', { hour12: false });

            // Source
            const c2 = row.insertCell(1);
            c2.className = "py-2 font-mono text-primary";
            c2.textContent = packet.src_ip || '-';

            // Destination
            const c3 = row.insertCell(2);
            c3.className = "py-2 font-mono text-white";
            c3.textContent = packet.dst_ip || '-';

            // Protocol
            const c4 = row.insertCell(3);
            c4.className = "py-2";
            c4.textContent = packet.protocol || '-';

            // Status
            const c5 = row.insertCell(4);
            c5.className = "py-2";
            if (packet.is_threat) {
                c5.innerHTML = '<span class="text-xs font-bold text-red-400">● THREAT</span>';
                row.classList.add('bg-red-900/10');
            } else {
                c5.innerHTML = '<span class="text-xs text-gray-500">Normal</span>';
            }

            // Actions
            const c6 = row.insertCell(5);
            c6.className = "py-2 text-right";
            const btn = document.createElement('button');
            btn.innerHTML = '<span class="material-symbols-outlined text-[20px]">visibility</span>';
            btn.className = "text-gray-400 hover:text-primary transition-colors bg-transparent border-none cursor-pointer p-0 flex items-center ml-auto";
            btn.title = "View Details";
            btn.onclick = () => openModal(packet);
            c6.appendChild(btn);

            // Limit to 20 rows
            while (dbTable.rows.length > 20) {
                dbTable.deleteRow(-1);
            }
        }
    }

    // ===== Top Talkers Update (Throttled to 1s) =====
    function updateTopTalkers(force = false) {
        if (!topTalkersChart) return;

        const now = Date.now();

        // Throttle: only update once per second unless forced
        if (!force && now - topTalkersLastUpdate < 1000) return;
        topTalkersLastUpdate = now;

        // Get all IPs and counts
        const entries = Object.entries(srcIpCounts);

        if (entries.length === 0) {
            topTalkersChart.data.labels = ['No data yet'];
            topTalkersChart.data.datasets[0].data = [0];
            topTalkersChart.update('none');
            return;
        }

        // Sort by count (descending) and take top 5
        entries.sort((a, b) => b[1] - a[1]);
        const top5 = entries.slice(0, 5);

        // Build labels with resolved names
        const labels = [];
        const data = [];
        let needsResolution = false;

        for (const [ip, count] of top5) {
            const name = resolvedNames[ip];

            // Lazy resolution: request resolution only for Top 5 IPs
            if (name === undefined && !pendingResolutions.has(ip)) {
                pendingResolutions.add(ip);
                socket.emit('resolve_ip', { ip });
                needsResolution = true;
            }

            // Format label: "Name (123...)" or just IP if no name
            let label;
            if (name) {
                // Shorten IP for display
                const shortIp = ip.length > 15 ? ip.slice(0, 12) + '...' : ip;
                label = `${name} (${shortIp})`;
            } else {
                label = ip;
            }

            labels.push(label);
            data.push(count);
        }

        // Show loading indicator if resolving
        if (needsResolution) {
            const loader = document.getElementById('topTalkersLoading');
            if (loader) loader.classList.remove('hidden');
        }

        // Update chart data
        topTalkersChart.data.labels = labels;
        topTalkersChart.data.datasets[0].data = data;
        topTalkersChart.update('none');  // 'none' = no animation for performance
    }

    // ===== Deep Dive Modal for IP Details =====
    function showIPDetails(ip) {
        // Get resolved name if available
        const name = resolvedNames[ip] || ip;
        const totalPackets = srcIpCounts[ip] || 0;

        // Trigger geo lookup to populate cache (for Connection Inspector)
        socket.emit('resolve_geo', { ip: ip });

        // We need to fetch packet details from API for protocol breakdown
        // Using the in-memory srcIpCounts for count, fetch protocol breakdown from API
        fetch(`/api/packets?limit=50000`)
            .then(res => res.json())
            .then(data => {
                if (!data.success || !data.packets) {
                    showIPDetailsModal(ip, name, totalPackets, {}, [], null);
                    return;
                }

                // Filter packets for this IP
                const ipPackets = data.packets.filter(p => p.src_ip === ip);

                // Calculate protocol breakdown
                const protocolCounts = {};
                const destIpCounts = {};

                for (const pkt of ipPackets) {
                    const proto = (pkt.protocol || 'OTHER').toUpperCase();
                    protocolCounts[proto] = (protocolCounts[proto] || 0) + 1;

                    if (pkt.dst_ip) {
                        destIpCounts[pkt.dst_ip] = (destIpCounts[pkt.dst_ip] || 0) + 1;
                    }
                }

                // Get top 3 destinations
                const topDests = Object.entries(destIpCounts)
                    .sort((a, b) => b[1] - a[1])
                    .slice(0, 3);

                // Get cached geo info
                const geo = geoCache[ip] || null;

                showIPDetailsModal(ip, name, ipPackets.length, protocolCounts, topDests, geo);
            })
            .catch(err => {
                console.error('Error fetching packet data:', err);
                showIPDetailsModal(ip, name, totalPackets, {}, [], null);
            });
    }

    function showIPDetailsModal(ip, name, totalPackets, protocolCounts, topDests, geo) {
        // Calculate percentages
        const total = Object.values(protocolCounts).reduce((a, b) => a + b, 0) || 1;
        const protocolBars = Object.entries(protocolCounts)
            .sort((a, b) => b[1] - a[1])
            .map(([proto, count]) => {
                const pct = ((count / total) * 100).toFixed(1);
                const color = proto === 'TCP' ? '#0df269'
                    : proto === 'UDP' ? '#3b82f6'
                        : proto === 'ICMP' ? '#a855f7'
                            : proto === 'ICMPV6' ? '#f59e0b'
                                : '#555';
                return `
                    <div class="flex items-center gap-2 mb-2">
                        <span class="w-16 text-xs text-gray-400">${proto}</span>
                        <div class="flex-1 bg-[#222] rounded-full h-3 overflow-hidden">
                            <div class="h-full rounded-full" style="width: ${pct}%; background: ${color}"></div>
                        </div>
                        <span class="w-16 text-xs text-gray-300 text-right">${pct}%</span>
                    </div>
                `;
            }).join('');

        // Top destinations
        const destHtml = topDests.length > 0
            ? topDests.map(([dstIp, count]) => `
                <div class="flex justify-between text-xs py-1">
                    <span class="font-mono text-gray-300">${dstIp}</span>
                    <span class="text-primary">${count} pkts</span>
                </div>
            `).join('')
            : '<p class="text-gray-500 text-xs">No destination data</p>';

        // Geo location display
        const geoHtml = geo
            ? `<div class="bg-[#111] p-3 rounded border border-[#333]">
                    <span class="text-xs text-gray-500 uppercase block mb-1">Location</span>
                    <div class="text-white text-sm flex items-center gap-2">
                        <span class="text-lg">${geo.flag || '🌐'}</span>
                        <span>${geo.city || 'Unknown'}, ${geo.country || 'Unknown'}</span>
                    </div>
                </div>`
            : '';

        const htmlContent = `
            <div class="space-y-4">
                <div class="grid grid-cols-2 gap-4">
                    <div class="bg-[#111] p-3 rounded border border-[#333]">
                        <span class="text-xs text-gray-500 uppercase block mb-1">IP Address</span>
                        <div class="text-primary font-mono text-sm">${ip}</div>
                    </div>
                    <div class="bg-[#111] p-3 rounded border border-[#333]">
                        <span class="text-xs text-gray-500 uppercase block mb-1">Total Packets</span>
                        <div class="text-white font-bold text-lg">${totalPackets.toLocaleString()}</div>
                    </div>
                </div>
                
                ${geoHtml}
                
                <div class="bg-[#111] p-4 rounded border border-[#333]">
                    <span class="text-xs text-gray-500 uppercase block mb-3">Protocol Breakdown</span>
                    ${protocolBars || '<p class="text-gray-500 text-xs">No protocol data</p>'}
                </div>
                
                <div class="bg-[#111] p-4 rounded border border-[#333]">
                    <span class="text-xs text-gray-500 uppercase block mb-2">Top Destinations</span>
                    ${destHtml}
                </div>
            </div>
        `;

        const title = name !== ip ? `Deep Dive: ${name}` : `Deep Dive: ${ip}`;
        window.SentinelsGlobal.showModal(title, htmlContent, null);
    }

    function updateCounters() {
        elements.totalPackets.textContent = formatNumber(state.totalPackets);
        elements.threatCount.textContent = state.threatCount;
        elements.activeIPs.textContent = state.activeIPs.size;

        // Update threat status
        if (state.threatCount > 0) {
            elements.threatStatus.textContent = 'CRITICAL';
            elements.threatIcon.classList.add('animate-pulse');
        }

        // Find top protocol
        const topProto = Object.entries(state.protocolCounts)
            .sort((a, b) => b[1] - a[1])[0];

        if (topProto && topProto[1] > 0) {
            elements.topProtocol.textContent = topProto[0];
            const percent = Math.round((topProto[1] / state.totalPackets) * 100);
            elements.protocolPercent.textContent = `${percent}%`;
        }
    }

    function updateProtocolChart() {
        const { TCP, UDP, ICMP, OTHER } = state.protocolCounts;
        const total = TCP + UDP + ICMP + OTHER;

        protocolChart.data.datasets[0].data = [TCP, UDP, ICMP, OTHER];
        protocolChart.update('none');

        // Update legend percentages
        if (total > 0) {
            elements.tcpPercent.textContent = `${Math.round((TCP / total) * 100)}%`;
            elements.udpPercent.textContent = `${Math.round((UDP / total) * 100)}%`;
            elements.icmpPercent.textContent = `${Math.round((ICMP / total) * 100)}%`;
            elements.otherPercent.textContent = `${Math.round((OTHER / total) * 100)}%`;
        }
    }

    function updateTrafficChart(packet) {
        const time = new Date(packet.timestamp).toLocaleTimeString();
        const size = packet.len || 0;

        trafficChart.data.labels.push(time);
        trafficChart.data.datasets[0].data.push(size);

        // Keep only last 50 data points
        if (trafficChart.data.labels.length > 50) {
            trafficChart.data.labels.shift();
            trafficChart.data.datasets[0].data.shift();
        }

        trafficChart.update('none');
    }

    function addTableRow(packet) {
        // Remove empty state if present
        if (elements.emptyState) {
            elements.emptyState.remove();
        }

        const row = document.createElement('tr');
        const isThreat = packet.threat;

        row.className = isThreat
            ? 'bg-danger/5 hover:bg-danger/10 transition-colors group'
            : 'hover:bg-white/5 transition-colors group';

        const time = new Date(packet.timestamp).toLocaleTimeString('en-US', {
            hour12: false,
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            fractionalSecondDigits: 3
        });

        const statusHtml = isThreat
            ? `<span class="flex items-center gap-2 text-danger text-xs font-bold uppercase">
                   <span class="material-symbols-outlined text-[14px]">warning</span> ${packet.threat_type || 'Threat'}
               </span>`
            : `<span class="flex items-center gap-2 text-primary text-xs font-bold uppercase">
                   <span class="size-1.5 rounded-full bg-primary"></span> Normal
               </span>`;

        const protocolClass = isThreat
            ? 'bg-danger/20 text-danger border-danger/40'
            : 'bg-[#333] text-gray-300 border-gray-600';

        row.innerHTML = `
            <td class="px-6 py-4 font-mono ${isThreat ? 'text-danger' : 'text-gray-400'} group-hover:text-primary">${time}</td>
            <td class="px-6 py-4 font-mono ${isThreat ? 'text-white font-bold' : 'text-gray-300'}">${packet.src_ip || '—'}</td>
            <td class="px-6 py-4 font-mono text-gray-300">${packet.dst_ip || '—'}</td>
            <td class="px-6 py-4">
                <span class="inline-flex items-center px-2 py-1 rounded text-xs font-bold ${protocolClass} border">${packet.protocol || '—'}</span>
            </td>
            <td class="px-6 py-4 font-mono text-gray-400">${packet.len || 0} B</td>
            <td class="px-6 py-4">${statusHtml}</td>
        `;

        // Prepend row (newest first)
        elements.tableBody.insertBefore(row, elements.tableBody.firstChild);

        // Limit to 20 rows
        while (elements.tableBody.children.length > 20) {
            elements.tableBody.removeChild(elements.tableBody.lastChild);
        }
    }

    function flashThreatCard() {
        const card = elements.threatCount.closest('.bg-surface');
        if (card) {
            card.classList.add('animate-pulse');
            setTimeout(() => card.classList.remove('animate-pulse'), 1000);
        }
    }

    // ===== Utility Functions =====
    function formatNumber(num) {
        if (num >= 1000000) return (num / 1000000).toFixed(2) + 'M';
        if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
        return num.toString();
    }

    function showToast(message, type = 'success') {
        // Create toast element
        const toast = document.createElement('div');
        toast.className = `fixed bottom-4 right-4 px-6 py-3 rounded-lg shadow-lg z-50 transition-all transform translate-y-0 ${type === 'success' ? 'bg-primary text-black' : 'bg-danger text-white'
            }`;
        toast.innerHTML = `<span class="font-bold">${message}</span>`;
        document.body.appendChild(toast);

        // Remove after 3 seconds
        setTimeout(() => {
            toast.classList.add('opacity-0', 'translate-y-4');
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }

    function resetLocalState() {
        // Reset all local state
        state.totalPackets = 0;
        state.threatCount = 0;
        state.activeIPs.clear();
        state.protocolCounts = { TCP: 0, UDP: 0, ICMP: 0, OTHER: 0 };
        state.packetsPerSecond = 0;
        state.lastSecondPackets = 0;
        state.monitoringActive = false;

        // Update UI
        updateCounters();
        updateProtocolChart();

        // Clear charts
        trafficChart.data.labels = [];
        trafficChart.data.datasets[0].data = [];
        trafficChart.update();

        protocolChart.data.datasets[0].data = [0, 0, 0, 0];
        protocolChart.update();

        // Clear table
        if (elements.tableBody) {
            elements.tableBody.innerHTML = `
                <tr id="empty-state">
                    <td colspan="6" class="px-6 py-12 text-center text-gray-500">
                        <span class="material-symbols-outlined text-4xl mb-2 block">hourglass_empty</span>
                        Waiting for packets...
                    </td>
                </tr>
            `;
        }
    }

    function updateMonitoringUI(isActive) {
        state.monitoringActive = isActive;

        const pauseBtn = document.getElementById('global-pause-btn');
        const statusText = document.getElementById('system-status-text');

        if (pauseBtn) {
            pauseBtn.innerHTML = isActive
                ? '<span class="material-symbols-outlined">pause</span>'
                : '<span class="material-symbols-outlined">play_arrow</span>';
            pauseBtn.title = isActive ? 'Pause Monitoring' : 'Start Monitoring';
        }

        if (statusText) {
            statusText.textContent = isActive ? 'Monitoring' : 'Paused';
            statusText.className = isActive ? 'text-primary font-bold' : 'text-danger font-bold';
        }

        // Update live indicator
        if (elements.liveIndicator) {
            elements.liveIndicator.classList.toggle('opacity-50', !isActive);
        }
    }

    // ===== Packets Per Second Counter =====
    setInterval(() => {
        state.packetsPerSecond = state.lastSecondPackets;
        state.lastSecondPackets = 0;

        const rateText = `${state.packetsPerSecond}/s`;

        // Update main rate display
        if (elements.packetsRate) {
            elements.packetsRate.textContent = rateText;
        }

        // Update card badge (if exists)
        const rateBadge = document.querySelector('.packets-rate-badge');
        if (rateBadge) {
            rateBadge.textContent = rateText;
        }
    }, 1000);

    // ===== Chart Control Buttons (optional - may be removed in UI cleanup) =====
    if (elements.btnClearChart) {
        elements.btnClearChart.addEventListener('click', () => {
            trafficChart.data.labels = [];
            trafficChart.data.datasets[0].data = [];
            trafficChart.update();
        });
    }

    if (elements.btnPauseChart) {
        elements.btnPauseChart.addEventListener('click', () => {
            state.isPaused = !state.isPaused;
            elements.btnPauseChart.textContent = state.isPaused ? 'Resume' : 'Pause';
            elements.btnPauseChart.classList.toggle('bg-danger', state.isPaused);
            elements.btnPauseChart.classList.toggle('text-white', state.isPaused);
            if (elements.liveIndicator) {
                elements.liveIndicator.classList.toggle('opacity-50', state.isPaused);
            }
        });
    }

    // ===== Global Monitoring Controls =====

    // Listen for monitoring status updates
    socket.on('monitoring_status', (data) => {
        updateMonitoringUI(data.active);
    });

    // Listen for session restart (button handler is in base.html with modal confirmation)
    socket.on('session_restarted', (data) => {
        // Clear dashboard table
        const tbody = document.getElementById('dashboardTableBody');
        if (tbody) tbody.innerHTML = '';

        resetLocalState();
        updateMonitoringUI(false);
    });

    // Global Pause/Play Button
    const globalPauseBtn = document.getElementById('global-pause-btn');
    if (globalPauseBtn) {
        globalPauseBtn.addEventListener('click', () => {
            const newState = !state.monitoringActive;
            socket.emit('toggle_monitoring', { target_state: newState });
        });
    }

    // ===== Expose showIPDetails globally for Connection Inspector =====
    window.SentinelsShowIPDetails = showIPDetails;

    console.log('[Sentinels] Dashboard initialized');
});
