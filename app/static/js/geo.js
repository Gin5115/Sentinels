/**
 * Sentinels - Geo IP World Map
 * D3.js world map with real-time IP connection plotting.
 * Circles: size = traffic volume, color = threat status (red) / clean (green)
 * Click circle or country row for detailed popup.
 */

// ===== State =====
let connections = [];
let projection, pathGen, svg, circlesGroup;
let worldLoaded = false;

const COLOR_CLEAN  = '#0df269';
const COLOR_THREAT = '#ff2a2a';

function radiusScale(packets, maxPackets) {
    if (!maxPackets || maxPackets === 0) return 4;
    return 3 + Math.sqrt(packets / maxPackets) * 11;
}

// ===== Map Initialisation =====
function initMap() {
    const container = document.getElementById('mapContainer');
    const W = container.clientWidth  || 900;
    const H = container.clientHeight || 580;

    svg = d3.select('#worldMap').attr('width', W).attr('height', H);

    projection = d3.geoNaturalEarth1()
        .scale(W / 2 / Math.PI * 0.95)
        .translate([W / 2, H / 2]);

    pathGen = d3.geoPath().projection(projection);

    svg.append('rect').attr('width', W).attr('height', H).attr('fill', '#0d0d0d');

    d3.json('/static/data/countries-110m.json').then(world => {
        worldLoaded = true;

        svg.insert('path', ':first-child')
            .datum(d3.geoGraticule()())
            .attr('fill', 'none').attr('stroke', '#1a1a1a').attr('stroke-width', 0.3)
            .attr('d', pathGen);

        svg.append('g').attr('class', 'countries')
            .selectAll('path')
            .data(topojson.feature(world, world.objects.countries).features)
            .join('path')
            .attr('d', pathGen)
            .attr('fill', '#1a1a1a')
            .attr('stroke', '#2a2a2a')
            .attr('stroke-width', 0.4);

        svg.append('path')
            .datum(topojson.mesh(world, world.objects.countries, (a, b) => a !== b))
            .attr('fill', 'none').attr('stroke', '#333').attr('stroke-width', 0.5)
            .attr('d', pathGen);

        circlesGroup = svg.append('g').attr('class', 'circles');

        if (connections.length > 0) updateMap();
    }).catch(err => console.error('[GeoMap] Failed to load world data:', err));
}

// ===== Tooltip helpers =====
function showTooltip(event, d) {
    const tooltip   = document.getElementById('mapTooltip');
    const [mx, my]  = d3.pointer(event, document.getElementById('mapContainer'));
    tooltip.style.left  = (mx + 14) + 'px';
    tooltip.style.top   = (my - 10) + 'px';
    tooltip.classList.remove('hidden');
    document.getElementById('ttIp').textContent      = d.ip;
    document.getElementById('ttCountry').textContent = (d.geo.flag || '') + ' ' + (d.geo.country || 'Unknown');
    document.getElementById('ttCity').textContent    = d.geo.city || '';
    document.getElementById('ttPackets').textContent = d.count.toLocaleString() + ' packets';
    const ttStatus = document.getElementById('ttStatus');
    ttStatus.textContent = d.is_threat ? '⚠ Threat Detected' : '✓ Clean';
    ttStatus.style.color = d.is_threat ? COLOR_THREAT : COLOR_CLEAN;
}
function hideTooltip() {
    document.getElementById('mapTooltip').classList.add('hidden');
}

// ===== Map Update =====
function updateMap() {
    if (!worldLoaded || !circlesGroup) return;

    const plotable = connections.filter(c => c.geo && c.geo.lat != null && c.geo.lon != null);
    const maxPkts  = d3.max(connections, d => d.count) || 1;

    const noData     = document.getElementById('mapNoData');
    const noDataText = document.getElementById('mapNoDataText');
    if (noData) {
        if (plotable.length > 0) {
            noData.style.display = 'none';
        } else {
            noData.style.display = '';
            noDataText.textContent = connections.length > 0
                ? 'Resolving IP locations... dots will appear for public IPs'
                : 'Start monitoring to see connections on the map';
        }
    }

    // Pulse rings
    circlesGroup.selectAll('.pulse-ring')
        .data(plotable, d => d.ip)
        .join(
            enter => enter.append('circle').attr('class', 'pulse-ring')
                .attr('cx', d => projection([d.geo.lon, d.geo.lat])[0])
                .attr('cy', d => projection([d.geo.lon, d.geo.lat])[1])
                .attr('r', 0).attr('fill', 'none')
                .attr('stroke', d => d.is_threat ? COLOR_THREAT : COLOR_CLEAN)
                .attr('stroke-width', 1).attr('stroke-opacity', 0)
                .call(e => e.transition().duration(800)
                    .attr('r', d => radiusScale(d.count, maxPkts) + 5)
                    .attr('stroke-opacity', 0.2)),
            update => update.transition().duration(600)
                .attr('cx', d => projection([d.geo.lon, d.geo.lat])[0])
                .attr('cy', d => projection([d.geo.lon, d.geo.lat])[1])
                .attr('r',  d => radiusScale(d.count, maxPkts) + 5)
                .attr('stroke', d => d.is_threat ? COLOR_THREAT : COLOR_CLEAN),
            exit => exit.transition().duration(300).attr('stroke-opacity', 0).remove()
        );

    // Main dots
    const applyDotHandlers = sel => sel
        .on('mousemove', showTooltip)
        .on('mouseleave', hideTooltip)
        .on('click', (_event, d) => {
            hideTooltip();
            showIPPopup(d);
        });

    circlesGroup.selectAll('.ip-dot')
        .data(plotable, d => d.ip)
        .join(
            enter => enter.append('circle').attr('class', 'ip-dot')
                .attr('cx', d => projection([d.geo.lon, d.geo.lat])[0])
                .attr('cy', d => projection([d.geo.lon, d.geo.lat])[1])
                .attr('r', 0)
                .attr('fill', d => d.is_threat ? COLOR_THREAT : COLOR_CLEAN)
                .attr('fill-opacity', 0.85)
                .attr('stroke', d => d.is_threat ? COLOR_THREAT : COLOR_CLEAN)
                .attr('stroke-width', 1.5).attr('stroke-opacity', 0.4)
                .style('cursor', 'pointer')
                .call(applyDotHandlers)
                .call(e => e.transition().duration(500).attr('r', d => radiusScale(d.count, maxPkts))),
            update => update
                .attr('fill',   d => d.is_threat ? COLOR_THREAT : COLOR_CLEAN)
                .attr('stroke', d => d.is_threat ? COLOR_THREAT : COLOR_CLEAN)
                .call(applyDotHandlers)
                .transition().duration(600)
                .attr('cx', d => projection([d.geo.lon, d.geo.lat])[0])
                .attr('cy', d => projection([d.geo.lon, d.geo.lat])[1])
                .attr('r',  d => radiusScale(d.count, maxPkts)),
            exit => exit.transition().duration(300).attr('r', 0).remove()
        );
}

// ===== Popup: single IP =====
function showIPPopup(d) {
    const geo    = d.geo || {};
    const threat = d.is_threat;
    const color  = threat ? COLOR_THREAT : COLOR_CLEAN;

    document.getElementById('popupTitle').textContent    = d.ip;
    document.getElementById('popupSubtitle').textContent = (geo.flag || '🌐') + ' ' + (geo.country || 'Unknown') + (geo.city ? ', ' + geo.city : '');

    document.getElementById('popupStats').innerHTML = `
        <div class="bg-surface p-4 text-center">
            <p class="text-gray-500 text-xs uppercase tracking-wider mb-1">Packets</p>
            <p class="text-white font-bold text-xl font-mono">${d.count.toLocaleString()}</p>
        </div>
        <div class="bg-surface p-4 text-center">
            <p class="text-gray-500 text-xs uppercase tracking-wider mb-1">Status</p>
            <p class="font-bold text-lg" style="color:${color}">${threat ? '⚠ THREAT' : '✓ CLEAN'}</p>
        </div>
        <div class="bg-surface p-4 text-center">
            <p class="text-gray-500 text-xs uppercase tracking-wider mb-1">Location</p>
            <p class="text-white text-sm font-medium">${esc(geo.city || geo.country || 'Unknown')}</p>
        </div>
    `;

    document.getElementById('popupBody').innerHTML = `
        <div class="p-5 space-y-3">
            <div class="flex justify-between py-2 border-b border-[#2a2a2a]">
                <span class="text-gray-500 text-sm">IP Address</span>
                <span class="text-white font-mono text-sm">${esc(d.ip)}</span>
            </div>
            <div class="flex justify-between py-2 border-b border-[#2a2a2a]">
                <span class="text-gray-500 text-sm">Country</span>
                <span class="text-white text-sm">${geo.flag || ''} ${esc(geo.country || 'Unknown')}</span>
            </div>
            <div class="flex justify-between py-2 border-b border-[#2a2a2a]">
                <span class="text-gray-500 text-sm">City</span>
                <span class="text-white text-sm">${esc(geo.city || '—')}</span>
            </div>
            <div class="flex justify-between py-2 border-b border-[#2a2a2a]">
                <span class="text-gray-500 text-sm">Coordinates</span>
                <span class="text-gray-400 font-mono text-xs">${geo.lat != null ? geo.lat.toFixed(3) + ', ' + geo.lon.toFixed(3) : '—'}</span>
            </div>
            <div class="flex justify-between py-2">
                <span class="text-gray-500 text-sm">Threat Status</span>
                <span class="font-bold text-sm" style="color:${color}">${threat ? '⚠ Flagged' : '✓ Clean'}</span>
            </div>
        </div>
    `;

    openGeoPopup();
}

// ===== Popup: country =====
function showCountryPopup(countryName) {
    const countryConns = connections.filter(c => (c.geo?.country || 'Unknown') === countryName);
    if (!countryConns.length) return;

    const flag        = countryConns[0].geo?.flag || '🌐';
    const totalPkts   = countryConns.reduce((s, c) => s + c.count, 0);
    const threatCount = countryConns.filter(c => c.is_threat).length;
    const sorted      = [...countryConns].sort((a, b) => b.count - a.count);

    document.getElementById('popupTitle').textContent    = flag + ' ' + countryName;
    document.getElementById('popupSubtitle').textContent = sorted.length + ' IP' + (sorted.length !== 1 ? 's' : '') + ' detected';

    document.getElementById('popupStats').innerHTML = `
        <div class="bg-surface p-4 text-center">
            <p class="text-gray-500 text-xs uppercase tracking-wider mb-1">Total Packets</p>
            <p class="text-white font-bold text-xl font-mono">${totalPkts.toLocaleString()}</p>
        </div>
        <div class="bg-surface p-4 text-center">
            <p class="text-gray-500 text-xs uppercase tracking-wider mb-1">Unique IPs</p>
            <p class="text-primary font-bold text-xl">${sorted.length}</p>
        </div>
        <div class="bg-surface p-4 text-center">
            <p class="text-gray-500 text-xs uppercase tracking-wider mb-1">Threats</p>
            <p class="font-bold text-xl" style="color:${threatCount > 0 ? COLOR_THREAT : COLOR_CLEAN}">${threatCount}</p>
        </div>
    `;

    document.getElementById('popupBody').innerHTML = `
        <table class="w-full text-sm">
            <thead class="sticky top-0 bg-[#111] border-b border-[#333]">
                <tr>
                    <th class="px-4 py-2.5 text-left text-gray-500 font-medium">IP</th>
                    <th class="px-4 py-2.5 text-left text-gray-500 font-medium">City</th>
                    <th class="px-4 py-2.5 text-right text-gray-500 font-medium">Packets</th>
                    <th class="px-4 py-2.5 text-center text-gray-500 font-medium">Status</th>
                </tr>
            </thead>
            <tbody>
                ${sorted.map(c => `
                    <tr class="border-b border-[#222] hover:bg-white/5 transition-colors">
                        <td class="px-4 py-2.5 font-mono text-primary text-xs">${esc(c.ip)}</td>
                        <td class="px-4 py-2.5 text-gray-400 text-xs">${esc(c.geo?.city || '—')}</td>
                        <td class="px-4 py-2.5 text-right font-mono text-white font-bold text-xs">${c.count.toLocaleString()}</td>
                        <td class="px-4 py-2.5 text-center text-xs">
                            ${c.is_threat
                                ? '<span class="px-1.5 py-0.5 rounded bg-danger/20 text-danger border border-danger/30 font-bold text-xs">THREAT</span>'
                                : '<span class="px-1.5 py-0.5 rounded bg-primary/10 text-primary border border-primary/20 text-xs">CLEAN</span>'}
                        </td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;

    openGeoPopup();
}

// ===== Popup open / close =====
function openGeoPopup() {
    document.getElementById('geoPopup').classList.remove('hidden');
}
function closeGeoPopup(event) {
    if (event && event.target !== document.getElementById('geoPopup')) return;
    document.getElementById('geoPopup').classList.add('hidden');
}

// Expose closeGeoPopup globally for onclick attributes
window.closeGeoPopup = closeGeoPopup;

// ESC key closes popup
document.addEventListener('keydown', e => {
    if (e.key === 'Escape') document.getElementById('geoPopup')?.classList.add('hidden');
});

// ===== Country Breakdown Table =====
function updateCountryTable() {
    const byCountry = {};
    for (const conn of connections) {
        const country = conn.geo?.country || 'Unknown';
        const flag    = conn.geo?.flag    || '🌐';
        if (!byCountry[country]) byCountry[country] = { country, flag, ips: 0, packets: 0, threat: false };
        byCountry[country].ips++;
        byCountry[country].packets += conn.count;
        if (conn.is_threat) byCountry[country].threat = true;
    }

    const rows  = Object.values(byCountry).sort((a, b) => b.packets - a.packets);
    const tbody = document.getElementById('countryTableBody');
    if (!tbody) return;

    if (rows.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" class="px-4 py-10 text-center text-gray-600 text-xs">Waiting for data...</td></tr>`;
        return;
    }

    tbody.innerHTML = rows.map(r => `
        <tr class="border-b border-[#2a2a2a] hover:bg-white/5 transition-colors cursor-pointer"
            onclick="showCountryPopup(${JSON.stringify(r.country)})">
            <td class="px-3 py-2.5 text-white">
                <span class="mr-1">${r.flag}</span><span class="text-sm">${esc(r.country)}</span>
            </td>
            <td class="px-3 py-2.5 text-right font-mono text-gray-400 text-xs">${r.ips}</td>
            <td class="px-3 py-2.5 text-right font-mono text-primary text-xs font-bold">${r.packets.toLocaleString()}</td>
            <td class="px-3 py-2.5 text-center text-xs">
                ${r.threat ? '<span class="text-danger font-bold">⚠</span>' : '<span class="text-primary">✓</span>'}
            </td>
        </tr>
    `).join('');
}

// ===== Active Connections Table =====
function updateIPList() {
    const sorted = [...connections].sort((a, b) => b.count - a.count);
    document.getElementById('connCount').textContent   = sorted.length + (sorted.length === 1 ? ' connection' : ' connections');
    document.getElementById('ipListCount').textContent = sorted.length + ' IPs';

    const tbody = document.getElementById('ipListTableBody');
    if (!tbody) return;

    if (sorted.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="px-4 py-8 text-center text-gray-600">No connections yet</td></tr>`;
        return;
    }

    tbody.innerHTML = sorted.map(c => {
        const geo = c.geo || {};
        return `
            <tr class="border-b border-[#2a2a2a] hover:bg-white/5 transition-colors cursor-pointer"
                onclick="showIPPopup(${JSON.stringify(c)})">
                <td class="px-4 py-2.5 font-mono text-primary text-sm">${esc(c.ip)}</td>
                <td class="px-4 py-2.5 text-gray-300 text-sm">${geo.flag || ''} ${esc(geo.country || 'Unknown')}</td>
                <td class="px-4 py-2.5 text-gray-500 text-sm">${esc(geo.city || '—')}</td>
                <td class="px-4 py-2.5 text-right font-mono text-white text-sm font-bold">${c.count.toLocaleString()}</td>
                <td class="px-4 py-2.5 text-center text-xs">
                    ${c.is_threat
                        ? '<span class="px-2 py-0.5 rounded bg-danger/20 text-danger border border-danger/30 font-bold">THREAT</span>'
                        : '<span class="px-2 py-0.5 rounded bg-primary/10 text-primary border border-primary/20">CLEAN</span>'}
                </td>
            </tr>
        `;
    }).join('');
}

// ===== XSS safety =====
function esc(str) {
    if (str == null) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ===== SocketIO =====
document.addEventListener('DOMContentLoaded', () => {
    initMap();

    const socket = io();

    socket.on('connect', () => socket.emit('get_all_connections'));

    socket.on('all_connections_data', data => {
        connections = data || [];
        updateMap();
        updateCountryTable();
        updateIPList();

        // Resolve unknown public IPs — 8 per cycle to respect ip-api.com rate limit
        const unresolved = connections
            .filter(c => c.geo && c.geo.country === 'Unknown' && c.geo.lat == null)
            .slice(0, 8);
        for (const conn of unresolved) socket.emit('resolve_geo', { ip: conn.ip });
    });

    socket.on('geo_resolved', result => {
        const conn = connections.find(c => c.ip === result.ip);
        if (conn && result.country && result.country !== 'Unknown') {
            conn.geo = {
                country: result.country, city: result.city || '',
                flag:    result.flag    || '🌐',
                lat:     result.lat     || null,
                lon:     result.lon     || null
            };
            updateMap();
            updateCountryTable();
            updateIPList();
        }
    });

    setInterval(() => { if (socket.connected) socket.emit('get_all_connections'); }, 5000);

    // Redraw on resize
    let resizeTimer;
    window.addEventListener('resize', () => {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(() => {
            svg && svg.selectAll('*').remove();
            circlesGroup = null;
            worldLoaded  = false;
            initMap();
        }, 300);
    });
});