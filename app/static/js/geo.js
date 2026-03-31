/**
 * Sentinels - Geo IP World Map
 * D3.js world map with real-time IP connection plotting.
 * Circles: size = traffic volume, color = threat status (red) / clean (green)
 */

// ===== State =====
let connections = [];
let projection, pathGen, svg, circlesGroup;
let worldLoaded = false;

// ===== D3 Colour / Scale helpers =====
const COLOR_CLEAN  = '#0df269';
const COLOR_THREAT = '#ff2a2a';

function radiusScale(packets, maxPackets) {
    if (!maxPackets || maxPackets === 0) return 5;
    return 4 + Math.sqrt(packets / maxPackets) * 22;
}

// ===== Map Initialisation =====
function initMap() {
    const container = document.getElementById('mapContainer');
    const W = container.clientWidth  || 800;
    const H = container.clientHeight || 480;

    svg = d3.select('#worldMap')
        .attr('width',  W)
        .attr('height', H);

    projection = d3.geoNaturalEarth1()
        .scale(W / 2 / Math.PI * 0.95)
        .translate([W / 2, H / 2]);

    pathGen = d3.geoPath().projection(projection);

    // Ocean background
    svg.append('rect')
        .attr('width',  W)
        .attr('height', H)
        .attr('fill',   '#0d0d0d');

    // Load and draw countries
    d3.json('/static/data/countries-110m.json').then(world => {
        worldLoaded = true;

        // Country fills
        svg.append('g').attr('class', 'countries')
            .selectAll('path')
            .data(topojson.feature(world, world.objects.countries).features)
            .join('path')
            .attr('d',            pathGen)
            .attr('fill',         '#1a1a1a')
            .attr('stroke',       '#2a2a2a')
            .attr('stroke-width', 0.4);

        // Country borders
        svg.append('path')
            .datum(topojson.mesh(world, world.objects.countries, (a, b) => a !== b))
            .attr('fill',         'none')
            .attr('stroke',       '#333')
            .attr('stroke-width', 0.5)
            .attr('d',            pathGen);

        // Group for circles (rendered above countries)
        circlesGroup = svg.append('g').attr('class', 'circles');

        // Graticule (latitude/longitude grid lines)
        svg.insert('path', '.countries')
            .datum(d3.geoGraticule()())
            .attr('fill',         'none')
            .attr('stroke',       '#1a1a1a')
            .attr('stroke-width', 0.3)
            .attr('d',            pathGen);

        // If we already have data, render immediately
        if (connections.length > 0) updateMap();

    }).catch(err => console.error('[GeoMap] Failed to load world data:', err));
}

// ===== Map Update =====
function updateMap() {
    if (!worldLoaded || !circlesGroup) return;

    // Only connections with valid lat/lon can be plotted
    const plotable = connections.filter(c => c.geo && c.geo.lat != null && c.geo.lon != null);

    const maxPkts = d3.max(plotable, d => d.count) || 1;

    // Hide "no data" overlay if we have anything to show
    const noData = document.getElementById('mapNoData');
    if (noData) noData.style.display = plotable.length > 0 ? 'none' : '';

    const tooltip  = document.getElementById('mapTooltip');
    const ttIp     = document.getElementById('ttIp');
    const ttCountry = document.getElementById('ttCountry');
    const ttCity   = document.getElementById('ttCity');
    const ttPackets = document.getElementById('ttPackets');
    const ttStatus  = document.getElementById('ttStatus');

    // Pulse ring (outer) — drawn first so circles sit on top
    const rings = circlesGroup.selectAll('.pulse-ring')
        .data(plotable, d => d.ip);

    rings.join(
        enter => enter.append('circle')
            .attr('class', 'pulse-ring')
            .attr('cx', d => projection([d.geo.lon, d.geo.lat])[0])
            .attr('cy', d => projection([d.geo.lon, d.geo.lat])[1])
            .attr('r',  0)
            .attr('fill', 'none')
            .attr('stroke', d => d.is_threat ? COLOR_THREAT : COLOR_CLEAN)
            .attr('stroke-width', 1)
            .attr('stroke-opacity', 0)
            .call(enter => enter.transition().duration(800)
                .attr('r', d => radiusScale(d.count, maxPkts) + 6)
                .attr('stroke-opacity', 0.25)),
        update => update.transition().duration(600)
            .attr('cx', d => projection([d.geo.lon, d.geo.lat])[0])
            .attr('cy', d => projection([d.geo.lon, d.geo.lat])[1])
            .attr('r',  d => radiusScale(d.count, maxPkts) + 6)
            .attr('stroke', d => d.is_threat ? COLOR_THREAT : COLOR_CLEAN),
        exit => exit.transition().duration(300).attr('stroke-opacity', 0).remove()
    );

    // Main dots
    const dots = circlesGroup.selectAll('.ip-dot')
        .data(plotable, d => d.ip);

    dots.join(
        enter => enter.append('circle')
            .attr('class', 'ip-dot')
            .attr('cx', d => projection([d.geo.lon, d.geo.lat])[0])
            .attr('cy', d => projection([d.geo.lon, d.geo.lat])[1])
            .attr('r',  0)
            .attr('fill',         d => d.is_threat ? COLOR_THREAT : COLOR_CLEAN)
            .attr('fill-opacity', 0.85)
            .attr('stroke',       d => d.is_threat ? COLOR_THREAT : COLOR_CLEAN)
            .attr('stroke-width', 1.5)
            .attr('stroke-opacity', 0.4)
            .style('cursor', 'pointer')
            .call(enter => enter.transition().duration(500)
                .attr('r', d => radiusScale(d.count, maxPkts)))
            .on('mousemove', (event, d) => {
                const [mx, my] = d3.pointer(event, document.getElementById('mapContainer'));
                tooltip.style.left  = (mx + 14) + 'px';
                tooltip.style.top   = (my - 10) + 'px';
                tooltip.classList.remove('hidden');
                ttIp.textContent      = d.ip;
                ttCountry.textContent = (d.geo.flag || '') + ' ' + (d.geo.country || 'Unknown');
                ttCity.textContent    = d.geo.city || '';
                ttPackets.textContent = d.count.toLocaleString() + ' packets';
                ttStatus.textContent  = d.is_threat ? '⚠ Threat Detected' : '✓ Clean';
                ttStatus.style.color  = d.is_threat ? COLOR_THREAT : COLOR_CLEAN;
            })
            .on('mouseleave', () => tooltip.classList.add('hidden')),
        update => update
            .attr('fill',   d => d.is_threat ? COLOR_THREAT : COLOR_CLEAN)
            .attr('stroke', d => d.is_threat ? COLOR_THREAT : COLOR_CLEAN)
            .on('mousemove', (event, d) => {
                const [mx, my] = d3.pointer(event, document.getElementById('mapContainer'));
                tooltip.style.left  = (mx + 14) + 'px';
                tooltip.style.top   = (my - 10) + 'px';
                tooltip.classList.remove('hidden');
                ttIp.textContent      = d.ip;
                ttCountry.textContent = (d.geo.flag || '') + ' ' + (d.geo.country || 'Unknown');
                ttCity.textContent    = d.geo.city || '';
                ttPackets.textContent = d.count.toLocaleString() + ' packets';
                ttStatus.textContent  = d.is_threat ? '⚠ Threat Detected' : '✓ Clean';
                ttStatus.style.color  = d.is_threat ? COLOR_THREAT : COLOR_CLEAN;
            })
            .on('mouseleave', () => tooltip.classList.add('hidden'))
            .transition().duration(600)
            .attr('cx', d => projection([d.geo.lon, d.geo.lat])[0])
            .attr('cy', d => projection([d.geo.lon, d.geo.lat])[1])
            .attr('r',  d => radiusScale(d.count, maxPkts)),
        exit => exit.transition().duration(300).attr('r', 0).remove()
    );
}

// ===== Country Breakdown Table =====
function updateCountryTable() {
    // Group connections by country
    const byCountry = {};
    for (const conn of connections) {
        const country = conn.geo?.country || 'Unknown';
        const flag    = conn.geo?.flag    || '🌐';
        if (!byCountry[country]) {
            byCountry[country] = { country, flag, ips: 0, packets: 0, threat: false };
        }
        byCountry[country].ips++;
        byCountry[country].packets += conn.count;
        if (conn.is_threat) byCountry[country].threat = true;
    }

    const rows = Object.values(byCountry).sort((a, b) => b.packets - a.packets);
    const tbody = document.getElementById('countryTableBody');
    if (!tbody) return;

    if (rows.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" class="px-4 py-10 text-center text-gray-600 text-xs">Waiting for data...</td></tr>`;
        return;
    }

    tbody.innerHTML = rows.map(r => `
        <tr class="border-b border-[#2a2a2a] hover:bg-white/5 transition-colors">
            <td class="px-4 py-2.5 text-white">
                <span class="mr-1.5">${r.flag}</span>
                <span class="text-sm">${esc(r.country)}</span>
            </td>
            <td class="px-4 py-2.5 text-right font-mono text-gray-400 text-xs">${r.ips}</td>
            <td class="px-4 py-2.5 text-right font-mono text-primary text-xs font-bold">${r.packets.toLocaleString()}</td>
            <td class="px-4 py-2.5 text-center text-xs">
                ${r.threat
                    ? '<span class="text-danger font-bold">⚠</span>'
                    : '<span class="text-primary">✓</span>'}
            </td>
        </tr>
    `).join('');
}

// ===== Active Connections Table =====
function updateIPList() {
    const sorted = [...connections].sort((a, b) => b.count - a.count);

    document.getElementById('connCount').textContent =
        sorted.length + (sorted.length === 1 ? ' connection' : ' connections');
    document.getElementById('ipListCount').textContent = sorted.length + ' IPs';

    const tbody = document.getElementById('ipListTableBody');
    if (!tbody) return;

    if (sorted.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="px-4 py-8 text-center text-gray-600">No connections yet</td></tr>`;
        return;
    }

    tbody.innerHTML = sorted.map(c => {
        const geo    = c.geo || {};
        const threat = c.is_threat;
        return `
            <tr class="border-b border-[#2a2a2a] hover:bg-white/5 transition-colors">
                <td class="px-4 py-2.5 font-mono text-primary text-sm">${esc(c.ip)}</td>
                <td class="px-4 py-2.5 text-gray-300 text-sm">${geo.flag || ''} ${esc(geo.country || 'Unknown')}</td>
                <td class="px-4 py-2.5 text-gray-500 text-sm">${esc(geo.city || '—')}</td>
                <td class="px-4 py-2.5 text-right font-mono text-white text-sm font-bold">${c.count.toLocaleString()}</td>
                <td class="px-4 py-2.5 text-center text-xs">
                    ${threat
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
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

// ===== SocketIO =====
document.addEventListener('DOMContentLoaded', () => {
    initMap();

    const socket = io();

    socket.on('connect', () => {
        socket.emit('get_all_connections');
    });

    socket.on('all_connections_data', data => {
        connections = data || [];
        updateMap();
        updateCountryTable();
        updateIPList();
    });

    // Refresh every 5 seconds
    setInterval(() => {
        if (socket.connected) socket.emit('get_all_connections');
    }, 5000);

    // Redraw map on window resize
    let resizeTimer;
    window.addEventListener('resize', () => {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(() => {
            svg && svg.selectAll('*').remove();
            circlesGroup = null;
            worldLoaded = false;
            initMap();
        }, 300);
    });
});
