/**
 * NEXUS-STRIKE Strix Dashboard — Full JavaScript
 * 13-page SPA with Chart.js, D3.js, live API polling, WebSocket scan progress
 */

'use strict';

// ── State ──────────────────────────────────────────────────────
let severityChart = null;
let scanPolling = null;
let allFindings = [];
let scanSocket = null;

// ── Bootstrap ──────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
    initNavigation();
    initThemeToggle();
    initHamburger();
    initScanWebSocket();
    await Promise.all([loadStats(), loadReports()]);
    initAgentGraph();
    loadSkillChips();
});

// ── Theme Toggle ──────────────────────────────────────────────
function initThemeToggle() {
    const toggle = document.getElementById('theme-toggle');
    if (!toggle) return;

    // Load saved theme (default: dark)
    const saved = localStorage.getItem('nexus-theme') || 'dark';
    document.documentElement.setAttribute('data-theme', saved);
    toggle.textContent = saved === 'dark' ? '🌙' : '☀️';

    toggle.addEventListener('click', () => {
        const current = document.documentElement.getAttribute('data-theme') || 'dark';
        const next = current === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', next);
        localStorage.setItem('nexus-theme', next);
        toggle.textContent = next === 'dark' ? '🌙' : '☀️';
    });
}

// ── Hamburger Menu (mobile) ───────────────────────────────────
function initHamburger() {
    const hamburger = document.getElementById('hamburger');
    const sidebar = document.getElementById('sidebar');
    if (!hamburger || !sidebar) return;

    hamburger.addEventListener('click', () => {
        sidebar.classList.toggle('open');
    });

    // Close sidebar when a nav item is clicked on mobile
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', () => {
            if (window.innerWidth <= 768) sidebar.classList.remove('open');
        });
    });
}

// ── WebSocket Scan Progress ───────────────────────────────────
function initScanWebSocket() {
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const wsUrl = `${proto}://${window.location.host}/ws/scan`;

    try {
        scanSocket = new WebSocket(wsUrl);

        scanSocket.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                handleScanEvent(data);
            } catch (e) {
                console.warn('Invalid WS message:', event.data);
            }
        };

        scanSocket.onclose = () => {
            // Auto-reconnect after 3s
            setTimeout(() => {
                if (document.visibilityState !== 'hidden') initScanWebSocket();
            }, 3000);
        };

        scanSocket.onerror = () => {
            // Silent — server may not be running
        };
    } catch (e) {
        console.warn('WebSocket init failed:', e);
    }
}

function handleScanEvent(data) {
    const output = document.getElementById('scan-output');
    if (!output) return;

    if (data.type === 'status') {
        const statusText = data.status === 'running' ? '🟢 Running' : (data.status === 'stopped' ? '⏹ Stopped' : '⚪ Idle');
        output.textContent = `Status: ${statusText} | Target: ${data.target || '—'}\n`;
    } else if (data.type === 'phase') {
        output.textContent += `\n[Phase ${data.phase}] ${data.message || ''}`;
        output.scrollTop = output.scrollHeight;
    } else if (data.type === 'output') {
        output.textContent += `\n${data.line || ''}`;
        output.scrollTop = output.scrollHeight;
    }
}

// ── Navigation ─────────────────────────────────────────────────
function initNavigation() {
    document.querySelectorAll('.nav-item').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const page = link.dataset.page;
            if (page) navigate(page);
        });
    });

    // Handle hash on load
    const hash = window.location.hash.replace('#', '');
    if (hash) navigate(hash);
}

/**
 * Switch to a named page, activating sidebar + main panel.
 * @param {string} pageName - page id (e.g. 'dashboard', 'chat')
 */
function navigate(pageName) {
    // Deactivate all
    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.page').forEach(el => el.classList.remove('active'));

    // Activate target
    const navEl = document.getElementById(`nav-${pageName}`);
    const pageEl = document.getElementById(`page-${pageName}`);

    if (navEl) navEl.classList.add('active');
    if (pageEl) pageEl.classList.add('active');

    // Update header
    const titles = {
        'dashboard':    ['Security Dashboard',      'Overview'],
        'pentests':     ['Pentests',                'Live Assessment Control'],
        'issues':       ['Security Issues',         'Findings & Vulnerabilities'],
        'reports':      ['Reports',                 'Generated Security Reports'],
        'supply-chain': ['Supply Chain',            'Third-party & Vendor Risk'],
        'repositories': ['Repositories',            'Code Security & Secrets'],
        'domains':      ['Tool Domains',            '277 tools across 29 domains'],
        'networks':     ['Networks',                'Asset Discovery & Topology'],
        'knowledge':    ['Knowledge Base',          'Platform Documentation'],
        'chat':         ['AI Security Chat',        'Skill-powered assistant'],
        'pr-reviews':   ['PR Reviews',              'Automated Code Security'],
        'integrations': ['Integrations',            'Connect your toolchain'],
        'settings':     ['Settings',                'Platform Configuration'],
    };

    const [title, breadcrumb] = titles[pageName] || ['NEXUS-STRIKE', ''];
    document.getElementById('page-title').textContent = title;
    document.getElementById('page-breadcrumb').textContent = breadcrumb;
    window.location.hash = pageName;

    // Lazy-load page data
    onPageLoad(pageName);
}

/** Lazy page data loaders */
async function onPageLoad(page) {
    switch (page) {
        case 'pentests':    await loadAgentTiers(); break;
        case 'issues':      await loadIssues(); break;
        case 'reports':     await loadReportsGrid(); break;
        case 'supply-chain': await loadSkills(); break;
        case 'repositories': await loadToolDomains(); break;
        case 'domains':     await loadDomains(); break;
        case 'networks':    await loadNetworkInfo(); break;
        case 'knowledge':   await loadKnowledge(); break;
        case 'chat':        await loadSkillChips(); break;
    }
}

// ── Stats ──────────────────────────────────────────────────────
async function loadStats() {
    try {
        const [statsRes, agentsRes, toolsRes] = await Promise.all([
            fetch('/api/stats'),
            fetch('/api/agents'),
            fetch('/api/tools'),
        ]);
        const stats  = await statsRes.json();
        const agents = await agentsRes.json();
        const tools  = await toolsRes.json();

        if (!stats.error) {
            setText('total-findings', stats.total_findings);
            setText('critical-count', stats.severity_counts?.critical ?? 0);
            setText('high-count',     stats.severity_counts?.high ?? 0);
            setText('medium-count',   stats.severity_counts?.medium ?? 0);

            allFindings = stats.findings || [];
            initSeverityChart(stats.severity_counts || {});
        }

        if (agents.total) setText('agent-count', agents.total);
        if (tools.total)  setText('tool-count', tools.total + '+');
        if (tools.total)  setText('settings-tools', tools.total);

    } catch (err) {
        console.warn('Stats load failed:', err);
    }
}

function initSeverityChart(counts) {
    const canvas = document.getElementById('severityChart');
    if (!canvas) return;

    if (severityChart) { severityChart.destroy(); }

    const ctx = canvas.getContext('2d');
    severityChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
            datasets: [{
                data: [
                    counts.critical || 0,
                    counts.high     || 0,
                    counts.medium   || 0,
                    counts.low      || 0,
                    counts.info     || 0,
                ],
                backgroundColor: ['#f85149','#d29922','#a371f7','#3fb950','#8b949e'],
                borderWidth: 0,
                hoverOffset: 6,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '65%',
            plugins: {
                legend: {
                    position: 'right',
                    labels: { color:'#8b949e', font:{ family:'Inter', size:12 }, padding:14 }
                }
            }
        }
    });
}

// ── Reports ────────────────────────────────────────────────────
async function loadReports() {
    try {
        const res  = await fetch('/api/reports');
        const data = await res.json();
        const tbody = document.getElementById('reports-tbody');
        if (!tbody) return;

        if (!data.reports || data.reports.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="loading-cell">No reports found. Run a scan first.</td></tr>';
            return;
        }

        tbody.innerHTML = data.reports.slice(0, 10).map(r => {
            const date = new Date(r.modified * 1000).toLocaleString();
            const size = (r.size / 1024).toFixed(1) + ' KB';
            const icon = r.name.endsWith('.pdf') ? '📄' : '📋';
            return `<tr>
                <td>${icon} ${escHtml(r.name)}</td>
                <td>${size}</td>
                <td>${date}</td>
                <td><a href="${r.url}" class="btn btn-sm" target="_blank">View</a></td>
            </tr>`;
        }).join('');
    } catch (err) {
        console.error('Reports load failed:', err);
    }
}

async function loadReportsGrid() {
    const grid = document.getElementById('reports-grid');
    if (!grid) return;
    grid.innerHTML = '<div class="loading-cell">Loading reports…</div>';

    try {
        const res  = await fetch('/api/reports');
        const data = await res.json();

        if (!data.reports || data.reports.length === 0) {
            grid.innerHTML = '<div class="empty-state"><span class="empty-icon">📭</span><p>No reports yet. Run a scan to generate one.</p></div>';
            return;
        }

        grid.innerHTML = data.reports.map(r => {
            const date = new Date(r.modified * 1000).toLocaleString();
            const size = (r.size / 1024).toFixed(1) + ' KB';
            const icon = r.name.endsWith('.pdf') ? '📄' : '📋';
            return `<div class="report-card">
                <h4>${icon} ${escHtml(r.name)}</h4>
                <div class="report-meta">${size} · ${date}</div>
                <a href="${r.url}" class="btn btn-sm" target="_blank">Open Report ↗</a>
            </div>`;
        }).join('');
    } catch (err) {
        grid.innerHTML = '<div class="loading-cell">Failed to load reports.</div>';
    }
}

// ── Agent Topology D3 Graph ────────────────────────────────────
function initAgentGraph() {
    const container = document.getElementById('agent-graph');
    if (!container || typeof d3 === 'undefined') return;

    const width  = container.offsetWidth || 420;
    const height = 240;

    const nodes = [
        { id:'NEXUS', group:0 },
        { id:'Offensive', group:1 }, { id:'Defensive', group:1 },
        { id:'Analysis', group:2 },  { id:'Recon', group:2 },
        { id:'Specialized', group:3},{ id:'Support', group:3 },
    ];
    const links = [
        {source:'NEXUS', target:'Offensive'}, {source:'NEXUS', target:'Defensive'},
        {source:'NEXUS', target:'Analysis'},  {source:'NEXUS', target:'Recon'},
        {source:'NEXUS', target:'Specialized'},{source:'NEXUS', target:'Support'},
    ];

    const colors = ['#58a6ff','#f85149','#3fb950','#d29922','#a371f7','#58a6ff','#8b949e'];

    const svg = d3.select(container).append('svg')
        .attr('width', width)
        .attr('height', height);

    const sim = d3.forceSimulation(nodes)
        .force('link', d3.forceLink(links).id(d => d.id).distance(72))
        .force('charge', d3.forceManyBody().strength(-180))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collision', d3.forceCollide(30));

    const link = svg.append('g').attr('stroke','#30363d').attr('stroke-opacity',0.8)
        .selectAll('line').data(links).join('line').attr('stroke-width', 1.5);

    const node = svg.append('g').selectAll('circle').data(nodes).join('circle')
        .attr('r', d => d.id === 'NEXUS' ? 22 : 16)
        .attr('fill', d => colors[d.group])
        .attr('fill-opacity', 0.9)
        .attr('stroke', d => colors[d.group])
        .attr('stroke-width', 1.5)
        .call(d3.drag()
            .on('start', (e, d) => { if (!e.active) sim.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y; })
            .on('drag',  (e, d) => { d.fx=e.x; d.fy=e.y; })
            .on('end',   (e, d) => { if (!e.active) sim.alphaTarget(0); d.fx=null; d.fy=null; }));

    const label = svg.append('g').selectAll('text').data(nodes).join('text')
        .text(d => d.id)
        .attr('fill','#e6edf3')
        .attr('font-size', d => d.id === 'NEXUS' ? '11px' : '9px')
        .attr('font-family','Inter,sans-serif')
        .attr('font-weight', d => d.id === 'NEXUS' ? '700' : '500')
        .attr('text-anchor','middle')
        .attr('dy', 4)
        .style('pointer-events','none');

    sim.on('tick', () => {
        link.attr('x1', d=>d.source.x).attr('y1', d=>d.source.y)
            .attr('x2', d=>d.target.x).attr('y2', d=>d.target.y);
        node.attr('cx', d=>d.x).attr('cy', d=>d.y);
        label.attr('x', d=>d.x).attr('y', d=>d.y);
    });
}

// ── Agent Tiers (Pentests page) ────────────────────────────────
async function loadAgentTiers() {
    const container = document.getElementById('tier-cards');
    if (!container) return;
    try {
        const res  = await fetch('/api/agents');
        const data = await res.json();
        if (!data.by_tier) return;
        container.innerHTML = Object.entries(data.by_tier).map(([tier, agents]) => `
            <div class="tier-card">
                <div class="tier-name">${tier}</div>
                <div class="tier-count">${agents.length}</div>
            </div>`).join('');
    } catch {}
}

// ── Issues ─────────────────────────────────────────────────────
async function loadIssues() {
    const list = document.getElementById('issues-list');
    if (!list) return;
    try {
        const res  = await fetch('/api/findings');
        const data = await res.json();
        renderIssues(data.findings || [], 'all');
    } catch {
        list.innerHTML = '<div class="empty-state"><span class="empty-icon">✅</span><p>Run a scan to see findings here.</p></div>';
    }
}

function renderIssues(findings, filter) {
    const list = document.getElementById('issues-list');
    if (!list) return;
    const filtered = filter === 'all' ? findings : findings.filter(f => f.severity?.toLowerCase() === filter);
    if (filtered.length === 0) {
        list.innerHTML = '<div class="empty-state"><span class="empty-icon">✅</span><p>No issues found.</p></div>';
        return;
    }
    list.innerHTML = filtered.map(f => `
        <div class="issue-item" data-severity="${f.severity?.toLowerCase() || 'info'}">
            <div class="issue-title">
                <span class="sev-badge sev-${f.severity?.toLowerCase() || 'info'}">${f.severity || 'info'}</span>
                &nbsp;${escHtml(f.title || f.description?.slice(0, 80) || 'Finding')}
            </div>
            <div class="issue-meta">${escHtml(f.tool || '')} · ${escHtml(f.target || '')}</div>
        </div>`).join('');
}

function filterIssues(severity) {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    event.target.classList.add('active');
    renderIssues(allFindings, severity);
}

// ── Skills (Supply Chain page) ─────────────────────────────────
async function loadSkills() {
    const grid = document.getElementById('skills-list');
    if (!grid) return;
    try {
        const res  = await fetch('/api/skills');
        const data = await res.json();
        const skills = data.functional || data.class_based || [];
        if (skills.length === 0) {
            grid.innerHTML = '<div class="loading-cell">No skills loaded.</div>';
            return;
        }
        const icons = { web:'🌐', cloud:'☁️', code:'💻', recon:'🔍', network:'📡', threat:'🎯', compliance:'📋' };
        grid.innerHTML = skills.map(name => {
            const key = Object.keys(icons).find(k => name.toLowerCase().includes(k)) || 'web';
            return `<div class="skill-card">
                <h4>${icons[key]} ${escHtml(name.replace(/_/g,' '))}</h4>
                <p>High-level security orchestration skill.</p>
                <div class="skill-cat">NEXUS-STRIKE Skill</div>
            </div>`;
        }).join('');
    } catch {
        grid.innerHTML = '<div class="loading-cell">Failed to load skills.</div>';
    }
}

// ── Tool Domains (Repositories page) ──────────────────────────
async function loadToolDomains() {
    const grid = document.getElementById('tool-domains-grid');
    if (!grid) return;
    try {
        const res  = await fetch('/api/tools');
        const data = await res.json();
        const counts = data.counts || {};
        grid.innerHTML = Object.entries(counts).sort((a,b) => b[1]-a[1]).map(([domain, count]) => `
            <div class="domain-card">
                <span class="domain-name">${escHtml(domain.replace(/_/g,' '))}</span>
                <span class="domain-count">${count}</span>
            </div>`).join('') || '<div class="loading-cell">No tool data.</div>';
    } catch {
        grid.innerHTML = '<div class="loading-cell">Failed to load tool data.</div>';
    }
}

// ── Domains page ───────────────────────────────────────────────
async function loadDomains() {
    const grid = document.getElementById('domains-grid');
    if (!grid) return;
    try {
        const res  = await fetch('/api/tools');
        const data = await res.json();
        const counts = data.counts || {};
        grid.innerHTML = Object.entries(counts).sort((a,b) => b[1]-a[1]).map(([domain, count]) => `
            <div class="domain-card">
                <span class="domain-name">${escHtml(domain.replace(/_/g,' '))}</span>
                <span class="domain-count">${count}</span>
            </div>`).join('') || '<div class="loading-cell">No domain data.</div>';
    } catch {
        grid.innerHTML = '<div class="loading-cell">Failed to load domains.</div>';
    }
}

// ── Networks page ──────────────────────────────────────────────
async function loadNetworkInfo() {
    try {
        const res  = await fetch('/api/tools');
        const data = await res.json();
        const counts = data.counts || {};
        const networkDomains = ['network','reconnaissance','osint','wireless','iot'];
        
        const netList  = document.getElementById('network-tools-list');
        const reconList = document.getElementById('recon-tools-list');

        if (netList) {
            const netItems = Object.entries(counts).filter(([d]) => networkDomains.slice(0,2).some(nd => d.includes(nd)));
            netList.innerHTML = netItems.map(([d, c]) => `<li>${escHtml(d.replace(/_/g,' '))} <strong>(${c})</strong></li>`).join('') || '<li>Loading…</li>';
        }
        if (reconList) {
            const reconItems = Object.entries(counts).filter(([d]) => networkDomains.slice(2).some(nd => d.includes(nd)));
            reconList.innerHTML = reconItems.map(([d, c]) => `<li>${escHtml(d.replace(/_/g,' '))} <strong>(${c})</strong></li>`).join('') || '<li>Loading…</li>';
        }
    } catch {}
}

// ── Knowledge page ─────────────────────────────────────────────
async function loadKnowledge() {
    try {
        const res  = await fetch('/api/agents');
        const data = await res.json();
        const tierSummary = document.getElementById('tier-summary');
        if (tierSummary && data.by_tier) {
            tierSummary.innerHTML = Object.entries(data.by_tier).map(([tier, agents]) => `
                <div class="tier-row">
                    <span class="tier-row-name">${tier}</span>
                    <span class="tier-row-count">${agents.length} agents</span>
                </div>`).join('');
        }
    } catch {}
}

// ── Skill Chips (Chat page) ────────────────────────────────────
async function loadSkillChips() {
    const container = document.getElementById('skill-chips');
    if (!container || container.children.length > 0) return;
    try {
        const res  = await fetch('/api/skills');
        const data = await res.json();
        const skills = data.functional || [];
        container.innerHTML = skills.map(name => `
            <button class="skill-chip" onclick="activateSkill('${escHtml(name)}')">
                🎯 ${escHtml(name.replace(/_/g,' '))}
            </button>`).join('');
    } catch {}
}

function activateSkill(skillName) {
    const input = document.getElementById('chat-input');
    if (input) {
        input.value = `Activate skill: ${skillName}`;
        input.focus();
    }
}

function sendChat() {
    const input   = document.getElementById('chat-input');
    const messages = document.getElementById('chat-messages');
    if (!input || !messages) return;

    const text = input.value.trim();
    if (!text) return;

    // Add user message
    const userMsg = document.createElement('div');
    userMsg.className = 'chat-msg user';
    userMsg.innerHTML = `
        <div class="chat-bubble">${escHtml(text)}</div>
        <div class="chat-avatar">H</div>`;
    messages.appendChild(userMsg);

    // Add NEXUS response
    const nexusMsg = document.createElement('div');
    nexusMsg.className = 'chat-msg system';
    nexusMsg.innerHTML = `
        <span class="chat-avatar">⚡</span>
        <div class="chat-bubble">Processing: <em>${escHtml(text)}</em> — Use <code>nexus live</code> to run a full scan.</div>`;
    messages.appendChild(nexusMsg);
    messages.scrollTop = messages.scrollHeight;
    input.value = '';
}

// ── Scan Control ───────────────────────────────────────────────
async function startScan() {
    const btn = document.getElementById('scan-btn');
    const text = document.getElementById('scan-btn-text');
    if (!btn) return;

    text.textContent = '⏳ Scanning…';
    btn.disabled = true;

    try {
        const res  = await fetch('/api/scan/start', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({target:'127.0.0.1'}) });
        const data = await res.json();
        console.log('Scan started:', data);
    } catch {
        // nexus live handles scans via CLI — API is stub
    } finally {
        setTimeout(() => { text.textContent = '▶ Start Scan'; btn.disabled = false; }, 3000);
    }
}

async function startScanFromPanel() {
    const target = document.getElementById('scan-target')?.value?.trim() || '127.0.0.1';
    const output = document.getElementById('scan-output');
    if (output) output.textContent = `🚀 Launching assessment against ${target}…\n`;
    await fetch('/api/scan/start', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({target}) }).catch(() => {});
}

async function stopScan() {
    const output = document.getElementById('scan-output');
    await fetch('/api/scan/stop', { method:'POST' }).catch(() => {});
    if (output) output.textContent += '\n⏹ Stop requested.';
}

// ── Helpers ────────────────────────────────────────────────────
function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}

function escHtml(str) {
    return String(str).replace(/[&<>"']/g, c => ({'&':'&','<':'<','>':'>','"':'"',"'":'&#39;'}[c]));
}
