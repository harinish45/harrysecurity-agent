/**
 * NEXUS-STRIKE Strix Dashboard — Full JavaScript
 * 13-page SPA with Chart.js, D3.js, live API polling, WebSocket scan progress
 */

'use strict';

// ── State ──────────────────────────────────────────────────────
let severityChart = null;
let benchmarkScoreChart = null;
let scanPolling = null;
let allFindings = [];
let scanSocket = null;

// ── Authenticated fetch ──────────────────────────────────────────
// The server has always supported an optional NEXUS_DASHBOARD_TOKEN
// (Authorization: Bearer <token>), but nothing in this file ever sent
// that header — meaning a configured token silently broke the whole UI.
// apiFetch() fixes that: it attaches a stored token (if any) and the
// same-origin signal header the server now requires on state-changing
// requests, and prompts once for a token on a 401 rather than failing
// silently forever.
const _rawFetch = window.fetch.bind(window);
const TOKEN_STORAGE_KEY = 'nexus-dashboard-token';

function getStoredToken() {
    try {
        return localStorage.getItem(TOKEN_STORAGE_KEY) || '';
    } catch (e) {
        return '';
    }
}

function setStoredToken(token) {
    try {
        if (token) localStorage.setItem(TOKEN_STORAGE_KEY, token);
        else localStorage.removeItem(TOKEN_STORAGE_KEY);
    } catch (e) { /* private browsing / storage blocked — token just won't persist */ }
}

async function apiFetch(url, options = {}, _retried = false) {
    const headers = new Headers(options.headers || {});
    const token = getStoredToken();
    if (token && !headers.has('Authorization')) {
        headers.set('Authorization', `Bearer ${token}`);
    }
    const method = (options.method || 'GET').toUpperCase();
    if (method !== 'GET' && method !== 'HEAD') {
        headers.set('X-Requested-With', 'NEXUS-Dashboard');
    }

    const response = await _rawFetch(url, { ...options, headers });

    if (response.status === 401 && !_retried) {
        const entered = window.prompt('Dashboard token required. Enter NEXUS_DASHBOARD_TOKEN:');
        if (entered) {
            setStoredToken(entered.trim());
            return apiFetch(url, options, true);
        }
    }
    return response;
}

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
    } else if (data.type === 'agent_event') {
        renderAgentEvent(data.event || {});
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
        'benchmarks':   ['Benchmark Dashboard',      'Suite scores, debate precision/recall, agent latency'],
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
        case 'pentests':    await loadAgentTiers(); initAnalysisTabs(); await loadMitreCoverage(); startBudgetMeterPolling(); break;
        case 'issues':      await loadIssues(); break;
        case 'reports':     await loadReportsGrid(); break;
        case 'benchmarks':  await loadBenchmarksPage(); break;
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
            apiFetch('/api/stats'),
            apiFetch('/api/agents'),
            apiFetch('/api/tools'),
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
        const res  = await apiFetch('/api/reports');
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
        const res  = await apiFetch('/api/reports');
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
        const res  = await apiFetch('/api/agents');
        const data = await res.json();
        if (!data.by_tier) return;
        container.innerHTML = Object.entries(data.by_tier).map(([tier, agents]) => `
            <div class="tier-card">
                <div class="tier-name">${tier}</div>
                <div class="tier-count">${agents.length}</div>
            </div>`).join('');

        const datalist = document.getElementById('agent-name-list');
        if (datalist) {
            const allNames = Object.values(data.by_tier).flat();
            datalist.innerHTML = allNames.map(name => `<option value="${escHtml(name)}"></option>`).join('');
        }
    } catch {}
}

// ── Run a single agent (Pentests page) ─────────────────────────
async function runAgent() {
    const agent = document.getElementById('agent-name')?.value?.trim();
    const target = document.getElementById('agent-target')?.value?.trim();
    const output = document.getElementById('agent-run-output');
    if (!agent || !target) {
        if (output) output.textContent = '⚠ Enter both an agent name and a target.';
        return;
    }
    if (output) output.textContent = `🎯 Running ${agent} against ${target}…\n`;
    try {
        const res = await apiFetch('/api/agent/run', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ agent, target }),
        });
        const data = await res.json();
        if (!res.ok) {
            if (output) output.textContent = `❌ ${data.detail || 'Request failed'}`;
            return;
        }
        const findings = data.findings || [];
        let text = `✅ Status: ${data.status || 'unknown'}\nFindings: ${findings.length}\n\n`;
        for (const f of findings.slice(0, 20)) {
            const title = (f && typeof f === 'object') ? (f.title || JSON.stringify(f)) : String(f);
            const sev = (f && typeof f === 'object') ? (f.severity || 'info') : 'info';
            text += `[${sev}] ${title}\n`;
        }
        if (findings.length > 20) text += `… and ${findings.length - 20} more\n`;
        if (output) output.textContent = text;
    } catch (e) {
        if (output) output.textContent = `❌ Request failed: ${e}`;
    }
}

// ── Issues ─────────────────────────────────────────────────────
async function loadIssues() {
    const list = document.getElementById('issues-list');
    if (!list) return;
    try {
        const res  = await apiFetch('/api/findings');
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
        const res  = await apiFetch('/api/skills');
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

// ── Tool Domains (shared by the Repositories page and the Domains page —
// same data, same rendering, just a different target grid element) ────
async function renderToolDomainsInto(gridId, emptyLabel, errorLabel) {
    const grid = document.getElementById(gridId);
    if (!grid) return;
    try {
        const res  = await apiFetch('/api/tools');
        const data = await res.json();
        const counts = data.counts || {};
        grid.innerHTML = Object.entries(counts).sort((a,b) => b[1]-a[1]).map(([domain, count]) => `
            <div class="domain-card">
                <span class="domain-name">${escHtml(domain.replace(/_/g,' '))}</span>
                <span class="domain-count">${count}</span>
            </div>`).join('') || `<div class="loading-cell">${emptyLabel}</div>`;
    } catch {
        grid.innerHTML = `<div class="loading-cell">${errorLabel}</div>`;
    }
}

async function loadToolDomains() {
    return renderToolDomainsInto('tool-domains-grid', 'No tool data.', 'Failed to load tool data.');
}

async function loadDomains() {
    return renderToolDomainsInto('domains-grid', 'No domain data.', 'Failed to load domains.');
}

// ── Networks page ──────────────────────────────────────────────
async function loadNetworkInfo() {
    try {
        const res  = await apiFetch('/api/tools');
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
        const res  = await apiFetch('/api/agents');
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
        const res  = await apiFetch('/api/skills');
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
        const res  = await apiFetch('/api/scan/start', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({target:'127.0.0.1'}) });
        const data = await res.json();
        console.log('Scan started:', data);
    } catch {
        // A rejected request here (guardrail block, missing NEXUS_LEGAL_ACK,
        // scope violation) is surfaced by the scan-output log via the /ws/scan
        // WebSocket, not by this catch — /api/scan/start is a real endpoint.
    } finally {
        setTimeout(() => { text.textContent = '▶ Start Scan'; btn.disabled = false; }, 3000);
    }
}

async function startScanFromPanel() {
    const target = document.getElementById('scan-target')?.value?.trim() || '127.0.0.1';
    const mode = document.getElementById('scan-mission-mode')?.value || 'live';
    const output = document.getElementById('scan-output');
    const stream = document.getElementById('agent-stream');
    if (output) output.textContent = `🚀 Launching ${mode} assessment against ${target}…\n`;
    if (stream) { stream.innerHTML = ''; agentStreamGroups = {}; }
    await apiFetch('/api/scan/start', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({target, mode}) }).catch(() => {});
}

// Per-agent event groups for the Live Agent Stream panel — keyed by agent
// name so repeated batches for the same agent collapse into one block
// instead of scrolling text.
let agentStreamGroups = {};

function renderAgentEvent(evt) {
    const stream = document.getElementById('agent-stream');
    if (!stream) return;

    if (evt.type === 'batch_start') {
        (evt.agents || []).forEach(name => {
            agentStreamGroups[name] = agentStreamGroups[name] || { status: 'running', batch: evt.batch };
        });
    } else if (evt.type === 'agent_done') {
        const name = evt.agent || 'unknown';
        agentStreamGroups[name] = {
            status: evt.status || 'completed',
            batch: evt.batch,
            findings: evt.findings_count,
            error: evt.error,
        };
    } else if (evt.type === 'debate_round') {
        const name = `debate_consensus_agent (${evt.finding_id})`;
        const verdict = evt.verdict?.verdict || evt.verdict?.consensus || '?';
        agentStreamGroups[name] = {
            status: evt.role === 'consensus' ? (verdict === 'disagreement' ? 'failed' : 'completed') : 'running',
            batch: '—',
            findings: undefined,
            error: undefined,
            debateRole: evt.role,
            debateVerdict: verdict,
        };
    }

    const rows = Object.entries(agentStreamGroups).map(([name, info]) => {
        const icon = info.status === 'failed' ? '❌' : (info.status === 'running' ? '⏳' : '✅');
        let detail;
        if (info.debateRole) {
            detail = `${info.debateRole}: ${escHtml(info.debateVerdict)}`;
        } else {
            detail = info.error
                ? `error: ${escHtml(info.error)}`
                : (info.findings !== undefined ? `${info.findings} finding(s)` : 'running…');
        }
        return `<div class="agent-stream-row"><span class="agent-stream-name">${icon} ${escHtml(name)}</span>`
             + `<span class="agent-stream-detail">batch ${info.batch ?? '?'} — ${detail}</span></div>`;
    });
    stream.innerHTML = rows.join('') || '<span class="muted">Waiting for agents…</span>';
}

async function stopScan() {
    const output = document.getElementById('scan-output');
    await apiFetch('/api/scan/stop', { method:'POST' }).catch(() => {});
    if (output) output.textContent += '\n⏹ Stop requested.';
}

// ── Mission Analysis panel (MITRE coverage / attack graph / report preview) ──
function initAnalysisTabs() {
    const bar = document.getElementById('analysis-tabs');
    if (!bar || bar.dataset.wired) return;
    bar.dataset.wired = '1';

    bar.addEventListener('click', (e) => {
        const btn = e.target.closest('.tab-btn');
        if (!btn) return;
        bar.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        const tab = btn.dataset.tab;
        ['mitre', 'graph', 'triage', 'report'].forEach(name => {
            const panel = document.getElementById(`analysis-${name}`);
            if (panel) panel.hidden = name !== tab;
        });
        if (tab === 'graph') loadAttackGraph();
        if (tab === 'triage') loadTriageBoard();
        if (tab === 'report') loadReportTonePreview();
    });

    const modeSelect = document.getElementById('report-tone-mode');
    if (modeSelect) modeSelect.addEventListener('change', loadReportTonePreview);
}

async function loadMitreCoverage() {
    const el = document.getElementById('analysis-mitre');
    if (!el) return;
    try {
        const res = await apiFetch('/api/mitre-coverage');
        const data = await res.json();
        if (!data.techniques || !data.techniques.length) {
            el.innerHTML = '<span class="muted">No MITRE ATT&CK-tagged findings in the latest report yet.</span>';
            return;
        }
        const sevClass = { critical: 'sev-critical', high: 'sev-high', medium: 'sev-medium', low: 'sev-low', info: 'sev-info' };
        el.innerHTML = `<div class="mitre-heatmap">${data.techniques.map(t => `
            <div class="mitre-cell ${sevClass[t.max_severity] || 'sev-info'}" title="${escHtml(t.name)} — ${t.count} finding(s)">
                <div class="mitre-cell-id">${escHtml(t.id)}</div>
                <div class="mitre-cell-count">${t.count}</div>
            </div>`).join('')}</div>`;
    } catch (e) {
        el.innerHTML = '<span class="muted">Could not load MITRE coverage.</span>';
    }
}

async function loadAttackGraph() {
    const el = document.getElementById('analysis-graph');
    if (!el || el.dataset.loaded) return;
    try {
        const res = await apiFetch('/api/attack-graph');
        const data = await res.json();
        el.innerHTML = data.svg || '<span class="muted">No graph data.</span>';
        el.dataset.loaded = '1';
    } catch (e) {
        el.innerHTML = '<span class="muted">Could not load attack graph.</span>';
    }
}

// Triage board columns, in the order XBOW-style verification moves a
// finding through: unverified/non_replayable -> failed -> verified, with
// any finding debate_consensus_agent flagged "disagreement" surfaced too.
const _TRIAGE_COLUMNS = [
    { key: 'non_replayable', label: 'Unverified (no replay evidence)' },
    { key: 'unverified', label: 'Verification Failed' },
    { key: 'failed', label: 'Replay Errored' },
    { key: 'verified', label: 'Verified' },
];

async function loadTriageBoard() {
    const el = document.getElementById('analysis-triage');
    if (!el) return;
    el.innerHTML = '<span class="muted">Loading…</span>';
    try {
        const res = await apiFetch('/api/findings?limit=200');
        const data = await res.json();
        const findings = data.findings || [];
        const buckets = {};
        _TRIAGE_COLUMNS.forEach(c => { buckets[c.key] = []; });
        buckets.unclassified = [];
        findings.forEach(f => {
            const status = f.verification_status;
            (buckets[status] ? buckets[status] : buckets.unclassified).push(f);
        });
        const columns = [..._TRIAGE_COLUMNS, { key: 'unclassified', label: 'Not Yet Verified' }];
        el.innerHTML = `<div class="triage-board">${columns.map(col => `
            <div class="triage-column">
                <div class="triage-column-header">${escHtml(col.label)} <span class="triage-count">${buckets[col.key].length}</span></div>
                ${buckets[col.key].slice(0, 20).map(f => `
                    <div class="triage-card sev-${f.severity || 'info'}">
                        <div class="triage-card-title">${escHtml(f.title || 'Untitled')}</div>
                        <div class="triage-card-meta">${escHtml(f.id || '')} · ${escHtml(f.severity || 'info')}</div>
                    </div>`).join('') || '<span class="muted triage-empty">—</span>'}
            </div>`).join('')}</div>`;
    } catch (e) {
        el.innerHTML = '<span class="muted">Could not load triage board.</span>';
    }
}

async function loadReportTonePreview() {
    const body = document.getElementById('report-tone-body');
    const mode = document.getElementById('report-tone-mode')?.value || 'pentest';
    if (!body) return;
    body.textContent = 'Loading…';
    try {
        const res = await apiFetch(`/api/report-tone?mode=${encodeURIComponent(mode)}`);
        const data = await res.json();
        body.textContent = data.report || 'No report data yet — run a mission first.';
    } catch (e) {
        body.textContent = 'Could not load report preview.';
    }
}

// ── Budget meter ───────────────────────────────────────────────
let budgetMeterInterval = null;

function startBudgetMeterPolling() {
    if (budgetMeterInterval) return;
    loadBudgetMeter();
    budgetMeterInterval = setInterval(loadBudgetMeter, 5000);
}

async function loadBudgetMeter() {
    const fill = document.getElementById('budget-meter-fill');
    const text = document.getElementById('budget-meter-text');
    if (!fill || !text) return;
    try {
        const res = await apiFetch('/api/budget');
        const data = await res.json();
        if (!data.mission_id) {
            text.textContent = 'No active mission';
            fill.style.width = '0%';
            return;
        }
        // NEXUS_BUDGET_MAX_TOKENS/_MAX_USD are optional — only render the bar
        // as a fraction of an actual configured cap; otherwise just show the
        // running total without implying a limit that isn't set.
        if (data.max_tokens) {
            fill.style.width = `${Math.min(100, (data.estimated_tokens / data.max_tokens) * 100)}%`;
        } else {
            fill.style.width = '0%';
        }
        const capNote = data.max_tokens ? ` / ${data.max_tokens} cap` : ' (no cap set)';
        text.textContent = `${data.estimated_tokens}${capNote} tokens (~$${(data.estimated_usd || 0).toFixed(4)}) — ${data.calls} call(s)`;
    } catch (e) {
        // Silent — budget endpoint may not be reachable yet.
    }
}

// ── Benchmark Dashboard page ─────────────────────────────────────
const _BENCHMARK_SUITE_COLORS = {
    intercode_ctf: '#3fb950',
    cybench: '#d29922',
    nyu_ctf: '#a371f7',
    debate_consensus_eval: '#58a6ff',
};

async function loadBenchmarksPage() {
    await Promise.all([
        loadBenchmarkScoreChart(),
        loadDebateEvalTable(),
        loadLatencyTable(),
    ]);
}

async function loadBenchmarkScoreChart() {
    const canvas = document.getElementById('benchmarkScoreChart');
    const empty = document.getElementById('benchmark-score-empty');
    if (!canvas) return;
    try {
        const res = await apiFetch('/api/benchmarks?limit=200');
        const data = await res.json();
        const runs = (data.runs || []).filter(r => r.run_at && typeof r.score === 'number');

        if (!runs.length) {
            canvas.hidden = true;
            if (empty) empty.hidden = false;
            return;
        }
        canvas.hidden = false;
        if (empty) empty.hidden = true;

        // Group by suite, oldest -> newest per suite, so each suite draws
        // its own score-over-time line.
        const bySuite = {};
        runs.forEach(r => { (bySuite[r.suite] = bySuite[r.suite] || []).push(r); });
        Object.values(bySuite).forEach(list => list.sort((a, b) => a.run_at.localeCompare(b.run_at)));

        // Shared x-axis: every distinct run_at across all suites, sorted.
        const allTimestamps = [...new Set(runs.map(r => r.run_at))].sort();

        const datasets = Object.entries(bySuite).map(([suite, list]) => {
            const bySuiteTime = Object.fromEntries(list.map(r => [r.run_at, r.score]));
            return {
                label: suite,
                data: allTimestamps.map(ts => bySuiteTime[ts] ?? null),
                borderColor: _BENCHMARK_SUITE_COLORS[suite] || '#8b949e',
                backgroundColor: 'transparent',
                spanGaps: true,
                tension: 0.25,
            };
        });

        if (benchmarkScoreChart) { benchmarkScoreChart.destroy(); }
        benchmarkScoreChart = new Chart(canvas.getContext('2d'), {
            type: 'line',
            data: { labels: allTimestamps.map(t => t.replace('T', ' ').replace('Z', '')), datasets },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { min: 0, max: 1, ticks: { color: '#8b949e' } },
                    x: { ticks: { color: '#8b949e', maxRotation: 45, minRotation: 45 } },
                },
                plugins: {
                    legend: { position: 'top', labels: { color: '#8b949e', font: { family: 'Inter', size: 11 } } },
                },
            },
        });
    } catch (e) {
        console.warn('Benchmark score chart load failed:', e);
        if (empty) { empty.hidden = false; empty.textContent = 'Could not load benchmark history.'; }
    }
}

async function loadDebateEvalTable() {
    const tbody = document.getElementById('debate-eval-tbody');
    if (!tbody) return;
    try {
        const res = await apiFetch('/api/benchmarks/debate-eval');
        const data = await res.json();
        const runs = data.runs || [];
        if (!runs.length) {
            tbody.innerHTML = '<tr><td colspan="9" class="loading-cell">No debate_consensus_eval runs yet — run <code>nexus benchmark --suite debate_consensus_eval</code>.</td></tr>';
            return;
        }
        tbody.innerHTML = runs.map(r => `
            <tr>
                <td>${escHtml((r.run_at || '').replace('T', ' ').replace('Z', ''))}</td>
                <td>${(r.precision ?? 0).toFixed(2)}</td>
                <td>${(r.recall ?? 0).toFixed(2)}</td>
                <td>${(r.f1 ?? 0).toFixed(2)}</td>
                <td>${r.tp ?? 0}</td>
                <td>${r.fp ?? 0}</td>
                <td>${r.fn ?? 0}</td>
                <td>${r.tn ?? 0}</td>
                <td>${r.abstained ?? 0}</td>
            </tr>`).join('');
    } catch (e) {
        tbody.innerHTML = '<tr><td colspan="9" class="loading-cell">Could not load debate-eval history.</td></tr>';
    }
}

async function loadLatencyTable() {
    const tbody = document.getElementById('latency-tbody');
    if (!tbody) return;
    try {
        const res = await apiFetch('/api/benchmarks/latency?limit=1');
        const data = await res.json();
        const latest = (data.runs || [])[0];
        if (!latest || !latest.results || !latest.results.length) {
            tbody.innerHTML = '<tr><td colspan="3" class="loading-cell">No latency runs yet — run <code>nexus benchmark --latency</code>.</td></tr>';
            return;
        }
        // Already sorted slowest-first by benchmark_agent_latency().
        tbody.innerHTML = latest.results.map(r => `
            <tr>
                <td>${escHtml(r.agent)}</td>
                <td>${r.latency_ms ?? '—'}</td>
                <td>${escHtml(r.status)}</td>
            </tr>`).join('');
    } catch (e) {
        tbody.innerHTML = '<tr><td colspan="3" class="loading-cell">Could not load latency history.</td></tr>';
    }
}

// ── Helpers ────────────────────────────────────────────────────
function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}

function escHtml(str) {
    return String(str).replace(/[&<>"']/g, c => ({'&':'&','<':'<','>':'>','"':'"',"'":'&#39;'}[c]));
}
