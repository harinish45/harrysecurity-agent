// NEXUS-STRIKE Dashboard JavaScript

document.addEventListener('DOMContentLoaded', async () => {
    await loadStats();
    await loadReports();
    initAgentGraph();
});

async function loadStats() {
    try {
        const response = await fetch('/api/stats');
        const data = await response.json();
        
        if (data.error) {
            console.warn(data.error);
            return;
        }

        document.getElementById('total-findings').textContent = data.total_findings;
        document.getElementById('critical-count').textContent = data.severity_counts.critical;
        document.getElementById('high-count').textContent = data.severity_counts.high;
        document.getElementById('medium-count').textContent = data.severity_counts.medium;

        // Initialize Chart.js
        const ctx = document.getElementById('severityChart').getContext('2d');
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{
                    data: [
                        data.severity_counts.critical,
                        data.severity_counts.high,
                        data.severity_counts.medium,
                        data.severity_counts.low,
                        data.severity_counts.info
                    ],
                    backgroundColor: ['#f85149', '#d29922', '#a371f7', '#3fb950', '#8b949e'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: { color: '#c9d1d9' }
                    }
                }
            }
        });
    } catch (error) {
        console.error('Failed to load stats:', error);
    }
}

async function loadReports() {
    try {
        const response = await fetch('/api/reports');
        const data = await response.json();
        const tbody = document.getElementById('reports-tbody');
        tbody.innerHTML = '';

        if (data.reports.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4">No reports found. Run a scan first.</td></tr>';
            return;
        }

        data.reports.slice(0, 10).forEach(report => {
            const row = document.createElement('tr');
            const date = new Date(report.modified * 1000).toLocaleString();
            const size = (report.size / 1024).toFixed(1) + ' KB';
            
            row.innerHTML = `
                <td>${report.name}</td>
                <td>${size}</td>
                <td>${date}</td>
                <td><a href="${report.url}" class="btn" target="_blank">View</a></td>
            `;
            tbody.appendChild(row);
        });
    } catch (error) {
        console.error('Failed to load reports:', error);
    }
}

function initAgentGraph() {
    // Simple D3.js force-directed graph placeholder
    const width = 400;
    const height = 250;
    const svg = d3.select('#agent-graph')
        .append('svg')
        .attr('width', width)
        .attr('height', height);

    const nodes = [
        { id: 'NEXUS', group: 1 },
        { id: 'Recon', group: 2 },
        { id: 'Network', group: 2 },
        { id: 'Web', group: 2 },
        { id: 'AD', group: 2 }
    ];

    const links = [
        { source: 'NEXUS', target: 'Recon' },
        { source: 'NEXUS', target: 'Network' },
        { source: 'NEXUS', target: 'Web' },
        { source: 'NEXUS', target: 'AD' }
    ];

    const simulation = d3.forceSimulation(nodes)
        .force('link', d3.forceLink(links).id(d => d.id).distance(50))
        .force('charge', d3.forceManyBody().strength(-100))
        .force('center', d3.forceCenter(width / 2, height / 2));

    const link = svg.append('g')
        .attr('stroke', '#8b949e')
        .attr('stroke-opacity', 0.6)
        .selectAll('line')
        .data(links)
        .join('line')
        .attr('stroke-width', 1.5);

    const node = svg.append('g')
        .selectAll('circle')
        .data(nodes)
        .join('circle')
        .attr('r', 20)
        .attr('fill', d => d.group === 1 ? '#58a6ff' : '#21262d')
        .attr('stroke', '#58a6ff')
        .call(d3.drag()
            .on('start', dragstarted)
            .on('drag', dragged)
            .on('end', dragended));

    const text = svg.append('g')
        .selectAll('text')
        .data(nodes)
        .join('text')
        .text(d => d.id)
        .attr('fill', '#c9d1d9')
        .attr('font-size', '10px')
        .attr('text-anchor', 'middle')
        .attr('dy', 4);

    simulation.on('tick', () => {
        link
            .attr('x1', d => d.source.x)
            .attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x)
            .attr('y2', d => d.target.y);

        node
            .attr('cx', d => d.x)
            .attr('cy', d => d.y);

        text
            .attr('x', d => d.x)
            .attr('y', d => d.y);
    });

    function dragstarted(event, d) {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
    }

    function dragged(event, d) {
        d.fx = event.x;
        d.fy = event.y;
    }

    function dragended(event, d) {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
    }
}