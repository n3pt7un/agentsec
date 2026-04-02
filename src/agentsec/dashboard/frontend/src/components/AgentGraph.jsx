import { useEffect, useRef } from 'react';
import * as d3 from 'd3';

function getCssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

export default function AgentGraph({ agents }) {
  const svgRef = useRef(null);

  useEffect(() => {
    if (!agents || agents.length === 0 || !svgRef.current) return;

    const width = svgRef.current.clientWidth || 600;
    const height = 400;

    // Read theme-aware colors at render time
    const colBgRaised  = getCssVar('--bg-surface-raised') || '#111111';
    const colBorderGrn = getCssVar('--border-green')      || '#1a2a1a';
    const colAccent    = getCssVar('--accent')             || '#22c55e';
    const colTextMuted = getCssVar('--text-secondary')     || '#6b7280';
    const colEdge      = getCssVar('--accent-dim')         || '#166534';

    const COL_RETRIEVER = '#60a5fa'; // blue accent for retriever-type nodes, intentional non-token

    const nodeColor = (d) => {
      const role = (d.role || '').toLowerCase();
      if (role.includes('supervis')) return colAccent;
      if (role.includes('retriev'))  return COL_RETRIEVER;
      return colBgRaised;
    };

    const nodes = agents.map(a => ({
      id: a.name,
      role: a.role,
      tools: a.tools || [],
      radius: 20 + (a.tools?.length || 0) * 5,
    }));

    const nodeIds = new Set(nodes.map(n => n.id));
    const links = [];
    for (const agent of agents) {
      for (const downstream of (agent.downstream_agents || [])) {
        if (nodeIds.has(downstream)) {
          links.push({ source: agent.name, target: downstream });
        }
      }
    }

    d3.select(svgRef.current).selectAll('*').remove();

    const svg = d3.select(svgRef.current)
      .attr('viewBox', [0, 0, width, height]);

    svg.append('defs').append('marker')
      .attr('id', 'arrowhead')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 25).attr('refY', 0)
      .attr('markerWidth', 6).attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', colEdge);

    const simulation = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(links).id(d => d.id).distance(120))
      .force('charge', d3.forceManyBody().strength(-300))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(d => d.radius + 10));

    const link = svg.append('g')
      .selectAll('line').data(links).join('line')
      .attr('stroke', colEdge)
      .attr('stroke-width', 1)
      .attr('opacity', 0.6)
      .attr('marker-end', 'url(#arrowhead)');

    const node = svg.append('g')
      .selectAll('g').data(nodes).join('g')
      .call(d3.drag()
        .on('start', (e, d) => { if (!e.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
        .on('drag',  (e, d) => { d.fx = e.x; d.fy = e.y; })
        .on('end',   (e, d) => { if (!e.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; })
      );

    node.append('circle')
      .attr('r', d => d.radius)
      .attr('fill', d => nodeColor(d))
      .attr('stroke', colBorderGrn)
      .attr('stroke-width', 1);

    node.append('text')
      .text(d => d.id)
      .attr('text-anchor', 'middle')
      .attr('dy', d => d.radius + 16)
      .attr('fill', colTextMuted)
      .attr('font-size', '11px')
      .attr('font-family', 'IBM Plex Mono, monospace');

    node.append('text')
      .text(d => d.tools.length > 0 ? `${d.tools.length} tools` : '')
      .attr('text-anchor', 'middle')
      .attr('dy', d => d.radius + 28)
      .attr('fill', colEdge)
      .attr('font-size', '9px')
      .attr('font-family', 'IBM Plex Sans, sans-serif');

    simulation.on('tick', () => {
      link
        .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
      node.attr('transform', d => `translate(${d.x},${d.y})`);
    });

    return () => simulation.stop();
  }, [agents]);

  if (!agents || agents.length === 0) {
    return (
      <p style={{ fontSize: '13px', color: 'var(--text-muted)', fontFamily: 'var(--font-sans)' }}>
        No agents discovered.
      </p>
    );
  }

  return (
    <div style={{
      background: 'var(--bg-surface)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius)',
      padding: '16px',
    }}>
      <h3 style={{
        fontSize: '11px',
        fontWeight: 600,
        color: 'var(--text-muted)',
        marginBottom: '12px',
        fontFamily: 'var(--font-sans)',
        textTransform: 'uppercase',
        letterSpacing: '0.08em',
      }}>
        Agent Topology
      </h3>
      <svg ref={svgRef} style={{ width: '100%', height: 400 }} />
    </div>
  );
}
