import { useEffect, useRef } from 'react';
import * as d3 from 'd3';

export default function AgentGraph({ agents }) {
  const svgRef = useRef(null);

  useEffect(() => {
    if (!agents || agents.length === 0 || !svgRef.current) return;

    const width = svgRef.current.clientWidth || 600;
    const height = 400;

    // Build nodes and links
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

    // Clear previous
    d3.select(svgRef.current).selectAll('*').remove();

    const svg = d3.select(svgRef.current)
      .attr('viewBox', [0, 0, width, height]);

    // Arrow marker
    svg.append('defs').append('marker')
      .attr('id', 'arrowhead')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 25)
      .attr('refY', 0)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', '#475569');

    const simulation = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(links).id(d => d.id).distance(120))
      .force('charge', d3.forceManyBody().strength(-300))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(d => d.radius + 10));

    const link = svg.append('g')
      .selectAll('line')
      .data(links)
      .join('line')
      .attr('stroke', '#475569')
      .attr('stroke-width', 2)
      .attr('marker-end', 'url(#arrowhead)');

    const node = svg.append('g')
      .selectAll('g')
      .data(nodes)
      .join('g')
      .call(d3.drag()
        .on('start', (event, d) => {
          if (!event.active) simulation.alphaTarget(0.3).restart();
          d.fx = d.x; d.fy = d.y;
        })
        .on('drag', (event, d) => { d.fx = event.x; d.fy = event.y; })
        .on('end', (event, d) => {
          if (!event.active) simulation.alphaTarget(0);
          d.fx = null; d.fy = null;
        })
      );

    // Circles
    node.append('circle')
      .attr('r', d => d.radius)
      .attr('fill', d => {
        if (d.role && d.role.toLowerCase().includes('supervis')) return '#3b82f6';
        if (d.role && d.role.toLowerCase().includes('retriev')) return '#8b5cf6';
        return '#64748b';
      })
      .attr('stroke', '#1e293b')
      .attr('stroke-width', 2);

    // Labels
    node.append('text')
      .text(d => d.id)
      .attr('text-anchor', 'middle')
      .attr('dy', d => d.radius + 16)
      .attr('fill', '#94a3b8')
      .attr('font-size', '11px');

    // Tool count
    node.append('text')
      .text(d => d.tools.length > 0 ? `${d.tools.length} tools` : '')
      .attr('text-anchor', 'middle')
      .attr('dy', d => d.radius + 28)
      .attr('fill', '#64748b')
      .attr('font-size', '9px');

    simulation.on('tick', () => {
      link
        .attr('x1', d => d.source.x)
        .attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x)
        .attr('y2', d => d.target.y);
      node.attr('transform', d => `translate(${d.x},${d.y})`);
    });

    return () => simulation.stop();
  }, [agents]);

  if (!agents || agents.length === 0) {
    return <div className="text-slate-500 text-sm">No agents discovered.</div>;
  }

  return (
    <div className="bg-slate-800 rounded-lg border border-slate-700 p-4">
      <h3 className="text-sm font-semibold text-slate-300 mb-3">Agent Topology</h3>
      <svg ref={svgRef} className="w-full" style={{ height: 400 }} />
    </div>
  );
}
