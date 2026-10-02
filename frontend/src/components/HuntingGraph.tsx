"use client";

import React, { useMemo, useState } from "react";

interface NodeData {
  id: string;
  value: string;
  type: string;
  severity: string;
  threat_score?: number;
  confidence?: number;
  status?: string;
  tlp?: string;
  mitre_technique?: string;
  is_root?: boolean;
}

interface EdgeData {
  id: string;
  source_indicator_id: string;
  target_indicator_id: string;
  relationship_type: string;
  confidence: number;
  evidence?: string;
  source?: string;
}

interface HuntingGraphProps {
  graphData: {
    root_id: string;
    nodes: NodeData[];
    edges: EdgeData[];
    max_depth: number;
    depth_reached: number;
    total_nodes: number;
    total_edges: number;
  } | null;
  loading: boolean;
  error: string | null;
  selectedNodeId: string | null;
  onSelectNode: (node: NodeData) => void;
  onPivotNode: (node: NodeData) => void;
}

const TYPE_ICONS: Record<string, string> = {
  ip: "🌐",
  domain: "🏢",
  url: "🔗",
  cve: "🛡️",
  hash_md5: "🔑",
  hash_sha256: "🔑",
  email: "✉️",
};

const SEVERITY_COLORS: Record<string, { bg: string; border: string; text: string; glow: string }> = {
  CRITICAL: { bg: "#450a0a", border: "#ef4444", text: "#fca5a5", glow: "rgba(239,68,68,0.4)" },
  HIGH: { bg: "#431407", border: "#f97316", text: "#fdba74", glow: "rgba(249,115,22,0.3)" },
  MEDIUM: { bg: "#422006", border: "#eab308", text: "#fde047", glow: "rgba(234,179,8,0.3)" },
  LOW: { bg: "#0f172a", border: "#3b82f6", text: "#93c5fd", glow: "rgba(59,130,246,0.2)" },
};

export function HuntingGraph({
  graphData,
  loading,
  error,
  selectedNodeId,
  onSelectNode,
  onPivotNode,
}: HuntingGraphProps) {
  const [hoveredNode, setHoveredNode] = useState<NodeData | null>(null);
  const [hoveredEdge, setHoveredEdge] = useState<EdgeData | null>(null);

  const width = 800;
  const height = 520;
  const centerX = width / 2;
  const centerY = height / 2;

  // Deterministic circular layout without Math.random()
  const { nodePositions, edgesWithCoords } = useMemo(() => {
    if (!graphData || !graphData.nodes || graphData.nodes.length === 0) {
      return { nodePositions: new Map<string, { x: number; y: number }>(), edgesWithCoords: [] };
    }

    const positions = new Map<string, { x: number; y: number }>();
    const rootId = graphData.root_id;

    // Separate root and other nodes
    const rootNode = graphData.nodes.find((n) => n.id === rootId) || graphData.nodes[0];
    const otherNodes = graphData.nodes.filter((n) => n.id !== rootNode?.id);

    // Place root at exact center
    if (rootNode) {
      positions.set(rootNode.id, { x: centerX, y: centerY });
    }

    // Partition remaining nodes into 1-hop and 2+-hop based on direct edges to root
    const directToRootIds = new Set<string>();
    graphData.edges.forEach((e) => {
      if (e.source_indicator_id === rootNode?.id) directToRootIds.add(e.target_indicator_id);
      if (e.target_indicator_id === rootNode?.id) directToRootIds.add(e.source_indicator_id);
    });

    const tier1Nodes = otherNodes.filter((n) => directToRootIds.has(n.id));
    const tier2Nodes = otherNodes.filter((n) => !directToRootIds.has(n.id));

    // Place Tier 1 in inner circle
    const r1 = Math.min(width, height) * 0.28;
    tier1Nodes.forEach((node, idx) => {
      const angle = (2 * Math.PI * idx) / (tier1Nodes.length || 1) - Math.PI / 2;
      positions.set(node.id, {
        x: centerX + r1 * Math.cos(angle),
        y: centerY + r1 * Math.sin(angle),
      });
    });

    // Place Tier 2 in outer circle with offset
    const r2 = Math.min(width, height) * 0.42;
    tier2Nodes.forEach((node, idx) => {
      const angle = (2 * Math.PI * idx) / (tier2Nodes.length || 1) - Math.PI / 4;
      positions.set(node.id, {
        x: centerX + r2 * Math.cos(angle),
        y: centerY + r2 * Math.sin(angle),
      });
    });

    // Map edges with coordinates
    const edgesCoords = graphData.edges
      .map((edge) => {
        const src = positions.get(edge.source_indicator_id);
        const tgt = positions.get(edge.target_indicator_id);
        if (!src || !tgt) return null;
        return {
          ...edge,
          x1: src.x,
          y1: src.y,
          x2: tgt.x,
          y2: tgt.y,
          midX: (src.x + tgt.x) / 2,
          midY: (src.y + tgt.y) / 2,
        };
      })
      .filter(Boolean) as (EdgeData & { x1: number; y1: number; x2: number; y2: number; midX: number; midY: number })[];

    return { nodePositions: positions, edgesWithCoords: edgesCoords };
  }, [graphData, centerX, centerY, width, height]);

  if (loading) {
    return (
      <div className="w-full h-[520px] bg-[#070c18] border border-slate-800 rounded-2xl flex flex-col items-center justify-center p-8 space-y-4">
        <div className="w-10 h-10 border-4 border-cyan-500/30 border-t-cyan-400 rounded-full animate-spin" />
        <div className="text-center space-y-1">
          <p className="text-xs font-mono font-bold text-slate-200">Traversing Indicator Relationship Graph</p>
          <p className="text-[11px] text-slate-500 font-mono">Resolving bounded multi-hop graph topology...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="w-full h-[520px] bg-[#070c18] border border-red-900/50 rounded-2xl flex flex-col items-center justify-center p-8 space-y-3">
        <span className="text-3xl">⚠️</span>
        <div className="text-center space-y-1 max-w-md">
          <p className="text-xs font-mono font-bold text-red-400">Graph Query Error</p>
          <p className="text-[11px] text-slate-400">{error}</p>
        </div>
      </div>
    );
  }

  if (!graphData || graphData.nodes.length === 0) {
    return (
      <div className="w-full h-[520px] bg-[#070c18] border border-slate-800 rounded-2xl flex flex-col items-center justify-center p-8 space-y-3">
        <span className="text-3xl">🎯</span>
        <div className="text-center space-y-1 max-w-md">
          <p className="text-xs font-mono font-bold text-slate-300">No Indicator Selected For Graph Analysis</p>
          <p className="text-[11px] text-slate-500">
            Use the Hunting Query Bar above to search an IOC, or select a target indicator from the list below to traverse its relationship graph.
          </p>
        </div>
      </div>
    );
  }

  const isSingleNode = graphData.nodes.length === 1 && graphData.edges.length === 0;

  return (
    <div className="relative w-full h-[520px] bg-[#070c18] border border-slate-800 rounded-2xl overflow-hidden shadow-inner flex items-center justify-center">
      {/* Background Grid Pattern */}
      <svg className="absolute inset-0 w-full h-full opacity-20 pointer-events-none" xmlns="http://www.w3.org/2000/svg">
        <defs>
          <pattern id="graph-grid" width="32" height="32" patternUnits="userSpaceOnUse">
            <path d="M 32 0 L 0 0 0 32" fill="none" stroke="#1e293b" strokeWidth="0.8" />
          </pattern>
        </defs>
        <rect width="100%" height="100%" fill="url(#graph-grid)" />
      </svg>

      {/* Graph Statistics Watermark */}
      <div className="absolute top-4 left-4 z-10 flex items-center gap-2 text-[10px] font-mono">
        <span className="px-2.5 py-1 bg-slate-900/90 border border-slate-800 rounded-lg text-cyan-400 font-bold">
          Nodes: {graphData.total_nodes}
        </span>
        <span className="px-2.5 py-1 bg-slate-900/90 border border-slate-800 rounded-lg text-purple-400 font-bold">
          Edges: {graphData.total_edges}
        </span>
        <span className="px-2.5 py-1 bg-slate-900/90 border border-slate-800 rounded-lg text-slate-400">
          Depth: {graphData.depth_reached} / {graphData.max_depth}
        </span>
      </div>

      {/* Single Node Isolated Banner */}
      {isSingleNode && (
        <div className="absolute bottom-4 left-4 right-4 z-10 p-2.5 rounded-xl bg-amber-950/60 border border-amber-800/80 text-[11px] text-amber-300 flex items-center justify-between">
          <span>⚠️ Isolated Node: No known relationships recorded in the threat graph yet.</span>
          <span className="font-mono text-[10px] text-amber-400">Click &apos;Derive Relationships&apos; to link evidence</span>
        </div>
      )}

      {/* SVG Canvas */}
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="w-full h-full max-h-[520px] select-none"
        preserveAspectRatio="xMidYMid meet"
      >
        <defs>
          <marker
            id="arrow"
            viewBox="0 0 10 10"
            refX="22"
            refY="5"
            markerWidth="6"
            markerHeight="6"
            orient="auto-start-reverse"
          >
            <path d="M 0 1 L 10 5 L 0 9 z" fill="#64748b" />
          </marker>
          <marker
            id="arrow-hover"
            viewBox="0 0 10 10"
            refX="22"
            refY="5"
            markerWidth="6"
            markerHeight="6"
            orient="auto-start-reverse"
          >
            <path d="M 0 1 L 10 5 L 0 9 z" fill="#38bdf8" />
          </marker>
        </defs>

        {/* Orbit Guideline Circles */}
        <circle cx={centerX} cy={centerY} r={Math.min(width, height) * 0.28} fill="none" stroke="#1e293b" strokeDasharray="4 4" strokeWidth="1" />
        <circle cx={centerX} cy={centerY} r={Math.min(width, height) * 0.42} fill="none" stroke="#0f172a" strokeDasharray="4 4" strokeWidth="1" />

        {/* Relationship Edges */}
        <g className="edges">
          {edgesWithCoords.map((edge) => {
            const isHovered = hoveredEdge?.id === edge.id;
            return (
              <g
                key={edge.id}
                className="cursor-pointer transition-all duration-200"
                onMouseEnter={() => setHoveredEdge(edge)}
                onMouseLeave={() => setHoveredEdge(null)}
              >
                {/* Wide invisible path for easier hover */}
                <line
                  x1={edge.x1}
                  y1={edge.y1}
                  x2={edge.x2}
                  y2={edge.y2}
                  stroke="transparent"
                  strokeWidth="14"
                />
                {/* Visible Edge */}
                <line
                  x1={edge.x1}
                  y1={edge.y1}
                  x2={edge.x2}
                  y2={edge.y2}
                  stroke={isHovered ? "#38bdf8" : "#334155"}
                  strokeWidth={isHovered ? 2.5 : 1.2}
                  strokeDasharray={edge.confidence < 60 ? "4 3" : undefined}
                  markerEnd={isHovered ? "url(#arrow-hover)" : "url(#arrow)"}
                />
                {/* Edge Label Pill */}
                <g transform={`translate(${edge.midX}, ${edge.midY})`}>
                  <rect
                    x="-42"
                    y="-9"
                    width="84"
                    height="18"
                    rx="9"
                    fill="#0b1220"
                    stroke={isHovered ? "#38bdf8" : "#1e293b"}
                    strokeWidth="1"
                  />
                  <text
                    textAnchor="middle"
                    dominantBaseline="central"
                    fill={isHovered ? "#38bdf8" : "#94a3b8"}
                    fontSize="8.5"
                    fontFamily="monospace"
                    fontWeight="600"
                  >
                    {edge.relationship_type}
                  </text>
                </g>
              </g>
            );
          })}
        </g>

        {/* Indicator Nodes */}
        <g className="nodes">
          {graphData.nodes.map((node) => {
            const pos = nodePositions.get(node.id);
            if (!pos) return null;

            const isSelected = selectedNodeId === node.id;
            const isRoot = node.is_root || node.id === graphData.root_id;
            const isHovered = hoveredNode?.id === node.id;
            const sevColor = SEVERITY_COLORS[node.severity] || SEVERITY_COLORS.LOW;
            const icon = TYPE_ICONS[node.type] || "🔹";
            const radius = isRoot ? 26 : 20;

            return (
              <g
                key={node.id}
                transform={`translate(${pos.x}, ${pos.y})`}
                className="cursor-pointer group"
                onClick={() => onSelectNode(node)}
                onDoubleClick={() => onPivotNode(node)}
                onMouseEnter={() => setHoveredNode(node)}
                onMouseLeave={() => setHoveredNode(null)}
              >
                {/* Outer Glow Halo for Selected or Root */}
                {(isSelected || isRoot || isHovered) && (
                  <circle
                    r={radius + 6}
                    fill="none"
                    stroke={isSelected ? "#06b6d4" : isRoot ? "#a855f7" : sevColor.border}
                    strokeWidth={isSelected ? 3 : 2}
                    opacity="0.8"
                    className={isRoot ? "animate-pulse" : ""}
                  />
                )}

                {/* Node Main Circle */}
                <circle
                  r={radius}
                  fill={sevColor.bg}
                  stroke={isSelected ? "#06b6d4" : sevColor.border}
                  strokeWidth={isRoot ? 2.5 : 1.5}
                />

                {/* Node Center Icon */}
                <text
                  textAnchor="middle"
                  dominantBaseline="central"
                  fontSize={isRoot ? "14" : "11"}
                >
                  {icon}
                </text>

                {/* Node Text Label */}
                <g transform={`translate(0, ${radius + 12})`}>
                  <rect
                    x="-55"
                    y="-8"
                    width="110"
                    height="16"
                    rx="4"
                    fill="#080d19"
                    stroke={isSelected ? "#06b6d4" : "#1e293b"}
                    strokeWidth="0.8"
                  />
                  <text
                    textAnchor="middle"
                    dominantBaseline="central"
                    fill={isSelected ? "#38bdf8" : "#e2e8f0"}
                    fontSize="9"
                    fontFamily="monospace"
                    fontWeight="600"
                  >
                    {node.value.length > 15 ? `${node.value.slice(0, 14)}…` : node.value}
                  </text>
                </g>
              </g>
            );
          })}
        </g>
      </svg>

      {/* Floating Hover Tooltip */}
      {hoveredNode && (
        <div className="absolute bottom-4 right-4 z-20 bg-[#0b1220]/95 border border-cyan-500/70 p-3 rounded-xl shadow-xl max-w-xs space-y-1.5 backdrop-blur text-xs">
          <div className="flex items-center justify-between gap-2">
            <span className="font-mono text-cyan-400 font-bold uppercase">{hoveredNode.type}</span>
            <span
              className="text-[10px] font-bold px-1.5 py-0.5 rounded font-mono"
              style={{
                backgroundColor: SEVERITY_COLORS[hoveredNode.severity]?.bg || "#0f172a",
                color: SEVERITY_COLORS[hoveredNode.severity]?.text || "#94a3b8",
              }}
            >
              {hoveredNode.severity}
            </span>
          </div>
          <p className="font-mono text-slate-100 font-semibold truncate">{hoveredNode.value}</p>
          <div className="text-[10px] text-slate-400 flex items-center justify-between border-t border-slate-800 pt-1">
            <span>Score: {hoveredNode.threat_score ?? "N/A"}/100</span>
            {hoveredNode.mitre_technique && (
              <span className="text-purple-400 font-mono">{hoveredNode.mitre_technique}</span>
            )}
          </div>
          <p className="text-[9px] text-cyan-400 italic">Double-click node to pivot graph</p>
        </div>
      )}

      {/* Floating Edge Tooltip */}
      {hoveredEdge && (
        <div className="absolute bottom-4 right-4 z-20 bg-[#0b1220]/95 border border-purple-500/70 p-3 rounded-xl shadow-xl max-w-sm space-y-1 backdrop-blur text-xs">
          <div className="flex items-center justify-between gap-2">
            <span className="font-mono text-purple-400 font-bold">{hoveredEdge.relationship_type}</span>
            <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800 font-mono">
              Conf: {hoveredEdge.confidence}%
            </span>
          </div>
          {hoveredEdge.evidence && (
            <p className="text-[11px] text-slate-300 font-sans italic">{hoveredEdge.evidence}</p>
          )}
          <p className="text-[10px] text-slate-500 font-mono">Source: {hoveredEdge.source || "automated"}</p>
        </div>
      )}
    </div>
  );
}

export default HuntingGraph;
