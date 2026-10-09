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
  CRITICAL: { bg: "#1f1416", border: "#f87171", text: "#fca5a5", glow: "rgba(248,113,113,0.3)" },
  HIGH: { bg: "#221915", border: "#fb923c", text: "#fdba74", glow: "rgba(251,146,60,0.25)" },
  MEDIUM: { bg: "#221f15", border: "#fbbf24", text: "#fde68a", glow: "rgba(251,191,36,0.2)" },
  LOW: { bg: "#14171d", border: "#64748b", text: "#cbd5e1", glow: "rgba(100,116,139,0.2)" },
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
      <div className="w-full h-[520px] bg-[#090A0C] border border-[#2B2C30] rounded-xl flex flex-col items-center justify-center p-8 space-y-4">
        <div className="w-9 h-9 border-2 border-[#19D5E5]/20 border-t-[#19D5E5] rounded-full animate-spin" />
        <div className="text-center space-y-1">
          <p className="text-xs font-mono font-bold text-[#F2F2F0]">Traversing Indicator Relationship Graph</p>
          <p className="text-[11px] text-[#72747A] font-mono">Resolving bounded multi-hop graph topology...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="w-full h-[520px] bg-[#090A0C] border border-red-900/60 rounded-xl flex flex-col items-center justify-center p-8 space-y-3">
        <span className="text-2xl text-red-400">⚠️</span>
        <div className="text-center space-y-1 max-w-md">
          <p className="text-xs font-mono font-bold text-red-400">Graph Query Error</p>
          <p className="text-[11px] text-[#A5A6AA]">{error}</p>
        </div>
      </div>
    );
  }

  if (!graphData || graphData.nodes.length === 0) {
    return (
      <div className="w-full h-[520px] bg-[#090A0C] border border-[#2B2C30] rounded-xl flex flex-col items-center justify-center p-8 space-y-3">
        <span className="text-2xl text-[#72747A]">🕸️</span>
        <div className="text-center space-y-1 max-w-md">
          <p className="text-xs font-mono font-bold text-[#F2F2F0]">No Indicator Selected For Graph Analysis</p>
          <p className="text-[11px] text-[#72747A]">
            Use the Hunting Query Bar above to search an IOC, or select a target indicator from the list to traverse its relationship graph.
          </p>
        </div>
      </div>
    );
  }

  const isSingleNode = graphData.nodes.length === 1 && graphData.edges.length === 0;

  return (
    <div className="relative w-full h-[520px] bg-[#090A0C] border border-[#2B2C30] rounded-xl overflow-hidden shadow-inner flex items-center justify-center">
      {/* Background Grid Pattern */}
      <svg className="absolute inset-0 w-full h-full opacity-30 pointer-events-none" xmlns="http://www.w3.org/2000/svg">
        <defs>
          <pattern id="graph-grid" width="32" height="32" patternUnits="userSpaceOnUse">
            <path d="M 32 0 L 0 0 0 32" fill="none" stroke="#202125" strokeWidth="0.8" />
          </pattern>
        </defs>
        <rect width="100%" height="100%" fill="url(#graph-grid)" />
      </svg>

      {/* Technical corner coordinate markings */}
      <div className="absolute top-3 right-3 text-[10px] font-mono text-[#72747A] tracking-wider pointer-events-none">
        GRAPH // TOPOLOGY 2D
      </div>

      {/* Graph Statistics Watermark */}
      <div className="absolute top-3 left-3 z-10 flex items-center gap-2 text-[10px] font-mono">
        <span className="px-2.5 py-1 bg-[#111214] border border-[#2B2C30] rounded text-[#19D5E5] font-bold">
          Nodes: {graphData.total_nodes}
        </span>
        <span className="px-2.5 py-1 bg-[#111214] border border-[#2B2C30] rounded text-[#A5A6AA] font-bold">
          Edges: {graphData.total_edges}
        </span>
        <span className="px-2.5 py-1 bg-[#111214] border border-[#2B2C30] rounded text-[#72747A]">
          Depth: {graphData.depth_reached} / {graphData.max_depth}
        </span>
      </div>

      {/* Single Node Isolated Banner */}
      {isSingleNode && (
        <div className="absolute bottom-3 left-3 right-3 z-10 p-2.5 rounded-lg bg-[#17181B] border border-amber-900/60 text-[11px] text-amber-300 flex items-center justify-between">
          <span>⚠️ Isolated Node: No known relationships recorded in the threat graph yet.</span>
          <span className="font-mono text-[10px] text-amber-400">Click &apos;Discover Relationships&apos; to link evidence</span>
        </div>
      )}

      {/* SVG Canvas with data-graph attribute for E2E tests */}
      <svg
        data-graph="hunting-topology"
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
            <path d="M 0 1 L 10 5 L 0 9 z" fill="#72747A" />
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
            <path d="M 0 1 L 10 5 L 0 9 z" fill="#19D5E5" />
          </marker>
        </defs>

        {/* Orbit Guideline Circles */}
        <circle cx={centerX} cy={centerY} r={Math.min(width, height) * 0.28} fill="none" stroke="#202125" strokeDasharray="4 4" strokeWidth="1" />
        <circle cx={centerX} cy={centerY} r={Math.min(width, height) * 0.42} fill="none" stroke="#17181B" strokeDasharray="4 4" strokeWidth="1" />

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
                  stroke={isHovered ? "#19D5E5" : "#2B2C30"}
                  strokeWidth={isHovered ? 2 : 1}
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
                    rx="4"
                    fill="#111214"
                    stroke={isHovered ? "#19D5E5" : "#2B2C30"}
                    strokeWidth="1"
                  />
                  <text
                    textAnchor="middle"
                    dominantBaseline="central"
                    fill={isHovered ? "#19D5E5" : "#A5A6AA"}
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
            const radius = isRoot ? 24 : 18;

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
                {/* Outer Halo for Selected or Root */}
                {(isSelected || isRoot || isHovered) && (
                  <circle
                    r={radius + 5}
                    fill="none"
                    stroke={isSelected ? "#19D5E5" : isRoot ? "#F2F2F0" : sevColor.border}
                    strokeWidth={isSelected ? 2 : 1.5}
                    opacity="0.8"
                  />
                )}

                {/* Node Main Circle */}
                <circle
                  r={radius}
                  fill={sevColor.bg}
                  stroke={isSelected ? "#19D5E5" : sevColor.border}
                  strokeWidth={isRoot ? 2 : 1}
                />

                {/* Node Center Icon */}
                <text
                  textAnchor="middle"
                  dominantBaseline="central"
                  fontSize={isRoot ? "13" : "10"}
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
                    rx="3"
                    fill="#111214"
                    stroke={isSelected ? "#19D5E5" : "#2B2C30"}
                    strokeWidth="0.8"
                  />
                  <text
                    textAnchor="middle"
                    dominantBaseline="central"
                    fill={isSelected ? "#19D5E5" : "#F2F2F0"}
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
        <div className="absolute bottom-3 right-3 z-20 bg-[#111214]/95 border border-[#19D5E5] p-3 rounded-lg shadow-xl max-w-xs space-y-1.5 backdrop-blur text-xs">
          <div className="flex items-center justify-between gap-2">
            <span className="font-mono text-[#19D5E5] font-bold uppercase">{hoveredNode.type}</span>
            <span
              className="text-[10px] font-bold px-1.5 py-0.5 rounded font-mono"
              style={{
                backgroundColor: SEVERITY_COLORS[hoveredNode.severity]?.bg || "#17181B",
                color: SEVERITY_COLORS[hoveredNode.severity]?.text || "#A5A6AA",
              }}
            >
              {hoveredNode.severity}
            </span>
          </div>
          <p className="font-mono text-[#F2F2F0] font-semibold truncate">{hoveredNode.value}</p>
          <div className="text-[10px] text-[#A5A6AA] flex items-center justify-between border-t border-[#2B2C30] pt-1">
            <span>Score: {hoveredNode.threat_score ?? "N/A"}/100</span>
            {hoveredNode.mitre_technique && (
              <span className="text-[#F2F2F0] font-mono">{hoveredNode.mitre_technique}</span>
            )}
          </div>
          <p className="text-[9px] text-[#19D5E5] italic">Double-click node to pivot graph</p>
        </div>
      )}

      {/* Floating Edge Tooltip */}
      {hoveredEdge && (
        <div className="absolute bottom-3 right-3 z-20 bg-[#111214]/95 border border-[#2B2C30] p-3 rounded-lg shadow-xl max-w-sm space-y-1 backdrop-blur text-xs">
          <div className="flex items-center justify-between gap-2">
            <span className="font-mono text-[#F2F2F0] font-bold">{hoveredEdge.relationship_type}</span>
            <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-[#17181B] text-[#A5A6AA] border border-[#2B2C30] font-mono">
              Conf: {hoveredEdge.confidence}%
            </span>
          </div>
          {hoveredEdge.evidence && (
            <p className="text-[11px] text-[#A5A6AA] font-sans italic">{hoveredEdge.evidence}</p>
          )}
          <p className="text-[10px] text-[#72747A] font-mono">Source: {hoveredEdge.source || "automated"}</p>
        </div>
      )}
    </div>
  );
}

export default HuntingGraph;
