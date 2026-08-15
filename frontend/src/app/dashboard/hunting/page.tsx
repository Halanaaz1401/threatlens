"use client";

import React, { useState } from "react";
import { 
  Target, 
  Search, 
  BookmarkPlus, 
  Tag, 
  Network, 
  Layers, 
  ShieldAlert, 
  ExternalLink,
  Info
} from "lucide-react";

interface NodeItem {
  id: string;
  label: string;
  type: "IOC" | "DOMAIN" | "ASN" | "ACTOR" | "MALWARE";
  x: number;
  y: number;
  details: string;
}

interface EdgeItem {
  from: string;
  to: string;
  relation: string;
}

export default function HuntingDashboard() {
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedTechnique, setSelectedTechnique] = useState("ALL");
  const [selectedNode, setSelectedNode] = useState<NodeItem | null>(null);

  const mitreTechniques = [
    { id: "T1071.001", name: "Web Protocols (C2)", count: 18 },
    { id: "T1566.001", name: "Spearphishing Attachment", count: 12 },
    { id: "T1059.001", name: "PowerShell Execution", count: 9 },
    { id: "T1110.003", name: "Password Spraying", count: 7 },
  ];

  const iocList = [
    { id: "node-1", value: "185.220.101.4", type: "IP", technique: "T1071.001", score: 94, source: "Feodo Tracker" },
    { id: "node-2", value: "malicious-invoice.doc.exe", type: "Hash (SHA256)", technique: "T1566.001", score: 88, source: "MalwareBazaar" },
    { id: "node-3", value: "auth-update-service.com", type: "Domain", technique: "T1071.001", score: 79, source: "URLhaus" },
    { id: "node-4", value: "invoke-mimikatz.ps1", type: "Script/Hash", technique: "T1059.001", score: 91, source: "AlienVault OTX" },
  ];

  // Interactive Graph Nodes & Edges
  const graphNodes: NodeItem[] = [
    { id: "n1", label: "185.220.101.4", type: "IOC", x: 180, y: 150, details: "Target C2 IP (Germany) - Feodo Tracker" },
    { id: "n2", label: "auth-update-service.com", type: "DOMAIN", x: 80, y: 60, details: "Fast-flux C2 domain resolving to IP" },
    { id: "n3", label: "AS206238", type: "ASN", x: 300, y: 70, details: "Autonomous System - Zwiebelfreunde e.V." },
    { id: "n4", label: "QakBot / CobaltStrike", type: "MALWARE", x: 90, y: 240, details: "Payload associated with beacon activity" },
    { id: "n5", label: "UNC2165 (Evil Corp)", type: "ACTOR", x: 290, y: 240, details: "Attributed Advanced Persistent Threat Actor" },
  ];

  const graphEdges: EdgeItem[] = [
    { from: "n2", to: "n1", relation: "resolves_to" },
    { from: "n1", to: "n3", relation: "hosted_on" },
    { from: "n4", to: "n1", relation: "communicates_with" },
    { from: "n5", to: "n4", relation: "operates" },
  ];

  const getNodeColor = (type: string) => {
    switch (type) {
      case "IOC":
        return "#ef4444"; // red
      case "DOMAIN":
        return "#38bdf8"; // cyan
      case "ASN":
        return "#a855f7"; // purple
      case "MALWARE":
        return "#f97316"; // orange
      case "ACTOR":
        return "#eab308"; // yellow
      default:
        return "#94a3b8";
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <Target className="h-6 w-6 text-purple-400" />
            Proactive Threat Hunting & ATT&CK Explorer
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            Persona: Mei Lin Tan (Threat Hunter) — Elasticsearch Querying & Adversary Pivoting
          </p>
        </div>

        <button
          onClick={() => alert("Hunt query saved as reusable detection rule.")}
          className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-purple-600 hover:bg-purple-500 text-xs font-mono font-medium text-white transition shadow-lg shadow-purple-600/20"
        >
          <BookmarkPlus className="h-4 w-4" />
          Save as Reusable Hunt
        </button>
      </div>

      {/* Full-text Search & MITRE Filters */}
      <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl space-y-4">
        <div className="relative">
          <Search className="absolute left-3.5 top-3 h-4 w-4 text-slate-500" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Elasticsearch query: IP, Hash, Domain, ASN, or MITRE ID..."
            className="w-full pl-10 pr-4 py-2 bg-slate-950 border border-slate-800 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-500/50 font-mono"
          />
        </div>

        {/* MITRE Technique Filters */}
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-mono text-slate-400 mr-2 flex items-center gap-1">
            <Tag className="h-3 w-3" /> ATT&CK Filter:
          </span>
          <button
            onClick={() => setSelectedTechnique("ALL")}
            className={`px-2.5 py-1 rounded text-xs font-mono border transition ${
              selectedTechnique === "ALL"
                ? "bg-purple-600/20 text-purple-300 border-purple-500/40"
                : "bg-slate-950 text-slate-400 border-slate-800 hover:bg-slate-800"
            }`}
          >
            All Techniques
          </button>
          {mitreTechniques.map((tech) => (
            <button
              key={tech.id}
              onClick={() => setSelectedTechnique(tech.id)}
              className={`px-2.5 py-1 rounded text-xs font-mono border transition ${
                selectedTechnique === tech.id
                  ? "bg-purple-600/20 text-purple-300 border-purple-500/40"
                  : "bg-slate-950 text-slate-400 border-slate-800 hover:bg-slate-800"
              }`}
            >
              {tech.id} - {tech.name} ({tech.count})
            </button>
          ))}
        </div>
      </div>

      {/* Main Grid: Discovered IOCs & Interactive Relationship Graph */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Discovered Indicators Column */}
        <div className="lg:col-span-5 p-5 bg-slate-900/60 border border-slate-800 rounded-xl space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <span className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <Layers className="h-4 w-4 text-purple-400" />
              Discovered Indicators ({iocList.length})
            </span>
            <span className="text-xs font-mono text-slate-500">Elasticsearch Indexed</span>
          </div>

          <div className="divide-y divide-slate-800/80 max-h-[380px] overflow-y-auto pr-1">
            {iocList
              .filter(
                (ioc) =>
                  (selectedTechnique === "ALL" || ioc.technique === selectedTechnique) &&
                  ioc.value.toLowerCase().includes(searchTerm.toLowerCase())
              )
              .map((ioc) => (
                <div
                  key={ioc.value}
                  onClick={() => {
                    const matchedNode = graphNodes.find((n) => n.label === ioc.value) || graphNodes[0];
                    setSelectedNode(matchedNode);
                  }}
                  className="py-3 px-2 rounded-lg hover:bg-slate-800/40 cursor-pointer transition flex items-center justify-between"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-mono text-white font-medium">{ioc.value}</span>
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                        {ioc.type}
                      </span>
                    </div>
                    <div className="text-xs font-mono text-slate-400">
                      Source: <span className="text-slate-300">{ioc.source}</span> | ATT&CK: <span className="text-purple-400">{ioc.technique}</span>
                    </div>
                  </div>
                  <div className="text-right">
                    <span className="text-[10px] font-mono text-slate-400 block">Score</span>
                    <span className="text-xs font-bold font-mono text-red-400">{ioc.score}/100</span>
                  </div>
                </div>
              ))}
          </div>
        </div>

        {/* Interactive Relationship Graph Visualizer */}
        <div className="lg:col-span-7 p-5 bg-slate-900/60 border border-slate-800 rounded-xl flex flex-col justify-between space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <div className="flex items-center gap-2">
              <Network className="h-4 w-4 text-purple-400" />
              <span className="text-sm font-semibold text-slate-200">Interactive Infrastructure Relationship Graph</span>
            </div>
            <span className="text-xs font-mono text-slate-400">Click any node to pivot</span>
          </div>

          {/* SVG Graph Canvas */}
          <div className="w-full h-[300px] bg-slate-950 rounded-lg border border-slate-800/80 relative overflow-hidden flex items-center justify-center">
            <svg className="w-full h-full" viewBox="0 0 380 300">
              {/* Edges */}
              {graphEdges.map((edge, idx) => {
                const source = graphNodes.find((n) => n.id === edge.from)!;
                const target = graphNodes.find((n) => n.id === edge.to)!;
                return (
                  <g key={idx}>
                    <line
                      x1={source.x}
                      y1={source.y}
                      x2={target.x}
                      y2={target.y}
                      stroke="#334155"
                      strokeWidth="1.5"
                      strokeDasharray="3 3"
                    />
                    <text
                      x={(source.x + target.x) / 2}
                      y={(source.y + target.y) / 2 - 4}
                      fill="#64748b"
                      fontSize="8"
                      fontFamily="monospace"
                      textAnchor="middle"
                    >
                      {edge.relation}
                    </text>
                  </g>
                );
              })}

              {/* Nodes */}
              {graphNodes.map((node) => {
                const isSelected = selectedNode?.id === node.id;
                return (
                  <g
                    key={node.id}
                    onClick={() => setSelectedNode(node)}
                    className="cursor-pointer transition-transform hover:scale-110"
                  >
                    <circle
                      cx={node.x}
                      cy={node.y}
                      r={isSelected ? 18 : 14}
                      fill="#0f172a"
                      stroke={getNodeColor(node.type)}
                      strokeWidth={isSelected ? 3 : 1.5}
                    />
                    <circle
                      cx={node.x}
                      cy={node.y}
                      r="4"
                      fill={getNodeColor(node.type)}
                    />
                    <text
                      x={node.x}
                      y={node.y + 22}
                      fill={isSelected ? "#ffffff" : "#94a3b8"}
                      fontSize="9"
                      fontFamily="monospace"
                      fontWeight={isSelected ? "bold" : "normal"}
                      textAnchor="middle"
                    >
                      {node.label.length > 18 ? node.label.slice(0, 15) + "..." : node.label}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>

          {/* Selected Node Details Card */}
          <div className="p-3 rounded-lg bg-purple-950/20 border border-purple-800/40 text-xs font-mono flex items-start gap-3">
            <Info className="h-4 w-4 text-purple-400 shrink-0 mt-0.5" />
            <div>
              {selectedNode ? (
                <div>
                  <span className="text-purple-300 font-bold">Node Selected: [{selectedNode.type}] {selectedNode.label}</span>
                  <p className="text-slate-300 mt-1">{selectedNode.details}</p>
                </div>
              ) : (
                <span className="text-slate-400">Click on any graph node or indicator above to inspect relationship metadata.</span>
              )}
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}