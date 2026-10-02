"use client";

import React, { useState, useEffect, useCallback, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import { useRole } from "@/context/RoleContext";
import {
  safeFetchIndicators,
  safeFetchMitreAnalytics,
  safeFetchIndicatorGraph,
  safeFetchIndicatorRelationships,
  safeFetchIndicatorEnrichment,
  safeHuntingSearch,
  safeDeriveRelationships,
} from "@/lib/api";
import { HuntingGraph } from "@/components/HuntingGraph";

function ThreatHuntingContent() {
  const { persona, role } = useRole();
  const searchParams = useSearchParams();
  const urlQuery = searchParams.get("q") || "";

  const [query, setQuery] = useState(urlQuery);
  const [searching, setSearching] = useState(false);
  const [searchResults, setSearchResults] = useState<any[]>([]);

  const [activeIndicator, setActiveIndicator] = useState<any | null>(null);
  const [selectedNode, setSelectedNode] = useState<any | null>(null);

  const [graphData, setGraphData] = useState<any | null>(null);
  const [graphLoading, setGraphLoading] = useState(false);
  const [graphError, setGraphError] = useState<string | null>(null);

  const [directRels, setDirectRels] = useState<any | null>(null);
  const [enrichment, setEnrichment] = useState<any | null>(null);

  const [maxDepth, setMaxDepth] = useState<number>(2);
  const [minConfidence, setMinConfidence] = useState<number>(0);

  const [isDeriving, setIsDeriving] = useState(false);
  const [deriveFeedback, setDeriveFeedback] = useState<string | null>(null);

  const [indicators, setIndicators] = useState<any[]>([]);
  const [mitreData, setMitreData] = useState<any>(null);
  const [activeTechnique, setActiveTechnique] = useState<string>("");

  // Load initial indicator list and MITRE analytics
  useEffect(() => {
    async function loadInitial() {
      const [iocs, mitre] = await Promise.all([
        safeFetchIndicators(),
        safeFetchMitreAnalytics(),
      ]);
      setIndicators(iocs || []);
      setMitreData(mitre);
      if (mitre?.techniques?.length > 0) {
        setActiveTechnique(mitre.techniques[0].id);
      }

      // If initial indicator exists and no URL query, select first indicator
      if (!urlQuery && iocs && iocs.length > 0 && !activeIndicator) {
        setActiveIndicator(iocs[0]);
      }
    }
    loadInitial();
  }, [urlQuery]);

  // Load graph, direct relationships, and enrichment whenever activeIndicator changes
  const loadIndicatorData = useCallback(async (ind: any) => {
    if (!ind || !ind.id) return;
    setGraphLoading(true);
    setGraphError(null);

    try {
      const [graph, rels, enrich] = await Promise.all([
        safeFetchIndicatorGraph(ind.id, maxDepth, minConfidence),
        safeFetchIndicatorRelationships(ind.id, "both", minConfidence),
        safeFetchIndicatorEnrichment(ind.id),
      ]);

      setGraphData(graph);
      setDirectRels(rels);
      setEnrichment(enrich);
      setSelectedNode(ind);
    } catch (err: any) {
      setGraphError(err?.message || "Failed to load indicator graph");
    } finally {
      setGraphLoading(false);
    }
  }, [maxDepth, minConfidence]);

  useEffect(() => {
    if (activeIndicator) {
      loadIndicatorData(activeIndicator);
    }
  }, [activeIndicator, loadIndicatorData]);

  // Run search
  const executeSearch = useCallback(async (searchStr: string) => {
    if (!searchStr.trim()) {
      setSearchResults([]);
      return;
    }
    setSearching(true);
    try {
      const res = await safeHuntingSearch(searchStr.trim());
      if (res && res.items) {
        setSearchResults(res.items);
        if (res.items.length === 1) {
          setActiveIndicator(res.items[0]);
        }
      } else {
        setSearchResults([]);
      }
    } catch {
      setSearchResults([]);
    } finally {
      setSearching(false);
    }
  }, []);

  // Handle URL query on load
  useEffect(() => {
    if (urlQuery) {
      setQuery(urlQuery);
      executeSearch(urlQuery);
    }
  }, [urlQuery, executeSearch]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    executeSearch(query);
  };

  // Node selection & graph pivoting
  const handleSelectNode = (node: any) => {
    setSelectedNode(node);
  };

  const handlePivotNode = (node: any) => {
    setActiveIndicator(node);
    setSelectedNode(node);
  };

  // Trigger authentic evidence derivation
  const handleDerive = async () => {
    setIsDeriving(true);
    setDeriveFeedback(null);
    try {
      const res = await safeDeriveRelationships(activeIndicator?.id);
      if (res && res.data) {
        const count = res.data.derived_count ?? 0;
        setDeriveFeedback(`Successfully discovered ${count} authentic evidence relationships.`);
        // Reload current graph
        if (activeIndicator) {
          loadIndicatorData(activeIndicator);
        }
      } else {
        setDeriveFeedback("Relationship derivation completed.");
      }
    } catch {
      setDeriveFeedback("Derivation requires Analyst permissions or experienced an error.");
    } finally {
      setIsDeriving(false);
      setTimeout(() => setDeriveFeedback(null), 5000);
    }
  };

  const techniques = mitreData?.techniques || [];
  const hasMitreData = mitreData?.has_data ?? false;
  const mappedIndicators = indicators.filter(
    (ioc) => ioc.mitre_technique && ioc.mitre_technique.toLowerCase().includes(activeTechnique.toLowerCase())
  );

  return (
    <div className="space-y-6 pb-12">
      {/* Header Banner */}
      <div className="bg-[#0b1220] border border-slate-800 rounded-2xl p-5 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="text-xl font-bold text-slate-100 flex items-center gap-2">
              🎯 Advanced Threat Hunting &amp; Relationship Graph
            </span>
            <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-purple-950/80 text-purple-400 border border-purple-800">
              {persona.name} ({persona.title})
            </span>
          </div>
          <p className="text-xs text-slate-400">
            Adversary infrastructure graph traversal, bounded multi-hop pivoting, and authentic evidence telemetry.
          </p>
        </div>

        {/* Derive Relationships Button */}
        <div className="flex items-center gap-3">
          {deriveFeedback && (
            <span className="text-[11px] font-mono text-cyan-400 animate-pulse bg-cyan-950/60 px-3 py-1 rounded-lg border border-cyan-800">
              {deriveFeedback}
            </span>
          )}
          <button
            onClick={handleDerive}
            disabled={isDeriving}
            className="flex items-center gap-2 px-3.5 py-1.5 rounded-xl bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white text-xs font-bold transition shadow-md shadow-purple-950/40 cursor-pointer"
            title="Scan DNS resolutions, URL hosts, and incident co-occurrences for real links"
          >
            {isDeriving ? (
              <>
                <span className="w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                <span>Deriving Evidence...</span>
              </>
            ) : (
              <>
                <span>⚡</span>
                <span>Discover Relationships</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Hunting Query Bar */}
      <div className="bg-[#0b1220] border border-slate-800 rounded-2xl p-4 shadow-sm space-y-3">
        <form onSubmit={handleSearchSubmit} className="flex flex-col md:flex-row items-center gap-3">
          <div className="relative flex-1 w-full">
            <span className="absolute inset-y-0 left-0 flex items-center pl-3 text-slate-500 text-sm">
              🔍
            </span>
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Hunt IOC value, IP, domain, URL, hash, or ATT&CK technique (e.g. 198.51.100.1, evil.com, T1071)..."
              className="w-full bg-[#080d19] border border-slate-700/80 rounded-xl pl-9 pr-8 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-all font-mono"
            />
            {query && (
              <button
                type="button"
                onClick={() => { setQuery(""); setSearchResults([]); }}
                className="absolute inset-y-0 right-0 flex items-center pr-3 text-slate-500 hover:text-slate-300 text-xs"
              >
                ✕
              </button>
            )}
          </div>

          {/* Depth Control */}
          <div className="flex items-center gap-1.5 bg-[#080d19] border border-slate-800 px-3 py-1.5 rounded-xl text-xs">
            <span className="text-slate-400 font-semibold text-[11px]">Hops:</span>
            {[1, 2, 3, 4].map((d) => (
              <button
                key={d}
                type="button"
                onClick={() => setMaxDepth(d)}
                className={`px-2 py-0.5 rounded font-mono font-bold text-xs transition ${
                  maxDepth === d
                    ? "bg-cyan-500 text-slate-950"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                {d}
              </button>
            ))}
          </div>

          {/* Min Confidence Control */}
          <div className="flex items-center gap-2 bg-[#080d19] border border-slate-800 px-3 py-1.5 rounded-xl text-xs">
            <span className="text-slate-400 font-semibold text-[11px]">Min Conf:</span>
            <select
              value={minConfidence}
              onChange={(e) => setMinConfidence(Number(e.target.value))}
              className="bg-transparent text-cyan-400 font-mono font-bold focus:outline-none cursor-pointer text-xs"
            >
              <option value="0" className="bg-[#0b1220] text-slate-200">0% (All)</option>
              <option value="50" className="bg-[#0b1220] text-slate-200">50%+</option>
              <option value="75" className="bg-[#0b1220] text-slate-200">75%+</option>
              <option value="90" className="bg-[#0b1220] text-slate-200">90%+</option>
            </select>
          </div>

          <button
            type="submit"
            disabled={searching}
            className="px-5 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-bold transition shadow-sm cursor-pointer whitespace-nowrap"
          >
            {searching ? "Hunting..." : "Hunt Target"}
          </button>
        </form>

        {/* Search Results Dropdown/Chips */}
        {searchResults.length > 0 && (
          <div className="pt-2 border-t border-slate-800/80">
            <div className="flex items-center justify-between pb-1.5">
              <span className="text-[11px] font-mono text-slate-400">
                Found {searchResults.length} matching indicator targets:
              </span>
            </div>
            <div className="flex flex-wrap gap-2 max-h-24 overflow-y-auto">
              {searchResults.map((item) => {
                const isActive = activeIndicator?.id === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => setActiveIndicator(item)}
                    className={`flex items-center gap-2 px-2.5 py-1 rounded-lg text-xs font-mono transition border ${
                      isActive
                        ? "bg-cyan-950/80 border-cyan-500 text-cyan-300 font-bold"
                        : "bg-[#080d19] border-slate-800 text-slate-300 hover:border-slate-700"
                    }`}
                  >
                    <span>{item.value}</span>
                    <span className="text-[10px] px-1 py-0.2 rounded bg-slate-800 text-slate-400">
                      {item.type}
                    </span>
                    {item.relationships_count > 0 && (
                      <span className="text-[10px] px-1 py-0.2 rounded bg-purple-950 text-purple-400 border border-purple-800">
                        {item.relationships_count} rels
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        )}
      </div>

      {/* Main Grid: Graph + Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Left 8 Cols: Graph Visualization + MITRE ATT&CK */}
        <div className="lg:col-span-8 space-y-6">
          <div className="bg-[#0b1220] border border-slate-800 rounded-2xl p-5 space-y-4 shadow-sm">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                  <span>🕸️</span> Bounded Indicator Relationship Graph
                </h2>
                <p className="text-xs text-slate-400">
                  {activeIndicator
                    ? `Visualizing ${activeIndicator.type?.toUpperCase()} target: ${activeIndicator.value}`
                    : "Select or search an IOC to render relationship topology"}
                </p>
              </div>

              {activeIndicator && (
                <div className="flex items-center gap-2">
                  <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300">
                    Focal: {activeIndicator.value?.length > 20 ? `${activeIndicator.value.slice(0, 18)}…` : activeIndicator.value}
                  </span>
                </div>
              )}
            </div>

            {/* Interactive Graph Canvas */}
            <HuntingGraph
              graphData={graphData}
              loading={graphLoading}
              error={graphError}
              selectedNodeId={selectedNode?.id || null}
              onSelectNode={handleSelectNode}
              onPivotNode={handlePivotNode}
            />
          </div>

          {/* MITRE ATT&CK Heatmap (Preserved & Grounded) */}
          <div className="bg-[#0b1220] border border-slate-800 rounded-2xl p-5 space-y-4 shadow-sm">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                  <span>🎯</span> MITRE ATT&amp;CK Technique Heatmap
                </h2>
                <p className="text-xs text-slate-400">
                  {hasMitreData
                    ? `Correlated technique density across ${mitreData.total_indicators_tagged} tagged indicators`
                    : "Live MITRE technique correlation"}
                </p>
              </div>
              <span className="text-[10px] font-mono bg-purple-950/80 text-purple-400 border border-purple-800 px-2 py-0.5 rounded">
                ATT&amp;CK Matrix
              </span>
            </div>

            {!hasMitreData || techniques.length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-500 font-mono bg-[#080d19] border border-slate-800 rounded-xl space-y-1">
                <p>⚠️ {mitreData?.message || "No MITRE ATT&CK techniques observed in ingested threat telemetry"}</p>
                <p className="text-[10px] text-slate-600">Technique IDs are extracted during ingestion and enrichment.</p>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {techniques.map((tech: any) => {
                  const isSelected = activeTechnique === tech.id;
                  return (
                    <div
                      key={tech.id}
                      onClick={() => setActiveTechnique(tech.id)}
                      className={`p-3.5 rounded-xl border cursor-pointer transition ${
                        isSelected
                          ? "bg-purple-950/40 border-purple-500 shadow-md shadow-purple-950/50"
                          : "bg-[#080d19] border-slate-800/80 hover:border-slate-700"
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-mono font-bold text-purple-400">{tech.id}</span>
                        <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-purple-950/80 text-purple-300 border border-purple-800">
                          {tech.count} IOCs
                        </span>
                      </div>
                      <div className="text-xs font-bold text-slate-100 pt-1.5">{tech.name}</div>
                      <div className="text-[10px] text-slate-400 pt-0.5">{tech.tactic}</div>
                    </div>
                  );
                })}
              </div>
            )}

            {activeTechnique && (
              <div className="pt-2">
                <h3 className="text-xs font-bold text-slate-300 pb-2">
                  Target IOCs mapped to {activeTechnique} ({mappedIndicators.length} matching):
                </h3>
                <div className="space-y-1.5 max-h-40 overflow-y-auto pr-1">
                  {mappedIndicators.length === 0 ? (
                    <div className="text-[11px] text-slate-500 font-mono p-2">
                      No active indicators currently match technique filter {activeTechnique}.
                    </div>
                  ) : (
                    mappedIndicators.slice(0, 10).map((ioc: any, i: number) => (
                      <div
                        key={i}
                        onClick={() => { setActiveIndicator(ioc); setSelectedNode(ioc); }}
                        className="flex items-center justify-between p-2 rounded-lg bg-[#080d19] border border-slate-800/60 text-xs font-mono cursor-pointer hover:border-cyan-500 transition"
                      >
                        <span className="text-slate-200 truncate max-w-[280px]">{ioc.value}</span>
                        <span className="text-cyan-400 font-bold">Investigate Graph →</span>
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Right 4 Cols: Selected Node Inspector & Telemetry */}
        <div className="lg:col-span-4 space-y-6">
          {/* Node Inspector Card */}
          <div className="bg-[#0b1220] border border-slate-800 rounded-2xl p-5 space-y-4 shadow-sm">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <span>🔍</span> Target Node Inspector
              </h2>
              {selectedNode && (
                <button
                  onClick={() => handlePivotNode(selectedNode)}
                  className="px-2 py-0.5 bg-cyan-950 hover:bg-cyan-900 border border-cyan-700 text-cyan-300 text-[10px] font-mono font-bold rounded transition cursor-pointer"
                >
                  Pivot as Root ⟳
                </button>
              )}
            </div>

            {selectedNode ? (
              <div className="space-y-4">
                {/* Main Node Header */}
                <div className="p-3.5 rounded-xl bg-[#080d19] border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono uppercase font-bold text-cyan-400">
                      {selectedNode.type}
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded font-bold border bg-slate-900 text-slate-200">
                      {selectedNode.severity || "MEDIUM"}
                    </span>
                  </div>
                  <p className="font-mono text-xs text-slate-100 font-bold break-all select-all">
                    {selectedNode.value}
                  </p>
                  <div className="grid grid-cols-2 gap-2 pt-1 text-[10px] font-mono border-t border-slate-800/80">
                    <span className="text-slate-400">Threat Score: <strong className="text-slate-200">{selectedNode.threat_score ?? 0}/100</strong></span>
                    <span className="text-slate-400">Status: <strong className="text-emerald-400">{selectedNode.status || "active"}</strong></span>
                    <span className="text-slate-400">Sightings: <strong className="text-slate-200">{selectedNode.sightings ?? 1}</strong></span>
                    <span className="text-slate-400">TLP: <strong className="text-amber-400 uppercase">{selectedNode.tlp || "amber"}</strong></span>
                  </div>
                </div>

                {/* Direct Relationships List */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xs font-bold text-slate-200">Connected Relationships</h3>
                    <span className="text-[10px] font-mono text-purple-400">
                      {directRels?.total ?? 0} direct links
                    </span>
                  </div>

                  {!directRels || directRels.items?.length === 0 ? (
                    <div className="p-3 rounded-xl bg-[#080d19] border border-slate-800 text-[11px] text-slate-500 font-mono text-center">
                      No direct relationships recorded yet.
                    </div>
                  ) : (
                    <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                      {directRels.items.map((rel: any) => {
                        const isOutgoing = rel.source_indicator_id === selectedNode.id;
                        const otherInd = isOutgoing ? rel.target_indicator : rel.source_indicator;
                        return (
                          <div
                            key={rel.id}
                            onClick={() => otherInd && handlePivotNode(otherInd)}
                            className="p-2.5 rounded-xl bg-[#080d19] border border-slate-800/80 hover:border-purple-500/70 transition cursor-pointer text-xs space-y-1"
                          >
                            <div className="flex items-center justify-between">
                              <span className="text-[10px] font-mono font-bold text-purple-400">
                                {isOutgoing ? "→" : "←"} {rel.relationship_type}
                              </span>
                              <span className="text-[9px] font-mono text-slate-400 bg-slate-900 px-1.5 py-0.5 rounded">
                                Conf: {rel.confidence}%
                              </span>
                            </div>
                            <p className="font-mono text-slate-200 truncate text-[11px]">
                              {otherInd?.value || "Target Indicator"}
                            </p>
                            {rel.evidence && (
                              <p className="text-[9.5px] text-slate-400 italic line-clamp-1">
                                {rel.evidence}
                              </p>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>

                {/* Threat Intelligence Enrichment Summary */}
                <div className="space-y-2">
                  <h3 className="text-xs font-bold text-slate-200">Threat Intel Enrichment</h3>
                  {enrichment && enrichment.length > 0 ? (
                    <div className="p-3 rounded-xl bg-[#080d19] border border-slate-800 space-y-2 text-xs">
                      {enrichment.slice(0, 2).map((item: any, idx: number) => (
                        <div key={idx} className="space-y-1 border-b border-slate-800/80 last:border-0 pb-1.5">
                          <div className="flex items-center justify-between">
                            <span className="font-bold text-cyan-400">{item.provider}</span>
                            <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-red-950 text-red-300">
                              {item.verdict?.toUpperCase() || "UNKNOWN"}
                            </span>
                          </div>
                          <div className="text-[10px] font-mono text-slate-400 flex justify-between">
                            <span>Malicious: {item.malicious_count || 0}</span>
                            <span>Reputation: {item.reputation ?? "N/A"}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="p-3 rounded-xl bg-[#080d19] border border-slate-800 text-[11px] text-slate-500 font-mono text-center">
                      No enrichment records available.
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className="p-8 text-center text-xs text-slate-500 font-mono">
                Click any node in the graph to inspect its properties and connected edges.
              </div>
            )}
          </div>

          {/* Quick Hunting Query Library */}
          <div className="bg-[#0b1220] border border-slate-800 rounded-2xl p-5 space-y-4 shadow-sm">
            <div>
              <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <span>⚡</span> Pre-Packaged Hunting Queries
              </h2>
              <p className="text-xs text-slate-400">Adversary search presets</p>
            </div>

            <div className="space-y-2.5">
              {[
                { label: "Critical C2 Domains", q: "type:domain severity:CRITICAL", val: "domain" },
                { label: "Exploited Web Services", q: "mitre:T1190 type:cve", val: "T1190" },
                { label: "Beaconing IP Infrastructure", q: "type:ip status:active", val: "ip" },
              ].map((preset, idx) => (
                <div
                  key={idx}
                  onClick={() => { setQuery(preset.val); executeSearch(preset.val); }}
                  className="p-3 rounded-xl bg-[#080d19] border border-slate-800/80 hover:border-cyan-500/70 cursor-pointer transition space-y-1"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-200">{preset.label}</span>
                    <span className="text-[9px] font-mono text-cyan-400">Run →</span>
                  </div>
                  <div className="text-[10px] font-mono text-slate-500 bg-slate-900/80 px-2 py-0.5 rounded">
                    {preset.q}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}

export default function ThreatHuntingPage() {
  return (
    <Suspense
      fallback={
        <div className="w-full h-96 flex items-center justify-center text-xs text-slate-500 font-mono">
          Loading Threat Hunting Workspace...
        </div>
      }
    >
      <ThreatHuntingContent />
    </Suspense>
  );
}
