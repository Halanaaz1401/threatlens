"use client";

import React, { useState, useEffect } from "react";
import { useRole } from "@/context/RoleContext";
import { safeFetchIndicators, safeFetchMitreAnalytics } from "@/lib/api";

export default function ThreatHuntingPage() {
  const { persona } = useRole();
  const [indicators, setIndicators] = useState<any[]>([]);
  const [mitreData, setMitreData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [activeTechnique, setActiveTechnique] = useState<string>("");

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      const [iocs, mitre] = await Promise.all([
        safeFetchIndicators(),
        safeFetchMitreAnalytics(),
      ]);
      setIndicators(iocs);
      setMitreData(mitre);
      if (mitre && mitre.techniques && mitre.techniques.length > 0) {
        setActiveTechnique(mitre.techniques[0].id);
      }
      setLoading(false);
    }
    loadData();
  }, []);

  const techniques = mitreData?.techniques || [];
  const hasData = mitreData?.has_data ?? false;

  const mappedIndicators = indicators.filter(
    (ioc) => ioc.mitre_technique && ioc.mitre_technique.toLowerCase().includes(activeTechnique.toLowerCase())
  );

  return (
    <div className="space-y-6 pb-12">
      <div className="bg-[#0b1220] border border-slate-800 rounded-2xl p-5 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="text-xl font-bold text-slate-100 flex items-center gap-2">
              🎯 Threat Hunting &amp; Adversary Pivoting
            </span>
            <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-purple-950/80 text-purple-400 border border-purple-800">
              {persona.name} ({persona.title})
            </span>
          </div>
          <p className="text-xs text-slate-400">
            Exploratory ATT&amp;CK technique matrix, node relationship correlation, and telemetry pivoting.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-8 bg-[#0b1220] border border-slate-800 rounded-2xl p-5 space-y-4 shadow-sm">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <span>🕸️</span> MITRE ATT&amp;CK Technique Heatmap
              </h2>
              <p className="text-xs text-slate-400">
                {hasData
                  ? `Correlated technique density across ${mitreData.total_indicators_tagged} tagged indicators`
                  : "Live MITRE technique correlation"}
              </p>
            </div>
            <span className="text-[10px] font-mono bg-purple-950/80 text-purple-400 border border-purple-800 px-2 py-0.5 rounded">
              ATT&amp;CK Matrix
            </span>
          </div>

          {loading ? (
            <div className="p-12 text-center text-xs text-slate-500 font-mono animate-pulse">
              Querying MITRE ATT&amp;CK telemetry...
            </div>
          ) : !hasData || techniques.length === 0 ? (
            <div className="p-8 text-center text-xs text-slate-500 font-mono bg-[#080d19] border border-slate-800 rounded-xl space-y-2">
              <p>⚠️ {mitreData?.message || "No MITRE ATT&CK techniques observed in ingested threat telemetry"}</p>
              <p className="text-[10px] text-slate-600">Feed normalizer automatically tags ATT&amp;CK technique IDs during ingestion.</p>
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
              <div className="space-y-1.5 max-h-44 overflow-y-auto pr-1">
                {mappedIndicators.length === 0 ? (
                  <div className="text-[11px] text-slate-500 font-mono p-2">
                    No active indicators currently match technique filter {activeTechnique}.
                  </div>
                ) : (
                  mappedIndicators.slice(0, 10).map((ioc: any, i: number) => (
                    <div key={i} className="flex items-center justify-between p-2 rounded-lg bg-[#080d19] border border-slate-800/60 text-xs font-mono">
                      <span className="text-slate-200 truncate max-w-[280px]">{ioc.value}</span>
                      <span className="text-red-400 font-bold">{ioc.severity_score}/100</span>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>

        <div className="lg:col-span-4 bg-[#0b1220] border border-slate-800 rounded-2xl p-5 space-y-4 shadow-sm">
          <div>
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <span>🎯</span> Active Threat Hunting Queries
            </h2>
            <p className="text-xs text-slate-400">Database-backed exploratory queries</p>
          </div>

          <div className="space-y-3">
            <div className="p-3.5 rounded-xl bg-[#080d19] border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-200">High-Severity C2 Ingress</span>
                <span className="text-[10px] font-mono text-purple-400 bg-purple-950 px-2 py-0.5 rounded border border-purple-800">
                  Active Filter
                </span>
              </div>
              <div className="text-[11px] font-mono text-slate-400 bg-slate-900/90 px-2.5 py-1 rounded border border-slate-800">
                type:ip severity:CRITICAL
              </div>
            </div>

            <div className="p-3.5 rounded-xl bg-[#080d19] border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-200">Weaponized Web Exploits</span>
                <span className="text-[10px] font-mono text-purple-400 bg-purple-950 px-2 py-0.5 rounded border border-purple-800">
                  Active Filter
                </span>
              </div>
              <div className="text-[11px] font-mono text-slate-400 bg-slate-900/90 px-2.5 py-1 rounded border border-slate-800">
                type:cve mitre:T1190
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
