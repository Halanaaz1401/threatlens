"use client";

import React, { useState, useEffect } from "react";
import { useRole } from "@/context/RoleContext";
import { safeFetchIndicators } from "@/lib/api";

export default function ThreatHuntingPage() {
  const { persona } = useRole();
  const [indicators, setIndicators] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTechnique, setActiveTechnique] = useState("T1071.001");
  const [savedHunts, setSavedHunts] = useState([
    { name: "C2 Ingress Beacons (Feodo / OTX)", query: "type:ip score:>=90", count: 12 },
    { name: "Active Weaponized CVE Exploits", query: "type:cve status:active", count: 4 },
  ]);

  useEffect(() => {
    async function loadIndicators() {
      setLoading(true);
      const items = await safeFetchIndicators();
      setIndicators(items);
      setLoading(false);
    }
    loadIndicators();
  }, []);

  const mitreTechniques = [
    { id: "T1071.001", name: "Web Protocols C2", tactic: "Command and Control", count: 14, severity: "High" },
    { id: "T1566.002", name: "Spearphishing Link", tactic: "Initial Access", count: 8, severity: "Critical" },
    { id: "T1090.003", name: "Multi-hop Proxy", tactic: "Command and Control", count: 6, severity: "High" },
    { id: "T1027", name: "Obfuscated Files/Info", tactic: "Defense Evasion", count: 11, severity: "Medium" },
    { id: "T1190", name: "Exploit Public-Facing App", tactic: "Initial Access", count: 3, severity: "Critical" },
  ];

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
            Exploratory ATT&amp;CK technique matrix, node relationship correlation, and persistent hunt creation.
          </p>
        </div>

        <button
          onClick={() => alert("Hunt query exported to SIEM detection rule")}
          className="bg-purple-600 hover:bg-purple-500 text-white font-bold px-4 py-2 rounded-xl text-xs shadow-sm transition"
        >
          Export Hunt to SIEM Rule &rarr;
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-8 bg-[#0b1220] border border-slate-800 rounded-2xl p-5 space-y-4 shadow-sm">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <span>🕸️</span> MITRE ATT&amp;CK Technique Heatmap
              </h2>
              <p className="text-xs text-slate-400">Correlated technique density across current threat landscape</p>
            </div>
            <span className="text-[10px] font-mono bg-purple-950/80 text-purple-400 border border-purple-800 px-2 py-0.5 rounded">
              ATT&amp;CK v14
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {mitreTechniques.map((tech) => {
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
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                      tech.severity === "Critical"
                        ? "bg-red-950/80 text-red-400 border border-red-800"
                        : "bg-orange-950/80 text-orange-400 border border-orange-800"
                    }`}>
                      {tech.count} IOCs
                    </span>
                  </div>
                  <div className="text-xs font-bold text-slate-100 pt-1.5">{tech.name}</div>
                  <div className="text-[10px] text-slate-400 pt-0.5">{tech.tactic}</div>
                </div>
              );
            })}
          </div>

          <div className="pt-2">
            <h3 className="text-xs font-bold text-slate-300 pb-2">Target IOCs mapped to {activeTechnique}:</h3>
            <div className="space-y-1.5 max-h-44 overflow-y-auto pr-1">
              {indicators.slice(0, 6).map((ioc: any, i: number) => (
                <div key={i} className="flex items-center justify-between p-2 rounded-lg bg-[#080d19] border border-slate-800/60 text-xs font-mono">
                  <span className="text-slate-200 truncate max-w-[280px]">{ioc.value}</span>
                  <span className="text-red-400 font-bold">{ioc.severity_score}/100</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="lg:col-span-4 bg-[#0b1220] border border-slate-800 rounded-2xl p-5 space-y-4 shadow-sm">
          <div>
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <span>💾</span> Persistent Threat Hunts
            </h2>
            <p className="text-xs text-slate-400">Saved exploratory search baselines</p>
          </div>

          <div className="space-y-3">
            {savedHunts.map((hunt, idx) => (
              <div key={idx} className="p-3.5 rounded-xl bg-[#080d19] border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-200">{hunt.name}</span>
                  <span className="text-[10px] font-mono text-purple-400 bg-purple-950 px-2 py-0.5 rounded border border-purple-800">{hunt.count} hits</span>
                </div>
                <div className="text-[11px] font-mono text-slate-400 bg-slate-900/90 px-2.5 py-1 rounded border border-slate-800">
                  {hunt.query}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
