"use client";

import React, { useState, useEffect } from "react";
import { useRole } from "@/context/RoleContext";
import { safeFetchIndicators } from "@/lib/api";

export default function IncidentResponsePage() {
  const { persona } = useRole();
  const [indicators, setIndicators] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [reportGenerated, setReportGenerated] = useState(false);

  useEffect(() => {
    async function loadIOCs() {
      setLoading(true);
      const items = await safeFetchIndicators();
      setIndicators(items);
      setLoading(false);
    }
    loadIOCs();
  }, []);

  const handleGenerateReport = async () => {
    try {
      let res = null;
      try {
        res = await fetch("http://127.0.0.1:8000/api/v1/export/stix");
      } catch {
        res = await fetch("http://localhost:8000/api/v1/export/stix");
      }

      if (res && res.ok) {
        const stixData = await res.json();
        const blob = new Blob([JSON.stringify(stixData, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = `INC-2026-0815-STIX2.1-Bundle.json`;
        link.click();
        URL.revokeObjectURL(url);
      } else {
        throw new Error("API fallback");
      }
    } catch {
      const mockBundle = { type: "bundle", spec_version: "2.1", objects: indicators };
      const blob = new Blob([JSON.stringify(mockBundle, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `INC-2026-0815-STIX2.1-Bundle.json`;
      link.click();
      URL.revokeObjectURL(url);
    } finally {
      setReportGenerated(true);
      setTimeout(() => setReportGenerated(false), 3500);
    }
  };

  return (
    <div className="space-y-6 pb-12">
      <div className="bg-[#0b1220] border border-slate-800 rounded-2xl p-5 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="text-xl font-bold text-slate-100 flex items-center gap-2">
              ⚠️ Incident Workspace: INC-2026-0815
            </span>
            <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-orange-950/80 text-orange-400 border border-orange-800">
              {persona.name} ({persona.title})
            </span>
          </div>
          <p className="text-xs text-slate-400">
            Active SEV-1: Suspected Emotet C2 Ingress via Workstation Subnet · Auto-correlated with 6 intelligence feeds.
          </p>
        </div>

        <button
          onClick={handleGenerateReport}
          className="bg-orange-600 hover:bg-orange-500 text-white font-bold px-4 py-2 rounded-xl text-xs flex items-center gap-2 shadow-sm transition"
        >
          <span>📦</span>
          <span>{reportGenerated ? "STIX 2.1 Exported!" : "Export STIX 2.1 Dossier"}</span>
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Forensic Timeline */}
        <div className="lg:col-span-7 bg-[#0b1220] border border-slate-800 rounded-2xl p-5 space-y-4 shadow-sm">
          <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <span>⏱️</span> Chronological Forensic Timeline
          </h2>
          <div className="space-y-3">
            <div className="p-3 rounded-xl bg-[#080d19] border-l-4 border-l-red-500 border border-slate-800/80 space-y-1">
              <div className="flex items-center justify-between text-xs">
                <span className="font-bold text-red-400">High-Severity C2 Beacon Detected</span>
                <span className="font-mono text-[10px] text-slate-400">18:42:10 UTC</span>
              </div>
              <p className="text-xs text-slate-300">Internal endpoint <code>10.0.4.18</code> established TCP connection to blacklisted C2 IP <code>185.220.101.4</code>.</p>
            </div>

            <div className="p-3 rounded-xl bg-[#080d19] border-l-4 border-l-orange-500 border border-slate-800/80 space-y-1">
              <div className="flex items-center justify-between text-xs">
                <span className="font-bold text-orange-400">Automated Scoring &amp; Enrichment</span>
                <span className="font-mono text-[10px] text-slate-400">18:42:15 UTC</span>
              </div>
              <p className="text-xs text-slate-300">ThreatLens scoring engine assigned composite severity <strong>92/100</strong>.</p>
            </div>
          </div>
        </div>

        {/* Right Column: Containment Checklist */}
        <div className="lg:col-span-5 bg-[#0b1220] border border-slate-800 rounded-2xl p-5 space-y-4 shadow-sm">
          <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <span>🛡️</span> Containment Checklist
          </h2>
          <div className="space-y-2.5 text-xs">
            <label className="flex items-center gap-3 p-2.5 rounded-lg bg-[#080d19] border border-slate-800/80 cursor-pointer">
              <input type="checkbox" defaultChecked className="rounded accent-orange-500" />
              <span className="text-slate-200">Isolate host <code>host-wkstn-04</code> at EDR layer</span>
            </label>
            <label className="flex items-center gap-3 p-2.5 rounded-lg bg-[#080d19] border border-slate-800/80 cursor-pointer">
              <input type="checkbox" defaultChecked className="rounded accent-orange-500" />
              <span className="text-slate-200">Push edge firewall block for <code>185.220.101.4</code></span>
            </label>
          </div>
        </div>
      </div>
    </div>
  );
}