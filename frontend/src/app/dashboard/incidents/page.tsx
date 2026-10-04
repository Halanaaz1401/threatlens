"use client";

import React, { useState, useEffect } from "react";
import { useRole } from "@/context/RoleContext";
import { safeFetchIndicators, safeFetchIncidents, safeFetchIncidentTimeline, getApiBaseUrl } from "@/lib/api";
import { getAuthHeaders } from "@/lib/auth";


export default function IncidentResponsePage() {
  const { persona } = useRole();
  const [indicators, setIndicators] = useState<any[]>([]);
  const [incidents, setIncidents] = useState<any[]>([]);
  const [activeIncident, setActiveIncident] = useState<any | null>(null);
  const [timeline, setTimeline] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [reportGenerated, setReportGenerated] = useState(false);

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      const [iocs, incList] = await Promise.all([
        safeFetchIndicators(),
        safeFetchIncidents()
      ]);
      setIndicators(iocs);
      setIncidents(incList);

      if (incList && incList.length > 0) {
        const topInc = incList[0];
        setActiveIncident(topInc);
        const tl = await safeFetchIncidentTimeline(topInc.id);
        setTimeline(tl);
      }
      setLoading(false);
    }
    loadData();
  }, []);

  const handleGenerateReport = async () => {
    const incCode = activeIncident?.incident_code || "INC-2026-0815";
    try {
      let res = null;
      const headers = { ...getAuthHeaders() };
      const baseUrl = getApiBaseUrl();
      res = await fetch(`${baseUrl}/api/v1/export/stix`, { headers });


      if (res && res.ok) {
        const stixData = await res.json();
        const blob = new Blob([JSON.stringify(stixData, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = `${incCode}-STIX2.1-Bundle.json`;
        link.click();
        URL.revokeObjectURL(url);
      } else {
        throw new Error("API fallback");
      }
    } catch {
      const bundle = { type: "bundle", spec_version: "2.1", objects: indicators };
      const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `${incCode}-STIX2.1-Bundle.json`;
      link.click();
      URL.revokeObjectURL(url);
    } finally {
      setReportGenerated(true);
      setTimeout(() => setReportGenerated(false), 3500);
    }
  };

  const incCode = activeIncident?.incident_code || "INC-2026-0815";
  const incTitle = activeIncident?.title || "Suspected Emotet C2 Ingress via Workstation Subnet";
  const incSeverity = activeIncident?.severity || "HIGH";
  const incStatus = activeIncident?.status || "OPEN";
  const alertCount = activeIncident?.alerts_count || 2;
  const primaryIoc = activeIncident?.primary_indicator || activeIncident?.matched_ioc_value || "185.220.101.4";

  return (
    <div className="space-y-6 pb-12">
      <div className="bg-[#0b1220] border border-slate-800 rounded-2xl p-5 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="text-xl font-bold text-slate-100 flex items-center gap-2">
              ⚠️ Incident Workspace: {incCode}
            </span>
            <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-orange-950/80 text-orange-400 border border-orange-800">
              {persona.name} ({persona.title})
            </span>
            <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${
              incSeverity === "CRITICAL" ? "bg-red-950 text-red-400 border-red-800" : "bg-amber-950 text-amber-400 border-amber-800"
            }`}>
              {incSeverity} · {incStatus}
            </span>
          </div>
          <p className="text-xs text-slate-400">
            {incTitle} · Correlated from {alertCount} active alerts with threat telemetry.
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
            {timeline && timeline.length > 0 ? (
              timeline.map((entry, idx) => (
                <div
                  key={entry.id || idx}
                  className={`p-3 rounded-xl bg-[#080d19] border-l-4 ${
                    entry.action?.includes("ESCALATED") || entry.action?.includes("CRITICAL")
                      ? "border-l-red-500"
                      : "border-l-orange-500"
                  } border border-slate-800/80 space-y-1`}
                >
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-bold text-slate-200">{entry.action}</span>
                    <span className="font-mono text-[10px] text-slate-400">
                      {entry.created_at ? new Date(entry.created_at).toLocaleTimeString() : "Recent"}
                    </span>
                  </div>
                  <p className="text-xs text-slate-300">{entry.details || "Automated telemetry event recorded."}</p>
                  <div className="text-[10px] text-slate-400">Actor: {entry.actor}</div>
                </div>
              ))
            ) : (
              <>
                <div className="p-3 rounded-xl bg-[#080d19] border-l-4 border-l-red-500 border border-slate-800/80 space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-bold text-red-400">High-Severity C2 Beacon Detected</span>
                    <span className="font-mono text-[10px] text-slate-400">18:42:10 UTC</span>
                  </div>
                  <p className="text-xs text-slate-300">Internal endpoint established communication with malicious IOC <code>{primaryIoc}</code>.</p>
                </div>

                <div className="p-3 rounded-xl bg-[#080d19] border-l-4 border-l-orange-500 border border-slate-800/80 space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-bold text-orange-400">Automated Scoring &amp; Incident Correlation</span>
                    <span className="font-mono text-[10px] text-slate-400">18:42:15 UTC</span>
                  </div>
                  <p className="text-xs text-slate-300">ThreatLens correlation engine created incident cluster for {primaryIoc}.</p>
                </div>
              </>
            )}
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
              <span className="text-slate-200">Isolate affected internal host at EDR layer</span>
            </label>
            <label className="flex items-center gap-3 p-2.5 rounded-lg bg-[#080d19] border border-slate-800/80 cursor-pointer">
              <input type="checkbox" defaultChecked className="rounded accent-orange-500" />
              <span className="text-slate-200">Push edge firewall block for <code>{primaryIoc}</code></span>
            </label>
            <label className="flex items-center gap-3 p-2.5 rounded-lg bg-[#080d19] border border-slate-800/80 cursor-pointer">
              <input type="checkbox" className="rounded accent-orange-500" />
              <span className="text-slate-200">Revoke associated session tokens and credentials</span>
            </label>
            <label className="flex items-center gap-3 p-2.5 rounded-lg bg-[#080d19] border border-slate-800/80 cursor-pointer">
              <input type="checkbox" className="rounded accent-orange-500" />
              <span className="text-slate-200">Trigger SIEM correlation rule backtrace (last 48h)</span>
            </label>
          </div>
        </div>
      </div>
    </div>
  );
}