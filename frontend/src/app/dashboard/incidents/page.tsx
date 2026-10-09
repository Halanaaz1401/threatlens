"use client";

import React, { useState, useEffect } from "react";
import { useRole } from "@/context/RoleContext";
import { safeFetchIndicators, safeFetchIncidents, safeFetchIncidentTimeline, getApiBaseUrl } from "@/lib/api";
import { getAuthHeaders } from "@/lib/auth";
import {
  ShieldAlert,
  Clock,
  Download,
  ArrowRight,
  CheckCircle2,
  ListChecks,
  Activity,
  AlertTriangle,
} from "lucide-react";

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
        safeFetchIncidents(),
      ]);
      setIndicators(iocs || []);
      setIncidents(incList || []);

      if (incList && incList.length > 0) {
        const topInc = incList[0];
        setActiveIncident(topInc);
        const tl = await safeFetchIncidentTimeline(topInc.id);
        setTimeline(tl || []);
      }
      setLoading(false);
    }
    loadData();
  }, []);

  const handleGenerateReport = async () => {
    const incCode = activeIncident?.incident_code || "INC-2026-0815";
    try {
      const headers = { ...getAuthHeaders() };
      const baseUrl = getApiBaseUrl();
      const res = await fetch(`${baseUrl}/api/v1/export/stix`, { headers });

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
      {/* Top Incident Summary Bar */}
      <div className="bg-[#111214] border border-[#2B2C30] rounded-xl p-5 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-lg font-bold text-[#F2F2F0]">
              Incident Workspace: {incCode}
            </h1>
            <span className="text-[10px] font-mono font-medium px-2 py-0.5 rounded bg-[#17181B] text-[#B0B0B4] border border-[#2B2C30]">
              {persona.name} ({persona.title})
            </span>
            <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded bg-[#17181B] border border-[#2B2C30] text-[#19D5E5]">
              {incSeverity} &bull; {incStatus}
            </span>
          </div>
          <p className="text-xs text-[#85858B] font-mono">
            {incTitle} &bull; Correlated from {alertCount} active alerts with threat telemetry.
          </p>
        </div>

        <button
          onClick={handleGenerateReport}
          className="bg-[#F2F2F0] hover:bg-white text-[#090A0C] font-semibold px-4 py-2 rounded-lg text-xs flex items-center gap-2 shadow-sm transition"
        >
          <Download className="w-3.5 h-3.5" />
          <span>{reportGenerated ? "STIX 2.1 Exported!" : "Export STIX 2.1 Dossier"}</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Left Column: Forensic Timeline */}
        <div className="lg:col-span-7 bg-[#111214] border border-[#2B2C30] rounded-xl p-5 space-y-4 shadow-sm">
          <h2 className="text-sm font-semibold text-[#F2F2F0] flex items-center gap-2">
            <Clock className="w-3.5 h-3.5 text-[#19D5E5]" />
            <span>Chronological Forensic Timeline</span>
          </h2>
          <div className="space-y-3">
            {timeline && timeline.length > 0 ? (
              timeline.map((entry, idx) => (
                <div
                  key={entry.id || idx}
                  className="p-3.5 rounded-lg bg-[#17181B] border border-[#2B2C30] space-y-1"
                >
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-semibold text-[#F2F2F0] font-mono">{entry.action}</span>
                    <span className="font-mono text-[10px] text-[#85858B]">
                      {entry.created_at ? new Date(entry.created_at).toLocaleTimeString() : "Recent"}
                    </span>
                  </div>
                  <p className="text-xs text-[#B0B0B4] leading-relaxed">{entry.details || "Automated telemetry event recorded."}</p>
                  <div className="text-[10px] text-[#85858B] font-mono">Actor: {entry.actor}</div>
                </div>
              ))
            ) : (
              <>
                <div className="p-3.5 rounded-lg bg-[#17181B] border border-[#2B2C30] space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-semibold text-red-400 font-mono">High-Severity C2 Beacon Detected</span>
                    <span className="font-mono text-[10px] text-[#85858B]">18:42:10 UTC</span>
                  </div>
                  <p className="text-xs text-[#B0B0B4]">
                    Internal endpoint established communication with malicious IOC <code className="text-[#19D5E5] font-mono">{primaryIoc}</code>.
                  </p>
                </div>

                <div className="p-3.5 rounded-lg bg-[#17181B] border border-[#2B2C30] space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-semibold text-[#19D5E5] font-mono">Automated Scoring &amp; Incident Correlation</span>
                    <span className="font-mono text-[10px] text-[#85858B]">18:42:15 UTC</span>
                  </div>
                  <p className="text-xs text-[#B0B0B4]">
                    ThreatLens correlation engine created incident cluster for {primaryIoc}.
                  </p>
                </div>
              </>
            )}
          </div>
        </div>

        {/* Right Column: Containment Checklist */}
        <div className="lg:col-span-5 bg-[#111214] border border-[#2B2C30] rounded-xl p-5 space-y-4 shadow-sm">
          <h2 className="text-sm font-semibold text-[#F2F2F0] flex items-center gap-2">
            <ListChecks className="w-3.5 h-3.5 text-[#19D5E5]" />
            <span>Containment Checklist</span>
          </h2>
          <div className="space-y-2.5 text-xs">
            <label className="flex items-center gap-3 p-3 rounded-lg bg-[#17181B] border border-[#2B2C30] cursor-pointer hover:border-[#42434A] transition">
              <input type="checkbox" defaultChecked className="rounded accent-[#19D5E5]" />
              <span className="text-[#F2F2F0]">Isolate affected internal host at EDR layer</span>
            </label>
            <label className="flex items-center gap-3 p-3 rounded-lg bg-[#17181B] border border-[#2B2C30] cursor-pointer hover:border-[#42434A] transition">
              <input type="checkbox" defaultChecked className="rounded accent-[#19D5E5]" />
              <span className="text-[#F2F2F0]">Push edge firewall block for <code className="text-[#19D5E5]">{primaryIoc}</code></span>
            </label>
            <label className="flex items-center gap-3 p-3 rounded-lg bg-[#17181B] border border-[#2B2C30] cursor-pointer hover:border-[#42434A] transition">
              <input type="checkbox" className="rounded accent-[#19D5E5]" />
              <span className="text-[#B0B0B4]">Revoke associated session tokens and credentials</span>
            </label>
            <label className="flex items-center gap-3 p-3 rounded-lg bg-[#17181B] border border-[#2B2C30] cursor-pointer hover:border-[#42434A] transition">
              <input type="checkbox" className="rounded accent-[#19D5E5]" />
              <span className="text-[#B0B0B4]">Trigger SIEM correlation rule backtrace (last 48h)</span>
            </label>
          </div>
        </div>
      </div>
    </div>
  );
}