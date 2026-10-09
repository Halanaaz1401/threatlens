"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { useRole } from "@/context/RoleContext";
import {
  safeFetchAnalyticsOverview,
  safeFetchMitreAnalytics,
  safeGenerateExecutiveReport,
  safeFetchReports,
  getReportDownloadUrl
} from "@/lib/api";
import AnalyticsCharts from "@/components/AnalyticsCharts";

export default function ExecutiveDashboardPage() {
  const { persona } = useRole();
  const [overview, setOverview] = useState<any>(null);
  const [mitreData, setMitreData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState("24h");

  // Executive PDF Reporting
  const [reports, setReports] = useState<any[]>([]);
  const [generatingReport, setGeneratingReport] = useState(false);
  const [reportSuccessMsg, setReportSuccessMsg] = useState<string | null>(null);

  const loadReportsList = async () => {
    const list = await safeFetchReports();
    setReports(list || []);
  };

  const handleGeneratePdf = async () => {
    setGeneratingReport(true);
    setReportSuccessMsg(null);
    try {
      const rep = await safeGenerateExecutiveReport(timeRange);
      if (rep && rep.id) {
        setReportSuccessMsg(`Report ${rep.report_code} generated successfully.`);
        await loadReportsList();
      } else {
        setReportSuccessMsg("Failed to generate report. Ensure analyst or executive role.");
      }
    } catch (err: any) {
      setReportSuccessMsg(`Error: ${err.message || 'Generation failed'}`);
    } finally {
      setGeneratingReport(false);
    }
  };

  useEffect(() => {
    loadReportsList();
  }, []);

  useEffect(() => {
    async function loadAnalytics() {
      setLoading(true);
      const [ov, mitre] = await Promise.all([
        safeFetchAnalyticsOverview(timeRange),
        safeFetchMitreAnalytics(),
      ]);
      setOverview(ov);
      setMitreData(mitre);
      setLoading(false);
    }
    loadAnalytics();
  }, [timeRange]);

  const kpiData = overview?.kpis;
  const riskScore = kpiData?.enterprise_risk_score?.score ?? 0;
  const riskLevel = kpiData?.enterprise_risk_score?.level ?? "LOW";
  const mttdFormatted = kpiData?.mttd?.formatted ?? "N/A (insufficient alerts)";
  const mttrFormatted = kpiData?.mttr?.formatted ?? "N/A (no closed incidents)";
  const sev1Count = kpiData?.active_sev1_incidents?.count ?? 0;
  const totalOpenIncidents = kpiData?.active_sev1_incidents?.total_open_incidents ?? 0;

  const kpis = [
    {
      label: "Enterprise Risk Score",
      value: `${riskScore} / 100`,
      change: `${riskLevel} Risk Posture`,
      color: riskScore >= 70 ? "text-red-400" : (riskScore >= 40 ? "text-amber-400" : "text-emerald-400"),
      sub: "Calculated across active vectors & incidents"
    },
    {
      label: "Mean Time to Detect (MTTD)",
      value: mttdFormatted,
      change: "Automated Ingestion Pipeline",
      color: "text-cyan-400",
      sub: "Indicator first_seen to alert creation"
    },
    {
      label: "Mean Time to Respond (MTTR)",
      value: mttrFormatted,
      change: "Incident Containment Cycle",
      color: "text-emerald-400",
      sub: "Incident creation to containment timeline"
    },
    {
      label: "Active SEV-1 Incidents",
      value: `${sev1Count}`,
      change: `${totalOpenIncidents} Total Open Incidents`,
      color: sev1Count > 0 ? "text-red-400" : "text-amber-400",
      sub: "Under Active Containment"
    },
  ];

  const techniques = mitreData?.techniques || [];

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-[#111214] border border-[#2B2C30] rounded-xl p-5 shadow-sm">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <h1 className="text-lg font-bold text-[#F2F2F0] font-editorial-sans">
              Executive Risk Posture &amp; CISO Board Overview
            </h1>
            <span className="text-[10px] font-mono font-medium px-2 py-0.5 rounded bg-[#17181B] text-[#19D5E5] border border-[#2B2C30]">
              {persona.name} ({persona.title})
            </span>
          </div>
          <p className="text-xs text-[#72747A] font-mono">
            Authoritative exposure metrics, MTTD/MTTR operational performance, and real-time risk tracking.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleGeneratePdf}
            disabled={generatingReport}
            className="bg-[#F2F2F0] hover:bg-white text-[#090A0C] font-semibold px-4 py-2 rounded-lg text-xs flex items-center gap-2 shadow-sm transition disabled:opacity-50"
          >
            <span>{generatingReport ? "Compiling PDF..." : "Generate Executive PDF Report"}</span>
            <span className="font-mono text-sm">&rarr;</span>
          </button>
          <Link
            href="/"
            className="bg-[#17181B] hover:bg-[#202125] border border-[#2B2C30] text-[#A5A6AA] hover:text-[#F2F2F0] font-medium px-4 py-2 rounded-lg text-xs transition font-mono"
          >
            Home Hub &rarr;
          </Link>
        </div>
      </div>

      {/* Executive PDF Briefing Notice & Recent Reports List */}
      {(reportSuccessMsg || reports.length > 0) && (
        <div className="bg-[#111214] border border-[#2B2C30] rounded-xl p-4 space-y-3 shadow-sm text-xs font-mono">
          <div className="flex items-center justify-between gap-2">
            <span className="font-semibold text-[#F2F2F0] flex items-center gap-1.5 uppercase text-[11px]">
              <span>Generated Executive PDF Reports (FR-23)</span>
            </span>
            {reportSuccessMsg && (
              <span className="text-[#19D5E5] font-medium">{reportSuccessMsg}</span>
            )}
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {reports.slice(0, 3).map((r) => (
              <div key={r.id} className="bg-[#17181B] border border-[#2B2C30] rounded-lg p-3 flex items-center justify-between gap-2">
                <div className="space-y-0.5">
                  <div className="flex items-center gap-1.5">
                    <span className="font-mono font-bold text-[#F2F2F0]">{r.report_code}</span>
                    <span className="text-[10px] font-mono px-1 py-0.2 rounded bg-[#090A0C] text-[#A5A6AA] border border-[#2B2C30]">
                      {r.time_range}
                    </span>
                  </div>
                  <p className="text-[11px] text-[#72747A]">{new Date(r.created_at).toLocaleDateString()}</p>
                </div>
                <a
                  href={getReportDownloadUrl(r.id)}
                  download={r.file_name}
                  target="_blank"
                  rel="noreferrer"
                  className="bg-[#111214] hover:bg-[#202125] border border-[#2B2C30] text-[#F2F2F0] font-medium px-2.5 py-1.5 rounded text-xs transition"
                >
                  Download &darr;
                </a>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* CISO High-Level Metric Tiles */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {kpis.map((k, i) => (
          <div key={i} className="bg-[#111214] border border-[#2B2C30] hover:border-[#3F4046] rounded-xl p-5 space-y-2 shadow-sm transition">
            <span className="text-[11px] font-mono text-[#72747A] uppercase tracking-wider block">{k.label}</span>
            <div className="flex items-baseline justify-between">
              <span className="text-2xl font-bold font-editorial-sans text-[#F2F2F0]">{loading ? "..." : k.value}</span>
              <span className="text-[10px] font-mono text-[#A5A6AA] bg-[#17181B] px-1.5 py-0.5 rounded border border-[#2B2C30]">{k.change}</span>
            </div>
            <p className="text-[10px] text-[#72747A] font-mono pt-1 border-t border-[#202125]">{k.sub}</p>
          </div>
        ))}
      </div>

      {/* Real Recharts Visualization */}
      <AnalyticsCharts
        timeSeriesData={overview?.trends?.series}
        severityBreakdown={overview?.severity?.chart_data}
        loading={loading}
        timeRange={timeRange}
        onTimeRangeChange={setTimeRange}
      />

      {/* Deep Executive Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Left: Top Threat Technique Exposure */}
        <div className="lg:col-span-7 bg-[#0b1220] border border-slate-800 rounded-2xl p-5 space-y-4 shadow-sm">
          <h2 className="text-sm font-bold text-slate-200 flex items-center gap-2">
            <span>🎯</span> Observed Threat Technique Exposure (MITRE ATT&amp;CK)
          </h2>

          <div className="space-y-3">
            {techniques.length === 0 ? (
              <div className="p-8 text-center text-xs text-slate-500 font-mono bg-[#080d19] border border-slate-800 rounded-xl">
                {mitreData?.message || "No MITRE techniques tagged in current threat landscape"}
              </div>
            ) : (
              techniques.slice(0, 5).map((tech: any, idx: number) => (
                <div
                  key={idx}
                  className="bg-[#080d19] border border-slate-800/90 rounded-xl p-3.5 flex items-center justify-between hover:border-slate-700 transition"
                >
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-bold text-slate-200">{tech.name}</span>
                      <span className="text-[9px] font-mono px-1.5 py-0.5 rounded font-bold bg-purple-950/80 text-purple-400 border border-purple-800">
                        {tech.id}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400">Tactic: {tech.tactic}</p>
                  </div>
                  <span className="text-xs font-mono font-bold text-cyan-400 bg-[#0e1628] px-2.5 py-1 rounded border border-slate-800">
                    {tech.count} IOCs
                  </span>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Right: SOC Operational Efficiency */}
        <div className="lg:col-span-5 bg-[#0b1220] border border-slate-800 rounded-2xl p-5 space-y-4 shadow-sm">
          <h2 className="text-sm font-bold text-slate-200 flex items-center gap-2">
            <span>⚡</span> Operational Threat Coverage
          </h2>

          <div className="space-y-4">
            <div className="space-y-1.5">
              <div className="flex justify-between text-xs font-medium text-slate-300">
                <span>Threat Intelligence Enrichment Coverage</span>
                <span className="text-cyan-400 font-bold">
                  {kpiData?.enrichment_coverage?.percentage ?? 0}%
                </span>
              </div>
              <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                <div
                  className="h-full bg-cyan-500 rounded-full transition-all duration-500"
                  style={{ width: `${Math.min(100, kpiData?.enrichment_coverage?.percentage ?? 0)}%` }}
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <div className="flex justify-between text-xs font-medium text-slate-300">
                <span>Total Indexed Indicators</span>
                <span className="text-emerald-400 font-bold">
                  {kpiData?.indicators?.total ?? 0}
                </span>
              </div>
              <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                <div className="h-full bg-emerald-500 rounded-full" style={{ width: "100%" }} />
              </div>
            </div>

            <div className="space-y-1.5">
              <div className="flex justify-between text-xs font-medium text-slate-300">
                <span>Correlated Security Incidents</span>
                <span className="text-purple-400 font-bold">
                  {totalOpenIncidents} Active
                </span>
              </div>
              <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                <div
                  className="h-full bg-purple-500 rounded-full transition-all duration-500"
                  style={{ width: totalOpenIncidents > 0 ? "100%" : "0%" }}
                />
              </div>
            </div>

            <div className="pt-2 p-3 bg-[#080d19] border border-slate-800 rounded-xl">
              <p className="text-[11px] text-slate-400 leading-relaxed">
                🛡️ <strong className="text-slate-200">CISO Audit Verification:</strong> Real-time PostgreSQL telemetry correlation and multi-provider external enrichment active.
              </p>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}