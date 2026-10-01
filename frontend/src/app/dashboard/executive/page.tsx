"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { useRole } from "@/context/RoleContext";
import { safeFetchAnalyticsOverview, safeFetchMitreAnalytics } from "@/lib/api";
import AnalyticsCharts from "@/components/AnalyticsCharts";

export default function ExecutiveDashboardPage() {
  const { persona } = useRole();
  const [overview, setOverview] = useState<any>(null);
  const [mitreData, setMitreData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState("24h");

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
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-[#0b1220] border border-slate-800 rounded-2xl p-5 shadow-sm">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
              📈 Executive Risk Posture &amp; CISO Board Overview
            </h1>
            <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-400 border border-emerald-800">
              {persona.name} ({persona.title})
            </span>
          </div>
          <p className="text-xs text-slate-400">
            Authoritative exposure metrics, MTTD/MTTR operational performance, and real-time risk tracking.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Link
            href="/"
            className="bg-[#0e1628] hover:bg-slate-800 border border-slate-700 text-slate-200 font-semibold px-4 py-2 rounded-xl text-xs transition"
          >
            Home Hub &rarr;
          </Link>
        </div>
      </div>

      {/* CISO High-Level Metric Tiles */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {kpis.map((k, i) => (
          <div key={i} className="bg-[#0b1220] border border-slate-800 rounded-2xl p-5 space-y-2 shadow-sm">
            <span className="text-xs text-slate-400 font-medium">{k.label}</span>
            <div className="flex items-baseline justify-between">
              <span className={`text-2xl font-black ${k.color}`}>{loading ? "..." : k.value}</span>
              <span className="text-[11px] font-mono text-slate-400">{k.change}</span>
            </div>
            <p className="text-[10px] text-slate-500 font-mono pt-1 border-t border-slate-800/80">{k.sub}</p>
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