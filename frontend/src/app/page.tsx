"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { useRole } from "@/context/RoleContext";
import AnalyticsCharts from "@/components/AnalyticsCharts";
import { safeFetchIndicators } from "@/lib/api";

export default function HomeHubPage() {
  const { persona } = useRole();
  const [stats, setStats] = useState({
    totalIOCs: 21,
    activeAlerts: 1,
    criticalThreats: 12,
    mttd: "4.2m",
  });

  useEffect(() => {
    async function loadStats() {
      const items = await safeFetchIndicators();
      const critical = items.filter((i: any) => i.severity_score >= 80).length;
      setStats({
        totalIOCs: items.length,
        activeAlerts: 1,
        criticalThreats: critical || 12,
        mttd: "4.2m",
      });
    }
    loadStats();
  }, []);

  return (
    <div className="space-y-8 pb-16">
      <div className="bg-gradient-to-r from-[#0b1220] via-[#0d172a] to-[#0b1220] border border-slate-800 rounded-3xl p-8 shadow-md">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <span className="text-2xl">🛡️</span>
              <h1 className="text-2xl md:text-3xl font-black text-slate-100 tracking-tight">
                ThreatLens Enterprise CTI &amp; SOC Operations
              </h1>
            </div>
            <p className="text-sm text-slate-400 max-w-2xl">
              Automated multi-source threat feed ingestion, 0–100 deterministic severity scoring, and role-based incident operations surface.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <Link
              href="/dashboard/analyst"
              className="bg-cyan-600 hover:bg-cyan-500 text-white font-bold px-5 py-2.5 rounded-xl text-xs shadow-md transition"
            >
              Open Analyst Queue &rarr;
            </Link>
            <Link
              href="/dashboard/hunting"
              className="bg-purple-600 hover:bg-purple-500 text-white font-bold px-5 py-2.5 rounded-xl text-xs shadow-md transition"
            >
              Threat Hunter &rarr;
            </Link>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-[#0b1220] border border-slate-800 rounded-2xl p-5 space-y-1">
          <span className="text-xs font-semibold text-slate-400">Total Canonical IOCs</span>
          <div className="text-2xl font-black text-cyan-400 font-mono">{stats.totalIOCs}</div>
          <span className="text-[10px] text-slate-500">Aggregated across 6 feeds</span>
        </div>

        <div className="bg-[#0b1220] border border-slate-800 rounded-2xl p-5 space-y-1">
          <span className="text-xs font-semibold text-slate-400">Critical Threats (≥ 80)</span>
          <div className="text-2xl font-black text-red-400 font-mono">{stats.criticalThreats}</div>
          <span className="text-[10px] text-slate-500">Requires immediate triage</span>
        </div>

        <div className="bg-[#0b1220] border border-slate-800 rounded-2xl p-5 space-y-1">
          <span className="text-xs font-semibold text-slate-400">Active SEV-1 Incidents</span>
          <div className="text-2xl font-black text-orange-400 font-mono">{stats.activeAlerts}</div>
          <span className="text-[10px] text-slate-500">Under containment protocol</span>
        </div>

        <div className="bg-[#0b1220] border border-slate-800 rounded-2xl p-5 space-y-1">
          <span className="text-xs font-semibold text-slate-400">Mean Time to Detect (MTTD)</span>
          <div className="text-2xl font-black text-emerald-400 font-mono">{stats.mttd}</div>
          <span className="text-[10px] text-slate-500">Automated stream ingestion</span>
        </div>
      </div>

      <AnalyticsCharts />

      <div className="space-y-4">
        <h2 className="text-sm font-bold text-slate-200 flex items-center gap-2">
          <span>👥</span> Role-Specific Operational Workspaces
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Link href="/dashboard/analyst" className="bg-[#0b1220] border border-slate-800 hover:border-cyan-500/80 rounded-2xl p-5 space-y-2 transition group">
            <div className="flex items-center justify-between">
              <span className="text-xl">🛡️</span>
              <span className="text-[10px] font-mono font-bold text-cyan-400 bg-cyan-950/80 px-2 py-0.5 rounded border border-cyan-800">Priya Nair</span>
            </div>
            <h3 className="text-sm font-bold text-slate-100 group-hover:text-cyan-400">SOC Analyst Queue</h3>
            <p className="text-xs text-slate-400">Live triage queue, 0–100 severity rankings, one-click enrichment.</p>
          </Link>

          <Link href="/dashboard/incidents" className="bg-[#0b1220] border border-slate-800 hover:border-orange-500/80 rounded-2xl p-5 space-y-2 transition group">
            <div className="flex items-center justify-between">
              <span className="text-xl">⚠️</span>
              <span className="text-[10px] font-mono font-bold text-orange-400 bg-orange-950/80 px-2 py-0.5 rounded border border-orange-800">Daniel Okafor</span>
            </div>
            <h3 className="text-sm font-bold text-slate-100 group-hover:text-orange-400">Incident Response</h3>
            <p className="text-xs text-slate-400">Forensic chronological timeline, host containment checklist, STIX dossier.</p>
          </Link>

          <Link href="/dashboard/hunting" className="bg-[#0b1220] border border-slate-800 hover:border-purple-500/80 rounded-2xl p-5 space-y-2 transition group">
            <div className="flex items-center justify-between">
              <span className="text-xl">🎯</span>
              <span className="text-[10px] font-mono font-bold text-purple-400 bg-purple-950/80 px-2 py-0.5 rounded border border-purple-800">Mei Lin Tan</span>
            </div>
            <h3 className="text-sm font-bold text-slate-100 group-hover:text-purple-400">Threat Hunting</h3>
            <p className="text-xs text-slate-400">Adversary graph pivoting, MITRE ATT&amp;CK matrix, reusable hunt queries.</p>
          </Link>

          <Link href="/dashboard/executive" className="bg-[#0b1220] border border-slate-800 hover:border-emerald-500/80 rounded-2xl p-5 space-y-2 transition group">
            <div className="flex items-center justify-between">
              <span className="text-xl">📈</span>
              <span className="text-[10px] font-mono font-bold text-emerald-400 bg-emerald-950/80 px-2 py-0.5 rounded border border-emerald-800">Rachel Adeyemi</span>
            </div>
            <h3 className="text-sm font-bold text-slate-100 group-hover:text-emerald-400">Executive Posture</h3>
            <p className="text-xs text-slate-400">Enterprise risk score, MTTD/MTTR benchmarks, scheduled board reporting.</p>
          </Link>
        </div>
      </div>
    </div>
  );
}
