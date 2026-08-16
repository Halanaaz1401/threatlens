"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useRole } from "@/context/RoleContext";

export default function ExecutiveDashboardPage() {
  const { persona } = useRole();
  const [scheduled, setScheduled] = useState(false);

  const kpis = [
    { label: "Enterprise Risk Score", value: "72 / 100", change: "-8.4% (Improved)", color: "text-red-400", sub: "Calculated across active vectors" },
    { label: "Mean Time to Detect (MTTD)", value: "4.2 mins", change: "-38% YoY", color: "text-cyan-400", sub: "Automated Feed Ingestion" },
    { label: "Mean Time to Respond (MTTR)", value: "18.5 mins", change: "-22% YoY", color: "text-emerald-400", sub: "One-click Containment" },
    { label: "Active SEV-1 Incidents", value: "1", change: "INC-2026-0815", color: "text-amber-400", sub: "Under Active Containment" },
  ];

  const topAdversaries = [
    { name: "UNC2452 / APT29", target: "Cloud Identity & Perimeter", volume: "1,420 IOCs", level: "Critical" },
    { name: "Lazarus Group", target: "Financial Gateways", volume: "890 IOCs", level: "High" },
    { name: "LockBit 3.0 Syndicate", target: "Endpoint Ransomware", volume: "640 IOCs", level: "High" },
    { name: "QakBot Infrastructure", target: "Malicious Spambot C2", volume: "510 IOCs", level: "Medium" },
  ];

  const handleScheduleDeck = () => {
    setScheduled(true);
    setTimeout(() => setScheduled(false), 3000);
  };

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
            Aggregated exposure metrics, MTTD/MTTR operational performance, and board-level risk tracking.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleScheduleDeck}
            className="bg-emerald-600 hover:bg-emerald-500 text-white font-bold px-4 py-2 rounded-xl text-xs flex items-center gap-2 shadow-sm transition"
          >
            <span>📊</span>
            <span>{scheduled ? "Board Deck Scheduled!" : "Schedule Weekly Board Deck"}</span>
          </button>
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
              <span className={`text-2xl font-black ${k.color}`}>{k.value}</span>
              <span className="text-[11px] font-mono text-slate-400">{k.change}</span>
            </div>
            <p className="text-[10px] text-slate-500 font-mono pt-1 border-t border-slate-800/80">{k.sub}</p>
          </div>
        ))}
      </div>

      {/* Deep Executive Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Left: Top Threat Actor Exposure */}
        <div className="lg:col-span-7 bg-[#0b1220] border border-slate-800 rounded-2xl p-5 space-y-4 shadow-sm">
          <h2 className="text-sm font-bold text-slate-200 flex items-center gap-2">
            <span>🎯</span> Targeted Adversary Campaign Exposure
          </h2>

          <div className="space-y-3">
            {topAdversaries.map((adv, idx) => (
              <div
                key={idx}
                className="bg-[#080d19] border border-slate-800/90 rounded-xl p-3.5 flex items-center justify-between hover:border-slate-700 transition"
              >
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold text-slate-200">{adv.name}</span>
                    <span
                      className={`text-[9px] font-mono px-1.5 py-0.5 rounded font-bold ${
                        adv.level === "Critical"
                          ? "bg-red-950/80 text-red-400 border border-red-800"
                          : adv.level === "High"
                          ? "bg-orange-950/80 text-orange-400 border border-orange-800"
                          : "bg-amber-950/80 text-amber-400 border border-amber-800"
                      }`}
                    >
                      {adv.level}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400">Target Area: {adv.target}</p>
                </div>
                <span className="text-xs font-mono font-bold text-cyan-400 bg-[#0e1628] px-2.5 py-1 rounded border border-slate-800">
                  {adv.volume}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Right: SOC Operational Efficiency */}
        <div className="lg:col-span-5 bg-[#0b1220] border border-slate-800 rounded-2xl p-5 space-y-4 shadow-sm">
          <h2 className="text-sm font-bold text-slate-200 flex items-center gap-2">
            <span>⚡</span> Alert Resolution Throughput
          </h2>

          <div className="space-y-4">
            <div className="space-y-1.5">
              <div className="flex justify-between text-xs font-medium text-slate-300">
                <span>Resolved Within SLA (&lt; 30 min)</span>
                <span className="text-emerald-400 font-bold">94.2%</span>
              </div>
              <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                <div className="h-full bg-emerald-500 rounded-full" style={{ width: "94.2%" }} />
              </div>
            </div>

            <div className="space-y-1.5">
              <div className="flex justify-between text-xs font-medium text-slate-300">
                <span>Automated Ingestion Feed Uptime</span>
                <span className="text-cyan-400 font-bold">99.9%</span>
              </div>
              <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                <div className="h-full bg-cyan-500 rounded-full" style={{ width: "99.9%" }} />
              </div>
            </div>

            <div className="space-y-1.5">
              <div className="flex justify-between text-xs font-medium text-slate-300">
                <span>Containment Playbook Automation</span>
                <span className="text-purple-400 font-bold">82.0%</span>
              </div>
              <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                <div className="h-full bg-purple-500 rounded-full" style={{ width: "82%" }} />
              </div>
            </div>

            <div className="pt-2 p-3 bg-[#080d19] border border-slate-800 rounded-xl">
              <p className="text-[11px] text-slate-400 leading-relaxed">
                🛡️ <strong className="text-slate-200">CISO Audit Note:</strong> Zero breaches crossed containment boundary in the last 30-day reporting cycle.
              </p>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}