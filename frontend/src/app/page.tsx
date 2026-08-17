"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useRole } from "@/context/RoleContext";

export default function HomePage() {
  const { role, persona } = useRole();
  const [activeTab, setActiveTab] = useState<"all" | "triage" | "hunting" | "executive">("all");

  const telemetryStats = [
    {
      label: "Indexed Indicators (IOCs)",
      value: "48,920",
      change: "+850 today",
      color: "text-cyan-400",
      glow: "border-cyan-500/20 bg-cyan-950/20",
    },
    {
      label: "Active Ingestion Feeds",
      value: "12 / 12",
      change: "99.9% Uptime",
      color: "text-emerald-400",
      glow: "border-emerald-500/20 bg-emerald-950/20",
    },
    {
      label: "Critical SEV-1 Alerts",
      value: "03",
      change: "Containment Active",
      color: "text-amber-400",
      glow: "border-amber-500/20 bg-amber-950/20",
    },
    {
      label: "Mean Time to Detect (MTTD)",
      value: "4.2m",
      change: "-38% YoY",
      color: "text-purple-400",
      glow: "border-purple-500/20 bg-purple-950/20",
    },
  ];

  const personaWorkflows = [
    {
      name: "Priya Nair",
      role: "Tier-2 SOC Analyst",
      action: "Triage Alert Queue",
      href: "/dashboard/analyst",
      icon: "🛡️",
      tag: "Alert Triage",
      desc: "Live stream ingestion, automated single-click IOC enrichment with VirusTotal/AbuseIPDB, and correlation scoring.",
      accent: "from-cyan-500/10 via-[#0b1324] to-[#080d1a] border-cyan-500/30 hover:border-cyan-400",
      badge: "border-cyan-500/40 text-cyan-300 bg-cyan-950/50",
    },
    {
      name: "Daniel Okafor",
      role: "Incident Response Lead",
      action: "Manage Active Incidents",
      href: "/dashboard/incidents",
      icon: "⚠️",
      tag: "Incident Operations",
      desc: "Containment checklist tracking, chronological forensic audit timelines, and direct evidence-backed IR dossier exports.",
      accent: "from-orange-500/10 via-[#0b1324] to-[#080d1a] border-orange-500/30 hover:border-orange-400",
      badge: "border-orange-500/40 text-orange-300 bg-orange-950/50",
    },
    {
      name: "Mei Lin Tan",
      role: "Threat Hunter",
      action: "Launch Hunting Graph",
      href: "/dashboard/hunting",
      icon: "🎯",
      tag: "Adversary Pivoting",
      desc: "Elasticsearch full-text querying, infrastructure node pivoting, MITRE ATT&CK overlays, and reusable hunting rule templates.",
      accent: "from-purple-500/10 via-[#0b1324] to-[#080d1a] border-purple-500/30 hover:border-purple-400",
      badge: "border-purple-500/40 text-purple-300 bg-purple-950/50",
    },
    {
      name: "Rachel Adeyemi",
      role: "Chief Information Security Officer (CISO)",
      action: "Executive Board View",
      href: "/dashboard/executive",
      icon: "📈",
      tag: "Risk & Governance",
      desc: "Enterprise risk posture overview, MTTD/MTTR operational health benchmarks, and automated board-ready reporting.",
      accent: "from-emerald-500/10 via-[#0b1324] to-[#080d1a] border-emerald-500/30 hover:border-emerald-400",
      badge: "border-emerald-500/40 text-emerald-300 bg-emerald-950/50",
    },
  ];

  const features = [
    {
      icon: "⚡",
      title: "Real-Time STIX / TAXII Feed Ingestion",
      desc: "Continuous automated aggregation from AlienVault OTX, URLhaus, and Feodo Tracker with sub-second IOC correlation.",
      category: "Ingestion Engine",
    },
    {
      icon: "🌐",
      title: "Adversary Infrastructure Pivoting",
      desc: "Graph-based correlation linking external threat indicators, command & control (C2) domains, and observed network telemetry.",
      category: "Threat Hunter",
    },
    {
      icon: "📑",
      title: "Defensible Forensic Incident Dossiers",
      desc: "Immutable incident evidence audit logs with single-click exportable post-incident forensic briefs.",
      category: "IR Lead",
    },
    {
      icon: "📊",
      title: "Executive Posture & Exposure Analytics",
      desc: "High-level risk velocity tracking, team throughput monitoring, and real-time MITRE matrix coverage oversight.",
      category: "CISO Oversight",
    },
  ];

  return (
    <div className="space-y-16 pb-20">
      {/* Hero Section */}
      <section className="relative pt-10 pb-6 text-center space-y-6 max-w-5xl mx-auto">
        {/* Glow Radial Backdrop */}
        <div className="absolute inset-0 -top-10 flex items-center justify-center -z-10 pointer-events-none">
          <div className="w-[500px] h-[250px] bg-cyan-600/10 blur-[120px] rounded-full" />
          <div className="w-[400px] h-[200px] bg-purple-600/10 blur-[140px] rounded-full" />
        </div>

        {/* Live Pill Badge */}
        <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-[#08101e] border border-cyan-500/30 text-cyan-300 text-xs font-mono font-semibold shadow-inner shadow-cyan-950/40">
          <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
          <span>CYBER THREAT INTELLIGENCE &amp; SOC INCIDENT PLATFORM</span>
        </div>

        {/* Main Title */}
        <h1 className="text-4xl sm:text-5xl md:text-6xl font-black text-slate-100 tracking-tight leading-[1.15]">
          Detect Earlier. Investigate Deeper. <br />
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-sky-200 to-purple-400">
            Orchestrate Incident Containment.
          </span>
        </h1>

        {/* Subtitle */}
        <p className="text-sm sm:text-base text-slate-400 max-w-3xl mx-auto leading-relaxed">
          ThreatLens unifies multi-source STIX/TAXII threat feeds, adversary graph analytics, and automated forensic timelines into an operational cockpit built for Tier-2 SOC analysts, Threat Hunters, and CISOs.
        </p>

        {/* CTA Button Group */}
        <div className="flex flex-wrap items-center justify-center gap-4 pt-3">
          <Link
            href="/dashboard/analyst"
            className="bg-gradient-to-r from-cyan-500 to-sky-600 hover:from-cyan-400 hover:to-sky-500 text-slate-950 font-bold px-6 py-3.5 rounded-xl text-xs transition-all duration-200 shadow-lg shadow-cyan-500/25 hover:scale-[1.02] flex items-center gap-2"
          >
            <span>🛡️</span> Launch SOC Analyst Queue
          </Link>
          <Link
            href="/dashboard/hunting"
            className="bg-[#0b1324] hover:bg-[#111c35] border border-slate-700/80 text-slate-200 font-semibold px-6 py-3.5 rounded-xl text-xs transition-all duration-200 hover:scale-[1.02] flex items-center gap-2 hover:border-slate-600"
          >
            <span>🎯</span> Query Threat Hunt Matrix
          </Link>
          <Link
            href="/dashboard/incidents"
            className="bg-[#0b1324] hover:bg-[#111c35] border border-slate-700/80 text-slate-200 font-semibold px-6 py-3.5 rounded-xl text-xs transition-all duration-200 hover:scale-[1.02] flex items-center gap-2 hover:border-slate-600"
          >
            <span>⚠️</span> Active Incident Operations
          </Link>
        </div>

        {/* Current Active Session Info */}
        <div className="pt-2">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-md bg-[#0b1220]/80 border border-slate-800 text-[11px] font-mono text-slate-400">
            <span>Session:</span>
            <span className="text-slate-200 font-bold">{persona?.name}</span>
            <span className="text-slate-600">&bull;</span>
            <span className="text-cyan-400 font-semibold">{persona?.title}</span>
          </div>
        </div>
      </section>

      {/* Real-time Telemetry Metrics */}
      <section className="grid grid-cols-2 lg:grid-cols-4 gap-4 max-w-6xl mx-auto">
        {telemetryStats.map((stat, i) => (
          <div
            key={i}
            className={`border rounded-2xl p-5 backdrop-blur-sm transition-all duration-200 hover:border-slate-700 ${stat.glow}`}
          >
            <span className="text-xs text-slate-400 font-medium block truncate">{stat.label}</span>
            <div className="flex items-baseline justify-between mt-2">
              <span className={`text-3xl font-black ${stat.color}`}>{stat.value}</span>
              <span className="text-[11px] font-mono text-slate-400 bg-slate-900/80 px-2 py-0.5 rounded border border-slate-800">
                {stat.change}
              </span>
            </div>
          </div>
        ))}
      </section>

      {/* Role-Specific Workspaces (Personas from PRD) */}
      <section className="space-y-6 max-w-6xl mx-auto">
        <div className="flex flex-col md:flex-row md:items-end justify-between gap-2 border-b border-slate-800/80 pb-4">
          <div>
            <span className="text-xs font-mono font-semibold text-cyan-400 uppercase tracking-wider">
              Role-Tailored SOC Operations
            </span>
            <h2 className="text-2xl font-bold text-slate-100 mt-1">
              Purpose-Built Command Views
            </h2>
          </div>
          <p className="text-xs text-slate-400 max-w-md text-left md:text-right">
            Dedicated operational workspaces matching the escalation chain from triage to board reporting.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5">
          {personaWorkflows.map((item, idx) => (
            <div
              key={idx}
              className={`bg-gradient-to-b ${item.accent} border rounded-2xl p-5 flex flex-col justify-between transition-all duration-300 hover:-translate-y-1.5 shadow-xl shadow-black/40 group`}
            >
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-2xl p-2 rounded-xl bg-slate-900/80 border border-slate-800">
                    {item.icon}
                  </span>
                  <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded-full border ${item.badge}`}>
                    {item.tag}
                  </span>
                </div>

                <div>
                  <h3 className="text-sm font-extrabold text-slate-100 group-hover:text-white transition">
                    {item.name}
                  </h3>
                  <p className="text-[11px] text-cyan-400/80 font-mono">{item.role}</p>
                  <p className="text-xs text-slate-400 mt-2.5 leading-relaxed">
                    {item.desc}
                  </p>
                </div>
              </div>

              <Link
                href={item.href}
                className="mt-6 w-full inline-flex items-center justify-center gap-2 bg-[#0a101f] hover:bg-slate-800/90 text-slate-200 border border-slate-700/80 py-2.5 px-3.5 rounded-xl text-xs font-bold transition-all shadow-sm"
              >
                <span>{item.action}</span>
                <span>&rarr;</span>
              </Link>
            </div>
          ))}
        </div>
      </section>

      {/* Platform Capabilities Grid */}
      <section className="space-y-6 max-w-6xl mx-auto">
        <div className="text-center space-y-1">
          <span className="text-xs font-mono font-semibold text-purple-400 uppercase tracking-wider">
            Architecture Highlights
          </span>
          <h2 className="text-2xl font-bold text-slate-100">End-to-End Threat Intelligence Engine</h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          {features.map((feat, i) => (
            <div
              key={i}
              className="bg-[#080e1b]/80 border border-slate-800/80 hover:border-slate-700/90 rounded-2xl p-6 transition-all duration-200 flex items-start gap-4 shadow-lg shadow-black/20"
            >
              <div className="text-2xl p-3 rounded-xl bg-slate-900/90 border border-slate-800 shrink-0">
                {feat.icon}
              </div>
              <div className="space-y-1.5">
                <div className="flex items-center gap-2">
                  <h3 className="text-sm font-bold text-slate-100">{feat.title}</h3>
                  <span className="text-[10px] font-mono text-slate-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                    {feat.category}
                  </span>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">{feat.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Quick Launch Operations Bar */}
      <section className="max-w-6xl mx-auto bg-gradient-to-r from-cyan-950/40 via-[#0b1324] to-purple-950/40 border border-cyan-500/20 rounded-2xl p-6 sm:p-8 flex flex-col md:flex-row items-center justify-between gap-6 shadow-2xl">
        <div className="space-y-1 text-center md:text-left">
          <h3 className="text-base font-bold text-slate-100 flex items-center justify-center md:justify-start gap-2">
            <span>🛡️</span> Ready to run live threat correlation?
          </h3>
          <p className="text-xs text-slate-400 max-w-xl">
            Switch your role from the top navigation bar to test role-based access control and inspect persona-specific telemetry views.
          </p>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          <Link
            href="/dashboard/analyst"
            className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold px-5 py-2.5 rounded-xl text-xs transition shadow-md shadow-cyan-500/20"
          >
            Enter Analyst Console
          </Link>
          <Link
            href="/dashboard/executive"
            className="bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold px-5 py-2.5 rounded-xl text-xs transition border border-slate-700"
          >
            CISO Executive View
          </Link>
        </div>
      </section>
    </div>
  );
}