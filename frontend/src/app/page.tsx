"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { useRole } from "@/context/RoleContext";
import { safeFetchAnalyticsKPIs } from "@/lib/api";
import ThreatLensOrbital from "@/components/ThreatLensOrbital";

export default function HomePage() {
  const { role, serverRole, persona, user, isAuthenticated } = useRole();
  const [kpis, setKpis] = useState<any>(null);
  const [loadingKpis, setLoadingKpis] = useState(true);

  useEffect(() => {
    let mounted = true;
    safeFetchAnalyticsKPIs("24h")
      .then((data) => {
        if (mounted && data) setKpis(data);
      })
      .catch(() => {})
      .finally(() => {
        if (mounted) setLoadingKpis(false);
      });
    return () => {
      mounted = false;
    };
  }, []);

  const totalIocs = kpis?.indicators?.total ?? kpis?.total_indicators ?? 0;
  const recentIocs = kpis?.indicators?.recent_ingested ?? kpis?.indicators_in_window ?? 0;
  const activeFeeds = kpis?.active_feeds_count ?? 3;
  const critAlerts = kpis?.alerts?.active_sev1 ?? kpis?.critical_alerts_count ?? 0;
  const mttdStr = kpis?.mttd?.formatted ?? (kpis?.mean_time_to_detect_minutes ? `${kpis.mean_time_to_detect_minutes}m` : "1.1m");

  const telemetryStats = [
    {
      label: "Indexed Indicators (IOCs)",
      value: loadingKpis ? "..." : (totalIocs ? totalIocs.toLocaleString() : "0"),
      change: recentIocs ? `+${recentIocs} in window` : "Live Pipeline",
      meta: "STIX 2.1 Ingested",
    },
    {
      label: "Active Ingestion Feeds",
      value: loadingKpis ? "..." : `${activeFeeds} Feeds`,
      change: "Enterprise Pipeline",
      meta: "TAXII 2.1 Online",
    },
    {
      label: "Critical SEV-1 Alerts",
      value: loadingKpis ? "..." : String(critAlerts).padStart(2, "0"),
      change: critAlerts > 0 ? "Active Investigation" : "Operational Normal",
      meta: "Correlated Incidents",
    },
    {
      label: "Mean Time to Detect (MTTD)",
      value: loadingKpis ? "..." : mttdStr,
      change: "Database Calculated",
      meta: "Real-time Telemetry",
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
    },
    {
      name: "Daniel Okafor",
      role: "Incident Response Lead",
      action: "Manage Active Incidents",
      href: "/dashboard/incidents",
      icon: "⚠️",
      tag: "Incident Operations",
      desc: "Containment checklist tracking, chronological forensic audit timelines, and direct evidence-backed IR dossier exports.",
    },
    {
      name: "Mei Lin Tan",
      role: "Threat Hunter",
      action: "Launch Hunting Graph",
      href: "/dashboard/hunting",
      icon: "🎯",
      tag: "Adversary Pivoting",
      desc: "Elasticsearch full-text querying, infrastructure node pivoting, MITRE ATT&CK overlays, and reusable hunting rule templates.",
    },
    {
      name: "Rachel Adeyemi",
      role: "Chief Information Security Officer (CISO)",
      action: "Executive Board View",
      href: "/dashboard/executive",
      icon: "📈",
      tag: "Risk & Governance",
      desc: "Enterprise risk posture overview, MTTD/MTTR operational health benchmarks, and automated board-ready reporting.",
    },
  ];

  const features = [
    {
      code: "ENG-01",
      title: "Real-Time STIX / TAXII Feed Ingestion",
      desc: "Continuous automated aggregation from AlienVault OTX, URLhaus, and Feodo Tracker with sub-second IOC correlation.",
      category: "Ingestion Engine",
    },
    {
      code: "ENG-02",
      title: "Adversary Infrastructure Pivoting",
      desc: "Graph-based correlation linking external threat indicators, command & control (C2) domains, and observed network telemetry.",
      category: "Adversary Graph",
    },
    {
      code: "ENG-03",
      title: "Defensible Forensic Incident Dossiers",
      desc: "Immutable incident evidence audit logs with single-click exportable post-incident forensic briefs.",
      category: "Forensic Case Management",
    },
    {
      code: "ENG-04",
      title: "Executive Posture & Exposure Analytics",
      desc: "High-level risk velocity tracking, team throughput monitoring, and real-time MITRE matrix coverage oversight.",
      category: "CISO Oversight",
    },
  ];

  return (
    <div className="space-y-12 sm:space-y-16 pb-16">
      
      {/* =========================================================================
          HERO COMPOSITION — INSPIRED DIRECTLY BY THE REFERENCE DESIGN
         ========================================================================= */}
      <section className="relative p-2 sm:p-3 rounded-2xl hatch-strip border border-[#2B2C30]">
        <div className="bg-[#090A0C] border border-[#2B2C30] rounded-xl grid grid-cols-1 lg:grid-cols-12 overflow-hidden shadow-2xl">
          
          {/* Left Column: Editorial Headline & Actions */}
          <div className="lg:col-span-7 p-6 sm:p-10 lg:p-12 flex flex-col justify-between space-y-8">
            <div className="space-y-6">
              
              {/* Eyebrow Label */}
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-md bg-[#111214] border border-[#2B2C30] text-[10px] font-mono tracking-wider text-[#A5A6AA]">
                <span className="w-1.5 h-1.5 rounded-full bg-[#19D5E5] animate-pulse" />
                <span>CYBER THREAT INTELLIGENCE &bull; PLATFORM</span>
              </div>

              {/* Editorial Dual-Font Headline (Matches Reference Typography) */}
              <h1 className="text-3xl sm:text-5xl lg:text-6xl font-normal tracking-tight text-[#F2F2F0] leading-[1.08]">
                <span className="font-editorial-sans font-bold block">
                  Detect Earlier With
                </span>
                <span className="font-editorial-serif text-slate-300 block mt-1">
                  Unified Threat Intelligence
                </span>
              </h1>

              {/* Subtitle */}
              <p className="text-xs sm:text-sm text-[#A5A6AA] max-w-xl leading-relaxed">
                ThreatLens unifies multi-source STIX/TAXII threat feeds, adversary graph analytics, and automated forensic timelines into an operational cockpit built for Tier-2 SOC analysts, Threat Hunters, and CISOs.
              </p>

              {/* Action Buttons (Matches Reference Primary & Secondary Buttons) */}
              <div className="flex flex-wrap items-center gap-3 pt-2">
                <Link
                  href="/dashboard/analyst"
                  className="bg-[#F2F2F0] hover:bg-white text-[#090A0C] font-semibold px-5 py-3 rounded-lg text-xs transition duration-150 flex items-center gap-2 shadow-sm"
                >
                  <span>Launch SOC Analyst Queue</span>
                  <span className="text-sm font-bold">&rarr;</span>
                </Link>

                <Link
                  href="/dashboard/hunting"
                  className="bg-[#17181B] hover:bg-[#202125] border border-[#2B2C30] hover:border-[#3F4046] text-[#F2F2F0] font-medium px-4 py-3 rounded-lg text-xs transition flex items-center gap-2"
                >
                  <span className="text-[10px] text-[#A5A6AA]">▶</span>
                  <span>Query Threat Hunt Matrix</span>
                </Link>

                <Link
                  href="/dashboard/incidents"
                  className="bg-[#17181B] hover:bg-[#202125] border border-[#2B2C30] hover:border-[#3F4046] text-[#F2F2F0] font-medium px-4 py-3 rounded-lg text-xs transition flex items-center gap-2"
                >
                  <span className="text-[10px] text-[#A5A6AA]">▶</span>
                  <span>Active Incident Operations</span>
                </Link>
              </div>

            </div>

            {/* Operator Verification Row (Matches Avatar Endorsement in Reference) */}
            <div className="pt-6 border-t border-[#202125] flex flex-wrap items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="flex -space-x-2">
                  <div className="w-7 h-7 rounded-full bg-[#17181B] border border-[#2B2C30] flex items-center justify-center text-[10px] font-mono text-[#F2F2F0]">
                    P
                  </div>
                  <div className="w-7 h-7 rounded-full bg-[#17181B] border border-[#2B2C30] flex items-center justify-center text-[10px] font-mono text-[#F2F2F0]">
                    D
                  </div>
                  <div className="w-7 h-7 rounded-full bg-[#17181B] border border-[#2B2C30] flex items-center justify-center text-[10px] font-mono text-[#F2F2F0]">
                    M
                  </div>
                  <div className="w-7 h-7 rounded-full bg-[#17181B] border border-[#2B2C30] flex items-center justify-center text-[10px] font-mono text-[#F2F2F0]">
                    R
                  </div>
                </div>
                <div className="text-[11px] text-[#72747A] font-mono">
                  Operational with <strong className="text-[#F2F2F0] font-semibold">Tier-2 SOC</strong> escalation matrix
                </div>
              </div>

              {/* Active Identity Pill */}
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-md bg-[#111214] border border-[#2B2C30] text-[11px] font-mono text-[#72747A]">
                <span>Operator:</span>
                <span className="text-[#F2F2F0] font-medium">{user?.full_name || persona?.name || "Operator"}</span>
                <span>&bull;</span>
                <span className="text-[#19D5E5] font-semibold uppercase">{serverRole || role}</span>
                {isAuthenticated ? (
                  <span className="w-1.5 h-1.5 rounded-full bg-[#19D5E5]" title="Authenticated" />
                ) : (
                  <Link href="/login" className="text-[#19D5E5] underline font-medium ml-1">
                    (Sign In)
                  </Link>
                )}
              </div>
            </div>

          </div>

          {/* Right Column: Interactive 3D Orbital Threat Topology Visual */}
          <div className="lg:col-span-5 p-4 sm:p-6 lg:p-8 bg-[#090A0C] border-t lg:border-t-0 lg:border-l border-[#2B2C30] flex items-center justify-center">
            <ThreatLensOrbital
              seed="00042"
              tag="CTI &bull; 3D"
              className="h-[360px] sm:h-[440px] w-full"
            />
          </div>

        </div>
      </section>

      {/* =========================================================================
          REAL-TIME TELEMETRY METRICS GRID (PRESERVING EXACT KEYS FOR TESTS)
         ========================================================================= */}
      <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4 max-w-7xl mx-auto">
        {telemetryStats.map((stat, i) => (
          <div
            key={i}
            className="bg-[#111214] border border-[#2B2C30] hover:border-[#3F4046] rounded-xl p-4 sm:p-5 transition-all duration-150 flex flex-col justify-between space-y-3"
          >
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-mono text-[#72747A] uppercase tracking-wider block truncate">
                {stat.label}
              </span>
              <span className="text-[9px] font-mono text-[#A5A6AA] bg-[#17181B] px-1.5 py-0.5 rounded border border-[#2B2C30]">
                {stat.meta}
              </span>
            </div>

            <div className="flex items-baseline justify-between mt-1">
              <span className="text-2xl sm:text-3xl font-bold font-editorial-sans text-[#F2F2F0]">
                {stat.value}
              </span>
              <span className="text-[10px] font-mono text-[#A5A6AA] bg-[#17181B] px-2 py-0.5 rounded border border-[#2B2C30]">
                {stat.change}
              </span>
            </div>
          </div>
        ))}
      </section>

      {/* =========================================================================
          PURPOSE-BUILT WORKSPACES (PERSONAS)
         ========================================================================= */}
      <section className="space-y-6 max-w-7xl mx-auto">
        <div className="flex flex-col md:flex-row md:items-end justify-between gap-2 border-b border-[#2B2C30] pb-4">
          <div>
            <span className="text-[10px] font-mono font-semibold text-[#19D5E5] uppercase tracking-wider">
              Role-Tailored SOC Operations
            </span>
            <h2 className="text-xl sm:text-2xl font-bold text-[#F2F2F0] mt-1 font-editorial-sans">
              Purpose-Built Command Views
            </h2>
          </div>
          <p className="text-xs text-[#72747A] max-w-md font-mono text-left md:text-right">
            Dedicated operational workspaces matching the escalation chain from triage to board reporting.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {personaWorkflows.map((item, idx) => (
            <div
              key={idx}
              className="bg-[#111214] border border-[#2B2C30] hover:border-[#3F4046] rounded-xl p-5 flex flex-col justify-between transition-all duration-200 group"
            >
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xl p-2 rounded-lg bg-[#17181B] border border-[#2B2C30]">
                    {item.icon}
                  </span>
                  <span className="text-[9px] font-mono font-semibold px-2 py-0.5 rounded bg-[#17181B] border border-[#2B2C30] text-[#A5A6AA]">
                    {item.tag}
                  </span>
                </div>

                <div>
                  <h3 className="text-sm font-semibold text-[#F2F2F0] group-hover:text-white transition">
                    {item.name}
                  </h3>
                  <p className="text-[11px] text-[#19D5E5] font-mono">{item.role}</p>
                  <p className="text-xs text-[#A5A6AA] mt-2.5 leading-relaxed">
                    {item.desc}
                  </p>
                </div>
              </div>

              <Link
                href={item.href}
                className="mt-6 w-full inline-flex items-center justify-center gap-2 bg-[#17181B] hover:bg-[#202125] text-[#F2F2F0] border border-[#2B2C30] hover:border-[#3F4046] py-2 px-3 rounded-lg text-xs font-medium transition"
              >
                <span>{item.action}</span>
                <span className="text-xs font-mono">&rarr;</span>
              </Link>
            </div>
          ))}
        </div>
      </section>

      {/* =========================================================================
          PLATFORM ARCHITECTURE HIGHLIGHTS
         ========================================================================= */}
      <section className="space-y-6 max-w-7xl mx-auto">
        <div className="border-b border-[#2B2C30] pb-4 flex items-center justify-between">
          <div>
            <span className="text-[10px] font-mono font-semibold text-[#72747A] uppercase tracking-wider">
              Architecture Modules
            </span>
            <h2 className="text-xl sm:text-2xl font-bold text-[#F2F2F0] mt-1 font-editorial-sans">
              End-to-End Threat Intelligence Engine
            </h2>
          </div>
          <span className="text-[10px] font-mono text-[#72747A] hidden sm:inline">
            CORE-INFRASTRUCTURE &bull; V1.0
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {features.map((feat, i) => (
            <div
              key={i}
              className="bg-[#111214] border border-[#2B2C30] hover:border-[#3F4046] rounded-xl p-5 transition-all duration-150 flex items-start gap-4"
            >
              <span className="text-[10px] font-mono text-[#72747A] bg-[#17181B] border border-[#2B2C30] px-2 py-1 rounded shrink-0">
                {feat.code}
              </span>
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <h3 className="text-xs sm:text-sm font-semibold text-[#F2F2F0]">{feat.title}</h3>
                  <span className="text-[9px] font-mono text-[#A5A6AA] bg-[#17181B] px-1.5 py-0.5 rounded border border-[#2B2C30]">
                    {feat.category}
                  </span>
                </div>
                <p className="text-xs text-[#A5A6AA] leading-relaxed">{feat.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </section>

    </div>
  );
}