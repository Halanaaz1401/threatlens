"use client";

import Link from "next/link";
import { 
  Shield, 
  Activity, 
  AlertTriangle, 
  Target, 
  ArrowRight, 
  Radio, 
  Lock, 
  Database,
  Layers
} from "lucide-react";

export default function HomePage() {
  const dashboards = [
    {
      title: "SOC Analyst Triage",
      desc: "Live real-time ingestion queue with sub-second alert triaging and SIEM correlation.",
      href: "/dashboard/analyst",
      icon: Shield,
      color: "text-red-400",
      border: "hover:border-red-500/50",
      badge: "Real-Time WebSocket",
    },
    {
      title: "Executive Risk Posture",
      desc: "Strategic CISO view with 30-day exposure trends, global heatmap, and customizable widgets.",
      href: "/dashboard/executive",
      icon: Activity,
      color: "text-indigo-400",
      border: "hover:border-indigo-500/50",
      badge: "CISO Metrics",
    },
    {
      title: "Incident Response (IR)",
      desc: "Containment checklists, chronological forensic timelines, and immutable audit trails.",
      href: "/dashboard/incidents",
      icon: AlertTriangle,
      color: "text-orange-400",
      border: "hover:border-orange-500/50",
      badge: "Active SEV-1",
    },
    {
      title: "Threat Hunting & ATT&CK",
      desc: "Elasticsearch querying, MITRE matrix mapping, and interactive relationship graph visualizer.",
      href: "/dashboard/hunting",
      icon: Target,
      color: "text-purple-400",
      border: "hover:border-purple-500/50",
      badge: "Graph Pivot",
    },
  ];

  return (
    <div className="space-y-12 py-6">
      {/* Hero Section */}
      <div className="text-center space-y-4 max-w-3xl mx-auto">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-red-500/10 border border-red-500/20 text-red-400 text-xs font-mono">
          <Radio className="h-3.5 w-3.5 animate-pulse" />
          Enterprise Cyber Threat Intelligence Platform
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold tracking-tight text-white font-mono">
          Unified Multi-Persona <span className="text-red-500">CTI SOC</span>
        </h1>
        <p className="text-sm sm:text-base text-slate-400 font-mono">
          Automated multi-feed normalization (STIX 2.1), sub-second Elasticsearch querying, and dynamic SIEM alert correlation.
        </p>
      </div>

      {/* Role-Specific Portal Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 max-w-5xl mx-auto">
        {dashboards.map((card) => {
          const Icon = card.icon;
          return (
            <Link
              key={card.href}
              href={card.href}
              className={`p-6 rounded-xl bg-slate-900/60 border border-slate-800 transition duration-200 flex flex-col justify-between space-y-4 group ${card.border}`}
            >
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-white">
                    <Icon className={`h-6 w-6 ${card.color}`} />
                  </div>
                  <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                    {card.badge}
                  </span>
                </div>
                <h2 className="text-lg font-bold text-white font-mono group-hover:text-red-400 transition">
                  {card.title}
                </h2>
                <p className="text-xs text-slate-400 font-mono leading-relaxed">
                  {card.desc}
                </p>
              </div>

              <div className="flex items-center gap-1 text-xs font-mono font-medium text-slate-300 group-hover:translate-x-1 transition">
                Enter Portal <ArrowRight className="h-3.5 w-3.5 ml-1 text-red-400" />
              </div>
            </Link>
          );
        })}
      </div>

      {/* Backend & Ingestion Telemetry Footer Banner */}
      <div className="max-w-5xl mx-auto p-4 rounded-xl bg-slate-950/80 border border-slate-800 grid grid-cols-2 sm:grid-cols-4 gap-4 text-center font-mono text-xs">
        <div className="space-y-1">
          <span className="text-slate-500 block text-[10px]">INGESTION ENGINE</span>
          <span className="text-emerald-400 font-semibold flex items-center justify-center gap-1.5">
            <Radio className="h-3 w-3" /> 6 Active Feeds
          </span>
        </div>
        <div className="space-y-1">
          <span className="text-slate-500 block text-[10px]">QUERY LATENCY</span>
          <span className="text-indigo-400 font-semibold flex items-center justify-center gap-1.5">
            <Database className="h-3 w-3" /> &lt; 50ms
          </span>
        </div>
        <div className="space-y-1">
          <span className="text-slate-500 block text-[10px]">STIX STANDARD</span>
          <span className="text-yellow-400 font-semibold flex items-center justify-center gap-1.5">
            <Layers className="h-3 w-3" /> STIX 2.1 / TAXII
          </span>
        </div>
        <div className="space-y-1">
          <span className="text-slate-500 block text-[10px]">ENCRYPTION</span>
          <span className="text-blue-400 font-semibold flex items-center justify-center gap-1.5">
            <Lock className="h-3 w-3" /> TLS 1.3
          </span>
        </div>
      </div>
    </div>
  );
}