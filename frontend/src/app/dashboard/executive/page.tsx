"use client";

import React, { useState, useEffect } from "react";
import { 
  Activity, 
  ShieldAlert, 
  TrendingUp, 
  FileDown, 
  CheckCircle, 
  AlertOctagon,
  Globe, 
  Layers,
  SlidersHorizontal,
  RotateCcw,
  Eye,
  EyeOff,
  Download,
  Printer
} from "lucide-react";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar
} from "recharts";
import GlobalHeatmap from "@/components/GlobalHeatmap";

const exposureTrendData = [
  { day: "Day 1", riskScore: 42, activeThreats: 18 },
  { day: "Day 5", riskScore: 48, activeThreats: 24 },
  { day: "Day 10", riskScore: 65, activeThreats: 45 },
  { day: "Day 15", riskScore: 58, activeThreats: 38 },
  { day: "Day 20", riskScore: 74, activeThreats: 62 },
  { day: "Day 25", riskScore: 68, activeThreats: 51 },
  { day: "Day 30", riskScore: 78, activeThreats: 69 },
];

const threatCategoryData = [
  { name: "C2 Communication", value: 38, color: "#ef4444" },
  { name: "Ransomware Delivery", value: 27, color: "#f97316" },
  { name: "Phishing / Credential Harvesting", value: 20, color: "#eab308" },
  { name: "Scanning & Exploitation", value: 15, color: "#3b82f6" },
];

const throughputData = [
  { period: "W1", open: 34, resolved: 28 },
  { period: "W2", open: 45, resolved: 42 },
  { period: "W3", open: 60, resolved: 55 },
  { period: "W4", open: 48, resolved: 51 },
];

interface WidgetState {
  kpiCards: boolean;
  trendChart: boolean;
  categoryDonut: boolean;
  throughputChart: boolean;
  globalMap: boolean;
}

const DEFAULT_WIDGETS: WidgetState = {
  kpiCards: true,
  trendChart: true,
  categoryDonut: true,
  throughputChart: true,
  globalMap: true,
};

export default function ExecutiveDashboard() {
  const [showWidgetModal, setShowWidgetModal] = useState(false);
  const [widgets, setWidgets] = useState<WidgetState>(DEFAULT_WIDGETS);

  useEffect(() => {
    const saved = localStorage.getItem("threatlens_exec_widgets");
    if (saved) {
      try {
        setWidgets(JSON.parse(saved));
      } catch (e) {
        console.error("Failed to parse saved widget state", e);
      }
    }
  }, []);

  const toggleWidget = (key: keyof WidgetState) => {
    const updated = { ...widgets, [key]: !widgets[key] };
    setWidgets(updated);
    localStorage.setItem("threatlens_exec_widgets", JSON.stringify(updated));
  };

  const resetWidgets = () => {
    setWidgets(DEFAULT_WIDGETS);
    localStorage.setItem("threatlens_exec_widgets", JSON.stringify(DEFAULT_WIDGETS));
  };

  const handleExportSTIX = () => {
    window.open("http://localhost:8000/api/v1/export/stix", "_blank");
  };

  const handleExportCSV = () => {
    window.open("http://localhost:8000/api/v1/export/csv", "_blank");
  };

  const handleExportPDF = () => {
    window.print();
  };

  return (
    <div className="space-y-6 print:p-0 print:m-0 print:space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-5 print:border-none">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <Activity className="h-6 w-6 text-indigo-400" />
            Executive Risk Posture Overview
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            Persona: Rachel Adeyemi (CISO) — Strategic Threat Exposure & Custom Widget Workspace
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 print:hidden">
          {/* Custom Widget Config Button */}
          <button
            onClick={() => setShowWidgetModal(!showWidgetModal)}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-200 border border-slate-700 transition"
          >
            <SlidersHorizontal className="h-3.5 w-3.5 text-indigo-400" />
            Customize Widgets
          </button>

          {/* Export STIX 2.1 */}
          <button
            onClick={handleExportSTIX}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-xs font-mono text-indigo-300 border border-indigo-500/40 transition"
            title="Download STIX 2.1 JSON Bundle"
          >
            <Download className="h-3.5 w-3.5" />
            Export STIX 2.1
          </button>

          {/* Export CSV */}
          <button
            onClick={handleExportCSV}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-xs font-mono text-slate-300 border border-slate-700 transition"
            title="Download CSV Feed"
          >
            <Download className="h-3.5 w-3.5" />
            Export CSV
          </button>

          {/* Export PDF Report */}
          <button
            onClick={handleExportPDF}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-xs font-mono font-medium text-white transition shadow-lg shadow-indigo-600/20"
          >
            <Printer className="h-4 w-4" />
            Generate PDF Report
          </button>
        </div>
      </div>

      {/* Widget Customizer Modal */}
      {showWidgetModal && (
        <div className="p-4 bg-slate-900 border border-indigo-500/30 rounded-xl space-y-3 shadow-xl print:hidden">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <span className="text-xs font-bold font-mono text-slate-200 uppercase tracking-wider flex items-center gap-2">
              <SlidersHorizontal className="h-3.5 w-3.5 text-indigo-400" />
              Executive Widget Library & Layout Settings
            </span>
            <button
              onClick={resetWidgets}
              className="text-[11px] font-mono text-slate-400 hover:text-slate-200 flex items-center gap-1"
            >
              <RotateCcw className="h-3 w-3" /> Reset Default
            </button>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-2 pt-1">
            {[
              { key: "kpiCards", label: "Executive KPIs" },
              { key: "trendChart", label: "30-Day Exposure Trend" },
              { key: "categoryDonut", label: "Threat Categories" },
              { key: "throughputChart", label: "SOC Throughput Pace" },
              { key: "globalMap", label: "Global Attack Heatmap" },
            ].map((item) => {
              const k = item.key as keyof WidgetState;
              const active = widgets[k];
              return (
                <button
                  key={k}
                  onClick={() => toggleWidget(k)}
                  className={`p-2.5 rounded-lg text-xs font-mono border flex items-center justify-between transition ${
                    active
                      ? "bg-indigo-950/40 border-indigo-500/40 text-indigo-300"
                      : "bg-slate-950/60 border-slate-800 text-slate-500 line-through"
                  }`}
                >
                  <span className="truncate">{item.label}</span>
                  {active ? <Eye className="h-3.5 w-3.5 shrink-0 ml-1" /> : <EyeOff className="h-3.5 w-3.5 shrink-0 ml-1" />}
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* Widget 1: KPI Summary Cards */}
      {widgets.kpiCards && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-xl">
            <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
              <span>ENTERPRISE RISK SCORE</span>
              <TrendingUp className="h-4 w-4 text-red-400" />
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-3xl font-bold font-mono text-red-400">78</span>
              <span className="text-xs text-slate-500 font-mono">/ 100 (Elevated)</span>
            </div>
            <p className="mt-2 text-[11px] text-red-400/80 font-mono">+12% vs last 30 days</p>
          </div>

          <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-xl">
            <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
              <span>ACTIVE CRITICAL IOCs</span>
              <AlertOctagon className="h-4 w-4 text-orange-400" />
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-3xl font-bold font-mono text-orange-400">24</span>
              <span className="text-xs text-slate-500 font-mono">Requiring Triage</span>
            </div>
            <p className="mt-2 text-[11px] text-slate-400 font-mono">Across 6 Ingested Feeds</p>
          </div>

          <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-xl">
            <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
              <span>MTTR (TRIAGE TO RESOLVE)</span>
              <CheckCircle className="h-4 w-4 text-emerald-400" />
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-3xl font-bold font-mono text-emerald-400">42 min</span>
              <span className="text-xs text-slate-500 font-mono">Target: &lt; 90 min</span>
            </div>
            <p className="mt-2 text-[11px] text-emerald-400/80 font-mono">SOC efficiency optimal</p>
          </div>

          <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-xl">
            <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
              <span>INGESTION COVERAGE</span>
              <Globe className="h-4 w-4 text-blue-400" />
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-3xl font-bold font-mono text-blue-400">6/6</span>
              <span className="text-xs text-slate-500 font-mono">Feeds Online</span>
            </div>
            <p className="mt-2 text-[11px] text-blue-400/80 font-mono">OTX, AbuseIPDB, URLhaus+</p>
          </div>
        </div>
      )}

      {/* Widget 2 & 3: Main Charts Row */}
      {(widgets.trendChart || widgets.categoryDonut) && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {widgets.trendChart && (
            <div className={`${widgets.categoryDonut ? "lg:col-span-2" : "lg:col-span-3"} p-5 bg-slate-900/60 border border-slate-800 rounded-xl flex flex-col justify-between`}>
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-3 mb-4">
                <span className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                  <TrendingUp className="h-4 w-4 text-indigo-400" />
                  30-Day Threat Exposure & Risk Score Trend
                </span>
                <span className="text-xs font-mono text-slate-500">Continuous Rolling Window</span>
              </div>
              <div className="h-64 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={exposureTrendData}>
                    <defs>
                      <linearGradient id="riskGradient" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#6366f1" stopOpacity={0.4} />
                        <stop offset="95%" stopColor="#6366f1" stopOpacity={0.0} />
                      </linearGradient>
                    </defs>
                    <XAxis dataKey="day" stroke="#64748b" fontSize={11} />
                    <YAxis stroke="#64748b" fontSize={11} domain={[0, 100]} />
                    <Tooltip
                      contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", borderRadius: "8px" }}
                      labelStyle={{ color: "#94a3b8" }}
                    />
                    <Area type="monotone" dataKey="riskScore" stroke="#6366f1" strokeWidth={2} fillOpacity={1} fill="url(#riskGradient)" name="Risk Score" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}

          {widgets.categoryDonut && (
            <div className={`${widgets.trendChart ? "lg:col-span-1" : "lg:col-span-3"} p-5 bg-slate-900/60 border border-slate-800 rounded-xl flex flex-col justify-between`}>
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-3 mb-4">
                <span className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                  <Layers className="h-4 w-4 text-indigo-400" />
                  Threat Categories
                </span>
                <span className="text-xs font-mono text-slate-500">Active Distribution</span>
              </div>
              <div className="h-52 w-full flex items-center justify-center">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={threatCategoryData}
                      cx="50%"
                      cy="50%"
                      innerRadius={45}
                      outerRadius={75}
                      paddingAngle={5}
                      dataKey="value"
                    >
                      {threatCategoryData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", borderRadius: "8px" }} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div className="space-y-1.5 mt-2">
                {threatCategoryData.map((cat) => (
                  <div key={cat.name} className="flex items-center justify-between text-xs font-mono">
                    <div className="flex items-center gap-2">
                      <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: cat.color }}></span>
                      <span className="text-slate-300 truncate max-w-[150px]">{cat.name}</span>
                    </div>
                    <span className="text-slate-400 font-semibold">{cat.value}%</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Widget 4: Alert Throughput */}
      {widgets.throughputChart && (
        <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-xl">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3 mb-4">
            <span className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-emerald-400" />
              SOC Alert Ingestion vs Resolution Throughput
            </span>
            <span className="text-xs font-mono text-slate-500">Weekly Pace Analysis</span>
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={throughputData}>
                <XAxis dataKey="period" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={11} />
                <Tooltip
                  contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", borderRadius: "8px" }}
                  labelStyle={{ color: "#94a3b8" }}
                />
                <Bar dataKey="open" fill="#f87171" radius={[4, 4, 0, 0]} name="Alerts Opened" />
                <Bar dataKey="resolved" fill="#34d399" radius={[4, 4, 0, 0]} name="Alerts Resolved" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Widget 5: Global Geographic Attack Heatmap */}
      {widgets.globalMap && <GlobalHeatmap />}
    </div>
  );
}