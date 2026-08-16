"use client";

import React from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from "recharts";

const timeSeriesData = [
  { time: "00:00", ingests: 120, highSev: 14 },
  { time: "04:00", ingests: 240, highSev: 28 },
  { time: "08:00", ingests: 450, highSev: 65 },
  { time: "12:00", ingests: 780, highSev: 110 },
  { time: "16:00", ingests: 920, highSev: 145 },
  { time: "20:00", ingests: 610, highSev: 82 },
  { time: "24:00", ingests: 380, highSev: 41 },
];

const severityBreakdown = [
  { name: "Critical (80-100)", value: 42, color: "#ef4444" },
  { name: "High (60-79)", value: 78, color: "#f97316" },
  { name: "Medium (40-59)", value: 135, color: "#eab308" },
  { name: "Low / Info (<40)", value: 210, color: "#3b82f6" },
];

export default function AnalyticsCharts() {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
      {/* Time Series Ingestion Volume */}
      <div className="lg:col-span-8 bg-[#0b1220] border border-slate-800 rounded-2xl p-5 shadow-sm space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <span>📈</span> 24-Hour Threat Ingestion &amp; Severity Velocity
            </h3>
            <p className="text-xs text-slate-400">
              Correlated throughput across 6 public &amp; private intelligence feeds
            </p>
          </div>
          <span className="text-[10px] font-mono bg-cyan-950/80 text-cyan-400 border border-cyan-800 px-2 py-0.5 rounded">
            Live Telemetry
          </span>
        </div>

        <div className="h-64 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={timeSeriesData}>
              <defs>
                <linearGradient id="colorIngest" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="colorHigh" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="time" stroke="#64748b" fontSize={11} />
              <YAxis stroke="#64748b" fontSize={11} />
              <Tooltip
                contentStyle={{
                  backgroundColor: "#080d19",
                  borderColor: "#334155",
                  borderRadius: "0.75rem",
                  fontSize: "12px",
                }}
              />
              <Area
                type="monotone"
                dataKey="ingests"
                name="Total Ingests"
                stroke="#06b6d4"
                fillOpacity={1}
                fill="url(#colorIngest)"
              />
              <Area
                type="monotone"
                dataKey="highSev"
                name="High Severity"
                stroke="#ef4444"
                fillOpacity={1}
                fill="url(#colorHigh)"
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Severity Ratio Donut */}
      <div className="lg:col-span-4 bg-[#0b1220] border border-slate-800 rounded-2xl p-5 shadow-sm space-y-4">
        <div>
          <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <span>🎯</span> Active Severity Distribution
          </h3>
          <p className="text-xs text-slate-400">Aggregated risk tiers in database</p>
        </div>

        <div className="h-44 w-full flex items-center justify-center">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={severityBreakdown}
                innerRadius={50}
                outerRadius={75}
                paddingAngle={4}
                dataKey="value"
              >
                {severityBreakdown.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  backgroundColor: "#080d19",
                  borderColor: "#334155",
                  borderRadius: "0.75rem",
                  fontSize: "12px",
                }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="space-y-1.5 text-xs font-medium">
          {severityBreakdown.map((item, i) => (
            <div key={i} className="flex items-center justify-between">
              <span className="flex items-center gap-2 text-slate-300">
                <span
                  className="w-2.5 h-2.5 rounded-full"
                  style={{ backgroundColor: item.color }}
                />
                {item.name}
              </span>
              <span className="font-mono text-slate-400">{item.value}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
