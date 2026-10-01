"use client";

import React, { useEffect, useState } from "react";
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
import { safeFetchAnalyticsOverview } from "@/lib/api";

interface TimeSeriesPoint {
  label: string;
  ingests: number;
  high_severity: number;
  timestamp?: string;
}

interface SeveritySlice {
  name: string;
  severity: string;
  value: number;
  color: string;
}

interface AnalyticsChartsProps {
  timeSeriesData?: TimeSeriesPoint[];
  severityBreakdown?: SeveritySlice[];
  loading?: boolean;
  timeRange?: string;
  onTimeRangeChange?: (tr: string) => void;
}

export default function AnalyticsCharts({
  timeSeriesData: propTimeSeries,
  severityBreakdown: propSeverity,
  loading: propLoading,
  timeRange = "24h",
  onTimeRangeChange,
}: AnalyticsChartsProps) {
  const [internalSeries, setInternalSeries] = useState<TimeSeriesPoint[]>([]);
  const [internalSeverity, setInternalSeverity] = useState<SeveritySlice[]>([]);
  const [loading, setLoading] = useState<boolean>(propLoading ?? false);
  const [selectedRange, setSelectedRange] = useState<string>(timeRange);

  useEffect(() => {
    if (propTimeSeries && propSeverity) {
      setInternalSeries(propTimeSeries);
      setInternalSeverity(propSeverity);
      return;
    }

    async function loadData() {
      setLoading(true);
      const res = await safeFetchAnalyticsOverview(selectedRange);
      if (res && res.trends && res.trends.series) {
        setInternalSeries(res.trends.series);
      } else {
        setInternalSeries([]);
      }

      if (res && res.severity && res.severity.chart_data) {
        setInternalSeverity(res.severity.chart_data);
      } else {
        setInternalSeverity([]);
      }
      setLoading(false);
    }

    loadData();
  }, [propTimeSeries, propSeverity, selectedRange]);

  const handleRange = (tr: string) => {
    setSelectedRange(tr);
    if (onTimeRangeChange) {
      onTimeRangeChange(tr);
    }
  };

  const series = propTimeSeries ?? internalSeries;
  const severity = propSeverity ?? internalSeverity;
  const isLoading = propLoading ?? loading;

  const totalIngests = series.reduce((acc, p) => acc + (p.ingests || 0), 0);
  const totalSeverityCount = severity.reduce((acc, s) => acc + (s.value || 0), 0);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
      {/* Time Series Ingestion Volume */}
      <div className="lg:col-span-8 bg-[#0b1220] border border-slate-800 rounded-2xl p-5 shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <span>📈</span> Threat Ingestion &amp; Severity Velocity
            </h3>
            <p className="text-xs text-slate-400">
              Correlated throughput across 6 intelligence feeds ({totalIngests} total ingests)
            </p>
          </div>

          <div className="flex items-center gap-1.5 bg-[#080d19] border border-slate-800 rounded-xl p-1 text-[11px] font-mono">
            {["24h", "7d", "30d", "90d"].map((tr) => (
              <button
                key={tr}
                onClick={() => handleRange(tr)}
                className={`px-2.5 py-0.5 rounded-lg font-bold transition ${
                  selectedRange === tr
                    ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/40"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                {tr}
              </button>
            ))}
          </div>
        </div>

        <div className="h-64 w-full">
          {isLoading ? (
            <div className="h-full w-full flex items-center justify-center text-xs text-slate-500 font-mono animate-pulse">
              Aggregating live threat velocity...
            </div>
          ) : series.length === 0 || totalIngests === 0 ? (
            <div className="h-full w-full flex flex-col items-center justify-center text-xs text-slate-500 font-mono gap-1">
              <span>Zero indicator ingests in selected {selectedRange} window</span>
              <span className="text-[10px] text-slate-600">Feed ingestion active</span>
            </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={series}>
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
                <XAxis dataKey="label" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
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
                  dataKey="high_severity"
                  name="High Severity"
                  stroke="#ef4444"
                  fillOpacity={1}
                  fill="url(#colorHigh)"
                />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Severity Ratio Donut */}
      <div className="lg:col-span-4 bg-[#0b1220] border border-slate-800 rounded-2xl p-5 shadow-sm space-y-4">
        <div>
          <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <span>🎯</span> Active Severity Distribution
          </h3>
          <p className="text-xs text-slate-400">Aggregated risk tiers ({totalSeverityCount} IOCs)</p>
        </div>

        <div className="h-44 w-full flex items-center justify-center">
          {isLoading ? (
            <div className="text-xs text-slate-500 font-mono animate-pulse">Calculating...</div>
          ) : totalSeverityCount === 0 ? (
            <div className="text-xs text-slate-500 font-mono">No active indicators</div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={severity}
                  innerRadius={50}
                  outerRadius={75}
                  paddingAngle={4}
                  dataKey="value"
                >
                  {severity.map((entry, index) => (
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
          )}
        </div>

        <div className="space-y-1.5 text-xs font-medium">
          {severity.map((item, i) => (
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
