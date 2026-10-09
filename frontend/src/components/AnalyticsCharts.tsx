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
import { TrendingUp, PieChart as PieChartIcon } from "lucide-react";

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
      <div className="lg:col-span-8 bg-[#111214] border border-[#2B2C30] rounded-xl p-5 shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h3 className="text-sm font-semibold text-[#F2F2F0] flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-[#19D5E5]" />
              <span>Threat Ingestion &amp; Severity Velocity</span>
            </h3>
            <p className="text-xs text-[#B0B0B4]">
              Correlated throughput across intelligence feeds ({totalIngests} total ingests)
            </p>
          </div>

          <div className="flex items-center gap-1.5 bg-[#090A0C] border border-[#2B2C30] rounded-lg p-1 text-[11px] font-mono">
            {["24h", "7d", "30d", "90d"].map((tr) => (
              <button
                key={tr}
                onClick={() => handleRange(tr)}
                className={`px-2.5 py-0.5 rounded font-bold transition cursor-pointer ${
                  selectedRange === tr
                    ? "bg-[#17181B] text-[#19D5E5] border border-[#19D5E5]/40"
                    : "text-[#85858B] hover:text-[#F2F2F0]"
                }`}
              >
                {tr}
              </button>
            ))}
          </div>
        </div>

        <div className="h-64 w-full">
          {isLoading ? (
            <div className="h-full w-full flex items-center justify-center text-xs text-[#85858B] font-mono animate-pulse">
              Aggregating live threat velocity...
            </div>
          ) : series.length === 0 || totalIngests === 0 ? (
            <div className="h-full w-full flex flex-col items-center justify-center text-xs text-[#85858B] font-mono gap-1">
              <span>Zero indicator ingests in selected {selectedRange} window</span>
              <span className="text-[10px] text-[#85858B]">Feed ingestion active</span>
            </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={series}>
                <defs>
                  <linearGradient id="colorIngest" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#19D5E5" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#19D5E5" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="colorHigh" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#EF4444" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#EF4444" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="label" stroke="#85858B" fontSize={11} tickLine={false} />
                <YAxis stroke="#85858B" fontSize={11} allowDecimals={false} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#111214",
                    borderColor: "#2B2C30",
                    borderRadius: "0.5rem",
                    fontSize: "12px",
                    color: "#F2F2F0",
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="ingests"
                  name="Total Ingests"
                  stroke="#19D5E5"
                  strokeWidth={1.5}
                  fillOpacity={1}
                  fill="url(#colorIngest)"
                />
                <Area
                  type="monotone"
                  dataKey="high_severity"
                  name="High Severity"
                  stroke="#EF4444"
                  strokeWidth={1.5}
                  fillOpacity={1}
                  fill="url(#colorHigh)"
                />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Severity Ratio Donut */}
      <div className="lg:col-span-4 bg-[#111214] border border-[#2B2C30] rounded-xl p-5 shadow-sm space-y-4">
        <div>
          <h3 className="text-sm font-semibold text-[#F2F2F0] flex items-center gap-2">
            <PieChartIcon className="w-4 h-4 text-[#19D5E5]" />
            <span>Active Severity Distribution</span>
          </h3>
          <p className="text-xs text-[#B0B0B4]">Aggregated risk tiers ({totalSeverityCount} IOCs)</p>
        </div>

        <div className="h-44 w-full flex items-center justify-center">
          {isLoading ? (
            <div className="text-xs text-[#85858B] font-mono animate-pulse">Calculating...</div>
          ) : totalSeverityCount === 0 ? (
            <div className="text-xs text-[#85858B] font-mono">No active indicators</div>
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
                    backgroundColor: "#111214",
                    borderColor: "#2B2C30",
                    borderRadius: "0.5rem",
                    fontSize: "12px",
                    color: "#F2F2F0",
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className="space-y-1.5 text-xs font-medium">
          {severity.map((item, i) => (
            <div key={i} className="flex items-center justify-between">
              <span className="flex items-center gap-2 text-[#B0B0B4]">
                <span
                  className="w-2.5 h-2.5 rounded-full"
                  style={{ backgroundColor: item.color }}
                />
                {item.name}
              </span>
              <span className="font-mono text-[#F2F2F0]">{item.value}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
