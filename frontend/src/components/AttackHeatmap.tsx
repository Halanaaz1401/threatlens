"use client";

import React from "react";

interface GeoThreatOrigin {
  country: string;
  code: string;
  attacks: string;
  share: number;
  threatLevel: "CRITICAL" | "HIGH" | "ELEVATED" | "NORMAL";
  color: string;
}

const geoData: GeoThreatOrigin[] = [
  { country: "United States", code: "US", attacks: "1.42M", share: 38, threatLevel: "CRITICAL", color: "bg-rose-500" },
  { country: "China", code: "CN", attacks: "980K", share: 26, threatLevel: "HIGH", color: "bg-amber-500" },
  { country: "Russia", code: "RU", attacks: "640K", share: 17, threatLevel: "HIGH", color: "bg-purple-500" },
  { country: "Germany", code: "DE", attacks: "290K", share: 8, threatLevel: "ELEVATED", color: "bg-cyan-500" },
  { country: "Netherlands", code: "NL", attacks: "190K", share: 5, threatLevel: "NORMAL", color: "bg-emerald-500" },
];

export function AttackHeatmap() {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-5 backdrop-blur-md">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-sm font-semibold text-slate-100">Global Threat Geo-Density</h3>
          <p className="text-xs text-slate-400">Live IoC origin density & targeted geographies</p>
        </div>
        <span className="inline-flex items-center gap-1.5 rounded-md bg-rose-500/10 px-2.5 py-1 text-xs font-mono font-medium text-rose-400 border border-rose-500/20">
          <span className="h-1.5 w-1.5 rounded-full bg-rose-500 animate-pulse" />
          Ingesting GeoIP Feeds
        </span>
      </div>

      <div className="space-y-3.5">
        {geoData.map((item) => (
          <div key={item.code} className="space-y-1.5">
            <div className="flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <span className="font-mono font-bold text-slate-300">{item.code}</span>
                <span className="text-slate-200">{item.country}</span>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-slate-400 font-mono">{item.attacks} IoCs</span>
                <span className="font-semibold text-slate-100">{item.share}%</span>
              </div>
            </div>
            
            <div className="h-2 w-full rounded-full bg-slate-800/80 overflow-hidden">
              <div
                className={`h-full rounded-full ${item.color} transition-all duration-500`}
                style={{ width: `${item.share}%` }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}