"use client";

import React, { useEffect, useState } from "react";
import { safeFetchGeoAnalytics } from "@/lib/api";

interface GeoCountry {
  country?: string;
  country_code?: string;
  country_name?: string;
  count: number;
}

export function AttackHeatmap() {
  const [loading, setLoading] = useState(true);
  const [geoData, setGeoData] = useState<{ has_data: boolean; countries: GeoCountry[] }>({
    has_data: false,
    countries: [],
  });

  useEffect(() => {
    let isMounted = true;
    safeFetchGeoAnalytics()
      .then((data) => {
        if (!isMounted) return;
        if (data && data.has_data && Array.isArray(data.countries)) {
          setGeoData(data);
        } else {
          setGeoData({ has_data: false, countries: [] });
        }
      })
      .catch(() => {
        if (isMounted) setGeoData({ has_data: false, countries: [] });
      })
      .finally(() => {
        if (isMounted) setLoading(false);
      });

    return () => {
      isMounted = false;
    };
  }, []);

  const total = geoData.countries.reduce((acc, c) => acc + c.count, 0) || 1;

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-5 backdrop-blur-md">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-sm font-semibold text-slate-100">Global Threat Geo-Density</h3>
          <p className="text-xs text-slate-400">Database-derived IoC origin density & targeted geographies</p>
        </div>
        <span className="inline-flex items-center gap-1.5 rounded-md bg-cyan-500/10 px-2.5 py-1 text-xs font-mono font-medium text-cyan-400 border border-cyan-500/20">
          <span className="h-1.5 w-1.5 rounded-full bg-cyan-500 animate-pulse" />
          Live Geo Analytics
        </span>
      </div>

      {loading ? (
        <div className="py-8 text-center text-xs text-slate-500 font-mono animate-pulse">
          Querying threat geography telemetry...
        </div>
      ) : !geoData.has_data || geoData.countries.length === 0 ? (
        <div className="py-8 text-center px-4 rounded-lg bg-slate-900/40 border border-slate-800/80">
          <p className="text-xs font-semibold text-slate-400">No Geographic Metadata Available</p>
          <p className="text-[11px] text-slate-500 mt-1 max-w-sm mx-auto">
            No indicators currently possess country attribution. Geographic distribution requires threat intelligence enrichment records with country metadata.
          </p>
        </div>
      ) : (
        <div className="space-y-3.5">
          {geoData.countries.map((item, idx) => {
            const share = Math.round((item.count / total) * 100);
            const displayName = item.country_name || item.country || item.country_code || `Location ${idx + 1}`;
            return (
              <div key={item.country_code || item.country || idx} className="space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-slate-300">{displayName}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-slate-400 font-mono">{item.count.toLocaleString()} IoCs</span>
                    <span className="font-semibold text-slate-100">{share}%</span>
                  </div>
                </div>
                <div className="h-2 w-full rounded-full bg-slate-800/80 overflow-hidden">
                  <div
                    className="h-full rounded-full bg-cyan-500 transition-all duration-500"
                    style={{ width: `${share}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}