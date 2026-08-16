"use client";

import React, { useEffect, useState } from "react";
import dynamic from "next/dynamic";
import "leaflet/dist/leaflet.css";

// Dynamic import with SSR completely disabled
const MapContainer = dynamic(
  () => import("react-leaflet").then((mod) => mod.MapContainer),
  { ssr: false }
);
const TileLayer = dynamic(
  () => import("react-leaflet").then((mod) => mod.TileLayer),
  { ssr: false }
);
const CircleMarker = dynamic(
  () => import("react-leaflet").then((mod) => mod.CircleMarker),
  { ssr: false }
);
const Tooltip = dynamic(
  () => import("react-leaflet").then((mod) => mod.Tooltip),
  { ssr: false }
);

interface ThreatLocation {
  id: string;
  name: string;
  lat: number;
  lng: number;
  count: number;
  severity: "Critical" | "High" | "Medium";
  color: string;
}

const THREAT_ORIGINS: ThreatLocation[] = [
  { id: "1", name: "United States (US-East)", lat: 37.7749, lng: -122.4194, count: 1240, severity: "High", color: "#f97316" },
  { id: "2", name: "Europe (Frankfurt C2)", lat: 50.1109, lng: 8.6821, count: 2890, severity: "Critical", color: "#ef4444" },
  { id: "3", name: "Russia (Moscow Pivot)", lat: 55.7558, lng: 37.6173, count: 3410, severity: "Critical", color: "#ef4444" },
  { id: "4", name: "India (Bengaluru Gateway)", lat: 12.9716, lng: 77.5946, count: 980, severity: "High", color: "#f97316" },
  { id: "5", name: "East Asia (Seoul Ingress)", lat: 37.5665, lng: 126.978, count: 620, severity: "Medium", color: "#eab308" },
];

export function GlobalHeatmap() {
  const [isClient, setIsClient] = useState(false);

  useEffect(() => {
    setIsClient(true);
  }, []);

  if (!isClient) {
    return (
      <div className="h-[320px] w-full bg-[#080d19] rounded-xl border border-slate-800 flex items-center justify-center text-slate-500 text-xs font-mono">
        Initializing Live Geo-Telemetry Map...
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* Heatmap Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="w-5 h-5 rounded-full bg-red-950/90 border border-red-500 flex items-center justify-center text-[10px] text-red-400 font-bold">
            ((o))
          </span>
          <h2 className="text-sm font-semibold text-slate-200">
            Global Threat Heatmap &amp; Origin Telemetry
          </h2>
        </div>
        <div className="flex items-center gap-2 text-[11px] text-red-400 font-medium">
          <span className="w-2 h-2 rounded-full bg-red-500 animate-ping" />
          <span>Live Geo-Enrichment Active</span>
        </div>
      </div>

      {/* Map Canvas */}
      <div className="h-[320px] w-full rounded-lg overflow-hidden border border-slate-800 relative z-0">
        <MapContainer
          center={[25, 20]}
          zoom={2}
          scrollWheelZoom={false}
          className="h-full w-full bg-[#080d19]"
        >
          <TileLayer
            attribution='&copy; <a href="https://carto.com/">CARTO</a>'
            url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
          />
          {THREAT_ORIGINS.map((point) => (
            <CircleMarker
              key={point.id}
              center={[point.lat, point.lng]}
              radius={point.severity === "Critical" ? 16 : point.severity === "High" ? 12 : 8}
              pathOptions={{
                color: point.color,
                fillColor: point.color,
                fillOpacity: 0.5,
                weight: 2,
              }}
            >
              <Tooltip direction="top" offset={[0, -10]} opacity={1}>
                <div className="bg-[#0b1220] border border-slate-700 p-2 rounded text-slate-200 text-xs shadow-lg">
                  <p className="font-bold text-slate-100">{point.name}</p>
                  <p className="text-[11px] text-slate-400">Events: {point.count.toLocaleString()}</p>
                  <p className="text-[10px] font-mono text-amber-400 uppercase">
                    Severity: {point.severity}
                  </p>
                </div>
              </Tooltip>
            </CircleMarker>
          ))}
        </MapContainer>
      </div>
    </div>
  );
}

export default GlobalHeatmap;