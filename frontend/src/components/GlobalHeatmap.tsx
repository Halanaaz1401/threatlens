"use client";

import React, { useEffect, useState } from "react";
import dynamic from "next/dynamic";
import "leaflet/dist/leaflet.css";
import { Globe2, ShieldAlert } from "lucide-react";

// Leaflet SSR hydration bypass
const MapContainer = dynamic(
  () => import("react-leaflet").then((m) => m.MapContainer),
  { ssr: false }
);
const TileLayer = dynamic(
  () => import("react-leaflet").then((m) => m.TileLayer),
  { ssr: false }
);
const CircleMarker = dynamic(
  () => import("react-leaflet").then((m) => m.CircleMarker),
  { ssr: false }
);
const Popup = dynamic(
  () => import("react-leaflet").then((m) => m.Popup),
  { ssr: false }
);

interface ThreatOrigin {
  id: string;
  lat: number;
  lng: number;
  country: string;
  city: string;
  ip: string;
  threat: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
  count: number;
}

const threatLocations: ThreatOrigin[] = [
  { id: "1", lat: 51.1657, lng: 10.4515, country: "Germany", city: "Frankfurt", ip: "185.220.101.4", threat: "Feodo C2 Node", severity: "CRITICAL", count: 34 },
  { id: "2", lat: 55.7558, lng: 37.6173, country: "Russia", city: "Moscow", ip: "91.240.118.12", threat: "Ransomware Drop Site", severity: "CRITICAL", count: 48 },
  { id: "3", lat: 37.7749, lng: -122.4194, country: "United States", city: "San Francisco", ip: "104.244.42.1", threat: "Phishing Infrastructure", severity: "HIGH", count: 19 },
  { id: "4", lat: 31.2304, lng: 121.4737, country: "China", city: "Shanghai", ip: "220.181.38.148", threat: "Port Scanning & Exploit Probing", severity: "MEDIUM", count: 12 },
  { id: "5", lat: 28.6139, lng: 77.2090, country: "India", city: "New Delhi", ip: "103.21.244.0", threat: "Credential Harvesting Proxy", severity: "HIGH", count: 22 },
  { id: "6", lat: 52.3676, lng: 4.9041, country: "Netherlands", city: "Amsterdam", ip: "194.26.29.112", threat: "Cobalt Strike Beacon", severity: "CRITICAL", count: 29 },
];

export default function GlobalHeatmap() {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  const getMarkerColor = (sev: string) => {
    switch (sev) {
      case "CRITICAL":
        return "#ef4444";
      case "HIGH":
        return "#f97316";
      default:
        return "#eab308";
    }
  };

  if (!mounted) {
    return (
      <div className="h-[380px] w-full rounded-xl bg-slate-900/60 border border-slate-800 flex items-center justify-center font-mono text-xs text-slate-500">
        Loading Global Threat Telemetry Map...
      </div>
    );
  }

  return (
    <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-xl space-y-4 shadow-xl">
      <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
        <div className="flex items-center gap-2">
          <Globe2 className="h-5 w-5 text-red-400 animate-pulse" />
          <span className="text-sm font-semibold text-slate-200">Global Threat Heatmap & Origin Telemetry</span>
        </div>
        <span className="text-xs font-mono text-slate-400 flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full bg-red-500"></span> Live Geo-Enrichment Active
        </span>
      </div>

      <div className="h-[380px] w-full rounded-lg overflow-hidden border border-slate-800 relative z-0">
        <MapContainer
          center={[25, 20]}
          zoom={2}
          scrollWheelZoom={false}
          className="h-full w-full bg-[#0b1120]"
        >
          <TileLayer
            attribution='&copy; <a href="https://carto.com/">CARTO</a>'
            url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
          />
          {threatLocations.map((loc) => (
            <CircleMarker
              key={loc.id}
              center={[loc.lat, loc.lng]}
              radius={8 + loc.count / 6}
              pathOptions={{
                color: getMarkerColor(loc.severity),
                fillColor: getMarkerColor(loc.severity),
                fillOpacity: 0.6,
                weight: 2,
              }}
            >
              <Popup className="custom-popup">
                <div className="p-1 font-mono text-xs text-slate-900">
                  <div className="font-bold text-red-600 flex items-center gap-1">
                    <ShieldAlert className="h-3.5 w-3.5" />
                    {loc.threat}
                  </div>
                  <div className="mt-1">Target IP: <b>{loc.ip}</b></div>
                  <div>Location: {loc.city}, {loc.country}</div>
                  <div>Events Detected: <b>{loc.count}</b></div>
                  <div className="mt-1 inline-block px-1.5 py-0.5 text-[10px] font-bold rounded bg-slate-200">
                    {loc.severity}
                  </div>
                </div>
              </Popup>
            </CircleMarker>
          ))}
        </MapContainer>
      </div>
    </div>
  );
}