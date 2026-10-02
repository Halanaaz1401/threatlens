"use client";

import React, { useEffect, useState } from "react";
import dynamic from "next/dynamic";
import "leaflet/dist/leaflet.css";
import { safeFetchGeoAnalytics } from "@/lib/api";

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

const COUNTRY_COORDINATES: Record<string, { lat: number; lng: number }> = {
  US: { lat: 37.0902, lng: -95.7129 },
  USA: { lat: 37.0902, lng: -95.7129 },
  CN: { lat: 35.8617, lng: 104.1954 },
  CHINA: { lat: 35.8617, lng: 104.1954 },
  RU: { lat: 61.524, lng: 105.3188 },
  RUSSIA: { lat: 61.524, lng: 105.3188 },
  DE: { lat: 51.1657, lng: 10.4515 },
  GERMANY: { lat: 51.1657, lng: 10.4515 },
  NL: { lat: 52.1326, lng: 5.2913 },
  NETHERLANDS: { lat: 52.1326, lng: 5.2913 },
  GB: { lat: 55.3781, lng: -3.436 },
  UK: { lat: 55.3781, lng: -3.436 },
  FR: { lat: 46.2276, lng: 2.2137 },
  FRANCE: { lat: 46.2276, lng: 2.2137 },
  IN: { lat: 20.5937, lng: 78.9629 },
  INDIA: { lat: 20.5937, lng: 78.9629 },
  JP: { lat: 36.2048, lng: 138.2529 },
  JAPAN: { lat: 36.2048, lng: 138.2529 },
  KR: { lat: 35.9078, lng: 127.7669 },
  KOREA: { lat: 35.9078, lng: 127.7669 },
  BR: { lat: -14.235, lng: -51.9253 },
  BRAZIL: { lat: -14.235, lng: -51.9253 },
};

export function GlobalHeatmap() {
  const [isClient, setIsClient] = useState(false);
  const [loading, setLoading] = useState(true);
  const [threatLocations, setThreatLocations] = useState<ThreatLocation[]>([]);
  const [hasData, setHasData] = useState(false);

  useEffect(() => {
    setIsClient(true);
    let isMounted = true;
    safeFetchGeoAnalytics()
      .then((data) => {
        if (!isMounted) return;
        if (data && data.has_data && Array.isArray(data.countries) && data.countries.length > 0) {
          setHasData(true);
          const mapped: ThreatLocation[] = [];
          data.countries.forEach((c: { country?: string; country_code?: string; country_name?: string; count: number }, idx: number) => {
            const code = (c.country_code || c.country || "").toUpperCase().trim();
            const name = c.country_name || c.country || code;
            const coords = COUNTRY_COORDINATES[code] || COUNTRY_COORDINATES[name.toUpperCase()];
            if (coords) {
              mapped.push({
                id: `geo-${idx}`,
                name: name,
                lat: coords.lat,
                lng: coords.lng,
                count: c.count,
                severity: c.count > 10 ? "Critical" : c.count > 3 ? "High" : "Medium",
                color: c.count > 10 ? "#ef4444" : c.count > 3 ? "#f97316" : "#eab308",
              });
            }
          });
          setThreatLocations(mapped);
        } else {
          setHasData(false);
          setThreatLocations([]);
        }
      })
      .catch(() => {
        if (isMounted) {
          setHasData(false);
          setThreatLocations([]);
        }
      })
      .finally(() => {
        if (isMounted) setLoading(false);
      });

    return () => {
      isMounted = false;
    };
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
          <span className="w-5 h-5 rounded-full bg-cyan-950/90 border border-cyan-500 flex items-center justify-center text-[10px] text-cyan-400 font-bold">
            ((o))
          </span>
          <h2 className="text-sm font-semibold text-slate-200">
            Global Threat Heatmap &amp; Origin Telemetry
          </h2>
        </div>
        <div className="flex items-center gap-2 text-[11px] text-cyan-400 font-medium">
          <span className="w-2 h-2 rounded-full bg-cyan-500 animate-pulse" />
          <span>Real-time Analytics API</span>
        </div>
      </div>

      {/* Map Canvas or Honest Empty State */}
      {loading ? (
        <div className="h-[320px] w-full bg-[#080d19] rounded-lg border border-slate-800 flex items-center justify-center text-slate-500 text-xs font-mono animate-pulse">
          Loading geographic telemetry from database...
        </div>
      ) : !hasData || threatLocations.length === 0 ? (
        <div className="h-[320px] w-full bg-[#080d19] rounded-lg border border-slate-800 flex flex-col items-center justify-center p-6 text-center">
          <div className="w-10 h-10 rounded-full bg-slate-900 border border-slate-700 flex items-center justify-center text-slate-400 text-lg mb-2">
            🌍
          </div>
          <h3 className="text-xs font-semibold text-slate-300">No Geographic Threat Telemetry Available</h3>
          <p className="text-[11px] text-slate-500 mt-1 max-w-md">
            No indicators currently possess geolocation attribution records. ThreatLens strictly displays backend-verified geographic intelligence and does not synthesize speculative attack locations.
          </p>
        </div>
      ) : (
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
            {threatLocations.map((point) => (
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
                    <p className="text-[10px] font-mono text-cyan-400 uppercase">
                      Severity: {point.severity}
                    </p>
                  </div>
                </Tooltip>
              </CircleMarker>
            ))}
          </MapContainer>
        </div>
      )}
    </div>
  );
}

export default GlobalHeatmap;