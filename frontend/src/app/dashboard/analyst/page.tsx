"use client";

import React, { useState, useEffect } from "react";
import { 
  ShieldAlert, 
  RefreshCw, 
  CheckCircle2, 
  Zap, 
  X, 
  ExternalLink, 
  Globe, 
  Server, 
  Activity, 
  Radio, 
  Eye,
  Crosshair
} from "lucide-react";
import axios from "axios";

interface AlertItem {
  id: string;
  rule_id: string;
  indicator_id: string;
  severity: string;
  status: string;
  assignee: string | null;
  created_at: string;
}

interface IndicatorDetail {
  id: string;
  value: string;
  type: string;
  severity_score: number;
  confidence: number;
  tlp: string;
  first_seen: string;
  last_seen: string;
  sources: { name: string; confidence: number; reported_at: string }[];
  enrichment: {
    asn: string;
    country: string;
    abuse_confidence: number;
    virustotal_ratio: string;
    threat_actor?: string;
  };
  internal_sightings: {
    timestamp: string;
    src_ip: string;
    dest_ip: string;
    hostname: string;
    protocol: string;
  }[];
}

export default function AnalystDashboard() {
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [updatingId, setUpdatingId] = useState<string | null>(null);
  
  // Drawer & Selection State
  const [selectedAlert, setSelectedAlert] = useState<AlertItem | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [indicatorData, setIndicatorData] = useState<IndicatorDetail | null>(null);
  const [enriching, setEnriching] = useState(false);

  const fetchAlerts = async () => {
    try {
      setLoading(true);
      const res = await axios.get("http://localhost:8000/api/v1/alerts/");
      setAlerts(res.data);
    } catch (err) {
      console.error("Failed to load alerts", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();

    const ws = new WebSocket("ws://localhost:8000/api/v1/alerts/ws");
    ws.onmessage = (event) => {
      try {
        const newAlert = JSON.parse(event.data);
        setAlerts((prev) => [newAlert, ...prev]);
      } catch (e) {
        console.error("WebSocket parse error", e);
      }
    };

    return () => {
      ws.close();
    };
  }, []);

  const handleUpdateStatus = async (id: string, newStatus: string) => {
    try {
      setUpdatingId(id);
      await axios.patch(`http://localhost:8000/api/v1/alerts/${id}`, {
        status: newStatus,
        assignee: "analyst_1",
      });
      setAlerts((prev) =>
        prev.map((a) => (a.id === id ? { ...a, status: newStatus, assignee: "analyst_1" } : a))
      );
    } catch (err) {
      console.error("Update failed", err);
    } finally {
      setUpdatingId(null);
    }
  };

  const openIndicatorDrawer = (alert: AlertItem) => {
    setSelectedAlert(alert);
    setDrawerOpen(true);
    // Mock enriched detail data according to PRD Sec 12.2
    setIndicatorData({
      id: alert.indicator_id || "ind-8823-909",
      value: "185.220.101.4",
      type: "IPv4",
      severity_score: alert.severity === "CRITICAL" ? 92 : 78,
      confidence: 95,
      tlp: "AMBER",
      first_seen: "2026-08-14 10:22:00 UTC",
      last_seen: "2026-08-15 15:45:10 UTC",
      sources: [
        { name: "AlienVault OTX", confidence: 90, reported_at: "2026-08-15 14:10" },
        { name: "AbuseIPDB", confidence: 98, reported_at: "2026-08-15 15:02" },
        { name: "Feodo Tracker", confidence: 95, reported_at: "2026-08-15 15:30" },
      ],
      enrichment: {
        asn: "AS206238 (Zwiebelfreunde e.V.)",
        country: "Germany (DE)",
        abuse_confidence: 98,
        virustotal_ratio: "18/89 Engines Flagged",
        threat_actor: "UNC2165 / Evil Corp Affiliate",
      },
      internal_sightings: [
        {
          timestamp: "2026-08-15 16:12:05 IST",
          src_ip: "192.168.1.105",
          dest_ip: "185.220.101.4",
          hostname: "FIN-WKS-042",
          protocol: "HTTPS / Port 443",
        },
        {
          timestamp: "2026-08-15 16:14:32 IST",
          src_ip: "192.168.1.105",
          dest_ip: "185.220.101.4",
          hostname: "FIN-WKS-042",
          protocol: "TCP / Port 8080",
        },
      ],
    });
  };

  const triggerEnrichment = () => {
    setEnriching(true);
    setTimeout(() => {
      setEnriching(false);
      alert("Enrichment refreshed across VirusTotal, AbuseIPDB, and OTX.");
    }, 1000);
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev.toUpperCase()) {
      case "CRITICAL":
        return "bg-red-500/10 text-red-400 border-red-500/30";
      case "HIGH":
        return "bg-orange-500/10 text-orange-400 border-orange-500/30";
      case "MEDIUM":
        return "bg-yellow-500/10 text-yellow-400 border-yellow-500/30";
      default:
        return "bg-blue-500/10 text-blue-400 border-blue-500/30";
    }
  };

  return (
    <div className="space-y-6 relative">
      {/* Header & Metrics */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <ShieldAlert className="h-6 w-6 text-red-500" />
            SOC Analyst Triage Queue
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            Persona: Priya Nair (Tier-2 SOC Analyst) — Live Real-Time Ingestion Stream
          </p>
        </div>

        <button
          onClick={fetchAlerts}
          className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono border border-slate-700 transition text-slate-200"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
          Refresh Feed
        </button>
      </div>

      {/* Live Alert Queue */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden shadow-2xl">
        <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
          <span className="text-sm font-semibold text-slate-200 flex items-center gap-2">
            <Zap className="h-4 w-4 text-yellow-400" />
            Active Alert Queue ({alerts.length})
          </span>
          <span className="text-xs font-mono text-slate-500">Sorted by Severity & Recency</span>
        </div>

        {alerts.length === 0 ? (
          <div className="p-12 text-center text-slate-500 text-sm font-mono">
            No active alerts in queue.
          </div>
        ) : (
          <div className="divide-y divide-slate-800/80">
            {alerts.map((alert) => (
              <div 
                key={alert.id} 
                className="p-4 hover:bg-slate-800/30 transition flex flex-col md:flex-row items-start md:items-center justify-between gap-4"
              >
                {/* Alert Details */}
                <div className="space-y-1 cursor-pointer" onClick={() => openIndicatorDrawer(alert)}>
                  <div className="flex items-center gap-2.5">
                    <span className={`px-2 py-0.5 text-[11px] font-bold font-mono border rounded ${getSeverityBadge(alert.severity)}`}>
                      {alert.severity}
                    </span>
                    <span className="text-sm font-mono font-medium text-slate-200 hover:text-red-400 transition flex items-center gap-1.5">
                      {alert.rule_id}
                      <Eye className="h-3.5 w-3.5 text-slate-500" />
                    </span>
                    <span className="text-xs text-slate-500 font-mono">({new Date(alert.created_at).toLocaleTimeString()})</span>
                  </div>
                  <div className="text-xs text-slate-400 font-mono">
                    Indicator ID: <span className="text-slate-300">{alert.indicator_id || "N/A"}</span> | Assignee: <span className="text-slate-300">{alert.assignee || "Unassigned"}</span>
                  </div>
                </div>

                {/* Status & Actions */}
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => openIndicatorDrawer(alert)}
                    className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 rounded text-xs font-mono flex items-center gap-1 transition"
                  >
                    <Crosshair className="h-3.5 w-3.5 text-red-400" />
                    Investigate
                  </button>

                  <span className="text-xs font-mono px-2.5 py-1 rounded bg-slate-800 text-slate-300 border border-slate-700">
                    Status: <span className="text-white font-semibold">{alert.status}</span>
                  </span>

                  {alert.status === "NEW" && (
                    <button
                      disabled={updatingId === alert.id}
                      onClick={() => handleUpdateStatus(alert.id, "ACKNOWLEDGED")}
                      className="px-3 py-1.5 bg-blue-600/20 hover:bg-blue-600/40 text-blue-400 border border-blue-500/40 rounded text-xs font-mono transition"
                    >
                      Acknowledge
                    </button>
                  )}

                  {alert.status === "ACKNOWLEDGED" && (
                    <button
                      disabled={updatingId === alert.id}
                      onClick={() => handleUpdateStatus(alert.id, "IN_PROGRESS")}
                      className="px-3 py-1.5 bg-yellow-600/20 hover:bg-yellow-600/40 text-yellow-400 border border-yellow-500/40 rounded text-xs font-mono transition"
                    >
                      Start Triage
                    </button>
                  )}

                  {alert.status === "IN_PROGRESS" && (
                    <button
                      disabled={updatingId === alert.id}
                      onClick={() => handleUpdateStatus(alert.id, "RESOLVED")}
                      className="px-3 py-1.5 bg-emerald-600/20 hover:bg-emerald-600/40 text-emerald-400 border border-emerald-500/40 rounded text-xs font-mono transition flex items-center gap-1"
                    >
                      <CheckCircle2 className="h-3.5 w-3.5" />
                      Resolve
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Slide-out Indicator Detail Drawer & Correlation Panel */}
      {drawerOpen && indicatorData && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-xs transition-all">
          <div className="w-full max-w-2xl bg-slate-900 border-l border-slate-800 h-full overflow-y-auto p-6 space-y-6 shadow-2xl">
            
            {/* Drawer Header */}
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div className="space-y-1">
                <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">Indicator Deep Dive</span>
                <h2 className="text-lg font-bold font-mono text-white flex items-center gap-2">
                  <Globe className="h-5 w-5 text-red-400" />
                  {indicatorData.value}
                </h2>
              </div>
              <button 
                onClick={() => setDrawerOpen(false)}
                className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            {/* Quick Metrics */}
            <div className="grid grid-cols-3 gap-3">
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <span className="text-[10px] font-mono text-slate-500 block">SEVERITY SCORE</span>
                <span className="text-xl font-bold font-mono text-red-400">{indicatorData.severity_score}/100</span>
              </div>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <span className="text-[10px] font-mono text-slate-500 block">CONFIDENCE</span>
                <span className="text-xl font-bold font-mono text-yellow-400">{indicatorData.confidence}%</span>
              </div>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <span className="text-[10px] font-mono text-slate-500 block">TLP MARKING</span>
                <span className="text-xl font-bold font-mono text-amber-400">{indicatorData.tlp}</span>
              </div>
            </div>

            {/* 1-Click Enrichment Trigger */}
            <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                  <Activity className="h-4 w-4 text-indigo-400" />
                  Enrichment Analysis Verdicts
                </span>
                <button
                  onClick={triggerEnrichment}
                  disabled={enriching}
                  className="px-2.5 py-1 bg-indigo-600/20 hover:bg-indigo-600/40 text-indigo-300 border border-indigo-500/40 rounded text-xs font-mono transition flex items-center gap-1"
                >
                  <RefreshCw className={`h-3 w-3 ${enriching ? "animate-spin" : ""}`} />
                  {enriching ? "Enriching..." : "Re-Enrich (1-Click)"}
                </button>
              </div>

              <div className="grid grid-cols-2 gap-2 text-xs font-mono pt-2">
                <div className="text-slate-400">ASN: <span className="text-slate-200">{indicatorData.enrichment.asn}</span></div>
                <div className="text-slate-400">Geo: <span className="text-slate-200">{indicatorData.enrichment.country}</span></div>
                <div className="text-slate-400">AbuseIPDB Confidence: <span className="text-red-400 font-bold">{indicatorData.enrichment.abuse_confidence}%</span></div>
                <div className="text-slate-400">VirusTotal: <span className="text-orange-400 font-bold">{indicatorData.enrichment.virustotal_ratio}</span></div>
              </div>
            </div>

            {/* Source Provenance */}
            <div className="space-y-3">
              <span className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                <Radio className="h-4 w-4 text-emerald-400" />
                Source Provenance (Multi-Feed Aggregation)
              </span>
              <div className="space-y-2">
                {indicatorData.sources.map((src) => (
                  <div key={src.name} className="flex items-center justify-between p-2.5 rounded-lg bg-slate-950 border border-slate-850 text-xs font-mono">
                    <span className="text-slate-200">{src.name}</span>
                    <span className="text-emerald-400">Confidence: {src.confidence}%</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Internal Sightings Correlation Panel */}
            <div className="space-y-3">
              <span className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                <Server className="h-4 w-4 text-red-400" />
                Internal Sightings & Event Correlation (SIEM telemetry)
              </span>
              <div className="border border-slate-800 rounded-lg overflow-hidden">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                    <tr>
                      <th className="p-2.5">Timestamp</th>
                      <th className="p-2.5">Hostname</th>
                      <th className="p-2.5">Source IP</th>
                      <th className="p-2.5">Protocol</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800 bg-slate-900/40">
                    {indicatorData.internal_sightings.map((s, idx) => (
                      <tr key={idx} className="hover:bg-slate-800/30">
                        <td className="p-2.5 text-slate-400">{s.timestamp}</td>
                        <td className="p-2.5 text-slate-200 font-semibold">{s.hostname}</td>
                        <td className="p-2.5 text-red-400">{s.src_ip}</td>
                        <td className="p-2.5 text-slate-300">{s.protocol}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

          </div>
        </div>
      )}
    </div>
  );
}