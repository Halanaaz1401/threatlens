"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { useRole } from "@/context/RoleContext";
import { getAuthHeaders, getAuthToken } from "@/lib/auth";
import { safeFetchIndicatorEnrichment, safeFetchIndicators } from "@/lib/api";
import { DetectionRulesManager } from "@/components/DetectionRulesManager";

interface IOCItem {
  id: string;
  value: string;
  type: string;
  severity_score: number;
  confidence: number;
  tlp: string;
  status: string;
  tags?: string;
  mitre_technique?: string;
}

export default function AnalystDashboardPage() {
  const { persona } = useRole();
  const [activeTab, setActiveTab] = useState<"queue" | "rules">("queue");
  const [indicators, setIndicators] = useState<IOCItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [selectedIOC, setSelectedIOC] = useState<IOCItem | null>(null);
  const [enrichmentData, setEnrichmentData] = useState<any>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [liveToast, setLiveToast] = useState<any>(null);
  const [fetchError, setFetchError] = useState<string | null>(null);

  const fetchIndicators = async () => {
    try {
      setLoading(true);
      setFetchError(null);
      const items = await safeFetchIndicators();
      setIndicators(items);
      if (items.length > 0) {
        setSelectedIOC(items[0]);
        handleEnrich(items[0]);
      } else {
        setSelectedIOC(null);
      }
    } catch (err: any) {
      setIndicators([]);
      setSelectedIOC(null);
      setFetchError("Network error: Cannot reach ThreatLens API gateway.");
    } finally {
      setLoading(false);
    }
  };

  // Real-Time Authenticated WebSocket with Deduplication (FR-03, FR-15)
  useEffect(() => {
    fetchIndicators();

    let socket: WebSocket | null = null;
    try {
      const token = getAuthToken();
      const rawBase = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";
      const wsBase = rawBase.replace(/^http/, "ws");
      const wsUrl = token
        ? `${wsBase}/api/v1/ws/alerts?token=${encodeURIComponent(token)}`
        : `${wsBase}/api/v1/ws/alerts`;
      socket = new WebSocket(wsUrl);

      socket.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          const alertData = payload.data || payload;
          if (
            payload.event === "NEW_CRITICAL_ALERT" ||
            payload.type === "NEW_ALERT" ||
            alertData.indicator
          ) {
            setLiveToast(alertData);

            setIndicators((prev) => {
              const iocVal = alertData.indicator || alertData.ioc_value;
              if (!iocVal) return prev;
              // Deduplicate: If IOC value already exists, filter old one out and push fresh to top
              const filtered = prev.filter((item) => item.value !== iocVal);
              const newEntry: IOCItem = {
                id: alertData.id || `alert-${Date.now()}-${alertData.indicator || "event"}`,
                value: iocVal,
                type: alertData.type || "ip",
                severity_score: alertData.severity_score || alertData.threat_score || 85,
                confidence: alertData.confidence || 95,
                tlp: "amber",
                status: "active",
                tags: typeof alertData.tags === "string" ? alertData.tags : (Array.isArray(alertData.tags) ? alertData.tags.join(",") : (alertData.source || "live_feed")),
                mitre_technique: alertData.mitre || "T1071"
              };
              // Keep queue bounded to top 50 canonical items
              return [newEntry, ...filtered].slice(0, 50);
            });

            setTimeout(() => {
              setLiveToast(null);
            }, 5000);
          }
        } catch (e) {
          console.error("WS parse error:", e);
        }
      };
    } catch (wsErr) {
      console.warn("WebSocket idle:", wsErr);
    }

    return () => {
      if (socket && socket.readyState === WebSocket.OPEN) {
        socket.close();
      }
    };
  }, []);

  const handleSyncFeeds = async () => {
    try {
      setSyncing(true);
      let res = null;
      const headers = { ...getAuthHeaders() };
      try {
        res = await fetch("http://127.0.0.1:8000/api/v1/indicators/sync-feeds", { method: "POST", headers });
      } catch {
        res = await fetch("http://localhost:8000/api/v1/indicators/sync-feeds", { method: "POST", headers });
      }

      if (res && res.ok) {
        await fetchIndicators();
      }
    } catch (err) {
      console.error("Sync failed:", err);
    } finally {
      setSyncing(false);
    }
  };

  const handleEnrich = async (ioc: IOCItem) => {
    try {
      const res = await safeFetchIndicatorEnrichment(ioc.id);
      if (res && res.data && res.data.enrichments && res.data.enrichments.length > 0) {
        const primary = res.data.enrichments[0];
        const agg = res.data.aggregate || {};
        setEnrichmentData({
          verdict: agg.verdict ? agg.verdict.toUpperCase() : (ioc.severity_score >= 80 ? "MALICIOUS" : "SUSPICIOUS"),
          reputationScore: `${ioc.severity_score}/100`,
          virustotalDetection: agg.malicious_votes ? `${agg.malicious_votes} Engines Flagged` : (primary.verdict || "Enriched"),
          autonomousSystem: primary.raw_payload?.as_owner || primary.raw_payload?.asn || "AS Details N/A",
          geolocation: primary.raw_payload?.country_name || primary.raw_payload?.country || "Location N/A",
          abuseConfidence: `${ioc.confidence || agg.confidence || 0}%`,
        });
      } else {
        setEnrichmentData({
          verdict: ioc.severity_score >= 80 ? "HIGH SEVERITY (Pending Provider Verification)" : "SUSPICIOUS (Pending Enrichment)",
          reputationScore: `${ioc.severity_score}/100`,
          virustotalDetection: "No third-party provider record",
          autonomousSystem: "Autonomous System data unavailable",
          geolocation: "Country telemetry unavailable",
          abuseConfidence: `${ioc.confidence || 0}%`,
        });
      }
    } catch {
      setEnrichmentData({
        verdict: "ENRICHMENT UNAVAILABLE",
        reputationScore: `${ioc.severity_score}/100`,
        virustotalDetection: "Query error",
        autonomousSystem: "N/A",
        geolocation: "N/A",
        abuseConfidence: `${ioc.confidence || 0}%`,
      });
    }
  };

  const filteredIOCs = indicators.filter(
    (i) =>
      i.value.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (i.mitre_technique && i.mitre_technique.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (i.tags && i.tags.toLowerCase().includes(searchQuery.toLowerCase()))
  );

  return (
    <div className="space-y-6 pb-12 relative">
      {/* Real-time WebSocket Alert Toast Pop-up */}
      {liveToast && (
        <div className="fixed bottom-6 right-6 z-50 bg-[#0e1628] border-2 border-red-500/90 p-4 rounded-2xl shadow-2xl shadow-red-950/80 flex items-start gap-3 max-w-md animate-bounce">
          <span className="text-2xl">🚨</span>
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold text-red-400">CRITICAL INCOMING THREAT</span>
              <span className="text-[10px] font-mono text-slate-400">{liveToast.timestamp}</span>
            </div>
            <p className="text-xs font-mono font-bold text-slate-100 truncate">{liveToast.indicator}</p>
            <div className="flex items-center gap-2 text-[10px] font-mono text-slate-400 pt-1">
              <span>Score: <strong className="text-red-400">{liveToast.severity_score}/100</strong></span>
              <span>&bull;</span>
              <span>Source: {liveToast.source}</span>
            </div>
          </div>
        </div>
      )}

      {/* Persona Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-[#0b1220] border border-slate-800 rounded-2xl p-5 shadow-sm">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="text-xl font-bold text-slate-100 flex items-center gap-2">
              🛡️ SOC Analyst Triage Queue
            </span>
            <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-400 border border-cyan-800">
              {persona.name} ({persona.title})
            </span>
          </div>
          <p className="text-xs text-slate-400">
            Real-time live WebSocket stream active. Ingesting high-severity IOCs automatically.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleSyncFeeds}
            disabled={syncing}
            className="bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-bold px-4 py-2 rounded-xl text-xs flex items-center gap-2 shadow-sm transition"
          >
            <span className={syncing ? "animate-spin" : ""}>🔄</span>
            <span>{syncing ? "Ingesting Feeds..." : "Sync Threat Feeds"}</span>
          </button>

          <Link
            href="/dashboard/incidents"
            className="bg-orange-600 hover:bg-orange-500 text-white font-bold px-4 py-2 rounded-xl text-xs transition"
          >
            Escalate to IR &rarr;
          </Link>
        </div>
      </div>

      {/* View Switcher Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
        <button
          onClick={() => setActiveTab("queue")}
          className={`px-4 py-2 rounded-xl text-xs font-bold transition flex items-center gap-2 ${
            activeTab === "queue"
              ? "bg-cyan-950/80 text-cyan-400 border border-cyan-800 shadow-sm"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-900"
          }`}
        >
          <span>🛡️</span>
          <span>Triage Queue &amp; Enrichment</span>
        </button>
        <button
          onClick={() => setActiveTab("rules")}
          className={`px-4 py-2 rounded-xl text-xs font-bold transition flex items-center gap-2 ${
            activeTab === "rules"
              ? "bg-blue-950/80 text-blue-400 border border-blue-800 shadow-sm"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-900"
          }`}
        >
          <span>⚙️</span>
          <span>Detection Rules &amp; Alert Routing (FR-17 / FR-18)</span>
        </button>
      </div>

      {activeTab === "rules" ? (
        <DetectionRulesManager />
      ) : (
        /* Main Grid: Queue Table + Enrichment Inspector */
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Triage Table */}
        <div className="lg:col-span-7 bg-[#0b1220] border border-slate-800 rounded-2xl p-5 space-y-4 shadow-sm">
          <div className="flex items-center justify-between gap-4">
            <h2 className="text-sm font-bold text-slate-200 flex items-center gap-2">
              <span>🚨</span> Active Ingested Indicators ({filteredIOCs.length})
            </h2>
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter by IP, URL, MITRE..."
              className="bg-[#0e1628] border border-slate-700/80 rounded-lg px-3 py-1 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 w-48"
            />
          </div>

          {loading ? (
            <div className="py-20 text-center text-slate-500 text-xs font-mono animate-pulse">
              Loading Canonical Intelligence from PostgreSQL...
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 font-semibold uppercase text-[10px]">
                    <th className="pb-3">Indicator Value</th>
                    <th className="pb-3">Type</th>
                    <th className="pb-3">Severity</th>
                    <th className="pb-3">ATT&amp;CK</th>
                    <th className="pb-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {filteredIOCs.map((ioc, idx) => {
                    const isSelected = selectedIOC?.value === ioc.value;
                    const score = ioc.severity_score || 0;
                    return (
                      <tr
                        key={`${ioc.id}-${idx}`}
                        onClick={() => {
                          setSelectedIOC(ioc);
                          handleEnrich(ioc);
                        }}
                        className={`cursor-pointer transition hover:bg-slate-800/40 ${
                          isSelected ? "bg-cyan-950/30 border-l-2 border-cyan-400" : ""
                        }`}
                      >
                        <td className="py-3 font-mono font-bold text-slate-200 max-w-[200px] truncate">
                          {ioc.value}
                        </td>
                        <td className="py-3">
                          <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300">
                            {ioc.type}
                          </span>
                        </td>
                        <td className="py-3">
                          <span
                            className={`font-black font-mono px-2 py-0.5 rounded text-[11px] ${
                              score >= 80
                                ? "bg-red-950/80 text-red-400 border border-red-800"
                                : score >= 50
                                ? "bg-orange-950/80 text-orange-400 border border-orange-800"
                                : "bg-amber-950/80 text-amber-400 border border-amber-800"
                            }`}
                          >
                            {score} / 100
                          </span>
                        </td>
                        <td className="py-3 font-mono text-cyan-400 text-[11px]">
                          {ioc.mitre_technique || "T1071"}
                        </td>
                        <td className="py-3 text-right">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedIOC(ioc);
                              handleEnrich(ioc);
                            }}
                            className="bg-[#0e1628] hover:bg-slate-700 text-slate-200 border border-slate-700 px-2 py-1 rounded text-[11px] font-medium"
                          >
                            Inspect &rarr;
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Right Column: One-Click Enrichment Inspector */}
        <div className="lg:col-span-5 space-y-4">
          <div className="bg-[#0b1220] border border-slate-800 rounded-2xl p-5 space-y-4 shadow-sm">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <span>🔍</span> Indicator Deep Enrichment
              </h3>
              <span className="text-[10px] font-mono text-slate-400 uppercase bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                TLP: AMBER
              </span>
            </div>

            {selectedIOC ? (
              <div className="space-y-4">
                <div className="p-3.5 rounded-xl bg-[#080d19] border border-slate-800 space-y-1">
                  <span className="text-[10px] font-mono text-slate-500 uppercase">Target Indicator</span>
                  <div className="text-xs font-mono font-bold text-cyan-400 break-all">
                    {selectedIOC.value}
                  </div>
                  <div className="flex items-center gap-2 pt-1 text-[10px] text-slate-400">
                    <span>Confidence: {selectedIOC.confidence}%</span>
                    <span>&bull;</span>
                    <span>Status: {selectedIOC.status}</span>
                  </div>
                </div>

                <div className="space-y-2 text-xs">
                  <div className="flex justify-between p-2 rounded-lg bg-[#0e1628] border border-slate-800/80">
                    <span className="text-slate-400">Consensus Verdict:</span>
                    <span className="font-bold text-red-400">{enrichmentData?.verdict || "MALICIOUS (High Confidence)"}</span>
                  </div>
                  <div className="flex justify-between p-2 rounded-lg bg-[#0e1628] border border-slate-800/80">
                    <span className="text-slate-400">Multi-Engine Detection:</span>
                    <span className="font-mono text-amber-400">{enrichmentData?.virustotalDetection || "54 / 72 Flagged"}</span>
                  </div>
                  <div className="flex justify-between p-2 rounded-lg bg-[#0e1628] border border-slate-800/80">
                    <span className="text-slate-400">Origin / Geo Location:</span>
                    <span className="text-slate-200">{enrichmentData?.geolocation || "Frankfurt, Germany (DE)"}</span>
                  </div>
                </div>

                <div className="pt-2 flex items-center gap-2">
                  <button
                    onClick={() => alert(`Indicator ${selectedIOC.value} acknowledged`)}
                    className="flex-1 bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold py-2 rounded-xl text-xs transition"
                  >
                    Acknowledge
                  </button>
                  <Link
                    href="/dashboard/incidents"
                    className="flex-1 bg-orange-600 hover:bg-orange-500 text-white font-bold py-2 rounded-xl text-xs text-center transition"
                  >
                    Tag &amp; Escalate
                  </Link>
                </div>
              </div>
            ) : null}
          </div>
        </div>
      </div>
      )}
    </div>
  );
}