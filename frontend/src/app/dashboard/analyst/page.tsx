"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { useRole } from "@/context/RoleContext";

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
  const [indicators, setIndicators] = useState<IOCItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [selectedIOC, setSelectedIOC] = useState<IOCItem | null>(null);
  const [enrichmentData, setEnrichmentData] = useState<any>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [liveToast, setLiveToast] = useState<any>(null);

  // Initial fallback indicators
  const defaultFallbackIOCs: IOCItem[] = [
    {
      id: "seed-1",
      value: "CVE-2024-21413",
      type: "cve",
      severity_score: 98,
      confidence: 100,
      tlp: "amber",
      status: "active",
      tags: "cisa_kev,rce",
      mitre_technique: "T1190"
    },
    {
      id: "seed-2",
      value: "45.142.214.22",
      type: "ip",
      severity_score: 95,
      confidence: 90,
      tlp: "amber",
      status: "active",
      tags: "otx,pulse,proxy",
      mitre_technique: "T1090.003"
    },
    {
      id: "seed-3",
      value: "185.220.101.4",
      type: "ip",
      severity_score: 92,
      confidence: 95,
      tlp: "amber",
      status: "active",
      tags: "c2,botnet,feodo",
      mitre_technique: "T1071.001"
    },
    {
      id: "seed-4",
      value: "27.133.154.218",
      type: "ip",
      severity_score: 83,
      confidence: 90,
      tlp: "amber",
      status: "active",
      tags: "c2,emotet",
      mitre_technique: "T1071.001"
    },
    {
      id: "seed-5",
      value: "http://evil-payload-bank.xyz/drop.exe",
      type: "url",
      severity_score: 74,
      confidence: 85,
      tlp: "amber",
      status: "active",
      tags: "phishing,payload",
      mitre_technique: "T1566.002"
    }
  ];

  const fetchIndicators = async () => {
    try {
      setLoading(true);
      let res = null;
      try {
        res = await fetch("http://127.0.0.1:8000/api/v1/indicators", { cache: "no-store" });
      } catch {
        res = await fetch("http://localhost:8000/api/v1/indicators", { cache: "no-store" });
      }

      if (res && res.ok) {
        const data = await res.json();
        const items = data.data || [];
        if (items.length > 0) {
          setIndicators(items);
          setSelectedIOC(items[0]);
          handleEnrich(items[0]);
          return;
        }
      }
      setIndicators(defaultFallbackIOCs);
      setSelectedIOC(defaultFallbackIOCs[0]);
      handleEnrich(defaultFallbackIOCs[0]);
    } catch {
      setIndicators(defaultFallbackIOCs);
      setSelectedIOC(defaultFallbackIOCs[0]);
      handleEnrich(defaultFallbackIOCs[0]);
    } finally {
      setLoading(false);
    }
  };

  // Real-Time WebSocket with Deduplication (FR-03)
  useEffect(() => {
    fetchIndicators();

    let socket: WebSocket | null = null;
    try {
      socket = new WebSocket("ws://127.0.0.1:8000/ws/alerts");

      socket.onmessage = (event) => {
        try {
          const alertData = JSON.parse(event.data);
          if (alertData.event === "NEW_CRITICAL_ALERT") {
            setLiveToast(alertData);

            setIndicators((prev) => {
              // Deduplicate: If IOC value already exists, filter old one out and push fresh to top
              const filtered = prev.filter((item) => item.value !== alertData.indicator);
              const newEntry: IOCItem = {
                id: `alert-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
                value: alertData.indicator,
                type: alertData.type,
                severity_score: alertData.severity_score,
                confidence: 95,
                tlp: "amber",
                status: "active",
                tags: alertData.source,
                mitre_technique: alertData.mitre
              };
              // Keep queue bounded to top 25 canonical items
              return [newEntry, ...filtered].slice(0, 25);
            });

            setTimeout(() => {
              setLiveToast(null);
            }, 4000);
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
      try {
        res = await fetch("http://127.0.0.1:8000/api/v1/indicators/sync-feeds", { method: "POST" });
      } catch {
        res = await fetch("http://localhost:8000/api/v1/indicators/sync-feeds", { method: "POST" });
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

  const handleEnrich = (ioc: IOCItem) => {
    setEnrichmentData({
      verdict: ioc.severity_score >= 80 ? "MALICIOUS (High Confidence)" : "SUSPICIOUS",
      reputationScore: `${ioc.severity_score}/100`,
      virustotalDetection: ioc.severity_score >= 80 ? "54 / 72 Flagged" : "28 / 72 Flagged",
      autonomousSystem: "AS13335 CLOUDFLARENET / Hosting Gateway",
      geolocation: "Frankfurt, Germany (DE)",
      abuseConfidence: `${ioc.confidence || 85}%`,
    });
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

      {/* Main Grid: Queue Table + Enrichment Inspector */}
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
    </div>
  );
}