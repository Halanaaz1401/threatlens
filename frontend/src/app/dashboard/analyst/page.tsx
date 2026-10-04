"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { useRole } from "@/context/RoleContext";
import { getAuthHeaders, getAuthToken } from "@/lib/auth";
import {
  safeFetchIndicatorEnrichment,
  safeFetchIndicators,
  safeFetchIndicator,
  safeUpdateIndicator,
  safeDeleteIndicator,
  safeExpireStaleIndicators,
  getApiBaseUrl,
  getWsBaseUrl,
} from "@/lib/api";

import { DetectionRulesManager } from "@/components/DetectionRulesManager";
import { FeedManagement } from "@/components/FeedManagement";

interface IOCItem {
  id: string;
  value: string;
  type: string;
  severity_score: number;
  threat_score?: number;
  confidence: number;
  tlp: string;
  status: string;
  tags?: any;
  mitre_technique?: string;
  source?: string;
  expires_at?: string;
  ttl_days?: number;
  is_expired?: boolean;
  analyst_notes?: string;
  revoked_reason?: string;
  sources?: any[];
  first_seen?: string;
  last_seen?: string;
}

export default function AnalystDashboardPage() {
  const { persona, role } = useRole();
  const [activeTab, setActiveTab] = useState<"queue" | "feeds" | "rules">("queue");
  const [indicators, setIndicators] = useState<IOCItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [expiringStale, setExpiringStale] = useState(false);
  const [selectedIOC, setSelectedIOC] = useState<IOCItem | null>(null);
  const [enrichmentData, setEnrichmentData] = useState<any>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [liveToast, setLiveToast] = useState<any>(null);
  const [fetchError, setFetchError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  // Edit / Revoke Modal States
  const [showEditModal, setShowEditModal] = useState(false);
  const [editNotes, setEditNotes] = useState("");
  const [editTlp, setEditTlp] = useState("amber");
  const [editTtlDays, setEditTtlDays] = useState(30);
  const [savingEdit, setSavingEdit] = useState(false);

  const [showRevokeModal, setShowRevokeModal] = useState(false);
  const [revokeReason, setRevokeReason] = useState("");
  const [revoking, setRevoking] = useState(false);

  const isAnalystOrAbove = role !== "CISO (Executive)";
  const isAdmin = role === "Administrator";

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

  useEffect(() => {
    fetchIndicators();

    let socket: WebSocket | null = null;
    try {
      const token = getAuthToken();
      const wsEndpoint = getWsBaseUrl();
      const wsUrl = token
        ? `${wsEndpoint}${wsEndpoint.includes("?") ? "&" : "?"}token=${encodeURIComponent(token)}`
        : wsEndpoint;
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
              return [newEntry, ...filtered].slice(0, 50);
            });

            setTimeout(() => {
              setLiveToast(null);
            }, 6000);
          }
        } catch {
          // ignore non-json messages
        }
      };
    } catch {
      // socket init error
    }

    return () => {
      if (socket) {
        socket.close();
      }
    };
  }, []);

  const handleSyncFeeds = async () => {
    try {
      setSyncing(true);
      const headers = { ...getAuthHeaders() };
      const baseUrl = getApiBaseUrl();
      const res = await fetch(`${baseUrl}/api/v1/indicators/sync-feeds`, { method: "POST", headers });

      if (res && res.ok) {
        await fetchIndicators();
        setActionSuccess("Threat feeds synchronized successfully.");
        setTimeout(() => setActionSuccess(null), 4000);
      }

    } catch (err) {
      console.error("Sync failed:", err);
    } finally {
      setSyncing(false);
    }
  };

  const handleExpireStale = async () => {
    try {
      setExpiringStale(true);
      const res = await safeExpireStaleIndicators(100);
      if (res && res.status === "success") {
        const count = res.result?.expired_count || 0;
        setActionSuccess(`TTL Expiration worker completed: ${count} stale indicators expired.`);
        setTimeout(() => setActionSuccess(null), 4000);
        await fetchIndicators();
      }
    } catch (err: any) {
      setFetchError(`Expiration failed: ${err.message}`);
    } finally {
      setExpiringStale(false);
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

  const openEditModal = (ioc: IOCItem) => {
    setSelectedIOC(ioc);
    setEditNotes(ioc.analyst_notes || "");
    setEditTlp(ioc.tlp || "amber");
    setEditTtlDays(ioc.ttl_days || 30);
    setShowEditModal(true);
  };

  const handleSaveEdit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedIOC) return;
    try {
      setSavingEdit(true);
      await safeUpdateIndicator(selectedIOC.id, {
        analyst_notes: editNotes,
        tlp: editTlp,
        ttl_days: Number(editTtlDays),
      });
      setShowEditModal(false);
      setActionSuccess(`Updated IOC ${selectedIOC.value}`);
      setTimeout(() => setActionSuccess(null), 3000);
      await fetchIndicators();
    } catch (err: any) {
      setFetchError(`Failed to update IOC: ${err.message}`);
    } finally {
      setSavingEdit(false);
    }
  };

  const handleRevokeConfirm = async () => {
    if (!selectedIOC) return;
    try {
      setRevoking(true);
      await safeDeleteIndicator(selectedIOC.id, revokeReason || "Revoked by analyst", false);
      setShowRevokeModal(false);
      setRevokeReason("");
      setActionSuccess(`Indicator ${selectedIOC.value} marked as revoked.`);
      setTimeout(() => setActionSuccess(null), 3000);
      await fetchIndicators();
    } catch (err: any) {
      setFetchError(`Failed to revoke IOC: ${err.message}`);
    } finally {
      setRevoking(false);
    }
  };

  const filteredIOCs = indicators.filter(
    (i) =>
      i.value.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (i.mitre_technique && i.mitre_technique.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (typeof i.tags === "string" && i.tags.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (Array.isArray(i.tags) && i.tags.some((t: string) => t.toLowerCase().includes(searchQuery.toLowerCase())))
  );

  return (
    <div className="space-y-6 max-w-[1600px] mx-auto p-6 min-h-screen">
      {/* Toast Alert */}
      {liveToast && (
        <div className="fixed bottom-6 right-6 z-50 bg-[#0f172a] border border-red-500/80 rounded-2xl p-4 shadow-2xl flex items-center gap-4 animate-bounce">
          <span className="text-xl">⚠️</span>
          <div>
            <div className="text-xs font-bold text-red-400">Live Ingestion Alert Triggered</div>
            <div className="text-xs font-mono text-slate-200">{liveToast.indicator || liveToast.ioc_value}</div>
          </div>
          <button onClick={() => setLiveToast(null)} className="text-slate-400 hover:text-white">✕</button>
        </div>
      )}

      {/* Persona Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-[#0b1220] border border-slate-800 rounded-2xl p-5 shadow-sm">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="text-xl font-bold text-slate-100 flex items-center gap-2">
              🛡️ SOC Analyst Triage &amp; Lifecycle Cockpit
            </span>
            <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-400 border border-cyan-800">
              {persona.name} ({persona.title})
            </span>
          </div>
          <p className="text-xs text-slate-400">
            Real-time live WebSocket stream active. Lifecycle, TTL expiration, and feed provenance monitoring.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleExpireStale}
            disabled={expiringStale}
            className="bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-200 border border-slate-700 font-semibold px-3 py-2 rounded-xl text-xs flex items-center gap-2 transition"
            title="Execute backend TTL expiration worker"
          >
            <span>⏱️</span>
            <span>{expiringStale ? "Expiring..." : "Run TTL Worker"}</span>
          </button>

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

      {actionSuccess && (
        <div className="p-3 bg-emerald-950/80 border border-emerald-800 rounded-xl text-xs text-emerald-300 flex items-center justify-between">
          <span>✓ {actionSuccess}</span>
          <button onClick={() => setActionSuccess(null)} className="text-emerald-400 hover:text-white">✕</button>
        </div>
      )}

      {fetchError && (
        <div className="p-3 bg-red-950/80 border border-red-800 rounded-xl text-xs text-red-300 flex items-center justify-between">
          <span>⚠️ {fetchError}</span>
          <button onClick={() => setFetchError(null)} className="text-red-400 hover:text-white">✕</button>
        </div>
      )}

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
          <span>Triage Queue &amp; IOC Lifecycle</span>
        </button>
        <button
          onClick={() => setActiveTab("feeds")}
          className={`px-4 py-2 rounded-xl text-xs font-bold transition flex items-center gap-2 ${
            activeTab === "feeds"
              ? "bg-emerald-950/80 text-emerald-400 border border-emerald-800 shadow-sm"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-900"
          }`}
        >
          <span>📡</span>
          <span>Feed Management (FR-05)</span>
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
          <span>Detection Rules &amp; Alert Routing</span>
        </button>
      </div>

      {activeTab === "rules" ? (
        <DetectionRulesManager />
      ) : activeTab === "feeds" ? (
        <FeedManagement />
      ) : (
        /* Main Grid: Queue Table + Enrichment / Lifecycle Inspector */
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left Column: Triage Table */}
          <div className="lg:col-span-7 bg-[#0b1220] border border-slate-800 rounded-2xl p-5 space-y-4 shadow-sm">
            <div className="flex items-center justify-between gap-4">
              <h2 className="text-sm font-bold text-slate-200 flex items-center gap-2">
                <span>🚨</span> Ingested Indicators ({filteredIOCs.length})
              </h2>
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filter by IP, URL, status, MITRE..."
                className="bg-[#0e1628] border border-slate-700/80 rounded-lg px-3 py-1 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 w-52"
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
                      <th className="pb-3">Status</th>
                      <th className="pb-3">Severity</th>
                      <th className="pb-3">TTL Expiry</th>
                      <th className="pb-3 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {filteredIOCs.map((ioc, idx) => {
                      const isSelected = selectedIOC?.id === ioc.id;
                      const score = ioc.severity_score || ioc.threat_score || 0;
                      const isExpired = ioc.status === "expired" || ioc.is_expired;
                      const isRevoked = ioc.status === "revoked";

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
                          <td className="py-3 font-mono font-bold text-slate-200 max-w-[180px] truncate">
                            {ioc.value}
                          </td>
                          <td className="py-3">
                            <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300">
                              {ioc.type}
                            </span>
                          </td>
                          <td className="py-3">
                            <span
                              className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border uppercase ${
                                isRevoked
                                  ? "bg-slate-800 text-slate-400 border-slate-700"
                                  : isExpired
                                  ? "bg-amber-950 text-amber-400 border-amber-800"
                                  : "bg-emerald-950 text-emerald-400 border-emerald-800"
                              }`}
                            >
                              {ioc.status}
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
                          <td className="py-3 font-mono text-[11px] text-slate-400">
                            {ioc.expires_at ? new Date(ioc.expires_at).toLocaleDateString() : `${ioc.ttl_days || 30}d`}
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

          {/* Right Column: IOC Lifecycle & Enrichment Inspector */}
          <div className="lg:col-span-5 space-y-4">
            <div className="bg-[#0b1220] border border-slate-800 rounded-2xl p-5 space-y-4 shadow-sm">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                  <span>🔍</span> IOC Lifecycle &amp; Intelligence
                </h3>
                <span className="text-[10px] font-mono text-slate-400 uppercase bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                  TLP: {selectedIOC?.tlp?.toUpperCase() || "AMBER"}
                </span>
              </div>

              {selectedIOC ? (
                <div className="space-y-4">
                  {/* Target Card */}
                  <div className="p-3.5 rounded-xl bg-[#080d19] border border-slate-800 space-y-1">
                    <span className="text-[10px] font-mono text-slate-500 uppercase">Target Indicator</span>
                    <div className="text-xs font-mono font-bold text-cyan-400 break-all">
                      {selectedIOC.value}
                    </div>
                    <div className="flex flex-wrap items-center gap-2 pt-1 text-[11px] text-slate-400">
                      <span>Source: <strong className="text-slate-200">{selectedIOC.source || "manual"}</strong></span>
                      <span>&bull;</span>
                      <span>Status: <strong className={selectedIOC.status === "active" ? "text-emerald-400" : "text-amber-400"}>{selectedIOC.status}</strong></span>
                      <span>&bull;</span>
                      <span>Confidence: {selectedIOC.confidence}%</span>
                    </div>
                  </div>

                  {/* Lifecycle & Expiration Details (FR-06, FR-08) */}
                  <div className="p-3.5 rounded-xl bg-[#0e1628] border border-slate-800 space-y-2 text-xs">
                    <div className="flex justify-between items-center text-slate-400">
                      <span>TTL Window:</span>
                      <span className="font-mono text-slate-200 font-semibold">{selectedIOC.ttl_days || 30} days</span>
                    </div>
                    <div className="flex justify-between items-center text-slate-400">
                      <span>Expiration Date:</span>
                      <span className="font-mono text-cyan-300">
                        {selectedIOC.expires_at ? new Date(selectedIOC.expires_at).toLocaleString() : "Not set"}
                      </span>
                    </div>
                    {selectedIOC.analyst_notes && (
                      <div className="mt-2 pt-2 border-t border-slate-800 text-slate-300">
                        <span className="text-[10px] text-slate-500 block uppercase font-mono">Analyst Notes:</span>
                        <p className="mt-0.5 italic">{selectedIOC.analyst_notes}</p>
                      </div>
                    )}
                    {selectedIOC.revoked_reason && (
                      <div className="mt-2 p-2 rounded bg-slate-900 border border-slate-800 text-[11px] text-slate-400">
                        <span className="text-red-400 font-semibold">Revocation Reason:</span> {selectedIOC.revoked_reason}
                      </div>
                    )}
                  </div>

                  {/* Enrichment Consensus */}
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

                  {/* Action Buttons (FR-07) */}
                  <div className="pt-2 grid grid-cols-2 gap-2">
                    {isAnalystOrAbove && (
                      <button
                        onClick={() => openEditModal(selectedIOC)}
                        className="bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold py-2 rounded-xl text-xs transition"
                      >
                        ✏️ Edit Notes / TTL
                      </button>
                    )}

                    {isAnalystOrAbove && selectedIOC.status !== "revoked" && (
                      <button
                        onClick={() => setShowRevokeModal(true)}
                        className="bg-red-950/80 hover:bg-red-900 text-red-300 border border-red-800 font-bold py-2 rounded-xl text-xs transition"
                      >
                        🚫 Revoke / Soft-Delete
                      </button>
                    )}
                  </div>
                </div>
              ) : null}
            </div>
          </div>
        </div>
      )}

      {/* Edit Modal */}
      {showEditModal && selectedIOC && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-[#0f172a] border border-slate-700 rounded-xl max-w-lg w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-white">
                Edit IOC: <span className="text-cyan-400 font-mono">{selectedIOC.value}</span>
              </h3>
              <button onClick={() => setShowEditModal(false)} className="text-slate-400 hover:text-white">✕</button>
            </div>

            <form onSubmit={handleSaveEdit} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-300 font-semibold mb-1">Analyst Notes</label>
                <textarea
                  value={editNotes}
                  onChange={(e) => setEditNotes(e.target.value)}
                  rows={3}
                  placeholder="Record investigation findings, threat actor attributions, or containment notes..."
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-slate-100 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-slate-300 font-semibold mb-1">TLP Protocol</label>
                  <select
                    value={editTlp}
                    onChange={(e) => setEditTlp(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-slate-100 focus:outline-none focus:border-cyan-500 uppercase font-mono"
                  >
                    <option value="white">TLP: WHITE</option>
                    <option value="green">TLP: GREEN</option>
                    <option value="amber">TLP: AMBER</option>
                    <option value="red">TLP: RED</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-300 font-semibold mb-1">TTL Window (Days)</label>
                  <input
                    type="number"
                    min={1}
                    max={365}
                    value={editTtlDays}
                    onChange={(e) => setEditTtlDays(Number(e.target.value))}
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
                  />
                </div>
              </div>

              <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowEditModal(false)}
                  className="px-4 py-1.5 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700 transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={savingEdit}
                  className="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold transition"
                >
                  {savingEdit ? "Saving..." : "Save Changes"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Revoke Modal */}
      {showRevokeModal && selectedIOC && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-[#0f172a] border border-red-800/80 rounded-xl max-w-md w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-red-400 flex items-center gap-2">
                <span>🚫</span> Revoke Indicator
              </h3>
              <button onClick={() => setShowRevokeModal(false)} className="text-slate-400 hover:text-white">✕</button>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">
              Are you sure you want to revoke <strong className="text-white font-mono">{selectedIOC.value}</strong>?
              This will transition the lifecycle state to <strong className="text-amber-400">revoked</strong> while preserving all historical provenance and sightings.
            </p>

            <div>
              <label className="block text-slate-300 text-xs font-semibold mb-1">Revocation Reason</label>
              <input
                type="text"
                value={revokeReason}
                onChange={(e) => setRevokeReason(e.target.value)}
                placeholder="e.g., False positive, decommissioned server, vendor alert retraction"
                className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-xs text-slate-100 focus:outline-none focus:border-red-500"
                required
              />
            </div>

            <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setShowRevokeModal(false)}
                className="px-4 py-1.5 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700 text-xs transition"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleRevokeConfirm}
                disabled={revoking}
                className="px-4 py-1.5 rounded-lg bg-red-600 hover:bg-red-500 text-white text-xs font-semibold transition"
              >
                {revoking ? "Revoking..." : "Confirm Revocation"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}