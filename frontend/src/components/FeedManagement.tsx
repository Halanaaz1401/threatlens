"use client";

import React, { useState, useEffect } from "react";
import { useRole } from "@/context/RoleContext";
import {
  safeFetchFeeds,
  safeEnableFeed,
  safeDisableFeed,
  safeUpdateFeedConfig,
  safeTriggerFeedFetch,
} from "@/lib/api";

export interface FeedItem {
  id: string;
  name: string;
  display_name?: string;
  provider?: string;
  feed_type?: string;
  endpoint_url?: string;
  description?: string;
  enabled: boolean;
  status: string;
  poll_interval_seconds: number;
  last_polled_at?: string;
  last_successful_fetch_at?: string;
  last_attempted_fetch_at?: string;
  error_message?: string;
  total_indicators_ingested: number;
  last_ingested_count: number;
  created_at?: string;
  updated_at?: string;
}

export function FeedManagement() {
  const { role } = useRole();
  const [feeds, setFeeds] = useState<FeedItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [fetchInProgress, setFetchInProgress] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Edit modal state
  const [editingFeed, setEditingFeed] = useState<FeedItem | null>(null);
  const [editDisplayName, setEditDisplayName] = useState("");
  const [editDescription, setEditDescription] = useState("");
  const [editPollInterval, setEditPollInterval] = useState(3600);
  const [savingEdit, setSavingEdit] = useState(false);

  const isPrivileged = role === "Administrator" || role === "Security Engineer";

  const loadFeeds = async () => {
    try {
      setRefreshing(true);
      setErrorMsg(null);
      const data = await safeFetchFeeds();
      if (Array.isArray(data)) {
        setFeeds(data);
      }
    } catch (err: any) {
      setErrorMsg("Failed to load feed inventory from API.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadFeeds();
  }, []);

  const handleToggleFeed = async (feed: FeedItem) => {
    if (!isPrivileged) return;
    try {
      setErrorMsg(null);
      if (feed.enabled) {
        await safeDisableFeed(feed.id);
        setSuccessMsg(`Feed '${feed.name}' disabled.`);
      } else {
        await safeEnableFeed(feed.id);
        setSuccessMsg(`Feed '${feed.name}' enabled.`);
      }
      await loadFeeds();
    } catch (err: any) {
      setErrorMsg(`Failed to toggle feed ${feed.name}: ${err.message || "Unknown error"}`);
    }
  };

  const handleTriggerFetch = async (feedName: string) => {
    if (!isPrivileged) return;
    try {
      setFetchInProgress(feedName);
      setErrorMsg(null);
      setSuccessMsg(null);
      const res = await safeTriggerFeedFetch(feedName);
      if (res && res.status === "success") {
        setSuccessMsg(`Ingestion triggered successfully for ${feedName}.`);
      } else {
        setErrorMsg(`Fetch completed with status: ${res?.status || "unknown"}`);
      }
      await loadFeeds();
    } catch (err: any) {
      setErrorMsg(`Failed to trigger ingestion: ${err.message || "Network error"}`);
    } finally {
      setFetchInProgress(null);
    }
  };

  const handleTriggerAll = async () => {
    if (!isPrivileged) return;
    try {
      setFetchInProgress("all");
      setErrorMsg(null);
      setSuccessMsg(null);
      const res = await safeTriggerFeedFetch("all");
      if (res && res.status === "success") {
        setSuccessMsg("Ingestion triggered for all enabled threat feeds.");
      }
      await loadFeeds();
    } catch (err: any) {
      setErrorMsg(`Failed to trigger all feeds: ${err.message}`);
    } finally {
      setFetchInProgress(null);
    }
  };

  const openEditModal = (feed: FeedItem) => {
    setEditingFeed(feed);
    setEditDisplayName(feed.display_name || feed.name);
    setEditDescription(feed.description || "");
    setEditPollInterval(feed.poll_interval_seconds || 3600);
  };

  const handleSaveConfig = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingFeed || !isPrivileged) return;
    try {
      setSavingEdit(true);
      setErrorMsg(null);
      await safeUpdateFeedConfig(editingFeed.id, {
        display_name: editDisplayName,
        description: editDescription,
        poll_interval_seconds: Number(editPollInterval),
      });
      setSuccessMsg(`Feed configuration updated for '${editingFeed.name}'.`);
      setEditingFeed(null);
      await loadFeeds();
    } catch (err: any) {
      setErrorMsg(`Failed to update feed configuration: ${err.message}`);
    } finally {
      setSavingEdit(false);
    }
  };

  const formatTimestamp = (ts?: string) => {
    if (!ts) return "Never";
    try {
      const dt = new Date(ts);
      return dt.toLocaleString();
    } catch {
      return ts;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/60 p-5 rounded-xl border border-slate-800">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <span>📡</span> Threat Feed Management
            <span className="text-xs font-mono font-medium px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800/80">
              FR-05 Verified
            </span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Real-time control plane for external STIX, URLhaus, ThreatFox, Feodo, MalwareBazaar, and CISA KEV ingestion pipelines.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={loadFeeds}
            disabled={refreshing}
            className="px-3.5 py-1.5 text-xs font-medium rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
          >
            {refreshing ? "Refreshing..." : "↻ Refresh Feeds"}
          </button>

          {isPrivileged && (
            <button
              onClick={handleTriggerAll}
              disabled={fetchInProgress !== null}
              className="px-4 py-1.5 text-xs font-semibold rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white shadow-md shadow-cyan-900/40 transition flex items-center gap-1.5"
            >
              {fetchInProgress === "all" ? (
                <>
                  <span className="animate-spin text-sm">⟳</span> Fetching All...
                </>
              ) : (
                <>
                  <span>⚡</span> Fetch All Feeds
                </>
              )}
            </button>
          )}
        </div>
      </div>

      {/* Messages */}
      {errorMsg && (
        <div className="p-3 bg-red-950/70 border border-red-800 rounded-lg text-xs text-red-300 flex items-center justify-between">
          <span>⚠️ {errorMsg}</span>
          <button onClick={() => setErrorMsg(null)} className="text-red-400 hover:text-white">✕</button>
        </div>
      )}
      {successMsg && (
        <div className="p-3 bg-emerald-950/70 border border-emerald-800 rounded-lg text-xs text-emerald-300 flex items-center justify-between">
          <span>✓ {successMsg}</span>
          <button onClick={() => setSuccessMsg(null)} className="text-emerald-400 hover:text-white">✕</button>
        </div>
      )}

      {/* Grid of Feed Cards */}
      {loading ? (
        <div className="text-center py-16 text-slate-400 text-sm">
          <span className="inline-block animate-spin mr-2">⟳</span> Connecting to ThreatLens Feed Service...
        </div>
      ) : feeds.length === 0 ? (
        <div className="text-center py-16 bg-slate-900/40 rounded-xl border border-slate-800 text-slate-400 text-sm">
          No threat feeds configured in database.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-5">
          {feeds.map((feed) => {
            const isFailing = feed.status === "failing" || Boolean(feed.error_message);
            const isFetchingThis = fetchInProgress === feed.name;

            return (
              <div
                key={feed.id}
                className={`bg-[#0d1527] rounded-xl border p-5 flex flex-col justify-between transition-all ${
                  !feed.enabled
                    ? "border-slate-800/80 opacity-75"
                    : isFailing
                    ? "border-red-800/70 shadow-lg shadow-red-950/20"
                    : "border-slate-700/80 hover:border-cyan-700/60"
                }`}
              >
                {/* Top Section */}
                <div>
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <h3 className="text-base font-bold text-white tracking-wide">
                        {feed.display_name || feed.name}
                      </h3>
                      <div className="flex items-center gap-2 mt-1">
                        <span className="text-[11px] font-mono font-semibold text-slate-400">
                          {feed.provider || "Community"}
                        </span>
                        <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                          {feed.feed_type || "multi"}
                        </span>
                      </div>
                    </div>

                    {/* Status Badge */}
                    <div>
                      {!feed.enabled ? (
                        <span className="text-[11px] font-semibold px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 border border-slate-700">
                          Disabled
                        </span>
                      ) : isFailing ? (
                        <span className="text-[11px] font-semibold px-2 py-0.5 rounded-full bg-red-950 text-red-400 border border-red-800 animate-pulse">
                          Failing
                        </span>
                      ) : (
                        <span className="text-[11px] font-semibold px-2 py-0.5 rounded-full bg-emerald-950 text-emerald-400 border border-emerald-800 flex items-center gap-1">
                          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" /> Active
                        </span>
                      )}
                    </div>
                  </div>

                  <p className="text-xs text-slate-400 mt-3 line-clamp-2 leading-relaxed">
                    {feed.description || "Ingests external indicator pulses into the central correlation engine."}
                  </p>

                  {/* Operational Telemetry */}
                  <div className="mt-4 pt-4 border-t border-slate-800/80 space-y-2 text-xs">
                    <div className="flex items-center justify-between text-slate-400">
                      <span>Last Ingested:</span>
                      <span className="font-mono text-cyan-300 font-semibold">
                        +{feed.last_ingested_count} IOCs
                      </span>
                    </div>
                    <div className="flex items-center justify-between text-slate-400">
                      <span>Total Lifetime Ingested:</span>
                      <span className="font-mono text-slate-200">
                        {feed.total_indicators_ingested.toLocaleString()} IOCs
                      </span>
                    </div>
                    <div className="flex items-center justify-between text-slate-400">
                      <span>Last Successful Sync:</span>
                      <span className="font-mono text-slate-300 text-[11px]">
                        {formatTimestamp(feed.last_successful_fetch_at)}
                      </span>
                    </div>
                    <div className="flex items-center justify-between text-slate-400">
                      <span>Poll Cadence:</span>
                      <span className="font-mono text-slate-300">
                        {Math.round(feed.poll_interval_seconds / 60)} mins
                      </span>
                    </div>

                    {feed.error_message && (
                      <div className="mt-2 p-2 bg-red-950/50 border border-red-900 rounded text-[11px] text-red-300 font-mono break-words">
                        Error: {feed.error_message}
                      </div>
                    )}
                  </div>
                </div>

                {/* Bottom Action Buttons */}
                <div className="mt-5 pt-3 border-t border-slate-800/80 flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    {isPrivileged ? (
                      <button
                        onClick={() => handleToggleFeed(feed)}
                        className={`text-xs px-2.5 py-1 rounded font-medium transition ${
                          feed.enabled
                            ? "bg-slate-800 hover:bg-red-950 text-slate-300 hover:text-red-300 border border-slate-700"
                            : "bg-emerald-950 hover:bg-emerald-900 text-emerald-300 border border-emerald-800"
                        }`}
                      >
                        {feed.enabled ? "Disable" : "Enable"}
                      </button>
                    ) : (
                      <span className="text-[10px] text-slate-500 italic">Read-only</span>
                    )}

                    {isPrivileged && (
                      <button
                        onClick={() => openEditModal(feed)}
                        className="text-xs px-2.5 py-1 rounded font-medium bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
                      >
                        Config
                      </button>
                    )}
                  </div>

                  {isPrivileged && (
                    <button
                      onClick={() => handleTriggerFetch(feed.name)}
                      disabled={isFetchingThis || !feed.enabled}
                      className={`text-xs px-3 py-1 rounded font-semibold transition flex items-center gap-1 ${
                        !feed.enabled
                          ? "bg-slate-800/50 text-slate-500 cursor-not-allowed"
                          : "bg-cyan-900/60 hover:bg-cyan-800 text-cyan-200 border border-cyan-700/60"
                      }`}
                    >
                      {isFetchingThis ? (
                        <>
                          <span className="animate-spin text-xs">⟳</span> Ingesting...
                        </>
                      ) : (
                        <>
                          <span>⚡</span> Fetch Now
                        </>
                      )}
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Edit Config Modal */}
      {editingFeed && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-[#0f172a] border border-slate-700 rounded-xl max-w-lg w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-white">
                Edit Feed Configuration: <span className="text-cyan-400 font-mono">{editingFeed.name}</span>
              </h3>
              <button onClick={() => setEditingFeed(null)} className="text-slate-400 hover:text-white">✕</button>
            </div>

            <form onSubmit={handleSaveConfig} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-300 font-semibold mb-1">Display Name</label>
                <input
                  type="text"
                  value={editDisplayName}
                  onChange={(e) => setEditDisplayName(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-slate-100 focus:outline-none focus:border-cyan-500"
                  required
                />
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Description</label>
                <textarea
                  value={editDescription}
                  onChange={(e) => setEditDescription(e.target.value)}
                  rows={3}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-slate-100 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Poll Interval (seconds)</label>
                <input
                  type="number"
                  min={60}
                  max={86400}
                  value={editPollInterval}
                  onChange={(e) => setEditPollInterval(Number(e.target.value))}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
                  required
                />
                <span className="text-[11px] text-slate-500 mt-1 block">
                  Current: {Math.round(editPollInterval / 60)} minutes ({editPollInterval} seconds). Min 60s, max 86400s.
                </span>
              </div>

              <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setEditingFeed(null)}
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
    </div>
  );
}
