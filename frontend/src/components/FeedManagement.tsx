"use client";

import React, { useState, useEffect } from "react";
import { useRole } from "@/context/RoleContext";
import {
  safeFetchFeeds,
  safeEnableFeed,
  safeDisableFeed,
  safeUpdateFeedConfig,
  safeTriggerFeedFetch,
  safeFetchWebhooks,
  safeEnableWebhook,
  safeDisableWebhook,
  safeDiscoverTaxii,
  safeFetchTaxiiCollections,
  safeCreateTaxiiFeed,
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
  taxii_api_root?: string;
  taxii_collection_id?: string;
  taxii_version?: string;
  last_added_after?: string;
  created_at?: string;
  updated_at?: string;
}

export interface WebhookItem {
  id: string;
  provider: string;
  display_name: string;
  description?: string;
  is_enabled: boolean;
  total_events_received: number;
  last_received_at?: string;
  last_status?: string;
  last_error?: string;
  created_at?: string;
  updated_at?: string;
}

export function FeedManagement() {
  const { role } = useRole();
  const [activeTab, setActiveTab] = useState<"feeds" | "webhooks">("feeds");

  // Feeds state
  const [feeds, setFeeds] = useState<FeedItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [fetchInProgress, setFetchInProgress] = useState<string | null>(null);

  // Webhooks state
  const [webhooks, setWebhooks] = useState<WebhookItem[]>([]);
  const [loadingWebhooks, setLoadingWebhooks] = useState(false);
  const [webhookToggling, setWebhookToggling] = useState<string | null>(null);

  // Messages
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Feed edit modal state
  const [editingFeed, setEditingFeed] = useState<FeedItem | null>(null);
  const [editDisplayName, setEditDisplayName] = useState("");
  const [editDescription, setEditDescription] = useState("");
  const [editPollInterval, setEditPollInterval] = useState(3600);
  const [savingEdit, setSavingEdit] = useState(false);

  // TAXII 2.1 modal state
  const [showTaxiiModal, setShowTaxiiModal] = useState(false);
  const [taxiiServerUrl, setTaxiiServerUrl] = useState("https://limo.anomali.com/taxii2/");
  const [taxiiUsername, setTaxiiUsername] = useState("");
  const [taxiiPassword, setTaxiiPassword] = useState("");
  const [taxiiRoots, setTaxiiRoots] = useState<string[]>([]);
  const [selectedRoot, setSelectedRoot] = useState<string>("");
  const [taxiiCollections, setTaxiiCollections] = useState<any[]>([]);
  const [selectedCollection, setSelectedCollection] = useState<string>("");
  const [taxiiFeedName, setTaxiiFeedName] = useState("");
  const [taxiiDisplayName, setTaxiiDisplayName] = useState("");
  const [discoveringTaxii, setDiscoveringTaxii] = useState(false);
  const [fetchingCollections, setFetchingCollections] = useState(false);
  const [creatingTaxiiFeed, setCreatingTaxiiFeed] = useState(false);

  const isPrivileged = role === "Administrator" || role === "Security Engineer";

  const loadFeeds = async () => {
    try {
      setRefreshing(true);
      setErrorMsg(null);
      const data = await safeFetchFeeds();
      if (Array.isArray(data)) {
        setFeeds(data);
      }
    } catch {
      setErrorMsg("Failed to load feed inventory from API.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  const loadWebhooks = async () => {
    try {
      setLoadingWebhooks(true);
      setErrorMsg(null);
      const data = await safeFetchWebhooks();
      if (Array.isArray(data)) {
        setWebhooks(data);
      }
    } catch {
      setErrorMsg("Failed to load inbound webhook integrations.");
    } finally {
      setLoadingWebhooks(false);
    }
  };

  useEffect(() => {
    loadFeeds();
    loadWebhooks();
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
        setSuccessMsg(`Ingestion triggered successfully for ${feedName}. Ingested: ${res.ingested_count ?? 0}`);
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

  const handleToggleWebhook = async (item: WebhookItem) => {
    if (!isPrivileged) return;
    try {
      setWebhookToggling(item.provider);
      setErrorMsg(null);
      if (item.is_enabled) {
        await safeDisableWebhook(item.provider);
        setSuccessMsg(`Inbound integration '${item.display_name}' disabled.`);
      } else {
        await safeEnableWebhook(item.provider);
        setSuccessMsg(`Inbound integration '${item.display_name}' enabled.`);
      }
      await loadWebhooks();
    } catch (err: any) {
      setErrorMsg(`Failed to update webhook ${item.display_name}: ${err.message}`);
    } finally {
      setWebhookToggling(null);
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

  // TAXII Discovery Handlers
  const handleTaxiiDiscover = async () => {
    try {
      setDiscoveringTaxii(true);
      setErrorMsg(null);
      const res = await safeDiscoverTaxii(taxiiServerUrl, taxiiUsername, taxiiPassword);
      if (res && Array.isArray(res.api_roots) && res.api_roots.length > 0) {
        setTaxiiRoots(res.api_roots);
        setSelectedRoot(res.api_roots[0]);
        setSuccessMsg(`TAXII Server Discovery OK: ${res.title || "TAXII 2.1"} (${res.api_roots.length} API roots found)`);
      } else {
        setErrorMsg("Discovery returned no valid API roots.");
      }
    } catch (err: any) {
      setErrorMsg(`TAXII Discovery failed: ${err.message || "Check URL and credentials"}`);
    } finally {
      setDiscoveringTaxii(false);
    }
  };

  const handleTaxiiFetchCollections = async () => {
    if (!selectedRoot) return;
    try {
      setFetchingCollections(true);
      setErrorMsg(null);
      const res = await safeFetchTaxiiCollections(taxiiServerUrl, selectedRoot, taxiiUsername, taxiiPassword);
      if (res && Array.isArray(res.collections) && res.collections.length > 0) {
        setTaxiiCollections(res.collections);
        setSelectedCollection(res.collections[0].id);
        setTaxiiFeedName(`taxii_${res.collections[0].title.toLowerCase().replace(/[^a-z0-9_]/g, "_")}`);
        setTaxiiDisplayName(res.collections[0].title);
        setSuccessMsg(`Fetched ${res.collections.length} TAXII Collections successfully.`);
      } else {
        setErrorMsg("No readable collections found under this API root.");
      }
    } catch (err: any) {
      setErrorMsg(`Failed to fetch TAXII collections: ${err.message}`);
    } finally {
      setFetchingCollections(false);
    }
  };

  const handleCreateTaxiiFeedSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!isPrivileged || !selectedCollection) return;
    try {
      setCreatingTaxiiFeed(true);
      setErrorMsg(null);
      await safeCreateTaxiiFeed({
        name: taxiiFeedName,
        display_name: taxiiDisplayName,
        endpoint_url: taxiiServerUrl,
        taxii_api_root: selectedRoot,
        taxii_collection_id: selectedCollection,
        taxii_username: taxiiUsername || undefined,
        taxii_password: taxiiPassword || undefined,
        poll_interval_seconds: 3600,
        enabled: true,
      });
      setSuccessMsg(`TAXII 2.1 Feed '${taxiiDisplayName}' registered and activated successfully.`);
      setShowTaxiiModal(false);
      await loadFeeds();
    } catch (err: any) {
      setErrorMsg(`Failed to register TAXII Feed: ${err.message}`);
    } finally {
      setCreatingTaxiiFeed(false);
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
    <div className="space-y-6 pb-12">
      {/* Header bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-[#111214] p-5 rounded-xl border border-[#2B2C30]">
        <div>
          <div className="flex items-center gap-3">
            <span className="text-[10px] font-mono uppercase tracking-widest text-[#19D5E5]">
              INGESTION PIPELINES // ADAPTER HUB
            </span>
          </div>
          <h1 className="text-xl md:text-2xl font-bold text-[#F2F2F0] tracking-tight">
            Threat Intelligence Feeds &amp; Webhooks
          </h1>
          <p className="text-xs text-[#A5A6AA] mt-1 max-w-2xl">
            Real-time control plane for TAXII 2.1 collections, STIX 2.1 intelligence feeds, and inbound SIEM/EDR webhook receivers.
          </p>
        </div>

        <div className="flex items-center gap-2.5 flex-wrap">
          {activeTab === "feeds" && isPrivileged && (
            <button
              onClick={() => setShowTaxiiModal(true)}
              className="px-3.5 py-2 text-xs font-semibold rounded-lg bg-[#F2F2F0] hover:bg-white text-[#090A0C] transition flex items-center gap-1.5 cursor-pointer"
            >
              <span>+</span> Connect TAXII 2.1 Server
            </button>
          )}

          <button
            onClick={() => {
              loadFeeds();
              loadWebhooks();
            }}
            disabled={refreshing || loadingWebhooks}
            className="px-3.5 py-2 text-xs font-medium rounded-lg bg-[#17181B] hover:bg-[#202125] text-[#F2F2F0] border border-[#2B2C30] transition cursor-pointer"
          >
            {refreshing || loadingWebhooks ? "Refreshing..." : "↻ Refresh"}
          </button>

          {activeTab === "feeds" && isPrivileged && (
            <button
              onClick={handleTriggerAll}
              disabled={fetchInProgress !== null}
              className="px-4 py-2 text-xs font-semibold rounded-lg bg-[#17181B] border border-[#2B2C30] hover:border-[#19D5E5] text-[#19D5E5] transition flex items-center gap-1.5 cursor-pointer"
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

      {/* Tabs */}
      <div className="flex items-center gap-2 border-b border-[#2B2C30] pb-2">
        <button
          onClick={() => setActiveTab("feeds")}
          className={`px-4 py-2 text-xs font-semibold rounded-lg transition flex items-center gap-2 cursor-pointer ${
            activeTab === "feeds"
              ? "bg-[#17181B] text-[#F2F2F0] border border-[#2B2C30] shadow-sm"
              : "text-[#72747A] hover:text-[#F2F2F0] hover:bg-[#111214]"
          }`}
        >
          <span>🌐</span> Threat Intelligence Feeds &amp; TAXII 2.1
          <span className="text-[10px] px-1.5 py-0.2 rounded bg-[#090A0C] text-[#A5A6AA] font-mono border border-[#2B2C30]">
            {feeds.length}
          </span>
        </button>

        <button
          onClick={() => setActiveTab("webhooks")}
          className={`px-4 py-2 text-xs font-semibold rounded-lg transition flex items-center gap-2 cursor-pointer ${
            activeTab === "webhooks"
              ? "bg-[#17181B] text-[#F2F2F0] border border-[#2B2C30] shadow-sm"
              : "text-[#72747A] hover:text-[#F2F2F0] hover:bg-[#111214]"
          }`}
        >
          <span>📥</span> Inbound SIEM &amp; EDR Webhook Receivers (FR-29)
          <span className="text-[10px] px-1.5 py-0.2 rounded bg-[#090A0C] text-[#A5A6AA] font-mono border border-[#2B2C30]">
            {webhooks.length}
          </span>
        </button>
      </div>

      {/* Messages */}
      {errorMsg && (
        <div className="p-3 bg-[#17181B] border border-red-900/60 rounded-lg text-xs text-red-300 flex items-center justify-between">
          <span>⚠️ {errorMsg}</span>
          <button onClick={() => setErrorMsg(null)} className="text-red-400 hover:text-white">✕</button>
        </div>
      )}
      {successMsg && (
        <div className="p-3 bg-[#17181B] border border-emerald-900/60 rounded-lg text-xs text-emerald-300 flex items-center justify-between">
          <span>✓ {successMsg}</span>
          <button onClick={() => setSuccessMsg(null)} className="text-emerald-400 hover:text-white">✕</button>
        </div>
      )}

      {/* Tab Content: Feeds */}
      {activeTab === "feeds" && (
        <>
          {loading ? (
            <div className="text-center py-16 text-[#72747A] text-sm font-mono">
              <span className="inline-block animate-spin mr-2">⟳</span> Connecting to ThreatLens Feed Service...
            </div>
          ) : feeds.length === 0 ? (
            <div className="text-center py-16 bg-[#111214] rounded-xl border border-[#2B2C30] text-[#72747A] text-sm font-mono">
              No threat feeds configured in database.
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-5">
              {feeds.map((feed) => {
                const isFailing = feed.status === "failing" || Boolean(feed.error_message);
                const isFetchingThis = fetchInProgress === feed.name;
                const isTaxii = feed.feed_type === "taxii";

                return (
                  <div
                    key={feed.id}
                    className={`bg-[#111214] rounded-xl border p-5 flex flex-col justify-between transition-all ${
                      !feed.enabled
                        ? "border-[#2B2C30] opacity-65"
                        : isFailing
                        ? "border-red-900/80 shadow-sm"
                        : "border-[#2B2C30] hover:border-[#72747A]"
                    }`}
                  >
                    {/* Top Section */}
                    <div>
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <div className="flex items-center gap-2">
                            <h3 className="text-base font-bold text-[#F2F2F0] tracking-wide">
                              {feed.display_name || feed.name}
                            </h3>
                            {isTaxii && (
                              <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-[#17181B] text-[#19D5E5] border border-[#2B2C30]">
                                TAXII 2.1
                              </span>
                            )}
                          </div>
                          <div className="flex items-center gap-2 mt-1">
                            <span className="text-[11px] font-mono font-semibold text-[#A5A6AA]">
                              {feed.provider || "Community"}
                            </span>
                            <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-[#090A0C] text-[#72747A] border border-[#2B2C30]">
                              {feed.feed_type || "multi"}
                            </span>
                          </div>
                        </div>

                        {/* Status Badge */}
                        <div>
                          {!feed.enabled ? (
                            <span className="text-[11px] font-semibold px-2 py-0.5 rounded-full bg-[#17181B] text-[#72747A] border border-[#2B2C30]">
                              Disabled
                            </span>
                          ) : isFailing ? (
                            <span className="text-[11px] font-semibold px-2 py-0.5 rounded-full bg-[#17181B] text-red-400 border border-red-900/80">
                              Failing
                            </span>
                          ) : (
                            <span className="text-[11px] font-semibold px-2 py-0.5 rounded-full bg-[#17181B] text-emerald-400 border border-emerald-900/60 flex items-center gap-1.5">
                              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" /> Active
                            </span>
                          )}
                        </div>
                      </div>

                      <p className="text-xs text-[#A5A6AA] mt-3 line-clamp-2 leading-relaxed">
                        {feed.description || "Ingests external indicator pulses into the central correlation engine."}
                      </p>

                      {/* TAXII Specific Details */}
                      {isTaxii && (
                        <div className="mt-3 p-2 bg-[#090A0C] border border-[#2B2C30] rounded text-[11px] text-[#A5A6AA] space-y-1 font-mono">
                          <div className="truncate">
                            <span className="text-[#19D5E5]">Collection:</span> {feed.taxii_collection_id || "default"}
                          </div>
                          {feed.taxii_api_root && (
                            <div className="truncate text-[#72747A]">
                              <span className="text-[#19D5E5]">API Root:</span> {feed.taxii_api_root}
                            </div>
                          )}
                          {feed.last_added_after && (
                            <div className="text-[10px] text-[#72747A]">
                              Cursor: {feed.last_added_after}
                            </div>
                          )}
                        </div>
                      )}

                      {/* Operational Telemetry */}
                      <div className="mt-4 pt-4 border-t border-[#2B2C30] space-y-2 text-xs">
                        <div className="flex items-center justify-between text-[#A5A6AA]">
                          <span>Last Ingested:</span>
                          <span className="font-mono text-[#19D5E5] font-semibold">
                            +{feed.last_ingested_count} IOCs
                          </span>
                        </div>
                        <div className="flex items-center justify-between text-[#A5A6AA]">
                          <span>Total Lifetime Ingested:</span>
                          <span className="font-mono text-[#F2F2F0]">
                            {feed.total_indicators_ingested.toLocaleString()} IOCs
                          </span>
                        </div>
                        <div className="flex items-center justify-between text-[#A5A6AA]">
                          <span>Last Successful Sync:</span>
                          <span className="font-mono text-[#72747A] text-[11px]">
                            {formatTimestamp(feed.last_successful_fetch_at)}
                          </span>
                        </div>
                        <div className="flex items-center justify-between text-[#A5A6AA]">
                          <span>Poll Cadence:</span>
                          <span className="font-mono text-[#72747A]">
                            {Math.round(feed.poll_interval_seconds / 60)} mins
                          </span>
                        </div>

                        {feed.error_message && (
                          <div className="mt-2 p-2 bg-[#17181B] border border-red-900/60 rounded text-[11px] text-red-300 font-mono break-words">
                            Error: {feed.error_message}
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Bottom Action Buttons */}
                    <div className="mt-5 pt-3 border-t border-[#2B2C30] flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        {isPrivileged ? (
                          <button
                            onClick={() => handleToggleFeed(feed)}
                            className={`text-xs px-2.5 py-1 rounded font-medium transition cursor-pointer ${
                              feed.enabled
                                ? "bg-[#17181B] hover:bg-[#202125] text-[#A5A6AA] border border-[#2B2C30]"
                                : "bg-[#17181B] hover:bg-[#202125] text-emerald-400 border border-emerald-900/60"
                            }`}
                          >
                            {feed.enabled ? "Disable" : "Enable"}
                          </button>
                        ) : (
                          <span className="text-[10px] text-[#72747A] italic font-mono">Read-only</span>
                        )}

                        {isPrivileged && (
                          <button
                            onClick={() => openEditModal(feed)}
                            className="text-xs px-2.5 py-1 rounded font-medium bg-[#17181B] hover:bg-[#202125] text-[#F2F2F0] border border-[#2B2C30] transition cursor-pointer"
                          >
                            Config
                          </button>
                        )}
                      </div>

                      {isPrivileged && (
                        <button
                          onClick={() => handleTriggerFetch(feed.name)}
                          disabled={isFetchingThis || !feed.enabled}
                          className={`text-xs px-3 py-1 rounded font-semibold transition flex items-center gap-1 cursor-pointer ${
                            !feed.enabled
                              ? "bg-[#17181B] text-[#72747A] border border-[#2B2C30] cursor-not-allowed"
                              : "bg-[#F2F2F0] hover:bg-white text-[#090A0C]"
                          }`}
                        >
                          {isFetchingThis ? (
                            <>
                              <span className="animate-spin text-xs">⟳</span> Polling...
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
        </>
      )}

      {/* Tab Content: Inbound SIEM/EDR Webhooks (FR-29) */}
      {activeTab === "webhooks" && (
        <>
          <div className="bg-[#111214] p-4 rounded-xl border border-[#2B2C30] text-xs text-[#A5A6AA] space-y-1">
            <div className="font-semibold text-[#F2F2F0] flex items-center gap-2 font-mono">
              <span>🔒</span> Canonical Webhook Ingestion Engine
            </div>
            <p className="text-[#A5A6AA]">
              Inbound security events delivered via HTTP POST to{" "}
              <code className="bg-[#090A0C] px-1 py-0.5 rounded text-[#19D5E5] font-mono border border-[#2B2C30]">
                /api/v1/integrations/webhooks/&lbrace;provider&rbrace;
              </code>{" "}
              are verified with HMAC SHA-256 or Bearer secret, protected against replay skew (300s window), normalized into canonical ThreatLens IOCs, and dispatched to detection rules and incident correlation.
            </p>
          </div>

          {loadingWebhooks ? (
            <div className="text-center py-16 text-[#72747A] text-sm font-mono">
              <span className="inline-block animate-spin mr-2">⟳</span> Loading Inbound Integrations...
            </div>
          ) : webhooks.length === 0 ? (
            <div className="text-center py-16 bg-[#111214] rounded-xl border border-[#2B2C30] text-[#72747A] text-sm font-mono">
              No webhook providers configured.
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-5">
              {webhooks.map((item) => {
                const isToggling = webhookToggling === item.provider;

                return (
                  <div
                    key={item.id}
                    className={`bg-[#111214] rounded-xl border p-5 flex flex-col justify-between transition-all ${
                      !item.is_enabled
                        ? "border-[#2B2C30] opacity-65"
                        : "border-[#2B2C30] hover:border-[#72747A]"
                    }`}
                  >
                    <div>
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <h3 className="text-base font-bold text-[#F2F2F0] tracking-wide">
                            {item.display_name}
                          </h3>
                          <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-[#090A0C] text-[#19D5E5] border border-[#2B2C30]">
                            {item.provider}
                          </span>
                        </div>

                        <div>
                          {item.is_enabled ? (
                            <span className="text-[11px] font-semibold px-2 py-0.5 rounded-full bg-[#17181B] text-emerald-400 border border-emerald-900/60 flex items-center gap-1.5">
                              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" /> Active
                            </span>
                          ) : (
                            <span className="text-[11px] font-semibold px-2 py-0.5 rounded-full bg-[#17181B] text-[#72747A] border border-[#2B2C30]">
                              Disabled
                            </span>
                          )}
                        </div>
                      </div>

                      <p className="text-xs text-[#A5A6AA] mt-3 line-clamp-2 leading-relaxed">
                        {item.description || "Ingests alerts and telemetry directly into ThreatLens correlation engine."}
                      </p>

                      <div className="mt-4 pt-3 border-t border-[#2B2C30] space-y-2 text-xs">
                        <div>
                          <span className="text-[#72747A] block text-[11px]">Endpoint URL:</span>
                          <code className="text-[11px] font-mono text-[#19D5E5] bg-[#090A0C] px-2 py-1 rounded block mt-0.5 break-all border border-[#2B2C30]">
                            /api/v1/integrations/webhooks/{item.provider}
                          </code>
                        </div>

                        <div className="flex items-center justify-between text-[#A5A6AA] pt-1">
                          <span>Total Events Ingested:</span>
                          <span className="font-mono text-[#F2F2F0] font-semibold">
                            {item.total_events_received.toLocaleString()}
                          </span>
                        </div>

                        <div className="flex items-center justify-between text-[#A5A6AA]">
                          <span>Last Event Received:</span>
                          <span className="font-mono text-[#72747A] text-[11px]">
                            {formatTimestamp(item.last_received_at)}
                          </span>
                        </div>

                        <div className="flex items-center justify-between text-[#A5A6AA]">
                          <span>Status:</span>
                          <span className="font-mono text-[#72747A] text-[11px]">
                            {item.last_status || "Ready"}
                          </span>
                        </div>

                        {item.last_error && (
                          <div className="mt-2 p-2 bg-[#17181B] border border-red-900/60 rounded text-[11px] text-red-300 font-mono break-words">
                            Error: {item.last_error}
                          </div>
                        )}
                      </div>
                    </div>

                    <div className="mt-5 pt-3 border-t border-[#2B2C30] flex items-center justify-between">
                      {isPrivileged ? (
                        <button
                          onClick={() => handleToggleWebhook(item)}
                          disabled={isToggling}
                          className={`text-xs px-3 py-1.5 rounded-lg font-medium transition cursor-pointer ${
                            item.is_enabled
                              ? "bg-[#17181B] hover:bg-[#202125] text-[#A5A6AA] border border-[#2B2C30]"
                              : "bg-[#17181B] hover:bg-[#202125] text-emerald-400 border border-emerald-900/60"
                          }`}
                        >
                          {isToggling ? "Updating..." : item.is_enabled ? "Disable Ingestion" : "Enable Ingestion"}
                        </button>
                      ) : (
                        <span className="text-[10px] text-[#72747A] italic font-mono">Read-only configuration</span>
                      )}

                      <span className="text-[10px] text-[#72747A] font-mono">HMAC SHA-256 Ready</span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </>
      )}

      {/* Edit Feed Config Modal */}
      {editingFeed && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="bg-[#111214] border border-[#2B2C30] rounded-xl max-w-lg w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-[#2B2C30] pb-3">
              <h3 className="text-base font-bold text-[#F2F2F0]">
                Edit Feed Configuration: <span className="text-[#19D5E5] font-mono">{editingFeed.name}</span>
              </h3>
              <button onClick={() => setEditingFeed(null)} className="text-[#72747A] hover:text-[#F2F2F0] cursor-pointer">✕</button>
            </div>

            <form onSubmit={handleSaveConfig} className="space-y-4 text-xs">
              <div>
                <label className="block text-[#A5A6AA] font-semibold mb-1">Display Name</label>
                <input
                  type="text"
                  value={editDisplayName}
                  onChange={(e) => setEditDisplayName(e.target.value)}
                  className="w-full bg-[#090A0C] border border-[#2B2C30] rounded-lg p-2 text-[#F2F2F0] focus:outline-none focus:border-[#19D5E5]"
                  required
                />
              </div>

              <div>
                <label className="block text-[#A5A6AA] font-semibold mb-1">Description</label>
                <textarea
                  value={editDescription}
                  onChange={(e) => setEditDescription(e.target.value)}
                  rows={3}
                  className="w-full bg-[#090A0C] border border-[#2B2C30] rounded-lg p-2 text-[#F2F2F0] focus:outline-none focus:border-[#19D5E5]"
                />
              </div>

              <div>
                <label className="block text-[#A5A6AA] font-semibold mb-1">Poll Interval (seconds)</label>
                <input
                  type="number"
                  min={60}
                  max={86400}
                  value={editPollInterval}
                  onChange={(e) => setEditPollInterval(Number(e.target.value))}
                  className="w-full bg-[#090A0C] border border-[#2B2C30] rounded-lg p-2 text-[#F2F2F0] focus:outline-none focus:border-[#19D5E5] font-mono"
                  required
                />
                <span className="text-[11px] text-[#72747A] mt-1 block font-mono">
                  Current: {Math.round(editPollInterval / 60)} minutes ({editPollInterval} seconds). Min 60s, max 86400s.
                </span>
              </div>

              <div className="flex items-center justify-end gap-3 pt-3 border-t border-[#2B2C30]">
                <button
                  type="button"
                  onClick={() => setEditingFeed(null)}
                  className="px-4 py-2 rounded-lg bg-[#17181B] text-[#A5A6AA] hover:text-[#F2F2F0] border border-[#2B2C30] transition cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={savingEdit}
                  className="px-4 py-2 rounded-lg bg-[#F2F2F0] hover:bg-white text-[#090A0C] font-semibold transition cursor-pointer"
                >
                  {savingEdit ? "Saving..." : "Save Changes"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Connect TAXII 2.1 Server Modal */}
      {showTaxiiModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="bg-[#111214] border border-[#2B2C30] rounded-xl max-w-xl w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-[#2B2C30] pb-3">
              <h3 className="text-base font-bold text-[#F2F2F0] flex items-center gap-2">
                <span>🌐</span> Connect TAXII 2.1 Server (FR-04)
              </h3>
              <button onClick={() => setShowTaxiiModal(false)} className="text-[#72747A] hover:text-[#F2F2F0] cursor-pointer">✕</button>
            </div>

            <div className="space-y-4 text-xs">
              {/* Step 1: Discovery */}
              <div className="space-y-2">
                <label className="block text-[#A5A6AA] font-semibold">TAXII 2.1 Discovery URL</label>
                <div className="flex items-center gap-2">
                  <input
                    type="url"
                    value={taxiiServerUrl}
                    onChange={(e) => setTaxiiServerUrl(e.target.value)}
                    placeholder="https://example.com/taxii2/"
                    className="flex-1 bg-[#090A0C] border border-[#2B2C30] rounded-lg p-2 text-[#F2F2F0] font-mono focus:outline-none focus:border-[#19D5E5]"
                  />
                  <button
                    type="button"
                    onClick={handleTaxiiDiscover}
                    disabled={discoveringTaxii || !taxiiServerUrl}
                    className="px-3.5 py-2 bg-[#F2F2F0] hover:bg-white text-[#090A0C] rounded-lg font-semibold transition flex items-center gap-1 cursor-pointer"
                  >
                    {discoveringTaxii ? "Discovering..." : "Discover"}
                  </button>
                </div>
              </div>

              {/* Optional Basic Auth */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-[#72747A] font-medium mb-1">Username (Optional)</label>
                  <input
                    type="text"
                    value={taxiiUsername}
                    onChange={(e) => setTaxiiUsername(e.target.value)}
                    placeholder="guest"
                    className="w-full bg-[#090A0C] border border-[#2B2C30] rounded-lg p-2 text-[#F2F2F0] font-mono"
                  />
                </div>
                <div>
                  <label className="block text-[#72747A] font-medium mb-1">Password (Optional)</label>
                  <input
                    type="password"
                    value={taxiiPassword}
                    onChange={(e) => setTaxiiPassword(e.target.value)}
                    placeholder="••••••••"
                    className="w-full bg-[#090A0C] border border-[#2B2C30] rounded-lg p-2 text-[#F2F2F0] font-mono"
                  />
                </div>
              </div>

              {/* Step 2: API Roots & Collections */}
              {taxiiRoots.length > 0 && (
                <div className="space-y-3 pt-3 border-t border-[#2B2C30]">
                  <div className="flex items-center justify-between">
                    <label className="block text-[#A5A6AA] font-semibold">API Root</label>
                    <button
                      type="button"
                      onClick={handleTaxiiFetchCollections}
                      disabled={fetchingCollections || !selectedRoot}
                      className="text-xs text-[#19D5E5] hover:underline cursor-pointer"
                    >
                      {fetchingCollections ? "Loading..." : "Load Collections"}
                    </button>
                  </div>
                  <select
                    value={selectedRoot}
                    onChange={(e) => setSelectedRoot(e.target.value)}
                    className="w-full bg-[#090A0C] border border-[#2B2C30] rounded-lg p-2 text-[#F2F2F0] font-mono"
                  >
                    {taxiiRoots.map((root) => (
                      <option key={root} value={root} className="bg-[#111214]">
                        {root}
                      </option>
                    ))}
                  </select>
                </div>
              )}

              {/* Step 3: Collection Selection and Feed Configuration */}
              {taxiiCollections.length > 0 && (
                <form onSubmit={handleCreateTaxiiFeedSubmit} className="space-y-3 pt-3 border-t border-[#2B2C30]">
                  <div>
                    <label className="block text-[#A5A6AA] font-semibold mb-1">Select Collection</label>
                    <select
                      value={selectedCollection}
                      onChange={(e) => {
                        setSelectedCollection(e.target.value);
                        const c = taxiiCollections.find((item) => item.id === e.target.value);
                        if (c) {
                          setTaxiiFeedName(`taxii_${c.title.toLowerCase().replace(/[^a-z0-9_]/g, "_")}`);
                          setTaxiiDisplayName(c.title);
                        }
                      }}
                      className="w-full bg-[#090A0C] border border-[#2B2C30] rounded-lg p-2 text-[#F2F2F0] font-mono"
                      required
                    >
                      {taxiiCollections.map((col) => (
                        <option key={col.id} value={col.id} className="bg-[#111214]">
                          {col.title} ({col.id.slice(0, 8)}...) - {col.can_read ? "Readable" : "Locked"}
                        </option>
                      ))}
                    </select>
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-[#A5A6AA] font-semibold mb-1">Feed Identifier</label>
                      <input
                        type="text"
                        value={taxiiFeedName}
                        onChange={(e) => setTaxiiFeedName(e.target.value)}
                        className="w-full bg-[#090A0C] border border-[#2B2C30] rounded-lg p-2 text-[#F2F2F0] font-mono"
                        required
                      />
                    </div>
                    <div>
                      <label className="block text-[#A5A6AA] font-semibold mb-1">Display Name</label>
                      <input
                        type="text"
                        value={taxiiDisplayName}
                        onChange={(e) => setTaxiiDisplayName(e.target.value)}
                        className="w-full bg-[#090A0C] border border-[#2B2C30] rounded-lg p-2 text-[#F2F2F0]"
                        required
                      />
                    </div>
                  </div>

                  <div className="flex items-center justify-end gap-3 pt-3">
                    <button
                      type="button"
                      onClick={() => setShowTaxiiModal(false)}
                      className="px-4 py-2 rounded-lg bg-[#17181B] text-[#A5A6AA] hover:text-[#F2F2F0] border border-[#2B2C30] transition cursor-pointer"
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      disabled={creatingTaxiiFeed}
                      className="px-4 py-2 rounded-lg bg-[#F2F2F0] hover:bg-white text-[#090A0C] font-semibold transition cursor-pointer"
                    >
                      {creatingTaxiiFeed ? "Registering..." : "Activate TAXII Feed"}
                    </button>
                  </div>
                </form>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default FeedManagement;
