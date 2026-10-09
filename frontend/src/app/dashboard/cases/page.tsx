"use client";

import React, { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import { useRole } from "@/context/RoleContext";
import {
  safeFetchCases,
  safeFetchCase,
  safeCreateCase,
  safeUpdateCaseStatus,
  safeAddCaseNote,
  safeAddCaseEvidence,
  safeUnlinkIncidentFromCase,
  safeUnlinkAlertFromCase,
  safeUnlinkIndicatorFromCase,
  safeFetchCaseTimeline,
  safeFetchCaseAudit
} from "@/lib/api";

export default function CasesDashboardPage() {
  const { persona, role } = useRole();
  const [cases, setCases] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  // Filters
  const [statusFilter, setStatusFilter] = useState<string>("ALL");
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [priorityFilter, setPriorityFilter] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState<string>("");

  // Selected Case Detail
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null);
  const [selectedCase, setSelectedCase] = useState<any | null>(null);
  const [detailLoading, setDetailLoading] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<string>("overview");
  const [timelineEntries, setTimelineEntries] = useState<any[]>([]);
  const [auditLogs, setAuditLogs] = useState<any[]>([]);

  // Action Form States
  const [newCaseModalOpen, setNewCaseModalOpen] = useState(false);
  const [newTitle, setNewTitle] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const [newSeverity, setNewSeverity] = useState("MEDIUM");
  const [newPriority, setNewPriority] = useState("P2");
  const [newAssignee, setNewAssignee] = useState(persona.name);
  const [createSubmitting, setCreateSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  // Note form
  const [noteContent, setNoteContent] = useState("");
  const [noteSubmitting, setNoteSubmitting] = useState(false);

  // Evidence form
  const [evidenceType, setEvidenceType] = useState("INDICATOR");
  const [evidenceTitle, setEvidenceTitle] = useState("");
  const [evidenceDesc, setEvidenceDesc] = useState("");
  const [evidenceProvider, setEvidenceProvider] = useState("Internal SOC Telemetry");
  const [evidenceConfidence, setEvidenceConfidence] = useState(80);
  const [evidenceSubmitting, setEvidenceSubmitting] = useState(false);

  // Status transition note modal
  const [pendingStatus, setPendingStatus] = useState<string | null>(null);
  const [statusNote, setStatusNote] = useState("");
  const [statusSubmitting, setStatusSubmitting] = useState(false);

  const loadCases = useCallback(async () => {
    setLoading(true);
    const filters: any = {};
    if (statusFilter !== "ALL") filters.status = statusFilter;
    if (severityFilter !== "ALL") filters.severity = severityFilter;
    if (priorityFilter !== "ALL") filters.priority = priorityFilter;
    if (searchQuery.trim()) filters.search = searchQuery.trim();

    const data = await safeFetchCases(filters);
    setCases(data || []);
    setLoading(false);
  }, [statusFilter, severityFilter, priorityFilter, searchQuery]);

  useEffect(() => {
    loadCases();
  }, [loadCases]);

  const loadCaseDetail = async (caseId: string) => {
    setSelectedCaseId(caseId);
    setDetailLoading(true);
    const detail = await safeFetchCase(caseId);
    setSelectedCase(detail);

    // Also fetch timeline and audit
    const [tl, au] = await Promise.all([
      safeFetchCaseTimeline(caseId),
      safeFetchCaseAudit(caseId)
    ]);
    setTimelineEntries(tl || []);
    setAuditLogs(au || []);
    setDetailLoading(false);
  };

  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) {
      setFormError("Title is required");
      return;
    }
    setCreateSubmitting(true);
    setFormError(null);
    try {
      const created = await safeCreateCase({
        title: newTitle.trim(),
        description: newDesc.trim() || undefined,
        severity: newSeverity,
        priority: newPriority,
        assignee: newAssignee.trim() || undefined,
        owner: persona.name,
        source: "Manual",
        tags: ["investigation"]
      });
      if (created && created.id) {
        setNewCaseModalOpen(false);
        setNewTitle("");
        setNewDesc("");
        await loadCases();
        loadCaseDetail(created.id);
      } else {
        setFormError("Failed to create case. Please verify credentials.");
      }
    } catch (err: any) {
      setFormError(err.message || "Failed to create case");
    } finally {
      setCreateSubmitting(false);
    }
  };

  const handleStatusTransition = async () => {
    if (!selectedCaseId || !pendingStatus) return;
    setStatusSubmitting(true);
    try {
      const res = await safeUpdateCaseStatus(selectedCaseId, pendingStatus, statusNote.trim() || undefined);
      if (res) {
        setPendingStatus(null);
        setStatusNote("");
        await loadCaseDetail(selectedCaseId);
        await loadCases();
      }
    } finally {
      setStatusSubmitting(false);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedCaseId || !noteContent.trim()) return;
    setNoteSubmitting(true);
    try {
      await safeAddCaseNote(selectedCaseId, noteContent.trim());
      setNoteContent("");
      await loadCaseDetail(selectedCaseId);
    } finally {
      setNoteSubmitting(false);
    }
  };

  const handleAddEvidence = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedCaseId || !evidenceTitle.trim()) return;
    setEvidenceSubmitting(true);
    try {
      await safeAddCaseEvidence(selectedCaseId, {
        evidence_type: evidenceType,
        title: evidenceTitle.trim(),
        description: evidenceDesc.trim() || undefined,
        source_provider: evidenceProvider.trim() || undefined,
        confidence: Number(evidenceConfidence)
      });
      setEvidenceTitle("");
      setEvidenceDesc("");
      await loadCaseDetail(selectedCaseId);
    } finally {
      setEvidenceSubmitting(false);
    }
  };

  const handleUnlinkIncident = async (incidentId: string) => {
    if (!selectedCaseId) return;
    if (confirm("Are you sure you want to unlink this incident from the case?")) {
      await safeUnlinkIncidentFromCase(selectedCaseId, incidentId);
      loadCaseDetail(selectedCaseId);
    }
  };

  const handleUnlinkAlert = async (alertId: string) => {
    if (!selectedCaseId) return;
    if (confirm("Are you sure you want to unlink this alert from the case?")) {
      await safeUnlinkAlertFromCase(selectedCaseId, alertId);
      loadCaseDetail(selectedCaseId);
    }
  };

  const handleUnlinkIndicator = async (indicatorId: string) => {
    if (!selectedCaseId) return;
    if (confirm("Are you sure you want to unlink this indicator?")) {
      await safeUnlinkIndicatorFromCase(selectedCaseId, indicatorId);
      loadCaseDetail(selectedCaseId);
    }
  };

  const getSeverityBadge = (sev: string) => {
    const s = sev?.toUpperCase();
    if (s === "CRITICAL") return "bg-red-950/80 text-red-400 border-red-800";
    if (s === "HIGH") return "bg-orange-950/80 text-orange-400 border-orange-800";
    if (s === "MEDIUM") return "bg-amber-950/80 text-amber-400 border-amber-800";
    return "bg-slate-800 text-slate-300 border-slate-700";
  };

  const getStatusBadge = (st: string) => {
    const s = st?.toUpperCase();
    if (s === "OPEN") return "bg-cyan-950/80 text-cyan-400 border-cyan-800";
    if (s === "IN_PROGRESS") return "bg-blue-950/80 text-blue-400 border-blue-800";
    if (s === "CONTAINED") return "bg-purple-950/80 text-purple-400 border-purple-800";
    if (s === "RESOLVED") return "bg-emerald-950/80 text-emerald-400 border-emerald-800";
    if (s === "CLOSED") return "bg-slate-900 text-slate-400 border-slate-800";
    return "bg-slate-800 text-slate-300 border-slate-700";
  };

  const getPriorityBadge = (p: string) => {
    const pr = p?.toUpperCase();
    if (pr === "P1") return "text-red-400 border-red-800 bg-red-950/60 font-black";
    if (pr === "P2") return "text-orange-400 border-orange-800 bg-orange-950/60 font-bold";
    if (pr === "P3") return "text-amber-400 border-amber-800 bg-amber-950/60";
    return "text-slate-400 border-slate-700 bg-slate-800/60";
  };

  return (
    <div className="space-y-6 pb-16">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-[#111214] border border-[#2B2C30] rounded-xl p-5 shadow-sm">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <h1 className="text-lg font-bold text-[#F2F2F0] font-editorial-sans">
              Forensic Case Management
            </h1>
            <span className="text-[10px] font-mono font-medium px-2 py-0.5 rounded bg-[#17181B] text-[#19D5E5] border border-[#2B2C30]">
              SOC INVESTIGATION
            </span>
          </div>
          <p className="text-xs text-[#72747A] font-mono">
            Multi-incident investigation tracking, forensic evidence provenance, investigator notes, and unified timelines.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setNewCaseModalOpen(true)}
            className="bg-[#F2F2F0] hover:bg-white text-[#090A0C] font-semibold px-4 py-2 rounded-lg text-xs flex items-center gap-1.5 shadow-sm transition"
          >
            <span>+</span> Open Investigation Case
          </button>
          <Link
            href="/dashboard/incidents"
            className="bg-[#17181B] hover:bg-[#202125] border border-[#2B2C30] text-[#A5A6AA] hover:text-[#F2F2F0] font-medium px-3.5 py-2 rounded-lg text-xs transition font-mono"
          >
            Incidents &rarr;
          </Link>
        </div>
      </div>

      {/* Filter Cockpit */}
      <div className="bg-[#111214] border border-[#2B2C30] rounded-xl p-4 flex flex-wrap items-center justify-between gap-3 text-xs shadow-sm">
        <div className="flex flex-wrap items-center gap-2">
          {/* Status Tabs */}
          <div className="flex items-center gap-1 bg-[#090A0C] border border-[#2B2C30] p-1 rounded-lg overflow-x-auto max-w-full">
            {["ALL", "OPEN", "IN_PROGRESS", "CONTAINED", "RESOLVED", "CLOSED"].map((st) => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className={`px-3 py-1 rounded text-xs font-mono font-medium transition ${
                  statusFilter === st
                    ? "bg-[#17181B] text-[#F2F2F0] border border-[#3F4046]"
                    : "text-[#72747A] hover:text-[#F2F2F0]"
                }`}
              >
                {st.replace("_", " ")}
              </button>
            ))}
          </div>

          {/* Severity Dropdown */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-[#090A0C] border border-[#2B2C30] text-[#A5A6AA] rounded-lg px-3 py-1.5 outline-none font-mono focus:border-[#19D5E5]"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          {/* Priority Dropdown */}
          <select
            value={priorityFilter}
            onChange={(e) => setPriorityFilter(e.target.value)}
            className="bg-[#090A0C] border border-[#2B2C30] text-[#A5A6AA] rounded-lg px-3 py-1.5 outline-none font-mono focus:border-[#19D5E5]"
          >
            <option value="ALL">All Priorities</option>
            <option value="P1">P1 - Urgent</option>
            <option value="P2">P2 - High</option>
            <option value="P3">P3 - Normal</option>
            <option value="P4">P4 - Low</option>
          </select>
        </div>

        {/* Search Input */}
        <div className="w-full sm:w-64">
          <input
            type="text"
            placeholder="Search cases by title or ID..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-[#090A0C] border border-[#2B2C30] text-[#F2F2F0] rounded-lg px-3.5 py-1.5 text-xs placeholder-[#72747A] outline-none focus:border-[#19D5E5] font-mono transition"
          />
        </div>
      </div>

      {/* Main Grid: Cases List & Detail Drawer */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column: Case Cards / Table */}
        <div className={`${selectedCaseId ? "lg:col-span-5" : "lg:col-span-12"} space-y-3`}>
          {loading ? (
            <div className="p-12 text-center text-xs text-slate-400 font-mono bg-[#0b1220] border border-slate-800 rounded-2xl">
              Loading authoritative investigation cases...
            </div>
          ) : cases.length === 0 ? (
            <div className="p-12 text-center text-xs text-slate-500 font-mono bg-[#0b1220] border border-slate-800 rounded-2xl">
              No cases found matching the selected filter criteria.
            </div>
          ) : (
            cases.map((c) => {
              const isSelected = selectedCaseId === c.id;
              return (
                <div
                  key={c.id}
                  onClick={() => loadCaseDetail(c.id)}
                  className={`bg-[#0b1220] border rounded-2xl p-4 cursor-pointer transition shadow-sm hover:border-slate-700 ${
                    isSelected ? "border-cyan-500 bg-[#0c182d]" : "border-slate-800/90"
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold text-cyan-400">{c.case_number}</span>
                        <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${getStatusBadge(c.status)}`}>
                          {c.status}
                        </span>
                        <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${getSeverityBadge(c.severity)}`}>
                          {c.severity}
                        </span>
                        <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded border ${getPriorityBadge(c.priority)}`}>
                          {c.priority}
                        </span>
                      </div>
                      <h3 className="text-sm font-bold text-slate-200 line-clamp-1">{c.title}</h3>
                    </div>

                    <div className="text-right text-[11px] font-mono text-slate-400">
                      <span>{c.created_at ? new Date(c.created_at).toLocaleDateString() : ""}</span>
                    </div>
                  </div>

                  <p className="text-xs text-slate-400 line-clamp-2 mt-2">
                    {c.description || "No description recorded for this investigation case."}
                  </p>

                  <div className="flex items-center justify-between gap-2 mt-3 pt-3 border-t border-slate-800/70 text-[11px] text-slate-400">
                    <div className="flex items-center gap-3">
                      <span title="Linked Incidents">⚠️ {c.incidents_count || 0}</span>
                      <span title="Linked Alerts">🛡️ {c.alerts_count || 0}</span>
                      <span title="Evidence Count">🔍 {c.evidence_count || 0}</span>
                      <span title="Notes">📝 {c.notes_count || 0}</span>
                    </div>
                    <span className="font-medium text-slate-300">Assignee: {c.assignee || "Unassigned"}</span>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Right Column: Case Detail Cockpit */}
        {selectedCaseId && (
          <div className="lg:col-span-7 bg-[#0b1220] border border-slate-800 rounded-2xl p-5 space-y-5 shadow-sm sticky top-20">
            {detailLoading || !selectedCase ? (
              <div className="p-12 text-center text-xs text-slate-400 font-mono">
                Loading investigation details...
              </div>
            ) : (
              <>
                {/* Header */}
                <div className="flex items-start justify-between gap-4 pb-4 border-b border-slate-800">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-sm font-black text-cyan-400">{selectedCase.case_number}</span>
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${getStatusBadge(selectedCase.status)}`}>
                        {selectedCase.status}
                      </span>
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${getSeverityBadge(selectedCase.severity)}`}>
                        {selectedCase.severity}
                      </span>
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${getPriorityBadge(selectedCase.priority)}`}>
                        {selectedCase.priority}
                      </span>
                    </div>
                    <h2 className="text-base font-bold text-slate-100">{selectedCase.title}</h2>
                    <p className="text-xs text-slate-400">
                      Lead: <strong className="text-slate-200">{selectedCase.assignee || "Unassigned"}</strong> | Opened by: {selectedCase.created_by} on {new Date(selectedCase.created_at).toLocaleString()}
                    </p>
                  </div>

                  {/* Close Drawer Button */}
                  <button
                    onClick={() => setSelectedCaseId(null)}
                    className="text-slate-400 hover:text-slate-200 text-lg px-2 py-1 rounded bg-[#080d19] border border-slate-800"
                    title="Close Details"
                  >
                    &times;
                  </button>
                </div>

                {/* Status Transition Control Bar */}
                <div className="bg-[#080d19] border border-slate-800 p-3 rounded-xl flex flex-wrap items-center justify-between gap-2">
                  <span className="text-xs font-semibold text-slate-300">Transition Status:</span>
                  <div className="flex items-center gap-1.5">
                    {["OPEN", "IN_PROGRESS", "CONTAINED", "RESOLVED", "CLOSED"].map((s) => {
                      if (s === selectedCase.status) return null;
                      return (
                        <button
                          key={s}
                          onClick={() => setPendingStatus(s)}
                          className="px-2.5 py-1 rounded text-[11px] font-semibold bg-[#0e1628] hover:bg-slate-800 border border-slate-700 text-slate-300 hover:text-white transition"
                        >
                          &rarr; {s.replace("_", " ")}
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* Sub-Tabs Navigation */}
                <div className="flex items-center gap-1 border-b border-slate-800 pb-2 text-xs font-semibold">
                  {[
                    { id: "overview", label: "Overview", icon: "📋" },
                    { id: "incidents", label: `Incidents (${selectedCase.incidents?.length || 0})`, icon: "⚠️" },
                    { id: "alerts", label: `Alerts (${selectedCase.alerts?.length || 0})`, icon: "🛡️" },
                    { id: "indicators", label: `Indicators (${selectedCase.indicators?.length || 0})`, icon: "🎯" },
                    { id: "evidence", label: `Evidence (${selectedCase.evidence?.length || 0})`, icon: "🔍" },
                    { id: "notes", label: `Notes (${selectedCase.notes?.length || 0})`, icon: "📝" },
                    { id: "timeline", label: "Timeline", icon: "⏱️" },
                    { id: "audit", label: "Audit Log", icon: "📜" },
                  ].map((tab) => (
                    <button
                      key={tab.id}
                      onClick={() => setActiveTab(tab.id)}
                      className={`px-3 py-1.5 rounded-lg transition ${
                        activeTab === tab.id
                          ? "bg-cyan-950 text-cyan-300 border border-cyan-800"
                          : "text-slate-400 hover:text-slate-200"
                      }`}
                    >
                      {tab.icon} {tab.label}
                    </button>
                  ))}
                </div>

                {/* Tab Content */}
                <div className="space-y-4 min-h-[300px]">
                  {/* OVERVIEW TAB */}
                  {activeTab === "overview" && (
                    <div className="space-y-4 text-xs">
                      <div className="bg-[#080d19] border border-slate-800/80 rounded-xl p-4 space-y-2">
                        <span className="font-semibold text-slate-300">Investigation Synopsis</span>
                        <p className="text-slate-400 leading-relaxed whitespace-pre-wrap">
                          {selectedCase.description || "No synopsis recorded."}
                        </p>
                      </div>

                      <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                        <div className="p-3 bg-[#080d19] border border-slate-800 rounded-xl space-y-1">
                          <span className="text-slate-500 font-medium">Source</span>
                          <p className="font-bold text-slate-200">{selectedCase.source}</p>
                        </div>
                        <div className="p-3 bg-[#080d19] border border-slate-800 rounded-xl space-y-1">
                          <span className="text-slate-500 font-medium">Owner</span>
                          <p className="font-bold text-slate-200">{selectedCase.owner || "Unassigned"}</p>
                        </div>
                        <div className="p-3 bg-[#080d19] border border-slate-800 rounded-xl space-y-1">
                          <span className="text-slate-500 font-medium">Created</span>
                          <p className="font-bold text-slate-200">{new Date(selectedCase.created_at).toLocaleDateString()}</p>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* INCIDENTS TAB */}
                  {activeTab === "incidents" && (
                    <div className="space-y-3 text-xs">
                      {selectedCase.incidents?.length === 0 ? (
                        <div className="p-6 text-center text-slate-500 font-mono">No correlated incidents linked to this case.</div>
                      ) : (
                        selectedCase.incidents.map((inc: any) => (
                          <div key={inc.id} className="bg-[#080d19] border border-slate-800 rounded-xl p-3.5 flex items-center justify-between gap-3">
                            <div className="space-y-1">
                              <div className="flex items-center gap-2">
                                <span className="font-mono font-bold text-slate-200">{inc.incident_code}</span>
                                <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${getSeverityBadge(inc.severity)}`}>
                                  {inc.severity}
                                </span>
                                <span className="text-slate-400">Score: {inc.correlation_score}</span>
                              </div>
                              <p className="text-slate-300 font-semibold">{inc.title}</p>
                              <p className="text-[11px] text-slate-500 font-mono">Host: {inc.affected_host || "N/A"} | Matched: {inc.matched_ioc || "N/A"}</p>
                            </div>
                            <button
                              onClick={() => handleUnlinkIncident(inc.id)}
                              className="text-red-400 hover:text-red-300 px-2 py-1 bg-red-950/40 border border-red-900 rounded text-[11px] transition"
                            >
                              Unlink
                            </button>
                          </div>
                        ))
                      )}
                    </div>
                  )}

                  {/* ALERTS TAB */}
                  {activeTab === "alerts" && (
                    <div className="space-y-3 text-xs">
                      {selectedCase.alerts?.length === 0 ? (
                        <div className="p-6 text-center text-slate-500 font-mono">No alerts attached to this case.</div>
                      ) : (
                        selectedCase.alerts.map((al: any) => (
                          <div key={al.id} className="bg-[#080d19] border border-slate-800 rounded-xl p-3 flex items-center justify-between gap-3">
                            <div className="space-y-0.5">
                              <div className="flex items-center gap-2">
                                <span className="font-mono font-bold text-slate-200">{al.alert_code || al.id.slice(0, 8)}</span>
                                <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${getSeverityBadge(al.severity)}`}>
                                  {al.severity}
                                </span>
                              </div>
                              <p className="text-slate-300">{al.title}</p>
                              <p className="text-[11px] text-slate-500 font-mono">IOC: {al.indicator_value || "N/A"}</p>
                            </div>
                            <button
                              onClick={() => handleUnlinkAlert(al.id)}
                              className="text-red-400 hover:text-red-300 px-2 py-1 bg-red-950/40 border border-red-900 rounded text-[11px] transition"
                            >
                              Unlink
                            </button>
                          </div>
                        ))
                      )}
                    </div>
                  )}

                  {/* INDICATORS TAB */}
                  {activeTab === "indicators" && (
                    <div className="space-y-3 text-xs">
                      {selectedCase.indicators?.length === 0 ? (
                        <div className="p-6 text-center text-slate-500 font-mono">No indicators linked directly to this case.</div>
                      ) : (
                        selectedCase.indicators.map((ind: any) => (
                          <div key={ind.id} className="bg-[#080d19] border border-slate-800 rounded-xl p-3 flex items-center justify-between gap-3">
                            <div className="space-y-0.5">
                              <div className="flex items-center gap-2">
                                <span className="font-mono font-bold text-cyan-400">{ind.value}</span>
                                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-slate-700 bg-slate-800 text-slate-300">
                                  {ind.type}
                                </span>
                              </div>
                              <p className="text-slate-400">Score: {ind.severity_score} | Confidence: {ind.confidence}%</p>
                            </div>
                            <button
                              onClick={() => handleUnlinkIndicator(ind.id)}
                              className="text-red-400 hover:text-red-300 px-2 py-1 bg-red-950/40 border border-red-900 rounded text-[11px] transition"
                            >
                              Unlink
                            </button>
                          </div>
                        ))
                      )}
                    </div>
                  )}

                  {/* EVIDENCE TAB */}
                  {activeTab === "evidence" && (
                    <div className="space-y-4 text-xs">
                      {/* Add Evidence Form */}
                      <form onSubmit={handleAddEvidence} className="bg-[#080d19] border border-slate-800 rounded-xl p-3.5 space-y-3">
                        <span className="font-bold text-slate-200 flex items-center gap-1.5">
                          <span>+</span> Attach Forensic Evidence
                        </span>
                        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                          <input
                            type="text"
                            placeholder="Evidence Title / Observation"
                            value={evidenceTitle}
                            onChange={(e) => setEvidenceTitle(e.target.value)}
                            required
                            className="sm:col-span-2 bg-[#0b1220] border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 outline-none focus:border-cyan-500"
                          />
                          <select
                            value={evidenceType}
                            onChange={(e) => setEvidenceType(e.target.value)}
                            className="bg-[#0b1220] border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 outline-none"
                          >
                            <option value="INDICATOR">Indicator</option>
                            <option value="ALERT">Alert Correlation</option>
                            <option value="LOG">Raw Log Evidence</option>
                            <option value="PCAP">Network PCAP</option>
                            <option value="FILE_HASH">Malware Sample</option>
                            <option value="RULE_MATCH">Detection Rule Match</option>
                          </select>
                        </div>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                          <input
                            type="text"
                            placeholder="Source Provider (e.g. VirusTotal, Splunk)"
                            value={evidenceProvider}
                            onChange={(e) => setEvidenceProvider(e.target.value)}
                            className="bg-[#0b1220] border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 outline-none"
                          />
                          <input
                            type="text"
                            placeholder="Description / Technical Artifact Detail"
                            value={evidenceDesc}
                            onChange={(e) => setEvidenceDesc(e.target.value)}
                            className="bg-[#0b1220] border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 outline-none"
                          />
                        </div>
                        <button
                          type="submit"
                          disabled={evidenceSubmitting}
                          className="bg-cyan-600 hover:bg-cyan-500 text-white font-bold px-3 py-1.5 rounded-lg text-xs transition disabled:opacity-50"
                        >
                          {evidenceSubmitting ? "Attaching..." : "Attach Evidence"}
                        </button>
                      </form>

                      {/* Evidence List */}
                      {selectedCase.evidence?.length === 0 ? (
                        <div className="p-6 text-center text-slate-500 font-mono">No evidence artifacts recorded for this case.</div>
                      ) : (
                        selectedCase.evidence.map((ev: any) => (
                          <div key={ev.id} className="bg-[#080d19] border border-slate-800 rounded-xl p-3.5 space-y-1.5">
                            <div className="flex items-center justify-between gap-2">
                              <div className="flex items-center gap-2">
                                <span className="font-bold text-slate-200">{ev.title}</span>
                                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-400 border border-cyan-800">
                                  {ev.evidence_type}
                                </span>
                              </div>
                              <span className="text-[11px] font-mono text-slate-400">Confidence: {ev.confidence}%</span>
                            </div>
                            {ev.description && <p className="text-slate-300">{ev.description}</p>}
                            <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono pt-1 border-t border-slate-800/80">
                              <span>Source: {ev.source_provider || "Internal"}</span>
                              <span>Collector: {ev.collected_by} ({new Date(ev.collected_at).toLocaleDateString()})</span>
                            </div>
                          </div>
                        ))
                      )}
                    </div>
                  )}

                  {/* NOTES TAB */}
                  {activeTab === "notes" && (
                    <div className="space-y-4 text-xs">
                      {/* Add Note Form */}
                      <form onSubmit={handleAddNote} className="space-y-2">
                        <textarea
                          rows={3}
                          placeholder="Record append-only investigator findings or hypothesis..."
                          value={noteContent}
                          onChange={(e) => setNoteContent(e.target.value)}
                          required
                          className="w-full bg-[#080d19] border border-slate-800 rounded-xl p-3 text-xs text-slate-200 placeholder-slate-500 outline-none focus:border-cyan-500"
                        />
                        <button
                          type="submit"
                          disabled={noteSubmitting || !noteContent.trim()}
                          className="bg-cyan-600 hover:bg-cyan-500 text-white font-bold px-3 py-1.5 rounded-lg text-xs transition disabled:opacity-50"
                        >
                          {noteSubmitting ? "Adding..." : "Add Investigator Note"}
                        </button>
                      </form>

                      {/* Notes Chronology */}
                      {selectedCase.notes?.length === 0 ? (
                        <div className="p-6 text-center text-slate-500 font-mono">No notes recorded yet.</div>
                      ) : (
                        selectedCase.notes.map((n: any) => (
                          <div key={n.id} className="bg-[#080d19] border border-slate-800 rounded-xl p-3.5 space-y-1.5">
                            <div className="flex items-center justify-between text-[11px] text-slate-400">
                              <span className="font-bold text-slate-200">✍️ {n.author}</span>
                              <span className="font-mono">{new Date(n.created_at).toLocaleString()}</span>
                            </div>
                            <p className="text-slate-300 leading-relaxed whitespace-pre-wrap">{n.content}</p>
                          </div>
                        ))
                      )}
                    </div>
                  )}

                  {/* TIMELINE TAB */}
                  {activeTab === "timeline" && (
                    <div className="space-y-3 text-xs">
                      {timelineEntries.length === 0 ? (
                        <div className="p-6 text-center text-slate-500 font-mono">No timeline events recorded.</div>
                      ) : (
                        timelineEntries.map((t: any) => (
                          <div key={t.id} className="bg-[#080d19] border border-slate-800 rounded-xl p-3 flex items-start gap-3">
                            <span className="text-base mt-0.5">⏱️</span>
                            <div className="space-y-0.5 flex-1">
                              <div className="flex items-center justify-between gap-2">
                                <span className="font-bold text-slate-200">{t.title}</span>
                                <span className="text-[10px] font-mono text-slate-500">{new Date(t.created_at).toLocaleString()}</span>
                              </div>
                              <p className="text-slate-400">{t.details}</p>
                              <span className="text-[10px] font-mono text-slate-500">Actor: {t.actor}</span>
                            </div>
                          </div>
                        ))
                      )}
                    </div>
                  )}

                  {/* AUDIT TAB */}
                  {activeTab === "audit" && (
                    <div className="space-y-3 text-xs">
                      {auditLogs.length === 0 ? (
                        <div className="p-6 text-center text-slate-500 font-mono">No immutable audit records for this case.</div>
                      ) : (
                        auditLogs.map((log: any) => (
                          <div key={log.id} className="bg-[#080d19] border border-slate-800 rounded-xl p-3 flex items-start gap-3">
                            <span className="text-base mt-0.5">📜</span>
                            <div className="space-y-0.5 flex-1">
                              <div className="flex items-center justify-between gap-2">
                                <span className="font-mono font-bold text-cyan-400">{log.action}</span>
                                <span className="text-[10px] font-mono text-slate-500">{new Date(log.timestamp).toLocaleString()}</span>
                              </div>
                              <p className="text-slate-400">{log.details}</p>
                              <span className="text-[10px] font-mono text-slate-500">Actor: {log.actor} | IP: {log.ip_address || "Internal"}</span>
                            </div>
                          </div>
                        ))
                      )}
                    </div>
                  )}
                </div>
              </>
            )}
          </div>
        )}
      </div>

      {/* NEW CASE MODAL */}
      {newCaseModalOpen && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-[#0b1220] border border-slate-700 rounded-2xl max-w-lg w-full p-6 space-y-4 shadow-xl">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <span>📁</span> Open New Forensic Case
              </h2>
              <button
                onClick={() => setNewCaseModalOpen(false)}
                className="text-slate-400 hover:text-slate-200 text-lg"
              >
                &times;
              </button>
            </div>

            {formError && (
              <div className="p-3 bg-red-950/60 border border-red-800 rounded-xl text-xs text-red-300">
                {formError}
              </div>
            )}

            <form onSubmit={handleCreateCase} className="space-y-3.5 text-xs">
              <div className="space-y-1">
                <label className="text-slate-300 font-semibold">Case Title *</label>
                <input
                  type="text"
                  placeholder="e.g. Cobalt Strike Beaconing Incident Investigation"
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  required
                  className="w-full bg-[#080d19] border border-slate-700 rounded-xl px-3.5 py-2 text-slate-200 outline-none focus:border-cyan-500"
                />
              </div>

              <div className="space-y-1">
                <label className="text-slate-300 font-semibold">Description / Objective</label>
                <textarea
                  rows={3}
                  placeholder="Briefly describe the trigger, affected scope, and primary indicators..."
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  className="w-full bg-[#080d19] border border-slate-700 rounded-xl p-3 text-slate-200 outline-none focus:border-cyan-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-slate-300 font-semibold">Severity</label>
                  <select
                    value={newSeverity}
                    onChange={(e) => setNewSeverity(e.target.value)}
                    className="w-full bg-[#080d19] border border-slate-700 rounded-xl px-3 py-2 text-slate-200 outline-none"
                  >
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-slate-300 font-semibold">Priority</label>
                  <select
                    value={newPriority}
                    onChange={(e) => setNewPriority(e.target.value)}
                    className="w-full bg-[#080d19] border border-slate-700 rounded-xl px-3 py-2 text-slate-200 outline-none"
                  >
                    <option value="P1">P1 - Urgent</option>
                    <option value="P2">P2 - High</option>
                    <option value="P3">P3 - Medium</option>
                    <option value="P4">P4 - Low</option>
                  </select>
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-slate-300 font-semibold">Lead Assignee</label>
                <input
                  type="text"
                  value={newAssignee}
                  onChange={(e) => setNewAssignee(e.target.value)}
                  className="w-full bg-[#080d19] border border-slate-700 rounded-xl px-3.5 py-2 text-slate-200 outline-none"
                />
              </div>

              <div className="flex items-center justify-end gap-3 pt-3 border-t border-[#2B2C30]">
                <button
                  type="button"
                  onClick={() => setNewCaseModalOpen(false)}
                  className="px-4 py-2 rounded-lg bg-[#17181B] border border-[#2B2C30] text-[#A5A6AA] hover:text-[#F2F2F0] text-xs font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createSubmitting}
                  className="bg-[#F2F2F0] hover:bg-white text-[#090A0C] font-semibold px-4 py-2 rounded-lg text-xs transition disabled:opacity-50 shadow-sm"
                >
                  {createSubmitting ? "Creating..." : "Create Case"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* STATUS TRANSITION MODAL */}
      {pendingStatus && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-[#111214] border border-[#2B2C30] rounded-xl max-w-md w-full p-6 space-y-4 shadow-xl">
            <h3 className="text-sm font-bold text-[#F2F2F0] font-editorial-sans">
              Confirm Transition to <span className="text-[#19D5E5] font-mono">{pendingStatus}</span>
            </h3>
            <p className="text-xs text-[#72747A] font-mono">
              Please provide a transition rationale or forensic justification for this status update.
            </p>
            <textarea
              rows={2}
              placeholder="e.g. Containment verified on host WIN-SRV-01; host isolated."
              value={statusNote}
              onChange={(e) => setStatusNote(e.target.value)}
              className="w-full bg-[#090A0C] border border-[#2B2C30] rounded-lg p-3 text-xs text-[#F2F2F0] outline-none font-mono focus:border-[#19D5E5]"
            />
            <div className="flex items-center justify-end gap-3">
              <button
                type="button"
                onClick={() => setPendingStatus(null)}
                className="px-3.5 py-1.5 rounded-lg text-xs font-mono bg-[#17181B] border border-[#2B2C30] text-[#A5A6AA] hover:text-[#F2F2F0]"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleStatusTransition}
                disabled={statusSubmitting}
                className="bg-[#F2F2F0] hover:bg-white text-[#090A0C] font-semibold px-4 py-1.5 rounded-lg text-xs disabled:opacity-50 shadow-sm"
              >
                {statusSubmitting ? "Updating..." : "Confirm Transition"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
