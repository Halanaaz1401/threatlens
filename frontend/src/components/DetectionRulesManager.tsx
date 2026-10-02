"use client";

import React, { useState, useEffect } from "react";
import { useRole } from "@/context/RoleContext";
import {
  safeFetchDetectionRules,
  safeCreateDetectionRule,
  safeEnableDetectionRule,
  safeDisableDetectionRule,
  safeDeleteDetectionRule,
  safeTestDetectionRule,
} from "@/lib/api";

interface ConditionItem {
  field: string;
  operator: string;
  value: any;
}

interface DetectionRule {
  id: string;
  name: string;
  description: string | null;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  priority: number;
  enabled: boolean;
  logic_operator: "AND" | "OR";
  conditions: ConditionItem[];
  routing_queue: string;
  dedup_window_minutes: number;
  version: number;
  created_by: string;
  created_at: string;
  updated_at: string;
}

const ROUTING_DESTINATIONS: Record<string, { label: string; owner: string; channel: string }> = {
  SOC_TIER_1: { label: "SOC Tier-1 Triage", owner: "SOC Triage Pool", channel: "Internal Queue" },
  SOC_TIER_2: { label: "SOC Tier-2 Investigation", owner: "Priya Nair (Analyst)", channel: "Internal Queue" },
  IR_LEAD: { label: "Incident Response Lead", owner: "Daniel Okafor (IR Lead)", channel: "Internal Queue" },
  SECURITY_ENGINEER: { label: "Security Engineering", owner: "Marcus Vance (Engineer)", channel: "Internal Queue" },
  THREAT_HUNTING: { label: "Threat Hunting Queue", owner: "Mei Lin Tan (Hunter)", channel: "Internal Queue" },
  CISO_ESCALATION: { label: "CISO Escalation", owner: "Rachel Adeyemi (CISO)", channel: "Executive Queue" },
};

export function DetectionRulesManager() {
  const { role, persona } = useRole();
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedRule, setSelectedRule] = useState<DetectionRule | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showTestModal, setShowTestModal] = useState(false);
  const [testResult, setTestResult] = useState<any>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  // RBAC checks based on persona
  const isAdminOrEng = role === "Administrator" || role === "Security Engineer";
  const canTest = isAdminOrEng || role === "Tier-2 SOC Analyst" || role === "Threat Hunter" || role === "Incident Response Lead";
  const isViewer = !isAdminOrEng && !canTest;

  // New Rule Form State
  const [newRule, setNewRule] = useState({
    name: "",
    description: "",
    severity: "HIGH" as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
    priority: 10,
    logic_operator: "AND" as "AND" | "OR",
    routing_queue: "SOC_TIER_2",
    dedup_window_minutes: 60,
    conditions: [
      { field: "severity_score", operator: ">=", value: "75" },
    ],
  });

  // Test Dry-Run State
  const [testIndicator, setTestIndicator] = useState({
    type: "ip",
    value: "198.51.100.44",
    severity_score: 85,
    threat_score: 90,
    source: "Recorded Future",
    verdict: "malicious",
    mitre_technique: "T1071",
  });

  const loadRules = async () => {
    try {
      setLoading(true);
      const data = await safeFetchDetectionRules();
      if (Array.isArray(data)) {
        setRules(data);
        if (data.length > 0 && !selectedRule) {
          setSelectedRule(data[0]);
        }
      }
    } catch (e) {
      console.error("Error loading rules:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadRules();
  }, []);

  const handleToggleEnable = async (rule: DetectionRule) => {
    if (!isAdminOrEng) return;
    try {
      if (rule.enabled) {
        await safeDisableDetectionRule(rule.id);
        setActionMessage(`Rule "${rule.name}" disabled.`);
      } else {
        await safeEnableDetectionRule(rule.id);
        setActionMessage(`Rule "${rule.name}" enabled.`);
      }
      await loadRules();
      setTimeout(() => setActionMessage(null), 4000);
    } catch (err: any) {
      setActionMessage(`Operation failed: ${err.message || "Unknown error"}`);
    }
  };

  const handleDeleteRule = async (ruleId: string) => {
    if (!isAdminOrEng) return;
    if (!confirm("Are you sure you want to delete this detection rule?")) return;
    try {
      await safeDeleteDetectionRule(ruleId);
      setActionMessage("Detection rule deleted.");
      if (selectedRule?.id === ruleId) {
        setSelectedRule(null);
      }
      await loadRules();
      setTimeout(() => setActionMessage(null), 4000);
    } catch (err: any) {
      setActionMessage(`Delete failed: ${err.message || "Unknown error"}`);
    }
  };

  const handleAddCondition = () => {
    setNewRule((prev) => ({
      ...prev,
      conditions: [...prev.conditions, { field: "type", operator: "==", value: "ip" }],
    }));
  };

  const handleRemoveCondition = (index: number) => {
    setNewRule((prev) => ({
      ...prev,
      conditions: prev.conditions.filter((_, i) => i !== index),
    }));
  };

  const handleConditionChange = (index: number, key: string, val: string) => {
    setNewRule((prev) => {
      const updated = [...prev.conditions];
      updated[index] = { ...updated[index], [key]: val };
      return { ...prev, conditions: updated };
    });
  };

  const handleCreateRuleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!isAdminOrEng) return;
    try {
      // Coerce numeric values where appropriate
      const parsedConditions = newRule.conditions.map((c) => {
        let parsedVal: any = c.value;
        if (["severity_score", "threat_score", "confidence"].includes(c.field)) {
          parsedVal = Number(c.value) || 0;
        }
        return {
          field: c.field,
          operator: c.operator,
          value: parsedVal,
        };
      });

      const payload = {
        name: newRule.name.trim(),
        description: newRule.description.trim() || null,
        severity: newRule.severity,
        priority: Number(newRule.priority) || 10,
        logic_operator: newRule.logic_operator,
        routing_queue: newRule.routing_queue,
        dedup_window_minutes: Number(newRule.dedup_window_minutes) || 60,
        conditions: parsedConditions,
        enabled: true,
      };

      const res = await safeCreateDetectionRule(payload);
      if (res && res.id) {
        setActionMessage(`Rule "${res.name}" created successfully.`);
        setShowCreateModal(false);
        setNewRule({
          name: "",
          description: "",
          severity: "HIGH",
          priority: 10,
          logic_operator: "AND",
          routing_queue: "SOC_TIER_2",
          dedup_window_minutes: 60,
          conditions: [{ field: "severity_score", operator: ">=", value: "75" }],
        });
        await loadRules();
        setSelectedRule(res);
        setTimeout(() => setActionMessage(null), 4000);
      } else {
        setActionMessage("Failed to create rule: Validation error.");
      }
    } catch (err: any) {
      setActionMessage(`Error creating rule: ${err.message || "Unknown error"}`);
    }
  };

  const handleRunTest = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedRule && !newRule) return;
    try {
      const ruleToTest = selectedRule || newRule;
      const payload = {
        rule: {
          name: ruleToTest.name || "Test Rule",
          conditions: ruleToTest.conditions,
          logic_operator: ruleToTest.logic_operator,
          severity: ruleToTest.severity,
          routing_queue: ruleToTest.routing_queue,
        },
        indicator: {
          type: testIndicator.type,
          value: testIndicator.value,
          severity_score: Number(testIndicator.severity_score) || 0,
          threat_score: Number(testIndicator.threat_score) || 0,
          source: testIndicator.source,
          mitre_technique: testIndicator.mitre_technique,
          enrichment_data: { verdict: testIndicator.verdict },
        },
      };

      const res = await safeTestDetectionRule(payload);
      setTestResult(res);
    } catch (err: any) {
      setTestResult({ error: err.message || "Test failed" });
    }
  };

  return (
    <div className="space-y-6">
      {/* Action Notification */}
      {actionMessage && (
        <div className="bg-cyan-950/90 border border-cyan-500/80 p-3 rounded-xl text-cyan-200 text-xs flex items-center justify-between shadow-lg">
          <span>{actionMessage}</span>
          <button onClick={() => setActionMessage(null)} className="text-cyan-400 hover:text-white font-bold ml-4">
            ✕
          </button>
        </div>
      )}

      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-[#0b1220] border border-slate-800 rounded-2xl p-5 shadow-sm">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xl font-bold text-slate-100 flex items-center gap-2">
              ⚙️ Configurable Detection Rules &amp; Alert Routing
            </span>
            <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-blue-950 text-blue-400 border border-blue-800">
              FR-17 &amp; FR-18
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Deterministic declarative condition evaluation engine with deduplication &amp; role-based queue routing.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {canTest && selectedRule && (
            <button
              onClick={() => {
                setTestResult(null);
                setShowTestModal(true);
              }}
              className="bg-purple-900/60 hover:bg-purple-800 border border-purple-600 text-purple-200 font-bold px-3.5 py-2 rounded-xl text-xs flex items-center gap-1.5 transition"
            >
              <span>🧪</span>
              <span>Dry-Run Test Rule</span>
            </button>
          )}

          {isAdminOrEng && (
            <button
              onClick={() => setShowCreateModal(true)}
              className="bg-cyan-600 hover:bg-cyan-500 text-white font-bold px-4 py-2 rounded-xl text-xs flex items-center gap-1.5 shadow-sm transition"
            >
              <span>+</span>
              <span>Create Rule</span>
            </button>
          )}
        </div>
      </div>

      {/* Alert Routing Overview Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {Object.entries(ROUTING_DESTINATIONS).map(([key, dest]) => {
          const count = rules.filter((r) => r.routing_queue === key && r.enabled).length;
          return (
            <div key={key} className="bg-[#0e1628] border border-slate-800/90 rounded-xl p-3 space-y-1">
              <span className="text-[10px] font-mono uppercase text-slate-400 truncate block">
                {dest.label}
              </span>
              <div className="flex items-baseline justify-between">
                <span className="text-lg font-bold text-slate-100">{count}</span>
                <span className="text-[10px] font-mono text-cyan-400">rules</span>
              </div>
              <div className="text-[10px] text-slate-500 truncate" title={dest.owner}>
                {dest.owner}
              </div>
            </div>
          );
        })}
      </div>

      {/* Main Grid: Rules Table + Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Rules Table */}
        <div className="lg:col-span-7 bg-[#0b1220] border border-slate-800 rounded-2xl p-5 space-y-4 shadow-sm">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold text-slate-200 flex items-center gap-2">
              <span>📋</span> Active Rules Inventory ({rules.length})
            </h2>
            <button
              onClick={loadRules}
              className="text-xs text-slate-400 hover:text-cyan-400 flex items-center gap-1"
            >
              <span>🔄</span> Refresh
            </button>
          </div>

          {loading ? (
            <div className="py-16 text-center text-slate-500 text-xs font-mono animate-pulse">
              Loading Detection Rules from Engine...
            </div>
          ) : rules.length === 0 ? (
            <div className="py-16 text-center text-slate-500 text-xs font-mono">
              No detection rules configured.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 font-semibold uppercase text-[10px]">
                    <th className="pb-3">Status</th>
                    <th className="pb-3">Rule Name</th>
                    <th className="pb-3">Severity</th>
                    <th className="pb-3">Queue</th>
                    <th className="pb-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {rules.map((rule) => {
                    const isSelected = selectedRule?.id === rule.id;
                    return (
                      <tr
                        key={rule.id}
                        onClick={() => setSelectedRule(rule)}
                        className={`cursor-pointer transition hover:bg-slate-800/40 ${
                          isSelected ? "bg-cyan-950/30 border-l-2 border-cyan-400" : ""
                        }`}
                      >
                        <td className="py-3">
                          <span
                            className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                              rule.enabled
                                ? "bg-emerald-950/80 text-emerald-400 border-emerald-800"
                                : "bg-slate-900 text-slate-500 border-slate-800"
                            }`}
                          >
                            {rule.enabled ? "ACTIVE" : "DISABLED"}
                          </span>
                        </td>
                        <td className="py-3 font-semibold text-slate-200 max-w-[200px] truncate">
                          {rule.name}
                        </td>
                        <td className="py-3">
                          <span
                            className={`font-mono px-2 py-0.5 rounded text-[10px] font-bold ${
                              rule.severity === "CRITICAL"
                                ? "bg-rose-950/80 text-rose-400 border border-rose-800"
                                : rule.severity === "HIGH"
                                ? "bg-amber-950/80 text-amber-400 border border-amber-800"
                                : rule.severity === "MEDIUM"
                                ? "bg-yellow-950/80 text-yellow-400 border border-yellow-800"
                                : "bg-slate-900 text-slate-400 border border-slate-800"
                            }`}
                          >
                            {rule.severity}
                          </span>
                        </td>
                        <td className="py-3 font-mono text-[11px] text-cyan-400">
                          {rule.routing_queue}
                        </td>
                        <td className="py-3 text-right" onClick={(e) => e.stopPropagation()}>
                          <div className="flex items-center justify-end gap-1.5">
                            {isAdminOrEng && (
                              <>
                                <button
                                  onClick={() => handleToggleEnable(rule)}
                                  className={`px-2 py-1 rounded text-[10px] font-medium border ${
                                    rule.enabled
                                      ? "bg-slate-900 hover:bg-slate-800 text-slate-400 border-slate-700"
                                      : "bg-emerald-950/60 hover:bg-emerald-900 text-emerald-400 border-emerald-700"
                                  }`}
                                >
                                  {rule.enabled ? "Disable" : "Enable"}
                                </button>
                                <button
                                  onClick={() => handleDeleteRule(rule.id)}
                                  className="bg-rose-950/60 hover:bg-rose-900 text-rose-400 border border-rose-800 px-2 py-1 rounded text-[10px]"
                                >
                                  Delete
                                </button>
                              </>
                            )}
                            {isViewer && (
                              <span className="text-[10px] text-slate-500 font-mono">Read-Only</span>
                            )}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Right Column: Rule Inspector & Declarative Conditions */}
        <div className="lg:col-span-5 space-y-4">
          <div className="bg-[#0b1220] border border-slate-800 rounded-2xl p-5 space-y-4 shadow-sm">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <span>🔍</span> Rule Inspection &amp; Logic
              </h3>
              {selectedRule && (
                <span className="text-[10px] font-mono text-slate-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                  v{selectedRule.version}
                </span>
              )}
            </div>

            {selectedRule ? (
              <div className="space-y-4">
                <div className="p-3.5 rounded-xl bg-[#080d19] border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-100">{selectedRule.name}</span>
                    <span className="text-[10px] font-mono text-cyan-400">{selectedRule.id}</span>
                  </div>
                  <p className="text-xs text-slate-400">{selectedRule.description || "No description provided."}</p>
                  <div className="flex items-center gap-3 pt-1 text-[10px] font-mono text-slate-500">
                    <span>Priority: {selectedRule.priority}</span>
                    <span>&bull;</span>
                    <span>Dedup Window: {selectedRule.dedup_window_minutes}m</span>
                    <span>&bull;</span>
                    <span>Author: {selectedRule.created_by}</span>
                  </div>
                </div>

                {/* Routing Destination Block */}
                <div className="p-3 rounded-xl bg-[#0e1628] border border-slate-800 space-y-1">
                  <span className="text-[10px] font-mono uppercase text-slate-500">Alert Routing Destination</span>
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-cyan-300">
                      {ROUTING_DESTINATIONS[selectedRule.routing_queue]?.label || selectedRule.routing_queue}
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
                      {selectedRule.routing_queue}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400">
                    Assigned Owner: <strong className="text-slate-200">{ROUTING_DESTINATIONS[selectedRule.routing_queue]?.owner}</strong>
                  </div>
                </div>

                {/* Declarative DSL Conditions */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-300">
                      Conditions (Operator: <strong className="text-cyan-400">{selectedRule.logic_operator}</strong>)
                    </span>
                    <span className="text-[10px] font-mono text-slate-500">
                      {selectedRule.conditions.length} condition(s)
                    </span>
                  </div>

                  <div className="space-y-1.5">
                    {selectedRule.conditions.map((cond, idx) => (
                      <div
                        key={idx}
                        className="flex items-center justify-between p-2 rounded-lg bg-[#0e1628] border border-slate-800/80 font-mono text-xs"
                      >
                        <span className="text-cyan-400">{cond.field}</span>
                        <span className="text-amber-400 font-bold">{cond.operator}</span>
                        <span className="text-emerald-300 truncate max-w-[150px]">
                          {typeof cond.value === "object" ? JSON.stringify(cond.value) : String(cond.value)}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                {canTest && (
                  <button
                    onClick={() => {
                      setTestResult(null);
                      setShowTestModal(true);
                    }}
                    className="w-full bg-purple-900/60 hover:bg-purple-800 text-purple-200 font-bold py-2 rounded-xl text-xs transition flex items-center justify-center gap-2 border border-purple-700/60"
                  >
                    <span>🧪</span>
                    <span>Test Against Sample IOC</span>
                  </button>
                )}
              </div>
            ) : (
              <div className="text-center py-12 text-slate-500 text-xs">
                Select a rule from the table to inspect conditions and routing rules.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Create Rule Modal */}
      {showCreateModal && isAdminOrEng && (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4">
          <div className="bg-[#0b1220] border border-slate-700 rounded-2xl p-6 max-w-xl w-full space-y-4 max-h-[90vh] overflow-y-auto shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <span>➕</span> Create Configurable Detection Rule
              </h3>
              <button
                onClick={() => setShowCreateModal(false)}
                className="text-slate-400 hover:text-white font-bold"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateRuleSubmit} className="space-y-4 text-xs">
              <div className="space-y-1">
                <label className="text-slate-300 font-semibold">Rule Name *</label>
                <input
                  type="text"
                  required
                  value={newRule.name}
                  onChange={(e) => setNewRule({ ...newRule, name: e.target.value })}
                  placeholder="e.g. Critical C2 IP Pattern Match"
                  className="w-full bg-[#0e1628] border border-slate-700 rounded-lg p-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="space-y-1">
                <label className="text-slate-300 font-semibold">Description</label>
                <textarea
                  value={newRule.description}
                  onChange={(e) => setNewRule({ ...newRule, description: e.target.value })}
                  placeholder="Operational purpose and adversary context..."
                  className="w-full bg-[#0e1628] border border-slate-700 rounded-lg p-2 text-slate-200 focus:outline-none focus:border-cyan-500 h-16"
                />
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div className="space-y-1">
                  <label className="text-slate-300 font-semibold">Severity</label>
                  <select
                    value={newRule.severity}
                    onChange={(e) => setNewRule({ ...newRule, severity: e.target.value as any })}
                    className="w-full bg-[#0e1628] border border-slate-700 rounded-lg p-2 text-slate-200"
                  >
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-slate-300 font-semibold">Logic Operator</label>
                  <select
                    value={newRule.logic_operator}
                    onChange={(e) => setNewRule({ ...newRule, logic_operator: e.target.value as any })}
                    className="w-full bg-[#0e1628] border border-slate-700 rounded-lg p-2 text-slate-200"
                  >
                    <option value="AND">AND (All match)</option>
                    <option value="OR">OR (Any match)</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-slate-300 font-semibold">Routing Queue</label>
                  <select
                    value={newRule.routing_queue}
                    onChange={(e) => setNewRule({ ...newRule, routing_queue: e.target.value })}
                    className="w-full bg-[#0e1628] border border-slate-700 rounded-lg p-2 text-slate-200"
                  >
                    <option value="SOC_TIER_1">SOC_TIER_1</option>
                    <option value="SOC_TIER_2">SOC_TIER_2</option>
                    <option value="IR_LEAD">IR_LEAD</option>
                    <option value="SECURITY_ENGINEER">SECURITY_ENGINEER</option>
                    <option value="THREAT_HUNTING">THREAT_HUNTING</option>
                    <option value="CISO_ESCALATION">CISO_ESCALATION</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-slate-300 font-semibold">Dedup Window (min)</label>
                  <input
                    type="number"
                    min={1}
                    max={1440}
                    value={newRule.dedup_window_minutes}
                    onChange={(e) => setNewRule({ ...newRule, dedup_window_minutes: Number(e.target.value) || 60 })}
                    className="w-full bg-[#0e1628] border border-slate-700 rounded-lg p-2 text-slate-200"
                  />
                </div>
              </div>

              {/* Conditions List */}
              <div className="space-y-2 border-t border-slate-800 pt-3">
                <div className="flex items-center justify-between">
                  <label className="text-slate-300 font-semibold">Declarative Conditions</label>
                  <button
                    type="button"
                    onClick={handleAddCondition}
                    className="text-cyan-400 hover:text-cyan-300 text-[11px] font-bold"
                  >
                    + Add Condition
                  </button>
                </div>

                <div className="space-y-2">
                  {newRule.conditions.map((cond, idx) => (
                    <div key={idx} className="flex items-center gap-2">
                      <select
                        value={cond.field}
                        onChange={(e) => handleConditionChange(idx, "field", e.target.value)}
                        className="bg-[#0e1628] border border-slate-700 rounded-lg p-1.5 text-slate-200 flex-1"
                      >
                        <option value="type">type</option>
                        <option value="value">value</option>
                        <option value="severity_score">severity_score</option>
                        <option value="threat_score">threat_score</option>
                        <option value="source">source</option>
                        <option value="verdict">verdict</option>
                        <option value="mitre_technique">mitre_technique</option>
                      </select>

                      <select
                        value={cond.operator}
                        onChange={(e) => handleConditionChange(idx, "operator", e.target.value)}
                        className="bg-[#0e1628] border border-slate-700 rounded-lg p-1.5 text-slate-200 w-24"
                      >
                        <option value="==">==</option>
                        <option value="!=">!=</option>
                        <option value=">">&gt;</option>
                        <option value=">=">&gt;=</option>
                        <option value="<">&lt;</option>
                        <option value="<=">&lt;=</option>
                        <option value="contains">contains</option>
                        <option value="regex_match">regex_match</option>
                      </select>

                      <input
                        type="text"
                        required
                        value={cond.value}
                        onChange={(e) => handleConditionChange(idx, "value", e.target.value)}
                        placeholder="Value..."
                        className="bg-[#0e1628] border border-slate-700 rounded-lg p-1.5 text-slate-200 flex-1"
                      />

                      {newRule.conditions.length > 1 && (
                        <button
                          type="button"
                          onClick={() => handleRemoveCondition(idx)}
                          className="text-rose-400 hover:text-rose-300 px-2 py-1 font-bold"
                        >
                          ✕
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              <div className="flex items-center justify-end gap-3 pt-4 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="bg-slate-800 hover:bg-slate-700 text-slate-300 px-4 py-2 rounded-xl"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="bg-cyan-600 hover:bg-cyan-500 text-white font-bold px-5 py-2 rounded-xl shadow-sm"
                >
                  Save &amp; Activate Rule
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Dry Run Test Modal */}
      {showTestModal && canTest && (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4">
          <div className="bg-[#0b1220] border border-slate-700 rounded-2xl p-6 max-w-xl w-full space-y-4 max-h-[90vh] overflow-y-auto shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <span>🧪</span> Rule Dry-Run Testing (Side-Effect Free)
              </h3>
              <button
                onClick={() => setShowTestModal(false)}
                className="text-slate-400 hover:text-white font-bold"
              >
                ✕
              </button>
            </div>

            <p className="text-xs text-slate-400">
              Evaluates real indicator telemetry against declarative rule conditions without creating alerts, publishing production events, or modifying database records.
            </p>

            <form onSubmit={handleRunTest} className="space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-slate-300 font-semibold">Indicator Type</label>
                  <input
                    type="text"
                    value={testIndicator.type}
                    onChange={(e) => setTestIndicator({ ...testIndicator, type: e.target.value })}
                    className="w-full bg-[#0e1628] border border-slate-700 rounded-lg p-2 text-slate-200"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-slate-300 font-semibold">Indicator Value</label>
                  <input
                    type="text"
                    value={testIndicator.value}
                    onChange={(e) => setTestIndicator({ ...testIndicator, value: e.target.value })}
                    className="w-full bg-[#0e1628] border border-slate-700 rounded-lg p-2 text-slate-200"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-slate-300 font-semibold">Severity Score (0-100)</label>
                  <input
                    type="number"
                    value={testIndicator.severity_score}
                    onChange={(e) => setTestIndicator({ ...testIndicator, severity_score: Number(e.target.value) || 0 })}
                    className="w-full bg-[#0e1628] border border-slate-700 rounded-lg p-2 text-slate-200"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-slate-300 font-semibold">Threat Score (0-100)</label>
                  <input
                    type="number"
                    value={testIndicator.threat_score}
                    onChange={(e) => setTestIndicator({ ...testIndicator, threat_score: Number(e.target.value) || 0 })}
                    className="w-full bg-[#0e1628] border border-slate-700 rounded-lg p-2 text-slate-200"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-slate-300 font-semibold">Feed / Source</label>
                  <input
                    type="text"
                    value={testIndicator.source}
                    onChange={(e) => setTestIndicator({ ...testIndicator, source: e.target.value })}
                    className="w-full bg-[#0e1628] border border-slate-700 rounded-lg p-2 text-slate-200"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-slate-300 font-semibold">Enrichment Verdict</label>
                  <input
                    type="text"
                    value={testIndicator.verdict}
                    onChange={(e) => setTestIndicator({ ...testIndicator, verdict: e.target.value })}
                    className="w-full bg-[#0e1628] border border-slate-700 rounded-lg p-2 text-slate-200"
                  />
                </div>
              </div>

              <button
                type="submit"
                className="w-full bg-purple-600 hover:bg-purple-500 text-white font-bold py-2 rounded-xl shadow-sm transition"
              >
                Execute Dry-Run Evaluation
              </button>
            </form>

            {/* Test Results Output */}
            {testResult && (
              <div className="mt-4 p-4 rounded-xl bg-[#080d19] border border-slate-800 space-y-3 font-mono text-xs">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400 font-semibold">Dry-Run Verdict:</span>
                  <span
                    className={`px-2 py-0.5 rounded font-bold ${
                      testResult.matched
                        ? "bg-rose-950 text-rose-400 border border-rose-800"
                        : "bg-slate-900 text-slate-400 border border-slate-800"
                    }`}
                  >
                    {testResult.matched ? "RULE MATCHED (TRIGGERED)" : "NO MATCH"}
                  </span>
                </div>

                <div className="text-[11px] text-slate-400 space-y-1">
                  <div>
                    Evaluated Conditions:{" "}
                    <strong className="text-slate-200">
                      {testResult.matched_conditions_count || 0} / {testResult.total_conditions || 0} passed
                    </strong>
                  </div>
                  <div>
                    Target Routing Destination:{" "}
                    <strong className="text-cyan-300">{testResult.routing_destination || "N/A"}</strong>
                  </div>
                </div>

                {testResult.condition_details && (
                  <div className="space-y-1 pt-2 border-t border-slate-800">
                    <span className="text-[10px] uppercase text-slate-500">Condition Breakdown:</span>
                    {testResult.condition_details.map((c: any, i: number) => (
                      <div
                        key={i}
                        className={`flex items-center justify-between p-1.5 rounded text-[10px] ${
                          c.matched ? "bg-emerald-950/40 text-emerald-300" : "bg-rose-950/40 text-rose-300"
                        }`}
                      >
                        <span>
                          {c.field} {c.operator} {String(c.expected)}
                        </span>
                        <span>{c.matched ? "PASS" : `FAIL (Actual: ${String(c.actual)})`}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
export default DetectionRulesManager;
