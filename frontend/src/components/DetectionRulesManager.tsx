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
import {
  Settings,
  FlaskConical,
  Plus,
  Shield,
  RotateCw,
  Search,
  X,
  CheckCircle2,
  AlertTriangle,
} from "lucide-react";

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
  const { role } = useRole();
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
        setActionMessage(`Disabled rule: ${rule.name}`);
      } else {
        await safeEnableDetectionRule(rule.id);
        setActionMessage(`Enabled rule: ${rule.name}`);
      }
      await loadRules();
      setTimeout(() => setActionMessage(null), 3000);
    } catch {
      setActionMessage("Failed to toggle rule state.");
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
      setTimeout(() => setActionMessage(null), 3000);
    } catch {
      setActionMessage("Failed to delete rule.");
    }
  };

  const handleAddCondition = () => {
    setNewRule({
      ...newRule,
      conditions: [...newRule.conditions, { field: "type", operator: "==", value: "" }],
    });
  };

  const handleRemoveCondition = (index: number) => {
    if (newRule.conditions.length <= 1) return;
    const next = [...newRule.conditions];
    next.splice(index, 1);
    setNewRule({ ...newRule, conditions: next });
  };

  const handleConditionChange = (index: number, key: keyof ConditionItem, val: any) => {
    const next = [...newRule.conditions];
    next[index] = { ...next[index], [key]: val };
    setNewRule({ ...newRule, conditions: next });
  };

  const handleCreateRuleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!isAdminOrEng) return;
    try {
      const parsedConditions = newRule.conditions.map((c) => {
        let v: any = c.value;
        if (!isNaN(Number(v)) && v.trim() !== "") {
          v = Number(v);
        }
        return { ...c, value: v };
      });

      const res = await safeCreateDetectionRule({
        ...newRule,
        conditions: parsedConditions,
      });

      if (res && res.id) {
        setActionMessage(`Detection Rule '${res.name}' created successfully.`);
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
        <div className="bg-[#17181B] border border-[#19D5E5]/40 p-3 rounded-lg text-[#19D5E5] text-xs flex items-center justify-between shadow-lg">
          <span className="flex items-center gap-1.5"><CheckCircle2 className="w-4 h-4 text-[#19D5E5] shrink-0" /> {actionMessage}</span>
          <button onClick={() => setActionMessage(null)} className="text-[#72747A] hover:text-white ml-4 cursor-pointer" aria-label="Dismiss notification">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-[#111214] border border-[#2B2C30] rounded-xl p-5 shadow-sm">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-bold text-[#F2F2F0] flex items-center gap-2">
              <Settings className="w-4 h-4 text-[#19D5E5]" /> Configurable Detection Rules &amp; Alert Routing
            </h2>
            <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-[#17181B] text-[#19D5E5] border border-[#2B2C30]">
              FR-17 &amp; FR-18
            </span>
          </div>
          <p className="text-xs text-[#A5A6AA] mt-1">
            Deterministic declarative condition evaluation engine with deduplication &amp; role-based queue routing.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          {canTest && selectedRule && (
            <button
              onClick={() => {
                setTestResult(null);
                setShowTestModal(true);
              }}
              className="bg-[#17181B] hover:bg-[#202125] border border-[#2B2C30] text-[#F2F2F0] font-bold px-3.5 py-2 rounded-lg text-xs flex items-center gap-1.5 transition cursor-pointer"
            >
              <FlaskConical className="w-3.5 h-3.5 text-[#19D5E5]" />
              <span>Dry-Run Test Rule</span>
            </button>
          )}

          {isAdminOrEng && (
            <button
              onClick={() => setShowCreateModal(true)}
              className="bg-[#F2F2F0] hover:bg-white text-[#090A0C] font-bold px-4 py-2 rounded-lg text-xs flex items-center gap-1.5 shadow-sm transition cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" />
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
            <div key={key} className="bg-[#111214] border border-[#2B2C30] rounded-lg p-3 space-y-1">
              <span className="text-[10px] font-mono uppercase text-[#72747A] truncate block">
                {dest.label}
              </span>
              <div className="flex items-baseline justify-between">
                <span className="text-lg font-bold text-[#F2F2F0] font-mono">{count}</span>
                <span className="text-[10px] font-mono text-[#19D5E5]">rules</span>
              </div>
              <div className="text-[10px] text-[#A5A6AA] truncate" title={dest.owner}>
                {dest.owner}
              </div>
            </div>
          );
        })}
      </div>

      {/* Main Grid: Rules Table + Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Rules Table */}
        <div className="lg:col-span-7 bg-[#111214] border border-[#2B2C30] rounded-xl p-5 space-y-4 shadow-sm">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-[#F2F2F0] flex items-center gap-2">
              <Shield className="w-4 h-4 text-[#19D5E5]" /> Active Rules Inventory <span className="font-mono text-xs text-[#85858B]">({rules.length})</span>
            </h3>
            <button
              onClick={loadRules}
              className="text-xs text-[#72747A] hover:text-[#F2F2F0] flex items-center gap-1 cursor-pointer font-mono"
            >
              <RotateCw className="w-3 h-3" /> Refresh
            </button>
          </div>

          {loading ? (
            <div className="py-16 text-center text-[#72747A] text-xs font-mono animate-pulse">
              Loading Detection Rules from Engine...
            </div>
          ) : rules.length === 0 ? (
            <div className="py-16 text-center text-[#72747A] text-xs font-mono">
              No detection rules configured.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-[#2B2C30] text-[#72747A] font-semibold uppercase text-[10px] font-mono">
                    <th className="pb-3">Status</th>
                    <th className="pb-3">Rule Name</th>
                    <th className="pb-3">Severity</th>
                    <th className="pb-3">Queue</th>
                    <th className="pb-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#2B2C30]">
                  {rules.map((rule) => {
                    const isSelected = selectedRule?.id === rule.id;
                    return (
                      <tr
                        key={rule.id}
                        onClick={() => setSelectedRule(rule)}
                        className={`cursor-pointer transition hover:bg-[#17181B] ${
                          isSelected ? "bg-[#17181B] border-l-2 border-[#19D5E5]" : ""
                        }`}
                      >
                        <td className="py-3">
                          <span
                            className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                              rule.enabled
                                ? "bg-[#111214] text-emerald-400 border-emerald-900/60"
                                : "bg-[#111214] text-[#72747A] border-[#2B2C30]"
                            }`}
                          >
                            {rule.enabled ? "ACTIVE" : "DISABLED"}
                          </span>
                        </td>
                        <td className="py-3 font-semibold text-[#F2F2F0] max-w-[200px] truncate">
                          {rule.name}
                        </td>
                        <td className="py-3">
                          <span
                            className={`font-mono px-2 py-0.5 rounded text-[10px] font-bold border ${
                              rule.severity === "CRITICAL"
                                ? "bg-[#17181B] text-red-400 border-red-900/60"
                                : rule.severity === "HIGH"
                                ? "bg-[#17181B] text-amber-400 border-amber-900/60"
                                : rule.severity === "MEDIUM"
                                ? "bg-[#17181B] text-yellow-400 border-yellow-900/60"
                                : "bg-[#17181B] text-[#A5A6AA] border-[#2B2C30]"
                            }`}
                          >
                            {rule.severity}
                          </span>
                        </td>
                        <td className="py-3 font-mono text-[11px] text-[#19D5E5]">
                          {rule.routing_queue}
                        </td>
                        <td className="py-3 text-right" onClick={(e) => e.stopPropagation()}>
                          <div className="flex items-center justify-end gap-1.5">
                            {isAdminOrEng && (
                              <>
                                <button
                                  onClick={() => handleToggleEnable(rule)}
                                  className={`px-2 py-1 rounded text-[10px] font-medium border cursor-pointer ${
                                    rule.enabled
                                      ? "bg-[#17181B] hover:bg-[#202125] text-[#A5A6AA] border-[#2B2C30]"
                                      : "bg-[#17181B] hover:bg-[#202125] text-emerald-400 border-emerald-900/60"
                                  }`}
                                >
                                  {rule.enabled ? "Disable" : "Enable"}
                                </button>
                                <button
                                  onClick={() => handleDeleteRule(rule.id)}
                                  className="bg-[#17181B] hover:bg-red-950 text-red-400 border border-red-900/60 px-2 py-1 rounded text-[10px] cursor-pointer"
                                >
                                  Delete
                                </button>
                              </>
                            )}
                            {isViewer && (
                              <span className="text-[10px] text-[#72747A] font-mono">Read-Only</span>
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
          <div className="bg-[#111214] border border-[#2B2C30] rounded-xl p-5 space-y-4 shadow-sm">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-[#F2F2F0] flex items-center gap-2">
                <Search className="w-4 h-4 text-[#19D5E5]" /> Rule Inspection &amp; Logic
              </h3>
              {selectedRule && (
                <span className="text-[10px] font-mono text-[#A5A6AA] bg-[#090A0C] px-2 py-0.5 rounded border border-[#2B2C30]">
                  v{selectedRule.version}
                </span>
              )}
            </div>

            {selectedRule ? (
              <div className="space-y-4">
                <div className="p-3.5 rounded-lg bg-[#090A0C] border border-[#2B2C30] space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-[#F2F2F0]">{selectedRule.name}</span>
                    <span className="text-[10px] font-mono text-[#19D5E5]">{selectedRule.id}</span>
                  </div>
                  <p className="text-xs text-[#A5A6AA]">{selectedRule.description || "No description provided."}</p>
                  <div className="flex items-center gap-3 pt-1 text-[10px] font-mono text-[#72747A]">
                    <span>Priority: {selectedRule.priority}</span>
                    <span>&bull;</span>
                    <span>Dedup Window: {selectedRule.dedup_window_minutes}m</span>
                    <span>&bull;</span>
                    <span>Author: {selectedRule.created_by}</span>
                  </div>
                </div>

                {/* Routing Destination Block */}
                <div className="p-3 rounded-lg bg-[#17181B] border border-[#2B2C30] space-y-1">
                  <span className="text-[10px] font-mono uppercase text-[#72747A]">Alert Routing Destination</span>
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-[#F2F2F0]">
                      {ROUTING_DESTINATIONS[selectedRule.routing_queue]?.label || selectedRule.routing_queue}
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#090A0C] text-[#19D5E5] border border-[#2B2C30]">
                      {selectedRule.routing_queue}
                    </span>
                  </div>
                  <div className="text-[11px] text-[#A5A6AA]">
                    Assigned Owner: <strong className="text-[#F2F2F0]">{ROUTING_DESTINATIONS[selectedRule.routing_queue]?.owner}</strong>
                  </div>
                </div>

                {/* Declarative DSL Conditions */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-[#A5A6AA]">
                      Conditions (Operator: <strong className="text-[#19D5E5]">{selectedRule.logic_operator}</strong>)
                    </span>
                    <span className="text-[10px] font-mono text-[#72747A]">
                      {selectedRule.conditions.length} condition(s)
                    </span>
                  </div>

                  <div className="space-y-1.5">
                    {selectedRule.conditions.map((cond, idx) => (
                      <div
                        key={idx}
                        className="flex items-center justify-between p-2 rounded bg-[#090A0C] border border-[#2B2C30] font-mono text-xs"
                      >
                        <span className="text-[#19D5E5]">{cond.field}</span>
                        <span className="text-[#F2F2F0] font-bold">{cond.operator}</span>
                        <span className="text-[#A5A6AA] truncate max-w-[150px]">
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
                    className="w-full bg-[#17181B] hover:bg-[#202125] text-[#F2F2F0] font-bold py-2 rounded-lg text-xs transition flex items-center justify-center gap-2 border border-[#2B2C30] cursor-pointer"
                  >
                    <FlaskConical className="w-3.5 h-3.5 text-[#19D5E5]" />
                    <span>Test Against Sample IOC</span>
                  </button>
                )}
              </div>
            ) : (
              <div className="text-center py-12 text-[#72747A] text-xs font-mono">
                Select a rule from the table to inspect conditions and routing rules.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Create Rule Modal */}
      {showCreateModal && isAdminOrEng && (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4">
          <div className="bg-[#111214] border border-[#2B2C30] rounded-xl p-6 max-w-xl w-full space-y-4 max-h-[90vh] overflow-y-auto shadow-2xl">
            <div className="flex items-center justify-between border-b border-[#2B2C30] pb-3">
              <h3 className="text-sm font-bold text-[#F2F2F0] flex items-center gap-2">
                <Plus className="w-4 h-4 text-[#19D5E5]" /> Create Configurable Detection Rule
              </h3>
              <button
                onClick={() => setShowCreateModal(false)}
                className="text-[#72747A] hover:text-[#F2F2F0] p-1 rounded-lg bg-[#17181B] border border-[#2B2C30] transition cursor-pointer"
                aria-label="Close dialog"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreateRuleSubmit} className="space-y-4 text-xs">
              <div className="space-y-1">
                <label className="text-[#A5A6AA] font-semibold">Rule Name *</label>
                <input
                  type="text"
                  required
                  value={newRule.name}
                  onChange={(e) => setNewRule({ ...newRule, name: e.target.value })}
                  placeholder="e.g. Critical C2 IP Pattern Match"
                  className="w-full bg-[#090A0C] border border-[#2B2C30] rounded-lg p-2 text-[#F2F2F0] focus:outline-none focus:border-[#19D5E5]"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[#A5A6AA] font-semibold">Description</label>
                <textarea
                  value={newRule.description}
                  onChange={(e) => setNewRule({ ...newRule, description: e.target.value })}
                  placeholder="Operational purpose and adversary context..."
                  className="w-full bg-[#090A0C] border border-[#2B2C30] rounded-lg p-2 text-[#F2F2F0] focus:outline-none focus:border-[#19D5E5] h-16"
                />
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div className="space-y-1">
                  <label className="text-[#A5A6AA] font-semibold">Severity</label>
                  <select
                    value={newRule.severity}
                    onChange={(e) => setNewRule({ ...newRule, severity: e.target.value as any })}
                    className="w-full bg-[#090A0C] border border-[#2B2C30] rounded-lg p-2 text-[#F2F2F0]"
                  >
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-[#A5A6AA] font-semibold">Logic Operator</label>
                  <select
                    value={newRule.logic_operator}
                    onChange={(e) => setNewRule({ ...newRule, logic_operator: e.target.value as any })}
                    className="w-full bg-[#090A0C] border border-[#2B2C30] rounded-lg p-2 text-[#F2F2F0]"
                  >
                    <option value="AND">AND (All match)</option>
                    <option value="OR">OR (Any match)</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-[#A5A6AA] font-semibold">Routing Queue</label>
                  <select
                    value={newRule.routing_queue}
                    onChange={(e) => setNewRule({ ...newRule, routing_queue: e.target.value })}
                    className="w-full bg-[#090A0C] border border-[#2B2C30] rounded-lg p-2 text-[#F2F2F0]"
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
                  <label className="text-[#A5A6AA] font-semibold">Dedup Window (min)</label>
                  <input
                    type="number"
                    min={1}
                    max={1440}
                    value={newRule.dedup_window_minutes}
                    onChange={(e) => setNewRule({ ...newRule, dedup_window_minutes: Number(e.target.value) || 60 })}
                    className="w-full bg-[#090A0C] border border-[#2B2C30] rounded-lg p-2 text-[#F2F2F0]"
                  />
                </div>
              </div>

              {/* Conditions List */}
              <div className="space-y-2 border-t border-[#2B2C30] pt-3">
                <div className="flex items-center justify-between">
                  <label className="text-[#A5A6AA] font-semibold">Declarative Conditions</label>
                  <button
                    type="button"
                    onClick={handleAddCondition}
                    className="text-[#19D5E5] hover:underline text-[11px] font-bold cursor-pointer font-mono"
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
                        className="bg-[#090A0C] border border-[#2B2C30] rounded-lg p-1.5 text-[#F2F2F0] flex-1"
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
                        className="bg-[#090A0C] border border-[#2B2C30] rounded-lg p-1.5 text-[#F2F2F0] w-24"
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
                        className="bg-[#090A0C] border border-[#2B2C30] rounded-lg p-1.5 text-[#F2F2F0] flex-1"
                      />

                      {newRule.conditions.length > 1 && (
                        <button
                          type="button"
                          onClick={() => handleRemoveCondition(idx)}
                          className="text-red-400 hover:text-red-300 p-1 cursor-pointer"
                          aria-label="Remove condition"
                        >
                          <X className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              <div className="flex items-center justify-end gap-3 pt-4 border-t border-[#2B2C30]">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="bg-[#17181B] hover:bg-[#202125] text-[#A5A6AA] px-4 py-2 rounded-lg cursor-pointer border border-[#2B2C30]"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="bg-[#F2F2F0] hover:bg-white text-[#090A0C] font-bold px-5 py-2 rounded-lg shadow-sm cursor-pointer"
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
          <div className="bg-[#111214] border border-[#2B2C30] rounded-xl p-6 max-w-xl w-full space-y-4 max-h-[90vh] overflow-y-auto shadow-2xl">
            <div className="flex items-center justify-between border-b border-[#2B2C30] pb-3">
              <h3 className="text-sm font-bold text-[#F2F2F0] flex items-center gap-2">
                <FlaskConical className="w-4 h-4 text-[#19D5E5]" /> Rule Dry-Run Testing (Side-Effect Free)
              </h3>
              <button
                onClick={() => setShowTestModal(false)}
                className="text-[#72747A] hover:text-[#F2F2F0] p-1 rounded-lg bg-[#17181B] border border-[#2B2C30] transition cursor-pointer"
                aria-label="Close dialog"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="text-xs text-[#A5A6AA]">
              Evaluates real indicator telemetry against declarative rule conditions without creating alerts, publishing production events, or modifying database records.
            </p>

            <form onSubmit={handleRunTest} className="space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-[#A5A6AA] font-semibold">Indicator Type</label>
                  <input
                    type="text"
                    value={testIndicator.type}
                    onChange={(e) => setTestIndicator({ ...testIndicator, type: e.target.value })}
                    className="w-full bg-[#090A0C] border border-[#2B2C30] rounded-lg p-2 text-[#F2F2F0]"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-[#A5A6AA] font-semibold">Indicator Value</label>
                  <input
                    type="text"
                    value={testIndicator.value}
                    onChange={(e) => setTestIndicator({ ...testIndicator, value: e.target.value })}
                    className="w-full bg-[#090A0C] border border-[#2B2C30] rounded-lg p-2 text-[#F2F2F0]"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-[#A5A6AA] font-semibold">Severity Score (0-100)</label>
                  <input
                    type="number"
                    value={testIndicator.severity_score}
                    onChange={(e) => setTestIndicator({ ...testIndicator, severity_score: Number(e.target.value) || 0 })}
                    className="w-full bg-[#090A0C] border border-[#2B2C30] rounded-lg p-2 text-[#F2F2F0]"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-[#A5A6AA] font-semibold">Threat Score (0-100)</label>
                  <input
                    type="number"
                    value={testIndicator.threat_score}
                    onChange={(e) => setTestIndicator({ ...testIndicator, threat_score: Number(e.target.value) || 0 })}
                    className="w-full bg-[#090A0C] border border-[#2B2C30] rounded-lg p-2 text-[#F2F2F0]"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-[#A5A6AA] font-semibold">Feed / Source</label>
                  <input
                    type="text"
                    value={testIndicator.source}
                    onChange={(e) => setTestIndicator({ ...testIndicator, source: e.target.value })}
                    className="w-full bg-[#090A0C] border border-[#2B2C30] rounded-lg p-2 text-[#F2F2F0]"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-[#A5A6AA] font-semibold">Enrichment Verdict</label>
                  <input
                    type="text"
                    value={testIndicator.verdict}
                    onChange={(e) => setTestIndicator({ ...testIndicator, verdict: e.target.value })}
                    className="w-full bg-[#090A0C] border border-[#2B2C30] rounded-lg p-2 text-[#F2F2F0]"
                  />
                </div>
              </div>

              <button
                type="submit"
                className="w-full bg-[#F2F2F0] hover:bg-white text-[#090A0C] font-bold py-2 rounded-lg shadow-sm transition cursor-pointer"
              >
                Execute Dry-Run Evaluation
              </button>
            </form>

            {/* Test Results Output */}
            {testResult && (
              <div className="mt-4 p-4 rounded-lg bg-[#090A0C] border border-[#2B2C30] space-y-3 font-mono text-xs">
                <div className="flex items-center justify-between">
                  <span className="text-[#A5A6AA] font-semibold">Dry-Run Verdict:</span>
                  <span
                    className={`px-2 py-0.5 rounded font-bold ${
                      testResult.matched
                        ? "bg-[#17181B] text-red-400 border border-red-900/60"
                        : "bg-[#17181B] text-[#72747A] border border-[#2B2C30]"
                    }`}
                  >
                    {testResult.matched ? "RULE MATCHED (TRIGGERED)" : "NO MATCH"}
                  </span>
                </div>

                <div className="text-[11px] text-[#A5A6AA] space-y-1">
                  <div>
                    Evaluated Conditions:{" "}
                    <strong className="text-[#F2F2F0]">
                      {testResult.matched_conditions_count || 0} / {testResult.total_conditions || 0} passed
                    </strong>
                  </div>
                  <div>
                    Target Routing Destination:{" "}
                    <strong className="text-[#19D5E5]">{testResult.routing_destination || "N/A"}</strong>
                  </div>
                </div>

                {testResult.condition_details && (
                  <div className="space-y-1 pt-2 border-t border-[#2B2C30]">
                    <span className="text-[10px] uppercase text-[#72747A]">Condition Breakdown:</span>
                    {testResult.condition_details.map((c: any, i: number) => (
                      <div
                        key={i}
                        className={`flex items-center justify-between p-1.5 rounded text-[10px] ${
                          c.matched ? "bg-[#17181B] text-emerald-300 border border-emerald-900/40" : "bg-[#17181B] text-red-300 border border-red-900/40"
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
