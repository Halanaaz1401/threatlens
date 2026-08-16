"use client";

import React, { useState } from "react";
import { hasPermission, Role } from "@/lib/rbac";

export interface AlertItem {
  id: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  title: string;
  indicator: string;
  type: string;
  source: string;
  timestamp: string;
  status: "NEW" | "ACKNOWLEDGED" | "ASSIGNED" | "ESCALATED_IR";
}

interface AlertQueueProps {
  currentRole: Role;
  onSelectAlert?: (alert: AlertItem) => void;
}

const mockAlerts: AlertItem[] = [
  {
    id: "ALT-9042",
    severity: "CRITICAL",
    title: "Cobalt Strike C2 Beaconing Detected",
    indicator: "185.220.101.5",
    type: "IPv4",
    source: "AbuseIPDB",
    timestamp: "2 mins ago",
    status: "NEW",
  },
  {
    id: "ALT-9041",
    severity: "HIGH",
    title: "Malicious Hash Match (Lumma Stealer)",
    indicator: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    type: "SHA256",
    source: "URLhaus",
    timestamp: "12 mins ago",
    status: "ACKNOWLEDGED",
  },
  {
    id: "ALT-9039",
    severity: "MEDIUM",
    title: "Suspicious Dynamic DNS Query Pattern",
    indicator: "update-win-telemetry.ddns.net",
    type: "Domain",
    source: "AlienVault OTX",
    timestamp: "34 mins ago",
    status: "NEW",
  },
];

export function AlertQueue({ currentRole, onSelectAlert }: AlertQueueProps) {
  const [alerts, setAlerts] = useState<AlertItem[]>(mockAlerts);
  const canTriage = hasPermission(currentRole, "triage_alerts");

  const handleStatusChange = (id: string, newStatus: AlertItem["status"]) => {
    setAlerts((prev) =>
      prev.map((alert) => (alert.id === id ? { ...alert, status: newStatus } : alert))
    );
  };

  const getSeverityBadge = (sev: AlertItem["severity"]) => {
    switch (sev) {
      case "CRITICAL":
        return "bg-rose-500/10 text-rose-400 border-rose-500/30";
      case "HIGH":
        return "bg-amber-500/10 text-amber-400 border-amber-500/30";
      case "MEDIUM":
        return "bg-yellow-500/10 text-yellow-400 border-yellow-500/30";
      default:
        return "bg-slate-500/10 text-slate-400 border-slate-500/30";
    }
  };

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-5 backdrop-blur-md">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-sm font-semibold text-slate-100">Live SOC Triage Queue</h3>
          <p className="text-xs text-slate-400">Prioritized alert stream with role-based actions</p>
        </div>
        <span className="inline-flex items-center rounded-md bg-cyan-500/10 px-2.5 py-1 text-xs font-mono font-medium text-cyan-400 border border-cyan-500/20">
          ● WebSocket Sync Active
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead>
            <tr className="border-b border-slate-800 text-slate-400">
              <th className="pb-3 font-medium">SEVERITY</th>
              <th className="pb-3 font-medium">ALERT / THREAT TITLE</th>
              <th className="pb-3 font-medium">INDICATOR (IOC)</th>
              <th className="pb-3 font-medium">SOURCE</th>
              <th className="pb-3 font-medium">TIME</th>
              <th className="pb-3 font-medium text-right">TRIAGE ACTION</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {alerts.map((alert) => (
              <tr 
                key={alert.id} 
                className="hover:bg-slate-900/50 cursor-pointer transition-colors"
                onClick={() => onSelectAlert?.(alert)}
              >
                <td className="py-3">
                  <span className={`inline-flex items-center rounded px-2 py-0.5 text-[10px] font-bold border ${getSeverityBadge(alert.severity)}`}>
                    {alert.severity}
                  </span>
                </td>
                <td className="py-3 font-medium text-slate-200">{alert.title}</td>
                <td className="py-3 font-mono text-cyan-300 truncate max-w-[180px]">{alert.indicator}</td>
                <td className="py-3 text-slate-400">{alert.source}</td>
                <td className="py-3 text-slate-500">{alert.timestamp}</td>
                <td className="py-3 text-right" onClick={(e) => e.stopPropagation()}>
                  <select
                    disabled={!canTriage}
                    value={alert.status}
                    onChange={(e) => handleStatusChange(alert.id, e.target.value as AlertItem["status"])}
                    className="bg-slate-900 border border-slate-700 text-xs rounded px-2 py-1 text-slate-200 outline-none focus:border-cyan-500 disabled:opacity-40 disabled:cursor-not-allowed"
                  >
                    <option value="NEW">New</option>
                    <option value="ACKNOWLEDGED">Acknowledge</option>
                    <option value="ASSIGNED">Assign to Me</option>
                    <option value="ESCALATED_IR">Escalate to IR</option>
                  </select>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}