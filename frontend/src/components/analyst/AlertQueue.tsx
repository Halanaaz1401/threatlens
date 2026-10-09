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
  alerts?: AlertItem[];
  onSelectAlert?: (alert: AlertItem) => void;
}

export function AlertQueue({ currentRole, alerts: propAlerts, onSelectAlert }: AlertQueueProps) {
  const [internalAlerts, setInternalAlerts] = useState<AlertItem[]>([]);
  const alerts = propAlerts !== undefined ? propAlerts : internalAlerts;
  const canTriage = hasPermission(currentRole, "triage_alerts");

  const handleStatusChange = (id: string, newStatus: AlertItem["status"]) => {
    setInternalAlerts((prev) =>
      prev.map((alert) => (alert.id === id ? { ...alert, status: newStatus } : alert))
    );
  };

  const getSeverityBadge = (sev: AlertItem["severity"]) => {
    switch (sev) {
      case "CRITICAL":
        return "bg-[#17181B] text-red-400 border-red-900/60";
      case "HIGH":
        return "bg-[#17181B] text-amber-400 border-amber-900/60";
      case "MEDIUM":
        return "bg-[#17181B] text-yellow-400 border-yellow-900/60";
      default:
        return "bg-[#17181B] text-[#A5A6AA] border-[#2B2C30]";
    }
  };

  return (
    <div className="rounded-xl border border-[#2B2C30] bg-[#111214] p-5 shadow-sm">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-sm font-semibold text-[#F2F2F0] font-mono">Live SOC Triage Queue</h3>
          <p className="text-xs text-[#A5A6AA]">Prioritized alert stream with role-based actions</p>
        </div>
        <span className="inline-flex items-center rounded bg-[#17181B] px-2.5 py-1 text-xs font-mono font-medium text-[#19D5E5] border border-[#2B2C30]">
          ● WebSocket Sync Active
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead>
            <tr className="border-b border-[#2B2C30] text-[#72747A] font-mono uppercase text-[10px]">
              <th className="pb-3 font-medium">SEVERITY</th>
              <th className="pb-3 font-medium">ALERT / THREAT TITLE</th>
              <th className="pb-3 font-medium">INDICATOR (IOC)</th>
              <th className="pb-3 font-medium">SOURCE</th>
              <th className="pb-3 font-medium">TIME</th>
              <th className="pb-3 font-medium text-right">TRIAGE ACTION</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#2B2C30]">
            {alerts.map((alert) => (
              <tr 
                key={alert.id} 
                className="hover:bg-[#17181B] cursor-pointer transition-colors"
                onClick={() => onSelectAlert?.(alert)}
              >
                <td className="py-3">
                  <span className={`inline-flex items-center rounded px-2 py-0.5 text-[10px] font-bold border ${getSeverityBadge(alert.severity)}`}>
                    {alert.severity}
                  </span>
                </td>
                <td className="py-3 font-medium text-[#F2F2F0]">{alert.title}</td>
                <td className="py-3 font-mono text-[#19D5E5] truncate max-w-[180px]">{alert.indicator}</td>
                <td className="py-3 text-[#A5A6AA]">{alert.source}</td>
                <td className="py-3 text-[#72747A] font-mono">{alert.timestamp}</td>
                <td className="py-3 text-right" onClick={(e) => e.stopPropagation()}>
                  <select
                    disabled={!canTriage}
                    value={alert.status}
                    onChange={(e) => handleStatusChange(alert.id, e.target.value as AlertItem["status"])}
                    className="bg-[#090A0C] border border-[#2B2C30] text-xs rounded px-2 py-1 text-[#F2F2F0] outline-none focus:border-[#19D5E5] disabled:opacity-40 disabled:cursor-not-allowed"
                  >
                    <option value="NEW" className="bg-[#111214]">New</option>
                    <option value="ACKNOWLEDGED" className="bg-[#111214]">Acknowledge</option>
                    <option value="ASSIGNED" className="bg-[#111214]">Assign to Me</option>
                    <option value="ESCALATED_IR" className="bg-[#111214]">Escalate to IR</option>
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

export default AlertQueue;