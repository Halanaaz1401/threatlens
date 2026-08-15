"use client";

import React, { useState } from "react";
import { 
  AlertTriangle, 
  Clock, 
  ShieldAlert, 
  CheckSquare, 
  FileText, 
  CheckCircle2, 
  Link2, 
  ExternalLink,
  PlusCircle
} from "lucide-react";

export default function IncidentsDashboard() {
  const [tasks, setTasks] = useState([
    { id: 1, text: "Isolate affected host IP: 192.168.1.105", completed: true },
    { id: 2, text: "Block C2 domain: bad-actor-c2.net on DNS sinkhole", completed: true },
    { id: 3, text: "Extract and analyze process memory dump", completed: false },
    { id: 4, text: "Check internal logs for lateral movement sightings", completed: false },
    { id: 5, text: "Rotate compromised service account credentials", completed: false },
  ]);

  const [linkedEvents, setLinkedEvents] = useState([
    { id: "EVT-101", title: "C2 Outbound Beacon (185.220.101.4)", time: "16:15:38", severity: "CRITICAL" },
    { id: "EVT-102", title: "Suspicious PowerShell Execution (Invoke-Mimikatz)", time: "16:18:22", severity: "HIGH" },
    { id: "EVT-103", title: "Multiple Failed SMB Auth Spikes", time: "16:21:05", severity: "HIGH" },
  ]);

  const [newAlertInput, setNewAlertInput] = useState("");

  const toggleTask = (id: number) => {
    setTasks((prev) =>
      prev.map((t) => (t.id === id ? { ...t, completed: !t.completed } : t))
    );
  };

  const handleLinkEvent = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newAlertInput.trim()) return;
    const newEvent = {
      id: `EVT-${Math.floor(100 + Math.random() * 900)}`,
      title: newAlertInput.trim(),
      time: new Date().toLocaleTimeString(),
      severity: "HIGH",
    };
    setLinkedEvents((prev) => [newEvent, ...prev]);
    setNewAlertInput("");
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <AlertTriangle className="h-6 w-6 text-orange-500" />
            Incident Response Workspace
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            Persona: Daniel Okafor (IR Lead) — Active Investigation, Containment & Forensic Timeline
          </p>
        </div>

        <button
          onClick={() => alert("Incident IR Post-Mortem Report generated from audit trail.")}
          className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-orange-600 hover:bg-orange-500 text-xs font-mono font-medium text-white transition shadow-lg shadow-orange-600/20"
        >
          <FileText className="h-4 w-4" />
          Generate IR Report
        </button>
      </div>

      {/* Incident Header Card */}
      <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-xl">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-3">
              <span className="px-2.5 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/30 text-xs font-mono font-bold">
                SEV-1 CRITICAL
              </span>
              <h2 className="text-base font-bold text-white">INC-2026-0815: Suspected Ransomware Pre-Cursor Activity</h2>
            </div>
            <p className="text-xs text-slate-400 font-mono mt-1">
              Lead: <span className="text-slate-300">Daniel Okafor</span> | TLP: <span className="text-amber-400 font-bold">AMBER</span> | Linked Events: <span className="text-orange-400 font-bold">{linkedEvents.length}</span>
            </p>
          </div>
          <span className="px-3 py-1 bg-yellow-500/10 border border-yellow-500/30 text-yellow-400 rounded-full text-xs font-mono animate-pulse">
            Active Containment
          </span>
        </div>
      </div>

      {/* Dynamic Link Event Trigger Bar */}
      <form onSubmit={handleLinkEvent} className="flex gap-3 p-4 bg-slate-900/60 border border-slate-800 rounded-xl items-center">
        <Link2 className="h-4 w-4 text-orange-400 shrink-0" />
        <input
          type="text"
          value={newAlertInput}
          onChange={(e) => setNewAlertInput(e.target.value)}
          placeholder="Dynamic Event Trigger: Paste Alert ID or Ingestion Rule to link to this active incident..."
          className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-orange-500/50"
        />
        <button
          type="submit"
          className="px-3 py-1.5 bg-orange-600/20 hover:bg-orange-600/40 text-orange-300 border border-orange-500/40 rounded-lg text-xs font-mono transition flex items-center gap-1.5"
        >
          <PlusCircle className="h-3.5 w-3.5" />
          Link Event
        </button>
      </form>

      {/* Main IR Grid: Timeline & Containment + Linked Events */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Timeline */}
        <div className="lg:col-span-2 p-5 bg-slate-900/60 border border-slate-800 rounded-xl space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <span className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <Clock className="h-4 w-4 text-orange-400" />
              Chronological Incident Timeline (Immutable Audit)
            </span>
          </div>

          <div className="space-y-6 relative before:absolute before:inset-0 before:left-3.5 before:w-0.5 before:bg-slate-800 ml-2">
            <div className="relative flex items-start gap-4">
              <div className="w-7 h-7 rounded-full bg-red-500/20 border border-red-500 flex items-center justify-center shrink-0 z-10">
                <ShieldAlert className="h-3.5 w-3.5 text-red-400" />
              </div>
              <div>
                <div className="text-xs font-mono text-slate-400">16:15:38 IST — Ingestion Detection</div>
                <p className="text-sm text-slate-200 mt-0.5">High-severity match: Outbound beacon to C2 IP 185.220.101.4.</p>
              </div>
            </div>

            {linkedEvents.map((evt) => (
              <div key={evt.id} className="relative flex items-start gap-4">
                <div className="w-7 h-7 rounded-full bg-orange-500/20 border border-orange-500 flex items-center justify-center shrink-0 z-10">
                  <Link2 className="h-3.5 w-3.5 text-orange-400" />
                </div>
                <div>
                  <div className="text-xs font-mono text-slate-400">{evt.time} IST — Linked Alert [{evt.id}]</div>
                  <p className="text-sm text-slate-200 mt-0.5">{evt.title}</p>
                </div>
              </div>
            ))}

            <div className="relative flex items-start gap-4">
              <div className="w-7 h-7 rounded-full bg-emerald-500/20 border border-emerald-500 flex items-center justify-center shrink-0 z-10">
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
              </div>
              <div>
                <div className="text-xs font-mono text-slate-400">16:26:40 IST — Network Isolation</div>
                <p className="text-sm text-slate-200 mt-0.5">Host 192.168.1.105 quarantined at perimeter firewall.</p>
              </div>
            </div>
          </div>
        </div>

        {/* Containment Checklist */}
        <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-xl space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <span className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <CheckSquare className="h-4 w-4 text-emerald-400" />
              Containment Checklist
            </span>
          </div>

          <div className="space-y-3">
            {tasks.map((task) => (
              <div
                key={task.id}
                onClick={() => toggleTask(task.id)}
                className="flex items-start gap-3 p-2.5 rounded-lg bg-slate-800/40 hover:bg-slate-800/80 border border-slate-850 cursor-pointer transition"
              >
                <input
                  type="checkbox"
                  checked={task.completed}
                  onChange={() => {}}
                  className="mt-1 h-4 w-4 rounded border-slate-700 bg-slate-900 text-orange-500 focus:ring-0 cursor-pointer"
                />
                <span className={`text-xs font-mono leading-relaxed ${task.completed ? "line-through text-slate-500" : "text-slate-200"}`}>
                  {task.text}
                </span>
              </div>
            ))}
          </div>
        </div>

      </div>
    </div>
  );
}