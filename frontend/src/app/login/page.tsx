"use client";

import React, { useState, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import { useAuth } from "@/context/RoleContext";

interface PresetCredential {
  label: string;
  role: string;
  email: string;
  color: string;
  icon: string;
}

const PRESET_CREDENTIALS: PresetCredential[] = [
  {
    label: "Administrator",
    role: "Full System Access & Governance",
    email: "admin_user@threatlens.io",
    color: "border-red-500/50 text-red-400 bg-red-950/30 hover:border-red-400",
    icon: "🛡️",
  },
  {
    label: "Security Engineer",
    role: "Detection Rules, Feeds & Ingestion",
    email: "engineer_user@threatlens.io",
    color: "border-blue-500/50 text-blue-400 bg-blue-950/30 hover:border-blue-400",
    icon: "🔧",
  },
  {
    label: "SOC Analyst",
    role: "Alert Triage, IOC Enrichment & Cases",
    email: "analyst_user@threatlens.io",
    color: "border-cyan-500/50 text-cyan-400 bg-cyan-950/30 hover:border-cyan-400",
    icon: "🔍",
  },
  {
    label: "SOC Auditor / Viewer",
    role: "Read-Only Compliance & Dashboards",
    email: "viewer_user@threatlens.io",
    color: "border-slate-500/50 text-slate-300 bg-slate-900/30 hover:border-slate-400",
    icon: "👁️",
  },
];

function LoginForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const redirectPath = searchParams ? searchParams.get("redirect") || "/" : "/";
  const { login, isAuthenticated } = useAuth();

  const [email, setEmail] = useState("admin_user@threatlens.io");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim() || !password.trim()) {
      setErrorMessage("Please enter both email and password.");
      return;
    }

    setLoading(true);
    setErrorMessage(null);

    const result = await login(email.trim(), password.trim());
    if (result.success) {
      router.push(redirectPath);
    } else {
      setErrorMessage(result.error || "Invalid email or password.");
      setLoading(false);
    }
  };

  const handleSelectPreset = (preset: PresetCredential) => {
    setEmail(preset.email);
    setPassword("RoleTestPass!123");
    setErrorMessage(null);
  };

  return (
    <div className="w-full max-w-md bg-[#0d1527]/95 border border-slate-800 rounded-2xl shadow-2xl p-6 sm:p-8 backdrop-blur relative overflow-hidden">
      
      {/* Glow accent */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-48 h-1 bg-gradient-to-r from-transparent via-cyan-500 to-transparent" />

      {/* Brand Header */}
      <div className="text-center mb-8">
        <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-cyan-950/80 border border-cyan-500/50 text-cyan-400 text-2xl font-bold shadow-lg shadow-cyan-950/50 mb-3">
          🛡️
        </div>
        <h1 className="text-2xl font-black tracking-widest text-white uppercase">
          THREATLENS <span className="text-cyan-400 text-sm font-mono font-semibold">SOC</span>
        </h1>
        <p className="text-xs text-slate-400 mt-1 font-medium">
          Cyber Threat Intelligence &amp; Incident Correlation Platform
        </p>
      </div>

      {/* Error Alert */}
      {errorMessage && (
        <div id="login-error-banner" className="mb-6 p-3 rounded-lg bg-red-950/60 border border-red-500/60 text-red-300 text-xs flex items-center gap-2">
          <span className="text-base">⚠️</span>
          <span>{errorMessage}</span>
        </div>
      )}

      {/* Authenticated info banner if already logged in */}
      {isAuthenticated && (
        <div className="mb-6 p-3 rounded-lg bg-cyan-950/60 border border-cyan-500/60 text-cyan-300 text-xs flex items-center justify-between">
          <span>You are currently authenticated.</span>
          <Link href="/" className="font-bold underline hover:text-white">
            Go to Console &rarr;
          </Link>
        </div>
      )}

      {/* Login Form */}
      <form onSubmit={handleLoginSubmit} className="space-y-4">
        <div>
          <label className="block text-xs font-semibold text-slate-300 mb-1.5">
            Operator Email / Identity
          </label>
          <div className="relative">
            <span className="absolute inset-y-0 left-0 flex items-center pl-3 text-slate-500 text-sm">
              📧
            </span>
            <input
              id="login-email-input"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="analyst@threatlens.io"
              required
              className="w-full bg-[#080d1a] border border-slate-700/80 rounded-xl pl-9 pr-3 py-2.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition"
            />
          </div>
        </div>

        <div>
          <div className="flex items-center justify-between mb-1.5">
            <label className="text-xs font-semibold text-slate-300" htmlFor="login-password-input">
              Access Password
            </label>
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="text-[11px] text-cyan-400 hover:text-cyan-300 transition"
            >
              {showPassword ? "Hide" : "Show"}
            </button>
          </div>
          <div className="relative">
            <span className="absolute inset-y-0 left-0 flex items-center pl-3 text-slate-500 text-sm">
              🔒
            </span>
            <input
              id="login-password-input"
              type={showPassword ? "text" : "password"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
              required
              className="w-full bg-[#080d1a] border border-slate-700/80 rounded-xl pl-9 pr-3 py-2.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition font-mono"
            />
          </div>
        </div>

        <button
          id="login-submit-button"
          type="submit"
          disabled={loading}
          className="w-full mt-2 py-3 px-4 rounded-xl font-bold text-xs uppercase tracking-wider text-black bg-gradient-to-r from-cyan-400 to-teal-400 hover:from-cyan-300 hover:to-teal-300 shadow-lg shadow-cyan-950/60 focus:outline-none focus:ring-2 focus:ring-cyan-500 transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 cursor-pointer"
        >
          {loading ? (
            <>
              <span className="w-4 h-4 border-2 border-slate-900 border-t-transparent rounded-full animate-spin" />
              <span>Authenticating with SOC Gateway...</span>
            </>
          ) : (
            <>
              <span>🔐</span>
              <span>Sign In to SOC Console</span>
            </>
          )}
        </button>
      </form>

      {/* Quick Role Fill Testing Section */}
      <div className="mt-8 pt-6 border-t border-slate-800">
        <div className="flex items-center justify-between mb-3">
          <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">
            Quick Role Testing Accounts
          </span>
          <span className="text-[10px] text-slate-500 font-mono">
            Pass: RoleTestPass!123
          </span>
        </div>

        <div className="grid grid-cols-2 gap-2">
          {PRESET_CREDENTIALS.map((preset) => (
            <button
              key={preset.label}
              type="button"
              onClick={() => handleSelectPreset(preset)}
              className={`p-2.5 rounded-xl border text-left transition text-xs flex flex-col gap-0.5 cursor-pointer ${preset.color}`}
            >
              <div className="flex items-center gap-1.5 font-bold">
                <span>{preset.icon}</span>
                <span className="truncate">{preset.label}</span>
              </div>
              <span className="text-[10px] text-slate-400 truncate">
                {preset.role}
              </span>
            </button>
          ))}
        </div>
      </div>

      {/* Footer */}
      <div className="mt-6 text-center text-[11px] text-slate-500">
        <span>Enterprise Token Revocation &amp; RBAC Server Enforced</span>
      </div>

    </div>
  );
}

export default function LoginPage() {
  return (
    <div className="min-h-[85vh] flex items-center justify-center px-4 py-8">
      <Suspense fallback={<div className="text-xs text-slate-500 font-mono">Loading authentication portal...</div>}>
        <LoginForm />
      </Suspense>
    </div>
  );
}
