"use client";

import React, { useState, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import { useAuth } from "@/context/RoleContext";

interface PresetCredential {
  label: string;
  role: string;
  email: string;
  badge: string;
}

const PRESET_CREDENTIALS: PresetCredential[] = [
  {
    label: "Administrator",
    role: "Full System Access & Governance",
    email: "admin_user@threatlens.io",
    badge: "ADMIN",
  },
  {
    label: "Security Engineer",
    role: "Detection Rules & Telemetry Feeds",
    email: "engineer_user@threatlens.io",
    badge: "ENGINEER",
  },
  {
    label: "SOC Analyst",
    role: "Alert Triage & Forensic Cases",
    email: "analyst_user@threatlens.io",
    badge: "ANALYST",
  },
  {
    label: "SOC Auditor / Viewer",
    role: "Read-Only Compliance & Dashboards",
    email: "viewer_user@threatlens.io",
    badge: "VIEWER",
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
    <div className="w-full max-w-md hatch-strip p-2 rounded-2xl border border-[#2B2C30]">
      <div className="bg-[#111214] border border-[#2B2C30] rounded-xl shadow-2xl p-6 sm:p-8 relative">
        
        {/* Brand Header */}
        <div className="text-center mb-7">
          <div className="inline-flex items-center justify-center w-10 h-10 rounded-lg bg-[#17181B] border border-[#2B2C30] text-[#F2F2F0] text-sm font-mono font-bold mb-3 shadow-inner">
            TL
          </div>
          <h1 className="text-xl sm:text-2xl font-normal tracking-tight text-[#F2F2F0]">
            <span className="font-editorial-sans font-bold">Sign In to </span>
            <span className="font-editorial-serif text-slate-300 italic">ThreatLens</span>
          </h1>
          <p className="text-[11px] text-[#72747A] font-mono mt-1">
            Cyber Threat Intelligence &bull; Security Operations Gateway
          </p>
        </div>

        {/* Error Alert */}
        {errorMessage && (
          <div
            id="login-error-banner"
            className="mb-5 p-3 rounded-lg bg-[#17181B] border border-red-500/50 text-red-400 text-xs flex items-center gap-2 font-mono"
          >
            <span>&bull;</span>
            <span>{errorMessage}</span>
          </div>
        )}

        {/* Authenticated banner if already logged in */}
        {isAuthenticated && (
          <div className="mb-5 p-3 rounded-lg bg-[#17181B] border border-[#2B2C30] text-[#A5A6AA] text-xs flex items-center justify-between font-mono">
            <span>Active authenticated session.</span>
            <Link href="/" className="text-[#19D5E5] font-semibold underline">
              Console &rarr;
            </Link>
          </div>
        )}

        {/* Login Form */}
        <form onSubmit={handleLoginSubmit} className="space-y-4">
          <div>
            <label className="block text-[11px] font-mono text-[#A5A6AA] mb-1.5 uppercase tracking-wider">
              Operator Email / Identity
            </label>
            <input
              id="login-email-input"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="analyst@threatlens.io"
              required
              className="w-full bg-[#090A0C] border border-[#2B2C30] rounded-lg px-3.5 py-2.5 text-xs text-[#F2F2F0] placeholder-[#72747A] focus:outline-none focus:border-[#19D5E5] transition font-mono"
            />
          </div>

          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label
                className="text-[11px] font-mono text-[#A5A6AA] uppercase tracking-wider"
                htmlFor="login-password-input"
              >
                Access Password
              </label>
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="text-[10px] text-[#A5A6AA] hover:text-[#F2F2F0] font-mono transition"
              >
                {showPassword ? "HIDE" : "SHOW"}
              </button>
            </div>
            <input
              id="login-password-input"
              type={showPassword ? "text" : "password"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
              required
              className="w-full bg-[#090A0C] border border-[#2B2C30] rounded-lg px-3.5 py-2.5 text-xs text-[#F2F2F0] placeholder-[#72747A] focus:outline-none focus:border-[#19D5E5] transition font-mono"
            />
          </div>

          <button
            id="login-submit-button"
            type="submit"
            disabled={loading}
            className="w-full mt-2 py-3 px-4 rounded-lg font-semibold text-xs text-[#090A0C] bg-[#F2F2F0] hover:bg-white transition disabled:opacity-50 flex items-center justify-center gap-2 cursor-pointer shadow-sm"
          >
            {loading ? (
              <span>Authenticating Gateway...</span>
            ) : (
              <>
                <span>Sign In to Console</span>
                <span className="text-sm font-bold">&rarr;</span>
              </>
            )}
          </button>
        </form>

        {/* Quick Role Fill Testing Section */}
        <div className="mt-7 pt-5 border-t border-[#202125]">
          <div className="flex items-center justify-between mb-2.5">
            <span className="text-[10px] font-mono font-medium text-[#72747A] uppercase tracking-wider">
              Quick Role Accounts
            </span>
            <span className="text-[10px] text-[#72747A] font-mono">
              Pass: RoleTestPass!123
            </span>
          </div>

          <div className="grid grid-cols-2 gap-2">
            {PRESET_CREDENTIALS.map((preset) => (
              <button
                key={preset.label}
                type="button"
                onClick={() => handleSelectPreset(preset)}
                className="p-2 rounded-lg bg-[#17181B] hover:bg-[#202125] border border-[#2B2C30] hover:border-[#3F4046] text-left transition text-xs flex flex-col gap-0.5 cursor-pointer"
              >
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-semibold text-[#F2F2F0] truncate">
                    {preset.label}
                  </span>
                  <span className="text-[9px] font-mono text-[#A5A6AA]">
                    {preset.badge}
                  </span>
                </div>
                <span className="text-[9px] text-[#72747A] truncate font-mono">
                  {preset.role}
                </span>
              </button>
            ))}
          </div>
        </div>

        {/* Footer */}
        <div className="mt-5 text-center text-[10px] font-mono text-[#72747A]">
          <span>Enterprise Token Revocation &bull; RBAC Server Enforced</span>
        </div>

      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <div className="min-h-[82vh] flex items-center justify-center px-4 py-8">
      <Suspense fallback={<div className="text-xs text-[#72747A] font-mono">Loading authentication portal...</div>}>
        <LoginForm />
      </Suspense>
    </div>
  );
}
