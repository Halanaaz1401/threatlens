"use client";

import React, { useState, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import { useAuth } from "@/context/RoleContext";
import { Shield, Mail, Lock, Eye, EyeOff, ArrowRight, CheckCircle2, AlertCircle } from "lucide-react";

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
    <div className="w-full max-w-md hatch-strip p-2 sm:p-2.5 rounded-2xl border border-[#2B2C30]">
      <div className="bg-[#111214] border border-[#2B2C30] rounded-xl shadow-2xl p-6 sm:p-8 relative">
        
        {/* Brand Header */}
        <div className="text-center mb-6">
          <div className="inline-flex items-center justify-center w-10 h-10 rounded-lg bg-[#17181B] border border-[#2B2C30] text-[#F2F2F0] text-sm font-mono font-bold mb-3 shadow-inner">
            TL
          </div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-[#F2F2F0]">
            Sign In to ThreatLens
          </h1>
          <p className="text-xs text-[#85858B] font-mono mt-1">
            Cyber Threat Intelligence &bull; Security Operations Gateway
          </p>
        </div>

        {/* Error Alert */}
        {errorMessage && (
          <div
            id="login-error-banner"
            className="mb-5 p-3 rounded-lg bg-[#17181B] border border-red-500/60 text-red-400 text-xs flex items-center gap-2 font-mono"
            role="alert"
          >
            <AlertCircle className="w-4 h-4 shrink-0 text-red-400" />
            <span>{errorMessage}</span>
          </div>
        )}

        {/* Authenticated banner if already logged in */}
        {isAuthenticated && (
          <div className="mb-5 p-3 rounded-lg bg-[#17181B] border border-[#2B2C30] text-[#B0B0B4] text-xs flex items-center justify-between font-mono">
            <span className="flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 text-[#22C55E]" />
              Active authenticated session.
            </span>
            <Link href="/" className="text-[#19D5E5] font-semibold underline flex items-center gap-1">
              <span>Console</span>
              <ArrowRight className="w-3 h-3" />
            </Link>
          </div>
        )}

        {/* Login Form */}
        <form onSubmit={handleLoginSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-mono text-[#B0B0B4] mb-1.5 uppercase tracking-wider">
              Operator Email / Identity
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[#85858B]">
                <Mail className="w-4 h-4" />
              </div>
              <input
                id="login-email-input"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@threatlens.io"
                required
                className="w-full bg-[#090A0C] border border-[#2B2C30] rounded-lg pl-9 pr-3.5 py-2.5 text-xs text-[#F2F2F0] placeholder-[#85858B] focus:outline-none focus:border-[#19D5E5] transition font-mono"
              />
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label
                className="text-xs font-mono text-[#B0B0B4] uppercase tracking-wider"
                htmlFor="login-password-input"
              >
                Access Password
              </label>
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="text-[11px] text-[#85858B] hover:text-[#F2F2F0] font-mono transition flex items-center gap-1 cursor-pointer"
                aria-label={showPassword ? "Hide password" : "Show password"}
              >
                {showPassword ? (
                  <>
                    <EyeOff className="w-3 h-3" />
                    <span>HIDE</span>
                  </>
                ) : (
                  <>
                    <Eye className="w-3 h-3" />
                    <span>SHOW</span>
                  </>
                )}
              </button>
            </div>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[#85858B]">
                <Lock className="w-4 h-4" />
              </div>
              <input
                id="login-password-input"
                type={showPassword ? "text" : "password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                required
                className="w-full bg-[#090A0C] border border-[#2B2C30] rounded-lg pl-9 pr-3.5 py-2.5 text-xs text-[#F2F2F0] placeholder-[#85858B] focus:outline-none focus:border-[#19D5E5] transition font-mono"
              />
            </div>
          </div>

          <button
            id="login-submit-button"
            type="submit"
            disabled={loading}
            className="w-full mt-2 py-3 px-4 rounded-lg font-semibold text-xs text-[#090A0C] bg-[#F2F2F0] hover:bg-white transition disabled:opacity-50 flex items-center justify-center gap-2 cursor-pointer shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#19D5E5]"
          >
            {loading ? (
              <span>Authenticating Gateway...</span>
            ) : (
              <>
                <span>Sign In to Console</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </>
            )}
          </button>
        </form>

        {/* Quick Role Fill Testing Section */}
        <div className="mt-7 pt-5 border-t border-[#202125]">
          <div className="flex items-center justify-between mb-2.5">
            <span className="text-[10px] font-mono font-medium text-[#85858B] uppercase tracking-wider">
              Quick Role Accounts
            </span>
            <span className="text-[10px] text-[#85858B] font-mono">
              Pass: RoleTestPass!123
            </span>
          </div>

          <div className="grid grid-cols-2 gap-2">
            {PRESET_CREDENTIALS.map((preset) => (
              <button
                key={preset.label}
                type="button"
                onClick={() => handleSelectPreset(preset)}
                className="p-2 rounded-lg bg-[#17181B] hover:bg-[#202125] border border-[#2B2C30] hover:border-[#42434A] text-left transition text-xs flex flex-col gap-0.5 cursor-pointer focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[#19D5E5]"
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-[#F2F2F0] truncate">
                    {preset.label}
                  </span>
                  <span className="text-[9px] font-mono text-[#B0B0B4]">
                    {preset.badge}
                  </span>
                </div>
                <span className="text-[10px] text-[#85858B] truncate font-mono">
                  {preset.role}
                </span>
              </button>
            ))}
          </div>
        </div>

        {/* Footer */}
        <div className="mt-5 text-center text-[10px] font-mono text-[#85858B]">
          <span>Enterprise Token Revocation &bull; RBAC Server Enforced</span>
        </div>

      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <div className="min-h-[82vh] flex items-center justify-center px-4 py-8">
      <Suspense fallback={<div className="text-xs text-[#85858B] font-mono">Loading authentication portal...</div>}>
        <LoginForm />
      </Suspense>
    </div>
  );
}
