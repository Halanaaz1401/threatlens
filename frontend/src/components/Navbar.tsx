"use client";

import React, { useState, useEffect, useRef } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useAuth, UserRole, PERSONA_CONFIG } from "@/context/RoleContext";

interface NavLinkItem {
  label: string;
  href: string;
  icon: string;
  adminOnly?: boolean;
}

const PRIMARY_NAV_ITEMS: NavLinkItem[] = [
  { label: "Home", href: "/", icon: "🏠" },
  { label: "Analyst", href: "/dashboard/analyst", icon: "🛡️" },
  { label: "Incidents", href: "/dashboard/incidents", icon: "⚠️" },
  { label: "Hunting", href: "/dashboard/hunting", icon: "🎯" },
  { label: "Cases", href: "/dashboard/cases", icon: "📁" },
];

const SECONDARY_NAV_ITEMS: NavLinkItem[] = [
  { label: "Executive View", href: "/dashboard/executive", icon: "📈" },
  { label: "Dashboards", href: "/dashboard/builder", icon: "📊" },
  { label: "Feeds & Telemetry", href: "/dashboard/feeds", icon: "📡" },
  { label: "Admin Feeds", href: "/dashboard/admin/feeds", icon: "⚙️", adminOnly: true },
];

export function Navbar() {
  const pathname = usePathname();
  const router = useRouter();
  const { user, role, serverRole, setRole, isAuthenticated, logout } = useAuth();

  const [searchVal, setSearchVal] = useState("");
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [moreMenuOpen, setMoreMenuOpen] = useState(false);
  const [accountMenuOpen, setAccountMenuOpen] = useState(false);

  const moreMenuRef = useRef<HTMLDivElement>(null);
  const accountMenuRef = useRef<HTMLDivElement>(null);
  const mobileMenuRef = useRef<HTMLDivElement>(null);

  // Close menus on click outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (moreMenuRef.current && !moreMenuRef.current.contains(event.target as Node)) {
        setMoreMenuOpen(false);
      }
      if (accountMenuRef.current && !accountMenuRef.current.contains(event.target as Node)) {
        setAccountMenuOpen(false);
      }
      if (mobileMenuRef.current && !mobileMenuRef.current.contains(event.target as Node)) {
        // Only if clicked outside mobile drawer
        const toggleBtn = document.getElementById("mobile-menu-toggle-btn");
        if (toggleBtn && !toggleBtn.contains(event.target as Node)) {
          setMobileMenuOpen(false);
        }
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  // Close menus on Escape key
  useEffect(() => {
    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        setMoreMenuOpen(false);
        setAccountMenuOpen(false);
        setMobileMenuOpen(false);
      }
    }
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, []);

  // Close mobile menu on route change
  useEffect(() => {
    setMobileMenuOpen(false);
    setMoreMenuOpen(false);
    setAccountMenuOpen(false);
  }, [pathname]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchVal.trim()) {
      router.push(`/dashboard/hunting?q=${encodeURIComponent(searchVal.trim())}`);
      setMobileMenuOpen(false);
    }
  };

  const isAdmin = serverRole === "admin" || role === "Administrator";
  const visibleSecondaryItems = SECONDARY_NAV_ITEMS.filter((item) => !item.adminOnly || isAdmin);
  const allNavItems = [...PRIMARY_NAV_ITEMS, ...visibleSecondaryItems];

  // Helper for role badge colors
  const getRoleBadgeStyle = (userRoleStr: string) => {
    const norm = userRoleStr.toLowerCase();
    if (norm.includes("admin")) return "text-red-400 bg-red-950/60 border-red-800";
    if (norm.includes("engineer")) return "text-blue-400 bg-blue-950/60 border-blue-800";
    if (norm.includes("analyst") || norm.includes("hunter") || norm.includes("incident"))
      return "text-cyan-400 bg-cyan-950/60 border-cyan-800";
    return "text-emerald-400 bg-emerald-950/60 border-emerald-800";
  };

  return (
    <header className="w-full bg-[#080d1a]/95 backdrop-blur border-b border-slate-800/90 px-3 sm:px-6 py-2.5 sticky top-0 z-50 shadow-md">
      <div className="max-w-7xl mx-auto flex items-center justify-between gap-2 sm:gap-4">
        
        {/* Left: Brand + Search */}
        <div className="flex items-center gap-3 sm:gap-4 shrink-0">
          <Link href="/" className="flex items-center gap-2.5 group shrink-0">
            <span className="w-8 h-8 rounded-lg bg-red-950/80 border border-red-500/70 flex items-center justify-center text-red-400 text-xs font-bold shadow-lg shadow-red-950/50 group-hover:border-red-400 transition">
              ((o))
            </span>
            <div className="flex flex-col">
              <div className="flex items-center gap-1.5">
                <span className="font-black tracking-wider text-slate-100 text-sm sm:text-base group-hover:text-white transition">
                  THREATLENS
                </span>
                <span className="text-[10px] bg-slate-800 text-cyan-400 px-1.5 py-0.2 rounded font-mono font-semibold border border-slate-700 hidden xs:inline">
                  SOC
                </span>
              </div>
              <span className="text-[10px] text-slate-400 font-medium hidden sm:inline">
                Enterprise CTI Platform
              </span>
            </div>
          </Link>

          {/* Quick Search Box (Desktop) */}
          <form onSubmit={handleSearchSubmit} className="relative hidden xl:block w-48 2xl:w-60">
            <button
              type="submit"
              className="absolute inset-y-0 left-0 flex items-center pl-2.5 text-slate-500 hover:text-cyan-400 text-xs transition"
              title="Search threat intelligence"
            >
              🔍
            </button>
            <input
              type="text"
              value={searchVal}
              onChange={(e) => setSearchVal(e.target.value)}
              placeholder="Search IOC, CVE, ATT&CK..."
              className="w-full bg-[#0d1527] border border-slate-800 rounded-lg pl-7 pr-2.5 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition"
            />
          </form>
        </div>

        {/* Center: Desktop Navigation Bar (Large screens) */}
        <nav className="hidden lg:flex items-center gap-1 bg-[#0d1527]/80 border border-slate-800/80 p-1 rounded-xl shrink-0" aria-label="Main Navigation">
          {PRIMARY_NAV_ITEMS.map((item) => {
            const isActive = pathname === item.href;
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                  isActive
                    ? "bg-cyan-950/80 text-cyan-300 border border-cyan-700/80 shadow-sm shadow-cyan-950/50"
                    : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
                }`}
              >
                <span className="text-xs">{item.icon}</span>
                <span>{item.label}</span>
              </Link>
            );
          })}

          {/* More Menu Dropdown */}
          <div className="relative" ref={moreMenuRef}>
            <button
              type="button"
              onClick={() => setMoreMenuOpen(!moreMenuOpen)}
              className={`flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-semibold transition cursor-pointer ${
                moreMenuOpen || visibleSecondaryItems.some((i) => pathname === i.href)
                  ? "bg-slate-800 text-cyan-300"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
              }`}
              aria-expanded={moreMenuOpen}
              aria-haspopup="true"
            >
              <span>More</span>
              <span className="text-[10px]">▼</span>
            </button>

            {moreMenuOpen && (
              <div className="absolute left-0 mt-2 w-48 bg-[#0d1527] border border-slate-800 rounded-xl shadow-2xl py-1.5 z-50 animate-fadeIn">
                {visibleSecondaryItems.map((item) => {
                  const isActive = pathname === item.href;
                  return (
                    <Link
                      key={item.href}
                      href={item.href}
                      className={`flex items-center gap-2 px-3 py-2 text-xs font-semibold transition ${
                        isActive
                          ? "bg-cyan-950/80 text-cyan-300"
                          : "text-slate-300 hover:bg-slate-800 hover:text-white"
                      }`}
                      onClick={() => setMoreMenuOpen(false)}
                    >
                      <span>{item.icon}</span>
                      <span>{item.label}</span>
                    </Link>
                  );
                })}
              </div>
            )}
          </div>
        </nav>

        {/* Right: Telemetry Live Status + User Identity / Login + Hamburger */}
        <div className="flex items-center gap-2 sm:gap-3 shrink-0">
          
          {/* Live Stream Telemetry Badge */}
          <div className="hidden sm:flex items-center gap-1.5 bg-emerald-950/60 border border-emerald-800/60 px-2.5 py-1 rounded-lg text-[11px] font-bold text-emerald-400 shrink-0">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            <span className="font-mono">LIVE</span>
          </div>

          {/* User Account / Session Area */}
          {isAuthenticated ? (
            <div className="relative" ref={accountMenuRef}>
              <button
                id="header-account-menu-btn"
                type="button"
                onClick={() => setAccountMenuOpen(!accountMenuOpen)}
                className="flex items-center gap-2 bg-[#0d1527] border border-slate-700/80 hover:border-cyan-500/80 px-2.5 py-1.5 rounded-lg text-xs transition cursor-pointer"
                aria-expanded={accountMenuOpen}
                aria-haspopup="true"
                aria-label="User account menu"
              >
                <div className="w-6 h-6 rounded-full bg-cyan-950 border border-cyan-500/60 flex items-center justify-center text-cyan-300 text-xs font-bold">
                  {user?.full_name ? user.full_name.charAt(0).toUpperCase() : user?.email ? user.email.charAt(0).toUpperCase() : "U"}
                </div>
                <div className="hidden md:flex flex-col text-left">
                  <span className="text-[11px] font-bold text-slate-200 leading-tight truncate max-w-[110px]">
                    {user?.full_name || user?.email?.split("@")[0] || "Operator"}
                  </span>
                  <span id="header-user-role-badge" className="text-[9px] text-cyan-400 font-mono uppercase leading-tight truncate max-w-[110px]">
                    {serverRole || role}
                  </span>
                </div>
                <span className="text-[10px] text-slate-400 ml-0.5">▼</span>
              </button>

              {/* Account Dropdown */}
              {accountMenuOpen && (
                <div className="absolute right-0 mt-2 w-64 bg-[#0d1527] border border-slate-800 rounded-xl shadow-2xl p-3 z-50 animate-fadeIn text-xs">
                  {/* User Profile Summary */}
                  <div className="pb-3 border-b border-slate-800 mb-3">
                    <div className="font-bold text-slate-100 truncate text-sm">
                      {user?.full_name || user?.email || "Security Operator"}
                    </div>
                    <div className="text-[11px] text-slate-400 truncate mt-0.5">
                      {user?.email}
                    </div>
                    <div className="mt-2 flex items-center gap-1.5">
                      <span className={`text-[10px] px-2 py-0.5 rounded border font-mono font-bold ${getRoleBadgeStyle(serverRole || role)}`}>
                        SERVER ROLE: {(serverRole || role).toUpperCase()}
                      </span>
                    </div>
                  </div>

                  {/* Quick Links */}
                  <div className="space-y-1 mb-3">
                    <Link
                      href="/dashboard/builder"
                      className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg text-slate-300 hover:bg-slate-800 hover:text-white transition"
                      onClick={() => setAccountMenuOpen(false)}
                    >
                      <span>📊</span>
                      <span>Custom Dashboards</span>
                    </Link>
                    <Link
                      href="/dashboard/analyst"
                      className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg text-slate-300 hover:bg-slate-800 hover:text-white transition"
                      onClick={() => setAccountMenuOpen(false)}
                    >
                      <span>🛡️</span>
                      <span>Analyst Triage Queue</span>
                    </Link>
                  </div>

                  {/* Persona Preview Switcher (Explicitly marked as UI Preview) */}
                  <div className="pt-2 pb-3 border-t border-slate-800">
                    <span className="text-[10px] text-slate-400 font-semibold uppercase block mb-1">
                      UI Persona Preview:
                    </span>
                    <select
                      value={role}
                      onChange={(e) => setRole(e.target.value as UserRole)}
                      className="w-full bg-[#080d1a] border border-slate-700 rounded-lg px-2 py-1.5 text-xs text-cyan-400 font-medium focus:outline-none cursor-pointer"
                    >
                      <option value="Administrator">Administrator (All Tabs)</option>
                      <option value="Tier-2 SOC Analyst">Priya Nair (SOC Analyst)</option>
                      <option value="Incident Response Lead">Daniel Okafor (IR Lead)</option>
                      <option value="Threat Hunter">Mei Lin Tan (Threat Hunter)</option>
                      <option value="CISO (Executive)">Rachel Adeyemi (CISO)</option>
                      <option value="Security Engineer">Marcus Vance (SecOps Eng)</option>
                      <option value="Viewer">Viewer (Auditor)</option>
                    </select>
                  </div>

                  {/* Sign Out Button */}
                  <div className="pt-2 border-t border-slate-800">
                    <button
                      id="header-logout-btn"
                      type="button"
                      onClick={async () => {
                        setAccountMenuOpen(false);
                        await logout();
                      }}
                      className="w-full flex items-center justify-center gap-2 py-2 px-3 rounded-lg bg-red-950/40 hover:bg-red-900/60 border border-red-800/60 text-red-400 hover:text-red-200 font-bold transition cursor-pointer"
                    >
                      <span>🚪</span>
                      <span>Sign Out of Console</span>
                    </button>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <Link
              id="header-signin-btn"
              href="/login"
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold text-black bg-cyan-400 hover:bg-cyan-300 transition shadow-sm shadow-cyan-950/60 shrink-0"
            >
              <span>🔐</span>
              <span>Sign In</span>
            </Link>
          )}

          {/* Mobile Menu Hamburger Button */}
          <button
            id="mobile-menu-toggle-btn"
            type="button"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="lg:hidden p-2 rounded-lg bg-[#0d1527] border border-slate-800 text-slate-300 hover:text-white hover:border-slate-700 transition"
            aria-label="Toggle Navigation Menu"
            aria-expanded={mobileMenuOpen}
          >
            {mobileMenuOpen ? (
              <span className="text-lg font-bold">✕</span>
            ) : (
              <span className="text-lg font-bold">☰</span>
            )}
          </button>

        </div>

      </div>

      {/* Mobile Drawer Navigation (Slide-down overlay for Mobile / Tablet) */}
      {mobileMenuOpen && (
        <div
          ref={mobileMenuRef}
          className="lg:hidden mt-2 pt-3 pb-4 border-t border-slate-800 space-y-3 animate-fadeIn"
          role="navigation"
          aria-label="Mobile Navigation"
        >
          {/* Mobile Search */}
          <form onSubmit={handleSearchSubmit} className="relative px-1">
            <button
              type="submit"
              className="absolute inset-y-0 left-0 flex items-center pl-3.5 text-slate-500"
              title="Search threat intelligence"
            >
              🔍
            </button>
            <input
              type="text"
              value={searchVal}
              onChange={(e) => setSearchVal(e.target.value)}
              placeholder="Search IOCs, CVEs, MITRE ATT&CK..."
              className="w-full bg-[#0d1527] border border-slate-800 rounded-lg pl-8 pr-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </form>

          {/* Links Grid */}
          <div className="grid grid-cols-2 gap-1.5 px-1">
            {allNavItems.map((item) => {
              const isActive = pathname === item.href;
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-semibold transition ${
                    isActive
                      ? "bg-cyan-950/90 text-cyan-300 border border-cyan-700/80"
                      : "text-slate-300 hover:bg-slate-800 hover:text-white bg-[#0d1527]/50"
                  }`}
                  onClick={() => setMobileMenuOpen(false)}
                >
                  <span className="text-sm">{item.icon}</span>
                  <span className="truncate">{item.label}</span>
                </Link>
              );
            })}
          </div>

          {/* User Section in Mobile Drawer */}
          <div className="px-1 pt-2 border-t border-slate-800">
            {isAuthenticated ? (
              <div className="bg-[#0d1527] border border-slate-800 rounded-xl p-3 flex flex-col gap-2">
                <div className="flex items-center justify-between">
                  <div className="flex flex-col">
                    <span className="text-xs font-bold text-slate-200">
                      {user?.full_name || user?.email?.split("@")[0] || "Operator"}
                    </span>
                    <span className="text-[10px] text-slate-400">
                      {user?.email}
                    </span>
                  </div>
                  <span className={`text-[10px] px-2 py-0.5 rounded border font-mono font-bold ${getRoleBadgeStyle(serverRole || role)}`}>
                    {(serverRole || role).toUpperCase()}
                  </span>
                </div>

                <button
                  type="button"
                  onClick={async () => {
                    setMobileMenuOpen(false);
                    await logout();
                  }}
                  className="w-full mt-1 py-2 px-3 rounded-lg bg-red-950/50 border border-red-800 text-red-400 font-bold text-xs flex items-center justify-center gap-1.5"
                >
                  <span>🚪</span>
                  <span>Sign Out</span>
                </button>
              </div>
            ) : (
              <Link
                href="/login"
                className="w-full py-2.5 px-4 rounded-xl bg-cyan-400 text-black font-bold text-xs flex items-center justify-center gap-2"
                onClick={() => setMobileMenuOpen(false)}
              >
                <span>🔐</span>
                <span>Sign In to Console</span>
              </Link>
            )}
          </div>
        </div>
      )}
    </header>
  );
}

export default Navbar;