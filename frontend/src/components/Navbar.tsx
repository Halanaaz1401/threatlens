"use client";

import React, { useState, useEffect, useRef } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useAuth, UserRole } from "@/context/RoleContext";
import {
  Search,
  ChevronDown,
  Menu,
  X,
  LogOut,
  LayoutDashboard,
  ShieldAlert,
  User as UserIcon,
  Shield,
  Activity,
  Layers,
  Radio,
  Sliders,
} from "lucide-react";

interface NavLinkItem {
  label: string;
  href: string;
  adminOnly?: boolean;
}

const PRIMARY_NAV_ITEMS: NavLinkItem[] = [
  { label: "Home", href: "/" },
  { label: "SOC Analyst", href: "/dashboard/analyst" },
  { label: "Incidents", href: "/dashboard/incidents" },
  { label: "Threat Hunting", href: "/dashboard/hunting" },
  { label: "Cases", href: "/dashboard/cases" },
];

const SECONDARY_NAV_ITEMS: NavLinkItem[] = [
  { label: "Executive View", href: "/dashboard/executive" },
  { label: "Dashboards", href: "/dashboard/builder" },
  { label: "Feeds & TAXII", href: "/dashboard/feeds" },
  { label: "Admin Feeds", href: "/dashboard/admin/feeds", adminOnly: true },
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

  // Close menus on route change
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

  const getRoleBadgeStyle = (userRoleStr: string) => {
    const norm = userRoleStr.toLowerCase();
    if (norm.includes("admin")) return "text-[#F2F2F0] bg-[#17181B] border-[#2B2C30]";
    if (norm.includes("engineer")) return "text-[#19D5E5] bg-[#111214] border-[#2B2C30]";
    if (norm.includes("analyst") || norm.includes("hunter")) return "text-[#19D5E5] bg-[#111214] border-[#2B2C30]";
    return "text-[#B0B0B4] bg-[#111214] border-[#2B2C30]";
  };

  return (
    <header className="w-full bg-[#090A0C]/95 backdrop-blur-md border-b border-[#2B2C30] px-3 sm:px-6 py-2.5 sticky top-0 z-50">
      <div className="max-w-7xl mx-auto flex items-center justify-between gap-3 sm:gap-4">
        
        {/* Left: Brand + Search */}
        <div className="flex items-center gap-3 sm:gap-5 shrink-0">
          <Link href="/" className="flex items-center gap-2.5 group shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#19D5E5] rounded-lg">
            <span className="w-8 h-8 rounded-lg bg-[#111214] border border-[#2B2C30] flex items-center justify-center text-[#F2F2F0] text-xs font-mono font-bold shadow-inner group-hover:border-[#19D5E5]/60 transition">
              TL
            </span>
            <div className="flex flex-col">
              <div className="flex items-center gap-1.5">
                <span className="font-semibold tracking-tight text-[#F2F2F0] text-sm sm:text-base group-hover:text-white transition">
                  THREATLENS
                </span>
                <span className="text-[9px] bg-[#17181B] text-[#19D5E5] px-1.5 py-0.5 rounded font-mono font-semibold border border-[#2B2C30] hidden xs:inline">
                  CTI
                </span>
              </div>
              <span className="text-[10px] text-[#85858B] font-mono hidden sm:inline leading-none">
                Security Operations Platform
              </span>
            </div>
          </Link>

          {/* Search Box */}
          <form onSubmit={handleSearchSubmit} className="relative hidden xl:block w-48 2xl:w-60">
            <button
              type="submit"
              className="absolute inset-y-0 left-0 flex items-center pl-2.5 text-[#85858B] hover:text-[#19D5E5] transition"
              title="Search threat intelligence"
              aria-label="Submit search"
            >
              <Search className="w-3.5 h-3.5" />
            </button>
            <input
              type="text"
              value={searchVal}
              onChange={(e) => setSearchVal(e.target.value)}
              placeholder="Search IOC, CVE, ATT&CK..."
              aria-label="Search threat indicators"
              className="w-full bg-[#111214] border border-[#2B2C30] rounded-lg pl-8 pr-2.5 py-1.5 text-xs text-[#F2F2F0] placeholder-[#85858B] focus:outline-none focus:border-[#19D5E5] transition font-mono"
            />
          </form>
        </div>

        {/* Center: Desktop Navigation Bar */}
        <nav className="hidden lg:flex items-center gap-1 bg-[#111214] border border-[#2B2C30] p-1 rounded-xl shrink-0" aria-label="Main Navigation">
          {PRIMARY_NAV_ITEMS.map((item) => {
            const isActive = pathname === item.href;
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[#19D5E5] ${
                  isActive
                    ? "bg-[#17181B] text-[#F2F2F0] border border-[#3F4046] shadow-sm"
                    : "text-[#B0B0B4] hover:text-[#F2F2F0] hover:bg-[#17181B]/50"
                }`}
              >
                {isActive && <span className="w-1.5 h-1.5 rounded-full bg-[#19D5E5]" />}
                <span>{item.label}</span>
              </Link>
            );
          })}

          {/* More Menu Dropdown */}
          <div className="relative" ref={moreMenuRef}>
            <button
              type="button"
              onClick={() => setMoreMenuOpen(!moreMenuOpen)}
              className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium transition cursor-pointer focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[#19D5E5] ${
                moreMenuOpen || visibleSecondaryItems.some((i) => pathname === i.href)
                  ? "bg-[#17181B] text-[#F2F2F0]"
                  : "text-[#B0B0B4] hover:text-[#F2F2F0] hover:bg-[#17181B]/50"
              }`}
              aria-expanded={moreMenuOpen}
              aria-haspopup="true"
              aria-label="Additional Navigation Options"
            >
              <span>More</span>
              <ChevronDown className="w-3 h-3 text-[#85858B]" />
            </button>

            {moreMenuOpen && (
              <div className="absolute left-0 mt-2 w-48 bg-[#111214] border border-[#2B2C30] rounded-xl shadow-2xl py-1.5 z-50 animate-fadeIn">
                {visibleSecondaryItems.map((item) => {
                  const isActive = pathname === item.href;
                  return (
                    <Link
                      key={item.href}
                      href={item.href}
                      className={`flex items-center gap-2 px-3 py-2 text-xs font-medium transition focus-visible:outline-none focus-visible:bg-[#17181B] ${
                        isActive
                          ? "bg-[#17181B] text-[#19D5E5]"
                          : "text-[#B0B0B4] hover:bg-[#17181B] hover:text-[#F2F2F0]"
                      }`}
                      onClick={() => setMoreMenuOpen(false)}
                    >
                      {isActive && <span className="w-1.5 h-1.5 rounded-full bg-[#19D5E5]" />}
                      <span>{item.label}</span>
                    </Link>
                  );
                })}
              </div>
            )}
          </div>
        </nav>

        {/* Right: Live Telemetry + User Identity / Login + Mobile Menu */}
        <div className="flex items-center gap-2 sm:gap-3 shrink-0">
          
          {/* Live Telemetry Status Pill */}
          <div className="hidden sm:flex items-center gap-1.5 bg-[#111214] border border-[#2B2C30] px-2.5 py-1 rounded-lg text-[10px] font-mono font-medium text-[#B0B0B4] shrink-0">
            <span className="w-1.5 h-1.5 rounded-full bg-[#19D5E5] animate-pulse" />
            <span>LIVE CTI</span>
          </div>

          {/* User Account / Session Area */}
          {isAuthenticated ? (
            <div className="relative" ref={accountMenuRef}>
              <button
                id="header-account-menu-btn"
                type="button"
                onClick={() => setAccountMenuOpen(!accountMenuOpen)}
                className="flex items-center gap-2 bg-[#111214] border border-[#2B2C30] hover:border-[#3F4046] px-2.5 py-1.5 rounded-lg text-xs transition cursor-pointer focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[#19D5E5]"
                aria-expanded={accountMenuOpen}
                aria-haspopup="true"
                aria-label="User account menu"
              >
                <div className="w-6 h-6 rounded-md bg-[#17181B] border border-[#2B2C30] flex items-center justify-center text-[#F2F2F0] text-xs font-mono font-bold">
                  {user?.full_name ? user.full_name.charAt(0).toUpperCase() : user?.email ? user.email.charAt(0).toUpperCase() : "U"}
                </div>
                <div className="hidden md:flex flex-col text-left">
                  <span className="text-[11px] font-medium text-[#F2F2F0] leading-tight truncate max-w-[110px]">
                    {user?.full_name || user?.email?.split("@")[0] || "Operator"}
                  </span>
                  <span id="header-user-role-badge" className="text-[9px] text-[#19D5E5] font-mono uppercase leading-tight truncate max-w-[110px]">
                    {serverRole || role}
                  </span>
                </div>
                <ChevronDown className="w-3 h-3 text-[#85858B] ml-0.5" />
              </button>

              {/* Account Dropdown */}
              {accountMenuOpen && (
                <div className="absolute right-0 mt-2 w-64 bg-[#111214] border border-[#2B2C30] rounded-xl shadow-2xl p-3 z-50 animate-fadeIn text-xs">
                  {/* User Profile Summary */}
                  <div className="pb-3 border-b border-[#2B2C30] mb-3">
                    <div className="font-semibold text-[#F2F2F0] truncate text-sm">
                      {user?.full_name || user?.email || "Security Operator"}
                    </div>
                    <div className="text-[11px] text-[#85858B] truncate font-mono mt-0.5">
                      {user?.email}
                    </div>
                    <div className="mt-2 flex items-center gap-1.5">
                      <span className={`text-[9px] px-2 py-0.5 rounded border font-mono font-bold ${getRoleBadgeStyle(serverRole || role)}`}>
                        SERVER ROLE: {(serverRole || role).toUpperCase()}
                      </span>
                    </div>
                  </div>

                  {/* Quick Links */}
                  <div className="space-y-1 mb-3">
                    <Link
                      href="/dashboard/builder"
                      className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg text-[#B0B0B4] hover:bg-[#17181B] hover:text-[#F2F2F0] transition"
                      onClick={() => setAccountMenuOpen(false)}
                    >
                      <LayoutDashboard className="w-3.5 h-3.5 text-[#85858B]" />
                      <span>Custom Dashboards</span>
                    </Link>
                    <Link
                      href="/dashboard/analyst"
                      className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg text-[#B0B0B4] hover:bg-[#17181B] hover:text-[#F2F2F0] transition"
                      onClick={() => setAccountMenuOpen(false)}
                    >
                      <ShieldAlert className="w-3.5 h-3.5 text-[#85858B]" />
                      <span>Analyst Triage Queue</span>
                    </Link>
                  </div>

                  {/* Persona Switcher Preview */}
                  <div className="pt-2 pb-3 border-t border-[#2B2C30]">
                    <span className="text-[10px] text-[#85858B] font-mono uppercase block mb-1">
                      UI Persona Preview:
                    </span>
                    <select
                      value={role}
                      onChange={(e) => setRole(e.target.value as UserRole)}
                      className="w-full bg-[#17181B] border border-[#2B2C30] rounded-lg px-2 py-1.5 text-xs text-[#F2F2F0] font-medium focus:outline-none cursor-pointer"
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
                  <div className="pt-2 border-t border-[#2B2C30]">
                    <button
                      id="header-logout-btn"
                      type="button"
                      onClick={async () => {
                        setAccountMenuOpen(false);
                        await logout();
                      }}
                      className="w-full flex items-center justify-center gap-2 py-2 px-3 rounded-lg bg-[#17181B] hover:bg-red-950/40 border border-[#2B2C30] hover:border-red-800/60 text-red-400 hover:text-red-300 font-semibold transition cursor-pointer text-xs"
                    >
                      <LogOut className="w-3.5 h-3.5" />
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
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold text-[#090A0C] bg-[#F2F2F0] hover:bg-white transition shadow-sm shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#19D5E5]"
            >
              <span>Sign In</span>
            </Link>
          )}

          {/* Mobile Menu Hamburger Button */}
          <button
            id="mobile-menu-toggle-btn"
            type="button"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="lg:hidden p-2 rounded-lg bg-[#111214] border border-[#2B2C30] text-[#B0B0B4] hover:text-[#F2F2F0] transition focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[#19D5E5]"
            aria-label="Toggle Navigation Menu"
            aria-expanded={mobileMenuOpen}
          >
            {mobileMenuOpen ? (
              <X className="w-4 h-4" />
            ) : (
              <Menu className="w-4 h-4" />
            )}
          </button>

        </div>

      </div>

      {/* Mobile Drawer Navigation */}
      {mobileMenuOpen && (
        <div
          ref={mobileMenuRef}
          className="lg:hidden mt-2 pt-3 pb-4 border-t border-[#2B2C30] space-y-3 animate-fadeIn"
          role="navigation"
          aria-label="Mobile Navigation"
        >
          {/* Mobile Search */}
          <form onSubmit={handleSearchSubmit} className="relative px-1">
            <button
              type="submit"
              className="absolute inset-y-0 left-0 flex items-center pl-3.5 text-[#85858B]"
              title="Search threat intelligence"
              aria-label="Search"
            >
              <Search className="w-3.5 h-3.5" />
            </button>
            <input
              type="text"
              value={searchVal}
              onChange={(e) => setSearchVal(e.target.value)}
              placeholder="Search IOCs, CVEs, MITRE ATT&CK..."
              aria-label="Search indicators"
              className="w-full bg-[#111214] border border-[#2B2C30] rounded-lg pl-8 pr-3 py-2 text-xs text-[#F2F2F0] placeholder-[#85858B] focus:outline-none focus:border-[#19D5E5] font-mono"
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
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium transition ${
                    isActive
                      ? "bg-[#17181B] text-[#19D5E5] border border-[#2B2C30]"
                      : "text-[#B0B0B4] hover:bg-[#17181B] hover:text-[#F2F2F0] bg-[#111214]"
                  }`}
                  onClick={() => setMobileMenuOpen(false)}
                >
                  {isActive && <span className="w-1.5 h-1.5 rounded-full bg-[#19D5E5]" />}
                  <span className="truncate">{item.label}</span>
                </Link>
              );
            })}
          </div>

          {/* User Section in Mobile Drawer */}
          <div className="px-1 pt-2 border-t border-[#2B2C30]">
            {isAuthenticated ? (
              <div className="bg-[#111214] border border-[#2B2C30] rounded-xl p-3 flex flex-col gap-2">
                <div className="flex items-center justify-between">
                  <div className="flex flex-col">
                    <span className="text-xs font-medium text-[#F2F2F0]">
                      {user?.full_name || user?.email?.split("@")[0] || "Operator"}
                    </span>
                    <span className="text-[10px] text-[#85858B] font-mono">
                      {user?.email}
                    </span>
                  </div>
                  <span className={`text-[9px] px-2 py-0.5 rounded border font-mono font-bold ${getRoleBadgeStyle(serverRole || role)}`}>
                    {(serverRole || role).toUpperCase()}
                  </span>
                </div>

                <button
                  type="button"
                  onClick={async () => {
                    setMobileMenuOpen(false);
                    await logout();
                  }}
                  className="w-full mt-1 py-2 px-3 rounded-lg bg-[#17181B] border border-[#2B2C30] text-red-400 font-semibold text-xs flex items-center justify-center gap-1.5"
                >
                  <LogOut className="w-3.5 h-3.5" />
                  <span>Sign Out</span>
                </button>
              </div>
            ) : (
              <Link
                href="/login"
                className="w-full py-2.5 px-4 rounded-xl bg-[#F2F2F0] text-[#090A0C] font-semibold text-xs flex items-center justify-center gap-2"
                onClick={() => setMobileMenuOpen(false)}
              >
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