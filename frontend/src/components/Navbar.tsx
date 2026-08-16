"use client";

import React, { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useRole, UserRole } from "@/context/RoleContext";

export function Navbar() {
  const pathname = usePathname();
  const { role, setRole, persona } = useRole();
  const [searchVal, setSearchVal] = useState("");

  const navItems = [
    { label: "Home Hub", href: "/", icon: "🏠" },
    { label: "SOC Analyst", href: "/dashboard/analyst", icon: "🛡️" },
    { label: "Executive View", href: "/dashboard/executive", icon: "📈" },
    { label: "Incidents & IR", href: "/dashboard/incidents", icon: "⚠️" },
    { label: "Threat Hunting", href: "/dashboard/hunting", icon: "🎯" },
  ];

  const allowedTabs = persona?.allowedTabs || ["/"];
  const visibleNavItems = navItems.filter((item) => allowedTabs.includes(item.href));

  return (
    <header className="w-full bg-[#080d1a]/95 backdrop-blur border-b border-slate-800/90 px-6 py-3.5 sticky top-0 z-50 shadow-md">
      <div className="max-w-[1600px] mx-auto flex items-center justify-between gap-6">
        
        {/* Left: Brand + Quick Search */}
        <div className="flex items-center gap-6">
          <Link href="/" className="flex items-center gap-3 group">
            <span className="w-8 h-8 rounded-lg bg-red-950/80 border border-red-500/70 flex items-center justify-center text-red-400 text-sm font-bold shadow-lg shadow-red-950/50 group-hover:border-red-400 transition">
              ((o))
            </span>
            <div className="flex flex-col">
              <div className="flex items-center gap-2">
                <span className="font-black tracking-widest text-slate-100 text-base group-hover:text-white transition">
                  THREATLENS
                </span>
                <span className="text-[10px] bg-slate-800/90 text-cyan-400 px-2 py-0.5 rounded font-mono font-semibold border border-slate-700">
                  v1.0 SOC
                </span>
              </div>
              <span className="text-[11px] text-slate-400 font-medium">
                Cyber Threat Intelligence Platform
              </span>
            </div>
          </Link>

          {/* Search Box */}
          <div className="relative hidden xl:block w-72">
            <span className="absolute inset-y-0 left-0 flex items-center pl-3 text-slate-500 text-sm">
              🔍
            </span>
            <input
              type="text"
              value={searchVal}
              onChange={(e) => setSearchVal(e.target.value)}
              placeholder="Search IOCs, CVEs, ATT&CK IDs..."
              className="w-full bg-[#0d1527] border border-slate-700/70 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-all"
            />
          </div>
        </div>

        {/* Center: Navigation Links */}
        <nav className="flex items-center gap-2 bg-[#0d1527]/80 border border-slate-800 p-1.5 rounded-xl">
          {visibleNavItems.map((item) => {
            const isActive = pathname === item.href;
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all ${
                  isActive
                    ? "bg-cyan-950/80 text-cyan-300 border border-cyan-700/80 shadow-md shadow-cyan-950/50"
                    : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
                }`}
              >
                <span className="text-sm">{item.icon}</span>
                <span>{item.label}</span>
              </Link>
            );
          })}
        </nav>

        {/* Right: Persona Info + Role Switcher + Live Status */}
        <div className="flex items-center gap-4">
          
          {/* Persona Card */}
          <div className="hidden md:flex flex-col text-right pr-3 border-r border-slate-800">
            <div className="flex items-center justify-end gap-1.5">
              <span className="text-xs font-bold text-slate-200">{persona?.name}</span>
              <span className={`text-[10px] px-1.5 py-0.5 rounded border font-mono font-bold ${persona?.badgeColor}`}>
                ACTIVE
              </span>
            </div>
            <span className="text-[11px] text-slate-400 font-medium">
              {persona?.title}
            </span>
          </div>

          {/* Role Dropdown */}
          <div className="flex items-center gap-2 bg-[#0d1527] border border-slate-700/80 px-3 py-1.5 rounded-lg text-xs shadow-inner">
            <span className="text-slate-400 font-semibold">Switch Persona:</span>
            <select
              value={role}
              onChange={(e) => setRole(e.target.value as UserRole)}
              className="bg-transparent text-cyan-400 font-bold focus:outline-none cursor-pointer text-xs pr-1"
            >
              <option value="Administrator" className="bg-[#0b1220] text-slate-200">Administrator (All Access)</option>
              <option value="Tier-2 SOC Analyst" className="bg-[#0b1220] text-slate-200">Priya Nair (SOC Analyst)</option>
              <option value="Incident Response Lead" className="bg-[#0b1220] text-slate-200">Daniel Okafor (IR Lead)</option>
              <option value="Threat Hunter" className="bg-[#0b1220] text-slate-200">Mei Lin Tan (Threat Hunter)</option>
              <option value="CISO (Executive)" className="bg-[#0b1220] text-slate-200">Rachel Adeyemi (CISO)</option>
              <option value="Security Engineer" className="bg-[#0b1220] text-slate-200">Marcus Vance (SecOps Eng)</option>
            </select>
          </div>

          {/* Telemetry Live Feed Badge */}
          <div className="flex items-center gap-2 bg-emerald-950/70 border border-emerald-700/70 px-3 py-1.5 rounded-lg text-xs font-bold text-emerald-400 shadow-sm">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="hidden sm:inline">FEED ACTIVE</span>
          </div>
        </div>

      </div>
    </header>
  );
}

export default Navbar;