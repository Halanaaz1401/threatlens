"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { 
  ShieldAlert, 
  Search, 
  Bell, 
  Activity, 
  Target, 
  Radio, 
  CheckCircle,
  Home
} from "lucide-react";
import React, { useState } from "react";

export default function Navbar() {
  const pathname = usePathname();
  const [searchQuery, setSearchQuery] = useState("");
  const [toastMsg, setToastMsg] = useState<string | null>(null);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (!searchQuery.trim()) return;

    setToastMsg(`Searching global index for: "${searchQuery}"...`);
    setTimeout(() => {
      setToastMsg(null);
    }, 4000);
  };

  const navItems = [
    { name: "Home Hub", href: "/", icon: Home },
    { name: "SOC Analyst", href: "/dashboard/analyst", icon: ShieldAlert },
    { name: "Executive View", href: "/dashboard/executive", icon: Activity },
    { name: "Incidents & IR", href: "/dashboard/incidents", icon: ShieldAlert },
    { name: "Threat Hunting", href: "/dashboard/hunting", icon: Target },
  ];

  return (
    <>
      <header className="sticky top-0 z-50 w-full border-b border-slate-800 bg-slate-950/80 backdrop-blur">
        <div className="flex h-14 items-center justify-between px-4 sm:px-8">
          
          {/* Logo & Main Title (Clickable to Home) */}
          <div className="flex items-center gap-6">
            <Link href="/" className="flex items-center gap-2 group transition">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-red-600/10 border border-red-600/30 text-red-500 group-hover:bg-red-600/20">
                <Radio className="h-4 w-4 animate-pulse" />
              </div>
              <span className="font-mono text-sm font-bold tracking-wider text-white">
                THREAT<span className="text-red-500">LENS</span>
              </span>
              <span className="hidden sm:inline-block rounded bg-slate-800 px-1.5 py-0.5 text-[10px] font-mono text-slate-400 border border-slate-700">
                CTI SOC V1.0
              </span>
            </Link>

            {/* Global Search Bar */}
            <form onSubmit={handleSearch} className="relative hidden md:block w-72">
              <Search className="absolute left-2.5 top-2 h-4 w-4 text-slate-500" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Global search IOC, hash, ASN..."
                className="w-full pl-9 pr-3 py-1.5 bg-slate-900 border border-slate-800 rounded-md text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-red-500/50 font-mono"
              />
            </form>
          </div>

          {/* Navigation Links */}
          <nav className="flex items-center gap-1 sm:gap-2">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = pathname === item.href;
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-mono transition ${
                    isActive
                      ? "bg-slate-800 text-white font-medium border border-slate-700"
                      : "text-slate-400 hover:text-slate-200 hover:bg-slate-900"
                  }`}
                >
                  <Icon className={`h-3.5 w-3.5 ${isActive ? "text-red-400" : "text-slate-400"}`} />
                  <span className="hidden sm:inline">{item.name}</span>
                </Link>
              );
            })}
          </nav>

          {/* Status Indicator & Notifications */}
          <div className="flex items-center gap-3">
            <button
              onClick={() => {
                setToastMsg("Notification center: All 6 CTI ingestion feeds are synchronized.");
                setTimeout(() => setToastMsg(null), 4000);
              }}
              className="relative p-1.5 rounded-md hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition"
            >
              <Bell className="h-4 w-4" />
              <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full animate-ping"></span>
              <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full"></span>
            </button>

            <div className="flex items-center gap-1.5 text-[11px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
              <span className="hidden sm:inline">FEED ACTIVE</span>
            </div>
          </div>

        </div>
      </header>

      {/* Global Toast Alert Notification */}
      {toastMsg && (
        <div className="fixed bottom-6 right-6 z-50 flex items-center gap-2 p-3.5 bg-slate-900 border border-slate-700 rounded-lg shadow-2xl text-xs font-mono text-slate-200 animate-slide-in">
          <CheckCircle className="h-4 w-4 text-emerald-400 shrink-0" />
          <span>{toastMsg}</span>
        </div>
      )}
    </>
  );
}