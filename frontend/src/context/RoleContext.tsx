"use client";

import React, { createContext, useContext, useState, useEffect } from "react";

export type UserRole =
  | "Tier-2 SOC Analyst"
  | "Incident Response Lead"
  | "Threat Hunter"
  | "CISO (Executive)"
  | "Security Engineer"
  | "Administrator";

export interface PersonaInfo {
  name: string;
  title: string;
  focus: string;
  badgeColor: string;
  allowedTabs: string[];
}

export const PERSONA_CONFIG: Record<UserRole, PersonaInfo> = {
  "Tier-2 SOC Analyst": {
    name: "Priya Nair",
    title: "Tier-2 SOC Analyst",
    focus: "Triage, Indicator Enrichment & Escalation",
    badgeColor: "text-cyan-400 border-cyan-800 bg-cyan-950/60",
    allowedTabs: ["/", "/dashboard/analyst"],
  },
  "Incident Response Lead": {
    name: "Daniel Okafor",
    title: "Incident Response Lead",
    focus: "Forensic Timeline, Containment & Reporting",
    badgeColor: "text-orange-400 border-orange-800 bg-orange-950/60",
    allowedTabs: ["/", "/dashboard/analyst", "/dashboard/incidents"],
  },
  "Threat Hunter": {
    name: "Mei Lin Tan",
    title: "Threat Hunter",
    focus: "Adversary Pivoting & ATT&CK Mapping",
    badgeColor: "text-purple-400 border-purple-800 bg-purple-950/60",
    allowedTabs: ["/", "/dashboard/hunting", "/dashboard/analyst"],
  },
  "CISO (Executive)": {
    name: "Rachel Adeyemi",
    title: "Chief Information Security Officer (CISO)",
    focus: "Enterprise Posture & Board Reporting",
    badgeColor: "text-emerald-400 border-emerald-800 bg-emerald-950/60",
    allowedTabs: ["/", "/dashboard/executive"],
  },
  "Security Engineer": {
    name: "Marcus Vance",
    title: "Security & Detection Engineer",
    focus: "STIX Feeds, Ingestion & System Health",
    badgeColor: "text-blue-400 border-blue-800 bg-blue-950/60",
    allowedTabs: ["/", "/dashboard/analyst", "/dashboard/hunting"],
  },
  Administrator: {
    name: "SecOps Admin",
    title: "Enterprise SuperAdmin",
    focus: "Full Access & Governance",
    badgeColor: "text-red-400 border-red-800 bg-red-950/60",
    allowedTabs: [
      "/",
      "/dashboard/analyst",
      "/dashboard/executive",
      "/dashboard/incidents",
      "/dashboard/hunting",
    ],
  },
};

interface RoleContextType {
  role: UserRole;
  setRole: (role: UserRole) => void;
  persona: PersonaInfo;
}

const RoleContext = createContext<RoleContextType | undefined>(undefined);

export function RoleProvider({ children }: { children: React.ReactNode }) {
  const [role, setRoleState] = useState<UserRole>("Administrator");

  useEffect(() => {
    const saved = localStorage.getItem("threatlens_role") as UserRole;
    if (saved && PERSONA_CONFIG[saved]) {
      setRoleState(saved);
    }
  }, []);

  const setRole = (newRole: UserRole) => {
    setRoleState(newRole);
    localStorage.setItem("threatlens_role", newRole);
  };

  const currentPersona = PERSONA_CONFIG[role] || PERSONA_CONFIG["Administrator"];

  return (
    <RoleContext.Provider
      value={{
        role,
        setRole,
        persona: currentPersona,
      }}
    >
      {children}
    </RoleContext.Provider>
  );
}

export function useRole() {
  const context = useContext(RoleContext);
  if (!context) {
    throw new Error("useRole must be used within a RoleProvider");
  }
  return context;
}