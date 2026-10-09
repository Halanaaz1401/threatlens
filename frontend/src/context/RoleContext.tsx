"use client";

import React, { createContext, useContext, useState, useEffect, useCallback } from "react";
import {
  getAuthToken,
  setAuthToken,
  removeAuthToken,
  getStoredUser,
  setStoredUser,
  removeStoredUser,
  StoredUser,
  AUTH_CHANGE_EVENT,
} from "@/lib/auth";
import { apiLogin, apiLogout, apiGetCurrentUser } from "@/lib/api";

export type UserRole =
  | "Tier-2 SOC Analyst"
  | "Incident Response Lead"
  | "Threat Hunter"
  | "CISO (Executive)"
  | "Security Engineer"
  | "Administrator"
  | "Viewer";

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
    allowedTabs: ["/", "/dashboard/analyst", "/dashboard/cases", "/dashboard/builder"],
  },
  "Incident Response Lead": {
    name: "Daniel Okafor",
    title: "Incident Response Lead",
    focus: "Forensic Timeline, Containment & Reporting",
    badgeColor: "text-orange-400 border-orange-800 bg-orange-950/60",
    allowedTabs: ["/", "/dashboard/analyst", "/dashboard/incidents", "/dashboard/cases", "/dashboard/builder"],
  },
  "Threat Hunter": {
    name: "Mei Lin Tan",
    title: "Threat Hunter",
    focus: "Adversary Pivoting & ATT&CK Mapping",
    badgeColor: "text-purple-400 border-purple-800 bg-purple-950/60",
    allowedTabs: ["/", "/dashboard/hunting", "/dashboard/analyst", "/dashboard/cases", "/dashboard/builder"],
  },
  "CISO (Executive)": {
    name: "Rachel Adeyemi",
    title: "Chief Information Security Officer (CISO)",
    focus: "Enterprise Posture & Board Reporting",
    badgeColor: "text-emerald-400 border-emerald-800 bg-emerald-950/60",
    allowedTabs: ["/", "/dashboard/executive", "/dashboard/cases", "/dashboard/builder"],
  },
  "Security Engineer": {
    name: "Marcus Vance",
    title: "Security & Detection Engineer",
    focus: "STIX Feeds, Ingestion & System Health",
    badgeColor: "text-blue-400 border-blue-800 bg-blue-950/60",
    allowedTabs: ["/", "/dashboard/analyst", "/dashboard/hunting", "/dashboard/feeds", "/dashboard/cases", "/dashboard/builder"],
  },
  Administrator: {
    name: "SecOps Admin",
    title: "Enterprise SuperAdmin",
    focus: "Full Access & Platform Governance",
    badgeColor: "text-red-400 border-red-800 bg-red-950/60",
    allowedTabs: [
      "/",
      "/dashboard/analyst",
      "/dashboard/executive",
      "/dashboard/incidents",
      "/dashboard/hunting",
      "/dashboard/feeds",
      "/dashboard/admin/feeds",
      "/dashboard/cases",
      "/dashboard/builder",
    ],
  },
  Viewer: {
    name: "SOC Auditor (Viewer)",
    title: "Read-Only Auditor",
    focus: "Observation & Compliance Review",
    badgeColor: "text-slate-400 border-slate-700 bg-slate-900/60",
    allowedTabs: ["/", "/dashboard/executive", "/dashboard/builder"],
  },
};

export function serverRoleToUserRole(serverRole?: string): UserRole {
  if (!serverRole) return "Administrator";
  const norm = serverRole.trim().toLowerCase();
  if (norm === "admin" || norm === "administrator") return "Administrator";
  if (norm === "security_engineer" || norm === "security engineer") return "Security Engineer";
  if (norm === "incident_responder" || norm === "incident responder") return "Incident Response Lead";
  if (norm === "threat_hunter" || norm === "threat hunter") return "Threat Hunter";
  if (norm === "analyst" || norm === "soc_analyst" || norm === "soc analyst") return "Tier-2 SOC Analyst";
  if (norm === "executive" || norm === "ciso") return "CISO (Executive)";
  if (norm === "viewer" || norm === "guest") return "Viewer";
  return "Administrator";
}

interface RoleContextType {
  role: UserRole;
  serverRole: string;
  setRole: (role: UserRole) => void;
  persona: PersonaInfo;
  user: StoredUser | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  authError: string | null;
  login: (email: string, password: string) => Promise<{ success: boolean; error?: string }>;
  logout: () => Promise<void>;
  refreshSession: () => Promise<void>;
}

const RoleContext = createContext<RoleContextType | undefined>(undefined);

export function RoleProvider({ children }: { children: React.ReactNode }) {
  const [role, setRoleState] = useState<UserRole>("Administrator");
  const [serverRole, setServerRole] = useState<string>("admin");
  const [user, setUser] = useState<StoredUser | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [authError, setAuthError] = useState<string | null>(null);

  const refreshSession = useCallback(async () => {
    const token = getAuthToken();
    if (!token) {
      setUser(null);
      setIsAuthenticated(false);
      setIsLoading(false);
      return;
    }

    try {
      const me = await apiGetCurrentUser();
      if (me && me.email) {
        const storedUser: StoredUser = {
          id: me.id,
          email: me.email,
          username: me.username || null,
          full_name: me.full_name || null,
          role: me.role,
          is_active: me.is_active,
        };
        setUser(storedUser);
        setStoredUser(storedUser);
        setServerRole(me.role);
        const mappedRole = serverRoleToUserRole(me.role);
        setRoleState(mappedRole);
        setIsAuthenticated(true);
      } else {
        // Token invalid or expired
        removeAuthToken();
        removeStoredUser();
        setUser(null);
        setIsAuthenticated(false);
      }
    } catch {
      // In case of network error, check cached user
      const cached = getStoredUser();
      if (cached) {
        setUser(cached);
        setServerRole(cached.role);
        setRoleState(serverRoleToUserRole(cached.role));
        setIsAuthenticated(true);
      } else {
        setUser(null);
        setIsAuthenticated(false);
      }
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshSession();

    const handleAuthEvent = () => {
      refreshSession();
    };

    window.addEventListener(AUTH_CHANGE_EVENT, handleAuthEvent);
    window.addEventListener("storage", handleAuthEvent);
    return () => {
      window.removeEventListener(AUTH_CHANGE_EVENT, handleAuthEvent);
      window.removeEventListener("storage", handleAuthEvent);
    };
  }, [refreshSession]);

  const login = async (email: string, password: string): Promise<{ success: boolean; error?: string }> => {
    setIsLoading(true);
    setAuthError(null);
    try {
      const res = await apiLogin({ email, password });
      if (!res || !res.access_token) {
        const errMsg = "Invalid email or password. Please verify credentials.";
        setAuthError(errMsg);
        setIsLoading(false);
        return { success: false, error: errMsg };
      }

      setAuthToken(res.access_token);
      setServerRole(res.role);
      const mappedRole = serverRoleToUserRole(res.role);
      setRoleState(mappedRole);

      // Fetch full user profile
      const me = await apiGetCurrentUser();
      if (me && me.email) {
        const fullUser: StoredUser = {
          id: me.id,
          email: me.email,
          username: me.username || null,
          full_name: me.full_name || null,
          role: me.role,
          is_active: me.is_active,
        };
        setUser(fullUser);
        setStoredUser(fullUser);
      } else {
        const basicUser: StoredUser = {
          id: "authenticated",
          email,
          role: res.role,
          is_active: true,
        };
        setUser(basicUser);
        setStoredUser(basicUser);
      }

      setIsAuthenticated(true);
      setIsLoading(false);
      return { success: true };
    } catch (err: any) {
      const errMsg = err?.message || "Authentication service temporarily unavailable.";
      setAuthError(errMsg);
      setIsLoading(false);
      return { success: false, error: errMsg };
    }
  };

  const logout = async () => {
    try {
      await apiLogout();
    } catch {
      // Ignore API logout error and ensure client cleanup
    } finally {
      removeAuthToken();
      removeStoredUser();
      setUser(null);
      setIsAuthenticated(false);
      setRoleState("Administrator");
      setServerRole("admin");
      if (typeof window !== "undefined") {
        window.location.href = "/login";
      }
    }
  };

  const setRole = (newRole: UserRole) => {
    setRoleState(newRole);
    if (typeof window !== "undefined") {
      localStorage.setItem("threatlens_role", newRole);
    }
  };

  const currentPersona = PERSONA_CONFIG[role] || PERSONA_CONFIG["Administrator"];

  return (
    <RoleContext.Provider
      value={{
        role,
        serverRole,
        setRole,
        persona: currentPersona,
        user,
        isAuthenticated,
        isLoading,
        authError,
        login,
        logout,
        refreshSession,
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

export const useAuth = useRole;