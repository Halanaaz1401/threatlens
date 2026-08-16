"use client";

import React, { createContext, useContext, useState, useEffect } from "react";

export type UserRole =
  | "Administrator"
  | "Incident Responder"
  | "Threat Hunter"
  | "SOC Analyst"
  | "Security Engineer"
  | "Executive";

interface RolePermissions {
  allowedTabs: string[]; // hrefs allowed for navigation
  canGenerateReport: boolean;
  canSaveHunt: boolean;
  canExecuteContainment: boolean;
}

const ROLE_PERMISSIONS: Record<UserRole, RolePermissions> = {
  Administrator: {
    allowedTabs: ["/", "/dashboard/analyst", "/dashboard/executive", "/dashboard/incidents", "/dashboard/hunting"],
    canGenerateReport: true,
    canSaveHunt: true,
    canExecuteContainment: true,
  },
  "Incident Responder": {
    allowedTabs: ["/", "/dashboard/analyst", "/dashboard/incidents"],
    canGenerateReport: true,
    canSaveHunt: false,
    canExecuteContainment: true,
  },
  "Threat Hunter": {
    allowedTabs: ["/", "/dashboard/hunting", "/dashboard/analyst"],
    canGenerateReport: false,
    canSaveHunt: true,
    canExecuteContainment: false,
  },
  "SOC Analyst": {
    allowedTabs: ["/", "/dashboard/analyst"],
    canGenerateReport: false,
    canSaveHunt: false,
    canExecuteContainment: false,
  },
  "Security Engineer": {
    allowedTabs: ["/", "/dashboard/analyst", "/dashboard/hunting"],
    canGenerateReport: false,
    canSaveHunt: true,
    canExecuteContainment: true,
  },
  Executive: {
    allowedTabs: ["/", "/dashboard/executive"],
    canGenerateReport: true,
    canSaveHunt: false,
    canExecuteContainment: false,
  },
};

interface RoleContextType {
  role: UserRole;
  setRole: (role: UserRole) => void;
  permissions: RolePermissions;
}

const RoleContext = createContext<RoleContextType | undefined>(undefined);

export function RoleProvider({ children }: { children: React.ReactNode }) {
  const [role, setRoleState] = useState<UserRole>("Administrator");

  useEffect(() => {
    const saved = localStorage.getItem("threatlens_role") as UserRole;
    if (saved && ROLE_PERMISSIONS[saved]) {
      setRoleState(saved);
    }
  }, []);

  const setRole = (newRole: UserRole) => {
    setRoleState(newRole);
    localStorage.setItem("threatlens_role", newRole);
  };

  return (
    <RoleContext.Provider
      value={{
        role,
        setRole,
        permissions: ROLE_PERMISSIONS[role],
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