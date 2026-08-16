export type Role = 
  | "Administrator" 
  | "Security Engineer" 
  | "Incident Responder" 
  | "Threat Hunter" 
  | "SOC Analyst" 
  | "Executive (Read-only)";

export const PERMISSIONS: Record<Role, string[]> = {
  "Administrator": ["*"],
  "Security Engineer": ["view_dashboard", "manage_feeds", "system_health"],
  "Incident Responder": ["view_dashboard", "search_intel", "manage_incidents", "containment_checklist", "generate_reports"],
  "Threat Hunter": ["view_dashboard", "search_intel", "enrich_ioc", "create_hunts", "export_stix"],
  "SOC Analyst": ["view_dashboard", "search_intel", "enrich_ioc", "triage_alerts", "escalate_incident"],
  "Executive (Read-only)": ["view_dashboard", "generate_reports"]
};

export const hasPermission = (userRole: Role, action: string): boolean => {
  if (userRole === "Administrator") return true;
  const userPerms = PERMISSIONS[userRole] || [];
  return userPerms.includes(action);
};