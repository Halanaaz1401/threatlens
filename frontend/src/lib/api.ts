import { getAuthHeaders } from "./auth";

const API_BASE_URLS = [
  process.env.NEXT_PUBLIC_API_URL,
  "http://127.0.0.1:8000",
  "http://localhost:8000",
].filter(Boolean) as string[];

async function apiGet(path: string) {
  const headers = { ...getAuthHeaders() };
  for (const base of API_BASE_URLS) {
    try {
      const res = await fetch(`${base}${path}`, { cache: "no-store", headers });
      if (res.ok) {
        return await res.json();
      }
    } catch {
      // try next host
    }
  }
  return null;
}

export async function safeFetchIndicators() {
  const json = await apiGet("/api/v1/indicators");
  if (json && json.data) {
    return json.data;
  }
  return [];
}

export async function safeFetchIncidents() {
  const json = await apiGet("/api/v1/incidents");
  return json || [];
}

export async function safeFetchIncidentTimeline(incidentId: string) {
  const json = await apiGet(`/api/v1/incidents/${incidentId}/timeline`);
  return json || [];
}

export async function safeFetchAnalyticsOverview(timeRange: string = "24h") {
  return await apiGet(`/api/v1/analytics/overview?time_range=${timeRange}`);
}

export async function safeFetchAnalyticsKPIs(timeRange: string = "24h") {
  return await apiGet(`/api/v1/analytics/kpis?time_range=${timeRange}`);
}

export async function safeFetchAnalyticsTrends(timeRange: string = "24h") {
  return await apiGet(`/api/v1/analytics/trends?time_range=${timeRange}`);
}

export async function safeFetchAnalyticsSeverity() {
  return await apiGet("/api/v1/analytics/severity");
}

export async function safeFetchMitreAnalytics() {
  return await apiGet("/api/v1/analytics/mitre");
}

export async function safeFetchGeoAnalytics() {
  return await apiGet("/api/v1/analytics/geography");
}

export async function safeFetchIndicatorEnrichment(indicatorId: string) {
  return await apiGet(`/api/v1/indicators/${indicatorId}/enrichment`);
}

async function apiPost(path: string, body: any) {
  const headers = {
    ...getAuthHeaders(),
    "Content-Type": "application/json",
  };
  for (const base of API_BASE_URLS) {
    try {
      const res = await fetch(`${base}${path}`, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
      });
      if (res.ok) {
        return await res.json();
      }
    } catch {
      // try next host
    }
  }
  return null;
}

export async function safeFetchIndicatorGraph(indicatorId: string, maxDepth: number = 2, minConfidence: number = 0) {
  return await apiGet(`/api/v1/hunting/graph/${indicatorId}?max_depth=${maxDepth}&min_confidence=${minConfidence}`);
}

export async function safeFetchIndicatorRelationships(indicatorId: string, direction: string = "both", minConfidence: number = 0) {
  return await apiGet(`/api/v1/hunting/indicators/${indicatorId}/relationships?direction=${direction}&min_confidence=${minConfidence}`);
}

export async function safeHuntingSearch(query: string) {
  return await apiGet(`/api/v1/hunting/search?q=${encodeURIComponent(query)}`);
}

export async function safeDeriveRelationships(indicatorId?: string) {
  return await apiPost("/api/v1/hunting/derive", { indicator_id: indicatorId || null, limit: 50 });
}

export async function safeCreateRelationship(payload: {
  source_indicator_id: string;
  target_indicator_id: string;
  relationship_type: string;
  confidence?: number;
  evidence?: string;
}) {
  return await apiPost("/api/v1/hunting/relationships", payload);
}

async function apiPut(path: string, body: any) {
  const headers = {
    ...getAuthHeaders(),
    "Content-Type": "application/json",
  };
  for (const base of API_BASE_URLS) {
    try {
      const res = await fetch(`${base}${path}`, {
        method: "PUT",
        headers,
        body: JSON.stringify(body),
      });
      if (res.ok) {
        return await res.json();
      }
    } catch {
      // try next host
    }
  }
  return null;
}

async function apiDelete(path: string) {
  const headers = { ...getAuthHeaders() };
  for (const base of API_BASE_URLS) {
    try {
      const res = await fetch(`${base}${path}`, {
        method: "DELETE",
        headers,
      });
      if (res.ok) {
        return await res.json();
      }
    } catch {
      // try next host
    }
  }
async function apiPatch(path: string, body: any) {
  const headers = {
    ...getAuthHeaders(),
    "Content-Type": "application/json",
  };
  for (const base of API_BASE_URLS) {
    try {
      const res = await fetch(`${base}${path}`, {
        method: "PATCH",
        headers,
        body: JSON.stringify(body),
      });
      if (res.ok) {
        return await res.json();
      }
    } catch {
      // try next host
    }
  }
  return null;
}

export async function safeFetchDetectionRules(params?: { enabled?: boolean; severity?: string }) {
  let query = "";
  const qparts: string[] = [];
  if (params?.enabled !== undefined) qparts.push(`enabled=${params.enabled}`);
  if (params?.severity) qparts.push(`severity=${params.severity}`);
  if (qparts.length > 0) query = `?${qparts.join("&")}`;
  const res = await apiGet(`/api/v1/detection-rules${query}`);
  return res || [];
}

export async function safeFetchDetectionRule(id: string) {
  return await apiGet(`/api/v1/detection-rules/${id}`);
}

export async function safeCreateDetectionRule(payload: any) {
  return await apiPost("/api/v1/detection-rules", payload);
}

export async function safeUpdateDetectionRule(id: string, payload: any) {
  return await apiPut(`/api/v1/detection-rules/${id}`, payload);
}

export async function safeDeleteDetectionRule(id: string) {
  return await apiDelete(`/api/v1/detection-rules/${id}`);
}

export async function safeEnableDetectionRule(id: string) {
  return await apiPost(`/api/v1/detection-rules/${id}/enable`, {});
}

export async function safeDisableDetectionRule(id: string) {
  return await apiPost(`/api/v1/detection-rules/${id}/disable`, {});
}

export async function safeTestDetectionRule(payload: any) {
  return await apiPost("/api/v1/detection-rules/test", payload);
}

export async function safeEvaluateIndicatorRules(indicatorId: string) {
  return await apiPost(`/api/v1/detection-rules/evaluate/${indicatorId}`, {});
}

// -----------------------------------------------------------------
// Phase 4D-C: IOC Lifecycle, Expiration, and Feed Management APIs
// -----------------------------------------------------------------

export async function safeFetchIndicator(id: string) {
  return await apiGet(`/api/v1/indicators/${id}`);
}

export async function safeCreateIndicator(payload: any) {
  return await apiPost("/api/v1/indicators/create", payload);
}

export async function safeUpdateIndicator(id: string, payload: any) {
  return await apiPut(`/api/v1/indicators/${id}`, payload);
}

export async function safeDeleteIndicator(id: string, reason?: string, hardDelete: boolean = false) {
  let url = `/api/v1/indicators/${id}?hard_delete=${hardDelete}`;
  if (reason) {
    url += `&reason=${encodeURIComponent(reason)}`;
  }
  return await apiDelete(url);
}

export async function safeExpireStaleIndicators(batchSize: number = 100) {
  return await apiPost("/api/v1/indicators/expire-stale", { batch_size: batchSize });
}

export async function safeFetchFeeds() {
  const res = await apiGet("/api/v1/feeds/");
  return res || [];
}

export async function safeFetchFeed(id: string) {
  return await apiGet(`/api/v1/feeds/${id}`);
}

export async function safeEnableFeed(id: string) {
  return await apiPost(`/api/v1/feeds/${id}/enable`, {});
}

export async function safeDisableFeed(id: string) {
  return await apiPost(`/api/v1/feeds/${id}/disable`, {});
}

export async function safeUpdateFeedConfig(id: string, payload: any) {
  return await apiPut(`/api/v1/feeds/${id}`, payload);
}

export async function safeTriggerFeedFetch(source: string = "all") {
  return await apiPost(`/api/v1/feeds/fetch?source=${encodeURIComponent(source)}`, {});
}

export async function safeFetchWebhooks() {
  const res = await apiGet("/api/v1/integrations/webhooks");
  return res || [];
}

export async function safeEnableWebhook(provider: string) {
  return await apiPost(`/api/v1/integrations/webhooks/${provider}/enable`, {});
}

export async function safeDisableWebhook(provider: string) {
  return await apiPost(`/api/v1/integrations/webhooks/${provider}/disable`, {});
}

export async function safeDiscoverTaxii(serverUrl: string, username?: string, password?: string) {
  return await apiPost("/api/v1/feeds/taxii/discover", {
    server_url: serverUrl,
    username: username || undefined,
    password: password || undefined,
  });
}

export async function safeFetchTaxiiCollections(serverUrl: string, apiRoot: string, username?: string, password?: string) {
  return await apiPost("/api/v1/feeds/taxii/collections", {
    server_url: serverUrl,
    api_root: apiRoot,
    username: username || undefined,
    password: password || undefined,
  });
}

export async function safeCreateTaxiiFeed(payload: any) {
  return await apiPost("/api/v1/feeds/taxii", payload);
}

// -----------------------------------------------------------------
// Phase 4E: Forensic Case Management & Executive Reporting APIs
// -----------------------------------------------------------------

export async function safeFetchCases(filters?: {
  status?: string;
  severity?: string;
  priority?: string;
  assignee?: string;
  search?: string;
}) {
  const params = new URLSearchParams();
  if (filters?.status) params.append("status", filters.status);
  if (filters?.severity) params.append("severity", filters.severity);
  if (filters?.priority) params.append("priority", filters.priority);
  if (filters?.assignee) params.append("assignee", filters.assignee);
  if (filters?.search) params.append("search", filters.search);
  const q = params.toString() ? `?${params.toString()}` : "";
  const res = await apiGet(`/api/v1/cases/${q}`);
  return res || [];
}

export async function safeFetchCase(caseId: string) {
  return await apiGet(`/api/v1/cases/${caseId}`);
}

export async function safeCreateCase(payload: {
  title: string;
  description?: string;
  severity?: string;
  priority?: string;
  assignee?: string;
  owner?: string;
  tags?: string[];
  source?: string;
}) {
  return await apiPost("/api/v1/cases/", payload);
}

export async function safeUpdateCase(caseId: string, payload: any) {
  return await apiPatch(`/api/v1/cases/${caseId}`, payload);
}

export async function safeUpdateCaseStatus(caseId: string, status: string, note?: string) {
  return await apiPatch(`/api/v1/cases/${caseId}/status`, { status, note });
}

export async function safeAssignCase(caseId: string, assignee?: string, owner?: string) {
  return await apiPatch(`/api/v1/cases/${caseId}/assign`, { assignee, owner });
}

export async function safeLinkIncidentToCase(caseId: string, incidentId: string) {
  return await apiPost(`/api/v1/cases/${caseId}/incidents`, { incident_id: incidentId });
}

export async function safeUnlinkIncidentFromCase(caseId: string, incidentId: string) {
  return await apiDelete(`/api/v1/cases/${caseId}/incidents/${incidentId}`);
}

export async function safeLinkAlertToCase(caseId: string, alertId: string) {
  return await apiPost(`/api/v1/cases/${caseId}/alerts`, { alert_id: alertId });
}

export async function safeUnlinkAlertFromCase(caseId: string, alertId: string) {
  return await apiDelete(`/api/v1/cases/${caseId}/alerts/${alertId}`);
}

export async function safeLinkIndicatorToCase(caseId: string, indicatorId: string) {
  return await apiPost(`/api/v1/cases/${caseId}/indicators`, { indicator_id: indicatorId });
}

export async function safeUnlinkIndicatorFromCase(caseId: string, indicatorId: string) {
  return await apiDelete(`/api/v1/cases/${caseId}/indicators/${indicatorId}`);
}

export async function safeAddCaseEvidence(caseId: string, payload: any) {
  return await apiPost(`/api/v1/cases/${caseId}/evidence`, payload);
}

export async function safeFetchCaseEvidence(caseId: string) {
  const res = await apiGet(`/api/v1/cases/${caseId}/evidence`);
  return res || [];
}

export async function safeAddCaseNote(caseId: string, content: string) {
  return await apiPost(`/api/v1/cases/${caseId}/notes`, { content });
}

export async function safeFetchCaseNotes(caseId: string) {
  const res = await apiGet(`/api/v1/cases/${caseId}/notes`);
  return res || [];
}

export async function safeFetchCaseTimeline(caseId: string) {
  const res = await apiGet(`/api/v1/cases/${caseId}/timeline`);
  return res || [];
}

export async function safeFetchCaseAudit(caseId: string) {
  const res = await apiGet(`/api/v1/cases/${caseId}/audit`);
  return res || [];
}

export async function safeGenerateExecutiveReport(timeRange: string = "30d") {
  return await apiPost("/api/v1/reports/executive", { time_range: timeRange });
}

export async function safeFetchReports() {
  const res = await apiGet("/api/v1/reports/");
  return res || [];
}

export async function safeFetchReport(reportId: string) {
  return await apiGet(`/api/v1/reports/${reportId}`);
}

export function getReportDownloadUrl(reportId: string): string {
  const base = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
  return `${base}/api/v1/reports/${reportId}/download`;
}
