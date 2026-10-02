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

