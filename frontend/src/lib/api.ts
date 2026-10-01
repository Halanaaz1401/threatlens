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
