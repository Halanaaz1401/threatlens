/**
 * Client-side Authentication Token Helper
 * Retrieves stored JWT bearer token and injects Authorization headers.
 */

export function getAuthToken(): string | null {
  if (typeof window === "undefined") return null;
  return (
    localStorage.getItem("threatlens_token") ||
    localStorage.getItem("token") ||
    sessionStorage.getItem("threatlens_token") ||
    null
  );
}

export function setAuthToken(token: string): void {
  if (typeof window === "undefined") return;
  localStorage.setItem("threatlens_token", token);
}

export function removeAuthToken(): void {
  if (typeof window === "undefined") return;
  localStorage.removeItem("threatlens_token");
  localStorage.removeItem("token");
}

export function getAuthHeaders(): Record<string, string> {
  const token = getAuthToken();
  if (token) {
    return {
      Authorization: `Bearer ${token}`,
    };
  }
  return {};
}
