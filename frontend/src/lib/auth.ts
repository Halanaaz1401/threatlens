/**
 * Client-side Authentication Token & Session Helper
 * Retrieves stored JWT bearer token and injects Authorization headers.
 */

export interface StoredUser {
  id: string;
  email: string;
  username?: string | null;
  full_name?: string | null;
  role: string;
  is_active: boolean;
}

export const AUTH_CHANGE_EVENT = "threatlens:auth-change";

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
  window.dispatchEvent(new CustomEvent(AUTH_CHANGE_EVENT, { detail: { action: "login" } }));
}

export function removeAuthToken(): void {
  if (typeof window === "undefined") return;
  localStorage.removeItem("threatlens_token");
  localStorage.removeItem("token");
  localStorage.removeItem("threatlens_user");
  sessionStorage.removeItem("threatlens_token");
  window.dispatchEvent(new CustomEvent(AUTH_CHANGE_EVENT, { detail: { action: "logout" } }));
}

export function getStoredUser(): StoredUser | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = localStorage.getItem("threatlens_user");
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export function setStoredUser(user: StoredUser): void {
  if (typeof window === "undefined") return;
  localStorage.setItem("threatlens_user", JSON.stringify(user));
  localStorage.setItem("threatlens_role", user.role);
}

export function removeStoredUser(): void {
  if (typeof window === "undefined") return;
  localStorage.removeItem("threatlens_user");
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
