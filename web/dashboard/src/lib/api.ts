import type {
  DashboardCreateToolGroupInput,
  DashboardConnectionsResponse,
  DashboardIssuedToken,
  DashboardDiagnosticsResponse,
  DashboardOAuthSessionResponse,
  DashboardOverviewResponse,
  DashboardPromptsResponse,
  DashboardRegisterServerInput,
  DashboardRegisterServerResponse,
  DashboardResourcesResponse,
  DashboardServersResponse,
  DashboardToolGroupsResponse,
  DashboardToolsResponse,
} from "./types";

async function requestJSON<T>(path: string, init?: RequestInit): Promise<T> {
	const csrfToken = document.cookie
		.split("; ")
		.find((row) => row.startsWith("mcpjungle_csrf="))
		?.split("=")[1];
  const response = await fetch(path, {
    ...init,
    headers: {
      Accept: "application/json",
		...(csrfToken ? { "X-CSRF-Token": decodeURIComponent(csrfToken) } : {}),
      ...(init?.headers ?? {}),
    },
  });
  if (!response.ok) {
	if (response.status === 401 && path.startsWith("/api/dashboard/")) {
		window.location.assign("/auth/login");
	}
    let message = `Request failed: ${response.status}`;
    try {
      const payload = (await response.json()) as { error?: string };
      if (payload.error) {
        message = payload.error;
      }
    } catch {
      // keep the fallback message
    }
    throw new Error(message);
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

export const api = {
  overview: () => requestJSON<DashboardOverviewResponse>("/api/dashboard/overview"),
  servers: () => requestJSON<DashboardServersResponse>("/api/dashboard/servers"),
  tools: () => requestJSON<DashboardToolsResponse>("/api/dashboard/tools"),
  toolGroups: () => requestJSON<DashboardToolGroupsResponse>("/api/dashboard/tool-groups"),
  prompts: () => requestJSON<DashboardPromptsResponse>("/api/dashboard/prompts"),
  resources: () => requestJSON<DashboardResourcesResponse>("/api/dashboard/resources"),
  diagnostics: () => requestJSON<DashboardDiagnosticsResponse>("/api/dashboard/diagnostics"),
  connections: () => requestJSON<DashboardConnectionsResponse>("/api/dashboard/connections"),
  createStaticConnection: (body: { name: string; description?: string; allow_list: string[] }) =>
    requestJSON<DashboardIssuedToken>("/api/dashboard/connections/static", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  rotateStaticConnection: (name: string) =>
    requestJSON<DashboardIssuedToken>(`/api/dashboard/connections/static/${encodeURIComponent(name)}/rotate`, { method: "POST" }),
  deleteStaticConnection: (name: string) =>
    requestJSON(`/api/dashboard/connections/static/${encodeURIComponent(name)}`, { method: "DELETE" }),
  revokeHostedConnection: (clientID: string) =>
    requestJSON(`/api/dashboard/connections/hosted/${encodeURIComponent(clientID)}`, { method: "DELETE" }),
  registerServer: (body: DashboardRegisterServerInput) =>
    requestJSON<DashboardRegisterServerResponse>("/api/dashboard/servers", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  getOAuthSession: (sessionID: string) =>
    requestJSON<DashboardOAuthSessionResponse>(`/api/dashboard/oauth/session/${encodeURIComponent(sessionID)}`),
  createToolGroup: (body: DashboardCreateToolGroupInput) =>
    requestJSON("/api/dashboard/tool-groups", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  deleteToolGroup: (name: string) =>
    requestJSON(`/api/dashboard/tool-groups/${encodeURIComponent(name)}`, {
      method: "DELETE",
    }),
  deleteServer: (name: string) =>
    requestJSON(`/api/dashboard/servers/${encodeURIComponent(name)}`, {
      method: "DELETE",
    }),
  setServerEnabled: (name: string, enabled: boolean) =>
    requestJSON(`/api/dashboard/servers/${encodeURIComponent(name)}/enabled`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled }),
    }),
  setToolEnabled: (name: string, enabled: boolean) =>
    requestJSON(`/api/dashboard/tools/${encodeURIComponent(name)}/enabled`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled }),
    }),
  setPromptEnabled: (name: string, enabled: boolean) =>
    requestJSON(`/api/dashboard/prompts/${encodeURIComponent(name)}/enabled`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled }),
    }),
};
