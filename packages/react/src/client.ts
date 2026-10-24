export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export interface VaultServiceClient {
  baseUrl: string;
  request<T>(path: string, init?: RequestInit): Promise<T>;
}

/**
 * One fetch wrapper shared by every hook in this package - always sends
 * the vault-unlock session cookie, and turns a non-2xx response into an
 * `ApiError` carrying the status code so hooks can distinguish e.g. a
 * wrong password (401) from a locked vault (423) from a network error.
 */
export function createVaultServiceClient(baseUrl: string): VaultServiceClient {
  async function request<T>(path: string, init?: RequestInit): Promise<T> {
    // Fastify's JSON body parser rejects an empty body if content-type:
    // application/json is set at all - only set it when there's actually
    // a body.
    const headers: Record<string, string> = { ...(init?.headers as Record<string, string> | undefined) };
    if (init?.body !== undefined) {
      headers["content-type"] = "application/json";
    }

    const response = await fetch(`${baseUrl}${path}`, {
      ...init,
      credentials: "include",
      headers,
    });

    if (!response.ok) {
      const body = (await response.json().catch(() => ({}))) as { error?: string };
      throw new ApiError(response.status, body.error ?? response.statusText);
    }

    return response.json() as Promise<T>;
  }

  return { baseUrl, request };
}
