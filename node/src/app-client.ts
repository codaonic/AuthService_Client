/**
 * Thrown when the auth service could not process a logout (network failure,
 * wrong client credentials, or an unexpected response).
 */
export class LogoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LogoutError";
  }
}

export interface AuthServiceClientOptions {
  /** Confidential clients only; omit for a public client. */
  clientSecret?: string;
  /** Overrides the global `fetch` (e.g. for tests or a custom agent). */
  fetch?: typeof fetch;
}

export interface LogoutUrlOptions {
  /** Must be listed under the application's "After-logout URLs" in the admin console. */
  postLogoutRedirectUri?: string;
  state?: string;
}

/**
 * Calls the auth service on behalf of an application that signs users in --
 * a website backend, a mobile or desktop app. Separate from TokenValidator,
 * which a resource server uses to check incoming tokens.
 */
export class AuthServiceClient {
  readonly issuer: string;
  readonly clientId: string;

  private readonly clientSecret?: string;
  private readonly fetchImpl: typeof fetch;

  constructor(issuer: string, clientId: string, options: AuthServiceClientOptions = {}) {
    this.issuer = issuer.replace(/\/+$/, "");
    this.clientId = clientId;
    this.clientSecret = options.clientSecret;
    this.fetchImpl = options.fetch ?? fetch;
  }

  get logoutEndpoint(): string {
    return `${this.issuer}/logout`;
  }

  /**
   * Signs the user who owns `refreshToken` out of this application. Only
   * this application is affected: the user stays signed in to every other
   * application, including ones in the same login group. Every refresh token
   * this application holds for them is revoked.
   *
   * Resolves true when the user was signed out, false when the auth service
   * no longer recognizes the token (already used, expired, or revoked) -- in
   * both cases the caller should clear its own session. Rejects with
   * LogoutError for anything else.
   */
  async logout(refreshToken: string): Promise<boolean> {
    const form = new URLSearchParams({ client_id: this.clientId, refresh_token: refreshToken });
    if (this.clientSecret) form.set("client_secret", this.clientSecret);

    let resp: Response;
    try {
      resp = await this.fetchImpl(this.logoutEndpoint, { method: "POST", body: form });
    } catch (err) {
      throw new LogoutError(`logout failed: ${err instanceof Error ? err.message : String(err)}`);
    }
    if (resp.status === 200) return true;

    let detail: unknown;
    try {
      detail = ((await resp.json()) as { detail?: unknown }).detail;
    } catch {
      detail = undefined;
    }
    if (resp.status === 400 && detail === "invalid_grant") return false;
    throw new LogoutError(`logout failed: ${resp.status} ${typeof detail === "string" ? detail : ""}`.trim());
  }

  /**
   * URL to redirect the user's browser to, for an application that holds no
   * refresh token.
   */
  logoutUrl(options: LogoutUrlOptions = {}): string {
    const params = new URLSearchParams({ client_id: this.clientId });
    if (options.postLogoutRedirectUri) params.set("post_logout_redirect_uri", options.postLogoutRedirectUri);
    if (options.state) params.set("state", options.state);
    return `${this.logoutEndpoint}?${params}`;
  }
}
