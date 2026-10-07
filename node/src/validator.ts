import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";

/**
 * Thrown by TokenValidator.validate when a token is malformed, expired, or
 * fails signature/issuer/audience verification.
 */
export class TokenValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TokenValidationError";
  }
}

export interface TokenValidatorOptions {
  /** Overrides the default "{issuer}/jwks.json" JWKS endpoint. */
  jwksUrl?: string;
  /** How long a fetched JWKS is cached, in milliseconds. Defaults to 5 minutes. */
  cacheMaxAgeMs?: number;
}

/**
 * Fetches and caches the auth service's JWKS, and verifies bearer tokens
 * locally. No network call to the auth service happens per request -- only
 * when the JWKS cache is cold or a token references an unknown `kid` (e.g.
 * right after key rotation).
 */
export class TokenValidator {
  readonly issuer: string;
  readonly resourceId: string;

  private readonly jwks: ReturnType<typeof createRemoteJWKSet>;

  constructor(issuer: string, resourceId: string, options: TokenValidatorOptions = {}) {
    this.issuer = issuer;
    this.resourceId = resourceId;
    const jwksUrl = options.jwksUrl ?? `${issuer.replace(/\/+$/, "")}/jwks.json`;
    this.jwks = createRemoteJWKSet(new URL(jwksUrl), {
      cacheMaxAge: options.cacheMaxAgeMs ?? 5 * 60 * 1000,
    });
  }

  /**
   * Verifies a bearer token's signature, `exp`, `iss`, and `aud` (must equal
   * resourceId). Returns the decoded claims on success, or throws
   * TokenValidationError.
   */
  async validate(token: string): Promise<JWTPayload> {
    try {
      const { payload } = await jwtVerify(token, this.jwks, {
        issuer: this.issuer,
        audience: this.resourceId,
        algorithms: ["RS256"],
      });
      return payload;
    } catch (err) {
      throw new TokenValidationError(err instanceof Error ? err.message : "invalid token");
    }
  }

  /** Reports whether claims carries the given scope in its space-separated `scope` claim. */
  static hasScope(claims: JWTPayload, scope: string): boolean {
    const raw = claims.scope;
    if (typeof raw !== "string") return false;
    return raw.split(/\s+/).filter(Boolean).includes(scope);
  }
}
