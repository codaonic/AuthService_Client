import type { NextFunction, Request, RequestHandler, Response } from "express";
import type { JWTPayload } from "jose";

import { TokenValidationError, TokenValidator } from "./validator.js";

declare module "express-serve-static-core" {
  interface Request {
    claims?: JWTPayload;
  }
}

function challengeHeader(req: Request, error?: string): string {
  const resourceMetadataUrl = `${req.protocol}://${req.get("host")}/.well-known/oauth-protected-resource`;
  let challenge = `Bearer resource_metadata="${resourceMetadataUrl}"`;
  if (error) {
    challenge += `, error="${error}"`;
  }
  return challenge;
}

/**
 * Builds an Express middleware that validates the bearer token and attaches
 * its claims to `req.claims`. A request with no/invalid token gets a 401 with
 * a WWW-Authenticate header pointing at this resource's
 * /.well-known/oauth-protected-resource -- the same 401-then-discover pattern
 * an MCP client expects.
 */
export function makeAuthMiddleware(validator: TokenValidator): RequestHandler {
  return async (req: Request, res: Response, next: NextFunction) => {
    const header = req.headers.authorization ?? "";
    if (!header.startsWith("Bearer ")) {
      res.setHeader("WWW-Authenticate", challengeHeader(req));
      res.status(401).json({ detail: "missing_bearer_token" });
      return;
    }

    const token = header.slice("Bearer ".length).trim();
    try {
      req.claims = await validator.validate(token);
      next();
    } catch (err) {
      const detail = err instanceof TokenValidationError ? err.message : "invalid_token";
      res.setHeader("WWW-Authenticate", challengeHeader(req, "invalid_token"));
      res.status(401).json({ detail });
    }
  };
}

/**
 * Builds an Express middleware that validates the token AND requires all
 * given scopes.
 */
export function makeScopeMiddleware(validator: TokenValidator, ...requiredScopes: string[]): RequestHandler {
  const requireAuth = makeAuthMiddleware(validator);

  return (req: Request, res: Response, next: NextFunction) => {
    requireAuth(req, res, () => {
      const claims = req.claims ?? {};
      const missing = requiredScopes.filter((scope) => !TokenValidator.hasScope(claims, scope));
      if (missing.length > 0) {
        res.status(403).json({ detail: `missing_scope: ${missing.join(", ")}` });
        return;
      }
      next();
    });
  };
}
