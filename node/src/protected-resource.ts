import { Router } from "express";

/**
 * RFC 9728 Protected Resource Metadata, served BY this resource server,
 * pointing back at the auth service. MCP clients fetch this after a 401 to
 * discover which authorization server to use.
 */
export function protectedResourceRouter(
  resourceId: string,
  authorizationServer: string,
  resourceName?: string,
): Router {
  const router = Router();

  router.get("/.well-known/oauth-protected-resource", (_req, res) => {
    const body: Record<string, unknown> = {
      resource: resourceId,
      authorization_servers: [authorizationServer],
      bearer_methods_supported: ["header"],
    };
    if (resourceName) {
      body.resource_name = resourceName;
    }
    res.json(body);
  });

  return router;
}
