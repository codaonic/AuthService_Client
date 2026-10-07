import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { makeAuthMiddleware, makeScopeMiddleware } from "../src/express";
import { protectedResourceRouter } from "../src/protected-resource";
import { TokenValidator } from "../src/validator";
import { createKeypair, ISSUER, makeToken, RESOURCE_ID, type TestKeypair } from "./helpers";
import { startJwksServer, type JwksServer } from "./jwks-server";

function buildApp(validator: TokenValidator) {
  const requireAuth = makeAuthMiddleware(validator);
  const requireProfileScope = makeScopeMiddleware(validator, "profile");

  const app = express();
  app.use(protectedResourceRouter(RESOURCE_ID, ISSUER, "Example API"));

  app.get("/me", requireAuth, (req, res) => {
    res.json({ sub: req.claims?.sub });
  });

  app.get("/profile", requireProfileScope, (req, res) => {
    res.json({ sub: req.claims?.sub });
  });

  return app;
}

describe("Express integration", () => {
  let keypair: TestKeypair;
  let jwks: JwksServer;
  let app: ReturnType<typeof buildApp>;

  beforeEach(async () => {
    keypair = await createKeypair();
    jwks = await startJwksServer(keypair.jwks);
    const validator = new TokenValidator(ISSUER, RESOURCE_ID, { jwksUrl: jwks.url });
    app = buildApp(validator);
  });

  afterEach(() => {
    jwks.server.close();
  });

  it("returns 401 with a challenge header when the token is missing", async () => {
    const res = await request(app).get("/me");

    expect(res.status).toBe(401);
    expect(res.headers["www-authenticate"]).toContain("resource_metadata=");
  });

  it("allows access with a valid token", async () => {
    const token = await makeToken(keypair, { sub: "user-1" });

    const res = await request(app).get("/me").set("Authorization", `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ sub: "user-1" });
  });

  it("returns 403 when the required scope is missing", async () => {
    const token = await makeToken(keypair, { scope: "email" });

    const res = await request(app).get("/profile").set("Authorization", `Bearer ${token}`);

    expect(res.status).toBe(403);
  });

  it("serves protected resource metadata", async () => {
    const res = await request(app).get("/.well-known/oauth-protected-resource");

    expect(res.status).toBe(200);
    expect(res.body.resource).toBe(RESOURCE_ID);
    expect(res.body.authorization_servers).toEqual([ISSUER]);
  });
});
