import { describe, expect, it } from "vitest";

import { AuthServiceClient, LogoutError } from "../src/app-client";
import { ISSUER } from "./helpers";

interface Seen {
  url: string;
  method?: string;
  form: URLSearchParams;
}

function fakeFetch(status: number, body: unknown, seen: Seen[] = []): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    seen.push({ url: String(input), method: init?.method, form: init?.body as URLSearchParams });
    return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
}

describe("AuthServiceClient", () => {
  it("posts client credentials and the refresh token", async () => {
    const seen: Seen[] = [];
    const client = new AuthServiceClient(ISSUER, "my-app", {
      clientSecret: "s3cret",
      fetch: fakeFetch(200, { status: "signed_out" }, seen),
    });

    expect(await client.logout("rt-123")).toBe(true);
    expect(seen[0].url).toBe(`${ISSUER}/logout`);
    expect(seen[0].method).toBe("POST");
    expect(Object.fromEntries(seen[0].form)).toEqual({
      client_id: "my-app",
      client_secret: "s3cret",
      refresh_token: "rt-123",
    });
  });

  it("sends no secret for a public client", async () => {
    const seen: Seen[] = [];
    const client = new AuthServiceClient(ISSUER, "my-app", { fetch: fakeFetch(200, {}, seen) });

    await client.logout("rt-123");
    expect(seen[0].form.has("client_secret")).toBe(false);
  });

  it("resolves false when the token is no longer known", async () => {
    const client = new AuthServiceClient(ISSUER, "my-app", { fetch: fakeFetch(400, { detail: "invalid_grant" }) });
    expect(await client.logout("stale")).toBe(false);
  });

  it("rejects on bad client credentials", async () => {
    const client = new AuthServiceClient(ISSUER, "my-app", { fetch: fakeFetch(401, { detail: "invalid_client" }) });
    await expect(client.logout("rt-123")).rejects.toThrow(LogoutError);
  });

  it("rejects on network failure", async () => {
    const failing = (async () => {
      throw new Error("down");
    }) as unknown as typeof fetch;
    const client = new AuthServiceClient(ISSUER, "my-app", { fetch: failing });
    await expect(client.logout("rt-123")).rejects.toThrow(LogoutError);
  });

  it("builds the browser logout URL", () => {
    const client = new AuthServiceClient(`${ISSUER}/`, "my app");
    expect(client.logoutUrl()).toBe(`${ISSUER}/logout?client_id=my+app`);

    const url = new URL(
      client.logoutUrl({ postLogoutRedirectUri: "https://app.example.com/signed-out?x=1", state: "abc" }),
    );
    expect(Object.fromEntries(url.searchParams)).toEqual({
      client_id: "my app",
      post_logout_redirect_uri: "https://app.example.com/signed-out?x=1",
      state: "abc",
    });
  });
});
