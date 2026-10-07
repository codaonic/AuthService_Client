import { createServer, type Server } from "node:http";

export interface JwksServer {
  server: Server;
  url: string;
  callCount: () => number;
}

export function startJwksServer(jwks: unknown): Promise<JwksServer> {
  let calls = 0;
  return new Promise((resolve) => {
    const server = createServer((_req, res) => {
      calls += 1;
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify(jwks));
    });
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address !== null ? address.port : 0;
      resolve({ server, url: `http://127.0.0.1:${port}/jwks.json`, callCount: () => calls });
    });
  });
}
