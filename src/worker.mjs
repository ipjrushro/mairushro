import { httpServerHandler } from "cloudflare:node";
import serverModule from "../server.js";

const { app, syncApprovedLeaveDiscordRoles, initMeetingAttendanceScheduler } = serverModule;

const PORT = 3000;
app.listen(PORT);
const handler = httpServerHandler({ port: PORT });

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    try {
      const response = await handler.fetch(request, env, ctx);

      // API-ul trebuie să răspundă JSON. Dacă runtime-ul întoarce accidental
      // o pagină HTML, o transformăm într-o eroare JSON lizibilă în dashboard.
      if (url.pathname.startsWith("/api/")) {
        const contentType = String(response.headers.get("content-type") || "").toLowerCase();

        if (contentType.includes("text/html")) {
          const body = await response.text();
          return Response.json(
            {
              error: "API-ul Poliției a returnat HTML în loc de JSON.",
              route: url.pathname,
              status: response.status,
              details: body.replace(/\s+/g, " ").slice(0, 500)
            },
            { status: response.ok ? 502 : response.status }
          );
        }
      }

      return response;
    } catch (error) {
      if (url.pathname.startsWith("/api/")) {
        return Response.json(
          {
            error: "Eroare internă în API-ul Poliției.",
            route: url.pathname,
            details: String(error?.message || error || "Eroare necunoscută")
          },
          { status: 500 }
        );
      }

      throw error;
    }
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil((async () => {
      await syncApprovedLeaveDiscordRoles();
      await initMeetingAttendanceScheduler();
    })());
  }
};
