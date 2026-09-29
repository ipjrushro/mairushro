import http from "node:http";
import { httpServerHandler } from "cloudflare:node";
import serverModule from "../server.js";

const { app, syncApprovedLeaveDiscordRoles, initMeetingAttendanceScheduler } = serverModule;
const server = http.createServer(app);
const handler = httpServerHandler(server);

export default {
  fetch(request, env, ctx) {
    return handler.fetch(request, env, ctx);
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil((async () => {
      await syncApprovedLeaveDiscordRoles();
      // Reîncarcă programările de prezență. Joburile scadente sunt armate de logica existentă.
      await initMeetingAttendanceScheduler();
    })());
  }
};
