import { httpServerHandler } from "cloudflare:node";
import serverModule from "../server.js";

const { app, syncApprovedLeaveDiscordRoles, initMeetingAttendanceScheduler } = serverModule;

const PORT = 3000;
app.listen(PORT);
const handler = httpServerHandler({ port: PORT });

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function b64urlBytes(value) {
  const raw = String(value || "");
  const base64 = raw.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(raw.length / 4) * 4, "=");
  const binary = atob(base64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function verifyToken(token, env, kind) {
  const parts = String(token || "").split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) throw new Error("Token invalid.");

  const [encoded, signature] = parts;
  const secret = String(env.SESSION_SECRET || env.B2_APPLICATION_KEY || "change-this-secret");
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const expected = new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(encoded)));
  const actual = b64urlBytes(signature);
  if (!equalBytes(expected, actual)) throw new Error("Semnătura tokenului este invalidă.");

  const payload = JSON.parse(decoder.decode(b64urlBytes(encoded)));
  if (!payload.exp || Date.now() > Number(payload.exp)) throw new Error("Token expirat.");

  const objectKey = String(payload.key || "");
  if (kind === "image" && (!objectKey.startsWith("images/") || objectKey.includes(".."))) {
    throw new Error("Cheie imagine invalidă.");
  }
  if (kind === "metadata" && (!objectKey.startsWith("reports/") || !objectKey.endsWith(".json") || objectKey.includes(".."))) {
    throw new Error("Cheie raport invalidă.");
  }
  return payload;
}

async function authorizeB2(env) {
  const id = String(env.B2_KEY_ID || "");
  const key = String(env.B2_APPLICATION_KEY || "");
  if (!id || !key) throw new Error("Lipsesc B2_KEY_ID/B2_APPLICATION_KEY.");

  const r = await fetch("https://api.backblazeb2.com/b2api/v3/b2_authorize_account", {
    headers: { Authorization: `Basic ${btoa(`${id}:${key}`)}` }
  });
  const text = await r.text();
  let data;
  try { data = JSON.parse(text); } catch { data = null; }
  if (!r.ok || !data) throw new Error(`B2 authorize HTTP ${r.status}: ${text.slice(0, 250)}`);
  return data;
}

function storageApi(auth) {
  return auth?.apiInfo?.storageApi || auth?.apiInfo?.storage_api || null;
}

async function bucketId(auth, env) {
  const storage = storageApi(auth);
  const allowed = storage?.allowed || auth?.allowed || {};
  if (allowed.bucketId || allowed.bucket_id) return String(allowed.bucketId || allowed.bucket_id);

  const apiUrl = storage?.apiUrl || storage?.api_url;
  const accountId = auth?.accountId || auth?.account_id;
  const token = auth?.authorizationToken || auth?.authorization_token;
  if (!apiUrl || !accountId || !token) throw new Error("Răspuns B2 authorize incomplet.");

  const r = await fetch(`${apiUrl}/b2api/v3/b2_list_buckets`, {
    method: "POST",
    headers: { Authorization: token, "Content-Type": "application/json" },
    body: JSON.stringify({ accountId, bucketName: String(env.B2_BUCKET || "") })
  });
  const text = await r.text();
  let data;
  try { data = JSON.parse(text); } catch { data = null; }
  if (!r.ok || !data) throw new Error(`B2 list buckets HTTP ${r.status}: ${text.slice(0, 250)}`);
  const found = (data.buckets || []).find(x => String(x.bucketName || "") === String(env.B2_BUCKET || ""));
  if (!found?.bucketId) throw new Error(`Bucketul ${env.B2_BUCKET || ""} nu a fost găsit.`);
  return String(found.bucketId);
}

async function uploadTarget(auth, id) {
  const storage = storageApi(auth);
  const apiUrl = storage?.apiUrl || storage?.api_url;
  const token = auth?.authorizationToken || auth?.authorization_token;
  if (!apiUrl || !token) throw new Error("Răspuns B2 authorize incomplet.");

  const r = await fetch(`${apiUrl}/b2api/v3/b2_get_upload_url`, {
    method: "POST",
    headers: { Authorization: token, "Content-Type": "application/json" },
    body: JSON.stringify({ bucketId: id })
  });
  const text = await r.text();
  let data;
  try { data = JSON.parse(text); } catch { data = null; }
  if (!r.ok || !data?.uploadUrl || !data?.authorizationToken) {
    throw new Error(`B2 get upload URL HTTP ${r.status}: ${text.slice(0, 250)}`);
  }
  return data;
}

async function nativeUpload(env, objectKey, contentType, body) {
  const auth = await authorizeB2(env);
  const id = await bucketId(auth, env);
  const target = await uploadTarget(auth, id);
  const sha1 = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-1", body)))
    .map(b => b.toString(16).padStart(2, "0")).join("");

  const r = await fetch(target.uploadUrl, {
    method: "POST",
    headers: {
      Authorization: target.authorizationToken,
      "X-Bz-File-Name": encodeURIComponent(objectKey),
      "Content-Type": contentType,
      "Content-Length": String(body.byteLength),
      "X-Bz-Content-Sha1": sha1
    },
    body
  });

  const text = await r.text();
  if (!r.ok) throw new Error(`B2 upload HTTP ${r.status}: ${text.slice(0, 350)}`);
  let data = {};
  try { data = text ? JSON.parse(text) : {}; } catch {}
  return data;
}

async function imageUpload(request, env, url) {
  try {
    const payload = await verifyToken(url.searchParams.get("token"), env, "image");
    const contentType = String(request.headers.get("content-type") || "").split(";")[0].trim().toLowerCase();
    if (!["image/jpeg", "image/png", "image/webp"].includes(contentType)) {
      return Response.json({ error: "Tip imagine invalid." }, { status: 400 });
    }
    if (contentType !== String(payload.contentType || "").toLowerCase()) {
      return Response.json({ error: "Tipul imaginii nu corespunde." }, { status: 400 });
    }
    const body = await request.arrayBuffer();
    if (!body.byteLength || body.byteLength !== Number(payload.size || 0)) {
      return Response.json({ error: "Dimensiunea imaginii nu corespunde." }, { status: 400 });
    }
    const data = await nativeUpload(env, String(payload.key), contentType, body);
    return Response.json({ success: true, key: String(payload.key), fileId: data?.fileId || null });
  } catch (e) {
    return Response.json({ error: "Upload imagine eșuat.", details: String(e?.message || e) }, { status: 500 });
  }
}

async function metadataUpload(request, env, url) {
  try {
    const payload = await verifyToken(url.searchParams.get("token"), env, "metadata");
    const body = await request.arrayBuffer();
    if (!body.byteLength || body.byteLength > 2 * 1024 * 1024) {
      return Response.json({ error: "Metadata raport invalidă." }, { status: 400 });
    }

    // Validăm că body-ul este JSON înainte de a-l pune în B2.
    try { JSON.parse(decoder.decode(body)); }
    catch { return Response.json({ error: "Metadata raport nu este JSON valid." }, { status: 400 }); }

    const data = await nativeUpload(env, String(payload.key), "application/json; charset=utf-8", body);
    return Response.json({ success: true, key: String(payload.key), fileId: data?.fileId || null });
  } catch (e) {
    return Response.json({ error: "Salvarea raportului în B2 a eșuat.", details: String(e?.message || e) }, { status: 500 });
  }
}


// ======================================================
// BACKBLAZE B2 — ȘTERGERE RAPOARTE (Native API)
// Folosește aceleași credențiale/API care funcționează deja la upload.
// Ștergem toate versiunile pentru reports/ și images/, nu doar ultima versiune.
// ======================================================
async function listNativeFileVersions(env, prefix) {
  const auth = await authorizeB2(env);
  const storage = storageApi(auth);
  const apiUrl = storage?.apiUrl || storage?.api_url;
  const token = auth?.authorizationToken || auth?.authorization_token;
  const id = await bucketId(auth, env);
  if (!apiUrl || !token || !id) throw new Error("Răspuns B2 authorize incomplet pentru ștergere.");

  const files = [];
  let startFileName = null;
  let startFileId = null;
  let pages = 0;

  while (true) {
    pages += 1;
    if (pages > 200) throw new Error(`Prea multe pagini B2 pentru ${prefix}.`);

    const body = {
      bucketId: id,
      prefix,
      maxFileCount: 1000
    };
    if (startFileName) body.startFileName = startFileName;
    if (startFileId) body.startFileId = startFileId;

    const r = await fetch(`${apiUrl}/b2api/v3/b2_list_file_versions`, {
      method: "POST",
      headers: { Authorization: token, "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    const text = await r.text();
    let data = null;
    try { data = text ? JSON.parse(text) : {}; } catch {}
    if (!r.ok || !data) throw new Error(`B2 list file versions HTTP ${r.status}: ${text.slice(0, 500)}`);

    for (const f of (data.files || [])) {
      const fileName = String(f.fileName || "");
      const fileId = String(f.fileId || "");
      if (fileName.startsWith(prefix) && fileId) files.push({ fileName, fileId });
    }

    startFileName = data.nextFileName || null;
    startFileId = data.nextFileId || null;
    if (!startFileName) break;
  }

  return { auth, apiUrl, token, files };
}

async function deleteNativeFileVersion(apiUrl, token, file) {
  const r = await fetch(`${apiUrl}/b2api/v3/b2_delete_file_version`, {
    method: "POST",
    headers: { Authorization: token, "Content-Type": "application/json" },
    body: JSON.stringify({ fileName: file.fileName, fileId: file.fileId })
  });
  const text = await r.text();
  if (!r.ok) throw new Error(`B2 delete ${file.fileName} HTTP ${r.status}: ${text.slice(0, 350)}`);
}

async function deleteNativeFilesInBatches(apiUrl, token, files) {
  // Loturi mici ca să nu bombardăm B2. Pentru volume foarte mari continuăm
  // secvențial pe loturi; fiecare versiune este ștearsă definitiv.
  const concurrency = 8;
  for (let i = 0; i < files.length; i += concurrency) {
    await Promise.all(
      files.slice(i, i + concurrency).map(file => deleteNativeFileVersion(apiUrl, token, file))
    );
  }
}

async function deleteAllReportStorage(env) {
  // O singură autorizare/listare per prefix; folosim Native B2 API, nu S3 SigV4.
  const reportListing = await listNativeFileVersions(env, "reports/");
  const imageListing = await listNativeFileVersions(env, "images/");

  await deleteNativeFilesInBatches(reportListing.apiUrl, reportListing.token, reportListing.files);
  await deleteNativeFilesInBatches(imageListing.apiUrl, imageListing.token, imageListing.files);

  // Verificare finală. Dacă ceva a rămas, dashboard-ul primește eroare reală.
  const remainingReports = await listNativeFileVersions(env, "reports/");
  const remainingImages = await listNativeFileVersions(env, "images/");

  if (remainingReports.files.length || remainingImages.files.length) {
    throw new Error(
      `Au rămas obiecte în B2: reports=${remainingReports.files.length}, images=${remainingImages.files.length}`
    );
  }

  return {
    deletedReports: reportListing.files.filter(x => x.fileName.endsWith(".json")).length,
    deletedImages: imageListing.files.length,
    deletedVersions: reportListing.files.length + imageListing.files.length
  };
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (request.method === "PUT" && url.pathname === "/api/report-image-upload") {
      return imageUpload(request, env, url);
    }
    if (request.method === "PUT" && url.pathname === "/api/internal/report-metadata-upload") {
      return metadataUpload(request, env, url);
    }

    try {
      const response = await handler.fetch(request, env, ctx);

      // Express validează sesiunea de admin + textul de confirmare. Abia după
      // aceea executăm ștergerea bulk nativă, ca să nu expunem un endpoint B2
      // care poate fi apelat fără autentificare.
      if (request.method === "DELETE" && url.pathname === "/api/admin/reports/all" && response.ok) {
        let gate = null;
        try { gate = await response.clone().json(); } catch {}
        if (gate?.nativeB2Delete === true) {
          try {
            const result = await deleteAllReportStorage(env);
            return Response.json({
              success: true,
              ...result,
              message: "Toate rapoartele și imaginile lor au fost șterse definitiv din Backblaze B2."
            });
          } catch (e) {
            return Response.json({
              error: "Rapoartele nu au putut fi șterse complet din Backblaze B2.",
              details: String(e?.message || e)
            }, { status: 500 });
          }
        }
      }

      if (url.pathname.startsWith("/api/")) {
        const ct = String(response.headers.get("content-type") || "").toLowerCase();
        if (ct.includes("text/html")) {
          const body = await response.text();
          return Response.json({
            error: "API-ul Poliției a returnat HTML în loc de JSON.",
            route: url.pathname,
            status: response.status,
            details: body.replace(/\s+/g, " ").slice(0, 500)
          }, { status: response.ok ? 502 : response.status });
        }
      }
      return response;
    } catch (e) {
      if (url.pathname.startsWith("/api/")) {
        return Response.json({
          error: "Eroare internă în API-ul Poliției.",
          route: url.pathname,
          details: String(e?.message || e || "Eroare necunoscută")
        }, { status: 500 });
      }
      throw e;
    }
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil((async () => {
      await syncApprovedLeaveDiscordRoles();
      await initMeetingAttendanceScheduler();
    })());
  }
};
